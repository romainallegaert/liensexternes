import re, time
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

import pandas as pd
import requests
import tldextract
import feedparser
from bs4 import BeautifulSoup
import streamlit as st

# ---- CONFIG STREAMLIT (one-shot, safe) ----
if "page_cfg_done" not in st.session_state:
    try:
        st.set_page_config(page_title="RSS Outlinks Extractor", page_icon="🔗", layout="wide")
    finally:
        # qu'il réussisse ou non, on évite de rappeler set_page_config aux reruns
        st.session_state["page_cfg_done"] = True
        # ---- Parser fallback (lxml si dispo, sinon html.parser) ----
PARSER = "lxml"
try:
    import lxml  # noqa: F401  # si lxml est installé, on l'utilise (plus rapide)
except Exception:
    PARSER = "html.parser"      # sinon, parser standard de Python


@st.cache_data(show_spinner=False, ttl=60*60*12)
def fetch_whois(domain: str) -> dict:
    """Retourne quelques champs WHOIS (email, registrar, dates) pour un domaine.
       Résultat mis en cache 12h pour éviter les appels répétés."""
    if not WHOIS_API_KEY or not domain:
        return {}
    try:
        r = requests.get(
            WHOIS_BASE,
            params={
                "apiKey": WHOIS_API_KEY,
                "domainName": domain,
                "outputFormat": "JSON",
            },
            timeout=30,
        )
        r.raise_for_status()
        rec = (r.json() or {}).get("WhoisRecord", {}) or {}

        # Email: on essaie plusieurs emplacements possibles
        email = (
            rec.get("contactEmail")
            or (rec.get("registrant") or {}).get("email")
            or (rec.get("administrativeContact") or {}).get("email")
            or (rec.get("technicalContact") or {}).get("email")
            or ""
        )

        registrar = (
            rec.get("registrarName")
            or (rec.get("registrar") or {}).get("name")
            or ""
        )
        created = rec.get("createdDate") or rec.get("createdDateNormalized") or ""
        expires = rec.get("expiresDate") or rec.get("expiresDateNormalized") or ""

        return {
            "whois_email": email,
            "whois_registrar": registrar,
            "domain_created": created,
            "domain_expires": expires,
        }
    except Exception:
        # En cas d’erreur, on renvoie un dict vide (l’app continue)
        return {}


# ================== UI ==================
st.title("🔗 RSS Outlinks Extractor")
st.caption("Analyse un flux RSS/Atom, ouvre chaque article et extrait les liens sortants du texte.")

with st.sidebar:
    st.header("Paramètres")
    feeds_text = st.text_area(
        "Liste d'URLs de flux (un par ligne)",
        value="https://lesdjadjas.fr/feed/\nhttps://www.carredinfo.fr/feed/"
    )
    max_items = st.number_input("Nombre max d'articles par flux", 1, 1000, 50, 1)
    delay_sec = st.slider("Pause entre articles (politesse)", 0.0, 5.0, 1.0, 0.5)
    external_only = st.checkbox("Garder uniquement les liens externes", value=True)
    restrict_to_paragraphs = st.checkbox("Ne garder que les liens dans les <p>", value=True)
    run_btn = st.button("Analyser tous les flux")

# On transforme le texte en vraie liste Python
feeds = [u.strip() for u in feeds_text.splitlines() if u.strip()]


st.markdown("— Respecte le **robots.txt** et les **CGU**. Identifie-toi avec un User-Agent. Limite le débit. —")

UA = "RSS-Outlinks/1.0 (+contact: you@example.com)"
HEADERS = {"User-Agent": UA}

# ================== Utils ==================
def http_get(url, timeout=25):
    r = requests.get(url, headers=HEADERS, timeout=timeout)
    r.raise_for_status()
    return r

def clean_url(u: str) -> str:
    """Supprime utm_*, fbclid, gclid, etc. pour mieux dédupliquer."""
    try:
        p = urlparse(u)
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if not (k.lower().startswith("utm_") or k.lower() in {"fbclid", "gclid"})]
        return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))
    except Exception:
        return u

def is_external(u: str, base_domain: str) -> bool:
    if not u.startswith("http"):
        return False
    dom = tldextract.extract(u).registered_domain
    return dom != "" and dom != base_domain

def safe_get_article_url(entry):
    if "link" in entry and entry.link:
        return entry.link
    if "links" in entry and entry.links:
        for l in entry.links:
            if l.get("rel") in (None, "alternate") and l.get("href"):
                return l["href"]
    return None

def get_body_root(soup: BeautifulSoup) -> BeautifulSoup:
    # conteneurs fréquents
    candidates = [
        '[itemprop="articleBody"]',
        "article .entry-content", ".entry-content",
        ".single-content", ".post-content", ".article-content",
        "article .content", "article"
    ]
    body = None
    for sel in candidates:
        body = soup.select_one(sel)
        if body:
            break
    if not body:
        body = soup

    # retirer zones non éditoriales
    for sel in [
        "nav", "header", "footer", "aside",
        ".share", ".social", ".post-share", ".share-buttons",
        ".related", ".tags", ".post-tags", ".entry-meta", ".post-meta",
        ".breadcrumbs", ".toc", ".newsletter", ".comments"
    ]:
        for el in body.select(sel):
            el.decompose()
    return body

def extract_links(body_root: BeautifulSoup, base_url: str, base_domain: str,
                  extern_only=True, only_paragraphs=True):
    elems = body_root.select("p") if only_paragraphs else [body_root]
    out = []
    for node in elems:
        for a in node.select("a[href]"):
            href = (a.get("href") or "").strip()
            abs_url = clean_url(urljoin(base_url, href))
            if abs_url.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            if extern_only and not is_external(abs_url, base_domain):
                continue
            anchor = a.get_text(" ", strip=True)
            out.append({"url": abs_url, "anchor": anchor})

    # dédoublonnage par URL (garde première ancre)
    seen, uniq = set(), []
    for item in out:
        if item["url"] in seen:
            continue
        seen.add(item["url"])
        uniq.append(item)
    return uniq

def parse_article(url: str, extern_only=True, only_paragraphs=True):
    resp = http_get(url)
    soup = BeautifulSoup(resp.text, PARSER)  # <— parser fallback
    base_domain = tldextract.extract(url).registered_domain

    title = soup.select_one("h1")
    title = title.get_text(strip=True) if title else ""

    # méta (best-effort)
    header_text = " ".join(soup.get_text(" ").split())
    m_date = re.search(r"\b(\d{1,2}\s+[A-Za-zéûîôàç]+(?:\s+20\d{2}))\b", header_text)
    date = m_date.group(1) if m_date else ""
    m_author = re.search(r"\bPar\s+(.+?)\b", header_text)
    author = m_author.group(1).strip() if m_author else ""

    body_root = get_body_root(soup)
    links = extract_links(body_root, url, base_domain, extern_only, only_paragraphs)
    domains = sorted({tldextract.extract(l["url"]).registered_domain for l in links if l["url"]})

    return {
        "article_url": url,
        "article_title": title,
        "article_author": author,
        "article_date": date,
        "outbound_count": len(links),
        "outbound_domains": "; ".join(domains),
        "links": links,
    }

# ================== Main action ==================
if run_btn:
    if not feeds:
        st.error("Merci d'indiquer au moins un flux RSS/Atom (un par ligne).")
        st.stop()

    articles_rows, links_rows = [], []
    total_items = 0

    # Lecture de tous les flux
    feeds_entries = []
    with st.spinner("Lecture des flux…"):
        for f in feeds:
            feed = feedparser.parse(f)
            entries = list(getattr(feed, "entries", []))[:max_items]
            feeds_entries.append((f, entries))
            total_items += len(entries)

    if total_items == 0:
        st.warning("Aucun item trouvé dans les flux fournis.")
        st.stop()

    progress = st.progress(0.0)
    status = st.empty()
    done = 0

    for feed_url, entries in feeds_entries:
        for entry in entries:
            art_url = safe_get_article_url(entry)
            if not art_url:
                status.write(f"⏭️ {feed_url}: item sans URL d’article")
                done += 1
                progress.progress(done / total_items)
                continue
            try:
                data = parse_article(
                    art_url,
                    extern_only=external_only,
                    only_paragraphs=restrict_to_paragraphs
                )
                # On ajoute la source du flux
                articles_rows.append({
                    "feed": feed_url,
                    "article_url": data["article_url"],
                    "article_title": data["article_title"],
                    "article_author": data["article_author"],
                    "article_date": data["article_date"],
                    "outbound_count": data["outbound_count"],
                    "outbound_domains": data["outbound_domains"],
                })
                for l in data["links"]:
                    links_rows.append({
                        "feed": feed_url,
                        "article_url": data["article_url"],
                        "article_title": data["article_title"],
                        "out_url": l["url"],
                        "out_anchor": l["anchor"],
                        "out_domain": tldextract.extract(l["url"]).registered_domain
                    })
                status.write(f"✅ {feed_url} — {data['article_title'][:80]}…  ({data['outbound_count']} lien(s))")
            except Exception as e:
                status.write(f"❌ {feed_url} — {art_url} — {e}")

            done += 1
            progress.progress(done / total_items)
            time.sleep(delay_sec)

     st.success("Terminé !")

    df_articles = pd.DataFrame(articles_rows)
    df_links = pd.DataFrame(links_rows)

    # ==== Enrichissement WHOIS par domaine unique ====
    if WHOIS_API_KEY and not df_links.empty and "out_domain" in df_links.columns:
        st.info("🔍 Enrichissement WHOIS… (1 requête par domaine unique)")
        unique_domains = sorted(df_links["out_domain"].dropna().unique().tolist())

        whois_rows = []
        for d in unique_domains:
            info = fetch_whois(d)  # résultat en cache 12h
            info["out_domain"] = d
            whois_rows.append(info)
            time.sleep(0.5)  # douceur pour l’API free tier; ajuste si besoin

        whois_df = pd.DataFrame(whois_rows)
        if not whois_df.empty:
            # on rajoute les colonnes whois_* dans df_links
            df_links = df_links.merge(whois_df, on="out_domain", how="left")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Articles")
        st.dataframe(df_articles, use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Télécharger (CSV articles)",
            df_articles.to_csv(index=False).encode("utf-8"),
            file_name="rss_outlinks_by_article.csv",
            mime="text/csv"
        )
    with col2:
        st.subheader("Liens sortants (1 ligne par lien)")
        st.dataframe(df_links, use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Télécharger (CSV liens)",
            df_links.to_csv(index=False).encode("utf-8"),
            file_name="rss_outlinks_flat.csv",
            mime="text/csv"
        )

    st.caption("Astuce : mets autant d’URLs de flux que tu veux (une par ligne).")

   
