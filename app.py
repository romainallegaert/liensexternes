import re, time
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

import pandas as pd
import requests
import tldextract
import feedparser
from bs4 import BeautifulSoup
import streamlit as st

# 🆕 Ajoute ces imports pour le crawl
import gzip
import io
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import urllib.robotparser as robotparser

import xml.etree.ElementTree as ET
import gzip


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
# ---- Parser fallback ----
PARSER = "lxml"
try:
    import lxml  # noqa: F401
except Exception:
    PARSER = "html.parser"

# ⬇️ CES DEUX LIGNES SANS AUCUNE INDENTATION
WHOIS_API_KEY = "at_5fF73TnhIdy94u3UCHB7N3rn1UGSi"
WHOIS_BASE = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
st.caption(f"DBG WHOIS key loaded: {'yes' if 'WHOIS_API_KEY' in globals() and WHOIS_API_KEY else 'no'}")


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

    mode = st.radio("Mode d’analyse", ["Flux RSS", "Sitemap"], index=0)

    if mode == "Flux RSS":
        feeds_text = st.text_area(
            "Liste d'URLs de flux (un par ligne)",
            value="https://lesdjadjas.fr/feed/\nhttps://www.carredinfo.fr/feed/"
        )
        max_items = st.number_input("Nombre max d'articles par flux", 1, 1000, 50, 1)
    else:
        sitemap_url = st.text_input("URL de la sitemap (xml ou gz)", value="https://lesdjadjas.fr/sitemap.xml")
        uploaded_sm = st.file_uploader("…ou dépose le fichier sitemap (xml / gz)", type=["xml", "gz"], accept_multiple_files=False)
        manual_urls_text = st.text_area("…ou colle directement une liste d’URLs (une par ligne)", value="", height=120)
        max_pages = st.number_input("Nombre max d’URLs à analyser", 10, 20000, 300, 10)

    delay_sec = st.slider("Pause entre pages (politesse)", 0.0, 5.0, 1.0, 0.5)
    external_only = st.checkbox("Garder uniquement les liens externes", value=True)
    restrict_to_paragraphs = st.checkbox("Ne garder que les liens dans les <p>", value=True)

    run_btn = st.button("Analyser")


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
# ================== Fonctions de crawl (site complet) ==================

def same_domain(u1: str, u2: str) -> bool:
    d1 = tldextract.extract(u1).registered_domain
    d2 = tldextract.extract(u2).registered_domain
    return d1 and d2 and d1 == d2

def try_load_robots(start_url: str, ua: str = "RSS-Outlinks/1.0"):
    try:
        p = robotparser.RobotFileParser()
        parsed = urlparse(start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        p.set_url(robots_url)
        p.read()
        return p
    except Exception:
        return None

def allowed_by_robots(robots, url: str, ua: str = "RSS-Outlinks/1.0") -> bool:
    try:
        if robots is None:
            return True
        return robots.can_fetch(ua, url)
    except Exception:
        return True

def find_internal_links(page_url: str, html: str):
    soup = BeautifulSoup(html, PARSER)
    links = set()
    for a in soup.select("a[href]"):
        href = (a.get("href") or "").strip()
        abs_url = urljoin(page_url, href)
        if abs_url.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        if same_domain(page_url, abs_url):
            links.add(clean_url(abs_url))
    return links

def fetch_sitemap_urls(site_url: str, max_urls: int = 500):
    """Essaie de lire le sitemap.xml d’un site pour extraire des URLs."""
    try:
        parsed = urlparse(site_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        sm_url = urljoin(base, "/sitemap.xml")
        r = requests.get(sm_url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        content = r.content
        # Support des fichiers gzip
        if r.headers.get("Content-Type", "").lower().startswith("application/gzip") or sm_url.endswith(".gz"):
            content = gzip.decompress(content)
        root = ET.fromstring(content)
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        urls = []
        for loc in root.findall(f".//{ns}url/{ns}loc"):
            if loc.text:
                urls.append(clean_url(loc.text.strip()))
                if len(urls) >= max_urls:
                    break
        return urls
    except Exception:
        return []

def crawl_site(start_url: str, max_pages: int = 100, delay: float = 1.0):
    """Petit crawler qui explore les liens internes d’un site jusqu’à max_pages."""
    seen = set()
    queue = [clean_url(start_url)]
    robots = try_load_robots(start_url, UA)
    pages = []

    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        if not allowed_by_robots(robots, url, UA):
            continue
        try:
            r = http_get(url)
            pages.append(url)
            for link in find_internal_links(url, r.text):
                if link not in seen and same_domain(start_url, link):
                    queue.append(link)
        except Exception:
            pass
        time.sleep(delay)
    return pages

# ================== Main action ==================
def parse_sitemap_bytes(content: bytes) -> list[str]:
    """Retourne les URLs d'un sitemap (index ou urlset) à partir de son contenu brut (xml ou gz)."""
    try:
        # si on nous passe directement du .gz
        try:
            content = gzip.decompress(content)
        except Exception:
            pass

        root = ET.fromstring(content)
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        urls = []

        # sitemap index -> récursion
        for el in root.findall(f".//{ns}sitemap/{ns}loc"):
            loc = (el.text or "").strip()
            if not loc:
                continue
            try:
                r = requests.get(loc, headers=HEADERS, timeout=20)
                r.raise_for_status()
                urls.extend(parse_sitemap_bytes(r.content))
            except Exception:
                pass

        # urlset direct
        for el in root.findall(f".//{ns}url/{ns}loc"):
            loc = (el.text or "").strip()
            if loc:
                urls.append(clean_url(loc))

        return urls
    except Exception:
        return []

def scrape_sitemap_url(sm_url: str, max_urls: int) -> list[str]:
    """Télécharge une sitemap par URL (xml ou gz) et renvoie jusqu'à max_urls URLs dédupliquées."""
    try:
        resp = requests.get(sm_url, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        all_urls = parse_sitemap_bytes(resp.content)
        # dédoublonnage + limite
        seen, out = set(), []
        for u in all_urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
                if len(out) >= max_urls:
                    break
        return out
    except Exception:
        return []

   # ================== Main action ==================
# ================== Main action ==================
if run_btn:
    articles_rows, links_rows = [], []
    status = st.empty()
    progress = st.progress(0.0)

    if mode == "Flux RSS":
        # --- ta logique RSS EXISTANTE ici (inchangée) ---
        ...
    else:
        # --------- Mode Sitemap ----------
        pages = []

        # 1) Liste manuelle prioritaire
        manual_list = [u.strip() for u in manual_urls_text.splitlines() if u.strip()]
        if manual_list:
            pages = manual_list[: int(max_pages)]
        # 2) Fichier uploadé
        elif uploaded_sm is not None:
            pages = parse_sitemap_bytes(uploaded_sm.read())
            # dédoublonnage + limite
            seen, tmp = set(), []
            for u in pages:
                if u not in seen:
                    seen.add(u)
                    tmp.append(u)
                    if len(tmp) >= int(max_pages):
                        break
            pages = tmp
        # 3) URL de sitemap
        elif sitemap_url.strip():
            pages = scrape_sitemap_url(sitemap_url.strip(), max_urls=int(max_pages))

        if not pages:
            st.warning("Aucune URL récupérée (vérifie l’URL du sitemap, le fichier ou la liste manuelle).")
            st.stop()

        st.write(f"🌐 {len(pages)} URL(s) à analyser via sitemap")
        for i, url in enumerate(pages, 1):
            try:
                data = parse_article(
                    url,
                    extern_only=external_only,
                    only_paragraphs=restrict_to_paragraphs
                )
                articles_rows.append({
                    "feed": "(sitemap)",
                    "article_url": data["article_url"],
                    "article_title": data["article_title"],
                    "article_author": data["article_author"],
                    "article_date": data["article_date"],
                    "outbound_count": data["outbound_count"],
                    "outbound_domains": data["outbound_domains"],
                })
                for l in data["links"]:
                    links_rows.append({
                        "feed": "(sitemap)",
                        "article_url": data["article_url"],
                        "article_title": data["article_title"],
                        "out_url": l["url"],
                        "out_anchor": l["anchor"],
                        "out_domain": tldextract.extract(l["url"]).registered_domain
                    })
                status.write(f"✅ {i}/{len(pages)} — {data['article_title'][:80]}… ({data['outbound_count']} lien(s))")
            except Exception as e:
                status.write(f"❌ {i}/{len(pages)} — {url} — {e}")
            progress.progress(i / len(pages))
            time.sleep(delay_sec)

    # --------- Commun (WHOIS + tableaux/CSV) ----------
    st.success("Terminé !")

    df_articles = pd.DataFrame(articles_rows)
    df_links = pd.DataFrame(links_rows)

    if WHOIS_API_KEY and not df_links.empty and "out_domain" in df_links.columns:
        st.info("🔍 Enrichissement WHOIS… (1 requête par domaine unique)")
        unique_domains = sorted(df_links["out_domain"].dropna().unique().tolist())
        whois_rows = []
        for d in unique_domains:
            info = fetch_whois(d)
            info["out_domain"] = d
            whois_rows.append(info)
            time.sleep(0.5)
        whois_df = pd.DataFrame(whois_rows)
        if not whois_df.empty:
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

    st.caption("Astuce : colle une *liste d’URLs* si tu veux cibler une catégorie précise.")


    # ==== Enrichissement WHOIS par domaine unique ====
    if WHOIS_API_KEY and not df_links.empty and "out_domain" in df_links.columns:
        st.info("🔍 Enrichissement WHOIS… (1 requête par domaine unique)")
        unique_domains = sorted(df_links["out_domain"].dropna().unique().tolist())

        whois_rows = []
        for d in unique_domains:
            info = fetch_whois(d)  # résultat en cache 12h
            info["out_domain"] = d
            whois_rows.append(info)
            time.sleep(0.5)  # douceur pour l’API free tier

        whois_df = pd.DataFrame(whois_rows)
        if not whois_df.empty:
            df_links = df_links.merge(whois_df, on="out_domain", how="left")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Articles")
        st.dataframe(df_articles, use_container_width=True, hide_index=True)
           st.download_button(
        "⬇️ Télécharger (CSV articles)",
        df_articles.to_csv(index=False).encode("utf-8"),
        file_name="rss_outlinks_by_article.csv",
        mime="text/csv",
        key="download_articles"  # 👈 clé unique
    )
with col2:
    st.subheader("Liens sortants (1 ligne par lien)")
    st.dataframe(df_links, use_container_width=True, hide_index=True)
    st.download_button(
        "⬇️ Télécharger (CSV liens)",
        df_links.to_csv(index=False).encode("utf-8"),
        file_name="rss_outlinks_flat.csv",
        mime="text/csv",
        key="download_links"  # 👈 autre clé unique
    )




    st.caption("Astuce : en mode Crawl, active d’abord « Tenter le sitemap.xml » : souvent > 100 URLs.")


   
