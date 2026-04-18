#!/usr/bin/env python3
"""
WP-Dex — Advanced WordPress Passive Reconnaissance Tool
=============================================================
Pure information gathering. No exploitation. No modification.
Use ONLY on websites you own or have explicit permission to audit.
"""

import requests
import re
import json
import argparse
import sys
import time
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode
from datetime import datetime
from collections import defaultdict

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependency: pip install requests beautifulsoup4")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ══════════════════════════════════════════════════════════════════
#  COLORS & DISPLAY
# ══════════════════════════════════════════════════════════════════
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔═════════════════════════════════════════════════════════════╗
║             WP-Dex — WordPress Recon & Audit Tool           ║
║           Passive reconnaissance only — no exploits	      ║
║							      ║
║		     Created by DotX-47			      ║
╚═════════════════════════════════════════════════════════════╝
{C.RESET}""")

def section(title, icon="◈"):
    width = 60
    print(f"\n{C.CYAN}{C.BOLD}{'─'*width}")
    print(f"  {icon}  {title}")
    print(f"{'─'*width}{C.RESET}")

def info(msg):   print(f"  {C.BLUE}[i]{C.RESET} {msg}")
def good(msg):   print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):   print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def bad(msg):    print(f"  {C.RED}[✗]{C.RESET} {msg}")
def dim(msg):    print(f"  {C.DIM}{msg}{C.RESET}")


# ══════════════════════════════════════════════════════════════════
#  HTTP SESSION
# ══════════════════════════════════════════════════════════════════
def make_session(user_agent=None, proxy=None, timeout=12):
    s = requests.Session()
    s.headers.update({
        "User-Agent": user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    s.verify = False
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s._timeout = timeout
    return s

def get(session, url, allow_redirects=True, stream=False):
    try:
        return session.get(url, timeout=session._timeout,
                           allow_redirects=allow_redirects, stream=stream)
    except Exception:
        return None

def normalize(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ══════════════════════════════════════════════════════════════════
#  WORDPRESS DETECTION
# ══════════════════════════════════════════════════════════════════
def detect_wordpress(session, base):
    signals = []
    checks = {
        "wp-login.php":    f"{base}/wp-login.php",
        "wp-admin/":       f"{base}/wp-admin/",
        "xmlrpc.php":      f"{base}/xmlrpc.php",
        "wp-includes/":    f"{base}/wp-includes/",
        "wp-cron.php":     f"{base}/wp-cron.php",
    }
    for label, url in checks.items():
        r = get(session, url, allow_redirects=False)
        if r and r.status_code in (200, 301, 302, 403, 405):
            signals.append(label)

    r = get(session, base)
    if r:
        if "wp-content" in r.text:   signals.append("wp-content in source")
        if "wp-includes" in r.text:  signals.append("wp-includes in source")
        if "WordPress" in r.text:    signals.append("WordPress string in source")

    return signals


# ══════════════════════════════════════════════════════════════════
#  SERVER & TECHNOLOGY FINGERPRINT
# ══════════════════════════════════════════════════════════════════
def fingerprint_server(session, base):
    info_map = {}
    r = get(session, base)
    if not r:
        return info_map

    h = {k.lower(): v for k, v in r.headers.items()}
    info_map["server"]          = h.get("server", "")
    info_map["x_powered_by"]    = h.get("x-powered-by", "")
    info_map["content_type"]    = h.get("content-type", "")
    info_map["cache_control"]   = h.get("cache-control", "")
    info_map["x_cache"]         = h.get("x-cache", "")
    info_map["cf_ray"]          = h.get("cf-ray", "")          # Cloudflare
    info_map["via"]             = h.get("via", "")
    info_map["x_varnish"]       = h.get("x-varnish", "")       # Varnish cache
    info_map["x_litespeed_tag"] = h.get("x-litespeed-tag", "") # LiteSpeed
    info_map["x_generator"]     = h.get("x-generator", "")
    info_map["protocol"]        = r.url.split(":")[0].upper()
    info_map["final_url"]       = r.url
    info_map["status_code"]     = r.status_code
    info_map["response_time_ms"]= int(r.elapsed.total_seconds() * 1000)
    info_map["encoding"]        = r.encoding or ""
    info_map["cookies"]         = {c.name: c.value for c in session.cookies}

    # CDN / WAF detection
    waf_signatures = {
        "Cloudflare":   ["cf-ray", "cloudflare"],
        "Sucuri":       ["x-sucuri-id", "sucuri"],
        "Wordfence":    ["wordfence"],
        "AWS CloudFront": ["x-amz-cf-id", "cloudfront"],
        "Akamai":       ["x-akamai", "akamai"],
        "Imperva":      ["x-iinfo", "incapsula"],
        "ModSecurity":  ["mod_security", "modsec"],
    }
    detected_waf = []
    full_text = str(r.headers).lower() + r.text[:2000].lower()
    for waf, sigs in waf_signatures.items():
        if any(sig in full_text for sig in sigs):
            detected_waf.append(waf)
    info_map["waf_cdn"] = detected_waf

    # PHP version from header
    php_match = re.search(r'PHP/([\d.]+)', h.get("x-powered-by", ""), re.I)
    if php_match:
        info_map["php_version"] = php_match.group(1)

    # SSL info
    if base.startswith("https://"):
        try:
            import ssl, socket
            host = urlparse(base).netloc.split(":")[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s2:
                s2.settimeout(5)
                s2.connect((host, 443))
                cert = s2.getpeercert()
                info_map["ssl_issuer"]  = dict(x[0] for x in cert.get("issuer", []))
                info_map["ssl_subject"] = dict(x[0] for x in cert.get("subject", []))
                info_map["ssl_expires"] = cert.get("notAfter", "")
                info_map["ssl_version"] = s2.version()
        except Exception:
            pass

    # Technology from source
    tech = []
    src = r.text[:20000]
    tech_patterns = {
        "jQuery":            r'jquery[.-]([\d.]+)',
        "jQuery UI":         r'jquery-ui[.-]([\d.]+)',
        "Bootstrap":         r'bootstrap[.-]([\d.]+)',
        "Google Analytics":  r'google-analytics\.com|gtag\(',
        "Google Tag Manager":r'googletagmanager\.com',
        "Facebook Pixel":    r'connect\.facebook\.net',
        "WooCommerce":       r'woocommerce',
        "Elementor":         r'elementor',
        "Divi":              r'/et-core/',
        "Beaver Builder":    r'fl-builder',
        "WPBakery":          r'wpb_js_composer|vc_row',
        "WPML":              r'sitepress|wpml',
        "Polylang":          r'polylang',
    }
    for name, pattern in tech_patterns.items():
        if re.search(pattern, src, re.I):
            tech.append(name)
    info_map["technologies"] = tech

    return info_map


# ══════════════════════════════════════════════════════════════════
#  WORDPRESS VERSION
# ══════════════════════════════════════════════════════════════════
def detect_wp_version(session, base):
    sources = {}

    probes = [
        (f"{base}/readme.html",             r'[Vv]ersion\s+([\d.]+)'),
        (f"{base}/feed/",                   r'\?v=([\d.]+)'),
        (f"{base}/?feed=rss2",              r'\?v=([\d.]+)'),
        (f"{base}/wp-links-opml.php",       r'generator="WordPress/([\d.]+)'),
        (f"{base}/wp-admin/install.php",    r'WordPress\s+([\d.]+)'),
    ]
    for url, pattern in probes:
        r = get(session, url)
        if r and r.status_code == 200:
            m = re.search(pattern, r.text)
            if m:
                key = url.split(base)[-1] or url
                sources[key] = m.group(1)

    # Meta generator
    r = get(session, base)
    if r:
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', r.text, re.I)
        if m:
            sources["meta generator"] = m.group(1)
        m = re.search(r'ver=([\d.]+)["\'].*?wp-includes', r.text)
        if m:
            sources["script ver param"] = m.group(1)

    return sources


# ══════════════════════════════════════════════════════════════════
#  USER / ADMIN ENUMERATION
# ══════════════════════════════════════════════════════════════════
def enumerate_users(session, base):
    users = {}

    # ── REST API ──────────────────────────────────────────────────
    for endpoint in [
        f"{base}/wp-json/wp/v2/users",
        f"{base}/wp-json/wp/v2/users?per_page=100",
        f"{base}/?rest_route=/wp/v2/users",
    ]:
        r = get(session, endpoint)
        if r and r.status_code == 200:
            try:
                for u in r.json():
                    uid = u.get("id", 0)
                    users[uid] = {
                        "id":          uid,
                        "login":       u.get("slug", ""),
                        "name":        u.get("name", ""),
                        "url":         u.get("link", ""),
                        "avatar":      list(u.get("avatar_urls", {}).values())[-1] if u.get("avatar_urls") else "",
                        "description": u.get("description", ""),
                        "source":      "REST API /wp/v2/users",
                    }
            except Exception:
                pass

    # ── ?author= redirect ─────────────────────────────────────────
    for i in range(1, 21):
        r = get(session, f"{base}/?author={i}", allow_redirects=True)
        if r and r.status_code == 200 and "/author/" in r.url:
            slug = r.url.split("/author/")[-1].strip("/").split("?")[0]
            if slug and i not in users:
                soup = BeautifulSoup(r.text, "html.parser")
                title_tag = soup.find("title")
                name = title_tag.get_text(strip=True).split("|")[0].strip() if title_tag else slug
                users[i] = {
                    "id": i, "login": slug, "name": name,
                    "url": r.url, "avatar": "", "description": "",
                    "source": "?author= redirect",
                }

    # ── Sitemaps ──────────────────────────────────────────────────
    for sitemap_url in [f"{base}/sitemap_author.xml", f"{base}/author-sitemap.xml"]:
        r = get(session, sitemap_url)
        if r and r.status_code == 200:
            for m in re.finditer(r'<loc>([^<]*/author/([^/<]+)/[^<]*)</loc>', r.text):
                slug = m.group(2)
                if not any(u.get("login") == slug for u in users.values()):
                    uid = f"sitemap_{slug}"
                    users[uid] = {
                        "id": "?", "login": slug, "name": slug,
                        "url": m.group(1), "avatar": "", "description": "",
                        "source": "sitemap",
                    }

    # ── oEmbed endpoint ───────────────────────────────────────────
    r = get(session, f"{base}/wp-json/oembed/1.0/embed?url={base}&format=json")
    if r and r.status_code == 200:
        try:
            data = r.json()
            author_name = data.get("author_name", "")
            author_url  = data.get("author_url", "")
            if author_name and not any(u.get("name") == author_name for u in users.values()):
                uid = f"oembed_{author_name}"
                users[uid] = {
                    "id": "?", "login": author_name, "name": author_name,
                    "url": author_url, "avatar": "", "description": "",
                    "source": "oEmbed",
                }
        except Exception:
            pass

    return list(users.values())


# ══════════════════════════════════════════════════════════════════
#  EMAIL HARVESTING
# ══════════════════════════════════════════════════════════════════
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
SKIP_DOMAINS = {"example.com", "domain.com", "sentry.io", "example.org",
                "wordpress.org", "schema.org", "w3.org", "yoursite.com"}

def harvest_emails(session, base, max_pages=10):
    emails = {}
    crawl_queue = [base, f"{base}/contact", f"{base}/about", f"{base}/about-us",
                   f"{base}/contact-us", f"{base}/team", f"{base}/our-team",
                   f"{base}/staff", f"{base}/sitemap.xml"]

    # Also grab links from homepage
    r = get(session, base)
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("/") or base in href:
                crawl_queue.append(urljoin(base, href))

    seen_urls = set()
    for url in crawl_queue[:max_pages]:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        r = get(session, url)
        if not r or r.status_code != 200:
            continue
        # Also check mailto: links
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            if a["href"].startswith("mailto:"):
                em = a["href"].replace("mailto:", "").split("?")[0].strip()
                if em and "@" in em:
                    domain = em.split("@")[-1].lower()
                    if domain not in SKIP_DOMAINS:
                        emails[em] = {"email": em, "source": url, "context": "mailto link"}
        # Regex scan
        for m in EMAIL_RE.finditer(r.text):
            em = m.group(0).lower()
            domain = em.split("@")[-1]
            if domain not in SKIP_DOMAINS and em not in emails:
                emails[em] = {"email": em, "source": url, "context": "page text"}

    return list(emails.values())


# ══════════════════════════════════════════════════════════════════
#  PLUGIN DETECTION
# ══════════════════════════════════════════════════════════════════
COMMON_PLUGINS = [
    "akismet","contact-form-7","woocommerce","jetpack","wordpress-seo","yoast-seo",
    "wordfence","wpforms-lite","elementor","classic-editor","updraftplus",
    "really-simple-ssl","litespeed-cache","all-in-one-wp-security-and-firewall",
    "wps-hide-login","wp-super-cache","wp-smushit","mailchimp-for-wp",
    "redirection","tablepress","wp-optimize","wp-file-manager",
    "advanced-custom-fields","shortcodes-ultimate","easy-digital-downloads",
    "buddypress","bbpress","wp-rocket","wp-mail-smtp","ninja-forms",
    "the-events-calendar","all-in-one-seo-pack","duplicate-page",
    "broken-link-checker","limit-login-attempts-reloaded","loginizer",
    "monsterinsights","rank-math","smush","sucuri-scanner","ithemes-security",
    "polylang","wpml","user-role-editor","members","ultimate-member",
    "enable-media-replace","regenerate-thumbnails","query-monitor",
    "health-check","debug-bar","wp-fastest-cache","w3-total-cache",
    "beaver-builder","divi","fusion-builder","wpbakery",
    "gravity-forms","formidable","forminator","fluent-forms",
    "mailpoet","newsletter","wp-ses","sendgrid","mailgun-for-wp",
    "woocommerce-subscriptions","woocommerce-payments","stripe-payments",
    "easy-paypal-donation","give","charitable","learnpress","learndash",
    "tutor","lifter-lms","memberpress","paid-memberships-pro",
    "wp-job-manager","wp-postratings","disqus-comment-system",
    "cookie-notice","cookie-law-info","gdpr-cookie-compliance",
    "wp-gdpr-compliance","complianz","cookiebot",
    "social-warfare","sassy-social-share","addtoany",
    "nextgen-gallery","envira-gallery","modula",
    "wp-table-of-contents","easy-table-of-contents",
    "schema-and-structured-data-for-wp","schema-markup-rich-snippets",
    "wp-seopress","squirrly-seo","the-seo-framework",
    "imagify","ewww-image-optimizer","shortpixel-image-optimiser",
    "autoptimize","fast-velocity-minify","sg-cachepress",
    "cloudflare","aruba-hispeed-cache","breeze",
    "translatepress-multilingual","gtranslate","google-language-translator",
    "wpcf7-recaptcha","recaptcha","advanced-google-recaptcha",
    "wp-statistics","statcounter","slimstat-analytics",
]

def probe_plugin(session, base, slug):
    for path in [
        f"{base}/wp-content/plugins/{slug}/readme.txt",
        f"{base}/wp-content/plugins/{slug}/README.txt",
        f"{base}/wp-content/plugins/{slug}/{slug}.php",
    ]:
        r = get(session, path)
        if r and r.status_code == 200 and len(r.text) > 20:
            text = r.text
            version   = None
            name      = slug
            desc      = ""
            requires  = ""
            tested_up = ""

            m = re.search(r'Stable tag:\s*([\d.]+)', text, re.I)
            if m: version = m.group(1)
            m = re.search(r'Version:\s*([\d.]+)', text, re.I)
            if m and not version: version = m.group(1)
            m = re.search(r'(?:Plugin Name|Name):\s*(.+)', text, re.I)
            if m: name = m.group(1).strip()
            m = re.search(r'(?:Description|Short Description):\s*(.+)', text, re.I)
            if m: desc = m.group(1).strip()[:120]
            m = re.search(r'Requires at least:\s*([\d.]+)', text, re.I)
            if m: requires = m.group(1)
            m = re.search(r'Tested up to:\s*([\d.]+)', text, re.I)
            if m: tested_up = m.group(1)

            return {
                "slug":        slug,
                "name":        name,
                "version":     version,
                "description": desc,
                "requires_wp": requires,
                "tested_up_to":tested_up,
                "accessible_file": path,
                "source":      "direct probe",
            }
    return None

def extract_plugins_from_source(session, base):
    found = {}
    pages = [base, f"{base}/", f"{base}/sitemap.xml"]
    for url in pages:
        r = get(session, url)
        if not r: continue
        for m in re.finditer(r'wp-content/plugins/([a-z0-9_-]+)/', r.text):
            slug = m.group(1)
            if slug not in found:
                found[slug] = {
                    "slug": slug, "name": slug, "version": None,
                    "source": "page source", "description": "",
                    "requires_wp": "", "tested_up_to": "", "accessible_file": "",
                }
    return found

def enumerate_plugins(session, base, threads=25):
    found = extract_plugins_from_source(session, base)
    info(f"Found {len(found)} plugins from page source")

    # REST API (if auth available)
    r = get(session, f"{base}/wp-json/wp/v2/plugins")
    if r and r.status_code == 200:
        try:
            for p in r.json():
                s = p.get("plugin", "").split("/")[0]
                if s:
                    found[s] = {
                        "slug": s, "name": p.get("name", s),
                        "version": p.get("version"), "description": "",
                        "source": "REST API", "requires_wp": "",
                        "tested_up_to": "", "accessible_file": "",
                    }
        except Exception:
            pass

    all_slugs = list(set(list(found.keys()) + COMMON_PLUGINS))

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe_plugin, session, base, sl): sl
                for sl in all_slugs if sl not in found}
        for fut in concurrent.futures.as_completed(futs):
            result = fut.result()
            if result:
                found[result["slug"]] = result

    return sorted(found.values(), key=lambda x: x["slug"])


# ══════════════════════════════════════════════════════════════════
#  THEME DETECTION
# ══════════════════════════════════════════════════════════════════
def enumerate_themes(session, base):
    themes = {}
    r = get(session, base)
    if r:
        for m in re.finditer(r'wp-content/themes/([a-z0-9_-]+)/', r.text):
            slug = m.group(1)
            themes[slug] = {"slug": slug}

    for slug in list(themes.keys()):
        r2 = get(session, f"{base}/wp-content/themes/{slug}/style.css")
        if r2 and r2.status_code == 200:
            txt = r2.text
            def grab(pat): m = re.search(pat, txt, re.I); return m.group(1).strip() if m else ""
            themes[slug].update({
                "name":        grab(r'Theme Name:\s*(.+)'),
                "version":     grab(r'Version:\s*([\d.]+)'),
                "author":      grab(r'Author:\s*(.+)'),
                "author_uri":  grab(r'Author URI:\s*(.+)'),
                "theme_uri":   grab(r'Theme URI:\s*(.+)'),
                "description": grab(r'Description:\s*(.+)')[:120],
                "template":    grab(r'Template:\s*(.+)'),  # parent theme
                "text_domain": grab(r'Text Domain:\s*(.+)'),
            })

    return list(themes.values())


# ══════════════════════════════════════════════════════════════════
#  SITE STRUCTURE MAPPING
# ══════════════════════════════════════════════════════════════════
def map_site_structure(session, base):
    structure = {
        "pages":       [],
        "categories":  [],
        "tags":        [],
        "posts":       [],
        "custom_post_types": [],
        "menus":       [],
        "media":       [],
    }

    # REST API pages
    r = get(session, f"{base}/wp-json/wp/v2/pages?per_page=50")
    if r and r.status_code == 200:
        try:
            for p in r.json():
                structure["pages"].append({
                    "id":     p.get("id"),
                    "title":  p.get("title", {}).get("rendered", ""),
                    "slug":   p.get("slug", ""),
                    "url":    p.get("link", ""),
                    "status": p.get("status", ""),
                    "template": p.get("template", ""),
                })
        except Exception:
            pass

    # REST API posts
    r = get(session, f"{base}/wp-json/wp/v2/posts?per_page=20")
    if r and r.status_code == 200:
        try:
            for p in r.json():
                structure["posts"].append({
                    "id":       p.get("id"),
                    "title":    p.get("title", {}).get("rendered", ""),
                    "slug":     p.get("slug", ""),
                    "url":      p.get("link", ""),
                    "date":     p.get("date", ""),
                    "author":   p.get("author"),
                    "categories": p.get("categories", []),
                })
        except Exception:
            pass

    # Categories
    r = get(session, f"{base}/wp-json/wp/v2/categories?per_page=50")
    if r and r.status_code == 200:
        try:
            for c in r.json():
                structure["categories"].append({
                    "id":    c.get("id"),
                    "name":  c.get("name", ""),
                    "slug":  c.get("slug", ""),
                    "count": c.get("count", 0),
                    "url":   c.get("link", ""),
                })
        except Exception:
            pass

    # Tags
    r = get(session, f"{base}/wp-json/wp/v2/tags?per_page=50")
    if r and r.status_code == 200:
        try:
            for t in r.json():
                structure["tags"].append({
                    "id":    t.get("id"),
                    "name":  t.get("name", ""),
                    "slug":  t.get("slug", ""),
                    "count": t.get("count", 0),
                })
        except Exception:
            pass

    # Custom post types
    r = get(session, f"{base}/wp-json/wp/v2/types")
    if r and r.status_code == 200:
        try:
            data = r.json()
            for cpt_slug, cpt_data in data.items():
                if cpt_slug not in ("post", "page", "attachment", "revision",
                                    "nav_menu_item", "custom_css", "customize_changeset",
                                    "oembed_cache", "user_request", "wp_block", "wp_template"):
                    structure["custom_post_types"].append({
                        "slug":        cpt_slug,
                        "name":        cpt_data.get("name", cpt_slug),
                        "rest_base":   cpt_data.get("rest_base", ""),
                        "description": cpt_data.get("description", ""),
                    })
        except Exception:
            pass

    # Menus
    r = get(session, f"{base}/wp-json/wp/v2/menus")
    if r and r.status_code == 200:
        try:
            for m in r.json():
                structure["menus"].append({
                    "id":   m.get("id"),
                    "name": m.get("name", ""),
                    "slug": m.get("slug", ""),
                    "count": m.get("count", 0),
                })
        except Exception:
            pass

    # Sitemap parsing
    r = get(session, f"{base}/sitemap.xml")
    if not r or r.status_code != 200:
        r = get(session, f"{base}/sitemap_index.xml")
    if r and r.status_code == 200:
        urls = re.findall(r'<loc>([^<]+)</loc>', r.text)
        structure["sitemap_urls"] = urls[:100]

    # Robots.txt
    r = get(session, f"{base}/robots.txt")
    if r and r.status_code == 200:
        structure["robots_txt"] = r.text.strip()

    return structure


# ══════════════════════════════════════════════════════════════════
#  SECURITY EXPOSURE CHECKS (passive only)
# ══════════════════════════════════════════════════════════════════
SENSITIVE_PATHS = [
    # WordPress core
    ("/wp-login.php",                    "Admin login page"),
    ("/wp-admin/",                       "Admin dashboard"),
    ("/xmlrpc.php",                      "XML-RPC endpoint"),
    ("/wp-cron.php",                     "WP-Cron"),
    ("/wp-config.php",                   "Config file"),
    ("/wp-config.php.bak",               "Config backup"),
    ("/wp-config.bak",                   "Config backup"),
    ("/wp-config.old",                   "Config backup"),
    ("/wp-config~",                      "Config backup (tilde)"),
    ("/readme.html",                     "Readme (version leak)"),
    ("/license.txt",                     "License file"),
    ("/wp-content/debug.log",            "Debug log"),
    ("/wp-content/uploads/",             "Uploads directory"),
    ("/wp-content/plugins/",             "Plugins directory"),
    ("/wp-content/themes/",              "Themes directory"),
    ("/wp-includes/",                    "WP Includes"),
    # System files
    ("/.env",                            ".env file"),
    ("/.htaccess",                       ".htaccess"),
    ("/.htpasswd",                       ".htpasswd"),
    ("/.git/HEAD",                       "Git HEAD"),
    ("/.git/config",                     "Git config"),
    ("/phpinfo.php",                     "phpinfo()"),
    ("/info.php",                        "phpinfo()"),
    ("/php.php",                         "phpinfo()"),
    ("/test.php",                        "Test PHP file"),
    ("/server-status",                   "Apache server-status"),
    ("/server-info",                     "Apache server-info"),
    # Backups
    ("/backup.zip",                      "Backup archive"),
    ("/backup.tar.gz",                   "Backup archive"),
    ("/site.zip",                        "Site backup"),
    ("/www.zip",                         "Site backup"),
    ("/wordpress.zip",                   "WordPress backup"),
    ("/db.sql",                          "Database dump"),
    ("/database.sql",                    "Database dump"),
    ("/wp-content/uploads/db.sql",       "DB dump in uploads"),
    # Other
    ("/wp-json/",                        "REST API root"),
    ("/wp-json/wp/v2/users",             "REST users endpoint"),
    ("/wp-trackback.php",                "Trackbacks"),
    ("/wp-comments-post.php",            "Comments endpoint"),
    ("/sitemap.xml",                     "Sitemap"),
    ("/sitemap_index.xml",               "Sitemap index"),
    ("/robots.txt",                      "Robots.txt"),
]

def check_exposures(session, base):
    results = []
    for path, label in SENSITIVE_PATHS:
        url = base + path
        r = get(session, url, allow_redirects=False)
        if not r:
            continue
        entry = {
            "path":  path,
            "label": label,
            "url":   url,
            "status": r.status_code,
            "size":  len(r.content),
        }
        if r.status_code in (200, 403):
            results.append(entry)

    return results

def check_security_headers(session, base):
    r = get(session, base)
    if not r:
        return {}
    h = {k.lower(): v for k, v in r.headers.items()}
    header_checks = {
        "Strict-Transport-Security": "strict-transport-security",
        "Content-Security-Policy":   "content-security-policy",
        "X-Frame-Options":           "x-frame-options",
        "X-Content-Type-Options":    "x-content-type-options",
        "Referrer-Policy":           "referrer-policy",
        "Permissions-Policy":        "permissions-policy",
        "X-XSS-Protection":          "x-xss-protection",
        "Cross-Origin-Opener-Policy":"cross-origin-opener-policy",
        "Cross-Origin-Resource-Policy":"cross-origin-resource-policy",
    }
    return {name: h.get(key, "MISSING") for name, key in header_checks.items()}


# ══════════════════════════════════════════════════════════════════
#  REST API RECONNAISSANCE
# ══════════════════════════════════════════════════════════════════
def probe_rest_api(session, base):
    info_map = {}
    r = get(session, f"{base}/wp-json/")
    if r and r.status_code == 200:
        try:
            data = r.json()
            info_map["name"]        = data.get("name", "")
            info_map["description"] = data.get("description", "")
            info_map["url"]         = data.get("url", "")
            info_map["home"]        = data.get("home", "")
            info_map["gmt_offset"]  = data.get("gmt_offset")
            info_map["timezone"]    = data.get("timezone_string", "")
            info_map["namespaces"]  = data.get("namespaces", [])
            info_map["wp_version"]  = data.get("wp_version") or data.get("version", "")
            # Exposed routes (top-level keys)
            routes = list(data.get("routes", {}).keys())
            info_map["route_count"] = len(routes)
            info_map["routes_sample"] = routes[:30]
        except Exception:
            pass
    return info_map


# ══════════════════════════════════════════════════════════════════
#  SOCIAL MEDIA & CONTACT INFO
# ══════════════════════════════════════════════════════════════════
SOCIAL_PATTERNS = {
    "Facebook":   r'facebook\.com/(?!sharer|share|plugins|dialog|permalink)([a-zA-Z0-9.\-_/]+)',
    "Twitter/X":  r'(?:twitter|x)\.com/([a-zA-Z0-9_]+)',
    "Instagram":  r'instagram\.com/([a-zA-Z0-9_.]+)',
    "LinkedIn":   r'linkedin\.com/(?:company|in)/([a-zA-Z0-9._-]+)',
    "YouTube":    r'youtube\.com/(?:channel|c|user)/([a-zA-Z0-9_-]+)',
    "TikTok":     r'tiktok\.com/@([a-zA-Z0-9_.]+)',
    "Pinterest":  r'pinterest\.com/([a-zA-Z0-9_/]+)',
    "GitHub":     r'github\.com/([a-zA-Z0-9_-]+)',
    "Telegram":   r't\.me/([a-zA-Z0-9_]+)',
    "WhatsApp":   r'wa\.me/([0-9+]+)',
}
PHONE_RE = re.compile(r'(?:tel:|phone:)?\+?[\d\s\-().]{10,20}(?=\s|<|"|\')', re.I)

def extract_social_and_contact(session, base):
    social  = defaultdict(set)
    phones  = set()

    pages = [base, f"{base}/contact", f"{base}/about", f"{base}/about-us",
             f"{base}/contact-us", f"{base}/", f"{base}/?page_id=2"]

    for url in pages:
        r = get(session, url)
        if not r or r.status_code != 200:
            continue
        for platform, pat in SOCIAL_PATTERNS.items():
            for m in re.finditer(pat, r.text, re.I):
                handle = m.group(1).strip("/").split("?")[0]
                if 3 < len(handle) < 60:
                    social[platform].add(handle)

        # Phone numbers via tel: links
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            if a["href"].startswith("tel:"):
                phones.add(a["href"].replace("tel:", "").strip())

    return {
        "social_media": {k: list(v) for k, v in social.items()},
        "phones":       list(phones),
    }


# ══════════════════════════════════════════════════════════════════
#  KNOWN VULNERABILITY LOOKUP  (offline CVE map — no auth needed)
# ══════════════════════════════════════════════════════════════════
# A curated sample of high-profile WordPress plugin CVEs
PLUGIN_VULN_DB = {
    "elementor":             [{"cve": "CVE-2023-48777", "severity": "CRITICAL", "desc": "Arbitrary file upload via unprotected REST route", "fixed_in": "3.18.2"}],
    "wpforms-lite":          [{"cve": "CVE-2024-2783",  "severity": "HIGH",     "desc": "Missing capability check on form deletion", "fixed_in": "1.8.8"}],
    "contact-form-7":        [{"cve": "CVE-2023-6449",  "severity": "HIGH",     "desc": "Unrestricted file upload", "fixed_in": "5.8.4"}],
    "wp-file-manager":       [{"cve": "CVE-2020-25213", "severity": "CRITICAL", "desc": "Unauthenticated RCE via elFinder", "fixed_in": "6.9"}],
    "wordfence":             [{"cve": "CVE-2023-2007",  "severity": "MEDIUM",   "desc": "IP bypass via header spoofing", "fixed_in": "7.10.3"}],
    "jetpack":               [{"cve": "CVE-2023-2996",  "severity": "HIGH",     "desc": "Shortcode injection leading to XSS", "fixed_in": "12.1.1"}],
    "woocommerce":           [{"cve": "CVE-2021-32789", "severity": "HIGH",     "desc": "SQL injection via order search", "fixed_in": "5.5.1"}],
    "updraftplus":           [{"cve": "CVE-2023-32960", "severity": "HIGH",     "desc": "Insecure direct object reference", "fixed_in": "1.23.9"}],
    "advanced-custom-fields":[{"cve": "CVE-2023-30777", "severity": "HIGH",     "desc": "Reflected XSS in admin field builder", "fixed_in": "6.1.6"}],
    "slider-revolution":     [{"cve": "CVE-2014-9734",  "severity": "CRITICAL", "desc": "Arbitrary file download (old versions)", "fixed_in": "4.2"}],
    "wpml":                  [{"cve": "CVE-2024-6386",  "severity": "CRITICAL", "desc": "RCE via Server-Side Template Injection in WPML shortcode", "fixed_in": "4.6.13"}],
    "litespeed-cache":       [{"cve": "CVE-2024-44000", "severity": "CRITICAL", "desc": "Unauthenticated privilege escalation via cookie stealing", "fixed_in": "6.5.1"}],
    "really-simple-ssl":     [{"cve": "CVE-2024-10924", "severity": "CRITICAL", "desc": "Authentication bypass in 2FA implementation", "fixed_in": "9.1.2"}],
    "loginizer":             [{"cve": "CVE-2020-27615", "severity": "CRITICAL", "desc": "SQL injection in username field", "fixed_in": "1.6.4"}],
    "all-in-one-seo-pack":   [{"cve": "CVE-2021-25036", "severity": "HIGH",     "desc": "Privilege escalation via broken access control", "fixed_in": "4.1.5.2"}],
    "yoast-seo":             [{"cve": "CVE-2021-25116", "severity": "MEDIUM",   "desc": "Reflected XSS via get parameter", "fixed_in": "17.3"}],
    "ninja-forms":           [{"cve": "CVE-2022-34819", "severity": "CRITICAL", "desc": "Code injection — arbitrary code execution", "fixed_in": "3.6.11"}],
}

def lookup_vulnerabilities(plugins):
    vulns = []
    for p in plugins:
        slug = p.get("slug", "")
        if slug in PLUGIN_VULN_DB:
            for v in PLUGIN_VULN_DB[slug]:
                vulns.append({
                    "plugin":   slug,
                    "version":  p.get("version", "?"),
                    **v,
                    "note": "Verify actual version before assuming vulnerable"
                })
    return vulns


# ══════════════════════════════════════════════════════════════════
#  PRETTY PRINT REPORT
# ══════════════════════════════════════════════════════════════════
def print_report(data):
    r = data["results"]

    # Server info
    section("Server & Technology Fingerprint", "🖥")
    sv = r.get("server_info", {})
    if sv.get("server"):       info(f"Server:         {sv['server']}")
    if sv.get("x_powered_by"): warn(f"X-Powered-By:   {sv['x_powered_by']}")
    if sv.get("php_version"):  warn(f"PHP Version:    {sv['php_version']}")
    if sv.get("protocol"):     info(f"Protocol:       {sv['protocol']}")
    if sv.get("waf_cdn"):      good(f"WAF / CDN:      {', '.join(sv['waf_cdn'])}")
    if sv.get("ssl_issuer"):   info(f"SSL Issuer:     {sv.get('ssl_issuer', {}).get('O', '')}")
    if sv.get("ssl_expires"):  info(f"SSL Expires:    {sv['ssl_expires']}")
    if sv.get("response_time_ms"): info(f"Response time:  {sv['response_time_ms']}ms")
    tech = sv.get("technologies", [])
    if tech: info(f"Technologies:   {', '.join(tech)}")
    if sv.get("cookies"):      info(f"Cookies:        {', '.join(sv['cookies'].keys())}")

    # REST API
    section("REST API Info", "🔗")
    api = r.get("rest_api", {})
    if api.get("name"):        info(f"Site name:      {api['name']}")
    if api.get("description"): info(f"Description:    {api['description']}")
    if api.get("timezone"):    info(f"Timezone:       {api['timezone']}")
    if api.get("wp_version"):  warn(f"WP version (API):{api['wp_version']}")
    if api.get("namespaces"):  info(f"Namespaces:     {', '.join(api['namespaces'][:8])}")
    if api.get("route_count"): info(f"API Routes:     {api['route_count']} total")

    # WP Version
    section("WordPress Version", "🔢")
    versions = r.get("wp_version", {})
    if versions:
        for src, ver in versions.items():
            warn(f"Version {ver}  (from {src})")
    else:
        good("Version not publicly exposed")

    # Users
    section("Users / Admins", "👤")
    users = r.get("users", [])
    if users:
        for u in users:
            bad(f"ID={u['id']}  login={u['login']}  name=\"{u['name']}\"  [{u['source']}]")
            if u.get("url"):    dim(f"         Profile: {u['url']}")
            if u.get("avatar"): dim(f"         Avatar:  {u['avatar']}")
    else:
        good("No users enumerated")

    # Emails
    section("Email Addresses Found", "📧")
    emails = r.get("emails", [])
    if emails:
        for e in emails:
            warn(f"{e['email']}  [{e['context']} — {e['source']}]")
    else:
        good("No emails found")

    # Social / contact
    section("Social Media & Phone Numbers", "🌐")
    social = r.get("social_contact", {})
    for platform, handles in social.get("social_media", {}).items():
        info(f"{platform}: {', '.join(handles)}")
    for phone in social.get("phones", []):
        info(f"Phone: {phone}")

    # Site structure
    section("Site Structure", "🗺")
    struct = r.get("structure", {})
    pages = struct.get("pages", [])
    if pages:
        info(f"Pages ({len(pages)}):")
        for p in pages[:15]:
            dim(f"  [{p.get('status','?')}] {p.get('title','')} → {p.get('url','')}")
    posts = struct.get("posts", [])
    if posts:
        info(f"Recent posts ({len(posts)}):")
        for p in posts[:5]:
            dim(f"  {p.get('date','')[:10]}  {p.get('title','')}")
    cats = struct.get("categories", [])
    if cats:
        info(f"Categories: {', '.join(c['name'] for c in cats[:10])}")
    tags = struct.get("tags", [])
    if tags:
        info(f"Tags ({len(tags)}): {', '.join(t['name'] for t in tags[:10])}")
    cpts = struct.get("custom_post_types", [])
    if cpts:
        info(f"Custom post types: {', '.join(c['slug'] for c in cpts)}")
    menus = struct.get("menus", [])
    if menus:
        info(f"Menus: {', '.join(m['name'] for m in menus)}")

    # Plugins
    section(f"Plugins Detected ({len(r.get('plugins',[]))})", "🔌")
    for p in r.get("plugins", []):
        ver = p.get("version") or "unknown"
        src = p.get("source", "")
        name = p.get("name") or p.get("slug")
        warn(f"{name} ({p['slug']})  v{ver}  [{src}]")
        if p.get("description"): dim(f"    {p['description']}")

    # Themes
    section("Themes", "🎨")
    for t in r.get("themes", []):
        name = t.get("name") or t["slug"]
        info(f"{name} ({t['slug']})  v{t.get('version','?')}  by {t.get('author','?')}")
        if t.get("template"): dim(f"    Parent theme: {t['template']}")

    # Vulnerabilities
    section("Known Vulnerabilities (by installed plugins)", "⚠️")
    vulns = r.get("vulnerabilities", [])
    if vulns:
        for v in vulns:
            bad(f"{v['plugin']} — {v['cve']} [{v['severity']}]")
            dim(f"    {v['desc']}")
            dim(f"    Fixed in: {v['fixed_in']}  |  Installed: {v['version']}")
            dim(f"    {v['note']}")
    else:
        good("No known CVEs matched detected plugins")

    # Security checks
    section("Security Checks", "🔒")
    sec = r.get("security", {})
    for path_info in sec.get("exposures", []):
        st = path_info["status"]
        label = path_info["label"]
        path  = path_info["path"]
        size  = path_info["size"]
        if st == 200:
            bad(f"[{st}] {label:35s} {path}  ({size} bytes)")
        else:
            warn(f"[{st}] {label:35s} {path}")

    print(f"\n  {C.BOLD}HTTP Security Headers:{C.RESET}")
    for header, val in sec.get("headers", {}).items():
        if val == "MISSING":
            warn(f"MISSING  {header}")
        else:
            good(f"Present  {header}: {val[:80]}")


# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="WP-Recon Pro — Passive WordPress reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wp_recon.py https://example.com
  python wp_recon.py https://example.com -o report.json
  python wp_recon.py https://example.com --proxy http://127.0.0.1:8080 --threads 30
  python wp_recon.py https://example.com --skip-plugins --skip-emails
        """
    )
    parser.add_argument("url",          help="Target WordPress site URL")
    parser.add_argument("-o","--output",help="Save JSON report to file",  default=None)
    parser.add_argument("--proxy",      help="HTTP/S proxy",              default=None)
    parser.add_argument("--ua",         help="Custom User-Agent",         default=None)
    parser.add_argument("--threads",    type=int, default=25,             help="Plugin probe threads (default: 25)")
    parser.add_argument("--timeout",    type=int, default=12,             help="HTTP timeout in seconds (default: 12)")
    parser.add_argument("--skip-plugins",  action="store_true", help="Skip plugin enumeration")
    parser.add_argument("--skip-emails",   action="store_true", help="Skip email harvesting")
    parser.add_argument("--skip-structure",action="store_true", help="Skip site structure mapping")
    args = parser.parse_args()

    target  = normalize(args.url)
    session = make_session(user_agent=args.ua, proxy=args.proxy, timeout=args.timeout)

    print(f"  {C.BOLD}Target:{C.RESET}  {target}")
    print(f"  {C.BOLD}Time:{C.RESET}    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {C.YELLOW}[!] Only scan sites you own or have written permission to audit.{C.RESET}")

    # ── Detect WordPress ──────────────────────────────────────────
    print(f"\n{C.BOLD}[*] Checking for WordPress...{C.RESET}")
    signals = detect_wordpress(session, target)
    if not signals:
        bad(f"WordPress not detected at {target}")
        sys.exit(1)
    good(f"WordPress confirmed ({', '.join(signals[:3])})")

    report = {
        "target":     target,
        "scanned_at": str(datetime.now()),
        "results":    {}
    }
    R = report["results"]

    # ── Server fingerprint ────────────────────────────────────────
    print(f"\n{C.DIM}[*] Fingerprinting server...{C.RESET}")
    R["server_info"] = fingerprint_server(session, target)

    # ── REST API ──────────────────────────────────────────────────
    print(f"{C.DIM}[*] Probing REST API...{C.RESET}")
    R["rest_api"] = probe_rest_api(session, target)

    # ── WP Version ───────────────────────────────────────────────
    print(f"{C.DIM}[*] Detecting WordPress version...{C.RESET}")
    R["wp_version"] = detect_wp_version(session, target)

    # ── Users ─────────────────────────────────────────────────────
    print(f"{C.DIM}[*] Enumerating users...{C.RESET}")
    R["users"] = enumerate_users(session, target)

    # ── Emails ────────────────────────────────────────────────────
    if not args.skip_emails:
        print(f"{C.DIM}[*] Harvesting emails...{C.RESET}")
        R["emails"] = harvest_emails(session, target)
    else:
        R["emails"] = []

    # ── Social / Contact ─────────────────────────────────────────
    print(f"{C.DIM}[*] Extracting social media & contact info...{C.RESET}")
    R["social_contact"] = extract_social_and_contact(session, target)

    # ── Site structure ────────────────────────────────────────────
    if not args.skip_structure:
        print(f"{C.DIM}[*] Mapping site structure...{C.RESET}")
        R["structure"] = map_site_structure(session, target)
    else:
        R["structure"] = {}

    # ── Plugins ───────────────────────────────────────────────────
    if not args.skip_plugins:
        print(f"{C.DIM}[*] Enumerating plugins (this may take a moment)...{C.RESET}")
        R["plugins"] = enumerate_plugins(session, target, threads=args.threads)
    else:
        R["plugins"] = []

    # ── Themes ────────────────────────────────────────────────────
    print(f"{C.DIM}[*] Detecting themes...{C.RESET}")
    R["themes"] = enumerate_themes(session, target)

    # ── Vulnerabilities ───────────────────────────────────────────
    R["vulnerabilities"] = lookup_vulnerabilities(R.get("plugins", []))

    # ── Security / Exposures ──────────────────────────────────────
    print(f"{C.DIM}[*] Checking exposed paths & security headers...{C.RESET}")
    R["security"] = {
        "exposures": check_exposures(session, target),
        "headers":   check_security_headers(session, target),
    }

    # ── Print ─────────────────────────────────────────────────────
    print_report(report)

    # ── Save JSON ─────────────────────────────────────────────────
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        good(f"\nJSON report saved → {args.output}")

    print(f"\n{C.BOLD}{C.GREEN}Scan complete.{C.RESET}\n")


if __name__ == "__main__":
    main()
