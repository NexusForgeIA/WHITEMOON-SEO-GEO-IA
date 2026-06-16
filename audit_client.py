#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoría GEO IA — WhiteMoon Agencia IA · whitemoon.es

Herramienta interna para auditar la visibilidad de webs de clientes en
motores de IA (ChatGPT, Claude, Perplexity, Grok) y buscadores.

Uso:
    python audit_client.py https://cliente.es "Nombre Cliente" "sector" "ciudad"

Genera: reports/audit-{dominio}-{fecha}.md
"""

import base64
import io
import json
import os
import re
import sys
import time
import unicodedata
from datetime import date
from pathlib import Path
from urllib.parse import quote_plus, urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("❌ Faltan dependencias. Instala con:  pip install -r requirements.txt")
    sys.exit(1)

USER_AGENT = "Mozilla/5.0 (compatible; WhiteMoon-Audit/1.0)"
HEADERS = {"User-Agent": USER_AGENT, "Accept-Language": "es-ES,es;q=0.9"}
# Headers de navegador real para búsquedas en Google (best-effort; Google
# suele mostrar muro de consentimiento o captcha a peticiones automatizadas).
BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
    "Accept-Language": "es-ES,es;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
TIMEOUT = 25
TIMEOUT_SHORT = 10  # peticiones a terceros (competidores, directorios): no bloquear la auditoría

# API gratuita de PageSpeed Insights (obtener key en Google Cloud Console)
PAGESPEED_API_KEY = os.environ.get("PAGESPEED_API_KEY", "").strip()
PAGESPEED_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"

AI_BOTS = ["GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended"]

# Directorios locales por sector (siempre 4 → área "directorios" vale 4 pts fijos)
DIRECTORIOS_BASE = ["paginasamarillas.es", "yelp.es"]
DIRECTORIOS_SECTOR = {
    "hosteleria": ["tripadvisor.es", "eltenedor.es"],
    "hotel": ["tripadvisor.es", "booking.com"],
    "inmobiliaria": ["idealista.com", "fotocasa.es"],
    "dental": ["doctoralia.es", "cylex.es"],
    "podologia": ["doctoralia.es", "cylex.es"],
    "estetica": ["treatwell.es", "cylex.es"],
    "abogados": ["cylex.es", "infoisinfo.es"],
    "gestoria": ["cylex.es", "infoisinfo.es"],
}
DIRECTORIOS_DEFAULT = ["cylex.es", "infoisinfo.es"]

LOCALBUSINESS_HINTS = (
    "localbusiness", "dentist", "restaurant", "store", "medicalbusiness",
    "professionalservice", "legalservice", "attorney", "physician",
    "realestateagent", "autorepair", "hairsalon", "beautysalon", "plumber",
    "electrician", "homeandconstructionbusiness", "foodestablishment",
    "lodgingbusiness", "financialservice", "travelagency", "veterinarycare",
)

# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 1 — FETCH
# ──────────────────────────────────────────────────────────────────────────────

def fetch_site(url, html_manual=None):
    """Descarga la página principal, robots.txt y llms.txt.

    Con html_manual (HTML pegado a mano cuando la web bloquea el fetch,
    p. ej. Cloudflare/403) se omite la descarga de la página principal y
    se analiza ese HTML; robots.txt y llms.txt se intentan igualmente.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if html_manual:
        root = "{0}://{1}".format(urlparse(url).scheme, urlparse(url).netloc)
        html = html_manual.encode("utf-8")
        return {"url": url, "root": root, "html": html,
                "soup": BeautifulSoup(html, "html.parser"),
                "robots": _fetch_optional(root + "/robots.txt"),
                "llms": _fetch_optional(root + "/llms.txt")}

    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
    except requests.exceptions.SSLError:
        _die("Error SSL al conectar con %s.\n   Sugerencia: el certificado es inválido o ha caducado. "
             "Prueba con http:// o revisa el certificado del cliente." % url)
    except requests.exceptions.ConnectTimeout:
        _die("Timeout conectando con %s.\n   Sugerencia: el servidor tarda demasiado. "
             "Verifica que la web está online y vuelve a intentarlo." % url)
    except requests.exceptions.ConnectionError:
        _die("No se pudo conectar con %s.\n   Sugerencia: comprueba que el dominio existe "
             "y que está bien escrito (¿falta www?)." % url)

    if resp.status_code >= 400:
        hints = {
            403: "el servidor bloquea bots (WAF/Cloudflare). Pide al cliente que permita el User-Agent WhiteMoon-Audit.",
            404: "la URL no existe. Revisa la ruta o prueba con la home del dominio.",
            429: "demasiadas peticiones. Espera unos minutos y reintenta.",
            500: "error interno del servidor del cliente. Reintenta más tarde.",
            503: "servicio no disponible (mantenimiento o bloqueo anti-bot).",
        }
        hint = hints.get(resp.status_code, "revisa la URL y reintenta.")
        _die("La web devolvió HTTP %d al pedir %s.\n   Sugerencia: %s" % (resp.status_code, url, hint))

    final_url = resp.url
    # root = URL base incluyendo el path (sin trailing slash), para que robots.txt
    # y llms.txt se busquen relativos al sitio. Caso típico: GitHub Pages de proyecto
    # (https://user.github.io/PROYECTO/) donde el sitio NO vive en el dominio raíz.
    parsed = urlparse(final_url)
    path = parsed.path
    # Si el path apunta a un fichero (último segmento con extensión), usar su directorio.
    if "." in path.rsplit("/", 1)[-1]:
        path = path.rsplit("/", 1)[0]
    root = "{0}://{1}{2}".format(parsed.scheme, parsed.netloc, path.rstrip("/"))

    robots_txt = _fetch_optional(root + "/robots.txt")
    llms_txt = _fetch_optional(root + "/llms.txt")

    # Parsear desde bytes: BeautifulSoup detecta el charset del documento
    # (evita mojibake cuando el servidor no declara charset en las cabeceras)
    soup = BeautifulSoup(resp.content, "html.parser")
    return {"url": final_url, "root": root, "html": resp.content, "soup": soup,
            "robots": robots_txt, "llms": llms_txt}


def _fetch_optional(url, timeout=TIMEOUT):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        if r.status_code == 200 and "<html" not in r.text[:500].lower():
            return r.text
    except requests.exceptions.RequestException:
        pass
    return None


class AuditError(Exception):
    """Error de auditoría con mensaje claro para el usuario."""


def _die(msg):
    raise AuditError(msg)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers de análisis
# ──────────────────────────────────────────────────────────────────────────────

def _norm(text):
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode()
    return text.lower().strip()


def meta_content(soup, name=None, prop=None):
    if name:
        tag = soup.find("meta", attrs={"name": re.compile("^%s$" % re.escape(name), re.I)})
    else:
        tag = soup.find("meta", attrs={"property": re.compile("^%s$" % re.escape(prop), re.I)})
    return (tag.get("content") or "").strip() if tag else None


def collect_jsonld(soup):
    """Devuelve (nodos, bloques_totales, bloques_invalidos). Aplana @graph y anidados."""
    nodes, total, invalid = [], 0, 0

    def walk(data):
        if isinstance(data, list):
            for item in data:
                walk(item)
        elif isinstance(data, dict):
            if data.get("@type"):
                nodes.append(data)
            for value in data.values():
                walk(value)

    for script in soup.find_all("script", type=re.compile("application/ld\\+json", re.I)):
        total += 1
        raw = script.string or script.get_text() or ""
        try:
            walk(json.loads(raw.strip()))
        except (json.JSONDecodeError, ValueError):
            invalid += 1
    return nodes, total, invalid


def node_types(node):
    t = node.get("@type", [])
    return [t] if isinstance(t, str) else list(t)


def find_nodes(nodes, type_name):
    return [n for n in nodes if any(_norm(t) == _norm(type_name) for t in node_types(n))]


def find_localbusiness(nodes):
    out = []
    for n in nodes:
        for t in node_types(n):
            tl = _norm(t)
            if "business" in tl or tl in LOCALBUSINESS_HINTS:
                out.append(n)
                break
    return out


def count_visible_faq(soup):
    """Cuenta preguntas FAQ visibles en el DOM (details, .faq, accordion, ¿…?)."""
    n_details = len(soup.select("details summary"))
    questions = set()
    for el in soup.find_all(["h2", "h3", "h4", "summary", "button", "strong", "dt"]):
        txt = el.get_text(strip=True)
        if 8 <= len(txt) <= 200 and (txt.endswith("?") or txt.startswith("¿")):
            questions.add(txt)
    has_container = bool(soup.select('[class*="faq" i], [class*="accordion" i], [id*="faq" i]'))
    count = max(n_details, len(questions))
    if count == 0 and has_container:
        count = 1
    return count


def parse_robots_groups(text):
    """Parsea robots.txt en grupos {agents, disallows, allows}."""
    groups, agents, rules_started = [], [], False
    cur = None
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "user-agent":
            if rules_started or cur is None:
                cur = {"agents": [], "disallows": [], "allows": []}
                groups.append(cur)
                rules_started = False
            cur["agents"].append(val.lower())
        elif key in ("disallow", "allow") and cur is not None:
            rules_started = True
            cur["disallows" if key == "disallow" else "allows"].append(val)
    return groups


def bot_access(robots_text, bot):
    """→ 'allowed' | 'blocked' | 'implicit' | 'no_robots'"""
    if robots_text is None:
        return "no_robots"
    groups = parse_robots_groups(robots_text)
    specific = [g for g in groups if bot.lower() in g["agents"]]
    wildcard = [g for g in groups if "*" in g["agents"]]
    target = specific or wildcard
    if not target:
        return "implicit"
    blocked = any("/" in [d.strip() for d in g["disallows"] if d.strip() == "/"] for g in target)
    root_allowed = any(a.strip() in ("/", "") for g in target for a in g["allows"])
    if blocked and not root_allowed:
        return "blocked"
    return "allowed" if specific else "implicit"


# ──────────────────────────────────────────────────────────────────────────────
# Motor de checks
# ──────────────────────────────────────────────────────────────────────────────

class Audit:
    def __init__(self):
        self.checks = []  # cada check: dict

    def add(self, area, cid, label, status, points, max_points, detail=""):
        self.checks.append({
            "area": area, "id": cid, "label": label, "status": status,
            "points": round(points, 2), "max": max_points, "detail": detail,
        })

    def area_score(self, *areas):
        sel = [c for c in self.checks if c["area"] in areas]
        return round(sum(c["points"] for c in sel), 1), round(sum(c["max"] for c in sel), 1)

    def failed(self):
        return [c for c in self.checks if c["status"] in ("warn", "error") and c["points"] < c["max"]]


STATUS_EMOJI = {"ok": "✅", "warn": "⚠️", "error": "❌", "info": "ℹ️"}


def fmt_pts(v):
    return ("%g" % round(v, 1))


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 2 — SEO TÉCNICO (63 pts: META 12 + ESTRUCTURA 16 + SCHEMA 27 + ROBOTS 8)
# ──────────────────────────────────────────────────────────────────────────────

def check_meta_tags(a, site, ctx):
    soup = site["soup"]

    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""
    ctx["title"] = title
    if title:
        a.add("meta", "title", "Etiqueta <title> presente", "ok", 2, 2, '"%s"' % title[:90])
    else:
        a.add("meta", "title", "Etiqueta <title> presente", "error", 0, 2, "No existe <title>")
    if title and len(title) <= 65:
        a.add("meta", "title_len", "<title> ≤ 65 caracteres", "ok", 1, 1, "%d caracteres" % len(title))
    else:
        a.add("meta", "title_len", "<title> ≤ 65 caracteres",
              "warn" if title else "error", 0, 1,
              "%d caracteres (se trunca en resultados)" % len(title) if title else "Sin título")
    kw_hit = any(tok and tok in _norm(title)
                 for tok in [_norm(ctx["nombre"]).split()[0] if ctx["nombre"] else "",
                             _norm(ctx["sector"]), _norm(ctx["ciudad"])])
    a.add("meta", "title_kw", "<title> contiene marca o keyword",
          "ok" if kw_hit else "warn", 1 if kw_hit else 0, 1,
          "Detectada marca/keyword en el título" if kw_hit
          else "El título no menciona ni la marca, ni el sector, ni la ciudad")

    desc = meta_content(soup, name="description")
    if desc:
        a.add("meta", "desc", "Meta description presente", "ok", 2, 2, '"%s…"' % desc[:80])
        ok_len = len(desc) <= 160
        a.add("meta", "desc_len", "Meta description ≤ 160 caracteres",
              "ok" if ok_len else "warn", 1 if ok_len else 0, 1, "%d caracteres" % len(desc))
    else:
        a.add("meta", "desc", "Meta description presente", "error", 0, 2, "No existe")
        a.add("meta", "desc_len", "Meta description ≤ 160 caracteres", "error", 0, 1, "No existe")

    canon = soup.find("link", rel=lambda v: v and "canonical" in v)
    canon_href = (canon.get("href") or "").strip() if canon else ""
    def _n(u):
        p = urlparse(u)
        return (p.netloc.lower().replace("www.", ""), p.path.rstrip("/") or "/")
    if canon_href and _n(urljoin(site["url"], canon_href)) == _n(site["url"]):
        a.add("meta", "canonical", "Canonical self-referente", "ok", 1, 1, canon_href)
    elif canon_href:
        a.add("meta", "canonical", "Canonical self-referente", "warn", 0, 1,
              "Apunta a %s (no coincide con la URL auditada)" % canon_href)
    else:
        a.add("meta", "canonical", "Canonical self-referente", "error", 0, 1, "No existe")

    og_t, og_d = meta_content(soup, prop="og:title"), meta_content(soup, prop="og:description")
    if og_t and og_d:
        a.add("meta", "og_td", "og:title y og:description", "ok", 1, 1)
    else:
        missing = [x for x, v in [("og:title", og_t), ("og:description", og_d)] if not v]
        a.add("meta", "og_td", "og:title y og:description", "error", 0.5 if (og_t or og_d) else 0, 1,
              "Falta: " + ", ".join(missing))

    og_img = meta_content(soup, prop="og:image")
    if og_img and not og_img.lower().split("?")[0].endswith(".svg"):
        a.add("meta", "og_img", "og:image presente (no SVG)", "ok", 1, 1, og_img[:90])
    elif og_img:
        a.add("meta", "og_img", "og:image presente (no SVG)", "error", 0, 1,
              "Es SVG: la mayoría de plataformas (WhatsApp, LinkedIn, iMessage) no lo renderizan")
    else:
        a.add("meta", "og_img", "og:image presente (no SVG)", "error", 0, 1, "No existe")

    w = meta_content(soup, prop="og:image:width")
    h = meta_content(soup, prop="og:image:height")
    if w == "1200" and h == "630":
        a.add("meta", "og_dims", "og:image:width=1200 y height=630", "ok", 0.5, 0.5)
    else:
        a.add("meta", "og_dims", "og:image:width=1200 y height=630", "warn", 0, 0.5,
              "Declarado: %s×%s" % (w or "—", h or "—"))

    tw = meta_content(soup, name="twitter:card")
    a.add("meta", "twitter", "twitter:card presente", "ok" if tw else "warn",
          0.5 if tw else 0, 0.5, tw or "No existe")

    html_tag = soup.find("html")
    lang = (html_tag.get("lang") or "").strip() if html_tag else ""
    a.add("meta", "lang", "Atributo lang en <html>", "ok" if lang else "warn",
          0.5 if lang else 0, 0.5, 'lang="%s"' % lang if lang else "No declarado")

    vp = meta_content(soup, name="viewport")
    a.add("meta", "viewport", "Meta viewport declarado", "ok" if vp else "error",
          0.5 if vp else 0, 0.5, vp or "No existe — la web no es mobile-friendly para Google")


def check_structure(a, site):
    soup = site["soup"]

    h1s = soup.find_all("h1")
    if len(h1s) == 1:
        a.add("estructura", "h1", "H1 único", "ok", 2, 2, '"%s"' % h1s[0].get_text(strip=True)[:80])
    elif len(h1s) == 0:
        a.add("estructura", "h1", "H1 único", "error", 0, 2, "No hay ningún H1")
    else:
        a.add("estructura", "h1", "H1 único", "warn", 0.5, 2, "Hay %d H1 (debe haber exactamente 1)" % len(h1s))

    headings = [(int(t.name[1]), t.get_text(strip=True)[:60])
                for t in soup.find_all(re.compile("^h[1-6]$"))]
    jumps = []
    prev = None
    for level, text in headings:
        if prev is not None and level > prev + 1:
            jumps.append("H%d → H%d (\"%s\")" % (prev, level, text))
        prev = level
    if headings and not jumps:
        a.add("estructura", "hierarchy", "Jerarquía de encabezados H1→H2→H3", "ok", 2, 2,
              "%d encabezados, sin saltos de nivel" % len(headings))
    elif headings:
        a.add("estructura", "hierarchy", "Jerarquía de encabezados H1→H2→H3", "warn", 0.5, 2,
              "Saltos detectados: " + "; ".join(jumps[:3]))
    else:
        a.add("estructura", "hierarchy", "Jerarquía de encabezados H1→H2→H3", "error", 0, 2,
              "No hay encabezados")

    imgs = [i for i in soup.find_all("img") if not (i.get("aria-hidden") == "true")]
    if imgs:
        with_alt = [i for i in imgs if (i.get("alt") or "").strip()]
        ratio = len(with_alt) / len(imgs)
        pts = 1.5 if ratio == 1 else (0.75 if ratio >= 0.8 else 0)
        status = "ok" if ratio == 1 else ("warn" if ratio >= 0.8 else "error")
        a.add("estructura", "img_alt", "Imágenes con atributo alt", status, pts, 1.5,
              "%d de %d imágenes con alt" % (len(with_alt), len(imgs)))
        with_dims = [i for i in imgs if i.get("width") and i.get("height")]
        ratio_d = len(with_dims) / len(imgs)
        pts_d = 0.5 if ratio_d == 1 else (0.25 if ratio_d >= 0.8 else 0)
        a.add("estructura", "img_dims", "Imágenes con width y height",
              "ok" if ratio_d == 1 else ("warn" if ratio_d >= 0.8 else "error"), pts_d, 0.5,
              "%d de %d imágenes con dimensiones (evita CLS)" % (len(with_dims), len(imgs)))
    else:
        a.add("estructura", "img_alt", "Imágenes con atributo alt", "info", 1.5, 1.5, "Sin imágenes <img>")
        a.add("estructura", "img_dims", "Imágenes con width y height", "info", 0.5, 0.5, "Sin imágenes <img>")

    ext_scripts = [s for s in soup.find_all("script", src=True)]
    if ext_scripts:
        deferred = [s for s in ext_scripts
                    if s.has_attr("defer") or s.has_attr("async") or s.get("type") == "module"]
        ratio_s = len(deferred) / len(ext_scripts)
        pts_s = 2 if ratio_s == 1 else (1 if ratio_s >= 0.5 else 0)
        a.add("estructura", "scripts", "Scripts externos con defer/async",
              "ok" if ratio_s == 1 else ("warn" if ratio_s >= 0.5 else "error"), pts_s, 2,
              "%d de %d scripts no bloquean el renderizado (rendimiento real medido por PageSpeed)"
              % (len(deferred), len(ext_scripts)))
    else:
        a.add("estructura", "scripts", "Scripts externos con defer/async", "info", 2, 2,
              "Sin scripts externos")


def check_schema(a, site, ctx):
    nodes, total, invalid = collect_jsonld(site["soup"])
    ctx["jsonld_nodes"] = nodes

    if total > 0:
        a.add("schema", "jsonld", "Al menos 1 bloque JSON-LD", "ok", 2, 2,
              "%d bloques <script type=\"application/ld+json\">" % total)
    else:
        a.add("schema", "jsonld", "Al menos 1 bloque JSON-LD", "error", 0, 2,
              "La web no tiene datos estructurados — los motores de IA no pueden 'entenderla'")
    if total > 0 and invalid == 0:
        a.add("schema", "jsonld_valid", "Todos los bloques JSON-LD son válidos", "ok", 1, 1)
    elif total > 0:
        a.add("schema", "jsonld_valid", "Todos los bloques JSON-LD son válidos", "error", 0, 1,
              "%d de %d bloques con JSON inválido (no parseable)" % (invalid, total))
    else:
        a.add("schema", "jsonld_valid", "Todos los bloques JSON-LD son válidos", "error", 0, 1, "Sin bloques")

    types = sorted({t for n in nodes for t in node_types(n)})
    ctx["schema_types"] = types
    a.add("schema", "types", "Tipos de schema detectados", "info", 0, 0,
          ", ".join(types) if types else "Ninguno")

    org = find_nodes(nodes, "Organization")
    lbs = find_localbusiness(nodes)
    if org or lbs:
        a.add("schema", "org", "Organization o LocalBusiness", "ok", 2, 2,
              ", ".join(sorted({t for n in (org + lbs) for t in node_types(n)})))
    else:
        a.add("schema", "org", "Organization o LocalBusiness", "error", 0, 2, "No presente")

    lb_complete = False
    lb_detail = "No hay LocalBusiness"
    for lb in lbs:
        addr = lb.get("address") or {}
        if isinstance(addr, list):
            addr = addr[0] if addr else {}
        has = {
            "name": bool(lb.get("name")),
            "telephone": bool(lb.get("telephone")),
            "address": bool(addr),
            "addressLocality": bool(isinstance(addr, dict) and addr.get("addressLocality")),
        }
        if all(has.values()):
            lb_complete = True
            lb_detail = "name, address, telephone y addressLocality presentes"
            ctx["lb_node"] = lb
            break
        lb_detail = "Faltan campos: " + ", ".join(k for k, v in has.items() if not v)
        ctx["lb_node"] = lb
    a.add("schema", "lb_complete", "LocalBusiness completo (name, address, telephone, addressLocality)",
          "ok" if lb_complete else ("warn" if lbs else "error"),
          6 if lb_complete else (2.5 if lbs else 0), 6, lb_detail)

    faq = find_nodes(nodes, "FAQPage")
    ctx["faq_schema"] = bool(faq)
    a.add("schema", "faqpage", "FAQPage presente", "ok" if faq else "error",
          6 if faq else 0, 6, "" if faq else "Sin FAQPage — fuente directa para LLMs")

    visible_qs = count_visible_faq(site["soup"])
    ctx["visible_faq"] = visible_qs
    if faq:
        a.add("schema", "faq_dom", "FAQPage con preguntas visibles en el DOM",
              "ok" if visible_qs else "error", 0.5 if visible_qs else 0, 0.5,
              "%d preguntas visibles" % visible_qs if visible_qs
              else "FAQPage declarado pero sin preguntas visibles → riesgo de penalización por schema engañoso")
    else:
        a.add("schema", "faq_dom", "FAQPage con preguntas visibles en el DOM", "error", 0, 0.5,
              "No aplica (sin FAQPage)")

    bc = find_nodes(nodes, "BreadcrumbList")
    a.add("schema", "breadcrumb", "BreadcrumbList presente", "ok" if bc else "warn",
          0.5 if bc else 0, 0.5, "" if bc else "No presente")


def check_robots(a, site, ctx):
    robots = site["robots"]
    if robots is not None:
        a.add("robots", "robots_txt", "robots.txt existe", "ok", 0.5, 0.5)
        has_sitemap = any(l.strip().lower().startswith("sitemap:") for l in robots.splitlines())
        a.add("robots", "sitemap", "Sitemap declarado en robots.txt",
              "ok" if has_sitemap else "warn", 0.5 if has_sitemap else 0, 0.5,
              "" if has_sitemap else "Sin línea Sitemap:")
    else:
        a.add("robots", "robots_txt", "robots.txt existe", "error", 0, 0.5, "No existe o no accesible")
        a.add("robots", "sitemap", "Sitemap declarado en robots.txt", "error", 0, 0.5, "Sin robots.txt")

    ctx["bots"] = {}
    for bot in AI_BOTS:
        access = bot_access(robots, bot)
        ctx["bots"][bot] = access
        if access == "blocked":
            a.add("robots", "bot_" + bot, "%s permitido" % bot, "error", 0, 0.5,
                  "❌ BLOQUEADO en robots.txt — este motor de IA no puede leer la web")
        elif access == "allowed":
            a.add("robots", "bot_" + bot, "%s permitido" % bot, "ok", 0.5, 0.5, "Permitido explícitamente")
        else:
            a.add("robots", "bot_" + bot, "%s permitido" % bot, "warn", 0.5, 0.5,
                  "No declarado (acceso implícito)" if access != "no_robots" else "Sin robots.txt (acceso implícito)")

    llms = site["llms"]
    if llms and llms.strip():
        a.add("robots", "llms_txt", "llms.txt (recomendado para GEO)", "ok", 2, 2,
              "%d líneas" % len(llms.strip().splitlines()))
        ctx["llms_ok"] = True
    else:
        a.add("robots", "llms_txt", "llms.txt (recomendado para GEO)", "warn", 0, 2,
              "No existe — útil pero no crítico: da a los LLMs un resumen estructurado del negocio")
        ctx["llms_ok"] = False


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 3 — GEO (11 pts: metas básicas 4 + lb_locality 4 + geocoords 3)
# ──────────────────────────────────────────────────────────────────────────────

def check_geo(a, site, ctx):
    soup = site["soup"]
    nodes = ctx.get("jsonld_nodes", [])

    # geo.region + geo.placename + ICBM: señales de bajo impacto real → 4 pts juntas
    region = meta_content(soup, name="geo.region")
    a.add("geo", "geo_region", "Meta geo.region (ej: ES-MD)", "ok" if region else "warn",
          1.5 if region else 0, 1.5, region or "No declarada")

    place = meta_content(soup, name="geo.placename")
    a.add("geo", "geo_place", "Meta geo.placename", "ok" if place else "warn",
          1.5 if place else 0, 1.5, place or "No declarada")

    icbm = meta_content(soup, name="ICBM")
    a.add("geo", "icbm", "Meta ICBM con coordenadas", "ok" if icbm else "warn",
          1 if icbm else 0, 1, icbm or "No declarada")

    lb_geo_ok = False
    for lb in find_localbusiness(nodes):
        addr = lb.get("address") or {}
        if isinstance(addr, list):
            addr = addr[0] if addr else {}
        if isinstance(addr, dict) and addr.get("addressLocality") and addr.get("addressRegion"):
            lb_geo_ok = True
            break
    a.add("geo", "lb_locality", "LocalBusiness con addressLocality y addressRegion",
          "ok" if lb_geo_ok else "error", 4 if lb_geo_ok else 0, 4,
          "" if lb_geo_ok else "Sin dirección estructurada completa en schema")

    coords_ok = False
    for n in find_nodes(nodes, "GeoCoordinates"):
        if n.get("latitude") is not None and n.get("longitude") is not None:
            coords_ok = True
            break
    a.add("geo", "geocoords", "GeoCoordinates en schema (latitude/longitude)",
          "ok" if coords_ok else "error", 3 if coords_ok else 0, 3,
          "" if coords_ok else "Sin coordenadas en datos estructurados")

    ctx["geo_signals"] = sum(1 for c in a.checks if c["area"] == "geo" and c["status"] == "ok")


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 4 — AEO (13 pts)
# ──────────────────────────────────────────────────────────────────────────────

def check_aeo(a, site, ctx):
    faq_schema = ctx.get("faq_schema", False)
    a.add("aeo", "aeo_faq_schema", "FAQPage schema presente", "ok" if faq_schema else "error",
          2 if faq_schema else 0, 2,
          "" if faq_schema else "Sin FAQPage los motores de respuesta no tienen Q&A que citar")

    visible = ctx.get("visible_faq", 0)
    a.add("aeo", "aeo_faq_dom", "Preguntas FAQ visibles en el DOM", "ok" if visible else "error",
          5 if visible else 0, 5,
          "%d preguntas detectadas" % visible if visible else "Sin FAQ visible (details/.faq/accordion)")

    q_pts = round(min(visible, 10) * 0.3, 1)
    a.add("aeo", "aeo_faq_count", "Número de preguntas FAQ (máx. 10 puntuables)",
          "ok" if visible >= 6 else ("warn" if visible else "error"), q_pts, 3,
          "%d preguntas → %s/3 pts" % (visible, fmt_pts(q_pts)))

    howto = bool(find_nodes(ctx.get("jsonld_nodes", []), "HowTo"))
    a.add("aeo", "aeo_howto", "HowTo schema presente", "ok" if howto else "warn",
          3 if howto else 0, 3, "" if howto else "Sin HowTo (recomendado si hay procesos/servicios paso a paso)")


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 4.5 — PRESENCIA Y AUTORIDAD (13 pts: GBP 3 + about 3 + casos 3 + arquitectura 4)
# ──────────────────────────────────────────────────────────────────────────────

ABOUT_PATTERNS = ("/about", "/quienes-somos", "/quienes_somos", "/sobre-nosotros",
                  "/sobre_nosotros", "/sobre-mi", "/equipo", "/nosotros")
ABOUT_TEXTS = ("sobre nosotros", "quienes somos", "sobre mi", "nuestro equipo", "el equipo")
CASOS_PATTERNS = ("/casos", "/caso-", "/casos-de-exito", "/casos-exito", "/exito",
                  "/testimonios", "/clientes", "/portfolio", "/proyectos")


def _internal_links(soup, root):
    """Devuelve lista de (path_en_minúsculas, texto) de enlaces internos."""
    out = []
    host = urlparse(root).netloc.lower().replace("www.", "")
    for a_tag in soup.find_all("a", href=True):
        href = (a_tag.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        p = urlparse(urljoin(root + "/", href))
        if p.netloc and p.netloc.lower().replace("www.", "") != host:
            continue
        out.append((p.path.lower(), a_tag.get_text(" ", strip=True)))
    return out


def _fetch_sitemap_urls(site):
    """Recupera <loc> del sitemap (declarado en robots.txt o /sitemap.xml).
    Best-effort y memoizado en `site` (se consulta desde autoridad y contenido)."""
    if "_sitemap_urls" in site:
        return site["_sitemap_urls"]
    sitemaps = [l.split(":", 1)[1].strip()
                for l in (site["robots"] or "").splitlines()
                if l.strip().lower().startswith("sitemap:")]
    if not sitemaps:
        sitemaps = [site["root"] + "/sitemap.xml"]
    urls, seen, queue = [], set(), list(sitemaps)
    while queue and len(seen) < 5:
        sm = queue.pop(0)
        if sm in seen:
            continue
        seen.add(sm)
        try:
            r = requests.get(sm, headers=HEADERS, timeout=TIMEOUT_SHORT)
        except requests.exceptions.RequestException:
            continue
        if r.status_code != 200:
            continue
        locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", r.text, re.I | re.S)
        if "<sitemapindex" in r.text.lower():
            queue.extend(locs[:10])
        else:
            urls.extend(locs)
    site["_sitemap_urls"] = urls
    return urls


def _detect_gbp(nombre, ciudad):
    """Best-effort: busca el panel de conocimiento de Google para el negocio.
    → True (ficha detectada) | False (no detectada) | None (no verificable)."""
    query = ("%s %s" % (nombre or "", ciudad or "")).strip()
    if not query:
        return None
    try:
        r = requests.get("https://www.google.com/search",
                         params={"q": query, "hl": "es", "gl": "es"},
                         headers=BROWSER_HEADERS, timeout=TIMEOUT_SHORT)
    except requests.exceptions.RequestException:
        return None
    if r.status_code != 200:
        return None
    html = r.text.lower()
    # Si Google muestra el muro de consentimiento o un captcha, no es verificable
    if "consent.google" in html or "unusual traffic" in html or "/sorry/" in str(r.url).lower():
        return None
    markers = ("kp-wholepage", "knowledge-panel", "kno-rdesc", "kc:/local",
               "/maps/place", "kp-header", "kno-ecr-pt")
    return any(m in html for m in markers)


def check_autoridad(a, site, ctx):
    soup = site["soup"]
    nombre, ciudad = ctx["nombre"], ctx["ciudad"]
    nodes = ctx.get("jsonld_nodes", [])
    links = _internal_links(soup, site["root"])

    # 1) Google Business Profile (3 pts)
    gbp = _detect_gbp(nombre, ciudad)
    if gbp is True:
        a.add("autoridad", "gbp", "Ficha de Google Business Profile activa", "ok", 3, 3,
              'Panel de conocimiento detectado para "%s %s"' % (nombre, ciudad))
    elif gbp is False:
        a.add("autoridad", "gbp", "Ficha de Google Business Profile activa", "error", 0, 3,
              "No se detecta ficha GBP — crear/optimizar el perfil en google.com/business")
    else:
        a.add("autoridad", "gbp", "Ficha de Google Business Profile activa", "warn", 0, 3,
              "No verificable automáticamente (Google limitó la consulta) — revisar manualmente")

    # 2) Página "Quiénes somos" / "Sobre nosotros" (3 pts) — señal E-E-A-T básica
    about_texts = tuple(_norm(t) for t in ABOUT_TEXTS)
    about = False
    for path, text in links:
        if any(p in path for p in ABOUT_PATTERNS) or any(t in _norm(text) for t in about_texts):
            about = True
            break
    a.add("autoridad", "about", 'Página "Quiénes somos" / "Sobre nosotros"',
          "ok" if about else "error", 3 if about else 0, 3,
          "Detectada en la navegación" if about
          else "No se encuentra — añade una página de equipo/historia (señal E-E-A-T básica)")

    # 3) Casos de éxito / testimonios (3 pts)
    casos = any(p in path for path, _ in links for p in CASOS_PATTERNS)
    has_review = bool(find_nodes(nodes, "Review") or find_nodes(nodes, "AggregateRating"))
    casos = casos or has_review
    detalle_casos = ("schema Review/AggregateRating presente" if has_review
                     else "Sección de casos/testimonios detectada") if casos \
        else "No se encuentran casos de éxito ni testimonios — refuerzan la confianza y el E-E-A-T"
    a.add("autoridad", "casos", "Casos de éxito o testimonios",
          "ok" if casos else "error", 3 if casos else 0, 3, detalle_casos)

    # 4) Arquitectura SEO local (4 pts) — páginas por ciudad/zona
    ciudad_norm = _norm(ciudad)
    ciudad_slug = ciudad_norm.replace(" ", "-")
    # Patrones típicos de landings locales: "servicio-en-zona", secciones de zonas, etc.
    ZONE_HINTS = ("-en-", "/en-", "/zona", "/zonas", "/areas", "/area-",
                  "/cobertura", "/donde-estamos", "/localidades")

    def _is_local(path, text=""):
        if path in ("", "/"):
            return False
        pn = _norm(path)
        if ciudad_norm and (ciudad_norm in pn or ciudad_slug in path or ciudad_norm in _norm(text)):
            return True
        return any(h in path for h in ZONE_HINTS)

    local_pages = {path for path, text in links if _is_local(path, text)}
    for u in _fetch_sitemap_urls(site):
        path = urlparse(u).path.lower()
        if _is_local(path):
            local_pages.add(path)
    n_local = len(local_pages)
    ctx["local_pages"] = n_local
    if n_local >= 2:
        a.add("autoridad", "arquitectura", "Arquitectura SEO local (páginas por zona)", "ok", 4, 4,
              "%d páginas locales detectadas" % n_local)
    elif n_local == 1:
        a.add("autoridad", "arquitectura", "Arquitectura SEO local (páginas por zona)", "warn", 2, 4,
              "Solo 1 página local — crea páginas por cada zona de cobertura")
    else:
        a.add("autoridad", "arquitectura", "Arquitectura SEO local (páginas por zona)", "error", 0, 4,
              "Sin páginas locales por zona — clave para captar búsquedas '%s en {zona}'" % ciudad)


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 4b — MARKETING (informativo, no puntúa en el score)
# ──────────────────────────────────────────────────────────────────────────────

def check_ads(a, site):
    html = site["html"].decode("utf-8", errors="ignore")
    pixel = "fbq(" in html or "connect.facebook.net" in html
    a.add("ads", "meta_pixel", "Píxel de Meta Ads", "ok" if pixel else "warn",
          0, 0, "Píxel Meta activo" if pixel else "Sin píxel Meta")


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 4.6 — PAGESPEED (8 pts, dentro de SEO Técnico)
# ──────────────────────────────────────────────────────────────────────────────

def _ps_vital(a, cid, label, value, good, bad, fmt):
    """Core Web Vital informativo (0 pts): ✅ ≤good · ⚠️ ≤bad · ❌ >bad."""
    if value is None:
        a.add("pagespeed", cid, label, "info", 0, 0, "Sin datos")
        return
    st = "ok" if value <= good else ("warn" if value <= bad else "error")
    a.add("pagespeed", cid, label, st, 0, 0, fmt % value)


def check_pagespeed(a, site, ctx):
    """Rendimiento móvil vía PageSpeed Insights API (gratis con API key)."""
    if not PAGESPEED_API_KEY:
        a.add("pagespeed", "pagespeed_score", "Rendimiento móvil (PageSpeed)", "warn", 0, 8,
              "No configurada — define la variable PAGESPEED_API_KEY (gratis en Google Cloud) "
              "para medir el rendimiento real (hasta 8 pts)")
        return
    try:
        r = requests.get(PAGESPEED_ENDPOINT, params={
            "url": site["url"], "strategy": "mobile", "key": PAGESPEED_API_KEY,
        }, timeout=TIMEOUT)
        data = r.json()
    except (requests.exceptions.RequestException, ValueError):
        a.add("pagespeed", "pagespeed_score", "Rendimiento móvil (PageSpeed)", "warn", 0, 8,
              "No se pudo consultar PageSpeed (red o cuota agotada) — reinténtalo más tarde")
        return

    lh = data.get("lighthouseResult", {}) or {}
    perf = ((lh.get("categories", {}) or {}).get("performance") or {}).get("score")
    if perf is None:
        msg = (data.get("error", {}) or {}).get("message", "respuesta sin puntuación")
        a.add("pagespeed", "pagespeed_score", "Rendimiento móvil (PageSpeed)", "warn", 0, 8,
              "PageSpeed no devolvió puntuación: %s" % str(msg)[:100])
        return

    score = round(perf * 100)
    ctx["pagespeed_score"] = score
    if score >= 90:
        a.add("pagespeed", "pagespeed_score", "Rendimiento móvil (PageSpeed)", "ok", 8, 8,
              "Score móvil %d/100" % score)
    elif score >= 70:
        a.add("pagespeed", "pagespeed_score", "Rendimiento móvil (PageSpeed)", "warn", 4, 8,
              "Score móvil %d/100 (mejorable)" % score)
    else:
        a.add("pagespeed", "pagespeed_score", "Rendimiento móvil (PageSpeed)", "error", 0, 8,
              "Score móvil %d/100 (lento para los estándares de Google)" % score)

    # Core Web Vitals (informativos): datos de campo (CrUX) y fallback a laboratorio.
    # Cualquier diferencia en la forma de la respuesta no debe romper la auditoría.
    try:
        audits = lh.get("audits", {}) or {}
        crux = ((data.get("loadingExperience", {}) or {}).get("metrics", {})) or {}

        def lab(key):
            return (audits.get(key, {}) or {}).get("numericValue")

        def crux_pct(key):
            v = crux.get(key)
            return v.get("percentile") if isinstance(v, dict) else None

        lcp = None
        if crux_pct("LARGEST_CONTENTFUL_PAINT_MS") is not None:
            lcp = crux_pct("LARGEST_CONTENTFUL_PAINT_MS") / 1000.0
        elif lab("largest-contentful-paint") is not None:
            lcp = lab("largest-contentful-paint") / 1000.0
        _ps_vital(a, "pagespeed_lcp", "LCP — Largest Contentful Paint", lcp, 2.5, 4.0, "%.1f s")

        cls = None
        if crux_pct("CUMULATIVE_LAYOUT_SHIFT_SCORE") is not None:
            cls = crux_pct("CUMULATIVE_LAYOUT_SHIFT_SCORE") / 100.0
        elif lab("cumulative-layout-shift") is not None:
            cls = lab("cumulative-layout-shift")
        _ps_vital(a, "pagespeed_cls", "CLS — Cumulative Layout Shift", cls, 0.1, 0.25, "%.2f")

        inp = crux_pct("INTERACTION_TO_NEXT_PAINT")
        _ps_vital(a, "pagespeed_inp", "INP — Interaction to Next Paint",
                  float(inp) if inp is not None else None, 200, 500, "%.0f ms")
    except Exception:
        pass  # los Core Web Vitals son informativos; nunca deben romper la auditoría


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 4.7 — CRO / CONVERSIÓN (8 pts)
# ──────────────────────────────────────────────────────────────────────────────

PHONE_RE = re.compile(r"(?:\+34[\s.\-]?)?[6-9]\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}")
CTA_WORDS = ("contact", "llama", "llamanos", "pide", "reserva", "solicita", "presupuesto",
             "compra", "empieza", "prueba gratis", "descarga", "pide cita", "reservar",
             "consulta", "escribenos", "mas informacion", "comprar", "apuntate")


def check_cro(a, site, ctx):
    soup = site["soup"]
    wa = phone = form = cta = False
    try:
        low = site["html"].decode("utf-8", errors="ignore").lower()
        wa = "wa.me" in low or "whatsapp.com" in low or "api.whatsapp" in low

        body = soup.body
        text = body.get_text(" ", strip=True) if body else soup.get_text(" ", strip=True)
        phone = bool(soup.select_one('a[href^="tel:"]')) or bool(PHONE_RE.search(text))

        form = bool(soup.find("form"))

        hero = body.decode_contents()[:1000].lower() if body else ""
        has_btn = any(m in hero for m in ("<button", 'role="button"', 'type="submit"', "btn", "cta"))
        has_cta_text = any(w in _norm(hero) for w in CTA_WORDS)
        cta = ("<a " in hero or "<button" in hero) and (has_btn or has_cta_text)
    except Exception:
        pass  # ante cualquier error de parseo, se puntúa lo detectado hasta el momento

    a.add("cro", "cro_whatsapp", "WhatsApp visible", "ok" if wa else "warn",
          2 if wa else 0, 2,
          "Enlace a WhatsApp detectado" if wa else "Sin enlace a WhatsApp — canal directo muy usado en España")
    a.add("cro", "cro_phone", "Teléfono visible", "ok" if phone else "warn",
          2 if phone else 0, 2,
          "Teléfono detectado en la página" if phone else "Sin teléfono visible")
    a.add("cro", "cro_form", "Formulario de contacto", "ok" if form else "warn",
          2 if form else 0, 2, "<form> detectado" if form else "Sin formulario de contacto")
    a.add("cro", "cro_cta", "CTA visible en el hero", "ok" if cta else "warn",
          2 if cta else 0, 2,
          "Llamada a la acción detectada arriba" if cta else "Sin CTA clara en la parte superior")


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 4.8 — DIRECTORIOS LOCALES (4 pts) + COMPETENCIA y CONTENIDO (informativos)
# ──────────────────────────────────────────────────────────────────────────────

DIRECTORY_DOMAINS = ("paginasamarillas", "yelp.", "tripadvisor", "idealista", "fotocasa",
                     "doctoralia", "booking.com", "eltenedor", "thefork", "cylex", "infoisinfo",
                     "treatwell", "facebook.", "instagram.", "linkedin.", "youtube.",
                     "twitter.", "x.com", "google.", "wikipedia.", "amazon.", "tuugo", "11870")


def _google_search_html(query, num=10):
    """HTML de una búsqueda en Google (best-effort). None si falla o bloquea."""
    try:
        r = requests.get("https://www.google.es/search",
                         params={"q": query, "num": num, "hl": "es", "gl": "es"},
                         headers=BROWSER_HEADERS, timeout=TIMEOUT_SHORT)
    except requests.exceptions.RequestException:
        return None
    if r.status_code != 200:
        return None
    return r.text


def _extract_organic_urls(html, exclude=(), limit=10):
    """URLs orgánicas (no ads, no directorios/redes) de una SERP de Google."""
    from urllib.parse import unquote
    cands = re.findall(r'/url\?q=(https?://[^&"]+)', html)
    cands += re.findall(r'<a[^>]+href="(https?://[^"]+)"', html)
    urls, seen = [], set()
    for raw in cands:
        u = unquote(raw)
        host = urlparse(u).netloc.lower()
        if not host or host in seen:
            continue
        if any(d in host for d in ("google.", "gstatic.", "googleusercontent", "googleadservices")):
            continue
        if any(x and x in host for x in exclude):
            continue
        seen.add(host)
        urls.append(u)
        if len(urls) >= limit:
            break
    return urls


def _directory_presence(nombre, dom):
    """→ True (aparece) | False (no aparece) | None (no verificable)."""
    html = _google_search_html('"%s" site:%s' % (nombre, dom))
    if html is None:
        return None
    low = html.lower()
    if "/sorry/" in low or "consent.google" in low or "unusual traffic" in low:
        return None
    for u in _extract_organic_urls(html, exclude=(), limit=10):
        if dom.lower() in urlparse(u).netloc.lower():
            return True
    if any(s in low for s in ("no se han encontrado resultados",
                              "did not match any documents", "no results found")):
        return False
    return bool(re.search(r'https?://[^"\'>]*%s' % re.escape(dom), low))


DIR_TIME_BUDGET = 25  # segundos máx. para todas las consultas de directorios


def check_directorios(a, ctx):
    nombre, sector = ctx["nombre"], ctx["sector"]
    skey = sector_key(sector)
    dirs = (DIRECTORIOS_BASE + DIRECTORIOS_SECTOR.get(skey, DIRECTORIOS_DEFAULT))[:4]
    ctx["directorios"] = {}
    start = time.monotonic()
    for dom in dirs:
        present = None
        if time.monotonic() - start < DIR_TIME_BUDGET:
            try:
                present = _directory_presence(nombre, dom)
            except Exception:
                present = None
        ctx["directorios"][dom] = present
        if present is True:
            a.add("directorios", "dir_" + dom, "Presencia en %s" % dom, "ok", 1, 1, "Ficha detectada")
        elif present is False:
            a.add("directorios", "dir_" + dom, "Presencia en %s" % dom, "warn", 0, 1,
                  "No detectada — darse de alta refuerza el NAP y el SEO local")
        else:
            a.add("directorios", "dir_" + dom, "Presencia en %s" % dom, "info", 0, 1,
                  "No verificable (Google limitó la consulta)")


def _quick_site_checks(url):
    """Checks básicos de un competidor (best-effort). None si no responde."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT_SHORT, allow_redirects=True)
    except requests.exceptions.RequestException:
        return None
    if r.status_code >= 400:
        return None
    root = "{0}://{1}".format(urlparse(r.url).scheme, urlparse(r.url).netloc)
    soup = BeautifulSoup(r.content, "html.parser")
    title_tag = soup.find("title")
    title_txt = title_tag.get_text(strip=True) if title_tag else ""
    nodes, _, _ = collect_jsonld(soup)
    return {
        "host": urlparse(r.url).netloc.lower().replace("www.", ""),
        "title_ok": bool(title_txt) and len(title_txt) <= 65,
        "lb": bool(find_localbusiness(nodes)),
        "faq": bool(find_nodes(nodes, "FAQPage")),
        "llms": bool((_fetch_optional(root + "/llms.txt", timeout=TIMEOUT_SHORT) or "").strip()),
        "robots": _fetch_optional(root + "/robots.txt", timeout=TIMEOUT_SHORT) is not None,
    }


COMP_TIME_BUDGET = 35  # segundos máx. para analizar competidores


def check_competidores(audit, site, ctx):
    """Top 5 competidores orgánicos para '{sector} {ciudad}' + checks básicos.
    Informativo y best-effort: cualquier fallo deja la lista vacía sin romper nada."""
    sector, ciudad, url_cliente = ctx["sector"], ctx["ciudad"], ctx["url"]
    client_host = urlparse(url_cliente).netloc.lower().replace("www.", "")
    competidores = []
    try:
        html = _google_search_html("%s %s" % (sector, ciudad))
        if html:
            low = html.lower()
            if not any(s in low for s in ("/sorry/", "consent.google", "unusual traffic")):
                exclude = DIRECTORY_DOMAINS + (client_host,)
                start = time.monotonic()
                for u in _extract_organic_urls(html, exclude=exclude, limit=12):
                    if len(competidores) >= 5 or time.monotonic() - start > COMP_TIME_BUDGET:
                        break
                    checks = _quick_site_checks(u)
                    if checks and checks["host"] != client_host:
                        competidores.append(checks)
    except Exception:
        competidores = []
    ctx["competidores"] = competidores

    nodes = ctx.get("jsonld_nodes", [])
    t = next((c for c in audit.checks if c["id"] == "title_len"), None)
    ctx["cliente_checks"] = {
        "host": client_host,
        "title_ok": bool(t and t["status"] == "ok"),
        "lb": bool(find_localbusiness(nodes)),
        "faq": ctx.get("faq_schema", False),
        "llms": ctx.get("llms_ok", False),
        "robots": site["robots"] is not None,
    }


def check_contenido(site, ctx):
    """Inventario de contenido: páginas en sitemap y artículos de blog."""
    try:
        urls = set(_fetch_sitemap_urls(site))
        blog_pat = ("/blog/", "/noticias/", "/articulos/", "/articulo/", "/post/", "/posts/")
        blog_urls = [u for u in urls if any(p in u.lower() for p in blog_pat)]
        ctx["contenido"] = {
            "total": len(urls),
            "has_blog": len(blog_urls) > 0,
            "blog_count": len(blog_urls),
        }
    except Exception:
        ctx["contenido"] = {"total": 0, "has_blog": False, "blog_count": 0}


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 5 — PUNTUACIÓN GLOBAL Y NIVEL
# ──────────────────────────────────────────────────────────────────────────────

def nivel(score):
    if score < 50:
        return "🔴", "Crítico", "señales técnicas para motores de IA muy incompletas"
    if score < 70:
        return "🟡", "Mejorable", "presencia parcial en motores de IA"
    if score < 85:
        return "🟢", "Bueno", "bien posicionado para motores de IA"
    return "⭐", "Excelente", "referente en su sector para motores de IA"


def frase_resumen(score, nombre, sector, ciudad):
    if score < 50:
        return ("%s tiene margen de mejora en las señales técnicas que los motores de IA "
                "usan para verificar y citar negocios locales." % nombre)
    if score < 70:
        return ("%s tiene una base aprovechable, pero los motores de IA solo 'entienden' "
                "parte del negocio: con varias correcciones concretas puede empezar a "
                "aparecer en respuestas sobre %s en %s." % (nombre, sector, ciudad))
    if score < 85:
        return ("%s está bien posicionada para motores de IA: con los ajustes pendientes "
                "puede convertirse en la respuesta por defecto para %s en %s."
                % (nombre, sector, ciudad))
    return ("%s es un referente técnico en %s: los motores de IA tienen todo lo necesario "
            "para recomendarla cuando alguien busca %s en %s."
            % (nombre, sector, sector, ciudad))


# Explicaciones técnicas para cada error posible: (qué es, por qué importa,
# qué tiene la competencia que sí lo implementa, cómo corregirlo)
FIX_GUIDE = {
    "title": ("El <title> es el titular de la página en Google y la primera señal que leen los LLMs.",
              "Sin título, ni Google ni los motores de IA saben de qué trata la web.",
              "Tu competidor con un <title> claro aparece en buscadores y en respuestas de IA; tú, no.",
              "Añadir en <head>: <title>Marca — Servicio en Ciudad</title> (≤65 caracteres)."),
    "desc": ("La meta description es el texto bajo el título en los resultados de búsqueda.",
             "Google y los LLMs la usan como resumen canónico de la página.",
             "Tu competidor controla su descripción en Google; en la tuya, Google improvisa un texto peor.",
             '<meta name="description" content="Descripción con servicio + ciudad, ≤160 caracteres">.'),
    "canonical": ("La etiqueta canonical indica la URL 'oficial' de la página.",
                  "Evita contenido duplicado (http/https, con/sin www) que diluye la autoridad.",
                  "Tu competidor concentra toda su autoridad en una URL; la tuya se reparte y rankea por debajo.",
                  '<link rel="canonical" href="URL-exacta-de-la-página"> en el <head>.'),
    "og_td": ("Open Graph controla cómo se ve la web al compartirla (WhatsApp, LinkedIn, etc.).",
              "Sin og:title/og:description el enlace compartido sale sin titular ni resumen.",
              "Cuando tu competidor comparte su web sale con titular y resumen; la tuya, en blanco.",
              'Añadir <meta property="og:title" …> y <meta property="og:description" …>.'),
    "og_img": ("og:image es la imagen de previsualización al compartir el enlace.",
               "WhatsApp, iMessage y LinkedIn no renderizan SVG ni enlaces sin imagen.",
               "El enlace de tu competidor sale con imagen atractiva; el tuyo, 'en gris' y sin clics.",
               "Crear una imagen JPG/PNG de 1200×630 px y declararla en og:image (URL absoluta)."),
    "viewport": ("El meta viewport activa el renderizado responsive en móviles.",
                 "Google indexa mobile-first: sin viewport la web se considera no apta para móvil.",
                 "Tu competidor está marcado como apto para móvil y se queda el 60% del tráfico que tú pierdes.",
                 '<meta name="viewport" content="width=device-width, initial-scale=1">.'),
    "h1": ("El H1 es el titular principal que estructura semánticamente la página.",
           "Buscadores y LLMs lo usan para identificar el tema central.",
           "Tu competidor deja claro su servicio principal; tu página compite peor por la misma keyword.",
           "Dejar exactamente un <h1> con el servicio principal + ciudad."),
    "hierarchy": ("La jerarquía H1→H2→H3 es el índice lógico del contenido.",
                  "Los LLMs trocean el contenido por encabezados para extraer respuestas.",
                  "La IA extrae respuestas limpias de la web de tu competidor; de la tuya, fragmentos mal delimitados.",
                  "Reordenar encabezados sin saltar niveles (de H2 se pasa a H3, no a H4)."),
    "img_alt": ("El atributo alt describe cada imagen para buscadores y lectores de pantalla.",
                "Es señal de relevancia, accesibilidad legal (EAA 2025) y contexto para la IA.",
                "Tu competidor aparece en Google Imágenes y cumple accesibilidad; tú quedas fuera y expuesto.",
                'Añadir alt descriptivo a cada <img>: alt="qué se ve + contexto del negocio".'),
    "img_dims": ("width/height reservan el espacio de la imagen antes de cargarla.",
                 "Evitan el salto de layout (CLS), métrica de Core Web Vitals.",
                 "La web de tu competidor carga sin saltos; la tuya pierde puntos de experiencia en Google.",
                 "Declarar width y height reales en cada <img>."),
    "scripts": ("defer/async evitan que los scripts bloqueen el renderizado.",
                "Mejoran LCP/FID, métricas que Google usa para rankear.",
                "La web de tu competidor carga más rápido y rankea mejor en móvil que la tuya.",
                "Añadir defer a los <script src> que no sean críticos para el primer render."),
    "jsonld": ("JSON-LD son los datos estructurados que describen el negocio a las máquinas.",
               "Es el formato que Google y los LLMs leen para 'entender' qué es el negocio, dónde está y qué ofrece.",
               "Tu competidor es una entidad que la IA entiende y recomienda; tú eres texto plano que ignora.",
               'Añadir <script type="application/ld+json"> con LocalBusiness (+FAQPage) en el <head>.'),
    "jsonld_valid": ("Bloques JSON-LD con sintaxis inválida.",
                     "Un JSON roto se ignora por completo: es como no tenerlo.",
                     "Tu competidor tiene schema que sí cuenta; el tuyo, roto, es como no tenerlo.",
                     "Validar cada bloque en validator.schema.org y corregir la sintaxis."),
    "org": ("Schema Organization/LocalBusiness identifica la entidad detrás de la web.",
            "Los LLMs recomiendan entidades, no páginas: sin entidad declarada no hay recomendación.",
            "Tu competidor está declarado como empresa local y la IA lo recomienda con nombre y datos; tú no apareces.",
            "Añadir un nodo LocalBusiness con name, url, logo, address y telephone."),
    "lb_complete": ("LocalBusiness incompleto: faltan campos de contacto/dirección estructurados.",
                    "Los motores de IA locales cruzan nombre + dirección + teléfono (NAP) para validar el negocio.",
                    "Tu competidor tiene el NAP completo y aparece en búsquedas locales por IA ('X cerca de mí'); tú quedas fuera.",
                    "Completar name, telephone y address con addressLocality en el JSON-LD."),
    "faqpage": ("FAQPage marca preguntas y respuestas en formato legible por máquinas.",
                "Es la fuente directa de la que ChatGPT/Perplexity extraen respuestas citables.",
                "Tu competidor con FAQPage es la fuente que cita ChatGPT/Perplexity; tus respuestas no se ven.",
                "Añadir schema FAQPage con 6-10 preguntas reales de clientes y respuestas de 40-60 palabras."),
    "faq_dom": ("Las preguntas del schema deben existir también como contenido visible.",
                "Schema sin contenido visible se considera engañoso (riesgo de penalización).",
                "Tu competidor publica preguntas reales que la IA cita; en tu web no hay texto que citar.",
                "Publicar una sección FAQ visible (details/accordion) con las mismas preguntas del schema."),
    "breadcrumb": ("BreadcrumbList describe la ruta de navegación de la página.",
                   "Ayuda a buscadores e IA a entender la estructura del sitio.",
                   "Tu competidor muestra migas de pan en Google; tu resultado se ve más pobre al lado.",
                   "Añadir schema BreadcrumbList con la jerarquía Inicio → Sección → Página."),
    "robots_txt": ("robots.txt es el fichero que regula el acceso de los bots.",
                   "Sin él no hay control ni declaración de sitemap.",
                   "Tu competidor con robots.txt aparece antes que tú en los crawlers de IA.",
                   "Crear /robots.txt con User-agent: * Allow: / y la línea Sitemap:."),
    "sitemap": ("La línea Sitemap: en robots.txt indica dónde está el mapa del sitio.",
                "Acelera el descubrimiento de páginas nuevas por todos los bots.",
                "El contenido nuevo de tu competidor se indexa antes que el tuyo.",
                "Añadir Sitemap: https://dominio.es/sitemap.xml a robots.txt."),
    "llms_txt": ("llms.txt es el fichero estándar que resume el negocio para los LLMs.",
                 "Es la señal GEO más directa: dice a ChatGPT/Claude/Perplexity qué es el negocio, dónde está y qué ofrece.",
                 "Tu competidor con llms.txt le dicta a la IA qué decir de su negocio; de ti, la IA improvisa.",
                 "Crear /llms.txt en Markdown: # Negocio, > resumen, secciones de servicios, zona y contacto."),
    "geo_region": ("Meta geo.region declara la región en código ISO (ej: ES-MD).",
                   "Señal directa de geolocalización para crawlers de IA.",
                   "Tu competidor está asociado a su provincia en respuestas locales; tú no apareces en la zona.",
                   '<meta name="geo.region" content="ES-XX"> (código ISO 3166-2 de la provincia).'),
    "geo_place": ("Meta geo.placename declara la localidad en texto plano.",
                  "Refuerza la asociación negocio↔ciudad para la IA.",
                  "Tu competidor aparece en consultas 'en {ciudad}'; tú eres invisible en esa búsqueda.",
                  '<meta name="geo.placename" content="Ciudad">.'),
    "icbm": ("Meta ICBM declara las coordenadas exactas del negocio.",
             "Permite a los motores responder a búsquedas 'cerca de mí'.",
             "Tu competidor gana las búsquedas 'cerca de mí', las de mayor intención de compra; tú las pierdes.",
             '<meta name="ICBM" content="40.4168, -3.7038"> (lat, lng reales del negocio).'),
    "lb_locality": ("Dirección estructurada (addressLocality + addressRegion) en el schema.",
                    "Es el dato que los LLMs citan textualmente al recomendar negocios locales.",
                    "Tu competidor aparece con dirección correcta en las respuestas de IA; tú, sin ubicación.",
                    "Completar address en LocalBusiness con streetAddress, addressLocality, addressRegion y postalCode."),
    "geocoords": ("GeoCoordinates añade latitude/longitude al schema del negocio.",
                  "Coordenadas exactas = máxima precisión para resultados de proximidad.",
                  "Tu competidor geolocalizado gana las búsquedas por cercanía; tú quedas detrás.",
                  'Añadir "geo": {"@type":"GeoCoordinates","latitude":…,"longitude":…} al LocalBusiness.'),
    "aeo_faq_schema": ("FAQPage schema (ver sección Schema).",
                       "Los Answer Engines construyen sus respuestas a partir de Q&A estructuradas.",
                       "Tu competidor es la respuesta literal que da la IA sobre el sector; tú no entras en la respuesta.",
                       "Implementar FAQPage con preguntas que los clientes hacen de verdad."),
    "aeo_faq_dom": ("Sección de preguntas frecuentes visible en la página.",
                    "El contenido visible es lo que la IA puede citar y enlazar.",
                    "Tu competidor recibe citas directas con enlace en ChatGPT/Perplexity; tú no.",
                    "Crear sección FAQ con <details><summary>¿Pregunta?</summary>respuesta</details>."),
    "aeo_howto": ("HowTo schema describe procesos paso a paso.",
                  "Ideal para 'cómo funciona X' — consultas muy frecuentes en IA.",
                  "Tu competidor responde los '¿cómo funciona…?' en IA; esas consultas se las queda él.",
                  "Añadir schema HowTo al proceso principal del servicio (3-6 pasos)."),
    "gbp": ("Google Business Profile es la ficha del negocio en Google Maps y el buscador.",
            "Es la principal fuente que la IA y Google cruzan para validar un negocio local (NAP, reseñas, horario).",
            "Presencia en el mapa, en 'cerca de mí' y en las respuestas locales de IA.",
            "Crear/reclamar la ficha en google.com/business: categoría, dirección, teléfono, fotos y reseñas."),
    "about": ("Una página 'Quiénes somos' presenta al equipo, la experiencia y la historia.",
              "Es una señal E-E-A-T básica: demuestra que detrás del negocio hay personas reales y expertas.",
              "Confianza de usuarios y motores de IA, que priorizan entidades con autoría verificable.",
              "Publicar una página /sobre-nosotros con equipo, años de experiencia y enlaces a perfiles."),
    "casos": ("Casos de éxito y testimonios muestran resultados reales con clientes.",
              "Aportan prueba social citable y refuerzan el E-E-A-T del negocio.",
              "Conversión y credibilidad frente a competidores sin pruebas verificables.",
              "Crear /casos o /testimonios y marcar Review/AggregateRating en JSON-LD."),
    "arquitectura": ("La arquitectura SEO local son páginas dedicadas a cada zona de cobertura.",
                     "Permiten posicionar y ser citado por la IA para cada ciudad/barrio donde opera el negocio.",
                     "Tráfico y recomendaciones de IA en cada zona, no solo en la ciudad principal.",
                     "Crear una página por zona con contenido propio (servicio + zona), enlazada desde el menú."),
    "pagespeed_score": ("El rendimiento móvil (Core Web Vitals) mide la velocidad real de carga e interacción.",
                        "Google rankea según estas métricas y los usuarios abandonan las webs lentas.",
                        "Posiciones en móvil (>60% del tráfico) y conversiones perdidas por abandono.",
                        "Optimizar imágenes (WebP), diferir JS, usar caché/CDN y reducir el CSS bloqueante."),
    "cro_whatsapp": ("Un enlace a WhatsApp permite contactar en un toque desde el móvil.",
                     "Es el canal de contacto más inmediato y usado en España.",
                     "Leads que se enfrían porque no encuentran un canal directo de contacto.",
                     "Añadir un botón flotante wa.me/<número> visible en todas las páginas."),
    "cro_phone": ("El teléfono visible (y como enlace tel:) facilita la llamada inmediata.",
                  "Muchos clientes locales prefieren llamar justo cuando tienen la intención.",
                  "Llamadas perdidas de clientes con alta intención de compra.",
                  'Mostrar el teléfono en la cabecera como <a href="tel:+34...">.'),
    "cro_form": ("Un formulario de contacto capta a quien prefiere escribir antes que llamar.",
                 "Permite recoger leads fuera del horario de atención.",
                 "Leads de usuarios que no llaman pero sí dejarían sus datos.",
                 "Añadir un <form> de contacto sencillo (nombre, contacto y mensaje)."),
    "cro_cta": ("La llamada a la acción del hero guía al visitante hacia el siguiente paso.",
                "Sin un CTA claro arriba, el usuario no sabe qué hacer al entrar.",
                "Conversión: visitas que se van sin pedir cita, presupuesto o contacto.",
                "Colocar un botón claro en el hero: 'Pide cita', 'Solicita presupuesto', etc."),
}


# ──────────────────────────────────────────────────────────────────────────────
# INFORME
# ──────────────────────────────────────────────────────────────────────────────

AREA_TITLES = [
    ("meta", "Meta tags"),
    ("estructura", "Estructura HTML"),
    ("schema", "Schema JSON-LD"),
]


# ──────────────────────────────────────────────────────────────────────────────
# GRÁFICAS DEL INFORME (matplotlib → PNG base64 embebido en el markdown)
# ──────────────────────────────────────────────────────────────────────────────

CHART_BG = "#0e0e16"
CHART_FG = "#f0f0f5"
CHART_TRACK = "#1e1e2e"
CHART_GREEN = "#00d4aa"
CHART_GOLD = "#f5c842"
CHART_RED = "#ff4444"
CHART_DPI = 96


def _color_pct(pct):
    return CHART_GREEN if pct >= 0.8 else (CHART_GOLD if pct >= 0.5 else CHART_RED)


def _fig_b64(plt, fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=CHART_DPI, facecolor=fig.get_facecolor())
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def generate_charts(audit_data):
    """Genera las 3 gráficas del informe como PNG en base64.

    audit_data: seo/geo/aeo/autoridad/cro/directorios y sus _max, score y los contadores
    checks_ok/checks_warn/checks_error.
    Devuelve {'areas', 'roi', 'checks'} → string base64 de cada PNG.
    Si matplotlib no está disponible devuelve {} y el informe sale sin gráficas.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return {}

    # Los hatch (texturas) diferencian las series también en impresión B/N
    rc = {
        "font.family": "monospace",
        "text.color": CHART_FG,
        "axes.labelcolor": CHART_FG,
        "xtick.color": CHART_FG,
        "ytick.color": CHART_FG,
        "axes.edgecolor": CHART_TRACK,
        "axes.titlecolor": CHART_FG,
        "hatch.linewidth": 1.0,
    }
    charts = {}
    with matplotlib.rc_context(rc):

        # ── 1. Puntuación por área (barras horizontales, 600x360) ──
        fig, ax = plt.subplots(figsize=(600 / CHART_DPI, 360 / CHART_DPI), dpi=CHART_DPI)
        fig.patch.set_facecolor(CHART_BG)
        ax.set_facecolor(CHART_BG)
        areas = [  # de abajo arriba: SEO queda en la primera fila visible
            ("Directorios", audit_data.get("directorios", 0), audit_data.get("directorios_max", 0), "oo"),
            ("Conversión (CRO)", audit_data.get("cro", 0), audit_data.get("cro_max", 0), "\\\\"),
            ("Autoridad", audit_data.get("autoridad", 0), audit_data.get("autoridad_max", 0), "++"),
            ("AEO", audit_data["aeo"], audit_data["aeo_max"], ".."),
            ("GEO", audit_data["geo"], audit_data["geo_max"], "xx"),
            ("SEO Técnico", audit_data["seo"], audit_data["seo_max"], "//"),
        ]
        ys = range(len(areas))
        ax.barh(ys, [a[2] for a in areas], color=CHART_TRACK, height=0.6)
        for y, (_, pts, maxp, hatch) in zip(ys, areas):
            ax.barh(y, pts, color=_color_pct(pts / maxp if maxp else 1), height=0.6,
                    hatch=hatch, edgecolor=CHART_BG, linewidth=0.8)
            ax.text(maxp + 1, y, "%s/%s" % (fmt_pts(pts), fmt_pts(maxp)),
                    va="center", fontsize=9, color=CHART_FG)
        ax.set_yticks(list(ys))
        ax.set_yticklabels([a[0] for a in areas], fontsize=9)
        ax.set_xticks([])
        ax.set_xlim(0, max(a[2] for a in areas) * 1.22)
        ax.tick_params(length=0)
        for sp in ax.spines.values():
            sp.set_visible(False)
        ax.set_title("Puntuación por área", fontsize=12, pad=12)
        fig.tight_layout()
        charts["areas"] = _fig_b64(plt, fig)

        # ── 2. Resumen de checks (donut, 400x400) ──
        fig, ax = plt.subplots(figsize=(400 / CHART_DPI, 400 / CHART_DPI), dpi=CHART_DPI)
        fig.patch.set_facecolor(CHART_BG)
        ax.set_facecolor(CHART_BG)
        datos = [("OK", audit_data["checks_ok"], CHART_GREEN, "//"),
                 ("Warning", audit_data["checks_warn"], CHART_GOLD, ".."),
                 ("Fallo", audit_data["checks_error"], CHART_RED, "xx")]
        datos = [d for d in datos if d[1] > 0] or [("Sin checks", 1, CHART_TRACK, "")]
        wedges, _ = ax.pie([d[1] for d in datos], colors=[d[2] for d in datos],
                           startangle=90, counterclock=False,
                           wedgeprops=dict(width=0.32, edgecolor=CHART_BG, linewidth=1.5))
        for wedge, d in zip(wedges, datos):
            wedge.set_hatch(d[3])
        ax.text(0, 0.05, "%d/100" % audit_data["score"], ha="center", va="center",
                fontsize=20, fontweight="bold", color=CHART_FG)
        ax.text(0, -0.17, "score", ha="center", va="center", fontsize=9, color=CHART_FG)
        ax.set_title("Resumen de checks", fontsize=12, pad=10)
        fig.legend(wedges, ["%s (%d)" % (d[0], d[1]) for d in datos],
                   loc="lower center", ncol=3, frameon=False, fontsize=8)
        fig.subplots_adjust(bottom=0.12, top=0.88)
        charts["checks"] = _fig_b64(plt, fig)

    return charts


def estado_emoji(pts, maxp):
    ratio = pts / maxp if maxp else 1
    return "✅" if ratio >= 0.85 else ("🟢" if ratio >= 0.7 else ("⚠️" if ratio >= 0.5 else "❌"))


def top_problemas(audit):
    """Los 3 problemas con más puntos perdidos, en lenguaje de negocio."""
    negocio = {
        "llms_txt": "La web no tiene llms.txt: los motores de IA no tienen una ficha estándar del negocio que leer primero.",
        "jsonld": "La web no tiene datos estructurados: los motores de IA no pueden verificar el negocio como entidad (nombre, dirección, servicios).",
        "org": "El negocio no está identificado como empresa local en el código: la IA no puede verificarlo con nombre, dirección y teléfono.",
        "aeo_faq_schema": "No hay preguntas frecuentes estructuradas: los LLMs no tienen respuestas del negocio que citar textualmente.",
        "aeo_faq_dom": "No hay sección de preguntas y respuestas visible: la IA no tiene texto del negocio que citar.",
        "lb_complete": "Faltan datos de contacto estructurados (dirección/teléfono): la IA no puede 'fichar' el negocio para búsquedas locales.",
        "geocoords": "El negocio no tiene coordenadas declaradas: compite en desventaja en las búsquedas tipo 'cerca de mí', las de mayor intención de compra.",
        "lb_locality": "La dirección no está en formato máquina: el negocio no queda asociado a su ciudad en los datos que leen los motores de IA.",
        "icbm": "Sin coordenadas geográficas la web compite en desventaja en búsquedas de proximidad.",
        "geo_region": "La web no declara su provincia: la IA no la asocia con la zona donde están sus clientes.",
        "geo_place": "La web no declara su ciudad: pierde relevancia en consultas 'en {ciudad}'.",
        "desc": "Sin descripción para buscadores, Google inventa el texto del anuncio gratuito del negocio y rinde peor.",
        "og_img": "Cada vez que alguien comparte la web por WhatsApp, el enlace sale sin imagen: se pierde confianza y clics.",
        "title": "La web no tiene titular para buscadores: pierde clics en cada búsqueda.",
        "viewport": "La web no está marcada como apta para móvil: Google la penaliza en más del 60% de las búsquedas.",
        "h1": "La página no tiene un titular principal claro: buscadores e IA no saben cuál es el servicio principal.",
        "bot_GPTBot": "El crawler de ChatGPT (GPTBot) tiene el acceso bloqueado en robots.txt: ese motor no puede leer el contenido de la web.",
        "bot_ClaudeBot": "El crawler de Claude (ClaudeBot) tiene el acceso bloqueado en robots.txt: ese motor no puede leer el contenido de la web.",
        "bot_PerplexityBot": "El crawler de Perplexity (PerplexityBot) tiene el acceso bloqueado en robots.txt: ese motor no puede leer el contenido de la web.",
        "aeo_howto": "No se explica ningún proceso paso a paso: se pierden las consultas '¿cómo funciona…?' en IA.",
        "gbp": "El negocio no tiene (o no se detecta) ficha de Google Business: pierde el mapa, las reseñas y las búsquedas 'cerca de mí'.",
        "about": "No hay página 'Quiénes somos': falta la señal de confianza (E-E-A-T) que la IA usa para recomendar entidades verificables.",
        "casos": "No hay casos de éxito ni testimonios: falta la prueba social que convierte y que la IA puede citar.",
        "arquitectura": "No hay páginas locales por zona: el negocio solo compite en su ciudad principal y pierde las zonas de alrededor.",
        "pagespeed_score": "La web es lenta en móvil: Google la penaliza y los usuarios se van antes de convertir.",
        "cro_whatsapp": "No hay WhatsApp visible: se pierde el canal de contacto más inmediato del cliente.",
        "cro_phone": "El teléfono no está visible: dificultas que te llamen justo cuando tienen la intención.",
        "cro_form": "No hay formulario de contacto: pierdes los leads que prefieren escribir a llamar.",
        "cro_cta": "Falta una llamada a la acción clara arriba: el visitante no sabe qué hacer al entrar.",
    }
    fallos = sorted(audit.failed(), key=lambda c: c["max"] - c["points"], reverse=True)
    out = []
    for c in fallos:
        if c["id"] in negocio:
            out.append(negocio[c["id"]])
        if len(out) == 3:
            break
    for c in fallos:
        if len(out) == 3:
            break
        g = FIX_GUIDE.get(c["id"])
        if g and g[2] not in out:
            out.append("%s — tu competencia que sí lo tiene: %s" % (c["label"], g[2][0].lower() + g[2][1:]))
    return out


ACTIONS = [
    # (ids de checks, acción, impacto, esfuerzo)
    (["jsonld", "jsonld_valid", "org", "lb_complete", "lb_locality"],
     "Implementar schema LocalBusiness completo (NAP + dirección estructurada)", "Alto", "Bajo"),
    (["llms_txt"], "Crear llms.txt con la ficha del negocio para LLMs", "Alto", "Bajo"),
    (["faqpage", "faq_dom", "aeo_faq_schema", "aeo_faq_dom", "aeo_faq_count"],
     "Crear sección FAQ visible + schema FAQPage (8-10 preguntas reales)", "Alto", "Medio"),
    (["geo_region", "geo_place", "icbm", "geocoords"],
     "Añadir señales GEO (geo.region, geo.placename, ICBM, GeoCoordinates)", "Alto", "Bajo"),
    (["bot_GPTBot", "bot_ClaudeBot", "bot_PerplexityBot", "bot_Google-Extended"],
     "Desbloquear bots de IA en robots.txt", "Alto", "Bajo"),
    (["gbp"], "Crear/optimizar la ficha de Google Business Profile", "Alto", "Bajo"),
    (["pagespeed_score"], "Optimizar el rendimiento móvil (Core Web Vitals)", "Alto", "Medio"),
    (["cro_whatsapp", "cro_phone", "cro_form", "cro_cta"],
     "Mejorar la conversión: WhatsApp, teléfono, formulario y CTA visibles", "Alto", "Bajo"),
    (["dir_paginasamarillas.es", "dir_yelp.es", "dir_tripadvisor.es", "dir_eltenedor.es",
      "dir_booking.com", "dir_idealista.com", "dir_fotocasa.es", "dir_doctoralia.es",
      "dir_cylex.es", "dir_treatwell.es", "dir_infoisinfo.es"],
     "Dar de alta el negocio en directorios locales relevantes", "Medio", "Bajo"),
    (["arquitectura"], "Crear páginas locales por zona de cobertura", "Alto", "Medio"),
    (["about"], 'Publicar página "Quiénes somos" (equipo y experiencia)', "Medio", "Bajo"),
    (["casos"], "Añadir casos de éxito / testimonios (+ schema Review)", "Medio", "Medio"),
    (["title", "title_len", "title_kw", "desc", "desc_len", "canonical"],
     "Optimizar title, meta description y canonical", "Medio", "Bajo"),
    (["og_td", "og_img", "og_dims", "twitter"],
     "Configurar Open Graph completo con imagen 1200×630", "Medio", "Bajo"),
    (["aeo_howto"], "Añadir schema HowTo al servicio principal", "Medio", "Medio"),
    (["h1", "hierarchy"], "Corregir jerarquía de encabezados (H1 único, sin saltos)", "Medio", "Bajo"),
    (["img_alt", "img_dims"], "Completar alt y dimensiones en imágenes", "Medio", "Medio"),
    (["breadcrumb"], "Añadir schema BreadcrumbList", "Bajo", "Bajo"),
    (["scripts"], "Diferir scripts externos no críticos (defer/async)", "Bajo", "Bajo"),
    (["robots_txt", "sitemap"], "Crear/completar robots.txt con Sitemap", "Bajo", "Bajo"),
    (["lang", "viewport"], "Declarar lang y viewport", "Bajo", "Bajo"),
]

IMPACT_RANK = {"Alto": 0, "Medio": 1, "Bajo": 2}
EFFORT_RANK = {"Bajo": 0, "Medio": 1, "Alto": 2}


# ──────────────────────────────────────────────────────────────────────────────
# Productos WhiteMoon
# ──────────────────────────────────────────────────────────────────────────────

# Ticket medio por sector (clave: sector tal como se selecciona en el formulario)
SECTOR_TICKETS = {
    "clínica dental": 800,
    "taller mecánico": 350,
    "gestoría": 400,
    "centro de estética": 250,
    "hostelería": 180,
    "inmobiliaria": 3500,
    "farmacia": 120,
    "despacho de abogados": 600,
    "podología": 180,
    "academia": 300,
    "gimnasio": 500,
    "hotel": 1200,
    "e-commerce": 150,
    "fontanería": 300,
    "servicio técnico": 280,
    "transporte y logística": 1500,
    "marketing y publicidad": 2000,
    "muebles y decoración": 900,
    "bodega y vinos": 1800,
    "psicología y coaching": 350,
    "psiquiatría": 500,
    "formación y academia": 300,
    "otro": 400,
}

TICKET_DEFAULT = 400


def ticket_sector(sector):
    """Ticket medio del sector seleccionado (comparación sin acentos/mayúsculas)."""
    normalizado = {_norm(k): v for k, v in SECTOR_TICKETS.items()}
    return normalizado.get(_norm(sector), TICKET_DEFAULT)

SECTOR_PATTERNS = [
    ("dental", ["dental", "dentist", "odont"]),
    ("taller", ["taller", "mecanic"]),
    ("gestoria", ["gestor", "asesor"]),
    ("estetica", ["estet", "belleza", "peluquer"]),
    ("hosteleria", ["hostel", "restaur", "cafeter", "bar"]),
    ("inmobiliaria", ["inmobil"]),
    ("farmacia", ["farmac", "parafarm"]),
    ("abogados", ["abogad", "jurid", "legal"]),
    ("podologia", ["podolog"]),
    ("psicologia", ["psicolog", "coach"]),
    ("psiquiatria", ["psiquiatr"]),
    ("academia", ["academ", "formaci", "escuela"]),
    ("gimnasio", ["gimnas", "fitness", "crossfit"]),
    ("hotel", ["hotel", "alojam", "hostal", "apartament"]),
    ("ecommerce", ["ecommerce", "e-commerce", "tienda online", "comercio electr"]),
    ("fontaneria", ["fontaner"]),
]


def sector_key(sector):
    s = _norm(sector)
    for key, pats in SECTOR_PATTERNS:
        if any(p in s for p in pats):
            return key
    return "otro"


PRODUCTOS = {
    "spark": {
        "nombre": "Spark",
        "setup": "499€", "mes": "199€/mes",
        "url": "whitemoon.es/spark/",
        "porque": "Ideal para negocios de {sector} que quieren dar el primer paso en {ciudad}: "
                  "visibilidad para la IA y atención por chat, rápido de implantar y con las "
                  "bases GEO/AEO incluidas.",
        "incluye": [
            "Chatbot IA entrenado con la información del negocio",
            "Captura de leads 24/7 con aviso inmediato",
            "Implementación GEO/AEO básica (schema, llms.txt, señales locales)",
            "Panel de conversaciones y métricas",
        ],
    },
    "orion": {
        "nombre": "Orion IA Agent",
        "setup": "999€", "mes": "199€/mes",
        "url": "whitemoon.es/orion-agent/",
        "porque": "Ideal para negocios de {sector} que quieren atender clientes 24/7 sin "
                  "operador humano: Orion IA captura leads automáticamente y gestiona citas "
                  "en español natural.",
        "incluye": [
            "Agente de voz 24/7 en español natural",
            "Captura nombre, teléfono y motivo automáticamente",
            "Notificación inmediata a tu WhatsApp",
            "Gestión de citas sin intervención humana",
            "Operativo en 5-7 días · Sin permanencia",
        ],
    },
    "core": {
        "nombre": "Core",
        "setup": "1.800€", "mes": "opcional (mantenimiento)",
        "url": "whitemoon.es/core/",
        "porque": "Ideal para negocios de {sector} que necesitan una base digital sólida en "
                  "{ciudad}: web nueva con GEO/AEO de serie y Orion IA integrado desde el "
                  "primer día.",
        "incluye": [
            "Web nueva optimizada GEO/AEO desde el diseño",
            "Schema completo, llms.txt y señales de geolocalización",
            "Chat IA (Orion IA) integrado en la web",
            "Analítica de visibilidad en buscadores y motores de IA",
        ],
    },
    "core_rag": {
        "nombre": "Core RAG",
        "setup": "3.200€", "mes": "opcional (mantenimiento)",
        "url": "whitemoon.es/core-rag/",
        "porque": "Ideal para negocios de {sector} que responden las mismas preguntas cada "
                  "día: Core RAG convierte su documentación en respuestas instantáneas, "
                  "fiables y citables.",
        "incluye": [
            "IA que responde con la documentación real del negocio (RAG)",
            "Base de conocimiento privada y actualizable",
            "Respuestas consistentes para clientes y equipo",
            "Integración en web y canales de atención",
        ],
    },
}

# Producto por sector cuando la base técnica ya es buena (score > 75)
PRODUCTO_POR_SECTOR = {
    "dental": "orion", "estetica": "orion", "podologia": "orion", "gimnasio": "orion",
    "gestoria": "core_rag", "abogados": "core_rag", "academia": "core_rag",
    "psicologia": "core_rag", "psiquiatria": "core_rag",
    "hosteleria": "spark", "hotel": "spark",
    "inmobiliaria": "core",
    "taller": "orion", "fontaneria": "orion",
    "ecommerce": "spark", "farmacia": "spark",
    "otro": "core",
}


def productos_recomendados(score, sector):
    """Orion IA Agent siempre primero; el segundo según sector y score."""
    skey = sector_key(sector)
    if skey in ("gestoria", "abogados", "academia", "psicologia", "psiquiatria"):
        segundo = "core_rag"
    elif score < 50:
        segundo = "spark"
    else:
        segundo = PRODUCTO_POR_SECTOR.get(skey, "core")
    if segundo == "orion":
        segundo = "core_rag"
    return ["orion", segundo]


def plan_de_accion(audit):
    lost = {c["id"]: c["max"] - c["points"] for c in audit.failed()}
    plan = []
    for ids, accion, impacto, esfuerzo in ACTIONS:
        pts = round(sum(lost.get(i, 0) for i in ids), 1)
        if pts > 0:
            plan.append({"accion": accion, "impacto": impacto, "esfuerzo": esfuerzo, "pts": pts})
    plan.sort(key=lambda p: (IMPACT_RANK[p["impacto"]], EFFORT_RANK[p["esfuerzo"]], -p["pts"]))
    return plan[:5]


def business_name_from_title(title, fallback):
    """Extrae el nombre del negocio del <title> cortando en el primer separador
    habitual (—, –, -, |, ·, :, »). Si no hay título usable, usa el nombre dado."""
    if title:
        name = re.split(r"\s*[\|–—·:»>]\s*|\s+-\s+", title)[0].strip()
        if len(name) >= 2:
            return name
    return fallback


def split_scores(audit, seo_pts, seo_max, geo_pts, geo_max, aeo_pts, aeo_max,
                 aut_pts=0, aut_max=0, cro_pts=0, cro_max=0, dir_pts=0, dir_max=0):
    """Reparte el score en dos métricas que suman el global:
    - Score Técnico  = SEO (incl. PageSpeed, sin llms.txt) + CRO
    - Score Control IA = GEO + AEO + Autoridad + Directorios + llms.txt
    El llms.txt está en el área 'robots', así que se mueve a Control IA.
    Autoridad/Directorios (E-E-A-T) y GEO/AEO definen cómo la IA representa y
    recomienda al negocio; CRO es técnico de la propia web (conversión)."""
    llms = next((c for c in audit.checks if c["id"] == "llms_txt"), None)
    llms_pts = llms["points"] if llms else 0
    llms_max = llms["max"] if llms else 0
    tecnico_pts = round(seo_pts - llms_pts + cro_pts, 1)
    tecnico_max = round(seo_max - llms_max + cro_max, 1)
    control_pts = round(geo_pts + aeo_pts + aut_pts + dir_pts + llms_pts, 1)
    control_max = round(geo_max + aeo_max + aut_max + dir_max + llms_max, 1)
    return tecnico_pts, tecnico_max, control_pts, control_max


def render_report(audit, site, ctx):
    nombre, sector, ciudad = ctx["nombre"], ctx["sector"], ctx["ciudad"]
    hoy = date.today().isoformat()

    seo_pts, seo_max = audit.area_score("meta", "estructura", "schema", "robots", "pagespeed")
    geo_pts, geo_max = audit.area_score("geo")
    aeo_pts, aeo_max = audit.area_score("aeo")
    aut_pts, aut_max = audit.area_score("autoridad")
    cro_pts, cro_max = audit.area_score("cro")
    dir_pts, dir_max = audit.area_score("directorios")
    score = round(seo_pts + geo_pts + aeo_pts + aut_pts + cro_pts + dir_pts)
    emoji, nombre_nivel, desc_nivel = nivel(score)

    # Dos métricas que suman el global (CRO → técnico, Directorios → control IA).
    tecnico_pts, tecnico_max, control_pts, control_max = split_scores(
        audit, seo_pts, seo_max, geo_pts, geo_max, aeo_pts, aeo_max, aut_pts, aut_max,
        cro_pts, cro_max, dir_pts, dir_max)

    plan = plan_de_accion(audit)
    ganancia = round(sum(p["pts"] for p in plan))
    score_potencial = min(100, score + ganancia)

    try:
        charts = generate_charts({
            "seo": seo_pts, "seo_max": seo_max,
            "geo": geo_pts, "geo_max": geo_max,
            "aeo": aeo_pts, "aeo_max": aeo_max,
            "autoridad": aut_pts, "autoridad_max": aut_max,
            "cro": cro_pts, "cro_max": cro_max,
            "directorios": dir_pts, "directorios_max": dir_max,
            "score": score,
            "checks_ok": sum(1 for c in audit.checks if c["status"] == "ok"),
            "checks_warn": sum(1 for c in audit.checks if c["status"] == "warn"),
            "checks_error": sum(1 for c in audit.checks if c["status"] == "error"),
        })
    except Exception:
        charts = {}  # las gráficas nunca deben impedir generar el informe

    L = []
    w = L.append

    def w_chart(key, alt):
        if charts.get(key):
            w("![%s](data:image/png;base64,%s)" % (alt, charts[key]))
            w("")

    # ── Cabecera ──
    w("# Auditoría GEO IA — %s" % nombre)
    w("")
    w("**Fecha:** %s | **URL:** %s | **Sector:** %s | **Ciudad:** %s" % (hoy, site["url"], sector, ciudad))
    w("**Realizada por:** WhiteMoon Agencia IA · whitemoon.es")
    w("")
    w("---")
    w("")

    # ── Resumen ejecutivo ──
    w("## 🎯 RESUMEN EJECUTIVO")
    w("*(Para el CEO/dueño del negocio)*")
    w("")
    w("> **Aparecer en IA no es suficiente — lo importante es controlar lo que dice la IA de ti.** "
      "Sin las señales correctas, ChatGPT y Grok improvisan. Con ellas, tú decides el mensaje.")
    w("")
    w("**Puntuación global: %d/100 — %s %s** (%s)" % (score, emoji, nombre_nivel, desc_nivel))
    w("")
    w("- 🔧 **Score Técnico** (SEO + PageSpeed + CRO, sin llms.txt): **%s/%s** %s"
      % (fmt_pts(tecnico_pts), fmt_pts(tecnico_max), estado_emoji(tecnico_pts, tecnico_max)))
    w("- 🤖 **Score Control IA** (GEO + AEO + Autoridad + Directorios + llms.txt): **%s/%s** %s"
      % (fmt_pts(control_pts), fmt_pts(control_max), estado_emoji(control_pts, control_max)))
    w("")
    w("**Puntuación por área:**")
    w("")
    w("- 🔧 SEO Técnico: **%s/%s** %s"
      % (fmt_pts(seo_pts), fmt_pts(seo_max), estado_emoji(seo_pts, seo_max)))
    w("- 🌍 GEO Local IA: **%s/%s** %s"
      % (fmt_pts(geo_pts), fmt_pts(geo_max), estado_emoji(geo_pts, geo_max)))
    w("- 💬 AEO Respuestas: **%s/%s** %s"
      % (fmt_pts(aeo_pts), fmt_pts(aeo_max), estado_emoji(aeo_pts, aeo_max)))
    w("- 🏆 Autoridad: **%s/%s** %s"
      % (fmt_pts(aut_pts), fmt_pts(aut_max), estado_emoji(aut_pts, aut_max)))
    w("- 🎯 Conversión (CRO): **%s/%s** %s"
      % (fmt_pts(cro_pts), fmt_pts(cro_max), estado_emoji(cro_pts, cro_max)))
    w("- 🗂️ Directorios locales: **%s/%s** %s"
      % (fmt_pts(dir_pts), fmt_pts(dir_max), estado_emoji(dir_pts, dir_max)))
    w("")
    w_chart("checks", "Resumen de checks")
    w("**En una frase:** %s" % frase_resumen(score, nombre, sector, ciudad))
    w("")
    problemas = top_problemas(audit)
    if problemas:
        w("**Los %d problemas más urgentes:**" % len(problemas))
        for i, p in enumerate(problemas, 1):
            w("%d. %s" % (i, p))
    else:
        w("**Sin problemas urgentes** — la web está técnicamente sólida; ver mejoras menores abajo.")
    w("")
    w("---")
    w("")

    w_chart("areas", "Puntuación por área")

    # ── Análisis técnico ──
    w("## 🔬 ANÁLISIS TÉCNICO COMPLETO")
    w("*(Para el SEO/informático/agencia)*")
    w("")
    w("### SEO Técnico")
    w("")
    for area, title in AREA_TITLES:
        checks = [c for c in audit.checks if c["area"] == area]
        pts = sum(c["points"] for c in checks)
        maxp = sum(c["max"] for c in checks)
        w("#### %s (%s/%s pts)" % (title, fmt_pts(pts), fmt_pts(maxp)))
        w("")
        for c in checks:
            if c["id"] == "types":
                w("- ℹ️ **Tipos de schema detectados:** %s" % (c["detail"] or "ninguno"))
                continue
            detail = " — %s" % c["detail"] if c["detail"] else ""
            w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
            _render_fix(w, c)
        w("")

    # PageSpeed (rendimiento real, dentro de SEO Técnico)
    ps_checks = [c for c in audit.checks if c["area"] == "pagespeed"]
    if ps_checks:
        ps_pts = sum(c["points"] for c in ps_checks)
        ps_max = sum(c["max"] for c in ps_checks)
        w("#### Rendimiento — PageSpeed Insights (%s/%s pts)" % (fmt_pts(ps_pts), fmt_pts(ps_max)))
        w("")
        for c in ps_checks:
            detail = " — %s" % c["detail"] if c["detail"] else ""
            w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
            _render_fix(w, c)
        w("")

    # ── GEO ──
    w("### GEO — Señales de Geolocalización IA")
    w("")
    w("Señales detectadas: **%d/5** → **%s/%s puntos**"
      % (ctx.get("geo_signals", 0), fmt_pts(geo_pts), fmt_pts(geo_max)))
    w("")
    for c in [c for c in audit.checks if c["area"] == "geo"]:
        detail = " — %s" % c["detail"] if c["detail"] else ""
        w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
        _render_fix(w, c)
    w("")
    w("> **Nota sobre geo.region / geo.placename / ICBM:** señales de geolocalización")
    w("> básicas — impacto moderado, fáciles de implementar. Suman en conjunto, pero el")
    w("> peso real lo aportan la dirección estructurada (LocalBusiness) y la ficha de Google.")
    w("")
    w("> Estas 5 señales son las que permiten a un motor de IA responder con confianza a")
    w("> \"%s en %s\" citando a un negocio concreto. Sin ellas, la IA recurre a directorios" % (sector, ciudad))
    w("> genéricos o a competidores mejor etiquetados.")
    w("")

    # ── AEO ──
    w("### AEO — Optimización para Motores de Respuesta")
    w("")
    for c in [c for c in audit.checks if c["area"] == "aeo"]:
        detail = " — %s" % c["detail"] if c["detail"] else ""
        w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
        _render_fix(w, c)
    w("")

    # ── Presencia y Autoridad ──
    w("### Presencia y Autoridad (E-E-A-T)")
    w("")
    w("Puntuación: **%s/%s puntos**" % (fmt_pts(aut_pts), fmt_pts(aut_max)))
    w("")
    for c in [c for c in audit.checks if c["area"] == "autoridad"]:
        detail = " — %s" % c["detail"] if c["detail"] else ""
        w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
        _render_fix(w, c)
    w("")
    w("> La autoridad (Google Business, equipo visible, casos reales y arquitectura local)")
    w("> es lo que distingue a un negocio recomendable de uno más: son las señales E-E-A-T")
    w("> que la IA cruza para decidir a quién cita.")
    w("")

    # ── CRO / Conversión ──
    w("### Conversión (CRO)")
    w("")
    w("Puntuación: **%s/%s puntos**" % (fmt_pts(cro_pts), fmt_pts(cro_max)))
    w("")
    for c in [c for c in audit.checks if c["area"] == "cro"]:
        detail = " — %s" % c["detail"] if c["detail"] else ""
        w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
        _render_fix(w, c)
    w("")
    w("> Atraer visitas no sirve si no convierten: WhatsApp, teléfono, formulario y una")
    w("> llamada a la acción clara son lo mínimo para transformar la visita en cliente.")
    w("")

    # ── Directorios locales ──
    w("### Directorios locales")
    w("")
    w("Puntuación: **%s/%s puntos**" % (fmt_pts(dir_pts), fmt_pts(dir_max)))
    w("")
    for c in [c for c in audit.checks if c["area"] == "directorios"]:
        detail = " — %s" % c["detail"] if c["detail"] else ""
        w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
        _render_fix(w, c)
    w("")
    w("> Las citas en directorios refuerzan el NAP (nombre, dirección, teléfono) y la")
    w("> autoridad local que Google y la IA usan para validar el negocio.")
    w("")

    # ── Robots ──
    w("### Robots y Acceso para Bots IA")
    w("")
    for c in [c for c in audit.checks if c["area"] == "robots" and not c["id"].startswith("bot_")]:
        detail = " — %s" % c["detail"] if c["detail"] else ""
        w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
        _render_fix(w, c)
    w("")
    w("| Bot de IA | Motor | Estado |")
    w("|-----------|-------|--------|")
    bot_motor = {"GPTBot": "ChatGPT (OpenAI)", "ClaudeBot": "Claude (Anthropic)",
                 "PerplexityBot": "Perplexity", "Google-Extended": "Gemini (Google)"}
    estado_txt = {"allowed": "✅ Permitido", "blocked": "❌ Bloqueado",
                  "implicit": "⚠️ No declarado (acceso implícito)",
                  "no_robots": "⚠️ Sin robots.txt (acceso implícito)"}
    for bot in AI_BOTS:
        w("| %s | %s | %s |" % (bot, bot_motor[bot], estado_txt[ctx["bots"].get(bot, "implicit")]))
    w("")
    w("> **Nota sobre los bots de IA:** si no están bloqueados, los bots acceden igualmente.")
    w("> Declarar `Allow` es una buena práctica pero no imprescindible. Lo crítico es **no**")
    w("> bloquearlos por error en robots.txt.")
    w("")

    # ── Marketing ──
    w("### Marketing — Píxel de Meta Ads")
    w("")
    for c in [c for c in audit.checks if c["area"] == "ads"]:
        detail = " — %s" % c["detail"] if c["detail"] else ""
        w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
    w("")

    # ── Inventario de contenido ──
    cont = ctx.get("contenido")
    if cont:
        w("### Inventario de contenido")
        w("")
        if cont["total"]:
            blog = ("Sí (%d artículos)" % cont["blog_count"]) if cont["has_blog"] else "No"
            w("**%d páginas indexadas** (sitemap) · **Blog:** %s" % (cont["total"], blog))
        else:
            w("No se pudo leer el sitemap.xml para inventariar el contenido.")
        w("")
        w("> Más contenido útil y actualizado = más superficie para que la IA y Google te citen.")
        w("")
    w("---")
    w("")

    # ── Análisis de competencia ──
    comp = ctx.get("competidores")
    cli = ctx.get("cliente_checks")
    if comp or cli:
        w("## 🥊 ANÁLISIS DE COMPETENCIA")
        w("*(Top resultados orgánicos para \"%s en %s\" — informativo)*" % (sector, ciudad))
        w("")
        if comp:
            def _si(b):
                return "✅" if b else "❌"
            w("| Web | Title ≤65 | LocalBusiness | FAQPage | llms.txt | robots.txt |")
            w("|-----|:---------:|:-------------:|:-------:|:--------:|:----------:|")
            if cli:
                w("| **%s (tú)** | %s | %s | %s | %s | %s |" % (
                    cli["host"], _si(cli["title_ok"]), _si(cli["lb"]), _si(cli["faq"]),
                    _si(cli["llms"]), _si(cli["robots"])))
            for c in comp:
                w("| %s | %s | %s | %s | %s | %s |" % (
                    c["host"], _si(c["title_ok"]), _si(c["lb"]), _si(c["faq"]),
                    _si(c["llms"]), _si(c["robots"])))
            w("")
            w("> Compárate con quien ya aparece arriba: las columnas en ❌ de tu fila son")
            w("> exactamente las ventajas que hoy te llevan tus competidores.")
        else:
            w("No se pudieron extraer competidores automáticamente (Google limitó la consulta).")
            w("Repite la búsqueda manualmente: \"%s en %s\" y compara las 5 primeras webs." % (sector, ciudad))
        w("")
        w("---")
        w("")

    # ── Qué mejora con esta auditoría ──
    queries = ['- "%s en %s"' % (sector, ciudad),
               '- "mejor %s %s"' % (sector, ciudad),
               '- "%s"' % nombre]
    if score >= 90:
        w("## 📊 QUÉ TIENES BIEN Y CÓMO MANTENERLO")
        w("")
        w("Tu web tiene las señales técnicas correctas para que los motores de IA "
          "puedan verificar y citar tu negocio con confianza.")
        w("")
        w("**Lo que tienes implementado correctamente:**")
        w("")
        w("✅ Crawlers de IA con acceso permitido")
        w("✅ Datos estructurados verificables (schema)")
        w("✅ Señales GEO asociadas a tu ciudad")
        w("✅ Contenido FAQ y HowTo citable por LLMs")
        w("✅ llms.txt con ficha del negocio para LLMs")
        w("")
        w("**Verifica tu posición actual (2 minutos):** busca en ChatGPT y Perplexity:")
        w("")
        for q in queries:
            w(q)
        w("")
        w("**Para mantener tu posición:**")
        w("")
        w("- Actualiza el contenido FAQ periódicamente")
        w("- No elimines las señales GEO/AEO implementadas")
        w("- Añade contenido nuevo regularmente")
        w("")
    else:
        w("## 📊 QUÉ MEJORA CON ESTA AUDITORÍA")
        w("")
        w("Esta auditoría mide las señales técnicas que los motores de IA (ChatGPT, "
          "Grok, Perplexity, Gemini) utilizan para entender, verificar y citar negocios.")
        w("")
        w("**Lo que conseguirás implementando el plan de acción:**")
        w("")
        w("✅ Los crawlers de IA (GPTBot, ClaudeBot, PerplexityBot) podrán leer y "
          "entender tu negocio correctamente")
        w("✅ Tus datos (nombre, dirección, servicios, zona) estarán estructurados "
          "para ser citados textualmente")
        w("✅ Tendrás FAQ y HowTo que los LLMs pueden usar como respuesta directa "
          "a preguntas de clientes")
        w("✅ Tu negocio estará asociado con precisión a tu ciudad y zona de cobertura")
        w("")
        w("**Verifica tu posición actual (2 minutos):** busca en ChatGPT y Perplexity:")
        w("")
        for q in queries:
            w(q)
        w("")
        w("Anota si apareces — tras el plan de acción vuelve a buscar en 30-60 días "
          "para medir el impacto real.")
        w("")
        w("*Nota: la presencia en motores de IA depende de múltiples factores "
          "(antigüedad del dominio, reputación, competencia). Esta auditoría optimiza "
          "los factores técnicos verificables que están en tu mano.*")
        w("")
    w("---")
    w("")

    # ── Verifica tu presencia en IA ahora (links pregenerados) ──
    negocio = business_name_from_title(ctx.get("title", ""), nombre)
    q = quote_plus("%s %s" % (negocio, ciudad))
    w("## 🔎 VERIFICA TU PRESENCIA EN IA AHORA")
    w("")
    w("Pregunta a la IA por **%s** y comprueba qué dice de tu negocio:" % negocio)
    w("")
    w("- **ChatGPT:** https://chat.openai.com/?q=%s" % q)
    w("- **Perplexity:** https://www.perplexity.ai/search?q=%s" % q)
    w("- **Grok:** https://grok.x.com/?q=%s" % q)
    w("")
    w("Abre cada enlace y comprueba si la IA te recomienda. Anota el resultado — tras "
      "implementar el plan, vuelve a comprobarlo en 30 días.")
    w("")
    w("---")
    w("")

    # ── Plan de acción ──
    w("## 🚀 PLAN DE ACCIÓN PRIORIZADO")
    w("*(Top %d acciones por impacto/esfuerzo)*" % len(plan))
    w("")
    if plan:
        w("| # | Acción | Impacto | Esfuerzo | Puntos ganados |")
        w("|---|--------|---------|----------|----------------|")
        for i, p in enumerate(plan, 1):
            w("| %d | %s | %s | %s | +%s pts |" % (i, p["accion"], p["impacto"], p["esfuerzo"], fmt_pts(p["pts"])))
        w("")
        w("**Score potencial tras implementar las %d acciones: %d/100**" % (len(plan), score_potencial))
        w("*(Estimación honesta — suma exacta de los puntos de los checks corregidos, no inflada)*")
    else:
        w("No hay acciones pendientes de alto impacto: la web supera todos los checks puntuables.")
    w("")
    w("---")
    w("")

    # ── Hoja de ruta 6 meses ──
    w("## 🗓️ HOJA DE RUTA 6 MESES")
    w("")
    w("### Mes 1-2 — Base técnica")
    w("- Implementar LocalBusiness completo con NAP")
    w("- Añadir FAQPage con 8-10 preguntas reales")
    w("- Optimizar velocidad (defer scripts, imágenes WebP)")
    w("")
    w("### Mes 3-4 — Contenido y autoridad local")
    w("- Crear páginas locales por zona de cobertura")
    w("- Blog con 8-10 artículos sobre %s en %s" % (sector, ciudad))
    w("- Optimizar/crear ficha Google Business con fotos y reseñas")
    w("")
    w("### Mes 5-6 — E-E-A-T y backlinks")
    w('- Página "Quiénes somos" con equipo y experiencia real')
    w("- Casos de éxito con datos reales")
    w("- Backlinks locales (prensa, directorios, colaboradores)")
    w("- Reseñas verificadas en Google Business")
    w("")
    w("---")
    w("")

    # ── Potencial de mejora ──
    w("## 📈 POTENCIAL DE MEJORA")
    w("")
    w("**Score actual:** %d/100" % score)
    w("**Score potencial tras implementar el plan:** %d/100" % score_potencial)
    w("**Diferencia:** +%d puntos" % max(score_potencial - score, 0))
    w("")
    w("Las mejoras técnicas identificadas eliminan barreras que impiden que los motores")
    w("de búsqueda e IA indexen y recomienden tu negocio correctamente. El impacto en")
    w("tráfico y clientes depende de factores adicionales como autoridad de dominio,")
    w("competencia local y presupuesto de contenidos.")
    w("")
    w("---")
    w("")

    # ── Soluciones WhiteMoon ──
    w("## 💡 SOLUCIONES WHITEMOON RECOMENDADAS")
    w("*(Productos específicos para %s en %s)*" % (sector, ciudad))
    w("")
    for key in productos_recomendados(score, sector):
        p = PRODUCTOS[key]
        w("### %s" % p["nombre"])
        w("**Setup:** %s · **Mensualidad:** %s · **Sin permanencia**" % (p["setup"], p["mes"]))
        w("**Por qué para tu negocio:** %s" % p["porque"].format(sector=sector, ciudad=ciudad))
        w("**Incluye:**")
        for feat in p["incluye"]:
            w("- %s" % feat)
        w("")
        w("**Implementación incluida — sin necesidad de programador.**")
        w("")
        w("→ Más información: %s" % p["url"])
        w("")
    w("¿Tienes preguntas? Solicita una consulta gratuita de 15 minutos: whitemoon.es/auditoria-ia")
    w("")

    # ── Oportunidad Meta Ads (solo si la web no tiene píxel de Meta) ──
    sin_pixel = any(c["id"] == "meta_pixel" and c["status"] == "warn" for c in audit.checks)
    if sin_pixel:
        w("---")
        w("")
        w("## OPORTUNIDAD: CAPTACIÓN CON META ADS")
        w("")
        w("Tu negocio no tiene Meta Ads activo. Tu competencia puede estar captando")
        w("clientes en Facebook e Instagram mientras tú no apareces.")
        w("")
        w("**Simulación orientativa (presupuesto 300€/mes en Meta Ads):**")
        w("- Alcance estimado: 15.000-40.000 personas/mes en tu zona")
        w("- Leads estimados: 20-50 leads/mes")
        w("- Coste por lead estimado: 6-15€")
        w("")
        w("**Pack Ads WhiteMoon — 599€/mes**")
        w("- Gestión completa de Meta Ads (Facebook + Instagram)")
        w("- Creatividades incluidas")
        w("- Sin permanencia")
        w("- Inversión en plataforma: a cargo del cliente (mínimo recomendado 300€/mes)")
        w("")
        w("Contacto: 643 199 580 | comercial@whitemoon.es")
        w("")

    w("---")
    w("")

    # ── Verificación en 30 días ──
    w("## 📅 VERIFICACIÓN EN 30 DÍAS")
    w("")
    w("Guarda este informe. En 30 días tras implementar el plan, vuelve a auditar gratis en "
      "[whitemoon-seo-geo-ia.onrender.com](https://whitemoon-seo-geo-ia.onrender.com) y mide el impacto real.")
    w("")
    w("---")
    w("")
    w("*Auditoría GEO IA realizada por WhiteMoon · whitemoon.es*")
    w("*¿Quieres implementar estas mejoras? Solicitar propuesta sin compromiso: whitemoon.es/auditoria-geo-ia*")
    w("")

    return "\n".join(L), score


def _render_fix(w, check):
    """Para cada ERROR: qué es, por qué importa, qué pierde el negocio, cómo corregirlo."""
    if check["status"] != "error":
        return
    guide = FIX_GUIDE.get(check["id"])
    if not guide:
        return
    que, porque, pierde, como = guide
    w("  - **Qué es:** %s" % que)
    w("  - **Por qué importa:** %s" % porque)
    w("  - **Tu competencia que sí lo tiene:** %s" % pierde)
    w("  - **Cómo corregirlo:** %s" % como)


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def run_audit_full(url, nombre, sector, ciudad, out_dir="reports", html_manual=None):
    """Ejecuta la auditoría completa, escribe el informe y devuelve un dict
    con todos los datos (para CLI y para la interfaz web).

    html_manual: HTML pegado a mano (modo directo); si se indica, no se
    descarga la página principal. El análisis es idéntico en ambos casos."""
    print("🌙 WhiteMoon — Auditoría GEO IA")
    print("→ Auditando %s (%s, %s, %s)%s…" % (url, nombre, sector, ciudad,
                                              " [HTML directo]" if html_manual else ""))

    site = fetch_site(url, html_manual)
    print("✓ HTML descargado (%d KB) · robots.txt: %s · llms.txt: %s" % (
        len(site["html"]) // 1024,
        "sí" if site["robots"] is not None else "no",
        "sí" if site["llms"] else "no"))

    audit = Audit()
    ctx = {"nombre": nombre, "sector": sector, "ciudad": ciudad, "url": site["url"]}

    check_meta_tags(audit, site, ctx)
    check_structure(audit, site)
    check_schema(audit, site, ctx)
    check_robots(audit, site, ctx)
    check_geo(audit, site, ctx)
    check_aeo(audit, site, ctx)
    check_autoridad(audit, site, ctx)
    check_ads(audit, site)
    check_pagespeed(audit, site, ctx)
    check_cro(audit, site, ctx)
    check_directorios(audit, ctx)
    check_contenido(site, ctx)
    check_competidores(audit, site, ctx)

    report, score = render_report(audit, site, ctx)

    netloc = urlparse(site["url"]).netloc
    if netloc.startswith("www."):
        netloc = netloc[4:]
    domain = re.sub(r"[^A-Za-z0-9.-]", "-", netloc)  # ej. el ':' de un puerto rompe en Windows
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / ("audit-%s-%s.md" % (domain, date.today().isoformat()))
    path.write_text(report, encoding="utf-8")

    emoji, nombre_nivel, desc_nivel = nivel(score)
    print("✓ Score: %d/100 %s %s" % (score, emoji, nombre_nivel))
    print("✓ Informe generado: %s" % path)

    seo_pts, seo_max = audit.area_score("meta", "estructura", "schema", "robots", "pagespeed")
    geo_pts, geo_max = audit.area_score("geo")
    aeo_pts, aeo_max = audit.area_score("aeo")
    aut_pts, aut_max = audit.area_score("autoridad")
    cro_pts, cro_max = audit.area_score("cro")
    dir_pts, dir_max = audit.area_score("directorios")
    tecnico_pts, tecnico_max, control_pts, control_max = split_scores(
        audit, seo_pts, seo_max, geo_pts, geo_max, aeo_pts, aeo_max, aut_pts, aut_max,
        cro_pts, cro_max, dir_pts, dir_max)
    errores = [{"check": c["label"], "detail": c["detail"]}
               for c in audit.checks if c["status"] == "error"]
    warnings = [{"check": c["label"], "detail": c["detail"]}
                for c in audit.checks if c["status"] == "warn"]

    return {
        "path": str(path), "filename": path.name, "score": score,
        "nivel": nombre_nivel, "nivel_emoji": emoji, "nivel_desc": desc_nivel,
        "seo": seo_pts, "seo_max": seo_max,
        "geo": geo_pts, "geo_max": geo_max,
        "aeo": aeo_pts, "aeo_max": aeo_max,
        "autoridad": aut_pts, "autoridad_max": aut_max,
        "cro": cro_pts, "cro_max": cro_max,
        "directorios": dir_pts, "directorios_max": dir_max,
        "tecnico": tecnico_pts, "tecnico_max": tecnico_max,
        "control": control_pts, "control_max": control_max,
        "frase": frase_resumen(score, nombre, sector, ciudad),
        "problemas": top_problemas(audit),
        "errores": errores, "warnings": warnings,
        "report_md": report,
        "cliente": nombre, "sector": sector, "ciudad": ciudad, "url": site["url"],
    }


def run_audit(url, nombre, sector, ciudad, out_dir="reports"):
    """Ejecuta la auditoría completa y escribe el informe. Devuelve (ruta, score)."""
    data = run_audit_full(url, nombre, sector, ciudad, out_dir)
    return data["path"], data["score"]


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        print("Uso: python audit_client.py <url> \"Nombre Cliente\" \"sector\" \"ciudad\"")
        sys.exit(1)
    try:
        run_audit(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    except AuditError as e:
        print("❌ ERROR: %s" % e)
        sys.exit(1)


if __name__ == "__main__":
    main()
