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

import json
import re
import sys
import unicodedata
from datetime import date
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("❌ Faltan dependencias. Instala con:  pip install -r requirements.txt")
    sys.exit(1)

USER_AGENT = "Mozilla/5.0 (compatible; WhiteMoon-Audit/1.0)"
HEADERS = {"User-Agent": USER_AGENT, "Accept-Language": "es-ES,es;q=0.9"}
TIMEOUT = 25

AI_BOTS = ["GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended"]

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

def fetch_site(url):
    """Descarga la página principal, robots.txt y llms.txt."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
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
    root = "{0}://{1}".format(urlparse(final_url).scheme, urlparse(final_url).netloc)

    robots_txt = _fetch_optional(root + "/robots.txt")
    llms_txt = _fetch_optional(root + "/llms.txt")

    # Parsear desde bytes: BeautifulSoup detecta el charset del documento
    # (evita mojibake cuando el servidor no declara charset en las cabeceras)
    soup = BeautifulSoup(resp.content, "html.parser")
    return {"url": final_url, "root": root, "html": resp.content, "soup": soup,
            "robots": robots_txt, "llms": llms_txt}


def _fetch_optional(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        print(f"[DEBUG] {url} → {r.status_code} | {r.text[:200]!r}")
        if r.status_code == 200 and "<html" not in r.text[:500].lower():
            return r.text
    except requests.exceptions.RequestException as e:
        print(f"[DEBUG] {url} → EXCEPTION: {e}")
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
# BLOQUE 2 — SEO TÉCNICO (50 pts: META 12 + ESTRUCTURA 12 + SCHEMA 16 + ROBOTS 10)
# ──────────────────────────────────────────────────────────────────────────────

def check_meta_tags(a, site, ctx):
    soup = site["soup"]

    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""
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
        a.add("estructura", "h1", "H1 único", "ok", 3, 3, '"%s"' % h1s[0].get_text(strip=True)[:80])
    elif len(h1s) == 0:
        a.add("estructura", "h1", "H1 único", "error", 0, 3, "No hay ningún H1")
    else:
        a.add("estructura", "h1", "H1 único", "warn", 1, 3, "Hay %d H1 (debe haber exactamente 1)" % len(h1s))

    headings = [(int(t.name[1]), t.get_text(strip=True)[:60])
                for t in soup.find_all(re.compile("^h[1-6]$"))]
    jumps = []
    prev = None
    for level, text in headings:
        if prev is not None and level > prev + 1:
            jumps.append("H%d → H%d (\"%s\")" % (prev, level, text))
        prev = level
    if headings and not jumps:
        a.add("estructura", "hierarchy", "Jerarquía de encabezados H1→H2→H3", "ok", 3, 3,
              "%d encabezados, sin saltos de nivel" % len(headings))
    elif headings:
        a.add("estructura", "hierarchy", "Jerarquía de encabezados H1→H2→H3", "warn", 1, 3,
              "Saltos detectados: " + "; ".join(jumps[:3]))
    else:
        a.add("estructura", "hierarchy", "Jerarquía de encabezados H1→H2→H3", "error", 0, 3,
              "No hay encabezados")

    imgs = [i for i in soup.find_all("img") if not (i.get("aria-hidden") == "true")]
    if imgs:
        with_alt = [i for i in imgs if (i.get("alt") or "").strip()]
        ratio = len(with_alt) / len(imgs)
        pts = 3 if ratio == 1 else (1.5 if ratio >= 0.8 else 0)
        status = "ok" if ratio == 1 else ("warn" if ratio >= 0.8 else "error")
        a.add("estructura", "img_alt", "Imágenes con atributo alt", status, pts, 3,
              "%d de %d imágenes con alt" % (len(with_alt), len(imgs)))
        with_dims = [i for i in imgs if i.get("width") and i.get("height")]
        ratio_d = len(with_dims) / len(imgs)
        pts_d = 1.5 if ratio_d == 1 else (0.75 if ratio_d >= 0.8 else 0)
        a.add("estructura", "img_dims", "Imágenes con width y height",
              "ok" if ratio_d == 1 else ("warn" if ratio_d >= 0.8 else "error"), pts_d, 1.5,
              "%d de %d imágenes con dimensiones (evita CLS)" % (len(with_dims), len(imgs)))
    else:
        a.add("estructura", "img_alt", "Imágenes con atributo alt", "info", 3, 3, "Sin imágenes <img>")
        a.add("estructura", "img_dims", "Imágenes con width y height", "info", 1.5, 1.5, "Sin imágenes <img>")

    ext_scripts = [s for s in soup.find_all("script", src=True)]
    if ext_scripts:
        deferred = [s for s in ext_scripts
                    if s.has_attr("defer") or s.has_attr("async") or s.get("type") == "module"]
        ratio_s = len(deferred) / len(ext_scripts)
        pts_s = 1.5 if ratio_s == 1 else (0.75 if ratio_s >= 0.5 else 0)
        a.add("estructura", "scripts", "Scripts externos con defer/async",
              "ok" if ratio_s == 1 else ("warn" if ratio_s >= 0.5 else "error"), pts_s, 1.5,
              "%d de %d scripts no bloquean el renderizado" % (len(deferred), len(ext_scripts)))
    else:
        a.add("estructura", "scripts", "Scripts externos con defer/async", "info", 1.5, 1.5,
              "Sin scripts externos")


def check_schema(a, site, ctx):
    nodes, total, invalid = collect_jsonld(site["soup"])
    ctx["jsonld_nodes"] = nodes

    if total > 0:
        a.add("schema", "jsonld", "Al menos 1 bloque JSON-LD", "ok", 3, 3,
              "%d bloques <script type=\"application/ld+json\">" % total)
    else:
        a.add("schema", "jsonld", "Al menos 1 bloque JSON-LD", "error", 0, 3,
              "La web no tiene datos estructurados — los motores de IA no pueden 'entenderla'")
    if total > 0 and invalid == 0:
        a.add("schema", "jsonld_valid", "Todos los bloques JSON-LD son válidos", "ok", 2, 2)
    elif total > 0:
        a.add("schema", "jsonld_valid", "Todos los bloques JSON-LD son válidos", "error", 0, 2,
              "%d de %d bloques con JSON inválido (no parseable)" % (invalid, total))
    else:
        a.add("schema", "jsonld_valid", "Todos los bloques JSON-LD son válidos", "error", 0, 2, "Sin bloques")

    types = sorted({t for n in nodes for t in node_types(n)})
    ctx["schema_types"] = types
    a.add("schema", "types", "Tipos de schema detectados", "info", 0, 0,
          ", ".join(types) if types else "Ninguno")

    org = find_nodes(nodes, "Organization")
    lbs = find_localbusiness(nodes)
    if org or lbs:
        a.add("schema", "org", "Organization o LocalBusiness", "ok", 3, 3,
              ", ".join(sorted({t for n in (org + lbs) for t in node_types(n)})))
    else:
        a.add("schema", "org", "Organization o LocalBusiness", "error", 0, 3, "No presente")

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
          3 if lb_complete else (1 if lbs else 0), 3, lb_detail)

    faq = find_nodes(nodes, "FAQPage")
    ctx["faq_schema"] = bool(faq)
    a.add("schema", "faqpage", "FAQPage presente", "ok" if faq else "error",
          2 if faq else 0, 2, "" if faq else "Sin FAQPage — clave para aparecer en respuestas de IA")

    visible_qs = count_visible_faq(site["soup"])
    ctx["visible_faq"] = visible_qs
    if faq:
        a.add("schema", "faq_dom", "FAQPage con preguntas visibles en el DOM",
              "ok" if visible_qs else "error", 1 if visible_qs else 0, 1,
              "%d preguntas visibles" % visible_qs if visible_qs
              else "FAQPage declarado pero sin preguntas visibles → riesgo de penalización por schema engañoso")
    else:
        a.add("schema", "faq_dom", "FAQPage con preguntas visibles en el DOM", "error", 0, 1,
              "No aplica (sin FAQPage)")

    bc = find_nodes(nodes, "BreadcrumbList")
    a.add("schema", "breadcrumb", "BreadcrumbList presente", "ok" if bc else "warn",
          2 if bc else 0, 2, "" if bc else "No presente")


def check_robots(a, site, ctx):
    robots = site["robots"]
    if robots is not None:
        a.add("robots", "robots_txt", "robots.txt existe", "ok", 1, 1)
        has_sitemap = any(l.strip().lower().startswith("sitemap:") for l in robots.splitlines())
        a.add("robots", "sitemap", "Sitemap declarado en robots.txt",
              "ok" if has_sitemap else "warn", 1 if has_sitemap else 0, 1,
              "" if has_sitemap else "Sin línea Sitemap:")
    else:
        a.add("robots", "robots_txt", "robots.txt existe", "error", 0, 1, "No existe o no accesible")
        a.add("robots", "sitemap", "Sitemap declarado en robots.txt", "error", 0, 1, "Sin robots.txt")

    ctx["bots"] = {}
    for bot in AI_BOTS:
        access = bot_access(robots, bot)
        ctx["bots"][bot] = access
        if access == "blocked":
            a.add("robots", "bot_" + bot, "%s permitido" % bot, "error", 0, 1,
                  "❌ BLOQUEADO en robots.txt — este motor de IA no puede leer la web")
        elif access == "allowed":
            a.add("robots", "bot_" + bot, "%s permitido" % bot, "ok", 1, 1, "Permitido explícitamente")
        else:
            a.add("robots", "bot_" + bot, "%s permitido" % bot, "warn", 1, 1,
                  "No declarado (acceso implícito)" if access != "no_robots" else "Sin robots.txt (acceso implícito)")

    llms = site["llms"]
    if llms and llms.strip():
        a.add("robots", "llms_txt", "llms.txt existe (crítico para GEO)", "ok", 4, 4,
              "%d líneas" % len(llms.strip().splitlines()))
        ctx["llms_ok"] = True
    else:
        a.add("robots", "llms_txt", "llms.txt existe (crítico para GEO)", "error", 0, 4,
              "No existe — los LLMs no tienen un resumen estructurado del negocio")
        ctx["llms_ok"] = False


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 3 — GEO (20 pts: 5 señales × 4)
# ──────────────────────────────────────────────────────────────────────────────

def check_geo(a, site, ctx):
    soup = site["soup"]
    nodes = ctx.get("jsonld_nodes", [])

    region = meta_content(soup, name="geo.region")
    a.add("geo", "geo_region", "Meta geo.region (ej: ES-MD)", "ok" if region else "error",
          4 if region else 0, 4, region or "No declarada")

    place = meta_content(soup, name="geo.placename")
    a.add("geo", "geo_place", "Meta geo.placename", "ok" if place else "error",
          4 if place else 0, 4, place or "No declarada")

    icbm = meta_content(soup, name="ICBM")
    a.add("geo", "icbm", "Meta ICBM con coordenadas", "ok" if icbm else "error",
          4 if icbm else 0, 4, icbm or "No declarada")

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
          "ok" if coords_ok else "error", 4 if coords_ok else 0, 4,
          "" if coords_ok else "Sin coordenadas en datos estructurados")

    ctx["geo_signals"] = sum(1 for c in a.checks if c["area"] == "geo" and c["status"] == "ok")


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 4 — AEO (30 pts)
# ──────────────────────────────────────────────────────────────────────────────

def check_aeo(a, site, ctx):
    faq_schema = ctx.get("faq_schema", False)
    a.add("aeo", "aeo_faq_schema", "FAQPage schema presente", "ok" if faq_schema else "error",
          10 if faq_schema else 0, 10,
          "" if faq_schema else "Sin FAQPage los motores de respuesta no tienen Q&A que citar")

    visible = ctx.get("visible_faq", 0)
    a.add("aeo", "aeo_faq_dom", "Preguntas FAQ visibles en el DOM", "ok" if visible else "error",
          8 if visible else 0, 8,
          "%d preguntas detectadas" % visible if visible else "Sin FAQ visible (details/.faq/accordion)")

    q_pts = round(min(visible, 10) * 0.6, 1)
    a.add("aeo", "aeo_faq_count", "Número de preguntas FAQ (máx. 10 puntuables)",
          "ok" if visible >= 6 else ("warn" if visible else "error"), q_pts, 6,
          "%d preguntas → %s/6 pts" % (visible, fmt_pts(q_pts)))

    howto = bool(find_nodes(ctx.get("jsonld_nodes", []), "HowTo"))
    a.add("aeo", "aeo_howto", "HowTo schema presente", "ok" if howto else "warn",
          6 if howto else 0, 6, "" if howto else "Sin HowTo (recomendado si hay procesos/servicios paso a paso)")


# ──────────────────────────────────────────────────────────────────────────────
# BLOQUE 5 — PUNTUACIÓN GLOBAL Y NIVEL
# ──────────────────────────────────────────────────────────────────────────────

def nivel(score):
    if score < 50:
        return "🔴", "Crítico", "invisible para motores de IA"
    if score < 70:
        return "🟡", "Mejorable", "presencia parcial en motores de IA"
    if score < 85:
        return "🟢", "Bueno", "bien posicionado para motores de IA"
    return "⭐", "Excelente", "referente en su sector para motores de IA"


def frase_resumen(score, nombre, sector, ciudad):
    if score < 50:
        return ("Hoy, cuando alguien pregunta a ChatGPT o Perplexity por \"%s en %s\", "
                "%s es invisible: la web no da a los motores de IA la información que "
                "necesitan para recomendarla." % (sector, ciudad, nombre))
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
# qué pierde el negocio, cómo corregirlo)
FIX_GUIDE = {
    "title": ("El <title> es el titular de la página en Google y la primera señal que leen los LLMs.",
              "Sin título, ni Google ni los motores de IA saben de qué trata la web.",
              "Clics en buscadores y cualquier posibilidad de cita en respuestas de IA.",
              "Añadir en <head>: <title>Marca — Servicio en Ciudad</title> (≤65 caracteres)."),
    "desc": ("La meta description es el texto bajo el título en los resultados de búsqueda.",
             "Google y los LLMs la usan como resumen canónico de la página.",
             "CTR en buscadores: sin ella Google inventa el snippet y suele quedar peor.",
             '<meta name="description" content="Descripción con servicio + ciudad, ≤160 caracteres">.'),
    "canonical": ("La etiqueta canonical indica la URL 'oficial' de la página.",
                  "Evita contenido duplicado (http/https, con/sin www) que diluye la autoridad.",
                  "Autoridad de dominio repartida entre URLs duplicadas → peor ranking.",
                  '<link rel="canonical" href="URL-exacta-de-la-página"> en el <head>.'),
    "og_td": ("Open Graph controla cómo se ve la web al compartirla (WhatsApp, LinkedIn, etc.).",
              "Sin og:title/og:description el enlace compartido sale sin titular ni resumen.",
              "Cada enlace compartido por clientes pierde impacto y clics.",
              'Añadir <meta property="og:title" …> y <meta property="og:description" …>.'),
    "og_img": ("og:image es la imagen de previsualización al compartir el enlace.",
               "WhatsApp, iMessage y LinkedIn no renderizan SVG ni enlaces sin imagen.",
               "Los enlaces compartidos salen 'en gris', sin imagen: menos confianza y menos clics.",
               "Crear una imagen JPG/PNG de 1200×630 px y declararla en og:image (URL absoluta)."),
    "viewport": ("El meta viewport activa el renderizado responsive en móviles.",
                 "Google indexa mobile-first: sin viewport la web se considera no apta para móvil.",
                 "Posiciones en Google para más del 60% del tráfico (móvil).",
                 '<meta name="viewport" content="width=device-width, initial-scale=1">.'),
    "h1": ("El H1 es el titular principal que estructura semánticamente la página.",
           "Buscadores y LLMs lo usan para identificar el tema central.",
           "Relevancia temática: la página compite peor por su keyword principal.",
           "Dejar exactamente un <h1> con el servicio principal + ciudad."),
    "hierarchy": ("La jerarquía H1→H2→H3 es el índice lógico del contenido.",
                  "Los LLMs trocean el contenido por encabezados para extraer respuestas.",
                  "Fragmentos mal delimitados → peor extracción de respuestas por la IA.",
                  "Reordenar encabezados sin saltar niveles (de H2 se pasa a H3, no a H4)."),
    "img_alt": ("El atributo alt describe cada imagen para buscadores y lectores de pantalla.",
                "Es señal de relevancia, accesibilidad legal (EAA 2025) y contexto para la IA.",
                "Tráfico de Google Imágenes y riesgo de incumplimiento de accesibilidad.",
                'Añadir alt descriptivo a cada <img>: alt="qué se ve + contexto del negocio".'),
    "img_dims": ("width/height reservan el espacio de la imagen antes de cargarla.",
                 "Evitan el salto de layout (CLS), métrica de Core Web Vitals.",
                 "Penalización de experiencia de página en Google.",
                 "Declarar width y height reales en cada <img>."),
    "scripts": ("defer/async evitan que los scripts bloqueen el renderizado.",
                "Mejoran LCP/FID, métricas que Google usa para rankear.",
                "Velocidad percibida y posiciones en móvil.",
                "Añadir defer a los <script src> que no sean críticos para el primer render."),
    "jsonld": ("JSON-LD son los datos estructurados que describen el negocio a las máquinas.",
               "Es el formato que Google y los LLMs leen para 'entender' qué es el negocio, dónde está y qué ofrece.",
               "Sin JSON-LD el negocio es texto plano para la IA: no es citable ni recomendable con confianza.",
               'Añadir <script type="application/ld+json"> con LocalBusiness (+FAQPage) en el <head>.'),
    "jsonld_valid": ("Bloques JSON-LD con sintaxis inválida.",
                     "Un JSON roto se ignora por completo: es como no tenerlo.",
                     "Todo el esfuerzo de schema ya invertido no cuenta.",
                     "Validar cada bloque en validator.schema.org y corregir la sintaxis."),
    "org": ("Schema Organization/LocalBusiness identifica la entidad detrás de la web.",
            "Los LLMs recomiendan entidades, no páginas: sin entidad declarada no hay recomendación.",
            "Presencia en el 'knowledge graph' de Google y en las respuestas de IA.",
            "Añadir un nodo LocalBusiness con name, url, logo, address y telephone."),
    "lb_complete": ("LocalBusiness incompleto: faltan campos de contacto/dirección estructurados.",
                    "Los motores de IA locales cruzan nombre + dirección + teléfono (NAP) para validar el negocio.",
                    "Visibilidad en búsquedas locales por IA ('X cerca de mí').",
                    "Completar name, telephone y address con addressLocality en el JSON-LD."),
    "faqpage": ("FAQPage marca preguntas y respuestas en formato legible por máquinas.",
                "Es la fuente directa de la que ChatGPT/Perplexity extraen respuestas citables.",
                "Apariciones en respuestas de IA y rich results de Google.",
                "Añadir schema FAQPage con 6-10 preguntas reales de clientes y respuestas de 40-60 palabras."),
    "faq_dom": ("Las preguntas del schema deben existir también como contenido visible.",
                "Schema sin contenido visible se considera engañoso (riesgo de penalización).",
                "Posible penalización de Google + la IA no encuentra el texto que citar.",
                "Publicar una sección FAQ visible (details/accordion) con las mismas preguntas del schema."),
    "breadcrumb": ("BreadcrumbList describe la ruta de navegación de la página.",
                   "Ayuda a buscadores e IA a entender la estructura del sitio.",
                   "Rich results de migas de pan en Google.",
                   "Añadir schema BreadcrumbList con la jerarquía Inicio → Sección → Página."),
    "robots_txt": ("robots.txt es el fichero que regula el acceso de los bots.",
                   "Sin él no hay control ni declaración de sitemap.",
                   "Rastreo menos eficiente del sitio.",
                   "Crear /robots.txt con User-agent: * Allow: / y la línea Sitemap:."),
    "sitemap": ("La línea Sitemap: en robots.txt indica dónde está el mapa del sitio.",
                "Acelera el descubrimiento de páginas nuevas por todos los bots.",
                "Indexación más lenta de contenido nuevo.",
                "Añadir Sitemap: https://dominio.es/sitemap.xml a robots.txt."),
    "llms_txt": ("llms.txt es el fichero estándar que resume el negocio para los LLMs.",
                 "Es la señal GEO más directa: dice a ChatGPT/Claude/Perplexity qué es el negocio, dónde está y qué ofrece.",
                 "La oportunidad de controlar cómo te describe la IA — lo hará la competencia que sí lo tenga.",
                 "Crear /llms.txt en Markdown: # Negocio, > resumen, secciones de servicios, zona y contacto."),
    "geo_region": ("Meta geo.region declara la región en código ISO (ej: ES-MD).",
                   "Señal directa de geolocalización para crawlers de IA.",
                   "Asociación del negocio con su provincia en respuestas locales.",
                   '<meta name="geo.region" content="ES-XX"> (código ISO 3166-2 de la provincia).'),
    "geo_place": ("Meta geo.placename declara la localidad en texto plano.",
                  "Refuerza la asociación negocio↔ciudad para la IA.",
                  "Visibilidad en consultas 'en {ciudad}'.",
                  '<meta name="geo.placename" content="Ciudad">.'),
    "icbm": ("Meta ICBM declara las coordenadas exactas del negocio.",
             "Permite a los motores responder a búsquedas 'cerca de mí'.",
             "Consultas de proximidad, las de mayor intención de compra.",
             '<meta name="ICBM" content="40.4168, -3.7038"> (lat, lng reales del negocio).'),
    "lb_locality": ("Dirección estructurada (addressLocality + addressRegion) en el schema.",
                    "Es el dato que los LLMs citan textualmente al recomendar negocios locales.",
                    "Aparecer con dirección correcta en las respuestas de IA.",
                    "Completar address en LocalBusiness con streetAddress, addressLocality, addressRegion y postalCode."),
    "geocoords": ("GeoCoordinates añade latitude/longitude al schema del negocio.",
                  "Coordenadas exactas = máxima precisión para resultados de proximidad.",
                  "Posiciones en búsquedas por cercanía frente a competidores geolocalizados.",
                  'Añadir "geo": {"@type":"GeoCoordinates","latitude":…,"longitude":…} al LocalBusiness.'),
    "aeo_faq_schema": ("FAQPage schema (ver sección Schema).",
                       "Los Answer Engines construyen sus respuestas a partir de Q&A estructuradas.",
                       "Ser la respuesta literal que da la IA cuando preguntan por el sector.",
                       "Implementar FAQPage con preguntas que los clientes hacen de verdad."),
    "aeo_faq_dom": ("Sección de preguntas frecuentes visible en la página.",
                    "El contenido visible es lo que la IA puede citar y enlazar.",
                    "Citas directas en ChatGPT/Perplexity con enlace a la web.",
                    "Crear sección FAQ con <details><summary>¿Pregunta?</summary>respuesta</details>."),
    "aeo_howto": ("HowTo schema describe procesos paso a paso.",
                  "Ideal para 'cómo funciona X' — consultas muy frecuentes en IA.",
                  "Visibilidad en consultas informacionales del sector.",
                  "Añadir schema HowTo al proceso principal del servicio (3-6 pasos)."),
}


# ──────────────────────────────────────────────────────────────────────────────
# INFORME
# ──────────────────────────────────────────────────────────────────────────────

AREA_TITLES = [
    ("meta", "Meta tags"),
    ("estructura", "Estructura HTML"),
    ("schema", "Schema JSON-LD"),
]


def estado_emoji(pts, maxp):
    ratio = pts / maxp if maxp else 1
    return "✅" if ratio >= 0.85 else ("🟢" if ratio >= 0.7 else ("⚠️" if ratio >= 0.5 else "❌"))


def top_problemas(audit):
    """Los 3 problemas con más puntos perdidos, en lenguaje de negocio."""
    negocio = {
        "llms_txt": "La web no tiene llms.txt: los motores de IA no tienen ficha del negocio y recomendarán a competidores que sí la tengan.",
        "jsonld": "La web no tiene datos estructurados: para ChatGPT o Perplexity el negocio 'no existe' como entidad recomendable.",
        "org": "El negocio no está identificado como empresa local en el código: la IA no puede recomendarlo con nombre, dirección y teléfono.",
        "aeo_faq_schema": "No hay preguntas frecuentes estructuradas: cuando un cliente pregunta a la IA, la respuesta la dará la web de un competidor.",
        "aeo_faq_dom": "No hay sección de preguntas y respuestas visible: la IA no tiene texto del negocio que citar.",
        "lb_complete": "Faltan datos de contacto estructurados (dirección/teléfono): la IA no puede 'fichar' el negocio para búsquedas locales.",
        "geocoords": "El negocio no tiene coordenadas declaradas: pierde todas las búsquedas tipo 'cerca de mí', las de mayor intención de compra.",
        "lb_locality": "La dirección no está en formato máquina: el negocio no aparece asociado a su ciudad en respuestas de IA.",
        "icbm": "Sin coordenadas geográficas la web no compite en búsquedas de proximidad.",
        "geo_region": "La web no declara su provincia: la IA no la asocia con la zona donde están sus clientes.",
        "geo_place": "La web no declara su ciudad: invisible en consultas 'en {ciudad}'.",
        "desc": "Sin descripción para buscadores, Google inventa el texto del anuncio gratuito del negocio y rinde peor.",
        "og_img": "Cada vez que alguien comparte la web por WhatsApp, el enlace sale sin imagen: se pierde confianza y clics.",
        "title": "La web no tiene titular para buscadores: pierde clics en cada búsqueda.",
        "viewport": "La web no está marcada como apta para móvil: Google la penaliza en más del 60% de las búsquedas.",
        "h1": "La página no tiene un titular principal claro: buscadores e IA no saben cuál es el servicio principal.",
        "bot_GPTBot": "ChatGPT tiene prohibido leer la web: el negocio no puede aparecer en sus respuestas.",
        "bot_ClaudeBot": "Claude tiene prohibido leer la web: el negocio no puede aparecer en sus respuestas.",
        "bot_PerplexityBot": "Perplexity tiene prohibido leer la web: el negocio no puede aparecer en sus respuestas.",
        "aeo_howto": "No se explica ningún proceso paso a paso: se pierden las consultas '¿cómo funciona…?' en IA.",
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
            out.append("%s — pierde: %s" % (c["label"], g[2][0].lower() + g[2][1:]))
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
# ROI y productos WhiteMoon
# ──────────────────────────────────────────────────────────────────────────────

PRECIO_AUDITORIA = 899
TASA_CONVERSION = 0.08
VISITAS_POR_PUNTO = 0.5  # visitas/mes nuevas por cada punto de score recuperado

# Ticket medio por sector (benchmarks conservadores)
TICKET_SECTOR = {
    "dental": 180, "taller": 120, "gestoria": 150, "estetica": 65,
    "hosteleria": 35, "inmobiliaria": 300, "farmacia": 35, "abogados": 300,
    "podologia": 45, "academia": 200, "gimnasio": 50, "hotel": 120,
    "ecommerce": 95, "fontaneria": 250, "otro": 80,
}

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
        "porque": "El primer paso para que un {sector} de {ciudad} sea visible para la IA "
                  "y atienda clientes por chat: rápido de implantar y con las bases GEO/AEO incluidas.",
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
        "porque": "Un {sector} vive de su agenda: Orion atiende llamadas 24/7, da información, "
                  "prepara presupuestos básicos y reserva citas sin perder ningún cliente.",
        "incluye": [
            "Agente IA de voz que atiende llamadas 24/7",
            "Gestión de citas y reservas integrada con la agenda",
            "Mejoras GEO incluidas (señales locales + schema)",
            "Resumen de cada llamada y derivación a humano cuando toca",
        ],
    },
    "core": {
        "nombre": "Core",
        "setup": "1.800€", "mes": "opcional (mantenimiento)",
        "url": "whitemoon.es/core/",
        "porque": "Para un {sector} que necesita una base sólida en {ciudad}: web nueva con "
                  "GEO/AEO de serie y chat IA integrado desde el primer día.",
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
        "porque": "Un {sector} responde las mismas preguntas cada día: Core RAG convierte su "
                  "documentación en respuestas instantáneas, fiables y citables.",
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
    "hosteleria": "spark", "hotel": "spark",
    "inmobiliaria": "core",
    "taller": "orion", "fontaneria": "orion",
    "ecommerce": "spark", "farmacia": "spark",
    "otro": "core",
}


def productos_recomendados(score, sector):
    """Máximo 2 productos según score y sector."""
    skey = sector_key(sector)
    sectorial = PRODUCTO_POR_SECTOR.get(skey, "core")
    if score < 50:
        keys = ["spark"] + ([sectorial] if sectorial != "spark" else [])
    elif score <= 75:
        keys = ["orion"] + ([sectorial] if sectorial != "orion" else [])
    else:
        keys = [sectorial]
    return keys[:2]


def plan_de_accion(audit):
    lost = {c["id"]: c["max"] - c["points"] for c in audit.failed()}
    plan = []
    for ids, accion, impacto, esfuerzo in ACTIONS:
        pts = round(sum(lost.get(i, 0) for i in ids), 1)
        if pts > 0:
            plan.append({"accion": accion, "impacto": impacto, "esfuerzo": esfuerzo, "pts": pts})
    plan.sort(key=lambda p: (IMPACT_RANK[p["impacto"]], EFFORT_RANK[p["esfuerzo"]], -p["pts"]))
    return plan[:5]


def render_report(audit, site, ctx):
    nombre, sector, ciudad = ctx["nombre"], ctx["sector"], ctx["ciudad"]
    hoy = date.today().isoformat()

    seo_pts, seo_max = audit.area_score("meta", "estructura", "schema", "robots")
    geo_pts, geo_max = audit.area_score("geo")
    aeo_pts, aeo_max = audit.area_score("aeo")
    score = round(seo_pts + geo_pts + aeo_pts)
    emoji, nombre_nivel, desc_nivel = nivel(score)

    plan = plan_de_accion(audit)
    ganancia = round(sum(p["pts"] for p in plan))
    score_potencial = min(100, score + ganancia)

    L = []
    w = L.append

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
    w("**Puntuación global: %d/100 — %s %s** (%s)" % (score, emoji, nombre_nivel, desc_nivel))
    w("")
    w("| Área | Puntuación | Estado |")
    w("|------|-----------|--------|")
    w("| SEO técnico | %s/%s | %s |" % (fmt_pts(seo_pts), fmt_pts(seo_max), estado_emoji(seo_pts, seo_max)))
    w("| GEO — Visibilidad local IA | %s/%s | %s |" % (fmt_pts(geo_pts), fmt_pts(geo_max), estado_emoji(geo_pts, geo_max)))
    w("| AEO — Respuestas en IA | %s/%s | %s |" % (fmt_pts(aeo_pts), fmt_pts(aeo_max), estado_emoji(aeo_pts, aeo_max)))
    w("")
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

    # ── GEO ──
    w("### GEO — Señales de Geolocalización IA")
    w("")
    w("Señales detectadas: **%d/5** → **%s/20 puntos**" % (ctx.get("geo_signals", 0), fmt_pts(geo_pts)))
    w("")
    for c in [c for c in audit.checks if c["area"] == "geo"]:
        detail = " — %s" % c["detail"] if c["detail"] else ""
        w("- %s **%s**%s" % (STATUS_EMOJI[c["status"]], c["label"], detail))
        _render_fix(w, c)
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
    w("---")
    w("")

    # ── Evidencia en motores de IA ──
    w("## 📊 EVIDENCIA EN MOTORES DE IA")
    w("*(Lo que diferencia esta auditoría — ninguna agencia SEO tradicional lo hace)*")
    w("")
    w("**Queries exactas para verificar ahora mismo:**")
    w("Busca estas frases en ChatGPT, Grok y Perplexity y comprueba si apareces:")
    w("")
    w('- "%s en %s"' % (sector, ciudad))
    w('- "mejor %s %s"' % (sector, ciudad))
    w('- "%s recomendado %s"' % (sector, ciudad))
    w('- "%s cerca de %s"' % (sector, ciudad))
    w("")
    w("**Lo que verás si los errores críticos no se corrigen:**")
    w("")
    w("❌ %s NO aparecerá en las respuestas de IA" % nombre)
    w("✅ Competidores con GEO/AEO implementado SÍ aparecerán antes")
    w("")
    w("**Por qué ocurre:**")
    w("")
    w(_explicacion_llm(audit, ctx, nombre, sector, ciudad))
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

    # ── ROI estimado ──
    w("## 📈 ROI ESTIMADO")
    w("*(Impacto económico de corregir los errores detectados)*")
    w("")
    skey = sector_key(sector)
    ticket = TICKET_SECTOR[skey]
    puntos_rec = max(score_potencial - score, 0)
    visitas = puntos_rec * VISITAS_POR_PUNTO
    ingresos = visitas * ticket * TASA_CONVERSION
    if ingresos > 0:
        meses = PRECIO_AUDITORIA / ingresos
        w("Con una tasa de conversión estimada del %d%% (visita desde IA → cliente):"
          % int(TASA_CONVERSION * 100))
        w("")
        w("| Métrica | Estimación |")
        w("|---------|-----------|")
        w("| Visitas nuevas desde IA/mes | %s |" % fmt_pts(visitas))
        w("| Ticket medio sector | %d€ |" % ticket)
        w("| Ingresos adicionales estimados/mes | %d€ |" % round(ingresos))
        w("| Meses para recuperar la auditoría (%d€) | %s meses |"
          % (PRECIO_AUDITORIA, fmt_pts(round(meses, 1))))
    else:
        w("La web ya alcanza el máximo de los checks puntuables: el retorno aquí "
          "está en mantener la posición frente a competidores que están implementando GEO/AEO.")
    w("")
    w("*Estimación conservadora basada en benchmarks del sector. Los resultados "
      "reales dependen de la implementación y competencia local.*")
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
        w("**Por qué para %s:** %s" % (sector, p["porque"].format(sector=sector, ciudad=ciudad)))
        w("**Incluye:**")
        for feat in p["incluye"]:
            w("- %s" % feat)
        w("")
        w("→ Más información: %s" % p["url"])
        w("")
    w("¿Tienes preguntas? Solicita una consulta gratuita de 15 minutos: whitemoon.es/auditoria-ia")
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
    w("  - **Qué pierde el negocio:** %s" % pierde)
    w("  - **Cómo corregirlo:** %s" % como)


def _explicacion_llm(audit, ctx, nombre, sector, ciudad):
    """Explica cómo deciden los LLMs, anclada a los errores concretos detectados."""
    failed_ids = {c["id"] for c in audit.failed()}
    partes = [
        "Cuando alguien pregunta a un LLM por \"%s en %s\", el motor no improvisa: "
        "recupera entidades de negocio que pueda verificar (nombre + dirección + teléfono "
        "estructurados), que tengan contenido citable (FAQ, respuestas claras) y a las que "
        "sus crawlers puedan acceder. Después recomienda las que le dan más confianza." % (sector, ciudad)
    ]
    motivos = []
    if {"jsonld", "org", "lb_complete"} & failed_ids:
        motivos.append("la web no expone una entidad de negocio verificable en JSON-LD, "
                       "así que el LLM no puede confirmar que %s es un %s real en %s" % (nombre, sector, ciudad))
    if {"geo_region", "geo_place", "icbm", "geocoords", "lb_locality"} & failed_ids:
        motivos.append("faltan señales de geolocalización, por lo que la IA no asocia el negocio con %s "
                       "y prioriza competidores correctamente etiquetados" % ciudad)
    if {"aeo_faq_schema", "aeo_faq_dom", "faqpage"} & failed_ids:
        motivos.append("no hay preguntas y respuestas estructuradas que el motor pueda citar textualmente, "
                       "que es el formato del que se alimentan las respuestas de IA")
    if "llms_txt" in failed_ids:
        motivos.append("no existe llms.txt, el resumen estándar que los LLMs leen primero para entender un negocio")
    bloqueados = [b for b, s in ctx.get("bots", {}).items() if s == "blocked"]
    if bloqueados:
        motivos.append("los bots %s tienen el acceso bloqueado en robots.txt: esos motores no pueden "
                       "leer la web aunque quisieran" % ", ".join(bloqueados))
    if motivos:
        partes.append("En el caso de %s, hoy ocurre lo siguiente: %s." % (nombre, "; ".join(motivos)))
        partes.append("El resultado es directo: ante esas cuatro queries, la IA tiene más confianza en "
                      "cualquier competidor que sí exponga estos datos, y será a él a quien recomiende.")
    else:
        partes.append("%s expone correctamente estas señales: el trabajo ahora es mantenerlas y ampliar "
                      "contenido citable para consolidar la posición." % nombre)
    return "\n\n".join(partes)


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def run_audit_full(url, nombre, sector, ciudad, out_dir="reports"):
    """Ejecuta la auditoría completa, escribe el informe y devuelve un dict
    con todos los datos (para CLI y para la interfaz web)."""
    print("🌙 WhiteMoon — Auditoría GEO IA")
    print("→ Auditando %s (%s, %s, %s)…" % (url, nombre, sector, ciudad))

    site = fetch_site(url)
    print("✓ HTML descargado (%d KB) · robots.txt: %s · llms.txt: %s" % (
        len(site["html"]) // 1024,
        "sí" if site["robots"] is not None else "no",
        "sí" if site["llms"] else "no"))

    audit = Audit()
    ctx = {"nombre": nombre, "sector": sector, "ciudad": ciudad}

    check_meta_tags(audit, site, ctx)
    check_structure(audit, site)
    check_schema(audit, site, ctx)
    check_robots(audit, site, ctx)
    check_geo(audit, site, ctx)
    check_aeo(audit, site, ctx)

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

    seo_pts, seo_max = audit.area_score("meta", "estructura", "schema", "robots")
    geo_pts, geo_max = audit.area_score("geo")
    aeo_pts, aeo_max = audit.area_score("aeo")
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
