#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interfaz web local de la Auditoría GEO IA — WhiteMoon Agencia IA · whitemoon.es

Uso:
    python app.py
    → abrir http://localhost:5000  (password por defecto: whitemoon2026)

Cambiar password:  variable de entorno AUDIT_PASSWORD
"""

import hashlib
import io
import os
import re
from datetime import timedelta
from pathlib import Path

import requests
from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
import markdown as md_lib

from audit_client import AuditError, run_audit_full

BASE = Path(__file__).resolve().parent
REPORTS_DIR = BASE / "reports"
# En import (no solo en __main__) para que exista también bajo gunicorn
REPORTS_DIR.mkdir(exist_ok=True)
PASSWORD = os.environ.get("AUDIT_PASSWORD", "whitemoon2026")

# Supabase: captura de leads del informe completo (freemium). La clave anon es
# pública por diseño (RLS permite solo INSERT anónimo en leads_web).
SUPABASE_URL = os.environ.get(
    "SUPABASE_URL", "https://mlaqtniujnvfxcvcourm.supabase.co").rstrip("/")
SUPABASE_KEY = os.environ.get(
    "SUPABASE_KEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1s"
    "YXF0bml1am52ZnhjdmNvdXJtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzc4MzUyMzIsImV4cC"
    "I6MjA5MzQxMTIzMn0.Neh7VUS8ADsxf0DPab0JoJyGXOAXnLIaXzXbKzj2BGs")

# Notificación WhatsApp vía CallMeBot (endpoint público de auditoría gratuita).
# El apikey es específico del número destino en CallMeBot; sin él, el aviso se
# omite silenciosamente (la auditoría sigue funcionando).
CALLMEBOT_PHONE = os.environ.get("CALLMEBOT_PHONE", "+34643199580")
CALLMEBOT_APIKEY = os.environ.get("CALLMEBOT_APIKEY", "")

# Orígenes permitidos para CORS (formulario público en whitemoon.es)
CORS_ALLOWED_ORIGINS = {"https://whitemoon.es", "https://www.whitemoon.es"}

app = Flask(__name__)
# Secret estable entre reinicios (herramienta local mono-usuario)
app.secret_key = hashlib.sha256(("whitemoon-audit-" + PASSWORD).encode()).hexdigest()
app.permanent_session_lifetime = timedelta(hours=12)

SECTORES = [
    "bodega y vinos", "centro de estética", "clínica dental",
    "despacho de abogados", "e-commerce", "farmacia", "fontanería",
    "formación y academia", "gestoría", "gimnasio", "hostelería", "hotel",
    "inmobiliaria", "marketing y publicidad", "muebles y decoración",
    "podología", "psicología y coaching", "psiquiatría", "servicio técnico",
    "taller mecánico", "transporte y logística",
    "otro",
]

# Solo ficheros generados por audit_client: sin rutas, sin caracteres raros
FILENAME_RE = re.compile(r"^audit-[A-Za-z0-9.-]+-\d{4}-\d{2}-\d{2}\.md$")


# ──────────────────────────────────────────────────────────────────────────────
# Autenticación
# ──────────────────────────────────────────────────────────────────────────────

@app.before_request
def require_login():
    # El endpoint público de auditoría gratuita no requiere login.
    if request.endpoint in ("login", "static", "audit_public"):
        return None
    if not session.get("auth"):
        if request.method == "POST" or request.path.startswith("/audit"):
            return jsonify(ok=False, error="No autenticado. Recarga la página e inicia sesión."), 401
        return redirect(url_for("login", next=request.path))
    return None


@app.after_request
def add_cors_headers(resp):
    """CORS solo para los orígenes permitidos (formulario público en whitemoon.es)."""
    origin = request.headers.get("Origin", "")
    if origin in CORS_ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Max-Age"] = "86400"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("password", "") == PASSWORD:
            session.permanent = True
            session["auth"] = True
            dest = request.args.get("next", "/")
            if not dest.startswith("/") or dest.startswith("//"):
                dest = "/"
            return redirect(dest)
        error = "Password incorrecto"
    return render_template("login.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ──────────────────────────────────────────────────────────────────────────────
# Auditoría
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return render_template("index.html", sectores=SECTORES)


@app.post("/audit")
def audit():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    nombre = (data.get("nombre") or "").strip()
    sector = (data.get("sector") or "").strip()
    ciudad = (data.get("ciudad") or "").strip()
    # Modo HTML directo (uso interno): HTML pegado a mano cuando la web
    # bloquea el fetch (Cloudflare/403). URL/sector/ciudad siguen siendo
    # obligatorios para los metadatos del informe.
    html_manual = (data.get("html") or "").strip() or None

    if not all([url, nombre, sector, ciudad]):
        return jsonify(ok=False, error="Faltan campos: url, nombre, sector y ciudad son obligatorios."), 400
    if not re.match(r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}", url) \
            and "localhost" not in url:
        return jsonify(ok=False, error="La URL no parece válida (ej: https://cliente.es)."), 400

    try:
        result = run_audit_full(url, nombre, sector, ciudad, out_dir=str(REPORTS_DIR),
                                html_manual=html_manual)
    except AuditError as e:
        return jsonify(ok=False, error=str(e)), 502
    except Exception as e:
        return jsonify(ok=False, error="Error inesperado durante la auditoría: %s" % e), 500

    return jsonify(
        ok=True,
        score=result["score"],
        nivel=result["nivel"],
        nivel_emoji=result["nivel_emoji"],
        nivel_desc=result["nivel_desc"],
        seo=result["seo"], seo_max=result["seo_max"],
        geo=result["geo"], geo_max=result["geo_max"],
        aeo=result["aeo"], aeo_max=result["aeo_max"],
        autoridad=result["autoridad"], autoridad_max=result["autoridad_max"],
        cro=result["cro"], cro_max=result["cro_max"],
        directorios=result["directorios"], directorios_max=result["directorios_max"],
        tecnico=result["tecnico"], tecnico_max=result["tecnico_max"],
        control=result["control"], control_max=result["control_max"],
        frase=result["frase"],
        problemas=result["problemas"],
        errores_criticos=result["errores"],
        warnings=result["warnings"],
        informe_md=result["report_md"],
        informe_html=render_markdown(result["report_md"]),
        filename=result["filename"],
        url=result["url"],
    )


# ──────────────────────────────────────────────────────────────────────────────
# Captura de lead — endpoint conservado para uso futuro.
# NO se invoca desde el flujo normal: la herramienta ya está protegida por login,
# así que el informe completo y el PDF se muestran siempre tras autenticarse.
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/lead")
def lead():
    data = request.get_json(silent=True) or {}
    nombre = (data.get("nombre") or "").strip()
    email = (data.get("email") or "").strip()
    telefono = (data.get("telefono") or "").strip()
    url = (data.get("url") or "").strip()

    if not all([nombre, email, telefono]):
        return jsonify(ok=False, error="Nombre, email y teléfono son obligatorios."), 400

    payload = {
        "nombre": nombre,
        "email": email,
        "telefono": telefono,
        "origen": "auditoria-geo-ia",
        "sector": "auditoria",
        "mensaje": "Solicitó informe completo para %s" % (url or "—"),
    }
    try:
        r = requests.post(
            SUPABASE_URL + "/rest/v1/leads_web",
            json=payload,
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": "Bearer " + SUPABASE_KEY,
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        return jsonify(ok=False, error="No se pudo guardar el lead: %s" % e), 502

    if r.status_code not in (200, 201, 204):
        return jsonify(ok=False,
                       error="No se pudo guardar el lead (HTTP %d)." % r.status_code), 502
    return jsonify(ok=True)


# ──────────────────────────────────────────────────────────────────────────────
# Auditoría pública gratuita (sin login) — para el formulario de whitemoon.es
# ──────────────────────────────────────────────────────────────────────────────

def _save_public_lead(nombre, telefono, url, score):
    """Guarda el lead de la auditoría gratuita en Supabase (best-effort)."""
    payload = {
        "nombre": nombre,
        "telefono": telefono,
        "origen": "auditoria-gratuita-web",
        "mensaje": "Auditó: %s · Score: %d/100" % (url, score),
    }
    try:
        requests.post(
            SUPABASE_URL + "/rest/v1/leads_web",
            json=payload,
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": "Bearer " + SUPABASE_KEY,
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        app.logger.warning("No se pudo guardar el lead público: %s", e)


def _notify_whatsapp(nombre, telefono, url, score, score_tecnico, score_control_ia):
    """Avisa por WhatsApp vía CallMeBot (best-effort; se omite sin apikey)."""
    text = ("🔍 Auditoría GEO/SEO Gratuita\n"
            "👤 %s · 📱 %s\n"
            "🌐 URL: %s\n"
            "📊 Score: %d/100\n"
            "🔧 Técnico: %s · 🤖 Control IA: %s"
            % (nombre, telefono, url, score, score_tecnico, score_control_ia))
    apikey = os.environ.get("CALLMEBOT_APIKEY", "")
    if not apikey:
        app.logger.info("CALLMEBOT_APIKEY no configurado: aviso de WhatsApp omitido.")
        return
    try:
        requests.get(
            "https://api.callmebot.com/whatsapp.php",
            params={"phone": CALLMEBOT_PHONE, "text": text, "apikey": apikey},
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        app.logger.warning("No se pudo enviar el aviso de WhatsApp: %s", e)


@app.post("/audit-public")
def audit_public():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    nombre = (data.get("nombre") or "").strip()
    telefono = (data.get("telefono") or "").strip()

    if not all([url, nombre, telefono]):
        return jsonify(ok=False, error="Faltan campos: url, nombre y telefono son obligatorios."), 400
    if not re.match(r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}", url) \
            and "localhost" not in url:
        return jsonify(ok=False, error="La URL no parece válida (ej: https://cliente.es)."), 400

    try:
        # Sector/ciudad no se piden en el formulario público; se auditan igualmente.
        result = run_audit_full(url, nombre, "auditoría", "", out_dir=str(REPORTS_DIR))
    except AuditError as e:
        return jsonify(ok=False, error=str(e)), 502
    except Exception as e:
        return jsonify(ok=False, error="Error inesperado durante la auditoría: %s" % e), 500

    score = result["score"]
    score_tecnico = result["tecnico"]
    score_control_ia = result["control"]
    _save_public_lead(nombre, telefono, url, score)
    _notify_whatsapp(nombre, telefono, url, score, score_tecnico, score_control_ia)

    return jsonify(
        score=score,
        score_tecnico=score_tecnico,
        score_control_ia=score_control_ia,
        top3_problemas=result["problemas"][:3],
    )


# ──────────────────────────────────────────────────────────────────────────────
# Informes
# ──────────────────────────────────────────────────────────────────────────────

def render_markdown(text):
    # El informe menciona etiquetas como <title> o <head> de forma literal:
    # escapamos '<' para que no se interpreten como HTML real
    return md_lib.markdown(text.replace("<", "&lt;"),
                           extensions=["tables", "nl2br", "sane_lists"])


def safe_report_path(filename):
    if not FILENAME_RE.match(filename):
        abort(404)
    path = REPORTS_DIR / filename
    if not path.is_file():
        abort(404)
    return path


def parse_report_meta(path):
    """Extrae cliente, sector, ciudad, score y nivel de la cabecera del .md."""
    head = path.read_text(encoding="utf-8")[:2500]
    meta = {"filename": path.name, "cliente": "—", "sector": "—", "ciudad": "—",
            "fecha": "—", "url": "", "score": None, "nivel": "—", "emoji": ""}
    m = re.search(r"^# Auditoría GEO IA — (.+)$", head, re.M)
    if m:
        meta["cliente"] = m.group(1).strip()
    m = re.search(r"\*\*Fecha:\*\* (.+?) \| \*\*URL:\*\* (.+?) \| "
                  r"\*\*Sector:\*\* (.+?) \| \*\*Ciudad:\*\* (.+?)$", head, re.M)
    if m:
        meta["fecha"], meta["url"], meta["sector"], meta["ciudad"] = \
            (m.group(i).strip() for i in range(1, 5))
    m = re.search(r"Puntuación global: (\d+)/100 — (\S+) (\w+)", head)
    if m:
        meta["score"] = int(m.group(1))
        meta["emoji"] = m.group(2)
        meta["nivel"] = m.group(3)
    return meta


@app.get("/reports")
def reports_list():
    files = sorted(REPORTS_DIR.glob("audit-*.md"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    reports = [parse_report_meta(p) for p in files]
    return render_template("reports_list.html", reports=reports)


@app.get("/reports/<filename>")
def report_view(filename):
    path = safe_report_path(filename)
    meta = parse_report_meta(path)
    html = render_markdown(path.read_text(encoding="utf-8"))
    return render_template("report.html", meta=meta, informe_html=html, filename=filename)


@app.post("/reports/<filename>/delete")
def report_delete(filename):
    path = safe_report_path(filename)
    path.unlink()
    return jsonify(ok=True)


@app.post("/export-pdf/<filename>")
def export_pdf(filename):
    path = safe_report_path(filename)
    try:
        from weasyprint import HTML as WeasyHTML
    except Exception:
        # Sin weasyprint: el frontend abre el informe y usa la impresión del navegador
        return jsonify(ok=False, fallback="print",
                       url=url_for("report_view", filename=filename) + "?print=1")

    body = render_markdown(path.read_text(encoding="utf-8"))
    doc = """<html><head><meta charset="utf-8"><style>
        @page { margin: 18mm 16mm; }
        body { font-family: sans-serif; color: #111; font-size: 11px; line-height: 1.55; }
        h1 { font-size: 20px; } h2 { font-size: 15px; margin-top: 18px; }
        h3 { font-size: 13px; } h4 { font-size: 12px; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ccc; padding: 5px 8px; text-align: left; }
        th { background: #f3f0fa; }
        blockquote { border-left: 3px solid #7c4dff; margin-left: 0; padding-left: 12px; color: #444; }
        img { display: block; margin: 20px auto; max-width: 100%%; }
        </style></head><body>%s</body></html>""" % body
    pdf = WeasyHTML(string=doc).write_pdf()
    return send_file(io.BytesIO(pdf), mimetype="application/pdf",
                     as_attachment=True,
                     download_name=filename.replace(".md", ".pdf"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("🌙 WhiteMoon — Auditoría GEO IA · http://localhost:%d" % port)
    app.run(host="0.0.0.0", port=port, debug=False)
