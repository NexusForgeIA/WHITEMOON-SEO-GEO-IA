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

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
import markdown as md_lib

from audit_client import AuditError, audit_signals, run_audit_full

BASE = Path(__file__).resolve().parent
REPORTS_DIR = BASE / "reports"
# En import (no solo en __main__) para que exista también bajo gunicorn
REPORTS_DIR.mkdir(exist_ok=True)
PASSWORD = os.environ.get("AUDIT_PASSWORD", "whitemoon2026")

app = Flask(__name__)
# Secret estable entre reinicios (herramienta local mono-usuario)
app.secret_key = hashlib.sha256(("whitemoon-audit-" + PASSWORD).encode()).hexdigest()
app.permanent_session_lifetime = timedelta(hours=12)

SECTORES = [
    "clínica dental", "taller mecánico", "gestoría", "centro de estética",
    "hostelería", "inmobiliaria", "farmacia", "despacho de abogados",
    "podología", "academia", "gimnasio", "hotel", "e-commerce",
    "fontanería", "otro",
]

# Solo ficheros generados por audit_client: sin rutas, sin caracteres raros
FILENAME_RE = re.compile(r"^audit-[A-Za-z0-9.-]+-\d{4}-\d{2}-\d{2}\.md$")


# ──────────────────────────────────────────────────────────────────────────────
# Autenticación
# ──────────────────────────────────────────────────────────────────────────────

@app.before_request
def require_login():
    # /audit-json es el endpoint del Radar de prospección: lo consume un worker
    # en lote (sin sesión de navegador), así que queda fuera del login.
    if request.endpoint in ("login", "static", "audit_json"):
        return None
    if not session.get("auth"):
        if request.method == "POST" or request.path.startswith("/audit"):
            return jsonify(ok=False, error="No autenticado. Recarga la página e inicia sesión."), 401
        return redirect(url_for("login", next=request.path))
    return None


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

    if not all([url, nombre, sector, ciudad]):
        return jsonify(ok=False, error="Faltan campos: url, nombre, sector y ciudad son obligatorios."), 400
    if not re.match(r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}", url) \
            and "localhost" not in url:
        return jsonify(ok=False, error="La URL no parece válida (ej: https://cliente.es)."), 400

    try:
        result = run_audit_full(url, nombre, sector, ciudad, out_dir=str(REPORTS_DIR))
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
        frase=result["frase"],
        problemas=result["problemas"],
        errores_criticos=result["errores"],
        warnings=result["warnings"],
        informe_md=result["report_md"],
        informe_html=render_markdown(result["report_md"]),
        filename=result["filename"],
    )


@app.post("/audit-json")
def audit_json():
    """Radar de prospección — MODO RÁPIDO.

    Body: {"url": "https://..."}
    Respuesta (siempre HTTP 200; el worker trata ok:false como fallo suave):
      OK    → {"ok": true, "score": <0-100>, "senales": {...}}
      Fallo → {"ok": false, "error": "..."}

    Reutiliza el motor de scoring existente. Sin PageSpeed, sin renders y CERO
    efectos secundarios: no envía WhatsApp, no guarda leads, no escribe informes.
    """
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify(ok=False, error="Falta el campo 'url'.")
    if not re.match(r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}", url) \
            and "localhost" not in url:
        return jsonify(ok=False, error="La URL no parece válida (ej: https://cliente.es).")

    try:
        result = audit_signals(url)
    except AuditError as e:
        # URL inválida o web caída → fallo suave para el worker
        return jsonify(ok=False, error=str(e))
    except Exception as e:
        return jsonify(ok=False, error="Error inesperado durante el análisis: %s" % e)

    return jsonify(ok=True, score=result["score"], senales=result["senales"])


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
        </style></head><body>%s</body></html>""" % body
    pdf = WeasyHTML(string=doc).write_pdf()
    return send_file(io.BytesIO(pdf), mimetype="application/pdf",
                     as_attachment=True,
                     download_name=filename.replace(".md", ".pdf"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("🌙 WhiteMoon — Auditoría GEO IA · http://localhost:%d" % port)
    app.run(host="0.0.0.0", port=port, debug=False)
