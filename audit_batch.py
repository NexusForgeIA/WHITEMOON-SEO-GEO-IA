#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoría GEO IA en lote — WhiteMoon Agencia IA · whitemoon.es

Procesa un CSV de clientes y genera un informe por cada uno.

Formato del CSV (con o sin cabecera):
    url, nombre, sector, ciudad

Ejemplo:
    https://clinicadental-ejemplo.es, Clínica Dental Ejemplo, clínica dental, Majadahonda
    https://taller-ejemplo.es, Taller Ejemplo, taller mecánico, Las Rozas

Uso:
    python audit_batch.py clientes.csv
"""

import csv
import sys
from pathlib import Path

from audit_client import run_audit


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        print("Uso: python audit_batch.py clientes.csv")
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    if not csv_path.exists():
        print("❌ ERROR: no existe el fichero %s" % csv_path)
        sys.exit(1)

    rows = []
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        for raw in csv.reader(f):
            if not raw or not any(cell.strip() for cell in raw):
                continue
            cells = [c.strip() for c in raw]
            # Saltar cabecera si la primera celda no parece una URL
            if not cells[0].lower().startswith(("http://", "https://", "www.")) and "." not in cells[0]:
                continue
            if len(cells) < 4:
                print("⚠️  Fila ignorada (faltan columnas, se esperan url,nombre,sector,ciudad): %s" % raw)
                continue
            rows.append(cells[:4])

    if not rows:
        print("❌ ERROR: el CSV no contiene filas válidas (url, nombre, sector, ciudad).")
        sys.exit(1)

    print("🌙 WhiteMoon — Auditoría GEO IA en lote: %d clientes\n" % len(rows))
    resultados, fallos = [], []
    for i, (url, nombre, sector, ciudad) in enumerate(rows, 1):
        print("─" * 60)
        print("[%d/%d] %s" % (i, len(rows), nombre))
        try:
            path, score = run_audit(url, nombre, sector, ciudad)
            resultados.append((nombre, score, path))
        except SystemExit:
            # run_audit hace sys.exit(1) en errores de fetch: seguimos con el resto
            fallos.append((nombre, url))
        except Exception as e:  # un cliente roto no debe parar el lote
            print("❌ ERROR auditando %s: %s" % (url, e))
            fallos.append((nombre, url))
        print()

    print("═" * 60)
    print("RESUMEN DEL LOTE")
    print("═" * 60)
    for nombre, score, path in sorted(resultados, key=lambda r: r[1]):
        print("  %3d/100  %s  →  %s" % (score, nombre, path))
    if fallos:
        print("\nNo auditados (revisar URL o acceso):")
        for nombre, url in fallos:
            print("  ✗ %s (%s)" % (nombre, url))
    print("\n✓ %d informes generados en reports/" % len(resultados))


if __name__ == "__main__":
    main()
