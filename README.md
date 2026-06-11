# 🌙 Auditoría GEO IA — WhiteMoon

Herramienta interna de **WhiteMoon Agencia IA** (whitemoon.es) para auditar la
visibilidad de webs de clientes en **motores de IA** (ChatGPT, Claude,
Perplexity, Grok, Gemini) y buscadores tradicionales.

Se ejecuta **en local** y genera **informes profesionales en Markdown** listos
para entregar al cliente.

## ¿Qué analiza?

| Bloque | Puntos | Qué mide |
|--------|--------|----------|
| **SEO técnico** | 50 | Meta tags (12), estructura HTML (12), Schema JSON-LD (16), robots/acceso bots IA + llms.txt (10) |
| **GEO** — visibilidad local IA | 20 | 5 señales de geolocalización (geo.region, geo.placename, ICBM, dirección estructurada, GeoCoordinates) × 4 pts |
| **AEO** — respuestas en IA | 30 | FAQPage schema, FAQ visible en el DOM, nº de preguntas, HowTo |
| **TOTAL** | **100** | |

> Nota: el bloque de robots y acceso para bots IA (GPTBot, ClaudeBot,
> PerplexityBot, Google-Extended) y el llms.txt puntúan dentro del SEO técnico.

## Instalación

Requiere Python 3.8+.

```bash
pip install -r requirements.txt
```

## Uso — un cliente

```bash
python audit_client.py <url> "<Nombre Cliente>" "<sector>" "<ciudad>"
```

Ejemplo real:

```bash
python audit_client.py https://clinicadental-sonrisa.es "Clínica Dental Sonrisa" "clínica dental" "Majadahonda"
```

Salida:

```
🌙 WhiteMoon — Auditoría GEO IA
→ Auditando https://clinicadental-sonrisa.es (Clínica Dental Sonrisa, clínica dental, Majadahonda)…
✓ HTML descargado (84 KB) · robots.txt: sí · llms.txt: no
✓ Score: 47/100 🔴 Crítico
✓ Informe generado: reports/audit-clinicadental-sonrisa.es-2026-06-11.md
```

## Uso — en lote (CSV)

Crea un `clientes.csv` con las columnas `url, nombre, sector, ciudad`
(la cabecera es opcional):

```csv
url,nombre,sector,ciudad
https://clinicadental-sonrisa.es,Clínica Dental Sonrisa,clínica dental,Majadahonda
https://taller-perez.es,Taller Pérez,taller mecánico,Las Rozas
```

Y ejecuta:

```bash
python audit_batch.py clientes.csv
```

Genera un informe por cliente en `reports/` y un resumen del lote ordenado
por score (los peores primero = mayor oportunidad comercial).

## Interfaz Web

Además de la línea de comandos, la herramienta incluye una interfaz web local
con diseño WhiteMoon (dark premium, gauge animado, historial de informes).

```bash
pip install -r requirements.txt
python app.py
```

Abrir **http://localhost:5000** en el navegador.

- **Password por defecto:** `whitemoon2026`
- **Cambiar password:** variable de entorno `AUDIT_PASSWORD`

```bash
# Windows (PowerShell)
$env:AUDIT_PASSWORD = "mi-password"; python app.py

# Linux / macOS
AUDIT_PASSWORD="mi-password" python app.py
```

Qué permite la interfaz:

- Lanzar auditorías desde un formulario (URL, cliente, sector, ciudad)
- Ver el score animado con gauge + barras SEO/GEO/AEO y errores/warnings
- Ver el informe completo renderizado, copiar el Markdown
- Descargar PDF (con `weasyprint` instalado genera el PDF en servidor; si no,
  abre el diálogo de impresión del navegador con estilos de impresión limpios)
- Historial de informes con filtro por nivel, ver/PDF/eliminar

### Despliegue en Render

El repo incluye `render.yaml`: al crear un **Web Service Python** en Render
apuntando a este repo se configura solo (build `pip install -r
requirements.txt`, arranque con gunicorn). Configura la variable de entorno
`AUDIT_PASSWORD` en el panel de Render — es la única barrera de acceso, usa
una password fuerte.

> Aviso: el disco de Render es efímero — los informes en `reports/` se
> pierden en cada deploy/reinicio. Descarga el PDF o el Markdown de cada
> auditoría al terminarla. Los informes son confidenciales: no compartas la
> URL del servicio fuera de WhiteMoon.

## Cómo interpretar el score

| Score | Nivel | Significado |
|-------|-------|-------------|
| 0-49 | 🔴 Crítico | Invisible para motores de IA |
| 50-69 | 🟡 Mejorable | Presencia parcial |
| 70-84 | 🟢 Bueno | Bien posicionado |
| 85-100 | ⭐ Excelente | Referente en su sector |

## Ejemplo de output (fragmento del informe)

```markdown
## 🎯 RESUMEN EJECUTIVO
*(Para el CEO/dueño del negocio)*

**Puntuación global: 47/100 — 🔴 Crítico** (invisible para motores de IA)

| Área | Puntuación | Estado |
|------|-----------|--------|
| SEO técnico | 33/50 | ⚠️ |
| GEO — Visibilidad local IA | 4/20 | ❌ |
| AEO — Respuestas en IA | 10/30 | ❌ |

**En una frase:** Hoy, cuando alguien pregunta a ChatGPT o Perplexity por
"clínica dental en Majadahonda", Clínica Dental Sonrisa es invisible: la web
no da a los motores de IA la información que necesitan para recomendarla.

**Los 3 problemas más urgentes:**
1. No hay preguntas frecuentes estructuradas: cuando un cliente pregunta a la
   IA, la respuesta la dará la web de un competidor.
2. La web no tiene llms.txt: los motores de IA no tienen ficha del negocio y
   recomendarán a competidores que sí la tengan.
3. El negocio no tiene coordenadas declaradas: pierde todas las búsquedas tipo
   "cerca de mí", las de mayor intención de compra.
```

El informe completo incluye además: análisis técnico check a check (con
*qué es / por qué importa / qué pierde el negocio / cómo corregirlo* en cada
error), estado de acceso de cada bot de IA, la sección **Evidencia en Motores
de IA** con las queries exactas para que el cliente compruebe en ChatGPT /
Grok / Perplexity que no aparece, el plan de acción priorizado con puntos
ganados por acción y la tabla de implementación con precios de WhiteMoon.

## Política de confidencialidad

**Los informes son confidenciales.** La carpeta `reports/` está en
`.gitignore` y **nunca se commitea**: contiene datos de clientes y análisis
comerciales. Solo se versiona el `.gitkeep`.

## Precio del servicio

**Auditoría GEO IA — 899€** · Solicitudes: whitemoon.es/auditoria-geo-ia

| Implementación posterior | Precio |
|--------------------------|--------|
| Schema LocalBusiness/FAQPage | 200-400€ |
| llms.txt + señales GEO | 150-300€ |
| Rediseño web con IA integrada | Pack Core — 1.800€ |
| Agente IA de voz | Pack Orion IA Agent — 999€ |
| RAG sobre documentación | Pack Core RAG — 3.200€ |

---

*WhiteMoon Agencia IA · whitemoon.es*
