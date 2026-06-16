# 🌙 Auditoría GEO IA — WhiteMoon

Herramienta interna de **WhiteMoon Agencia IA** (whitemoon.es) para auditar la
visibilidad de webs de clientes en **motores de IA** (ChatGPT, Claude,
Perplexity, Grok, Gemini) y buscadores tradicionales.

Se ejecuta **en local** y genera **informes profesionales en Markdown** listos
para entregar al cliente.

## ¿Qué analiza?

| Bloque | Puntos | Qué mide |
|--------|--------|----------|
| **SEO técnico** | 51 | Meta tags (12), estructura HTML (8), Schema JSON-LD (18, LocalBusiness 6 + FAQPage 6), robots/bots IA + llms.txt (5) y **rendimiento PageSpeed (8)** |
| **GEO** — visibilidad local IA | 11 | geo.region + geo.placename + ICBM juntos (4), dirección estructurada (4), GeoCoordinates (3) |
| **AEO** — respuestas en IA | 13 | FAQPage schema, FAQ visible en el DOM, nº de preguntas, HowTo |
| **Presencia y Autoridad** (E-E-A-T) | 13 | Google Business Profile (3), "Quiénes somos" (3), casos/testimonios (3), arquitectura SEO local (4) |
| **Conversión (CRO)** | 8 | WhatsApp (2), teléfono (2), formulario (2), CTA en el hero (2) |
| **Directorios locales** | 4 | Presencia en directorios relevantes del sector (1 pt c/u, máx 4) |
| **TOTAL** | **100** | |

> Notas:
> - **PageSpeed** usa la API gratuita de Google PageSpeed Insights. Requiere la
>   variable de entorno `PAGESPEED_API_KEY` (gratis en Google Cloud Console); si
>   no está configurada, el check sale como ⚠️ "No configurada".
> - El **análisis de competencia** y el **inventario de contenido** son
>   informativos (no puntúan) y se basan en búsquedas best-effort en Google.
> - El llms.txt es **recomendado** (no crítico): si los bots no están bloqueados,
>   acceden igualmente.

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
- Ver el score animado con gauge + barras SEO/GEO/AEO, desglosado además en
  **Score Técnico** (SEO + Schema + Robots) y **Score Control IA**
  (GEO + AEO + llms.txt)
- El informe completo y el PDF se muestran **siempre** tras el login (la
  herramienta ya está protegida por password, sin muros adicionales)
- Bloque **Verifica tu presencia en IA ahora** con enlaces pregenerados a
  ChatGPT, Perplexity y Grok usando el nombre del negocio + ciudad
- Ver el informe completo renderizado, copiar el Markdown
- Descargar PDF (con `weasyprint` instalado genera el PDF en servidor; si no,
  abre el diálogo de impresión del navegador con estilos de impresión limpios)
- Historial de informes con filtro por nivel, ver/PDF/eliminar

#### Endpoint público `POST /audit-public` (sin login)

Pensado para un formulario de captación en **whitemoon.es**. No requiere login
y tiene CORS abierto para `whitemoon.es` / `www.whitemoon.es`.

- **Recibe** JSON: `{url, nombre, telefono}`
- **Ejecuta** la auditoría completa
- **Devuelve** solo: `{score, score_tecnico, score_control_ia, top3_problemas}`
- **Guarda** el lead en Supabase `leads_web` (`origen = auditoria-gratuita-web`,
  `mensaje = "Auditó: [url] · Score: [score]/100"`)
- **Avisa** por WhatsApp vía CallMeBot al número de la agencia

Variables de entorno para el aviso de WhatsApp (best-effort; si falta el apikey
el aviso se omite y la auditoría sigue funcionando):

| Variable | Por defecto |
|----------|-------------|
| `CALLMEBOT_PHONE` | `+34643199580` |
| `CALLMEBOT_APIKEY` | *(vacío — obtener en callmebot.com)* |

#### Endpoint /lead (Supabase) — opcional, sin usar en el flujo normal

Existe un endpoint `POST /lead` que inserta en la tabla `leads_web` del
proyecto Supabase (`origen = auditoria-geo-ia`, `sector = auditoria`). **No se
llama desde la interfaz** — se conserva por si se quiere reactivar una captura
de leads en el futuro. Las credenciales llevan un valor por defecto en el
código (la clave `anon` es pública por diseño; la política RLS solo permite
`INSERT` anónimo). Para apuntar a otro proyecto, define las variables de
entorno:

| Variable | Por defecto |
|----------|-------------|
| `SUPABASE_URL` | `https://mlaqtniujnvfxcvcourm.supabase.co` |
| `SUPABASE_KEY` | clave `anon` del proyecto |

### Despliegue en Render

El repo incluye `render.yaml`: al crear un **Web Service Python** en Render
apuntando a este repo se configura solo (build `pip install -r
requirements.txt`, arranque con gunicorn). Configura la variable de entorno
`AUDIT_PASSWORD` en el panel de Render — es la única barrera de acceso, usa
una password fuerte. Opcionalmente, `SUPABASE_URL` y `SUPABASE_KEY` para la
captura de leads (traen valores por defecto funcionales). Render redespliega
automáticamente tras cada merge a `main`.

> Aviso: el disco de Render es efímero — los informes en `reports/` se
> pierden en cada deploy/reinicio. Descarga el PDF o el Markdown de cada
> auditoría al terminarla. Los informes son confidenciales: no compartas la
> URL del servicio fuera de WhiteMoon.

## Cómo interpretar el score

| Score | Nivel | Significado |
|-------|-------|-------------|
| 0-49 | 🔴 Crítico | Señales técnicas para motores de IA muy incompletas |
| 50-69 | 🟡 Mejorable | Presencia parcial |
| 70-84 | 🟢 Bueno | Bien posicionado |
| 85-100 | ⭐ Excelente | Referente en su sector |

## Ejemplo de output (fragmento del informe)

```markdown
## 🎯 RESUMEN EJECUTIVO
*(Para el CEO/dueño del negocio)*

**Puntuación global: 38/100 — 🔴 Crítico** (señales técnicas para motores de IA muy incompletas)

**Puntuación por área:**

- 🔧 SEO Técnico: **29/51** ⚠️
- 🌍 GEO Local IA: **4/11** ❌
- 💬 AEO Respuestas: **0/13** ❌
- 🏆 Autoridad: **3/13** ❌
- 🎯 Conversión (CRO): **6/8** 🟢
- 🗂️ Directorios locales: **0/4** ❌

**En una frase:** Clínica Dental Sonrisa tiene margen de mejora en las señales
técnicas que los motores de IA usan para verificar y citar negocios locales.

**Los 3 problemas más urgentes:**
1. No hay preguntas frecuentes estructuradas: los LLMs no tienen respuestas
   del negocio que citar textualmente.
2. La web no tiene llms.txt: los motores de IA no tienen una ficha estándar
   del negocio que leer primero.
3. El negocio no tiene coordenadas declaradas: compite en desventaja en las
   búsquedas tipo "cerca de mí", las de mayor intención de compra.
```

El informe completo incluye además: análisis técnico check a check (con
*qué es / por qué importa / tu competencia que sí lo tiene / cómo corregirlo*
en cada error), estado de acceso de cada bot de IA, la sección **Evidencia en Motores
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
