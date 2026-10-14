# Lista final de requisitos — PhishGuard (Práctica 3)

- **Origen de la numeración:** `docs/auditoria-p3.md` §3 (propuesta derivada del informe P1 y del código; el informe P1 no numeraba RF/RNF).
- **Estados:** Cumplido / Parcial / Pendiente / A revisar / Descartado.
- **Fecha de esta lista:** 14/10/2026.

---

## 1. Requisitos funcionales

| ID | Requisito | Estado |
|----|-----------|--------|
| RF-01 | Analizar una URL sospechosa y devolver score, veredicto, indicadores y explicación | Cumplido |
| RF-02 | Analizar el texto de un email (cuerpo o correo con cabeceras), mínimo 10 caracteres | Cumplido |
| RF-03 | Extraer 15 características de la URL (longitud, subdominios, keywords, TLD, HTTPS, IP, WHOIS, etc.) | Cumplido |
| RF-04 | Extraer señales del email (remitente, Reply-To, URLs, frases, adjuntos) | Cumplido |
| RF-05 | Consultar reputación en VirusTotal (API v3) | Cumplido |
| RF-06 | Consultar URLScan.io como contexto adicional | Cumplido |
| RF-07 | Veredicto con IA (Claude): JSON estricto, score 0–100, veredictos PHISHING / SOSPECHOSO / LEGÍTIMO, explicación en español | Cumplido |
| RF-08 | Motor heurístico de respaldo cuando no hay IA | Cumplido |
| RF-09 | Tolerancia a fallos de VirusTotal, URLScan o WHOIS | Cumplido |
| RF-10 | Guardar cada análisis en SQLite (SQLAlchemy) | **Parcial** |
| RF-11 | Historial paginado y filtrable por veredicto | Cumplido |
| RF-12 | Dashboard con estadísticas y cuota de IA | Cumplido |
| RF-13 | Medidor visual 0–100 con colores por veredicto | Cumplido |
| RF-14 | URLs PHISHING no clicables (tachadas / bloqueadas) | Cumplido |
| RF-15 | API REST con documentación interactiva (`/docs`) | Cumplido |

**Notas de estado**

- **RF-10 Parcial:** en local/Compose los datos persisten; en Render (`sqlite:////tmp/…`) se pierden en cada reinicio (documentado en el README).
- **RF-15:** `/docs` está disponible en desarrollo; en producción se desactiva a propósito (`ENVIRONMENT=production`, ver RNF-09).
- **RF-08:** en modo sin IA la UI muestra «Análisis limitado (sin IA)» y no devuelve `LEGÍTIMO` (usa `NO CONCLUYENTE` si no hay señales suficientes).

---

## 2. Requisitos no funcionales

| ID | Requisito | Estado |
|----|-----------|--------|
| RNF-01 | Rate limiting por IP (10/min análisis, 30/min historial; 429 + `Retry-After`) | Cumplido |
| RNF-02 | Cabeceras de seguridad HTTP (OWASP) en el backend | Cumplido (backend) |
| RNF-03 | Protección anti-SSRF | Cumplido |
| RNF-04 | Validación y saneado de entradas (límites, HTML, 413/415/504) | Cumplido |
| RNF-05 | Contenedor backend sin privilegios (`appuser`, UID 10001) | Cumplido |
| RNF-06 | Logs de auditoría JSON sin cuerpos ni claves | Cumplido |
| RNF-07 | Cuotas configurables de Anthropic (hora/día) persistidas en BD | **Parcial** |
| RNF-08 | Secretos solo en `.env` / paneles; nunca en el repositorio | Cumplido |
| RNF-09 | Errores genéricos; sin `/docs` en producción | Cumplido |
| RNF-10 | Entorno reproducible con Docker Compose | **Parcial** |
| RNF-11 | Despliegue en Internet con HTTPS y dominio propio | **Parcial** |
| RNF-12 | Configuración por variables de entorno | Cumplido |
| RNF-13 | Interfaz y resultados en español | Cumplido |

**Notas de estado**

- **RNF-07 / RNF-11 Parciales:** disco efímero y cold start del plan gratuito de Render.
- **RNF-10 Parcial:** falta instalación por otra persona en máquina limpia; sin healthchecks ni lock de dependencias del backend.
- **RNF-02:** el frontend (Pages / nginx) no añade las mismas cabeceras OWASP.

**Recuento:** RF 14 Cumplidos + 1 Parcial; RNF 10 Cumplidos + 3 Parciales. Ningún Pendiente en la lista principal.

---

## 3. Requisitos modificados o a revisar (con justificación)

### D-01 — Despliegue en VPS Hetzner → Render + Cloudflare Pages

| | |
|--|--|
| **Estado** | **A revisar** |
| **Versión original** | Enunciado P1, requisito obligatorio 03: despliegue en un VPS de **Hetzner**. |
| **Versión nueva** | Backend en **Render** (Docker, HTTPS gestionado) y frontend en **Cloudflare Pages** con dominio `https://phishguard.cmmario.com`. |
| **Justificación** | El VPS de Hetzner **nunca se llegó a recibir**, así que no fue posible desplegar ahí. Se usó el stack gratuito Render + Cloudflare Pages para cumplir el objetivo de tener la aplicación accesible en Internet con HTTPS y dominio propio (RNF-11). **Consecuencias aceptadas:** arranque en frío del plan free de Render y disco efímero (`/tmp`), que vacían historial y contadores de cuota en cada reinicio (afecta a RF-10, RNF-07 y RNF-11). Documentado en el README y en `docs/evidencias/verificacion-produccion.md`. El FAQ de la P3 indica que el despliegue no es obligatorio; aun así se mantiene como «A revisar» por si el docente exige Hetzner. |

### D-02 — Análisis de capturas / imágenes

| | |
|--|--|
| **Estado** | **Descartado** (trabajo futuro) |
| **Versión original** | Roadmap P2 / herramienta 08 del enunciado P1 como entrada posible. |
| **Versión nueva** | No implementado. |
| **Justificación** | El informe P1 lo planificó para una práctica posterior, no como requisito de la P1. |

### D-03 — Extensión de Chrome

| | |
|--|--|
| **Estado** | **Descartado** (trabajo futuro) |
| **Versión original** | Roadmap P2. |
| **Versión nueva** | No implementado. |
| **Justificación** | Fuera del alcance de la P1/P3 entregada. |

### D-04 — Análisis masivo CSV + PDF

| | |
|--|--|
| **Estado** | **Descartado** (trabajo futuro) |
| **Versión original** | Roadmap P2. |
| **Versión nueva** | No implementado. |
| **Justificación** | Fuera del alcance. |

### D-05 — Alertas Slack / Teams

| | |
|--|--|
| **Estado** | **Descartado** (trabajo futuro) |
| **Versión original** | Roadmap P2. |
| **Versión nueva** | No implementado. |
| **Justificación** | Fuera del alcance. |

### D-06 — Usuarios JWT e historial privado

| | |
|--|--|
| **Estado** | **A revisar** (parcialmente mitigado) |
| **Versión original** | Roadmap P2: usuarios con login JWT e historial privado. |
| **Versión nueva** | Sin usuarios. El historial exige `ADMIN_TOKEN` (Bearer) y ya no guarda cuerpos de email (solo huella SHA-256). |
| **Justificación** | La P3 pregunta cómo se autentica. Se justifica un único token de administración frente a un sistema de usuarios completo, por alcance académico y minimización de datos. Queda a criterio docente si basta. |

### D-07 — Caché Redis

| | |
|--|--|
| **Estado** | **Descartado** (trabajo futuro) |
| **Justificación** | Roadmap P2; no implementado. |

### D-08 — Panel de auditoría de peticiones bloqueadas

| | |
|--|--|
| **Estado** | **Descartado** (trabajo futuro) |
| **Justificación** | Roadmap P2; los logs JSON van a stdout de Render, sin panel propio. |

### D-09 — Google Safe Browsing

| | |
|--|--|
| **Estado** | **Descartado** (trabajo futuro) |
| **Justificación** | Roadmap P2; no implementado. |

### D-10 — VirusTotal y URLScan «en paralelo lógico»

| | |
|--|--|
| **Estado** | **A revisar** |
| **Versión original** | Informe P1 §5.3 paso 4: consultas «en paralelo lógico». |
| **Versión nueva** | En código se ejecutan **en secuencia** (`analyze.py`). |
| **Justificación** | Desajuste documentación/código. Corregir el texto de la memoria o usar `asyncio.gather`. **PENDIENTE** de decisión en la memoria final. |

---

## 4. Cambios relevantes respecto al informe P1 (sin cambiar el ID)

| Tema | Original (P1 / código antiguo) | Nueva | Justificación |
|------|-------------------------------|-------|---------------|
| Veredicto sin IA | Podía salir `LEGÍTIMO` con score bajo en emails | `NO CONCLUYENTE` + etiqueta «Análisis limitado (sin IA)» | H-02 / RF-08 (`76faa4e`) |
| Historial | Público, con texto íntegro del email | `ADMIN_TOKEN` + minimización SHA-256 | H-01 (`0d1d385`) |
| `/docs` en producción | Público | 404 si `ENVIRONMENT=production` | H-07 / RNF-09 (`df134a9`) |
| IP / rate limit en producción | `TRUSTED_PROXY_HOPS=1` sobre XFF | `TRUST_CF_CONNECTING_IP=true` (Cloudflare) | H-13 (`22b9f2e`) |
| URLScan | Búsqueda por dominio (sin POST `/scan/`) | Explícito: solo hostname; `REQUIRED_SCAN_VISIBILITY=unlisted` por si se añade escaneo | Minimización RF-06 (`b4a8715`) |
