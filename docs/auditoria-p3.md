# Auditoría previa a la entrega — Práctica 3 (PhishGuard)

- **Fecha de la auditoría:** 14/10/2026
- **Commit auditado:** `0d0b615` (rama `main`, HEAD) — se revisaron también `dev` y `origin/cloudflare/workers-autoconfig`
- **Fecha límite de entrega:** viernes 16/10/2026
- **Material de referencia:**
  - Enunciado: `Práctica_3_Evolve.pdf`
  - Informe P1: `PhishGuard_Practica1_Mario_Cruz_Martinez.pdf`
  - Enunciado P1: `practica_ciberseguridad_IA.pdf`, consultado solo para contrastar los requisitos obligatorios de la P1
- **Alcance:** la auditoría inicial fue solo de análisis, sin modificar ningún fichero del proyecto ni reescribir el historial. Las correcciones posteriores se hicieron en 8 commits, uno por bloque, sin push ni tags. Su estado está en el [apartado 7](#7-correcciones-aplicadas) y en las columnas «Estado» de los apartados 3 y 5, actualizadas con el commit que resuelve cada punto.

> **Estado a 14/10/2026, tras las correcciones:** se han resuelto H-01, H-02, H-03, H-04, H-05, H-07, H-09, H-12 y H-13, y RF-08, RNF-01 y RNF-09 pasan a Cumplido. H-13 (IP del rate limit en producción detrás de Cloudflare → Render) se diagnosticó con logs reales y se corrige con `TRUST_CF_CONNECTING_IP`. Hay 157 tests automáticos que pasan. pip-audit da 0 vulnerabilidades y npm audit 2 moderadas en producción, aceptadas como RA-02. Lo que sigue abierto está en el [apartado 7.2](#72-qué-sigue-abierto).
>
> Los apartados 3 y 5, el 2.3 y la primera tabla del apartado 4 reflejan el estado actual. El «Resumen» de este apartado, los apartados 1, 2.1 y 2.2, la segunda tabla del 4 y el 6 son el diagnóstico original. En el 6 solo se han añadido las marcas de «Hecho».

## Resumen (diagnóstico original)

| Área | Resultado |
|------|-----------|
| Secretos en el historial git | **Ninguno.** gitleaks, trufflehog y una búsqueda manual coinciden. |
| Secretos en el árbol de trabajo | 2 coincidencias, ambas en `.env`, que es local, está en `.gitignore` y nunca se ha versionado. Es lo esperado. |
| Dependencias del backend (pip-audit) | 1 paquete vulnerable: `python-multipart 0.0.29`, con 3 avisos que se corrigen en 0.0.31. |
| Dependencias del frontend (npm audit) | 18 vulnerabilidades (12 altas, 5 moderadas, 1 baja, 0 críticas). Solo 5 afectan al código de producción: `axios` y `form-data` (altas) y `react-router-dom` con sus dependencias (moderadas). |
| Requisitos | 15 funcionales y 13 no funcionales derivados del informe P1 y del código: 21 Cumplidos, 7 Parciales, 0 Pendientes, más 10 dudosos aparte. |
| Huecos frente al enunciado | Faltan `LICENSE` (el repo es **público** y el README dice MIT), pruebas automatizadas, la etiqueta `v1.0-practica3` y varios apartados del README. |
| Fallos relevantes detectados | El motor heurístico de respaldo clasifica **todos** los emails como LEGÍTIMO. `/api/history` expone públicamente el texto íntegro de los emails analizados. El rate limit se puede saltar falsificando `X-Forwarded-For`. El historial no persiste en producción. |

Me faltan dos entradas para cerrar la auditoría:

1. **Calificación y comentarios del equipo docente sobre la P1.** El apartado 3 del enunciado los exige y no los he encontrado. Pueden cambiar el estado de algunos requisitos a «A revisar».
2. **Lista numerada de requisitos de la P1.** El informe P1 no la tiene. La numeración del apartado 3 de este informe es una **propuesta** derivada de sus apartados 5, 6 y 8 y del código.

---

## 1. Secretos

### 1.1 Método

| Herramienta | Versión | Alcance | Resultado |
|-------------|---------|---------|-----------|
| `gitleaks git . --log-opts="--all" --redact` | 8.30.1 | Historial completo, todas las ramas y referencias remotas | `no leaks found` (18 commits escaneados, ~318 KB) |
| `trufflehog git file://<repo>` | 3.99.2 | Historial completo | `verified_secrets: 0`, `unverified_secrets: 0` (187 fragmentos, ~326 KB) |
| `gitleaks dir . --redact` | 8.30.1 | Árbol de trabajo, incluidos los ficheros ignorados | 2 hallazgos (detalle abajo) |
| Búsqueda manual en `git log --all -p` | — | Los 19 commits de todas las ramas | Solo los marcadores de `.env.example` (`your_key_here`, `your_virustotal_key_here`) |

La búsqueda manual usó patrones para claves de Anthropic (`sk-ant-…`), asignaciones `api_key|secret|token|password = …`, cadenas hexadecimales de 64 caracteres (formato de VirusTotal), UUID (formato de URLScan), AWS (`AKIA…`), GitHub (`ghp_…`) y claves privadas PEM.

Los binarios de gitleaks y trufflehog se descargaron de sus releases oficiales en `%TEMP%\p3-audit-tools\`, fuera del repositorio. Sus informes JSON (con los valores redactados) están en esa misma carpeta, por si se quieren adjuntar como evidencia en la memoria.

### 1.2 Hallazgos

| # | Tipo | Fichero | Commit | ¿Versionado? | Valoración |
|---|------|---------|--------|--------------|------------|
| S-01 | `anthropic-api-key` (gitleaks) | `.env`, línea 1 | Ninguno | **No.** Lo excluye `.gitignore:2` y `git ls-files` no lo conoce. | Correcto: es la configuración local. **No abras `.env` en el vídeo ni en las capturas** (ahora mismo está abierto en el editor). |
| S-02 | `generic-api-key` (gitleaks) | `.env`, línea 2 | Ninguno | No | Igual que S-01. |

**Historial git: 0 secretos reales.** Ficheros sensibles revisados expresamente:

| Fichero | Commits | Contenido |
|---------|---------|-----------|
| `.env.example` | `407c26e`, `4d21d47`, `e743182`… | Solo marcadores (`your_key_here`). |
| `frontend/.env.production` | `0deea69` | Solo `VITE_API_URL` con una URL de ejemplo. |
| `SECURITY.md` | Añadido en `efd5d18`, borrado en `843a711` | Medidas de seguridad y proceso de divulgación. Sin credenciales. |
| `docs/LOVABLE_UI_PROMPT.md` | Añadido en `55540b0`, borrado en `ad9d36f` | Prompt de diseño de UI. Sin credenciales. |
| `wrangler.jsonc` | `c2add9b` (rama `cloudflare/workers-autoconfig`, generado por el bot de Cloudflare) | Configuración sin secretos. |
| `render.yaml` | Varios | Las claves se declaran con `sync: false`, sin valor. |

**No hace falta revocar claves ni limpiar el historial.**

### 1.3 Información no secreta pero visible en un repo público

El repositorio `MCM13/phishguard` es **público** (comprobado en la API de GitHub: `private=False`). Esto es lo que se publica, sin ser un secreto:

| Dato | Dónde | Recomendación |
|------|-------|---------------|
| Email personal del autor, `pi.mariocruz@gmail.com` | Metadatos de autor de 18 commits | No es un secreto. Cambiarlo exigiría reescribir el historial, cosa que no se ha hecho. Si molesta, usa el email `noreply` de GitHub en los commits nuevos (`git config user.email`). |
| Trailer `Co-authored-by: Cursor <cursoragent@cursor.com>` | 17 commits | Encaja con la declaración de uso de IA que exige el apartado 12 del enunciado. Menciónalo en la memoria. |
| Dominio de producción `phishguard.cmmario.com` | `.env.example` (comentario) e informe P1 | Es público a propósito. |
| URL del backend `phishguard-backend-qszu.onrender.com` | Bundle JS de producción (no en el repo) | Es inevitable en una SPA. |
| IPs `192.168.0.1`, `169.254.169.254`, `127.0.0.1` | Código y script de pruebas anti-SSRF | Son datos de prueba, no infraestructura real. |

---

## 2. Dependencias

Salidas completas:

- [`docs/evidencias/pip-audit.txt`](evidencias/pip-audit.txt)
- [`docs/evidencias/npm-audit.txt`](evidencias/npm-audit.txt)

### 2.1 Backend: `pip-audit -r backend/requirements.txt`

- **Entorno:** contenedor `python:3.11-slim`, la misma base que `backend/Dockerfile`, con pip-audit 2.10.1. Se resolvieron 42 paquetes, contando los transitivos.
- **Resultado:** `Found 6 known vulnerabilities in 1 package`. Son **3 avisos únicos**: pip-audit lista cada uno dos veces.

| Paquete | Versión | Aviso | CVE / GHSA | Corregido en | Severidad estimada* | Exposición en PhishGuard |
|---------|---------|-------|------------|--------------|---------------------|--------------------------|
| python-multipart | 0.0.29 | PYSEC-2026-3036 | CVE-2026-53539 / GHSA-5rvq-cxj2-64vf | 0.0.30 | Media-Alta (DoS por CPU cuadrática) | Baja. Solo afecta a cuerpos `application/x-www-form-urlencoded`, y `JSONContentTypeMiddleware` responde 415 a todo POST que no sea JSON. |
| python-multipart | 0.0.29 | PYSEC-2026-3037 | CVE-2026-53538 / GHSA-6jv3-5f52-599m | 0.0.30 | Media (contaminación de parámetros con `;`) | Muy baja. Ningún endpoint usa `request.form()`. |
| python-multipart | 0.0.29 | PYSEC-2026-3040 | CVE-2026-53540 / GHSA-v9pg-7xvm-68hf | 0.0.31 | Baja (el propio aviso dice que no afecta a ningún paquete conocido) | Ninguna. FastAPI y Starlette no llaman a `parse_form()`. |

\* pip-audit no da severidad para los avisos PYSEC. La estimación sale de la descripción de cada aviso y conviene contrastarla con la GHSA en la memoria.

**Resumen por severidad:** 0 críticas, 1 media-alta, 1 media, 1 baja. **Corrección:** fijar `python-multipart==0.0.31` (o superior).

**Observación:** `requirements.txt` fija solo las dependencias directas. Las transitivas (`starlette`, `anthropic` → `httpx`, etc.) se resuelven en cada build, así que una auditoría futura puede dar otro resultado. Valora generar un lock (`pip freeze > requirements.lock` o `pip-tools`).

### 2.2 Frontend: `npm audit` en `frontend/`

- **Entorno:** node v24.15.0, npm 11.12.1.
- **Base:** `frontend/package-lock.json`, sin ejecutar `npm install` y sin modificar el lockfile.

| Severidad | Total | Producción (`--omit=dev`) | Solo desarrollo o build |
|-----------|-------|---------------------------|-------------------------|
| Crítica | 0 | 0 | 0 |
| Alta | 12 | 2 | 10 |
| Moderada | 5 | 3 | 2 |
| Baja | 1 | 0 | 1 |
| **Total** | **18** | **5** | **13** |

**Paquetes que llegan al bundle de producción:**

| Paquete | Severidad | ¿Directo? | Nota |
|---------|-----------|-----------|------|
| `axios` (1.0.0 – 1.19.0) | Alta | Sí | 21 avisos. Muchos afectan solo al adaptador HTTP de Node (proxy, HTTP/2, `NO_PROXY`), que no se usa en el navegador. Aun así hay que actualizar: lo arregla `npm audit fix`. |
| `form-data` (4.0.0 – 4.0.5) | Alta | No (llega con axios) | Inyección CRLF en multipart. PhishGuard no envía multipart. |
| `react-router-dom`, `react-router`, `@remix-run/router` | Moderada | Sí / No / No | Redirección abierta con rutas que empiezan por `//`. Lo arregla `npm audit fix`. |

**Paquetes de desarrollo o build** (no llegan al navegador): `vite` (alta, directo; riesgo para el servidor de desarrollo en Windows), `postcss` (alta, directo), `tailwindcss` → `chokidar` / `micromatch` / `fast-glob` / `braces` (altas), `browserslist`, `nanoid`, `source-map-js` (altas), `postcss-selector-parser`, `baseline-browser-mapping` (moderadas) y `@babel/core` (baja).

**Corrección:**

- `npm audit fix` (sin `--force`) corrige todo salvo la cadena de `braces`.
- La cadena de `braces` exige `tailwindcss@4`, que es una versión mayor con cambios incompatibles. Como afecta solo al build, la opción razonable para el viernes es **aceptar y documentar el riesgo** en la memoria en vez de migrar a Tailwind 4.

### 2.3 Estado tras la corrección (bloque 2, commit `54365a5`)

Cambios aplicados: `python-multipart==0.0.31` en `backend/requirements.txt` y `npm audit fix` **sin `--force`** en `frontend/`, que solo modificó `package-lock.json`. Después se ejecutó `npm run build` y terminó correctamente.

Salidas completas:

- [`docs/evidencias/pip-audit-despues.txt`](evidencias/pip-audit-despues.txt)
- [`docs/evidencias/npm-audit-despues.txt`](evidencias/npm-audit-despues.txt)

| Auditoría | Antes | Después |
|-----------|-------|---------|
| pip-audit (backend) | 3 avisos en 1 paquete | **0** (`No known vulnerabilities found`) |
| npm audit, total | 18 (12 altas, 5 moderadas, 1 baja) | **9** (5 altas, 4 moderadas) |
| npm audit, solo producción (`--omit=dev`) | 5 (2 altas, 3 moderadas) | **2 moderadas** (`react-router` / `react-router-dom`) |

Se corrigieron `axios`, `form-data`, `vite`, `postcss`, `browserslist`, `nanoid`, `source-map-js`, `@babel/core` y `baseline-browser-mapping`, entre otros.

#### Riesgos aceptados

| ID | Paquetes | Severidad | ¿Llega a producción? | Por qué se acepta | Corrección futura |
|----|----------|-----------|----------------------|-------------------|-------------------|
| RA-01 | `tailwindcss@3` → `chokidar`, `micromatch`, `fast-glob`, `braces`, `postcss-nested`, `postcss-selector-parser` | 5 altas y 2 moderadas | **No.** Tailwind solo se ejecuta en el build y genera CSS estático. | Las vulnerabilidades son DoS por patrones glob o selectores maliciosos, y solo afectan a la máquina que compila, con ficheros del propio repositorio. Corregirlas exige migrar a Tailwind 4 (configuración CSS-first, otras clases y otro plugin de PostCSS), una migración demasiado arriesgada a dos días de la entrega. | Migrar a Tailwind 4 tras la entrega. |
| RA-02 | `react-router-dom@6` → `react-router` | 2 moderadas | Sí (bundle) | Los dos avisos que quedan son: (1) redirección abierta con `\` en `<Link>` / `useNavigate` cuando el destino lo controla el usuario, y (2) inyección en `deserializeErrors()` al hidratar **SSR**. PhishGuard solo usa `BrowserRouter`, `Routes`, `Route` y `NavLink` con rutas fijas (`/` y `/history`). No navega a destinos controlados por el usuario ni usa SSR, así que **no es explotable** en esta aplicación. La única corrección es `react-router-dom@7`, una versión mayor que pide `--force`. | Subir a `react-router-dom@7` (en v6 → v7 la API de estas piezas apenas cambia) y comprobar la navegación. |

---

## 3. Requisitos propuestos (RF / RNF)

**Cómo se han obtenido:** el informe P1 no numera requisitos. Cada uno de abajo cita su origen (apartado del informe P1, «Código» si solo existe en la implementación, o ambos). Los estados siguen el apartado 3 del enunciado: Cumplido / Parcial / Pendiente / A revisar / Descartado. La columna «Observaciones» recoge lo que habría que demostrar o corregir.

**Estado actualizado** tras los commits del apartado 7. Cuando un estado ha cambiado se indica como «antes → ahora (commit)». La columna «Test» señala el fichero de `backend/tests/` que lo verifica. «—» significa que el requisito no es verificable desde el código del backend (frontend o infraestructura) y se demuestra en el vídeo.

### 3.1 Requisitos funcionales

| ID | Requisito | Origen | Estado | Implementación | Test | Observaciones |
|----|-----------|--------|--------|----------------|------|---------------|
| RF-01 | Analizar una URL sospechosa y devolver score, veredicto, indicadores y explicación | P1 §3, §5.3, §8.1 | Cumplido | `backend/app/routers/analyze.py` (`POST /api/analyze/url`), `frontend/src/components/URLAnalyzer.jsx` | `test_analysis_url.py` | La respuesta incluye ahora `analysis_mode` y `analysis_label` (`76faa4e`). |
| RF-02 | Analizar el texto de un email (solo el cuerpo o el correo completo con cabeceras), con un mínimo de 10 caracteres | P1 §8.2 | Cumplido | `analyze.py` (`POST /api/analyze/email`), `frontend/src/components/EmailAnalyzer.jsx` | `test_analysis_email.py` | Validación doble: en el frontend y con Pydantic (`min_length=10`). |
| RF-03 | Extraer 15 características de la URL: longitud, subdominios, palabras clave, caracteres sospechosos, TLD inusual, HTTPS, IP como host, edad WHOIS y `young_domain` | P1 §5.3, §6.3 | Cumplido | `backend/app/services/url_extractor.py` | `test_analysis_url.py` | Son exactamente 15 claves. Si WHOIS falla, `domain_age_days = None` y el análisis sigue (P1 §6.8). **Corregido en `796b8d6`:** los TLD que no están en la Public Suffix List se marcan como inusuales (antes `tld` quedaba vacío). |
| RF-04 | Extraer señales del email: remitente, reply-to distinto del remitente, URLs, frases sospechosas en español e inglés, adjuntos | Código (P1 §8.2 solo lo menciona de pasada) | Cumplido | `backend/app/services/email_extractor.py`, `domain_utils.py` | `test_analysis_email.py`, `test_email_encoding.py` | **Ampliado en `76faa4e`:** se analizan las cabeceras antes de quitar el HTML. Se detectan: lenguaje de urgencia y amenaza; peticiones de credenciales y de pago; remitente visible frente a dominio real; Reply-To distinto; texto del enlace frente a destino; extensiones de adjunto peligrosas. **Corregido en `3acfb6b` (H-12):** el cuerpo ya no pierde tildes ni eñes cuando falta el charset o cuando no coincide con el texto. Lo cubre `test_email_encoding.py`. |
| RF-05 | Consultar la reputación de la URL en VirusTotal (API v3) | P1 §5.2, §6.4 | Cumplido | `backend/app/services/virustotal.py` | `test_analysis_url.py` | En emails solo se consulta la **primera** URL. Si la URL no existe en VT, se envía a analizar y se devuelve un resultado neutro. |
| RF-06 | Consultar URLScan.io como contexto adicional | P1 §5.2, §6.4 | Cumplido | `backend/app/services/urlscan.py` | `test_analysis_url.py` | Solo busca informes históricos del **dominio** (GET `/search/`); no lanza un escaneo nuevo. El resultado va a Claude pero **no se muestra en la UI**. `URLSCAN_API_KEY` añadida a `render.yaml` en `0d1d385`. **Minimización:** no se reenvían path ni query (tokens, emails) a URLScan; `REQUIRED_SCAN_VISIBILITY=unlisted` queda fijado por si algún día se añade POST `/scan/` (`test_urlscan_no_envia_escaneo_ni_expone_path_o_query`). |
| RF-07 | Veredicto con IA (Claude): JSON estricto con score 0-100, veredicto PHISHING / SOSPECHOSO / LEGÍTIMO, indicadores con severidad y explicación en español, con parseo defensivo y normalización | P1 §5.2, §6.3 | Cumplido | `backend/app/services/claude_analyzer.py` | `test_ai_and_quota.py`, `test_prompt_injection.py` (SDK simulado) | **Desde `f6b79c8`** la respuesta se valida contra un esquema JSON estricto (claves exactas, `score` entero de 0 a 100 y veredicto exacto); si no cumple, se usa el fallback en lugar de corregir los valores. El modelo por defecto del código (`claude-sonnet-4-5-20250929`) no coincide con el de `.env.example` y `render.yaml` (`claude-sonnet-4-6`). |
| RF-08 | Motor heurístico de respaldo cuando no hay IA (sin clave, cuota agotada, error o respuesta no válida) | P1 §5.3 paso 6, §6.3 | Parcial → **Cumplido** (`76faa4e`) | `claude_analyzer.py` (`_url_rules`, `_email_rules`, `_fallback_verdict`), `ResultCard.jsx`, `ScoreGauge.jsx`, `HistoryTable.jsx` | `test_analysis_email.py`, `test_external_failures.py` | Reglas propias para email y URL, más la señal de VirusTotal. En modo sin IA la interfaz muestra «Análisis limitado (sin IA)» y nunca da `LEGÍTIMO`: sin señales suficientes devuelve **`NO CONCLUYENTE`**. El email de phishing de prueba sale PHISHING 100. |
| RF-09 | Tolerancia a fallos: si VirusTotal, URLScan o WHOIS fallan o no están configurados, el análisis continúa | P1 §5.2, README | Cumplido | `virustotal.py`, `urlscan.py`, `url_extractor.py` (`try/except` con resultado neutro) | `test_external_failures.py` | **Demostrado con tests (`796b8d6`):** conexión rechazada, timeout, HTTP 500 y 429, JSON no válido, Anthropic caído y WHOIS caído, por separado y todos a la vez. En todos los casos la respuesta es 200 y no se filtran detalles del error. |
| RF-10 | Guardar cada análisis en la base de datos (SQLite con SQLAlchemy) | P1 §5.2, §5.3 paso 7 | **Parcial** | `backend/app/database.py`, `backend/app/models/analysis.py`, `analyze.py::_persist_analysis` | `test_history.py` | **Minimizado en `0d1d385`:** solo se guardan tipo, veredicto, score, modo, fecha, dominio y una huella SHA-256 del contenido. Las bases de datos antiguas se migran y se purgan al arrancar. Sigue Parcial porque **en producción** (Render, `sqlite:////tmp/…`) los datos se pierden en cada reinicio; está documentado en el README. |
| RF-11 | Historial paginado y filtrable por veredicto (Todos / PHISHING / SOSPECHOSO / LEGÍTIMO) | P1 §8.5 | Cumplido | `backend/app/routers/history.py` (`GET /api/history`), `frontend/src/pages/History.jsx`, `frontend/src/components/HistoryTable.jsx` | `test_history.py` | **Desde `0d1d385`** requiere `ADMIN_TOKEN` y el contador muestra el total real. El filtro incluye `NO CONCLUYENTE`. |
| RF-12 | Dashboard web con estadísticas: total analizado, phishing detectados, % de detección, score medio y cuota de IA | P1 §3; requisito obligatorio 01 del enunciado P1 | Cumplido | `history.py` (`GET /api/stats`), `frontend/src/pages/Dashboard.jsx` | `test_history.py` | `/api/stats` sigue siendo público (solo da agregados) y tiene rate limit desde `e7fa375`. |
| RF-13 | Medidor visual 0-100 con colores verde (0-30), ámbar (31-60) y rojo (61-100) | P1 §5.2, §8.4 | Cumplido | `frontend/src/components/ScoreGauge.jsx`, `ResultCard.jsx` | — (frontend) | El color depende del **veredicto**, no del rango del score. `NO CONCLUYENTE` se muestra en gris. |
| RF-14 | Las URLs con veredicto PHISHING no se muestran como enlace clicable (aparecen tachadas y marcadas como bloqueadas) | P1 §6.6, §8.5 | Cumplido | `frontend/src/components/ResultCard.jsx` | — (frontend) | Las URLs con veredicto **SOSPECHOSO** sí son clicables (`<a href>`). El historial ya no muestra URLs, solo el dominio. |
| RF-15 | API REST documentada de forma interactiva (`/docs`) | P1 §5.4, §7 paso 4 | Cumplido | `backend/app/main.py` (FastAPI por defecto) | `test_platform.py` | En producción está expuesta públicamente (ver RNF-09). |

### 3.2 Requisitos no funcionales

| ID | Requisito | Origen | Estado | Implementación | Test | Observaciones |
|----|-----------|--------|--------|----------------|------|---------------|
| RNF-01 | Rate limiting por IP: 10/min en los análisis y 30/min en el historial; respuesta 429 con `Retry-After` | P1 §6.6 | Parcial → **Cumplido** (`e7fa375`, H-13) | `backend/app/services/client_ip.py`, `rate_limit.py`, `main.py`, decoradores en los routers | `test_rate_limit.py` | (a) **Resuelto** en local con hops; en producción detrás de Cloudflare el hops=1 cogía el balanceador de Render (H-13) → `TRUST_CF_CONNECTING_IP`. (b) `/api/stats` tiene límite; `RATE_LIMIT_*` configurables (defaults del código si no están en el panel). (c) Contadores en memoria, un worker. Los 422 de análisis también cuentan (`7f48582`). |
| RNF-02 | Cabeceras de seguridad HTTP (OWASP Secure Headers): CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy y HSTS cuando la petición es HTTPS | P1 §6.6 | Cumplido (backend) | `backend/app/middleware/security_headers.py` | `test_security.py` | Comprobado también en las respuestas 401, 404 y 400. El frontend (nginx en Docker o Cloudflare Pages) no añade cabeceras ni CSP. |
| RNF-03 | Protección anti-SSRF: solo `http(s)`, bloqueo de localhost, IPs privadas, loopback, link-local, multicast, reservadas y metadata de cloud, con resolución DNS de cada IP | P1 §5.3 paso 2, §6.6 | Cumplido | `backend/app/services/url_validator.py` | `test_security.py` | 13 destinos internos, un dominio que resuelve a una IP privada y 6 esquemas no válidos. Se comprueba que no se llama a VirusTotal en esos casos. |
| RNF-04 | Validación y saneado de entradas: límites de longitud, eliminación de HTML/JS/CSS y caracteres de control, cuerpo máximo de 1 MB (413), solo `application/json` (415) y timeout de 30 s (504) | P1 §5.2; código | Cumplido | `backend/app/services/text_sanitizer.py`, `backend/app/middleware/request_guards.py`, esquemas Pydantic en `analyze.py` | `test_security.py` | **Desde `4907f96`** Claude, WHOIS y la resolución DNS se ejecutan en hilos (`asyncio.to_thread`) y ya no bloquean el event loop. El 504 responde a tiempo, pero no cancela el hilo; el cliente de Claude tiene su propio timeout de 25 s. El timeout de 504 no tiene test. |
| RNF-05 | El contenedor del backend se ejecuta sin privilegios (`appuser`, UID 10001) | P1 §6.6 | Cumplido | `backend/Dockerfile` | `test_platform.py` (estático) | Se demuestra con `docker exec phishguard-backend id`. |
| RNF-06 | Logs de auditoría en JSON (`phishguard.audit`) sin cuerpos ni claves de API | P1 §6.6 | Cumplido | `backend/app/middleware/audit_log.py` | `test_platform.py`, `test_history.py` | **Desde `0d1d385`** registra los accesos fallidos al historial (`event=admin_auth_failed`, `reason`) sin el token. **Desde `e7fa375`** la IP registrada no es falsificable. Siguen registrando la IP y el User-Agent truncado, que son datos personales. |
| RNF-07 | Cuotas configurables de llamadas a Anthropic (por hora y por día), con el contador guardado en la base de datos | P1 §6.6 | **Parcial** | `backend/app/services/anthropic_rate_limit.py`, `backend/app/models/anthropic_usage.py` | `test_ai_and_quota.py` | (b) **Resuelto en `e7fa375`:** comprobar y registrar se hacen bajo un lock, y los límites se leen en cada llamada. (a) Sigue Parcial: en Render el contador se reinicia con la base de datos de `/tmp`. Está documentado en el README. |
| RNF-08 | Gestión de secretos: las claves solo están en `.env` o en los paneles de Render y Cloudflare, nunca en el repositorio | P1 §6.7; README | Cumplido | `.gitignore`, `.env.example`, `render.yaml` (`sync: false`) | — (apartado 1) | Verificado en el apartado 1. `ADMIN_TOKEN` está vacío en `.env.example` (fail closed) y con `sync: false` en `render.yaml`. |
| RNF-09 | Errores genéricos, sin trazas ni detalles internos para el usuario | P1 (SECURITY.md histórico); `frontend/src/api.js` | Parcial → **Cumplido** (`df134a9`) | `frontend/src/api.js::friendlyError`, `analyze.py`, `admin_auth.py`, `main.py` | `test_security.py`, `test_external_failures.py`, `test_platform.py` | **Resuelto en `796b8d6`:** los 500 ya no exponen el nombre de la excepción. **En `76faa4e`:** el motivo del modo sin IA es genérico. El 401 del historial es idéntico para todos los motivos. **Resuelto en `df134a9`:** con `ENVIRONMENT=production` no se publican `/docs`, `/redoc` ni `/openapi.json` (404). |
| RNF-10 | Entorno reproducible con Docker Compose: 2 servicios, volumen persistente y variables desde `.env` | P1 §5.4, §6.2, §7 | **Parcial** | `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`, `README.md` | — | **En `9f3cebd`** se documentó la instalación desde cero paso a paso, y el comando de tests del README se verificó sobre una imagen limpia. **En `e62c678`** `frontend/Dockerfile` pasa a usar `npm ci` con `package-lock.json` (H-09); el build de la imagen se comprobó. Siguen abiertos: no hay healthchecks, el backend no tiene lock de dependencias transitivas y **falta una instalación hecha por otra persona**. |
| RNF-11 | Despliegue accesible en Internet con HTTPS y dominio propio (Cloudflare Pages + Render) | P1 §3, §6.7, §7 pasos 6-9 | **Parcial** | `render.yaml`, `frontend/.env.production`; configuración en los paneles | — | Sin cambios: los datos no persisten y el plan gratuito tiene arranque en frío. Las limitaciones están documentadas en el README (`9f3cebd`). **Hay que definir `ADMIN_TOKEN` y `TRUSTED_PROXY_HOPS=1` en el panel de Render** antes de la demo. Ver también D-01. |
| RNF-12 | Configuración por variables de entorno: modelo, límites de cuota, CORS, URL del backend y base de datos | P1 §9.2; README | Cumplido | `.env.example`, `backend/app/cors_config.py`, `database.py`, `rate_limit.py`, `client_ip.py` | `test_platform.py`, `test_ai_and_quota.py`, `test_rate_limit.py` | Añadidas `ADMIN_TOKEN`, `RATE_LIMIT_*`, `TRUSTED_PROXY_*` y `TRUST_CF_CONNECTING_IP` (H-13). Sigue pendiente H-08: el valor por defecto de CORS en código es `"*"`. |
| RNF-13 | Interfaz y resultados en español | P1 §3, §8 | Cumplido | Todo `frontend/src`, prompt de `claude_analyzer.py` | — (frontend) | — |

**Recuento actual:** RF: 14 Cumplidos y 1 Parcial (RF-10). RNF: 10 Cumplidos y 3 Parciales (RNF-07, RNF-10 y RNF-11). Ningún Pendiente. Antes de las correcciones eran RF 13/2 y RNF 8/5.

### 3.3 Requisitos dudosos (decidir antes de la memoria)

Estos elementos aparecen en el material de la P1 pero **no está claro que sean requisitos de la P1**. No los he metido en la lista principal para no inventar requisitos. Conviene decidir con el equipo docente si entran en la matriz (por ejemplo como «Descartado» o «A revisar», con justificación) o si basta con citarlos como trabajo futuro.

| ID | Elemento | Origen | Propuesta de estado | Comentario |
|----|----------|--------|---------------------|------------|
| D-01 | Despliegue en un VPS de **Hetzner** | Enunciado P1, requisito obligatorio 03 (no lo menciona el informe P1) | A revisar | Se desplegó en Render y Cloudflare. El enunciado de la P3 (FAQ) dice que el despliegue no es obligatorio. Justifica el cambio (coste, plan gratuito, HTTPS gestionado) o despliega en Hetzner si el docente lo exige. |
| D-02 | Análisis de capturas de pantalla o imágenes | Roadmap P2 §10.2 nº 1; el enunciado P1 (herramienta 08) lo cita como entrada posible | Descartado o trabajo futuro | El informe P1 lo planificó para la «Práctica 2», no como requisito de la P1. |
| D-03 | Extensión de Chrome | Roadmap P2 §10.2 nº 2 | Descartado o trabajo futuro | Igual que D-02. |
| D-04 | Análisis masivo desde CSV con informe en PDF | Roadmap P2 §10.2 nº 3 | Descartado o trabajo futuro | Igual que D-02. |
| D-05 | Alertas a Slack o Teams | Roadmap P2 §10.2 nº 4 | Descartado o trabajo futuro | Igual que D-02. |
| D-06 | Usuarios con inicio de sesión (JWT) e historial privado | Roadmap P2 §10.2 nº 5 | **A revisar** | El enunciado de la P3 pregunta expresamente cómo se autentica a los usuarios. **Desde `0d1d385`** el historial se protege con `ADMIN_TOKEN` y ya no contiene contenido analizado. Sigue sin haber usuarios, y en la memoria hay que justificar por qué basta con un único token de administrador. |
| D-07 | Caché Redis para URLs ya analizadas | Roadmap P2 §10.3 | Descartado o trabajo futuro | — |
| D-08 | Panel de auditoría con peticiones bloqueadas | Roadmap P2 §10.4 | Descartado o trabajo futuro | — |
| D-09 | Google Safe Browsing como cuarta fuente | Roadmap P2 §10.5 | Descartado o trabajo futuro | — |
| D-10 | Consultas a VirusTotal y URLScan «en paralelo lógico» | P1 §5.3 paso 4 | A revisar | El código las hace **en secuencia** (`analyze.py:131-132`). Corrige el texto o usa `asyncio.gather`. |

---

## 4. Huecos frente al enunciado (apartado 7 y lista de comprobación del apartado 14)

Estado actual de cada hueco:

| Elemento | Ahora |
|----------|-------|
| `README.md` | **Resuelto en `9f3cebd`**, salvo la instalación por otra persona en una máquina limpia, que sigue pendiente. Añadidos: instalación desde cero, variables, uso, tests, credenciales («No aplica…»), URL de despliegue y limitaciones. Los enlaces a `LICENSE` y `SECURITY.md` funcionan desde `0d1b429`. |
| `.env.example` | `ADMIN_TOKEN`, `RATE_LIMIT_*` y `TRUSTED_PROXY_*` añadidos (`0d1d385`, `e7fa375`). Sigue faltando `LOG_LEVEL`. |
| `.gitignore` | Ya no ignora `SECURITY.md` (`0d1b429`). Las demás sugerencias siguen pendientes. |
| Licencia | **Resuelto en `0d1b429`** (MIT). |
| `Dockerfile` y `docker-compose.yml` | uvicorn arranca con `--no-proxy-headers` (`e7fa375`) y `render.yaml` declara `URLSCAN_API_KEY` y `ADMIN_TOKEN` (`0d1d385`). `frontend/Dockerfile` usa `npm ci` (`e62c678`). Siguen pendientes los healthchecks. |
| Pruebas automatizadas | **Resuelto en `796b8d6`** y ampliado (prompt injection, docs off, encoding, rate limit/CF…): **157 tests** con pytest en `backend/tests/`; salida en [`docs/evidencias/pytest.txt`](evidencias/pytest.txt). No hay tests de frontend ni CI. |
| Etiqueta `v1.0-practica3` | **Pendiente a propósito:** en esta tanda se pidió no crear tags. |
| Documento de seguridad | `SECURITY.md` versionado (`0d1b429`, ampliado en `0d1d385`). El STRIDE completo sigue pendiente para la memoria. |

Diagnóstico original:

| Elemento | ¿Existe? | Estado | Qué falta |
|----------|----------|--------|-----------|
| `README.md` con instalación desde cero | Sí | **Incompleto** | (1) No tiene sección de **pruebas ni cómo ejecutarlas**. (2) No dice nada de los **datos de acceso de prueba**: indica de forma explícita «No aplica: la aplicación no tiene autenticación». (3) No tiene sección de **uso básico** (está en P1 §8; cópiala con la tabla de interpretación de scores y la URL de ejemplo). (4) **Enlaces rotos** a `LICENSE` y `SECURITY.md`, que no existen. (5) No avisa de que, sin `.env`, `docker compose` falla (`env_file` es obligatorio) ni de qué ocurre sin clave de Anthropic (se usa el motor heurístico). (6) «Desarrollo sin Docker» queda vago para Windows. (7) **Nadie ajeno lo ha probado en una máquina limpia** (es un punto obligatorio de la lista del apartado 14). |
| `.env.example` | Sí | Correcto, con detalles | Todas las variables tienen valores ficticios. Falta `LOG_LEVEL`. El comentario «Ver README para la lista completa» de modelos remite a una lista que el README no tiene. |
| `.gitignore` | Sí | Correcto, con detalles | Excluye `.env`, `node_modules/`, `dist/`, `*.db`, `venv/` y cachés. Sugerencias: añadir `*.log`, `.coverage`, `htmlcov/`, `coverage/`, `*.pem` y `*.key`. Ignora `SECURITY.md`, lo que contradice al README, que lo enlaza. Mejor versionar un documento de seguridad sin datos personales. |
| Licencia | **No** | **Falta** | El repo es **público** y el README anuncia MIT, pero no hay fichero `LICENSE` y GitHub no detecta licencia. Es obligatorio para repos públicos. |
| `Dockerfile` y `docker-compose.yml` | Sí | Correcto, con mejoras | Backend: imagen slim y usuario no root, bien. Frontend: no usa el lockfile (ver RNF-10) y nginx sirve sin cabeceras de seguridad. Compose: sin `healthcheck`. `render.yaml`: falta `URLSCAN_API_KEY` y el frontend en Docker de Render no se usa (va en Cloudflare Pages). |
| Pruebas automatizadas | **No** | **Falta** | No hay `tests/`, `pytest`, `conftest.py`, Vitest ni CI. Solo existe `scripts/security_e2e.ps1`, que es **semiautomático**: imprime resultados pero no comprueba nada ni devuelve un código de error, solo funciona en PowerShell y necesita el backend en marcha. El enunciado exige al menos una prueba por requisito, y las automáticas puntúan. |
| Etiqueta `v1.0-practica3` | **No** | **Falta** | `git tag` no devuelve nada. Hay que crearla sobre el commit final y subirla (`git push origin v1.0-practica3`). |
| Historial que refleje el trabajo | Parcial | — | 19 commits de un único autor; el informe P1 indica un único integrante. Decláralo en «Reparto del trabajo». La rama `dev` se quedó en el commit inicial: bórrala o explica su uso. |
| Documento de seguridad o modelo de amenazas | No (está fuera del repo) | Falta para la memoria | El apartado 7 de la memoria exige STRIDE, secretos, autenticación, entradas, dependencias y datos personales. El antiguo `SECURITY.md` (commit `efd5d18`) es una buena base. |
| Memoria y vídeo | Fuera del repo | — | No forman parte de esta auditoría. La matriz de trazabilidad puede partir de las tablas del apartado 3. |

---

## 5. Otros hallazgos técnicos (seguridad y calidad)

Estos fallos afectan a los criterios «Seguridad y calidad técnica» (15 %) y «Producto funcional» (30 %).

**Estado actual:**

| ID | Estado | Commit | Qué se hizo |
|----|--------|--------|-------------|
| H-01 | **Resuelto** | `0d1d385` | `/api/history` exige `Authorization: Bearer <ADMIN_TOKEN>`, comparado en tiempo constante. Sin token, con un token incorrecto o sin token configurado en el servidor responde un 401 genérico, y el intento queda en el log de auditoría. La base de datos solo guarda tipo, veredicto, score, modo, fecha, dominio y una huella SHA-256; el texto, la URL completa, la explicación y los indicadores ya no se guardan. Las bases de datos antiguas se migran y se purgan (`VACUUM`). El frontend pide el token y lo guarda solo en memoria. |
| H-02 | **Resuelto** | `76faa4e` | Motor heurístico con reglas de email y URL. En modo sin IA se muestra «Análisis limitado (sin IA)» y, en vez de `LEGÍTIMO`, el veredicto es `NO CONCLUYENTE`. Cubierto por `test_analysis_email.py`. |
| H-03 | **Resuelto** (ampliado en H-13) | `e7fa375` | `get_client_ip` común para slowapi y auditoría. `TRUSTED_PROXY_HOPS` / `TRUSTED_PROXY_CIDRS`. uvicorn con `--no-proxy-headers`. En producción con Cloudflare el hops=1 no bastaba → H-13. |
| H-04 | **Resuelto** | `4907f96` | `asyncio.to_thread` para el SDK de Anthropic, WHOIS (`extract_url_features`) y DNS (`validate_public_url`); el cliente de Anthropic tiene un timeout de 25 s. Cubierto por `test_event_loop.py`, que falla con el código anterior. |
| H-05 | **Resuelto (mitigado)** | `f6b79c8` | (1) Las instrucciones van en el prompt de sistema, y los datos, entre etiquetas `<contenido_analizado>`, con `<` y `>` escapados para que el contenido no pueda cerrar la etiqueta. (2) La respuesta se valida contra un esquema estricto; si no cumple, se usa el fallback. (3) Si las heurísticas dan riesgo alto y la IA un veredicto menor, prevalece PHISHING y la discrepancia se muestra (campo `discrepancy`, aviso en `ResultCard`). Cubierto por `test_prompt_injection.py`. Queda un riesgo residual: un email que engañe a la IA sin activar las heurísticas. |
| H-06 | Abierto (documentado) | `9f3cebd` | Limitación del disco efímero explicada en el README. |
| H-07 | **Resuelto** | `76faa4e`, `796b8d6`, `df134a9` | Los 500 y los motivos del modo sin IA son genéricos. Con `ENVIRONMENT=production` no hay `/docs`, `/redoc` ni `/openapi.json`. |
| H-08 | Abierto | — | — |
| H-09 | **Resuelto** | `e62c678` | `COPY package.json package-lock.json` y `npm ci`. |
| H-10 | Abierto | — | En el historial ya no se muestran URLs, pero en `ResultCard` las URLs SOSPECHOSO siguen siendo clicables. |
| H-11 | **Parcial** | `0d1d385` | Corregido el `totalCount` del historial (estaba en RF-11). Siguen pendientes «/72 motores», el modelo por defecto y `utcnow()`. |
| Nuevo | **Resuelto** | `796b8d6` | Encontrado por los tests: `url_extractor` no detectaba como inusuales los TLD que no están en la Public Suffix List. |
| H-12 (nuevo, media) | **Resuelto** | `3acfb6b` | **Encontrado en la prueba con la IA real del 14/10.** Al pegar un email sin `Content-Type`, `_get_body` perdía los caracteres no ASCII del cuerpo («cerámica» → «cer�mica»): Claude lo marcaba como «codificación de caracteres con errores» y las reglas heurísticas con tilde («contraseña», «número de tarjeta», «perderá el acceso») dejaban de detectar las frases. También fallaban `charset=utf-8` en 8 bits, HTML, partes multipart, base64 sin charset y charsets desconocidos, y el «€» acababa como el texto literal `\u20ac`. La causa: el contenido llega como texto Unicode desde el JSON y `get_content()` lo recodificaba y lo decodificaba como ASCII. Ahora las partes en 7bit/8bit se usan tal cual, y las partes en base64/quoted-printable se decodifican con el charset declarado, después UTF-8, después cp1252 y por último latin-1. `test_email_encoding.py` añade 22 tests, de los que 16 fallan con el código anterior. |
| H-13 (nuevo, alta funcional) | **Resuelto** | `22b9f2e` | **Encontrado en la verificación de producción (14/10).** Síntoma: 35× GET `/api/history` → 35×401 y **0×429**; la auditoría registraba IPs internas de Render (`10.24…`, luego `10.30…`) que **cambiaban entre peticiones**, así que cada una tenía otra clave de rate limit. Diagnóstico (`b905cf9`, `9322c0f`): un solo proceso; `headers_present=['x-forwarded-for','true-client-ip','cf-connecting-ip']`, `xff_entry_count=3`, `branch=xff_entries_minus_hops`. Cadena real: cliente → **Cloudflare** → balanceador Render → app (peer loopback). Con `TRUSTED_PROXY_HOPS=1` se tomaba la última entrada de XFF = balanceador interno. En A/B/C3, `CF-Connecting-IP` tenía siempre la IP pública real; si el cliente la envía, Cloudflare bloquea (403/1000); `True-Client-IP` falsa la sobrescribe Cloudflare. Arreglo: `TRUST_CF_CONNECTING_IP` (default `false`); si `true` y la cabecera es una IP válida, se usa; si no, respaldo XFF/hops. Activar solo con Cloudflare delante. Tests en `test_rate_limit.py`. |

Diagnóstico original:

| ID | Severidad | Hallazgo | Ubicación | Corrección propuesta |
|----|-----------|----------|-----------|----------------------|
| H-01 | **Alta (privacidad)** | `GET /api/history` es público y sin autenticación, y devuelve `input` con el **texto íntegro** de cada email analizado (hasta 10 000 caracteres). Cualquiera puede leer los correos que otros han pegado, con nombres, direcciones o datos de terceros. | `history.py`, `models/analysis.py::to_dict` | Opciones: no devolver `input` en el listado (o truncarlo o enmascararlo), proteger el historial con un token de administración, o no guardar el cuerpo del email. Documenta finalidad y conservación en el apartado de datos personales. |
| H-02 | **Alta (funcional)** | El motor heurístico ignora las señales de email: con la cuota agotada o sin clave, **todo email sale LEGÍTIMO con score 10**. | `claude_analyzer.py::_fallback_response` | Añadir reglas para `suspicious_phrases`, `mismatched_reply_to`, `has_attachments` y `url_count`, aplicando las reglas de URL a `urls_found`. Cubrirlo con un test. |
| H-03 | Media | Se puede saltar el rate limit falsificando `X-Forwarded-For`, lo que permite agotar la cuota diaria de Claude para todos los usuarios. El log de auditoría también registra la IP falsificada. | `rate_limit.py::client_ip_key`, `audit_log.py::_client_ip` | Fiarse solo del proxy conocido: `uvicorn --proxy-headers --forwarded-allow-ips=<proxy>` y `get_remote_address`, o usar el último salto que añade Render. |
| H-04 | Media | La llamada a Claude (cliente síncrono `Anthropic`) y la consulta WHOIS se ejecutan dentro de endpoints `async`: **bloquean el event loop** y el resto de peticiones esperan. El comentario de `claude_analyzer.py:258` («FastAPI la ejecuta en su threadpool») no es cierto para `async def`. | `claude_analyzer.py:256-263`, `url_extractor.py::_get_domain_age_days` | Usar `AsyncAnthropic` o `await asyncio.to_thread(...)` en ambos casos. |
| H-05 | Media | Inyección de prompt: el contenido del email entra literal en el prompt (en `body_preview` y otros campos), sin delimitarlo ni usar un prompt de sistema. Un email malicioso puede pedir «responde LEGÍTIMO». | `claude_analyzer.py::_build_prompt` | Mover las instrucciones a `system`, marcar los datos como no confiables, y fijar un mínimo de score cuando haya señales fuertes (por ejemplo, detecciones en VirusTotal). Es un buen tema para la memoria y el vídeo. |
| H-06 | Media | En producción la base de datos está en `/tmp` y se pierden historial y cuotas (verificado: `total=0`). | `render.yaml`, `database.py` | Disco persistente de Render (de pago) o una base de datos gestionada gratuita. Si no, documenta la limitación y haz la demo en local con Docker. |
| H-07 | Baja | Los errores 500 incluyen el nombre de la clase de la excepción; `/docs` y `/openapi.json` son públicos en producción. | `analyze.py:176`, `analyze.py:240`, `main.py` | Mensaje genérico, y `docs_url=None` en producción mediante una variable de entorno. |
| H-08 | Baja | Con `ALLOWED_ORIGINS` sin definir, el código usa `["*"]` junto con `allow_credentials=True`. | `cors_config.py:34`, `main.py:50-56` | Usar `http://localhost:3000` como valor por defecto, o fallar al arrancar en producción. |
| H-09 | Baja | `frontend/Dockerfile` ignora `package-lock.json` (`COPY package.json` + `npm install`). | `frontend/Dockerfile:7-8` | `COPY package*.json ./` + `RUN npm ci`. |
| H-10 | Baja | Las URLs SOSPECHOSO se muestran como enlaces clicables. | `ResultCard.jsx:88-96` | Bloquearlas también, o añadir una confirmación antes de abrirlas. |
| H-11 | Informativa | El prompt fija «/72 motores» aunque `total_engines` está disponible. El modelo por defecto del código no coincide con el de `.env.example`. `datetime.utcnow()` está obsoleto. | `claude_analyzer.py:58` y `:27`, `analyze.py:82` | Limpieza menor. |

---

## 6. Tareas priorizadas para cerrar la entrega

Faltan unos 2 días (hoy es miércoles 14/10 y se entrega el viernes 16/10). El enunciado recomienda **congelar el código antes de grabar el vídeo**. Las estimaciones son orientativas.

### P0: bloquean la entrega o restan muchos puntos (hacer hoy)

| # | Tarea | Relación | Estimación |
|---|-------|----------|------------|
| 1 | Pedir o localizar la **calificación y el feedback de la P1** y revisar si cambia el estado de algún requisito. | Enunciado §3 y memoria §3 | 15 min |
| 2 | **Hecho (`0d1b429`).** Añadir **`LICENSE` (MIT)**. El repo es público y el README ya lo anuncia. | Apdo. 4 | 5 min |
| 3 | **Hecho (`76faa4e`).** **Corregir el motor heurístico para emails** (H-02 / RF-08). | Producto funcional | 45 min |
| 4 | **Hecho (`54365a5`; las salidas están en `*-despues.txt`).** **Actualizar dependencias:** `python-multipart==0.0.31` y `npm audit fix` sin `--force`. Volver a ejecutar ambas auditorías y guardar las salidas como `docs/evidencias/*-post.txt`. Documentar en la memoria el riesgo aceptado de `braces` / `tailwindcss@3`. | Apdo. 2, RNF-08 | 45 min (con prueba de build) |
| 5 | **Hecho (`796b8d6`, 101 tests).** **Pruebas automatizadas mínimas con pytest** en `backend/tests/`: `url_validator` (SSRF), `text_sanitizer`, `email_extractor`, `url_extractor` (sin red), el motor heurístico de URL y email, y los endpoints con `TestClient`, simulando Claude, VirusTotal y URLScan (200, 400 por SSRF, 413, 415, 422, 429 y filtros del historial). Añadir `pytest` y `httpx` como dependencias de desarrollo. | Apdo. 4, memoria §8 | 3-4 h |
| 6 | **Hecho (`0d1d385`: token y minimización).** **Decidir y aplicar una mitigación para H-01** (no exponer el texto de los emails en `/api/history`, o protegerlo) y documentar el tratamiento de datos personales. | Seguridad, D-06 | 1 h |
| 7 | **Hecho (`9f3cebd`).** **Completar el README:** sección de pruebas, uso básico, «credenciales de prueba: no aplica», arreglar los enlaces a `LICENSE` y `SECURITY.md`, y explicar el modo sin clave de Anthropic. | Apdo. 4 | 45 min |
| 8 | **Que otra persona instale el proyecto desde cero** en una máquina o VM limpia siguiendo solo el README, y anotar las incidencias. | Lista §14 | 1 h |

### P1: alto impacto en la nota (hoy o mañana por la mañana)

| # | Tarea | Relación | Estimación |
|---|-------|----------|------------|
| 9 | **Hecho (`e7fa375`).** Arreglar la confianza en `X-Forwarded-For` (H-03 / RNF-01) y poner rate limit a `/api/stats`. | RNF-01 | 45 min |
| 10 | **Hecho (`4907f96`).** Sacar la llamada a Claude y la consulta WHOIS del event loop (H-04). | RNF-04, rendimiento | 30 min |
| 11 | **Hecho (`f6b79c8`).** Mitigar la inyección de prompt (H-05) y añadir un caso de prueba con un email que intente manipular al modelo. | Seguridad | 1 h |
| 12 | **Parcial (`796b8d6` y `df134a9`: errores 500 genéricos y `/docs` desactivado; falta CORS).** Errores 500 genéricos y `/docs` desactivado en producción (H-07). Valor por defecto seguro de CORS (H-08). | RNF-09, RNF-12 | 30 min |
| 13 | Decidir la persistencia en producción (H-06): disco o BD gestionada, o documentar la limitación y hacer la demo en local. | RF-10, RNF-11 | 30 min – 2 h |
| 14 | Documento de seguridad versionado (`docs/seguridad.md` o `SECURITY.md` sin datos personales) con modelo STRIDE, secretos, entradas, dependencias y datos personales. Es la base del apartado 7 de la memoria. | Memoria §7 | 1,5 h |
| 15 | Justificar por escrito D-01 (Hetzner → Render/Cloudflare) y los elementos del roadmap (D-02 a D-09), y corregir D-10. | Memoria §3-4 | 45 min |
| 16 | **Matriz de trazabilidad:** RF/RNF → fichero → PR-xx → evidencia (figura o minuto del vídeo), partiendo del apartado 3. | Enunciado §8 | 1,5 h |

### P2: mejoras si queda tiempo (antes de congelar)

| # | Tarea | Relación | Estimación |
|---|-------|----------|------------|
| 17 | **Parcial (`0d1d385`: `URLSCAN_API_KEY` en `render.yaml`; `e62c678`: `npm ci`).** `frontend/Dockerfile` con `npm ci` y lockfile; cabeceras de seguridad en nginx; `healthcheck` en compose; `URLSCAN_API_KEY` en `render.yaml`. | RNF-10, RNF-02 | 45 min |
| 18 | GitHub Actions: `pytest`, `pip-audit`, `npm audit --omit=dev`, gitleaks y `npm run build` en cada push. Es una evidencia muy visible de calidad. | Seguridad y calidad | 45 min |
| 19 | Convertir `security_e2e.ps1` en pruebas que comprueben resultados y fallen si algo no cuadra (o pasarlo a pytest). | Pruebas | 30 min |
| 20 | **Parcial (`0d1d385`: `totalCount`).** Corregir menores: `totalCount` del historial, enlaces SOSPECHOSO (H-10), «/72 motores» y unificar el modelo por defecto (H-11), mostrar URLScan en la UI. | RF-06, RF-11, RF-14 | 45 min |
| 21 | Fijar las dependencias transitivas del backend (lock). | RNF-10 | 15 min |

### Cierre (jueves por la tarde y viernes)

| # | Tarea |
|---|-------|
| 22 | Congelar el código, ejecutar gitleaks una última vez sobre el historial y crear y subir el tag `v1.0-practica3`. |
| 23 | Grabar el vídeo (10 minutos como mínimo) sobre esa versión, indicando el requisito que se demuestra en cada momento. Incluir un fallo de servicio (sin clave de VirusTotal), entradas no válidas (SSRF, 413, 415, 429) y el modo heurístico. **No mostrar `.env`.** |
| 24 | Memoria `P3_GrupoXX_Memoria.pdf` (20-40 páginas, con los 13 apartados en orden y la declaración de uso de IA) y comprobación de los enlaces en una ventana de incógnito. |

---

## 7. Correcciones aplicadas

Todas en la rama `main`, en local: **no se ha hecho push ni se han creado tags**. Cada bloque es un commit. Los bloques 9 a 13 corresponden a la segunda tanda (prompt injection, `/docs`, `npm ci` y event loop).

### 7.1 Registro

| Bloque | Commit | Mensaje | Resuelve |
|--------|--------|---------|----------|
| 1 | `0d1b429` | docs: añadir LICENSE (MIT) y SECURITY.md | Hueco «Licencia», enlaces rotos del README y `SECURITY.md` ignorado por `.gitignore` |
| 2 | `54365a5` | fix(deps): corregir dependencias vulnerables y documentar riesgos aceptados | Apartado 2: pip-audit pasa a 0 vulnerabilidades y npm audit de 18 a 9 (2 moderadas en producción). Riesgos aceptados RA-01 y RA-02 (apartado 2.3) |
| 3 | `76faa4e` | feat: reglas heurísticas propias para emails y modo 'Análisis limitado (sin IA)' | H-02, RF-08 y RF-04 (ampliado); RNF-09 en parte (el motivo del modo sin IA es genérico) |
| 4 | `0d1d385` | feat(security): proteger /api/history con ADMIN_TOKEN y minimizar datos guardados | H-01, minimización de RF-10, `totalCount` de RF-11, `URLSCAN_API_KEY` en `render.yaml` (RF-06) y auditoría de accesos fallidos (RNF-06) |
| 5 | `e7fa375` | fix(security): corregir bypass del rate limit por X-Forwarded-For y hacer configurables los límites | H-03, RNF-01 (a y b), RNF-07 (b), cuota de IA configurable en tiempo de ejecución |
| 6 | `796b8d6` | test: suite pytest del backend con un test por requisito verificable | Hueco «Pruebas automatizadas», demostración de RF-09, 500 genéricos (RNF-09 / H-07) y TLD fuera de la Public Suffix List (RF-03) |
| 7 | `9f3cebd` | docs(readme): instalacion desde cero, variables, uso, tests y limitaciones | Hueco «README» (salvo la prueba por otra persona), H-06 documentado, RNF-10 y RNF-11 documentados |
| 8 | `9a573c5` | docs(auditoria): marcar lo resuelto y en que commit | Este apartado y las columnas de estado |
| 9 | `f6b79c8` | fix(security): mitigar la inyeccion de prompt en el analisis con IA | H-05; RF-07 pasa a validar con un esquema estricto |
| 10 | `df134a9` | fix(security): desactivar /docs, /redoc y /openapi.json con ENVIRONMENT=production | H-07 y RNF-09 |
| 11 | `e62c678` | build(frontend): usar npm ci con package-lock.json en el Dockerfile | H-09 y RNF-10 en parte |
| 12 | `4907f96` | perf: sacar del event loop las llamadas bloqueantes a la IA, WHOIS y DNS | H-04 y la nota de RNF-04 |
| 13 | `bdb09ea` | docs: evidencias de pytest y auditoria actualizadas | Este apartado, `pytest.txt` (129 passed) y la limitación del README |
| 14 | `3acfb6b` | fix(email): conservar tildes y enes del cuerpo con o sin charset declarado | H-12, encontrado en la prueba con la IA real |
| 15 | `ca07da2` | docs: H-12 en la auditoria y evidencias de pytest | Este registro y `pytest.txt` (en ese momento; ahora 157 passed) |
| 16 | `7f48582` | fix(rate-limit): contar tambien los 422 de analisis invalidos | Los 422 de `/api/analyze` ya cuentan para el límite |
| 17 | `b905cf9` | chore(diag): log temporal de cabeceras de proxy sin exponer IPs | Diagnóstico de `get_client_ip` en Render |
| 18 | `b4a8715` | fix(urlscan): no reenviar path/query y fijar visibility unlisted | Control de minimización de RF-06 |
| 19 | `7c56463` | docs: aclarar que render.yaml no aplica al servicio creado a mano | README, `render.yaml` y esta nota |
| 20 | `9322c0f` | chore(diag): volcar IPs de proxy solo en UA PhishGuard-Verify | TEMP proxy_diag_verify |
| 21 | `22b9f2e` | fix(security): preferir CF-Connecting-IP tras Cloudflare (H-13) | `TRUST_CF_CONNECTING_IP`, tests y este hallazgo |
| 22 | (este commit) | chore(diag): retirar logs temporales de proxy | Quita `proxy_diag` / `proxy_diag_verify` |

**Evidencias:**

- [`pip-audit-despues.txt`](evidencias/pip-audit-despues.txt)
- [`npm-audit-despues.txt`](evidencias/npm-audit-despues.txt)
- [`pytest.txt`](evidencias/pytest.txt): 157 passed

Los casos que se pidieron expresamente en los tests son estos:

| Caso | Test |
|------|------|
| Un email de phishing en modo sin IA no sale `LEGÍTIMO` | `test_analysis_email.py::test_rf08_email_de_phishing_en_modo_sin_ia_no_sale_legitimo` |
| El historial sin token da 401; con token da 200 y sin cuerpos de email | `test_history.py::test_historial_sin_token_valido_da_401_generico_y_se_audita`, `::test_historial_con_token_da_200_sin_cuerpos_de_email` |
| `X-Forwarded-For` falsos no evitan el bloqueo | `test_rate_limit.py::test_rnf01_xff_falso_no_evita_el_bloqueo_sin_proxy`, `::test_rnf01_xff_falso_no_evita_el_bloqueo_detras_de_render` |
| `CF-Connecting-IP` con `TRUST_CF_CONNECTING_IP` (H-13) | `test_rate_limit.py::test_get_client_ip_cf_connecting_ip_gana_sobre_xff_falso`, `::test_get_client_ip_sin_trust_cf_ignora_cf_connecting_ip`, `::test_get_client_ip_cf_invalida_usa_respaldo_xff` |
| Entradas no válidas | `test_security.py::test_rnf04_*` |
| Anti-SSRF frente a URLs internas o privadas | `test_security.py::test_rnf03_*` |
| Cabeceras OWASP | `test_security.py::test_rnf02_*` |
| Caídas de VirusTotal, URLScan y Anthropic | `test_external_failures.py` |
| Inyección de prompt: «ignora las instrucciones anteriores…», JSON falso y cierre de etiqueta dentro del cuerpo | `test_prompt_injection.py` |
| Emails sin `Content-Type` con tildes y eñes: el cuerpo llega intacto y se siguen detectando las frases con tilde | `test_email_encoding.py` |
| Respuesta de la IA fuera de esquema, tratada como fallo | `test_prompt_injection.py::test_respuesta_fuera_de_esquema_es_fallo_de_la_ia` (17 variantes) |
| `/docs`, `/redoc` y `/openapi.json` desactivados en producción | `test_platform.py::test_docs_desactivados_en_produccion` |
| Claude y WHOIS no bloquean el event loop | `test_event_loop.py` |

Las APIs externas, WHOIS y DNS se simulan solo en `backend/tests/conftest.py`, y el propio fichero lo indica. Todas las URLs de los tests son ficticias (`example.com`, `.test`).

### 7.2 Qué sigue abierto

| Punto | Por qué sigue abierto | Siguiente paso |
|-------|-----------------------|----------------|
| RA-01 Tailwind 3 / `braces` (5 altas en build) | Corregirlo exige migrar a Tailwind 4 (cambio de versión mayor) | Aceptado y documentado (apartado 2.3) |
| RA-02 `react-router-dom@6` (2 moderadas en producción) | Corregirlo exige `react-router-dom@7`, que pide `--force`, y no es explotable en esta aplicación | Aceptado y documentado (apartado 2.3) |
| RF-10, RNF-07 (a), RNF-11 y H-06: persistencia en Render | Plan gratuito con `/tmp` efímero | Documentado en el README. Hacer la demo en local o contratar un disco persistente |
| RNF-10: sin healthchecks ni lock de dependencias del backend | No se pidió | `healthcheck` en Compose y `pip-tools` o `pip freeze` |
| Instalación desde cero por otra persona | Requiere a otra persona y una máquina limpia | Tarea P0 nº 8 |
| H-08 (CORS `*`), H-10 (enlaces SOSPECHOSO), H-11 (menores) | Fuera del alcance | Tareas P1 y P2 del apartado 6 |
| H-05 residual | Las heurísticas son el suelo, pero no lo cubren todo: un email que engañe a la IA sin señales heurísticas puede salir `SOSPECHOSO` o `LEGÍTIMO` | Mostrarlo en el vídeo como límite conocido; revisión humana |
| Hilos de WHOIS | Un 504 no cancela el hilo, y el código no fija un timeout para la consulta WHOIS | Aceptado: un único worker y un rate limit de 10/min por IP acotan el número de hilos. Si hace falta, se puede añadir un timeout a la consulta. |
| Tag `v1.0-practica3` y push | Se pidió expresamente no hacerlos | Tarea 22, sobre el commit final |
| Configuración de Render | El backend **no** se creó desde `render.yaml` (mandan defaults del código salvo lo añadido a mano). Tras H-13: en el panel hace falta `ADMIN_TOKEN`, `ENVIRONMENT=production` y **`TRUST_CF_CONNECTING_IP=true`** (Cloudflare delante). `TRUSTED_PROXY_HOPS` queda como respaldo. | Activar `TRUST_CF_CONNECTING_IP=true` en el panel tras desplegar el arreglo |
| `.env` local | Hay que añadir `ADMIN_TOKEN` a mano. Estas correcciones no lo han modificado. | Generar el token como indica el README |
