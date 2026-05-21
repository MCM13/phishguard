# Política y medidas de seguridad de PhishGuard

Este documento resume las medidas de seguridad implementadas en
PhishGuard, los riesgos conocidos y mitigados, y el procedimiento para
reportar vulnerabilidades de forma responsable.

PhishGuard es una herramienta de ciberseguridad: aplicamos defensa en
profundidad y tratamos cada superficie de ataque (red, datos, código,
contenedor, dependencias) de forma explícita.

---

## 1. Medidas de seguridad implementadas

### 1.1. Red y transporte

| Medida | Implementación | Fichero |
|--------|----------------|---------|
| **CORS controlado por entorno** | Lista CSV en `ALLOWED_ORIGINS`. `*` sólo en desarrollo. | `backend/app/main.py` |
| **HSTS sobre HTTPS** | `Strict-Transport-Security: max-age=31536000; includeSubDomains` cuando la petición es HTTPS (también detecta proxies vía `X-Forwarded-Proto`). | `backend/app/middleware/security_headers.py` |
| **Cabeceras OWASP Secure Headers** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), microphone=(), camera=()`, `Content-Security-Policy: default-src 'self'`. | `backend/app/middleware/security_headers.py` |
| **Rate limiting por IP** | `slowapi` con `key_func` que respeta `X-Forwarded-For`. 10/min en endpoints `analyze`, 30/min en `history`. Respuesta 429 con `Retry-After: 60`. | `backend/app/services/rate_limit.py`, `backend/app/main.py` |
| **Body máximo 1 MB** | `MaxBodySizeMiddleware`: rechaza por `Content-Length` y como cinturón de seguridad por acumulación real de chunks. | `backend/app/middleware/request_guards.py` |
| **Timeout 30 s por petición** | `RequestTimeoutMiddleware` con `asyncio.wait_for`. Devuelve 504. | `backend/app/middleware/request_guards.py` |
| **Content-Type estricto** | `JSONContentTypeMiddleware` exige `application/json` en POST/PUT/PATCH con body. Devuelve 415. | `backend/app/middleware/request_guards.py` |

### 1.2. Validación y sanitización

| Medida | Detalle | Fichero |
|--------|---------|---------|
| **Validación Pydantic** | `min_length` / `max_length` en `url` (3-2048) y `content` (10-50.000). | `backend/app/routers/analyze.py` |
| **Validación de URL** | Sólo `http(s)`. Hostname obligatorio. | `backend/app/services/url_validator.py` |
| **Anti-SSRF** | Rechazo de IPs literales privadas, loopback, link-local, multicast, reservadas. Rechazo de `localhost`, `0.0.0.0`, `::1`, `169.254.169.254` (metadata cloud). Resolución DNS + comprobación de cada IP devuelta. | `backend/app/services/url_validator.py` |
| **Stripping HTML/JS/CSS** | Eliminación de `<script>`, `<style>`, `<iframe>`, `<object>`, `<embed>`, `<svg>` con su contenido + cualquier otra etiqueta. Decodificación de entidades HTML. | `backend/app/services/text_sanitizer.py` |
| **Normalización Unicode + control chars** | NFC + eliminación de `\x00-\x1F` (excepto `\t\n\r`). Aplicado antes de persistir. | `backend/app/services/text_sanitizer.py` |
| **Truncado defensivo** | `input_data` ≤ 10.000, `url` ≤ 2.048, `ai_explanation` ≤ 5.000. | `backend/app/routers/analyze.py` |

### 1.3. Gestión de secretos

| Medida | Detalle |
|--------|---------|
| **Sin secretos en código** | `ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY` viven sólo en `.env`. Verificado con `git ls-tree -r main \| grep .env` → sólo aparece `.env.example`. |
| **`.env` en `.gitignore`** | Patrón `.env` cubre todas las variantes excepto `.env.example` y `.env.production` (URL pública, no secreta). |
| **`.dockerignore`** | Excluye `.env` también de la imagen Docker para que no se filtre por copia accidental. |
| **Sin secretos en logs** | El middleware de auditoría jamás imprime headers de autorización ni el body de la petición. |

### 1.4. Auditoría y trazabilidad

| Medida | Detalle | Fichero |
|--------|---------|---------|
| **Log JSON por petición** | `ts_utc`, `ip`, `method`, `path`, `status`, `latency_ms`, `verdict` (opcional), `rate_limited` (opcional), `ua` truncado. Canal `phishguard.audit` separado del root logger. | `backend/app/middleware/audit_log.py` |
| **NO se loguea body** | El contenido de URL y email es PII potencial (víctima) → sólo metadatos. |
| **Stack traces sólo en servidor** | `logger.exception` registra la traza; al cliente sólo le llega la clase de excepción. | `backend/app/routers/*.py` |

### 1.5. Resiliencia y cuotas

| Medida | Detalle |
|--------|---------|
| **Cuota de Anthropic** | `ANTHROPIC_MAX_PER_HOUR` y `ANTHROPIC_MAX_PER_DAY` (defaults 15/50). Contadores persistidos en SQLite. Cuando se agota, no se llama a la API y se devuelve veredicto heurístico local. Evita facturas inesperadas si la app es atacada. |
| **Fallback heurístico** | Si VirusTotal, URLScan o Claude fallan, el análisis continúa con reglas locales. No se filtran detalles del fallo al cliente. |
| **Timeouts en APIs externas** | 15 s en VirusTotal y URLScan; timeout por defecto en `python-whois`. |

### 1.6. Contenedor

| Medida | Detalle |
|--------|---------|
| **Usuario no-root** | `appuser` UID 10001. El proceso `uvicorn` no corre como `root`. | `backend/Dockerfile` |
| **Imagen base slim** | `python:3.11-slim` y `nginx:1.27-alpine` minimizan paquetes y CVEs. |
| **Sin shell exec por defecto** | `CMD` en formato exec; no se levanta `/bin/sh`. |
| **Volumen de datos** | `/data` propiedad de `appuser`; SQLite no necesita más permisos. |

### 1.7. Frontend

| Medida | Detalle |
|--------|---------|
| **Sin `dangerouslySetInnerHTML`** | Verificado con grep en `frontend/src/**`. React escapa todos los strings interpolados como texto plano. |
| **Enlaces externos seguros** | `rel="noopener noreferrer nofollow"` + `target="_blank"`. |
| **URLs PHISHING no-clicables** | Cuando el veredicto es PHISHING, la URL se renderiza como `<span>` con borde rojo y aviso `[bloqueado]`, jamás como `<a href>`. | `frontend/src/components/ResultCard.jsx` |
| **Mensajes de error genéricos** | Helper `friendlyError()` mapea respuestas HTTP a mensajes en español sin trazas. `console.error` sólo en `import.meta.env.DEV`. | `frontend/src/api.js` |

---

## 2. Vulnerabilidades conocidas y mitigadas

| Riesgo / OWASP | Mitigación |
|----------------|------------|
| **A01 — Broken Access Control** | Endpoints públicos por diseño; rate-limit por IP, sin sesiones ni datos personales en BD. |
| **A02 — Cryptographic Failures** | Sin almacenamiento de datos sensibles. TLS en producción vía Render/Cloudflare (HSTS activo). |
| **A03 — Injection (XSS, SQLi)** | SQLAlchemy ORM con parámetros (no concatenación SQL). React escapa outputs. CSP estricto en backend. |
| **A04 — Insecure Design** | Defensa en profundidad: fallbacks heurísticos, cuotas IA, validaciones múltiples. |
| **A05 — Security Misconfiguration** | Cabeceras OWASP, CORS configurable, modo no-root, base imágenes slim. |
| **A06 — Vulnerable Components** | Versiones fijadas en `requirements.txt` y `package.json`. Recomendado escanear con `pip-audit` y `npm audit` periódicamente. |
| **A07 — Identification & Authentication Failures** | No aplicable: PhishGuard no tiene autenticación de usuarios. |
| **A08 — Software & Data Integrity Failures** | Imágenes Docker reproducibles. No se ejecuta código descargado en runtime. |
| **A09 — Logging Failures** | Logs JSON estructurados con timestamp UTC. Bodies NO loggeados. |
| **A10 — Server-Side Request Forgery** | `validate_public_url` rechaza IPs privadas y resuelve DNS antes de cualquier llamada externa. |
| **Prompt Injection (LLM)** | Sanitización HTML antes de mandar contenido a Claude. El prompt fija formato JSON estricto. Si la IA se desvía, `_normalize_response` rescata o cae a heurística. |
| **Coste-DoS contra Anthropic** | `ANTHROPIC_MAX_PER_HOUR/DAY` impide vaciar créditos. |
| **Clickjacking** | `X-Frame-Options: DENY` + CSP `default-src 'self'`. |
| **Open-redirect a URL maliciosa desde la propia app** | URLs PHISHING no se renderizan como enlace clicable. |
| **Resource exhaustion** | Body ≤ 1 MB, timeout 30 s, rate limit, truncado de strings en BD. |

---

## 3. Cómo reportar una vulnerabilidad (responsible disclosure)

Si descubres una vulnerabilidad de seguridad en PhishGuard, **no abras
un issue público**. Sigue este procedimiento de divulgación
responsable:

1. **Reporta por canal privado** — Envía un email a la persona
   mantenedora del repositorio
   [`@MCM13`](https://github.com/MCM13) en GitHub con el asunto
   `[SECURITY] PhishGuard – breve descripción`. Si el repositorio
   ofrece la pestaña **Security Advisories** de GitHub, prefiere ese
   canal: permite coordinar el parche en privado.

2. **Incluye en el reporte:**
   - Versión / commit afectado.
   - Pasos detallados para reproducir.
   - Impacto estimado (qué puede hacer un atacante).
   - Si tienes una prueba de concepto, adjúntala.

3. **Tiempos esperados:**
   - **48 horas** para confirmación de recepción.
   - **7 días** para una evaluación inicial.
   - **30 días** objetivo de parche para vulnerabilidades de severidad alta.

4. **Embargo:** te pedimos no publicar el detalle de la vulnerabilidad
   hasta que se haya publicado el parche o hayan pasado 90 días desde
   el reporte (lo que ocurra antes), siguiendo la práctica estándar de
   coordinación responsable.

5. **Reconocimiento:** salvo que prefieras anonimato, mencionamos a
   los descubridores en la nota de release del parche.

---

## 4. Aspectos fuera del alcance

Las siguientes cuestiones se consideran limitaciones conocidas, no
vulnerabilidades a parchear, dado el caso de uso de PhishGuard:

- **No hay autenticación**: PhishGuard es un servicio público de
  análisis. Si se despliega en una organización con datos sensibles,
  debe protegerse con un proxy autenticado externo (Cloudflare Access,
  oauth2-proxy, Nginx basic-auth) y se debe restringir
  `ALLOWED_ORIGINS`.
- **Las URLs/emails se almacenan en SQLite sin cifrar**: cualquier
  persona con acceso al volumen `phishguard-data` puede leerlas. Si tu
  caso de uso lo exige, cifra el volumen a nivel de filesystem.
- **Las APIs de Claude/VirusTotal/URLScan reciben las URLs y emails
  enviados**: revisa las políticas de privacidad de cada proveedor.
- **El backend no escanea URLs activamente**: nunca abre ni descarga
  el contenido apuntado por la URL del usuario. Sólo extrae features
  textuales y consulta APIs de terceros. Esto reduce drásticamente la
  superficie SSRF, pero también significa que algunos indicadores
  basados en contenido renderizado (capturas, DOM) quedan fuera.

---

*Última actualización: aplicación del Plan de seguridad PhishGuard.*
