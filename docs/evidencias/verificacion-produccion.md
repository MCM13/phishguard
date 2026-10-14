# Verificación en producción — PhishGuard

- **Fecha:** 14/10/2026
- **Backend:** https://phishguard-backend-qszu.onrender.com
- **Frontend:** https://phishguard.cmmario.com  
  (el apex `cmmario.com` no tiene registro A; la app vive en el subdominio)
- **Commit desplegado al cierre:** `5f3feab` (+ `TRUST_CF_CONNECTING_IP=true` en el panel de Render)
- **IP pública del verificador:** `91.117.233.113`

No se escribe ningún secreto (`ADMIN_TOKEN`, claves de API) en este fichero.

---

## 1. Documentación de la API desactivada

Con `ENVIRONMENT=production`:

| Ruta | Código |
|------|--------|
| `GET /docs` | **404** |
| `GET /redoc` | **404** |
| `GET /openapi.json` | **404** |
| `GET /` (salud) | **200** |

---

## 2. Historial y `ADMIN_TOKEN`

| Caso | Código | Notas |
|------|--------|-------|
| `GET /api/history` sin token | **401** | |
| Con token falso | **401** | |
| Con token correcto | **200** | `items` con `id`, `type`, `score`, `verdict`, `analysis_mode`, `domain`, `fingerprint`, `timestamp`. **Sin** cuerpos de email ni campos `input` / `body_preview` / `ai_explanation`. |

---

## 3. Cabeceras de seguridad

Presentes en las respuestas del backend (entre otras):

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- `Content-Security-Policy: default-src 'self'`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

---

## 4. Análisis con IA (antes del cierre de H-13)

Sin gastar cuota adicional en la verificación final; resultados de la pasada previa con Claude real:

| Entrada | Veredicto | Score | `analysis_mode` |
|---------|-----------|-------|-----------------|
| `https://example.com` | LEGÍTIMO | 2 | `ai` |
| Email inventado en español con tildes («contraseña», «número», «días», «cerámica», «perderás») | PHISHING | 78 | `ai` |

En la respuesta del email los acentos llegaron **intactos** (tras el arreglo H-12 de codificación del extractor). No apareció «Análisis limitado (sin IA)».

---

## 5. Hallazgo H-13: IP del cliente y rate limit

### Síntoma (antes del arreglo)

- 35× `GET /api/history` sin token → **35×401, 0×429** (límite documentado: 30/min).
- 12× `POST /api/analyze/url` con `{}` → **12×422, 0×429** (límite: 10/min), tras corregir que los 422 cuenten (`7f48582`).
- La auditoría registraba IPs internas de Render (`10.24.135.5`, luego `10.30.224.5`) que **cambiaban entre peticiones**, así que cada una usaba otra clave de rate limit.

### Diagnóstico

- Un solo proceso (una línea `proxy_diag startup`).
- Cadena real: cliente → **Cloudflare** → balanceador de Render → app (peer loopback).
- Con `TRUSTED_PROXY_HOPS=1`, `get_client_ip` tomaba `X-Forwarded-For[-1]` = IP del balanceador interno.
- Pruebas marcadas (`PhishGuard-Verify-A/B/C3`): `CF-Connecting-IP` contenía siempre la IP pública real; si el cliente envía esa cabecera, Cloudflare bloquea (403/1000); `True-Client-IP` falsa la sobrescribe Cloudflare.

### Arreglo

- Commits: `22b9f2e` (`TRUST_CF_CONNECTING_IP`), `5f3feab` (retirada de logs temporales).
- En producción: `TRUST_CF_CONNECTING_IP=true` en el panel (el servicio no se creó desde `render.yaml`).

Detalle completo en `docs/auditoria-p3.md` (H-13).

---

## 6. Verificación final de H-13 (tras el despliegue)

**UA:** `PhishGuard-Verify-Final/1.0`  
**UTC aproximado:** 2026-10-14T16:20:52Z – 16:21:04Z

### Rate limit

| Prueba | Resultado | Esperado |
|--------|-----------|----------|
| 35× `GET /api/history` sin token | **30×401 + 5×429** (429 desde la 31) | ✓ |
| 12× `POST /api/analyze/url` body `{}` | **10×422 + 2×429** (429 desde la 11) | ✓ |
| `GET /` con `X-Forwarded-For: 203.0.113.99` | **200** | ✓ |

### IP en el log de auditoría / slowapi

Todas las líneas relevantes muestran **`ip": "91.117.233.113"`** (IP pública real), no `203.0.113.99` ni `10.x`:

```text
{"ts_utc": "2026-10-14T16:20:52.021371+00:00", "ip": "91.117.233.113", "method": "GET", "path": "/api/history", "status": 401, ..., "ua": "PhishGuard-Verify-Final/1.0"}
... ratelimit 30 per 1 minute (91.117.233.113) exceeded at endpoint: /api/history
{"ts_utc": "...", "ip": "91.117.233.113", "method": "GET", "path": "/api/history", "status": 429, "rate_limited": true, "ua": "PhishGuard-Verify-Final/1.0"}
... ratelimit 10 per 1 minute (91.117.233.113) exceeded at endpoint: /api/analyze/url
{"ts_utc": "2026-10-14T16:21:04.605413+00:00", "ip": "91.117.233.113", "method": "GET", "path": "/", "status": 200, "ua": "PhishGuard-Verify-Final/1.0"}
```

La última línea es la petición con `X-Forwarded-For` falsa: la IP auditada sigue siendo la real.

---

## 7. Frontend

| URL | Resultado |
|-----|-----------|
| https://phishguard.cmmario.com | **200**, título PhishGuard |
| https://cmmario.com (apex) | No resuelve (sin registro A/AAAA) |

---

## Conclusión

| Control | Estado |
|---------|--------|
| Docs desactivados en producción | OK |
| Historial protegido y sin cuerpos | OK |
| Cabeceras de seguridad | OK |
| Análisis con IA + tildes (H-12) | OK |
| Rate limit por IP real tras Cloudflare (H-13) | OK |
| XFF falsa no sustituye la IP | OK |

Pendiente operativo (fuera de este fichero): persistencia en `/tmp` (H-06), y variables opcionales `RATE_LIMIT_*` / `ANTHROPIC_MAX_*` solo si se quieren distintos de los defaults del código.
