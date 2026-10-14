# Pruebas — PhishGuard (Práctica 3)

- **Fuentes:** `docs/evidencias/pytest.txt`, prueba con IA real del 14/10, `docs/evidencias/verificacion-produccion.md`, `docs/auditoria-p3.md`.
- **Convención de estado:** OK / FALLIDO / PENDIENTE.
- **No se inventan resultados:** lo no comprobado queda PENDIENTE.

---

## A. Pruebas automatizadas (pytest)

**Evidencia:** [`evidencias/pytest.txt`](evidencias/pytest.txt) — **151 passed**, 1 warning (14/10/2026).  
**Nota:** tras H-13 la suite local recoge **157** tests (`pytest --collect-only`). Actualizar `pytest.txt` queda **PENDIENTE** (código congelado para documentación).

| ID | Requisito | Pasos | Resultado esperado | Resultado obtenido | Estado |
|----|-----------|-------|--------------------|--------------------|--------|
| PR-01 | RF-01, RF-03, RF-05, RF-06 | `pytest tests/test_analysis_url.py` (6 tests): URL válida, features, VT/URLScan simulados | Todos PASSED | 6 PASSED en `pytest.txt` | OK |
| PR-02 | RF-02, RF-04, RF-08 | `pytest tests/test_analysis_email.py` (10): email phishing/benigno, modo sin IA no LEGÍTIMO | Todos PASSED; phishing sin IA → PHISHING | 10 PASSED | OK |
| PR-03 | RF-04, H-12 | `pytest tests/test_email_encoding.py` (22): tildes/ñ sin charset, multipart, base64 | Cuerpo intacto; frases con tilde detectadas | 22 PASSED | OK |
| PR-04 | RF-07, RF-08, RNF-07 | `pytest tests/test_ai_and_quota.py` (5): modo AI/fallback y cuotas | PASSED | 5 PASSED | OK |
| PR-05 | RF-07, H-05 | `pytest tests/test_prompt_injection.py` (25): inyección, esquema estricto, suelo heurístico | PASSED; fuera de esquema → fallo IA | 25 PASSED | OK |
| PR-06 | RF-09 | `pytest tests/test_external_failures.py` (11): VT/URLScan/Anthropic/WHOIS caídos | HTTP 200 sin filtrar detalles | 11 PASSED | OK |
| PR-07 | RF-10, RF-11, RF-12, H-01 | `pytest tests/test_history.py` (9): 401 sin token, 200 con token sin cuerpos, stats | PASSED | 9 PASSED | OK |
| PR-08 | RNF-01, H-03, H-13 | `pytest tests/test_rate_limit.py` (9 en evidencia; +3 CF tras H-13): 429, XFF, CF-Connecting-IP | PASSED | 9 PASSED en `pytest.txt`; tests CF **PENDIENTE** de figurar en la evidencia regenerada | OK / PENDIENTE evidencia |
| PR-09 | RNF-02, RNF-03, RNF-04, RNF-09 | `pytest tests/test_security.py` (45): cabeceras, SSRF, validación, 500 genérico | PASSED | 45 PASSED | OK |
| PR-10 | RF-15, RNF-05, RNF-06, RNF-09, RNF-12 | `pytest tests/test_platform.py` (7): OpenAPI en dev, no-root, auditoría, docs off en prod | PASSED | 7 PASSED | OK |
| PR-11 | RNF-04, H-04 | `pytest tests/test_event_loop.py` (2): Claude/WHOIS no bloquean el loop | PASSED | 2 PASSED | OK |

---

## B. Prueba con IA real (14/10/2026)

Backend local/temporal con `.env` real; datos inventados; APIs externas reales (Claude). Log: 0 líneas «fuera de esquema».

| ID | Requisito | Pasos | Resultado esperado | Resultado obtenido | Estado |
|----|-----------|-------|--------------------|--------------------|--------|
| PR-20 | RF-01, RF-07 | Analizar `https://example.com` | Veredicto con `analysis_mode=ai` | **LEGÍTIMO**, score **2**, modo `ai` | OK |
| PR-21 | RF-01, RF-07 | Analizar `https://cmmario.com` | Veredicto con IA | **LEGÍTIMO**, score **20**, modo `ai` | OK |
| PR-22 | RF-01, RF-07 | Analizar URL inventada tipo phishing (`paypa1` + `.test`) | Riesgo alto / PHISHING | **PHISHING**, score **92**, modo `ai` | OK |
| PR-23 | RF-02, RF-07 | Email legítimo inventado | LEGÍTIMO o bajo riesgo con IA | **LEGÍTIMO**, score **12**, modo `ai` | OK |
| PR-24 | RF-02, RF-07, RF-08 | Email de phishing inventado | PHISHING | **PHISHING**, score **92**, modo `ai` | OK |
| PR-25 | RF-07, H-05 | Email con intento de inyección de prompt | No rebajar a LEGÍTIMO por la inyección; preferible PHISHING | **PHISHING**, score **95**, modo `ai`; sin discrepancia forzada en log | OK |

---

## C. Verificaciones en producción

**Fuente:** [`evidencias/verificacion-produccion.md`](evidencias/verificacion-produccion.md).  
Backend: `phishguard-backend-qszu.onrender.com`. Frontend: `phishguard.cmmario.com`.

| ID | Requisito | Pasos | Resultado esperado | Resultado obtenido | Estado |
|----|-----------|-------|--------------------|--------------------|--------|
| PR-30 | RNF-09, RF-15 | `GET /docs`, `/redoc`, `/openapi.json` | 404 | **404** los tres | OK |
| PR-31 | RF-11, H-01 | Historial sin token / token falso / token correcto | 401 / 401 / 200 sin cuerpos | **401 / 401 / 200** sin `input` ni cuerpos | OK |
| PR-32 | RNF-02 | Inspeccionar cabeceras de respuesta | CSP, XFO, nosniff, Referrer-Policy, Permissions-Policy, HSTS | Presentes (lista en verificación) | OK |
| PR-33 | RF-01, RF-07 | `POST /api/analyze/url` `https://example.com` | IA, no «Análisis limitado» | **LEGÍTIMO** score **2**, `analysis_mode=ai` | OK |
| PR-34 | RF-02, RF-07, H-12 | Email inventado con tildes | IA; acentos intactos | **PHISHING** score **78**, `ai`; tildes presentes en la respuesta | OK |
| PR-35 | RNF-01, H-13 | 35× `GET /api/history` sin token (UA `PhishGuard-Verify-Final/1.0`) | 30×401 + 5×429 | **30×401 + 5×429** | OK |
| PR-36 | RNF-01, H-13 | 12× `POST /api/analyze/url` body `{}` | 10×422 + 2×429 | **10×422 + 2×429** | OK |
| PR-37 | RNF-01, H-13 | `GET /` con `X-Forwarded-For: 203.0.113.99` | 200; IP auditada = pública real | **200**; log `ip=91.117.233.113` (no 203.0.113.99) | OK |
| PR-38 | RNF-11 | Abrir `https://phishguard.cmmario.com` | 200, UI PhishGuard | **200** | OK |

---

## D. Hallazgos corregidos (antes → después)

| ID | Requisito / hallazgo | Pasos | Resultado esperado | Resultado obtenido | Estado |
|----|----------------------|-------|--------------------|--------------------|--------|
| PR-40 | RF-08 / **H-02** fallback emails | Analizar email phishing **sin** clave/cuota IA | Antes: LEGÍTIMO score bajo. Después: PHISHING o NO CONCLUYENTE, nunca LEGÍTIMO engañoso; UI «Análisis limitado» | Antes: todo email LEGÍTIMO 10 (auditoría). Después: test `test_rf08_email_de_phishing_en_modo_sin_ia_no_sale_legitimo` PASSED; phishing → PHISHING 100 | OK |
| PR-41 | RF-11 / **H-01** historial público | `GET /api/history` sin auth | Antes: 200 con texto íntegro. Después: 401; con token 200 sin cuerpos | Antes: público (auditoría). Después: PR-07 y PR-31 | OK |
| PR-42 | RNF-01 / **H-03** bypass XFF | Martillo con XFF falsas distintas | Antes: cada XFF = otra clave. Después: misma IP / 429 | Tests `test_rnf01_xff_falso_*` PASSED; en producción cerrado con H-13 (PR-35–37) | OK |
| PR-43 | RF-07 / **H-05** inyección de prompt | Email «ignora instrucciones…» + JSON falso | Antes: riesgo de LEGÍTIMO. Después: delimitación + esquema + suelo heurístico | Tests PR-05 PASSED; IA real PR-25 → PHISHING 95 | OK |
| PR-44 | RNF-09 / **H-07** `/docs` en producción | `GET /docs` en Render | Antes: 200 docs. Después: 404 | PR-30 → **404** | OK |
| PR-45 | RNF-01 / **422 sin contar** | 12× POST analyze inválido | Antes: solo 422, sin 429. Después: 10×422 + 2×429 | Antes: 12×422 0×429 (diagnóstico). Después: PR-36 | OK |
| PR-46 | RF-04 / **H-12** codificación | Email sin Content-Type con «cerámica», «contraseña» | Antes: mojibake / frases no detectadas. Después: texto intacto | Antes: fallo en prueba IA real. Después: `test_email_encoding` 22 PASSED; PR-34 tildes OK | OK |
| PR-47 | RNF-01 / **H-13** IP tras Cloudflare | Ver logs + martillo producción | Antes: IP `10.x` variable, 0×429. Después: IP pública estable + 429 | Antes: 10.24… / 10.30…, 0×429. Después: PR-35–37, `ip=91.117.233.113` | OK |

---

## E. Pruebas manuales para el vídeo (PENDIENTE)

Las ejecutará el autor en la grabación. Resultado obtenido: **PENDIENTE**.

| ID | Requisito | Pasos | Resultado esperado | Resultado obtenido | Estado |
|----|-----------|-------|--------------------|--------------------|--------|
| PR-50 | RF-01, RF-13, RF-14 | En la UI, analizar URL legítima y una sospechosa inventada; mostrar medidor y bloqueo de enlace PHISHING | Score + colores; PHISHING no clicable | PENDIENTE | PENDIENTE |
| PR-51 | RF-02, RF-04 | Pegar email completo con cabeceras inventadas | Indicadores de remitente / Reply-To / frases | PENDIENTE | PENDIENTE |
| PR-52 | RF-08 | Forzar modo sin IA (quitar clave o agotar cuota) y analizar | «Análisis limitado (sin IA)»; no LEGÍTIMO engañoso | PENDIENTE | PENDIENTE |
| PR-53 | RF-11, H-01 | Historial sin token → error; con token → listado sin cuerpos | 401 / 200 limpio | PENDIENTE (UI); API ya OK en PR-31 | PENDIENTE |
| PR-54 | RF-12 | Abrir Dashboard | Totales y cuota visibles | PENDIENTE | PENDIENTE |
| PR-55 | RNF-03 | Intentar URL `http://127.0.0.1/` o metadata | 400 anti-SSRF | PENDIENTE (demo vídeo); tests PR-09 OK | PENDIENTE |
| PR-56 | RNF-01, H-13 | Mostrar 429 en producción y log con IP real pese a XFF falsa | 429; IP pública en log | API OK (PR-35–37); captura en vídeo PENDIENTE | PENDIENTE |
| PR-57 | RF-07, H-05 | Pegar email de inyección en la UI | PHISHING / no LEGÍTIMO por la inyección | PENDIENTE (UI); API real PR-25 OK | PENDIENTE |
| PR-58 | RNF-05 | `docker exec … id` → uid 10001 | appuser no root | PENDIENTE | PENDIENTE |
| PR-59 | RNF-10 | Instalación desde cero por otra persona | Arranque según README | PENDIENTE | PENDIENTE |
| PR-60 | D-01 / RNF-11 | Mostrar URLs públicas HTTPS | Frontend + backend accesibles | Parcialmente OK (PR-38); narración Hetzner PENDIENTE | PENDIENTE |
