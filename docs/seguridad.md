# Seguridad — PhishGuard (Práctica 3)

Documento de seguridad para la memoria. Fuentes: código, `SECURITY.md`, `docs/auditoria-p3.md`, `docs/evidencias/`.  
Lo no comprobado se marca **PENDIENTE**.

---

## 1. Modelo de amenazas (STRIDE)

### 1.1 Activos

| Activo | Por qué importa |
|--------|-----------------|
| Claves API (Anthropic, VirusTotal, URLScan) | Coste y abuso de cuota |
| `ADMIN_TOKEN` | Acceso al historial |
| Contenido analizado (URLs/emails pegados) | Puede incluir datos personales de terceros |
| Veredicto y explicación | Integridad del resultado que ve el usuario |
| Base de datos SQLite | Historial y contadores de cuota |
| Disponibilidad del backend | Demo y uso académico |
| Reputación del dominio / despliegue | Phishing reverse o abuso del servicio |

### 1.2 Atacantes (supuestos)

- Usuario anónimo en Internet contra el despliegue público.
- Usuario que pega contenido malicioso (inyección de prompt, SSRF vía URL).
- Cliente que falsifica cabeceras (`X-Forwarded-For`, etc.).
- Quién obtenga el repositorio o un `.env` filtrado.

### 1.3 Amenazas por categoría STRIDE y control

| STRIDE | Amenaza | Control que mitiga |
|--------|---------|-------------------|
| **S**poofing | Suplantar al administrador del historial | `ADMIN_TOKEN` Bearer + comparación en tiempo constante (`admin_auth.py`); 401 genérico |
| **S**poofing | Falsificar IP para evadir rate limit | `TRUST_CF_CONNECTING_IP` + Cloudflare (`client_ip.py`); hops XFF solo como respaldo |
| **T**ampering | Manipular el veredicto vía prompt injection | Delimitación `<contenido_analizado>`, esquema JSON estricto, suelo heurístico (`claude_analyzer.py`) |
| **T**ampering | Alterar dependencias / supply chain | Versiones fijadas; `pip-audit` / `npm audit`; `npm ci` en Dockerfile frontend |
| **R**epudiation | Negar un acceso al historial o un abuso | Log JSON `phishguard.audit` (IP, ruta, status, `admin_auth_failed`) sin cuerpos ni tokens |
| **I**nformation disclosure | Leer emails de otros en el historial | Minimización: no se guarda el cuerpo; historial autenticado (H-01) |
| **I**nformation disclosure | Filtrar secretos en git o en errores | `.gitignore`, `.env.example` vacío de secretos; errores genéricos; gitleaks/trufflehog sin leaks en historial |
| **I**nformation disclosure | Exponer superficie de ataque vía `/docs` | `ENVIRONMENT=production` → `/docs`, `/redoc`, `/openapi.json` = 404 |
| **I**nformation disclosure | Indexar URLs con tokens en URLScan | Solo se envía el **hostname** (GET `/search/`); no POST `/scan/` público |
| **D**enial of service | Agotar cuota Claude / saturar API | Rate limit por IP; cuotas hora/día Anthropic |
| **D**enial of service | SSRF / metadata cloud | `url_validator.py` (solo http(s), bloqueo privadas/metadata) |
| **E**levation of privilege | Root en el contenedor | `USER appuser` UID 10001 (`backend/Dockerfile`) |
| **E**levation of privilege | Ejecutar HTML/JS pegado | `text_sanitizer.strip_html`; UI no renderiza HTML del análisis |

---

## 2. Controles aplicados (y dónde están)

| Control | Fichero(s) |
|---------|------------|
| Rate limit por IP (10/min analyze, 30/min history, 60/min stats) | `backend/app/services/rate_limit.py`, decoradores en `routers/analyze.py`, `routers/history.py` |
| IP real tras Cloudflare | `backend/app/services/client_ip.py` (`TRUST_CF_CONNECTING_IP`) |
| Anti-SSRF | `backend/app/services/url_validator.py` |
| Cabeceras OWASP | `backend/app/middleware/security_headers.py` |
| Validación de entradas (Pydantic, 413, 415, 504, sanitizado) | `routers/analyze.py`, `middleware/request_guards.py`, `services/text_sanitizer.py` |
| Token de administrador | `backend/app/services/admin_auth.py`, `routers/history.py` |
| Logs de auditoría | `backend/app/middleware/audit_log.py` |
| Defensa anti prompt injection (capas) | `backend/app/services/claude_analyzer.py`: (1) system prompt + delimitación y escape de `<>`; (2) `_validate_ai_response` esquema estricto; (3) `_apply_heuristic_floor` — la IA no puede rebajar un PHISHING heurístico |
| `/docs` desactivado en producción | `backend/app/main.py` (`is_production()`) |
| Errores sin detalles internos | `analyze.py`, `history.py`, `frontend/src/api.js` (`friendlyError`) |
| Usuario no root en Docker | `backend/Dockerfile` (`appuser` 10001) |
| uvicorn sin interpretar XFF por su cuenta | `backend/Dockerfile` / compose: `--no-proxy-headers` |

---

## 3. Gestión de secretos

| Práctica | Detalle |
|----------|---------|
| Variables de entorno | Claves y `ADMIN_TOKEN` solo en `.env` local o paneles Render/Cloudflare |
| `.env.example` | Plantilla sin secretos reales; `ADMIN_TOKEN` vacío (fail closed) |
| `.gitignore` | Ignora `.env` |
| `render.yaml` | Claves con `sync: false` (blueprint de referencia; el servicio actual se configuró a mano) |
| Escaneo de historial | **gitleaks** y **trufflehog**: sin leaks en el historial git (`auditoria-p3.md` §1: «no leaks found») |
| Hallazgos en árbol de trabajo | Solo `.env` local ignorado (esperado) |
| Rotación | **Rotar `ADMIN_TOKEN` tras la entrega** (y cualquier clave que se haya pegado en chat o capturas). **PENDIENTE** de ejecución por el autor |

No abrir ni mostrar `.env` en el vídeo ni en capturas.

---

## 4. Dependencias

| Auditoría | Antes | Después | Evidencia |
|-----------|-------|---------|-----------|
| `pip-audit` (backend) | 3 avisos (`python-multipart`) | **0** — *No known vulnerabilities found* | `evidencias/pip-audit.txt`, `pip-audit-despues.txt` |
| `npm audit` total | 18 (12 altas, 5 moderadas, 1 baja) | **9** (5 altas, 4 moderadas) | `npm-audit.txt`, `npm-audit-despues.txt` |
| `npm audit --omit=dev` | 5 | **2 moderadas** (`react-router` / `react-router-dom`) | idem |

### Riesgos aceptados

| ID | Qué | Severidad | ¿Producción? | Por qué se acepta |
|----|-----|-----------|--------------|-------------------|
| **RA-01** | Cadena Tailwind 3 → `braces` / chokidar / micromatch… | 5 altas (+ moderadas de build) | **No** (solo build) | Migrar a Tailwind 4 es breaking; riesgo DoS en máquina de compilación con ficheros propios |
| **RA-02** | `react-router-dom@6` | 2 moderadas | Sí (bundle) | Open redirect / SSR no aplican: rutas fijas, `BrowserRouter`, sin SSR. Fix = v7 con `--force` |

---

## 5. Datos personales

### Qué se trata

- Texto o URL que el usuario **pega** para analizar (puede contener emails, nombres, tokens en query).
- IP del cliente y User-Agent truncado en el log de auditoría.
- Dominio derivado (remitente o hostname de la URL) guardado en BD.
- Huella SHA-256 del contenido (no reversible de forma práctica, pero permite correlacionar repeticiones).

### Minimización

- **No se guarda** el cuerpo del email, la URL completa, la explicación ni los indicadores; solo tipo, veredicto, score, modo, timestamp, dominio y `input_hash` SHA-256 (`models/analysis.py`, migración + `VACUUM` en `database.py`).
- A **URLScan** solo se envía el **hostname** (`urlscan.py`); no se hace POST `/scan/` que publicaría la URL.
- El historial exige administración y no devuelve cuerpos.

### Conservación

- Local/Compose: volumen Docker.
- **Producción Render:** SQLite en `/tmp` → se borra en reinicios/cold start (limitación documentada).

### Protección

- HTTPS en el despliegue público.
- Auth en historial; rate limit; sin docs en producción.

### Limitaciones

- El contenido viaja a Anthropic / VirusTotal (y búsqueda de dominio a URLScan) según claves configuradas: hay que avisarlo al usuario (transparencia). **Texto exacto del aviso en UI:** **PENDIENTE** de citar desde el frontend si se exige en memoria.
- Logs de Render conservan IP el tiempo que el proveedor retenga logs (fuera del control de la app).

---

## 6. Riesgos residuales

| Riesgo | Descripción | Mitigación parcial | Residual |
|--------|-------------|--------------------|----------|
| Inyección de prompt sin señales heurísticas | Un email elaborado puede convencer a la IA de LEGÍTIMO/SOSPECHOSO si las reglas locales no disparan | Delimitación + esquema + suelo heurístico cuando sí hay señales | **Sí:** no cubre todos los casos (H-05 residual) |
| Disco efímero en Render | Historial y cuotas se reinician | Documentado; demo en local o disco de pago | **Sí** (H-06 / RF-10 / RNF-07 / RNF-11) |
| Enlaces SOSPECHOSO clicables | H-10 | PHISHING ya bloqueado | **Sí** (menor) |
| CORS default `*` en código | H-08 | En producción se debe fijar `ALLOWED_ORIGINS` | **Sí** si alguien olvida la env |
| Cold start | Primera petición lenta | Calentar antes del vídeo | Operativo |

---

## 7. Referencias internas

- `SECURITY.md` (política de reporte)
- `docs/auditoria-p3.md` (hallazgos H-xx, RA-xx, secretos)
- `docs/evidencias/*`
- `docs/requisitos.md`, `docs/pruebas.md`, `docs/trazabilidad.md`
