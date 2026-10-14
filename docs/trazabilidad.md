# Matriz de trazabilidad — PhishGuard (Práctica 3)

Relaciona cada requisito con su implementación, las pruebas (`docs/pruebas.md`) y la evidencia.  
Los huecos **«Vídeo mm:ss»** los rellena el autor tras la grabación.

| Requisito | Descripción (resumen) | Estado final | Implementación | Prueba (IDs PR) | Evidencia |
|-----------|----------------------|--------------|----------------|-----------------|-----------|
| RF-01 | Analizar URL → score, veredicto, indicadores, explicación | Cumplido | `backend/app/routers/analyze.py`; `frontend/src/components/URLAnalyzer.jsx` | PR-01, PR-20–22, PR-33, PR-50 | `evidencias/pytest.txt`; `evidencias/verificacion-produccion.md` §4; Vídeo mm:ss |
| RF-02 | Analizar email (≥10 caracteres) | Cumplido | `analyze.py` `POST /api/analyze/email`; `EmailAnalyzer.jsx` | PR-02, PR-23–25, PR-34, PR-51 | pytest.txt; verificación §4; Vídeo mm:ss |
| RF-03 | 15 features de URL | Cumplido | `backend/app/services/url_extractor.py` | PR-01 | pytest.txt (`test_analysis_url`); Vídeo mm:ss |
| RF-04 | Señales de email | Cumplido | `email_extractor.py`, `domain_utils.py` | PR-02, PR-03, PR-46, PR-51 | pytest.txt (`test_analysis_email`, `test_email_encoding`); Vídeo mm:ss |
| RF-05 | VirusTotal v3 | Cumplido | `backend/app/services/virustotal.py` | PR-01, PR-06 | pytest.txt; Vídeo mm:ss |
| RF-06 | URLScan (búsqueda por dominio) | Cumplido | `backend/app/services/urlscan.py` | PR-01, PR-06 | pytest.txt; auditoría RF-06 / minimización; Vídeo mm:ss |
| RF-07 | Veredicto Claude (JSON estricto) | Cumplido | `backend/app/services/claude_analyzer.py` | PR-04, PR-05, PR-20–25, PR-33–34, PR-43, PR-57 | pytest.txt; verificación §4; Vídeo mm:ss |
| RF-08 | Fallback heurístico / «Análisis limitado» | Cumplido | `claude_analyzer.py` (`_fallback_*`); `ResultCard.jsx` | PR-02, PR-04, PR-40, PR-52 | pytest.txt; auditoría H-02; Vídeo mm:ss |
| RF-09 | Tolerancia a fallos VT/URLScan/WHOIS | Cumplido | `virustotal.py`, `urlscan.py`, `url_extractor.py` | PR-06 | pytest.txt (`test_external_failures`); Vídeo mm:ss |
| RF-10 | Persistencia SQLite | **Parcial** | `database.py`, `models/analysis.py`, `_persist_analysis` | PR-07 | pytest.txt (`test_history`); README limitaciones; Vídeo mm:ss |
| RF-11 | Historial paginado + filtro + auth | Cumplido | `routers/history.py`; `History.jsx`, `HistoryTable.jsx` | PR-07, PR-31, PR-41, PR-53 | verificación §2; pytest.txt; Vídeo mm:ss |
| RF-12 | Dashboard / stats | Cumplido | `history.py` `GET /api/stats`; `Dashboard.jsx` | PR-07, PR-54 | pytest.txt; Vídeo mm:ss |
| RF-13 | Medidor visual 0–100 | Cumplido | `ScoreGauge.jsx`, `ResultCard.jsx` | PR-50 | Vídeo mm:ss |
| RF-14 | URLs PHISHING no clicables | Cumplido | `ResultCard.jsx` | PR-50 | Vídeo mm:ss |
| RF-15 | API documentada (`/docs`) | Cumplido | `backend/app/main.py` (FastAPI) | PR-10, PR-30 | En dev: OpenAPI; en prod: 404 (RNF-09). verificación §1; Vídeo mm:ss |
| RNF-01 | Rate limit por IP | Cumplido | `client_ip.py`, `rate_limit.py`, routers | PR-08, PR-35–37, PR-42, PR-45, PR-47, PR-56 | verificación §5–6; pytest.txt; Vídeo mm:ss |
| RNF-02 | Cabeceras OWASP (backend) | Cumplido (backend) | `middleware/security_headers.py` | PR-09, PR-32 | verificación §3; pytest.txt; Vídeo mm:ss |
| RNF-03 | Anti-SSRF | Cumplido | `url_validator.py` | PR-09, PR-55 | pytest.txt; Vídeo mm:ss |
| RNF-04 | Validación / saneado / timeouts | Cumplido | `text_sanitizer.py`, `request_guards.py`, Pydantic | PR-09, PR-11 | pytest.txt; Vídeo mm:ss |
| RNF-05 | Contenedor no root | Cumplido | `backend/Dockerfile` | PR-10, PR-58 | pytest.txt (estático); Vídeo mm:ss |
| RNF-06 | Auditoría JSON | Cumplido | `middleware/audit_log.py` | PR-10, PR-37 | verificación §6 (líneas de log); pytest.txt; Vídeo mm:ss |
| RNF-07 | Cuotas Anthropic | **Parcial** | `anthropic_rate_limit.py`, `models/anthropic_usage.py` | PR-04 | pytest.txt; README (reinicio en `/tmp`); Vídeo mm:ss |
| RNF-08 | Gestión de secretos | Cumplido | `.gitignore`, `.env.example`, `render.yaml` | — (auditoría §1) | `auditoria-p3.md` §1 (gitleaks/trufflehog); Vídeo mm:ss |
| RNF-09 | Errores genéricos; sin docs en prod | Cumplido | `main.py`, `analyze.py`, `api.js` | PR-09, PR-10, PR-30, PR-44 | verificación §1; pytest.txt; Vídeo mm:ss |
| RNF-10 | Docker Compose reproducible | **Parcial** | `docker-compose.yml`, Dockerfiles, README | PR-59 | README; Vídeo mm:ss |
| RNF-11 | Despliegue HTTPS + dominio | **Parcial** | Render + Cloudflare Pages | PR-38, PR-60 | verificación §7; D-01 en `requisitos.md`; Vídeo mm:ss |
| RNF-12 | Config por entorno | Cumplido | `.env.example`, `cors_config.py`, `client_ip.py`, … | PR-10 | README; `.env.example`; Vídeo mm:ss |
| RNF-13 | UI en español | Cumplido | `frontend/src/*`, prompt Claude | PR-50–54 | Vídeo mm:ss |
| D-01 | Hetzner → Render/CF | **A revisar** | Despliegue actual | PR-60 | `requisitos.md` §3; Vídeo mm:ss |
| D-06 | Auth usuarios vs ADMIN_TOKEN | **A revisar** | `admin_auth.py` | PR-31, PR-53 | `requisitos.md`; Vídeo mm:ss |
| D-10 | VT/URLScan en paralelo | **A revisar** | `analyze.py` (secuencia) | — | `requisitos.md`; **PENDIENTE** decisión memoria |

### Hallazgos de seguridad enlazados (no son RF, sí trazan a pruebas)

| Hallazgo | Estado | Pruebas | Evidencia |
|----------|--------|---------|-----------|
| H-01 Historial | Resuelto | PR-41, PR-31 | auditoría; verificación §2 |
| H-02 Fallback email | Resuelto | PR-40 | auditoría; pytest |
| H-03 / H-13 IP y rate limit | Resuelto | PR-42, PR-47, PR-35–37 | verificación §5–6 |
| H-05 Prompt injection | Resuelto (mitigado) | PR-43, PR-25 | pytest; IA real |
| H-07 /docs prod | Resuelto | PR-44, PR-30 | verificación §1 |
| H-12 Codificación email | Resuelto | PR-46, PR-03, PR-34 | auditoría; verificación §4 |
| H-09 npm ci | Resuelto | — (build) | commit `e62c678`; **PENDIENTE** captura vídeo si se muestra |
