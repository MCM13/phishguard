# Scripts de PhishGuard

Utilidades de mantenimiento y pruebas. No forman parte del runtime de la aplicación.

| Script | Descripción |
|--------|-------------|
| `security_e2e.ps1` | Prueba E2E contra un backend en marcha (CORS, SSRF, rate limit 429, cabeceras). Uso: `powershell -File scripts/security_e2e.ps1` con el backend en `http://localhost:8000`. |
