# Política de seguridad de PhishGuard

## Versiones con soporte

| Versión | Soporte |
|---------|---------|
| `main` (última versión publicada) | Sí |
| Versiones anteriores | No |

PhishGuard es un proyecto académico mantenido por una sola persona. Las correcciones se publican sobre la rama `main`.

## Cómo reportar una vulnerabilidad

**No abras un issue público** con detalles explotables.

1. Usa las [Security Advisories privadas de GitHub](https://github.com/MCM13/phishguard/security/advisories/new) del repositorio.
2. Incluye, si es posible:
   - componente afectado (backend, frontend, despliegue) y versión o commit;
   - pasos para reproducirlo y prueba de concepto mínima;
   - impacto estimado (confidencialidad, integridad, disponibilidad);
   - si la has probado contra el despliegue público o solo en local.
3. Recibirás acuse de recibo en un plazo objetivo de 7 días. Se acordará contigo la fecha de divulgación una vez exista corrección.

### Reglas para las pruebas

- Prueba preferentemente sobre una instancia local (`docker compose up`).
- No ejecutes pruebas de denegación de servicio ni automatizadas de alto volumen contra el despliegue público: el backend usa planes gratuitos y créditos de API limitados.
- No envíes datos personales reales de terceros como contenido a analizar.

### Fuera de alcance

- Falsos positivos o negativos del veredicto: son una limitación conocida del análisis, no una vulnerabilidad. Puedes reportarlos como issue normal.
- Vulnerabilidades de VirusTotal, URLScan.io, Anthropic, Render o Cloudflare: repórtalas a cada proveedor.

## Resumen de controles de seguridad

| Área | Control | Implementación |
|------|---------|----------------|
| Secretos | Las claves de API solo viven en `.env` (ignorado por git) o en los paneles de Render y Cloudflare. El historial se ha revisado con gitleaks y trufflehog. | `.gitignore`, `.env.example`, `render.yaml` |
| Validación de entradas | Esquemas Pydantic con longitudes mínimas y máximas; cuerpo máximo de 1 MB (413); solo `application/json` en POST (415); timeout de 30 s (504). | `backend/app/routers/analyze.py`, `backend/app/middleware/request_guards.py` |
| Anti-SSRF | Solo `http(s)`. Se rechazan localhost, IPs privadas, loopback, link-local, multicast, reservadas y metadata de cloud, comprobando todas las IPs a las que resuelve el dominio. | `backend/app/services/url_validator.py` |
| Contenido activo | Se eliminan HTML, JS, CSS y caracteres de control antes de procesar o guardar. | `backend/app/services/text_sanitizer.py` |
| Control de acceso | `GET /api/history` exige `Authorization: Bearer <ADMIN_TOKEN>`, comparado en tiempo constante. Sin token, con token incorrecto o sin token configurado responde 401 genérico, y el intento queda en el log de auditoría (`event: admin_auth_failed`). | `backend/app/services/admin_auth.py`, `backend/app/routers/history.py` |
| Datos personales | Minimización: solo se guarda tipo, veredicto, score, modo de análisis, fecha, el dominio del remitente o de la URL y una huella SHA-256 del contenido. No se guarda el texto de los emails, ni la URL completa, ni la explicación. Las bases de datos antiguas se migran descartando ese contenido (con `VACUUM`). | `backend/app/models/analysis.py`, `backend/app/database.py` |
| Abuso y costes | Rate limiting por IP y cuotas por hora y por día de llamadas a la IA. | `backend/app/services/rate_limit.py`, `backend/app/services/anthropic_rate_limit.py` |
| Cabeceras HTTP | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy y HSTS sobre HTTPS. | `backend/app/middleware/security_headers.py` |
| Auditoría | Un log JSON por petición (fecha, IP, ruta, estado, latencia y veredicto), sin cuerpos ni claves. | `backend/app/middleware/audit_log.py` |
| Contenedores | El backend se ejecuta como usuario sin privilegios (`appuser`, UID 10001). | `backend/Dockerfile` |
| Frontend | Las URLs con veredicto PHISHING no se renderizan como enlace. Los mensajes de error son genéricos, sin trazas. | `frontend/src/components/ResultCard.jsx`, `frontend/src/api.js` |
| Dependencias | Versiones fijadas y auditadas con `pip-audit` y `npm audit`. | `backend/requirements.txt`, `frontend/package-lock.json`, `docs/evidencias/` |

## Limitaciones conocidas

- Los resultados son orientativos. Un modelo de lenguaje puede equivocarse o ser manipulado con contenido diseñado para ello (inyección de prompt).
- En el plan gratuito de Render el disco es efímero: el historial y los contadores de cuota se reinician con cada despliegue o reinicio.
