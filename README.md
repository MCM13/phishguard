# PhishGuard

[![Backend — Render](https://img.shields.io/badge/Backend-Render-46E3B7?style=flat&logo=render&logoColor=white)](https://render.com)
[![Frontend — Cloudflare Pages](https://img.shields.io/badge/Frontend-Cloudflare%20Pages-F38020?style=flat&logo=cloudflare&logoColor=white)](https://pages.cloudflare.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Análisis de phishing con IA para URLs y correos sospechosos — score, veredicto e indicadores en español.**

---

## Descripción general

**PhishGuard** es una aplicación web orientada a la detección de intentos de *phishing*. Permite analizar enlaces y mensajes de correo sospechosos y obtener una valoración clara del riesgo, pensada para formación, laboratorios de ciberseguridad y uso profesional con criterio humano.

### Problema que aborda

El *phishing* sigue siendo una de las vías de ataque más habituales: enlaces fraudulentos, suplantación de marcas y correos de urgencia que empujan a la víctima a actuar sin pensar. PhishGuard centraliza varias fuentes de inteligencia y un motor de IA para **priorizar la revisión** y documentar el porqué de cada alerta.

### Interfaz

Panel oscuro tipo *security operations*: fondo con rejilla y efectos sutiles, tarjetas *glass*, medidor semicircular de riesgo (0–100) y badges de veredicto en rojo, ámbar y verde. El flujo principal tiene pestañas **URL** / **Email**, panel de resultados en tiempo real e historial filtrable con paginación.

---

## Características principales

| Funcionalidad | Descripción |
|---------------|-------------|
| **Análisis de URLs** | Evalúa enlaces sospechosos y devuelve score, veredicto e indicadores. |
| **Análisis de emails** | Analiza el texto del mensaje (cuerpo o correo completo pegado). |
| **Score visual 0–100** | Medidor gráfico con explicación en español generada por IA. |
| **Historial y estadísticas** | Registro minimizado de análisis previos (protegido con `ADMIN_TOKEN`) y métricas agregadas en el panel. |
| **Tolerancia a fallos** | Si VirusTotal, URLScan, WHOIS o la IA no están disponibles, el análisis continúa con las señales restantes. |
| **Modo sin IA** | Sin clave de Anthropic, con la cuota agotada o si la IA falla, un motor heurístico analiza URL y email y la interfaz muestra «Análisis limitado (sin IA)». |

**Veredictos posibles:** `PHISHING` · `SOSPECHOSO` · `LEGÍTIMO` · `NO CONCLUYENTE`

`LEGÍTIMO` sólo lo emite la IA. En modo sin IA, si no hay señales suficientes de phishing el veredicto es `NO CONCLUYENTE`: la ausencia de señales heurísticas no prueba que algo sea seguro.

---

## Stack tecnológico

| Capa | Tecnología |
|------|------------|
| Frontend | React 18 · Vite · Tailwind CSS |
| Backend | Python 3.11 · FastAPI |
| IA | Claude API (Anthropic) |
| Threat intel | VirusTotal · URLScan.io |
| Contenedores | Docker · Docker Compose |
| Producción | Cloudflare Pages (frontend) · Render (backend) |

---

## Instalación desde cero con Docker Compose

### Requisitos previos

- [Git](https://git-scm.com/)
- [Docker](https://www.docker.com/) 24+ con Docker Compose v2 (en Windows y macOS, Docker Desktop arrancado)
- Opcional: claves de **Anthropic**, **VirusTotal** y **URLScan**. Sin ninguna clave la aplicación funciona en modo sin IA y sin reputación externa.

No hace falta tener Python ni Node instalados: todo se construye dentro de los contenedores.

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/MCM13/phishguard.git
cd phishguard

# 2. Crear el fichero de entorno desde la plantilla
cp .env.example .env          # Linux/macOS
# copy .env.example .env      # Windows (cmd o PowerShell)

# 3. Generar un token de administrador para el historial
docker run --rm python:3.11-slim python -c "import secrets; print(secrets.token_urlsafe(32))"

# 4. Editar .env: pegar el token en ADMIN_TOKEN= y, si las tienes, las claves
#    de API en lugar de los valores your_key_here (déjalos vacíos si no).
#    Nunca subas .env al repositorio: está en .gitignore.

# 5. Construir y arrancar
docker compose up -d --build

# 6. Comprobar que el backend responde
curl http://localhost:8000/
# {"status":"ok","service":"PhishGuard API","version":"1.0.0"}
```

| Servicio | URL local |
|----------|-----------|
| Frontend | http://localhost:3000 |
| Backend (API) | http://localhost:8000 |
| Documentación interactiva de la API | http://localhost:8000/docs |

- Ver los logs (incluido el log de auditoría en JSON): `docker compose logs -f backend`
- Detener: `docker compose down`. La base de datos se guarda en el volumen `phishguard-data` y se conserva.
- Borrar también los datos: `docker compose down -v`
- Comprobar que el backend corre sin privilegios: `docker exec phishguard-backend id` (debe mostrar `uid=10001(appuser)`).

> Las carpetas del proyecto deben llamarse **`frontend/`** y **`scripts/`** para que Docker y los proveedores de despliegue resuelvan las rutas correctamente.

### Desarrollo sin Docker (opcional)

**Backend:** `cd backend` → entorno virtual → `pip install -r requirements.txt` → `uvicorn app.main:app --reload --port 8000`

**Frontend:** `cd frontend` → `npm install` → `npm run dev` (configura `VITE_API_URL` en `.env` apuntando al backend local).

---

## Variables de entorno

Copia `.env.example` a `.env` en la raíz del proyecto. **Todas las claves y secretos van solo en `.env` o en el panel de tu proveedor de hosting** — nunca en el código ni en commits.

| Variable | ¿Obligatoria? | Por defecto | Uso |
|----------|:-------------:|-------------|-----|
| `ADMIN_TOKEN` | Para ver el historial | vacío | Token para `GET /api/history` (`Authorization: Bearer …`). Vacío = historial cerrado para todos. Usa 24 caracteres aleatorios o más. |
| `ANTHROPIC_API_KEY` | No* | vacío | Clave de la API de Anthropic (Claude). |
| `CLAUDE_MODEL` | No | `claude-sonnet-4-5-20250929` | Modelo de Claude (`.env.example` propone `claude-sonnet-4-6`). |
| `ANTHROPIC_MAX_PER_HOUR` | No | `10` | Máximo de llamadas a la IA por hora. `0` = sin límite. |
| `ANTHROPIC_MAX_PER_DAY` | No | `20` | Máximo de llamadas a la IA por día UTC. `0` = sin límite. Al agotarse se pasa al modo sin IA. |
| `VIRUSTOTAL_API_KEY` | No | vacío | Reputación de URLs vía VirusTotal. |
| `URLSCAN_API_KEY` | No | vacío | Informes de URLScan.io; si falta, se omite sin error. |
| `RATE_LIMIT_ANALYZE` | No | `10/minute` | Límite por IP de `POST /api/analyze/*`. |
| `RATE_LIMIT_HISTORY` | No | `30/minute` | Límite por IP de `GET /api/history` (también frena la fuerza bruta del token). |
| `RATE_LIMIT_STATS` | No | `60/minute` | Límite por IP de `GET /api/stats`. |
| `TRUSTED_PROXY_HOPS` | No | `0` | Proxies de confianza que añaden `X-Forwarded-For`. `0` = se usa la IP de la conexión (local). `1` en Render. |
| `TRUSTED_PROXY_CIDRS` | No | vacío | Redes (CSV) desde las que se acepta `X-Forwarded-For`. |
| `ALLOWED_ORIGINS` | Sí en producción | `*` en código, `http://localhost:3000` en Compose | Orígenes permitidos para CORS (lista separada por comas). |
| `FRONTEND_URL` | No | vacío | URL pública del frontend; se añade a CORS. |
| `DATABASE_URL` | No | `sqlite:////data/phishguard.db` en Compose | Cadena de conexión SQLite. |
| `LOG_LEVEL` | No | `INFO` | Nivel de log del backend. |
| `VITE_API_URL` | No | `http://localhost:8000` | URL pública del backend que usa el navegador (se fija al construir el frontend). |

\* Sin clave de Anthropic todos los análisis se hacen en modo sin IA.

**Formato de los límites:** `N/second`, `N/minute`, `N/hour` o `N/day`. Los límites de IA y de rate limit se leen en cada petición.

**Detrás de un proxy:** pon `TRUSTED_PROXY_HOPS` al número de proxies que hay delante del backend. Nunca uses un valor mayor: el cliente controla las entradas de la izquierda de `X-Forwarded-For` y podría saltarse el rate limit.

En **Render** y **Cloudflare Pages** define las mismas variables en el panel de Environment / Build variables de cada servicio.

---

## Uso básico

### Desde la interfaz web

1. Abre http://localhost:3000 (o la URL de producción).
2. En **Analizar**, elige la pestaña **URL** y pega un enlace que empiece por `http://` o `https://`, o la pestaña **Email** y pega el texto del correo. Si pegas el correo completo con cabeceras (`From:`, `Reply-To:`, `Subject:`…), el análisis también compara el remitente visible con el dominio real.
3. El resultado muestra el score de 0 a 100, el veredicto, los indicadores y la explicación. Si aparece el aviso **«Análisis limitado (sin IA)»**, el resultado viene del motor heurístico.
4. En **Historial**, introduce el valor de `ADMIN_TOKEN`. El token sólo se guarda en memoria y se olvida al recargar la página. El historial muestra tipo, veredicto, score, fecha, dominio y una huella del contenido, pero nunca el texto analizado.
5. El **Dashboard** muestra las estadísticas globales y la cuota de IA restante.

### Desde la API

```bash
curl -X POST http://localhost:8000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.verify-account.test/confirm"}'

curl -X POST http://localhost:8000/api/analyze/email \
  -H "Content-Type: application/json" \
  -d '{"content": "From: Soporte <alertas@banco-seguro.test>\nSubject: URGENTE\n\nSu cuenta sera bloqueada en 24 horas. Introduzca su contrasena."}'

curl http://localhost:8000/api/stats

curl "http://localhost:8000/api/history?page=1&page_size=20" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Las URLs que apuntan a la red interna (localhost, IPs privadas, `169.254.169.254`…) se rechazan con un 400 (protección anti-SSRF).

### Credenciales de prueba

No aplica: la herramienta no tiene usuarios; el historial se protege con `ADMIN_TOKEN`.

---

## Tests

La suite está en `backend/tests/` (pytest). No hace peticiones de red: VirusTotal, URLScan, Anthropic, WHOIS y DNS se simulan con mocks sólo dentro de los tests, y todas las URLs son ficticias (`example.com`, dominios `.test`).

Con Docker (no hace falta Python local):

```bash
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "$(pwd)/backend:/app" -w /app python:3.11-slim \
  sh -c "pip install -q -r requirements-dev.txt && python -m pytest -v -p no:cacheprovider"
```

En PowerShell cambia `$(pwd)` por `${PWD}`.

Con Python 3.11 local:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest -v
```

La última ejecución está guardada en [`docs/evidencias/pytest.txt`](docs/evidencias/pytest.txt). Hay un test por cada requisito verificable desde el código del backend; la correspondencia está en [`docs/auditoria-p3.md`](docs/auditoria-p3.md).

---

## Estructura del proyecto

```
phishguard/
├── backend/              # API REST (FastAPI)
│   ├── app/              # Lógica de aplicación, rutas y servicios
│   ├── tests/            # Suite pytest
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── Dockerfile
├── frontend/             # SPA React (Vite)
│   ├── src/
│   │   ├── components/   # Analizadores, resultados, historial…
│   │   ├── pages/
│   │   └── api.js        # Cliente HTTP hacia el backend
│   ├── package.json
│   └── Dockerfile
├── scripts/              # Utilidades de desarrollo y pruebas
├── docs/                 # Auditoría y evidencias (audits de dependencias, pytest)
├── docker-compose.yml    # Orquestación local
├── render.yaml           # Referencia de despliegue backend
├── .env.example          # Plantilla de variables (sin secretos)
└── README.md
```

---

## Despliegue en producción

### URL de despliegue

- Aplicación: **https://phishguard.cmmario.com**
- API: https://phishguard-backend-qszu.onrender.com (salud en `/`, documentación en `/docs`)

PhishGuard está pensado para un despliegue **desacoplado**:

| Componente | Plataforma | Notas |
|------------|------------|-------|
| **Frontend** | [Cloudflare Pages](https://pages.cloudflare.com) | Build desde la carpeta `frontend/` (`npm ci && npm run build`, salida `dist`). Configura `VITE_API_URL` con la URL pública de tu API. |
| **Backend** | [Render](https://render.com) | Servicio Docker desde `backend/`. Variables de entorno y claves en el panel de Render. |

Tras cada cambio en `VITE_API_URL` hay que **volver a desplegar el frontend** (se inyecta en tiempo de build). Mantén `ALLOWED_ORIGINS` alineado con el dominio real de tu aplicación.

En Render hay que definir en el panel, como mínimo, `ADMIN_TOKEN`, `ALLOWED_ORIGINS`/`FRONTEND_URL` y `TRUSTED_PROXY_HOPS=1`; las claves de API son opcionales. Consulta `render.yaml` y `.env.example` como referencia; los valores concretos de dominio y claves se configuran solo en los paneles de cada proveedor.

---

## Limitaciones conocidas

- **Arranque en frío de Render.** El plan gratuito duerme el backend tras unos 15 minutos sin tráfico. La primera petición después puede tardar alrededor de un minuto, y mientras tanto el frontend puede mostrar un error de conexión. Basta con reintentar.
- **Disco efímero: el historial se borra en cada reinicio.** En Render la base de datos SQLite está en `/tmp` (`DATABASE_URL=sqlite:////tmp/phishguard.db`). Cada redeploy, reinicio o arranque en frío la vacía: el historial, las estadísticas y el contador de cuota de IA vuelven a cero. Para conservarlos hace falta un Persistent Disk (de pago) o una base de datos externa. En local, con Docker Compose, los datos persisten en el volumen `phishguard-data`.
- **Cuota diaria de IA.** Por defecto se permiten 20 llamadas a Claude al día y 10 por hora (`ANTHROPIC_MAX_PER_DAY`, `ANTHROPIC_MAX_PER_HOUR`). Al agotarse, los análisis siguen en modo sin IA, que es menos preciso y nunca devuelve `LEGÍTIMO`. Como el contador vive en la misma base de datos efímera, en Render también se reinicia con cada arranque.
- **Rate limit en memoria.** Los contadores por IP no se comparten entre procesos y se pierden al reiniciar. Es suficiente con un único worker, que es como se despliega.
- **Llamadas síncronas.** WHOIS y el SDK de Anthropic son síncronos y bloquean el servidor mientras responden. El timeout global de 30 s no puede interrumpirlos.
- **Análisis heurístico limitado.** El modo sin IA se basa en reglas (urgencia, peticiones de credenciales o pagos, remitente frente a dominio real, Reply-To, texto del enlace frente a destino, adjuntos peligrosos, TLD, VirusTotal). Puede no detectar campañas bien construidas.

---

## Contribuir

Las contribuciones son bienvenidas.

1. Haz **fork** del repositorio.
2. Crea una rama: `git checkout -b feature/mi-mejora`
3. Realiza tus cambios con commits claros.
4. Abre un **Pull Request** describiendo el problema y la solución.

### Seguridad

Si descubres una vulnerabilidad, **no abras un issue público** con detalles explotables. Consulta [SECURITY.md](SECURITY.md) para el proceso de divulgación responsable mediante las [**Security Advisories**](https://github.com/MCM13/phishguard/security/advisories) privadas de GitHub.

---

## Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulta el fichero [LICENSE](LICENSE) para el texto completo.

---

## Aviso legal

Los resultados de PhishGuard son **orientativos**. Revisa siempre las alertas con criterio experto antes de bloquear dominios, reportar incidentes o tomar decisiones operativas. Pueden producirse falsos positivos y falsos negativos.
