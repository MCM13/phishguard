# PhishGuard

**Herramienta web de análisis de phishing con IA.**
Analiza URLs y emails sospechosos combinando extracción de features locales, VirusTotal, URLScan.io y Anthropic Claude para devolver:

- Un **score** de 0 a 100
- Un **veredicto**: `PHISHING` / `SOSPECHOSO` / `LEGÍTIMO`
- Una **explicación detallada** en español
- Una **lista de indicadores** con severidad

---

## Stack

| Capa     | Tecnología                                |
| -------- | ------------------------------------------ |
| Backend  | Python 3.11 · FastAPI · SQLAlchemy · SQLite |
| Frontend | React 18 · Vite · Tailwind CSS             |
| IA       | Anthropic Claude (`claude-sonnet-4-6` por defecto, configurable) |
| Externos | VirusTotal API v3 · URLScan.io API         |
| Deploy   | Docker · Docker Compose                    |

## Estructura del proyecto

> **Despliegue:** las carpetas deben llamarse exactamente `frontend/` y `scripts/` (no `Interfaz` ni `guiones`) para que Render, Docker y Cloudflare Pages resuelvan las rutas correctamente.

```
phishguard/
├── backend/                 # API FastAPI (Render: servicio Docker)
│   ├── app/
│   │   ├── main.py
│   │   ├── database.py
│   │   ├── cors_config.py
│   │   ├── middleware/      # CORS, auditoría, rate limit, cabeceras, guards
│   │   ├── models/          # SQLAlchemy (analyses, anthropic_usage)
│   │   ├── routers/         # analyze.py, history.py
│   │   └── services/        # extractores, VT, URLScan, Claude, sanitización
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                # SPA React + Vite (Cloudflare Pages / Docker)
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── api.js
│   │   └── App.jsx
│   ├── .env.production      # VITE_API_URL (público, versionado)
│   ├── package.json
│   └── Dockerfile
├── scripts/                 # Utilidades (tests E2E, etc.)
│   └── security_e2e.ps1
├── docker-compose.yml
├── render.yaml              # Blueprint Render (referencia)
├── .env.example
├── SECURITY.md
└── README.md
```

## Endpoints

| Método | Ruta                  | Descripción                                                       |
| ------ | --------------------- | ----------------------------------------------------------------- |
| POST   | `/api/analyze/url`    | Analiza una URL. Body: `{ "url": "..." }`                         |
| POST   | `/api/analyze/email`  | Analiza el texto de un email. Body: `{ "content": "..." }`        |
| GET    | `/api/history`        | Historial paginado (`?page=1&page_size=20&verdict=PHISHING`)      |
| GET    | `/api/stats`          | Estadísticas globales                                              |
| GET    | `/`                   | Healthcheck                                                       |

Documentación Swagger autogenerada en `http://localhost:8000/docs`.

## Variables de entorno

Crea un fichero `.env` en la raíz copiando `.env.example`:

```bash
cp .env.example .env
```

Variables soportadas:

| Variable               | Obligatoria | Descripción                                                              |
| ---------------------- | ----------- | ------------------------------------------------------------------------ |
| `ANTHROPIC_API_KEY`    | Sí          | API key de Anthropic Claude.                                             |
| `CLAUDE_MODEL`         | No          | ID del modelo de Claude a usar. Por defecto `claude-sonnet-4-6`. Ver [Modelos disponibles](#modelos-de-claude-disponibles). |
| `ANTHROPIC_MAX_PER_HOUR` | No        | Máximo de llamadas a Claude por hora (defecto `10`). `0` = sin límite horario. |
| `ANTHROPIC_MAX_PER_DAY`  | No        | Máximo de llamadas a Claude por día UTC (defecto `20`). `0` = sin límite diario. |
| `VIRUSTOTAL_API_KEY`   | No          | API key del plan **Public API** (gratis). Ver sección VirusTotal más abajo. |
| `URLSCAN_API_KEY`      | No          | Si falta, se omite URLScan sin romper el análisis.                       |
| `VITE_API_URL`         | No          | URL pública del backend visible desde el navegador. Por defecto `http://localhost:8000`. |
| `DATABASE_URL`         | No          | SQLite. Local: `sqlite:///./phishguard.db`. Docker: `sqlite:////data/phishguard.db`. Render: `sqlite:////tmp/phishguard.db`. |
| `ALLOWED_ORIGINS`      | No          | Lista CSV de orígenes CORS. En Render debe incluir la URL exacta del frontend. |
| `FRONTEND_URL`         | No          | URL pública del frontend; en Render se añade sola a CORS si falta en `ALLOWED_ORIGINS`. |

> **Importante:** si VirusTotal o URLScan no están configurados o fallan, el análisis continúa igualmente usando únicamente Claude + las features locales.

> **Cuota Anthropic:** al superar los límites horario/diario, PhishGuard **no llama a Claude** y devuelve un veredicto heurístico local (sin gastar créditos). El consumo se muestra en `GET /api/stats` bajo `anthropic_quota`.

### VirusTotal (API gratuita)

PhishGuard **ya integra** VirusTotal API v3 (`backend/app/services/virustotal.py`). Solo necesitas la clave:

1. Crea cuenta en [virustotal.com](https://www.virustotal.com).
2. Ve a [My API key](https://www.virustotal.com/gui/my-apikey) y copia tu clave.
3. Añádela como `VIRUSTOTAL_API_KEY` en `.env` (local) o en **Render → Environment** (producción).
4. Redeploy del backend.

El plan **Public API** es gratuito para uso personal/educativo (no comercial intensivo). Límites habituales: **4 peticiones/minuto** y **500/día** — suficiente para PhishGuard (1 consulta por análisis de URL).

Si la URL no está en la base de VirusTotal, se envía para análisis y en esa petición puede mostrarse 0 detecciones; en análisis posteriores ya tendrá datos.

### Modelos de Claude disponibles

El modelo a utilizar se configura con la variable `CLAUDE_MODEL` en el `.env`. Estos son los IDs recomendados:

| Modelo                          | Recomendación                          | Uso típico                                     |
| ------------------------------- | -------------------------------------- | ---------------------------------------------- |
| `claude-sonnet-4-6`             | **Recomendado** (por defecto)          | Mejor balance calidad / coste / velocidad.     |
| `claude-opus-4-6`               | Máxima calidad                         | Análisis más matizados, mayor coste y latencia.|
| `claude-haiku-4-5-20251001`     | Más rápido y económico                 | Alto volumen, latencia baja.                   |

Cambiar de modelo es tan sencillo como editar `.env` y recrear el contenedor:

```bash
# Edita .env y cambia, por ejemplo, a Opus
sed -i 's/^CLAUDE_MODEL=.*/CLAUDE_MODEL=claude-opus-4-6/' .env

# Recreación del contenedor (NO uses 'restart', no recarga el .env)
docker compose up -d backend
```

Para listar todos los modelos disponibles con tu API key:

```bash
curl https://api.anthropic.com/v1/models \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01"
```

## Instalación rápida con Docker (recomendado)

Requisitos: Docker 24+ y Docker Compose v2.

```bash
# 1. Copia el fichero de variables y rellena tus claves
cp .env.example .env
nano .env

# 2. Construye y arranca los contenedores
docker compose up -d --build

# 3. Comprueba que están vivos
curl http://localhost:8000/         # backend
xdg-open http://localhost:3000      # frontend (o ábrelo en el navegador)
```

- Frontend: `http://localhost:3000`
- Backend:  `http://localhost:8000` (Swagger en `/docs`)

Para parar:

```bash
docker compose down
```

La base de datos SQLite persiste en el volumen Docker `phishguard-data`.

## Despliegue en Render

En Render el filesystem del contenedor es **efímero**: si `DATABASE_URL` apunta a `./phishguard.db` en el directorio de la app, puede fallar con *readonly database* o perder datos en cada redeploy.

### Variables obligatorias en el servicio **backend** (Render → Environment)

| Variable | Valor ejemplo | Motivo |
| -------- | ------------- | ------ |
| `ANTHROPIC_API_KEY` | `sk-ant-...` | Sin esto solo hay análisis heurístico. |
| `DATABASE_URL` | `sqlite:////tmp/phishguard.db` | Ruta escribible en Render (4 barras = ruta absoluta `/tmp/...`). |
| `FRONTEND_URL` | `https://phishguard.cmmario.com` | Origen del navegador; se añade a CORS automáticamente. |
| `ALLOWED_ORIGINS` | `https://phishguard.cmmario.com` | Debe coincidir **exactamente** con la URL del frontend (incluye `https://`, sin `/` final). Si también usas `www`, añádelo: `https://phishguard.cmmario.com,https://www.phishguard.cmmario.com` |

> Si el frontend llama al API pero ves errores en el navegador (estadísticas vacías, CORS), casi siempre es `ALLOWED_ORIGINS` / `FRONTEND_URL` que no incluyen el dominio desde el que abres la app.

### Persistir la base de datos entre redeploys (opcional)

1. En Render → backend → **Disks** → añade un Persistent Disk montado en `/var/data`.
2. Configura `DATABASE_URL=sqlite:////var/data/phishguard.db`.

### Servicio **frontend** en Render

- Build arg / variable de build: `VITE_API_URL=https://phishguard-backend-qszu.onrender.com` (tu URL real del backend).
- Tras cambiar `VITE_API_URL` hay que **volver a desplegar** el frontend (se inyecta en build-time).

Referencia: fichero `render.yaml` en la raíz del repo.

### Cloudflare Pages (frontend)

En el panel de Pages, configura el repositorio con:

| Campo | Valor |
|-------|--------|
| **Root directory** | `frontend` |
| **Build command** | `npm ci && npm run build` |
| **Build output directory** | `dist` |
| **Variable de entorno** | `VITE_API_URL` = URL de tu backend (ej. `https://phishguard-backend-qszu.onrender.com`) |

No uses la carpeta `Interfaz` como raíz; debe ser **`frontend`**.

## Instalación manual (desarrollo local)

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\Activate.ps1       # Windows PowerShell

pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...
export VIRUSTOTAL_API_KEY=...      # opcional
export URLSCAN_API_KEY=...         # opcional

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
# Apunta al backend local
echo "VITE_API_URL=http://localhost:8000" > .env
npm run dev
```

Abre `http://localhost:3000` en el navegador.

## Despliegue en VPS Ubuntu 22.04 (Hetzner)

```bash
# 1. Instalar Docker y Compose
sudo apt update && sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker

# 2. Clonar el repositorio
git clone https://github.com/tu-usuario/phishguard.git
cd phishguard

# 3. Configurar variables de entorno
cp .env.example .env
nano .env
# - Pon tus API keys
# - Cambia VITE_API_URL a http://TU_IP_PUBLICA:8000 (o tu dominio)

# 4. Construir y arrancar
sudo docker compose up -d --build

# 5. Abrir puertos en el firewall
sudo ufw allow 3000/tcp
sudo ufw allow 8000/tcp
```

Para producción real se recomienda colocar un reverse proxy (Nginx o Caddy) con HTTPS delante de ambos servicios y restringir `ALLOWED_ORIGINS` a tu dominio.

### Actualizar a una nueva versión

```bash
git pull
sudo docker compose up -d --build
```

## Funcionamiento interno (resumen)

1. **Extracción de features:** longitud, subdominios, palabras clave (`login`, `paypal`, `verify`…), caracteres sospechosos (`@`, `--`, `%`, `~`), TLDs inusuales, HTTPS y edad del dominio vía `python-whois` (menos de 30 días → alta sospecha).
2. **Consulta externa:** VirusTotal (detecciones y categorías) y URLScan.io (informes previos del dominio). Ambas son **opcionales** y tolerantes a fallos.
3. **Decisión IA:** Claude recibe todas las señales y devuelve `score`, `verdict`, `indicators` y `explanation` en JSON estricto.
4. **Persistencia:** cada análisis se guarda en SQLite y queda accesible desde `/api/history` y la página *Historial*.

Si Claude no responde correctamente (sin clave, error de red, JSON inválido), el sistema cae a un **veredicto heurístico** generado localmente para que el usuario siempre reciba un resultado.

## Aviso

Los veredictos son orientativos y deben revisarse antes de tomar decisiones críticas de seguridad. La herramienta puede generar falsos positivos y negativos.
