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
| **Historial y estadísticas** | Registro de análisis previos y métricas agregadas en el panel. |
| **Tolerancia a fallos** | Si VirusTotal, URLScan u otros servicios no están disponibles, el análisis continúa con las señales restantes. |

**Veredictos posibles:** `PHISHING` · `SOSPECHOSO` · `LEGÍTIMO`

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

## Instalación y uso en local

### Requisitos previos

- [Git](https://git-scm.com/)
- [Docker](https://www.docker.com/) 24+ y Docker Compose v2
- Claves de API (al menos **Anthropic**; VirusTotal y URLScan son opcionales)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/MCM13/phishguard.git
cd phishguard

# 2. Crear el fichero de entorno desde la plantilla
cp .env.example .env

# 3. Editar .env y añadir tus claves (nunca las subas al repositorio)
#    nano .env   # Linux/macOS
#    notepad .env   # Windows

# 4. Arrancar la aplicación
docker compose up -d --build
```

| Servicio | URL local |
|----------|-----------|
| Frontend | http://localhost:3000 |
| Backend (API) | http://localhost:8000 |

Para detener los contenedores: `docker compose down`

> Las carpetas del proyecto deben llamarse **`frontend/`** y **`scripts/`** para que Docker y los proveedores de despliegue resuelvan las rutas correctamente.

### Desarrollo sin Docker (opcional)

**Backend:** `cd backend` → entorno virtual → `pip install -r requirements.txt` → `uvicorn app.main:app --reload --port 8000`

**Frontend:** `cd frontend` → `npm install` → `npm run dev` (configura `VITE_API_URL` en `.env` apuntando al backend local).

---

## Variables de entorno

Copia `.env.example` a `.env` en la raíz del proyecto. **Todas las claves y secretos van solo en `.env` o en el panel de tu proveedor de hosting** — nunca en el código ni en commits.

| Variable | ¿Obligatoria? | Uso |
|----------|:-------------:|-----|
| `ANTHROPIC_API_KEY` | Sí* | Clave de la API de Anthropic (Claude). |
| `CLAUDE_MODEL` | No | Identificador del modelo de Claude a utilizar. |
| `ANTHROPIC_MAX_PER_HOUR` | No | Control de uso de la API de IA (ventana horaria). |
| `ANTHROPIC_MAX_PER_DAY` | No | Control de uso de la API de IA (ventana diaria). |
| `VIRUSTOTAL_API_KEY` | No | Reputación de URLs vía VirusTotal. |
| `URLSCAN_API_KEY` | No | Informes de URLScan.io; si falta, se omite sin error. |
| `VITE_API_URL` | No | URL pública del backend que usa el navegador (build del frontend). |
| `ALLOWED_ORIGINS` | No | Orígenes permitidos para CORS (lista separada por comas). |
| `FRONTEND_URL` | No | URL pública del frontend (útil en producción). |
| `DATABASE_URL` | No | Cadena de conexión a la base de datos del backend. |

\* Sin clave de Anthropic el sistema puede operar con capacidades reducidas según la configuración del despliegue.

En **Render** y **Cloudflare Pages** define las mismas variables en el panel de Environment / Build variables de cada servicio.

---

## Estructura del proyecto

```
phishguard/
├── backend/              # API REST (FastAPI)
│   ├── app/              # Lógica de aplicación, rutas y servicios
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/             # SPA React (Vite)
│   ├── src/
│   │   ├── components/   # Analizadores, resultados, historial…
│   │   ├── pages/
│   │   └── api.js        # Cliente HTTP hacia el backend
│   ├── package.json
│   └── Dockerfile
├── scripts/              # Utilidades de desarrollo y pruebas
├── docker-compose.yml    # Orquestación local
├── render.yaml           # Referencia de despliegue backend
├── .env.example          # Plantilla de variables (sin secretos)
└── README.md
```

---

## Despliegue en producción

PhishGuard está pensado para un despliegue **desacoplado**:

| Componente | Plataforma | Notas |
|------------|------------|-------|
| **Frontend** | [Cloudflare Pages](https://pages.cloudflare.com) | Build desde la carpeta `frontend/` (`npm ci && npm run build`, salida `dist`). Configura `VITE_API_URL` con la URL pública de tu API. |
| **Backend** | [Render](https://render.com) | Servicio Docker desde `backend/`. Variables de entorno y claves en el panel de Render. |

Tras cada cambio en `VITE_API_URL` hay que **volver a desplegar el frontend** (se inyecta en tiempo de build). Mantén `ALLOWED_ORIGINS` alineado con el dominio real de tu aplicación.

Consulta `render.yaml` y `.env.example` como referencia; los valores concretos de dominio y claves se configuran solo en los paneles de cada proveedor.

---

## Contribuir

Las contribuciones son bienvenidas.

1. Haz **fork** del repositorio.
2. Crea una rama: `git checkout -b feature/mi-mejora`
3. Realiza tus cambios con commits claros.
4. Abre un **Pull Request** describiendo el problema y la solución.

### Seguridad

Si descubres una vulnerabilidad, **no abras un issue público** con detalles explotables. Consulta [SECURITY.md](SECURITY.md) para el proceso de divulgación responsable. Si ese fichero no está publicado aún, usa las [**Security Advisories**](https://github.com/MCM13/phishguard/security/advisories) privadas de GitHub.

---

## Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulta el fichero [LICENSE](LICENSE) para el texto completo.

---

## Aviso legal

Los resultados de PhishGuard son **orientativos**. Revisa siempre las alertas con criterio experto antes de bloquear dominios, reportar incidentes o tomar decisiones operativas. Pueden producirse falsos positivos y falsos negativos.
