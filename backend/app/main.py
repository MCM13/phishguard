"""
Punto de entrada de la API de PhishGuard.

Configura la aplicación FastAPI, los middlewares (CORS), incluye los
routers de análisis e historial e inicializa la base de datos al arrancar.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.database import init_db
from app.middleware.audit_log import AuditLogMiddleware
from app.middleware.request_guards import (
    JSONContentTypeMiddleware,
    MaxBodySizeMiddleware,
    RequestTimeoutMiddleware,
)
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.routers import analyze, history
from app.services.rate_limit import limiter

# Configuración de logging para producción
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="PhishGuard API",
    description=(
        "API de análisis de phishing impulsada por IA. Recibe URLs o emails "
        "sospechosos y devuelve un score, un veredicto y una explicación."
    ),
    version="1.0.0",
)

# CORS: en desarrollo permitimos cualquier origen; en producción se puede
# restringir mediante la variable de entorno ALLOWED_ORIGINS.
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "*")
allowed_origins = (
    ["*"] if allowed_origins_env.strip() == "*"
    else [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# NOTA: Starlette ejecuta los middlewares en ORDEN INVERSO al de registro
# (los últimos añadidos se ejecutan primero). El orden buscado de fuera
# hacia dentro es:
#   AuditLog → SecurityHeaders → MaxBodySize → ContentType → Timeout → RateLimit → handler
# Por tanto los registramos en el orden inverso (el primero en código es el
# más interno).

# Rate limiting: el limiter se inyecta en app.state para que los routers
# puedan referenciarlo, y el middleware procesa las cabeceras X-RateLimit-*.
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# Timeout global de 30 s — antes del rate limit no tiene sentido,
# pero antes del handler sí (cancela handlers lentos).
app.add_middleware(RequestTimeoutMiddleware)

# Validación de Content-Type antes de leer el body.
app.add_middleware(JSONContentTypeMiddleware)

# Tamaño máximo del body antes de cualquier procesamiento.
app.add_middleware(MaxBodySizeMiddleware)

# Cabeceras de seguridad HTTP en todas las respuestas (OWASP Secure Headers).
app.add_middleware(SecurityHeadersMiddleware)

# Auditoría: registra todas las peticiones en JSON (timestamp, IP, ruta,
# status, latencia y veredicto si aplica). NO loguea bodies ni API keys.
# Va el primero registrado para que sea el MÁS EXTERNO y capture todo.
app.add_middleware(AuditLogMiddleware)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Devuelve un 429 con mensaje claro en español cuando se excede el límite."""
    return JSONResponse(
        status_code=429,
        content={
            "detail": (
                "Has alcanzado el límite de peticiones por minuto. "
                "Por favor, espera un momento antes de volver a intentarlo."
            ),
            "limit": str(exc.detail),
        },
        headers={"Retry-After": "60"},
    )


@app.on_event("startup")
def on_startup() -> None:
    """Inicializa la base de datos al arrancar la aplicación."""
    init_db()


@app.get("/", tags=["health"])
def root() -> dict:
    """Endpoint de salud básico para healthchecks."""
    return {"status": "ok", "service": "PhishGuard API", "version": "1.0.0"}


# Registro de routers
app.include_router(analyze.router)
app.include_router(history.router)
