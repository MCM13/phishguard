"""
Punto de entrada de la API de PhishGuard.

Configura la aplicación FastAPI, los middlewares (CORS), incluye los
routers de análisis e historial e inicializa la base de datos al arrancar.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.routers import analyze, history

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
