"""
Configuración de CORS para FastAPI.

En producción (Render, dominio propio) el navegador solo acepta respuestas si
el backend devuelve Access-Control-Allow-Origin con el origen EXACTO del
frontend (esquema + host + puerto). Un dominio distinto al configurado en
ALLOWED_ORIGINS provoca errores en el navegador que a menudo se confunden
con fallos de API o de base de datos.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def _normalize_origin(origin: str) -> str:
    """Quita espacios y barra final para comparar orígenes de forma consistente."""
    return origin.strip().rstrip("/")


def get_allowed_origins() -> list[str]:
    """
    Construye la lista de orígenes permitidos para CORSMiddleware.

    Variables:
      ALLOWED_ORIGINS — CSV de orígenes (ej. https://app.onrender.com).
                        Usar "*" solo en desarrollo.
      FRONTEND_URL    — URL pública del frontend; se añade automáticamente
                        si no está ya en ALLOWED_ORIGINS (útil en Render).
    """
    raw = os.getenv("ALLOWED_ORIGINS", "*").strip()
    if raw == "*":
        return ["*"]

    origins: list[str] = []
    seen: set[str] = set()

    for part in raw.split(","):
        o = _normalize_origin(part)
        if o and o not in seen:
            origins.append(o)
            seen.add(o)

    frontend_url = _normalize_origin(os.getenv("FRONTEND_URL", ""))
    if frontend_url and frontend_url not in seen:
        origins.append(frontend_url)
        seen.add(frontend_url)
        logger.info("CORS: origen del frontend añadido desde FRONTEND_URL=%s", frontend_url)

    if not origins:
        logger.warning(
            "ALLOWED_ORIGINS vacío; usando '*' (no recomendado en producción)"
        )
        return ["*"]

    return origins
