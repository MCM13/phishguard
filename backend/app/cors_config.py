"""
Configuración de CORS para FastAPI.

En producción (Render, dominio propio) el navegador solo acepta respuestas si
el backend devuelve Access-Control-Allow-Origin con el origen EXACTO del
frontend (esquema + host + puerto). Un dominio distinto al configurado en
ALLOWED_ORIGINS provoca errores en el navegador que a menudo se confunden
con fallos de API o de base de datos.

Política (cerrada por defecto):
  - Sin ALLOWED_ORIGINS ni FRONTEND_URL, en desarrollo solo se permiten los
    orígenes del frontend local; en producción no se permite ninguno.
  - "*" solo se acepta si se pide explícitamente y no es producción.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

DEV_DEFAULT_ORIGINS = ("http://localhost:3000", "http://127.0.0.1:3000")


def _normalize_origin(origin: str) -> str:
    """Quita espacios y barra final para comparar orígenes de forma consistente."""
    return origin.strip().rstrip("/")


def _is_production() -> bool:
    return os.getenv("ENVIRONMENT", "").strip().lower() == "production"


def get_allowed_origins() -> list[str]:
    """
    Construye la lista de orígenes permitidos para CORSMiddleware.

    Variables:
      ALLOWED_ORIGINS — CSV de orígenes (ej. https://app.example.com).
                        "*" solo se respeta fuera de producción.
      FRONTEND_URL    — URL pública del frontend; se añade automáticamente
                        si no está ya en ALLOWED_ORIGINS (útil en Render).
    """
    production = _is_production()
    raw = os.getenv("ALLOWED_ORIGINS", "").strip()

    if raw == "*":
        if production:
            logger.error(
                "ALLOWED_ORIGINS='*' no se admite con ENVIRONMENT=production; "
                "CORS no permitirá ningún origen hasta que se configure el dominio real."
            )
            raw = ""
        else:
            logger.warning("CORS abierto a cualquier origen (ALLOWED_ORIGINS='*'); solo para desarrollo.")
            return ["*"]

    origins: list[str] = []
    seen: set[str] = set()

    for part in raw.split(","):
        o = _normalize_origin(part)
        if o and o != "*" and o not in seen:
            origins.append(o)
            seen.add(o)

    frontend_url = _normalize_origin(os.getenv("FRONTEND_URL", ""))
    if frontend_url and frontend_url not in seen:
        origins.append(frontend_url)
        seen.add(frontend_url)
        logger.info("CORS: origen del frontend añadido desde FRONTEND_URL=%s", frontend_url)

    if origins:
        return origins

    if production:
        logger.error(
            "ALLOWED_ORIGINS y FRONTEND_URL vacíos en producción: CORS no permitirá ningún origen."
        )
        return []

    logger.warning(
        "ALLOWED_ORIGINS vacío; se permiten solo los orígenes locales %s.",
        ", ".join(DEV_DEFAULT_ORIGINS),
    )
    return list(DEV_DEFAULT_ORIGINS)
