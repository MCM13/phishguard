"""
Configuración del rate limiter basado en slowapi.

Aplica límites por IP a los endpoints sensibles para prevenir abuso,
gasto excesivo de créditos de la API de Anthropic y ataques de fuerza bruta
contra el token de administrador.

La IP del cliente la resuelve `app.services.client_ip.get_client_ip`, que
sólo confía en X-Forwarded-For cuando hay proxies de confianza configurados
y toma la entrada que añadió el proxy, no la que envía el cliente.

Los límites se leen en cada petición de estas variables de entorno
(formato de slowapi/limits, p. ej. "10/minute" o "100/hour"):
  RATE_LIMIT_ANALYZE  — POST /api/analyze/*   (por defecto 10/minute)
  RATE_LIMIT_HISTORY  — GET  /api/history     (por defecto 30/minute)
  RATE_LIMIT_STATS    — GET  /api/stats       (por defecto 60/minute)
"""

from __future__ import annotations

import os

from fastapi import Request
from slowapi import Limiter

from app.services.client_ip import get_client_ip


def client_ip_key(request: Request) -> str:
    """Clave del rate limit: la IP real del cliente."""
    return get_client_ip(request)


def analyze_limit() -> str:
    return os.getenv("RATE_LIMIT_ANALYZE", "10/minute")


def history_limit() -> str:
    return os.getenv("RATE_LIMIT_HISTORY", "30/minute")


def stats_limit() -> str:
    return os.getenv("RATE_LIMIT_STATS", "60/minute")


# Único Limiter global que se importa desde main.py y los routers.
# NOTA: headers_enabled=False intencionadamente. Activarlo obligaría a que
# cada endpoint decorado reciba `response: Response` además de `request`,
# y nuestra respuesta 429 ya transporta `Retry-After` desde el handler.
limiter = Limiter(key_func=client_ip_key, headers_enabled=False)
