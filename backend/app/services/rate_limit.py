"""
Configuración del rate limiter basado en slowapi.

Aplica límites por IP a los endpoints sensibles para prevenir abuso,
gasto excesivo de créditos de la API de Anthropic y ataques de fuerza bruta.

Cuando la aplicación corre detrás de un proxy/CDN (Render, Cloudflare,
Nginx...), la IP real del cliente viene en la cabecera `X-Forwarded-For`.
La función `client_ip_key` lee esa cabecera, tomando la primera IP de la
cadena (la del cliente original), y si no existe cae a la IP del socket.
"""

from __future__ import annotations

from typing import Optional

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def _first_forwarded_ip(header_value: str) -> Optional[str]:
    """Devuelve la primera IP no vacía de un X-Forwarded-For (CSV)."""
    for part in header_value.split(","):
        ip = part.strip()
        if ip:
            return ip
    return None


def client_ip_key(request: Request) -> str:
    """
    Identifica al cliente por IP, priorizando X-Forwarded-For si existe.

    En despliegues directos (sin proxy) usa la IP del socket TCP.
    Si todo lo anterior falla, devuelve un marcador único para evitar
    KeyError de slowapi.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        ip = _first_forwarded_ip(forwarded)
        if ip:
            return ip
    return get_remote_address(request) or "unknown"


# Único Limiter global que se importa desde main.py y los routers.
# NOTA: headers_enabled=False intencionadamente. Activarlo obligaría a que
# cada endpoint decorado reciba `response: Response` además de `request`,
# y nuestra respuesta 429 ya transporta `Retry-After` desde el handler.
limiter = Limiter(key_func=client_ip_key, headers_enabled=False)
