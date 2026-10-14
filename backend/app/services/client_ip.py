"""
Resolución de la IP real del cliente para rate limiting y auditoría.

X-Forwarded-For es una lista "cliente, proxy1, proxy2, ..." en la que cada
proxy AÑADE a la derecha la IP de quien le conectó. Todo lo que hay a la
izquierda de lo añadido por nuestros proxies lo controla el cliente y puede
ser falso, así que nunca se usa el primer valor.

Configuración:
  TRUST_CF_CONNECTING_IP  Si es true y llega CF-Connecting-IP con una IP
                          válida, se usa esa cabecera (Cloudflare la fija y
                          rechaza la que envía el cliente). Solo activar con
                          Cloudflare delante; sin él, el cliente podría
                          falsificarla. Por defecto false (local / Compose).
  TRUSTED_PROXY_HOPS      Número de proxies de confianza delante de la app que
                          añaden su entrada a X-Forwarded-For. 0 (por defecto,
                          local / Docker Compose) = se ignora la cabecera y se
                          usa la IP del socket. Se usa como respaldo si
                          TRUST_CF_CONNECTING_IP no aporta una IP válida.
  TRUSTED_PROXY_CIDRS     Opcional. Lista CSV de redes desde las que se aceptan
                          esas cabeceras (p. ej. "10.0.0.0/8"). Si se define y
                          la conexión llega desde fuera de ellas, se usa la IP
                          del socket aunque TRUSTED_PROXY_HOPS sea > 0.

uvicorn se arranca con --no-proxy-headers para que esta función sea la
única que interpreta X-Forwarded-For.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import List

from starlette.requests import Request

logger = logging.getLogger(__name__)


def _trusted_hops() -> int:
    raw = os.getenv("TRUSTED_PROXY_HOPS", "0").strip()
    try:
        return max(0, int(raw))
    except ValueError:
        logger.warning("TRUSTED_PROXY_HOPS=%r no es un entero; se usa 0", raw)
        return 0


def _trust_cf_connecting_ip() -> bool:
    return os.getenv("TRUST_CF_CONNECTING_IP", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _trusted_networks() -> List[ipaddress._BaseNetwork]:
    networks = []
    for part in os.getenv("TRUSTED_PROXY_CIDRS", "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            logger.warning("TRUSTED_PROXY_CIDRS contiene una red inválida: %r", part)
    return networks


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _ip_from_xff(request: Request, peer: str) -> str:
    """Respaldo: TRUSTED_PROXY_HOPS sobre X-Forwarded-For."""
    hops = _trusted_hops()
    if hops == 0:
        return peer

    networks = _trusted_networks()
    if networks:
        peer_ip = _valid_ip(peer)
        if peer_ip is None or not any(ipaddress.ip_address(peer_ip) in net for net in networks):
            return peer

    entries = [
        entry.strip()
        for header in request.headers.getlist("x-forwarded-for")
        for entry in header.split(",")
        if entry.strip()
    ]
    if len(entries) < hops:
        return peer

    return _valid_ip(entries[-hops]) or peer


def get_client_ip(request: Request) -> str:
    """IP del cliente según Cloudflare (opcional) o la cadena de proxies."""
    peer = request.client.host if request.client and request.client.host else "unknown"

    if _trust_cf_connecting_ip():
        cf_ip = _valid_ip(request.headers.get("cf-connecting-ip") or "")
        if cf_ip:
            return cf_ip

    return _ip_from_xff(request, peer)
