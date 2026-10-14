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

# TEMPORAL (diagnóstico de producción en Render): quitar en el siguiente commit.
_PROXY_HEADER_NAMES = (
    "x-forwarded-for",
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "forwarded",
)


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


def log_trusted_proxy_hops_at_startup() -> None:
    """TEMPORAL: deja constancia del hops efectivo al arrancar (sin secretos)."""
    logger.warning(
        "TEMP proxy_diag startup TRUSTED_PROXY_HOPS_effective=%d "
        "TRUST_CF_CONNECTING_IP=%s TRUSTED_PROXY_CIDRS_configured=%s",
        _trusted_hops(),
        _trust_cf_connecting_ip(),
        bool(os.getenv("TRUSTED_PROXY_CIDRS", "").strip()),
    )


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


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_private(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _log_proxy_diag(
    request: Request,
    *,
    hops: int,
    peer: str,
    present_headers: List[str],
    xff_entries: List[str],
    branch: str,
) -> None:
    """TEMPORAL: metadatos de proxy; IPs solo con UA PhishGuard-Verify*."""
    if getattr(request.state, "_proxy_diag_logged", False):
        return
    request.state._proxy_diag_logged = True
    logger.warning(
        "TEMP proxy_diag hops=%d peer_is_loopback=%s peer_is_private=%s "
        "headers_present=%s xff_entry_count=%d branch=%s",
        hops,
        _is_loopback(peer),
        _is_private(peer),
        present_headers,
        len(xff_entries),
        branch,
    )
    ua = (request.headers.get("user-agent") or "").strip()
    if ua.startswith("PhishGuard-Verify"):
        logger.warning(
            "TEMP proxy_diag_verify ua=%r xff_entries=%s cf_connecting_ip=%r "
            "true_client_ip=%r",
            ua[:80],
            xff_entries,
            request.headers.get("cf-connecting-ip"),
            request.headers.get("true-client-ip"),
        )


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

    present_headers = [name for name in _PROXY_HEADER_NAMES if request.headers.get(name)]
    xff_entries = [
        entry.strip()
        for header in request.headers.getlist("x-forwarded-for")
        for entry in header.split(",")
        if entry.strip()
    ]

    if _trust_cf_connecting_ip():
        cf_ip = _valid_ip(request.headers.get("cf-connecting-ip") or "")
        if cf_ip:
            _log_proxy_diag(
                request,
                hops=_trusted_hops(),
                peer=peer,
                present_headers=present_headers,
                xff_entries=xff_entries,
                branch="cf_connecting_ip",
            )
            return cf_ip

    # Respaldo XFF / peer (también si CF está activado pero la cabecera falta o es inválida).
    client = _ip_from_xff(request, peer)
    branch = "xff_or_peer_fallback"
    if _trusted_hops() == 0:
        branch = "hops0_use_peer"
    _log_proxy_diag(
        request,
        hops=_trusted_hops(),
        peer=peer,
        present_headers=present_headers,
        xff_entries=xff_entries,
        branch=branch,
    )
    return client
