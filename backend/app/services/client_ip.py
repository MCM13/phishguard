"""
Resolución de la IP real del cliente para rate limiting y auditoría.

X-Forwarded-For es una lista "cliente, proxy1, proxy2, ..." en la que cada
proxy AÑADE a la derecha la IP de quien le conectó. Todo lo que hay a la
izquierda de lo añadido por nuestros proxies lo controla el cliente y puede
ser falso, así que nunca se usa el primer valor.

Configuración:
  TRUSTED_PROXY_HOPS  Número de proxies de confianza delante de la app que
                      añaden su entrada a X-Forwarded-For. 0 (por defecto,
                      local / Docker Compose) = se ignora la cabecera y se usa
                      la IP del socket. En Render es 1: su balanceador añade la
                      IP del cliente como último elemento.
  TRUSTED_PROXY_CIDRS Opcional. Lista CSV de redes desde las que se aceptan
                      esas cabeceras (p. ej. "10.0.0.0/8"). Si se define y la
                      conexión llega desde fuera de ellas, se usa la IP del
                      socket aunque TRUSTED_PROXY_HOPS sea > 0.

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

# TEMPORAL (diagnóstico de producción en Render): quitar tras identificar
# qué cabecera trae la IP real del cliente. Nunca registra valores de IP.
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


def log_trusted_proxy_hops_at_startup() -> None:
    """TEMPORAL: deja constancia del hops efectivo al arrancar (sin secretos)."""
    logger.warning(
        "TEMP proxy_diag startup TRUSTED_PROXY_HOPS_effective=%d "
        "TRUSTED_PROXY_CIDRS_configured=%s",
        _trusted_hops(),
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
    # Una sola línea por petición (rate limit y auditoría llaman ambos a get_client_ip).
    if getattr(request.state, "_proxy_diag_logged", False):
        return
    request.state._proxy_diag_logged = True
    xff_entry_count = len(xff_entries)
    logger.warning(
        "TEMP proxy_diag hops=%d peer_is_loopback=%s peer_is_private=%s "
        "headers_present=%s xff_entry_count=%d branch=%s",
        hops,
        _is_loopback(peer),
        _is_private(peer),
        present_headers,
        xff_entry_count,
        branch,
    )
    # Solo en peticiones de verificación propias: volcar valores para ver
    # qué entrada/cabecera es la IP pública real y cuáles son falsificables.
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


def _is_private(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """IP del cliente según la cadena de proxies de confianza configurada."""
    peer = request.client.host if request.client and request.client.host else "unknown"

    present_headers = [name for name in _PROXY_HEADER_NAMES if request.headers.get(name)]
    xff_entries = [
        entry.strip()
        for header in request.headers.getlist("x-forwarded-for")
        for entry in header.split(",")
        if entry.strip()
    ]
    xff_entry_count = len(xff_entries)

    hops = _trusted_hops()
    if hops == 0:
        _log_proxy_diag(
            request,
            hops=hops,
            peer=peer,
            present_headers=present_headers,
            xff_entries=xff_entries,
            branch="hops0_use_peer",
        )
        return peer

    networks = _trusted_networks()
    if networks:
        peer_ip = _valid_ip(peer)
        if peer_ip is None or not any(ipaddress.ip_address(peer_ip) in net for net in networks):
            _log_proxy_diag(
                request,
                hops=hops,
                peer=peer,
                present_headers=present_headers,
                xff_entries=xff_entries,
                branch="cidr_reject_use_peer",
            )
            return peer

    if xff_entry_count < hops:
        # Menos entradas que proxies: la petición no ha pasado por la cadena
        # esperada, así que la cabecera no es fiable.
        _log_proxy_diag(
            request,
            hops=hops,
            peer=peer,
            present_headers=present_headers,
            xff_entries=xff_entries,
            branch="xff_too_short_use_peer",
        )
        return peer

    client = _valid_ip(xff_entries[-hops])
    if client:
        _log_proxy_diag(
            request,
            hops=hops,
            peer=peer,
            present_headers=present_headers,
            xff_entries=xff_entries,
            branch="xff_entries_minus_hops",
        )
        return client

    _log_proxy_diag(
        request,
        hops=hops,
        peer=peer,
        present_headers=present_headers,
        xff_entries=xff_entries,
        branch="xff_invalid_use_peer",
    )
    return peer
