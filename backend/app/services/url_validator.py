"""
Validación de URLs antes del análisis.

Prevenir SSRF (Server-Side Request Forgery) es crítico porque algunas de
las dependencias del backend (whois, futuras peticiones HTTP) acaban
contactando con el host indicado en la URL. Si el atacante puede apuntar
a IPs privadas, podría escanear la red interna del VPS, llegar a metadata
endpoints de cloud (169.254.169.254), o usar el backend como proxy.

Esta utilidad realiza dos comprobaciones:

  1. Formato: la URL debe tener esquema http(s) y host no vacío.
  2. Destino: si el host es una IP literal o resoluble, no puede ser
     privada, loopback, link-local, multicast, reservada ni metadata.

Si no se puede resolver DNS (timeout, host inexistente) se DEJA pasar:
es responsabilidad del análisis posterior decidir si eso es indicador
de phishing o no — bloquearlo aquí daría falsos positivos para dominios
recién registrados que aún no propagaron.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Esquemas aceptados. Cualquier otro (ftp://, file://, javascript:, data:)
# se rechaza explícitamente.
_ALLOWED_SCHEMES = {"http", "https"}

# Hostnames que NO deben analizarse (apuntan a la propia infraestructura).
_FORBIDDEN_HOSTNAMES = {
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
}

# Direcciones IP literales especialmente sensibles más allá del rango privado.
_FORBIDDEN_LITERAL_IPS = {
    "0.0.0.0",
    "::",
    # Metadata service de AWS / GCP / Azure (clásico target de SSRF)
    "169.254.169.254",
}


class UnsafeURLError(ValueError):
    """Se lanza cuando la URL no puede analizarse por motivos de seguridad."""


def _is_private_or_reserved(ip: ipaddress._BaseAddress) -> bool:
    """True si la IP es privada, loopback, link-local o reservada."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_hostname(hostname: str) -> Tuple[ipaddress._BaseAddress, ...]:
    """Resuelve un hostname a todas sus IPs (v4 y v6)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        logger.info("No se pudo resolver %s: %s — se permite continuar", hostname, exc)
        return ()

    addresses = set()
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            addresses.add(ipaddress.ip_address(sockaddr[0]))
        elif family == socket.AF_INET6:
            # Eliminamos el scope id si viene (`fe80::1%eth0` → `fe80::1`)
            host = sockaddr[0].split("%", 1)[0]
            addresses.add(ipaddress.ip_address(host))
    return tuple(addresses)


def validate_public_url(raw_url: str) -> str:
    """
    Valida que la URL apunte a un destino público analizable.

    Returns:
        La URL normalizada (con esquema y sin espacios extra).

    Raises:
        UnsafeURLError: con un mensaje explicando por qué se rechaza.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise UnsafeURLError("La URL es obligatoria.")

    url = raw_url.strip()

    # Si no trae esquema, lo rechazamos: forzamos a que el usuario indique
    # explícitamente http o https. Esto cierra ambigüedades del estilo
    # `localhost:8000` que urlparse interpreta como esquema "localhost".
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(
            "La URL debe empezar por http:// o https://."
        )

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        raise UnsafeURLError("La URL no contiene un dominio válido.")

    if hostname in _FORBIDDEN_HOSTNAMES:
        raise UnsafeURLError(
            "No se permiten URLs apuntando a localhost o direcciones internas."
        )

    if hostname in _FORBIDDEN_LITERAL_IPS:
        raise UnsafeURLError(
            "No se permiten URLs apuntando a IPs reservadas o de metadata."
        )

    # Si el hostname es ya una IP literal, validamos directamente
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if _is_private_or_reserved(literal_ip):
            raise UnsafeURLError(
                "No se permiten URLs apuntando a IPs privadas, de loopback "
                "o reservadas (10.x, 127.x, 192.168.x, 169.254.x, ::1, ...)."
            )
        return url

    # Hostname textual: resolvemos y validamos cada IP devuelta.
    for ip in _resolve_hostname(hostname):
        if _is_private_or_reserved(ip):
            raise UnsafeURLError(
                f"El dominio {hostname} resuelve a una dirección privada o "
                "reservada. No se puede analizar por motivos de seguridad."
            )

    return url
