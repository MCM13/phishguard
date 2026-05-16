"""
Servicio de extracción de features de URLs.

A partir de una URL devuelve un diccionario con todas las señales que se
utilizarán para que Claude tome una decisión informada:
longitud, número de subdominios, palabras clave sospechosas, caracteres
especiales, TLD inusual, edad del dominio (vía python-whois) y si usa HTTPS.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import tldextract

logger = logging.getLogger(__name__)

# Palabras clave que suelen aparecer en URLs de phishing
SUSPICIOUS_KEYWORDS: List[str] = [
    "login",
    "secure",
    "account",
    "update",
    "verify",
    "bank",
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "password",
    "confirm",
]

# Caracteres considerados sospechosos en URLs
SUSPICIOUS_CHARS: List[str] = ["@", "--", "%", "~"]

# TLDs considerados habituales / de confianza
COMMON_TLDS = {"com", "es", "org", "net", "gov"}


def _normalize_url(raw_url: str) -> str:
    """Añade esquema http:// si la URL no lo trae, para poder parsearla."""
    url = (raw_url or "").strip()
    if not url:
        return ""
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return url


def _get_domain_age_days(domain: str) -> Optional[int]:
    """
    Calcula la edad del dominio en días usando python-whois.

    Si la consulta falla (sin conexión, dominio desconocido, etc.) devuelve
    None para que el resto del análisis pueda continuar sin bloquearse.
    """
    if not domain:
        return None

    try:
        # Import perezoso porque python-whois hace peticiones de red
        import whois  # type: ignore

        data = whois.whois(domain)
        created = data.creation_date if data else None

        # python-whois a veces devuelve una lista de fechas
        if isinstance(created, list):
            created = created[0] if created else None

        if not isinstance(created, datetime):
            return None

        # Normalizamos a UTC para poder restar fechas
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return max(0, (now - created).days)
    except Exception as exc:  # pragma: no cover - dependiente de red
        logger.warning("No se pudo obtener edad del dominio %s: %s", domain, exc)
        return None


def extract_url_features(raw_url: str) -> Dict[str, Any]:
    """
    Devuelve un diccionario con todas las features extraídas de la URL.

    El diccionario es JSON-serializable y se inyecta directamente en el
    prompt que se envía a Claude.
    """
    url = _normalize_url(raw_url)
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    # Subdominios: tldextract devuelve algo como "www.mail" -> 2 subdominios
    subdomain_str = extracted.subdomain or ""
    subdomain_count = len([s for s in subdomain_str.split(".") if s]) if subdomain_str else 0

    # Coincidencias de palabras clave sospechosas (comparación case-insensitive)
    lower_url = url.lower()
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]

    # Caracteres sospechosos detectados
    char_hits = [ch for ch in SUSPICIOUS_CHARS if ch in url]

    tld = (extracted.suffix or "").lower()
    unusual_tld = bool(tld) and tld not in COMMON_TLDS

    full_domain = ".".join(part for part in [extracted.domain, extracted.suffix] if part)
    domain_age_days = _get_domain_age_days(full_domain) if full_domain else None

    features: Dict[str, Any] = {
        "url": url,
        "domain": full_domain,
        "tld": tld,
        "url_length": len(url),
        "subdomain_count": subdomain_count,
        "subdomain": subdomain_str,
        "suspicious_keywords": keyword_hits,
        "suspicious_keyword_count": len(keyword_hits),
        "suspicious_characters": char_hits,
        "suspicious_character_count": len(char_hits),
        "unusual_tld": unusual_tld,
        "uses_https": parsed.scheme.lower() == "https",
        "uses_ip_address": _is_ip_address(parsed.hostname or ""),
        "domain_age_days": domain_age_days,
        "young_domain": (
            domain_age_days is not None and domain_age_days < 30
        ),
    }

    return features


def _is_ip_address(hostname: str) -> bool:
    """Devuelve True si el hostname es una dirección IP en lugar de un dominio."""
    if not hostname:
        return False
    parts = hostname.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
