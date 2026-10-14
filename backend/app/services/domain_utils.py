"""
Utilidades de dominios compartidas por los extractores de URL y email.

Usa tldextract en modo offline (snapshot de la Public Suffix List incluido
en el paquete) para que el análisis no dependa de descargar la lista en
cada arranque ni de tener salida a Internet.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Dict, Set, Tuple

import tldextract

EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# Marca -> etiquetas de dominio registrable que le pertenecen de verdad.
# Si una marca aparece en el nombre visible de un remitente pero el dominio
# real no es ninguno de estos, es un indicador fuerte de suplantación.
BRAND_DOMAINS: Dict[str, Set[str]] = {
    "paypal": {"paypal"},
    "amazon": {"amazon"},
    "microsoft": {"microsoft", "outlook", "live", "office", "office365"},
    "outlook": {"microsoft", "outlook", "live"},
    "apple": {"apple", "icloud"},
    "icloud": {"apple", "icloud"},
    "google": {"google", "gmail", "youtube"},
    "facebook": {"facebook", "facebookmail", "meta"},
    "instagram": {"instagram", "facebookmail", "meta"},
    "netflix": {"netflix"},
    "bbva": {"bbva"},
    "santander": {"santander", "bancosantander"},
    "caixabank": {"caixabank", "lacaixa"},
    "correos": {"correos"},
    "dhl": {"dhl"},
    "ups": {"ups"},
    "fedex": {"fedex"},
    "seur": {"seur"},
    "hacienda": {"agenciatributaria", "aeat", "hacienda"},
    "agencia tributaria": {"agenciatributaria", "aeat", "hacienda"},
    "dgt": {"dgt"},
    "linkedin": {"linkedin"},
}


def normalize_text(text: str) -> str:
    """Minúsculas y sin tildes, para comparar frases en español e inglés."""
    decomposed = unicodedata.normalize("NFKD", text or "")
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch)).lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def split_host(host: str) -> Tuple[str, str]:
    """
    Devuelve (etiqueta registrable, sufijo) de un hostname.

    Para TLDs que no están en la Public Suffix List (por ejemplo `.test`)
    se toma la última etiqueta como sufijo.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host or _is_ip(host):
        return host, ""
    ext = EXTRACT(host)
    if ext.suffix:
        return ext.domain, ext.suffix
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return host, ""


def registrable_domain(host: str) -> str:
    """`login.paypal.com` -> `paypal.com`; `a.b.example.test` -> `example.test`."""
    label, suffix = split_host(host)
    return f"{label}.{suffix}" if suffix else label


def brands_in_text(text: str) -> Set[str]:
    """Marcas conocidas mencionadas como palabra completa en un texto."""
    normalized = normalize_text(text)
    return {
        brand
        for brand in BRAND_DOMAINS
        if re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", normalized)
    }


def domain_belongs_to_brand(host: str, brand: str) -> bool:
    label, _ = split_host(host)
    return label in BRAND_DOMAINS.get(brand, set())
