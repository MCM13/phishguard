"""
Servicio de integración con URLScan.io.

Hace una búsqueda rápida del *dominio* en su API. Si no hay API key o falla,
devuelve un resultado neutro para no bloquear el análisis principal.

Minimización de datos:
  - No se lanzan escaneos nuevos (POST /scan/): eso publicaría la URL
    analizada (a menudo con tokens de restablecimiento o emails en la query).
  - La búsqueda envía solo el hostname, nunca la ruta ni los parámetros.
  - Si en el futuro se añade un escaneo nuevo, la visibilidad debe ser
    «unlisted» (REQUIRED_SCAN_VISIBILITY), nunca «public».
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

URLSCAN_BASE_URL = "https://urlscan.io/api/v1"
URLSCAN_TIMEOUT_SECONDS = 15

# Obligatorio si algún día se llama a POST /api/v1/scan/.
# «public» indexa la URL en el buscador de URLScan; «unlisted» no.
REQUIRED_SCAN_VISIBILITY = "unlisted"


def _empty_result(reason: str = "") -> Dict[str, Any]:
    return {
        "available": False,
        "malicious": False,
        "total_results": 0,
        "verdict": None,
        "reason": reason,
    }


def _domain_only(url: str) -> str:
    """Extrae solo el hostname: no se reenvían path ni query a URLScan."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or url).strip().lower()


async def analyze_url(url: str) -> Dict[str, Any]:
    """
    Busca informes previos sobre el dominio en URLScan.io.

    No lanza un nuevo escaneo (eso requiere esperar varios segundos y
    expondría la URL completa según la visibilidad del escaneo); sólo
    aprovechamos información histórica del dominio.
    """
    api_key = os.getenv("URLSCAN_API_KEY", "").strip()
    if not api_key:
        return _empty_result("URLSCAN_API_KEY no configurada")

    if not url:
        return _empty_result("URL vacía")

    domain = _domain_only(url)
    if not domain:
        return _empty_result("Dominio vacío")

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    params = {"q": f"domain:{domain}", "size": 5}

    try:
        async with httpx.AsyncClient(timeout=URLSCAN_TIMEOUT_SECONDS) as client:
            response = await client.get(
                f"{URLSCAN_BASE_URL}/search/",
                headers=headers,
                params=params,
            )

            if response.status_code != 200:
                return _empty_result(f"URLScan respondió {response.status_code}")

            data = response.json() or {}
            results = data.get("results") or []
            total = int(data.get("total", len(results)))

            malicious = False
            verdict = None
            for result in results:
                page_verdict = (
                    (result.get("verdicts") or {}).get("overall") or {}
                )
                if page_verdict.get("malicious"):
                    malicious = True
                    verdict = page_verdict
                    break

            return {
                "available": True,
                "malicious": malicious,
                "total_results": total,
                "verdict": verdict,
                "reason": "",
            }
    except Exception as exc:
        logger.warning("Fallo consultando URLScan: %s", exc)
        return _empty_result(f"Error inesperado: {exc.__class__.__name__}")
