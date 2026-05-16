"""
Servicio de integración con URLScan.io.

Hace una búsqueda rápida de la URL en su API. Si no hay API key o falla,
devuelve un resultado neutro para no bloquear el análisis principal.
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


def _empty_result(reason: str = "") -> Dict[str, Any]:
    return {
        "available": False,
        "malicious": False,
        "total_results": 0,
        "verdict": None,
        "reason": reason,
    }


async def analyze_url(url: str) -> Dict[str, Any]:
    """
    Busca informes previos sobre la URL/dominio en URLScan.io.

    No lanza un nuevo escaneo (eso requiere esperar varios segundos);
    sólo aprovechamos información histórica del dominio.
    """
    api_key = os.getenv("URLSCAN_API_KEY", "").strip()
    if not api_key:
        return _empty_result("URLSCAN_API_KEY no configurada")

    if not url:
        return _empty_result("URL vacía")

    domain = urlparse(url if "://" in url else f"http://{url}").hostname or url
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
