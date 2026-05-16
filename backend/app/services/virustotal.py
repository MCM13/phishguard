"""
Servicio de integración con VirusTotal API v3.

Permite consultar el veredicto de una URL en VirusTotal. Si la API key
no está configurada o la llamada falla por cualquier motivo, devuelve un
diccionario con valores neutros para que el resto del pipeline continúe.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_TIMEOUT_SECONDS = 15


def _empty_result(reason: str = "") -> Dict[str, Any]:
    """Resultado neutro cuando no podemos obtener datos de VirusTotal."""
    return {
        "available": False,
        "positives": 0,
        "total_engines": 0,
        "categories": [],
        "reputation": None,
        "reason": reason,
    }


async def analyze_url(url: str) -> Dict[str, Any]:
    """
    Consulta VirusTotal por una URL y devuelve un resumen con:
      - positives: motores que la marcan como maliciosa o sospechosa
      - total_engines: total de motores que analizaron
      - categories: categorías asignadas por los motores
      - reputation: puntuación de reputación del recurso

    Devuelve un dict "vacío" si no hay API key o si la llamada falla.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return _empty_result("VIRUSTOTAL_API_KEY no configurada")

    if not url:
        return _empty_result("URL vacía")

    # VirusTotal usa el ID = base64(url) sin padding como identificador
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=VT_TIMEOUT_SECONDS) as client:
            response = await client.get(endpoint, headers=headers)

            # Si la URL no existe aún en VT, intentamos enviarla para análisis
            if response.status_code == 404:
                submit = await client.post(
                    f"{VT_BASE_URL}/urls",
                    headers=headers,
                    data={"url": url},
                )
                if submit.status_code not in (200, 201):
                    return _empty_result(
                        f"VT no tiene esta URL y el envío falló ({submit.status_code})"
                    )
                # No esperamos al análisis: devolvemos resultado neutro
                return _empty_result("URL recién enviada a VirusTotal")

            if response.status_code != 200:
                return _empty_result(
                    f"VirusTotal respondió {response.status_code}"
                )

            data = response.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {}) or {}

            positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
            total = sum(int(v or 0) for v in stats.values())

            return {
                "available": True,
                "positives": positives,
                "total_engines": total,
                "categories": list((attrs.get("categories") or {}).values()),
                "reputation": attrs.get("reputation"),
                "reason": "",
            }
    except Exception as exc:
        logger.warning("Fallo consultando VirusTotal: %s", exc)
        return _empty_result(f"Error inesperado: {exc.__class__.__name__}")
