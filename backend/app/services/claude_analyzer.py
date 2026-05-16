"""
Servicio que envía las features extraídas a la API de Anthropic Claude y
parsea su respuesta en un veredicto estructurado.

Construye exactamente el prompt definido en las especificaciones del
proyecto y exige que Claude devuelva únicamente JSON.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from anthropic import Anthropic

logger = logging.getLogger(__name__)

# Modelo de Claude usado para el análisis.
# La especificación original pedía `claude-sonnet-4-20250514`, pero ese id
# ya no existe en la API. Usamos el equivalente vigente más cercano
# (Claude Sonnet 4.5). Se puede sobrescribir con la variable CLAUDE_MODEL.
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5-20250929")
CLAUDE_MAX_TOKENS = 1024


def _build_prompt(features: Dict[str, Any], vt_result: Optional[Dict[str, Any]]) -> str:
    """
    Construye el prompt en español que se enviará a Claude.

    El prompt corresponde literalmente al definido en las especificaciones
    del proyecto. Si VirusTotal no está disponible se reflejan ceros y
    una nota explícita en las categorías para que la IA lo tenga en cuenta.
    """
    vt_positives = 0
    vt_categories: List[str] = []

    if vt_result and vt_result.get("available"):
        vt_positives = int(vt_result.get("positives") or 0)
        vt_categories = list(vt_result.get("categories") or [])
    elif vt_result:
        vt_categories = [f"(VirusTotal no disponible: {vt_result.get('reason', '')})"]

    features_json = json.dumps(features, ensure_ascii=False, indent=2, default=str)
    categories_str = ", ".join(vt_categories) if vt_categories else "ninguna"

    return f"""Eres un experto en ciberseguridad especializado en detección de phishing.
Analiza los siguientes datos y determina si la URL/email es phishing.

=== FEATURES EXTRAÍDAS ===
{features_json}

=== RESULTADOS VIRUSTOTAL ===
Detecciones positivas: {vt_positives}/72 motores
Categorías: {categories_str}

=== INSTRUCCIONES ===
Responde ÚNICAMENTE en JSON con esta estructura exacta, sin texto adicional:
{{
  "score": <número entero 0-100>,
  "verdict": <"PHISHING" | "SOSPECHOSO" | "LEGÍTIMO">,
  "indicators": [
    {{"name": "...", "severity": "high|medium|low", "detail": "..."}}
  ],
  "explanation": "<explicación clara en español de 2-3 frases>"
}}"""


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """
    Intenta extraer el primer bloque JSON válido de la respuesta de Claude.

    Aunque le pedimos JSON puro, hacemos un parseo defensivo por si añade
    texto antes o después.
    """
    if not text:
        return None

    text = text.strip()
    # Eliminamos bloques de código markdown si los hubiera
    fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1)

    # Buscamos el primer { ... } balanceado de forma simple
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    candidate = text[start : end + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def _fallback_response(features: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """
    Veredicto heurístico de emergencia si Claude no responde correctamente.

    Calcula un score basándose en las features extraídas para que el usuario
    siempre reciba un resultado utilizable. Esta heurística no pretende
    sustituir a la IA, sólo dar un veredicto razonable cuando falla.
    """
    score = 10
    indicators: List[Dict[str, str]] = []

    # TLDs gratuitos abusados sistemáticamente en campañas de phishing
    free_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "info"}

    # Marcas que se suplantan con frecuencia. Si aparecen en el dominio
    # pero el dominio no es el oficial, es una bandera roja muy fuerte.
    impersonated_brands = {
        "paypal", "amazon", "microsoft", "apple", "google", "facebook",
        "instagram", "netflix", "bbva", "santander", "correos", "dhl",
        "ups", "fedex",
    }

    if features.get("young_domain"):
        score += 35
        indicators.append({
            "name": "Dominio recién registrado",
            "severity": "high",
            "detail": "El dominio tiene menos de 30 días de antigüedad.",
        })

    keyword_hits = features.get("suspicious_keywords") or []
    if keyword_hits:
        # Base 12 + 6 por cada palabra extra, con un techo de 35
        bonus = min(35, 12 + 6 * (len(keyword_hits) - 1))
        score += bonus
        severity = "high" if len(keyword_hits) >= 3 else "medium"
        indicators.append({
            "name": "Palabras clave sospechosas",
            "severity": severity,
            "detail": f"Detectadas {len(keyword_hits)} palabras: {keyword_hits}.",
        })

    if features.get("suspicious_character_count", 0) >= 1:
        score += 10
        indicators.append({
            "name": "Caracteres sospechosos en la URL",
            "severity": "medium",
            "detail": f"Caracteres: {features.get('suspicious_characters', [])}.",
        })

    tld = (features.get("tld") or "").lower()
    if tld in free_tlds:
        score += 20
        indicators.append({
            "name": "TLD gratuito frecuente en phishing",
            "severity": "high",
            "detail": f"El TLD .{tld} se usa habitualmente en campañas maliciosas.",
        })
    elif features.get("unusual_tld"):
        score += 10
        indicators.append({
            "name": "TLD poco habitual",
            "severity": "low",
            "detail": f"TLD detectado: .{tld}",
        })

    # Suplantación de marca: por ejemplo "paypal" en el dominio pero no
    # siendo paypal.com, paypal.es, etc.
    domain = (features.get("domain") or "").lower()
    subdomain = (features.get("subdomain") or "").lower()
    haystack = f"{subdomain}.{domain}"
    brands_found = [b for b in impersonated_brands if b in haystack]
    # Filtramos las que coinciden con el dominio oficial (paypal.com → ok)
    real_brands_impersonated = [
        b for b in brands_found if not domain.startswith(f"{b}.")
    ]
    if real_brands_impersonated:
        score += 25
        indicators.append({
            "name": "Posible suplantación de marca",
            "severity": "high",
            "detail": (
                f"El dominio incluye {real_brands_impersonated} pero no es el "
                "dominio oficial de esas marcas."
            ),
        })

    if features.get("uses_https") is False:
        score += 10
        indicators.append({
            "name": "Sin HTTPS",
            "severity": "medium",
            "detail": "La URL no usa una conexión cifrada.",
        })
    if features.get("uses_ip_address"):
        score += 20
        indicators.append({
            "name": "Dirección IP en lugar de dominio",
            "severity": "high",
            "detail": "Usar IP directa es típico de campañas de phishing.",
        })

    # Penalización adicional por exceso de subdominios concatenados
    if features.get("subdomain_count", 0) >= 2:
        score += 10
        indicators.append({
            "name": "Múltiples subdominios",
            "severity": "medium",
            "detail": (
                f"La URL tiene {features.get('subdomain_count')} niveles de "
                "subdominio, técnica común en phishing."
            ),
        })

    score = max(0, min(100, score))
    if score >= 61:
        verdict = "PHISHING"
    elif score >= 31:
        verdict = "SOSPECHOSO"
    else:
        verdict = "LEGÍTIMO"

    return {
        "score": score,
        "verdict": verdict,
        "indicators": indicators,
        "explanation": (
            "No se pudo contactar con la IA, por lo que este veredicto se ha "
            f"generado mediante reglas heurísticas internas. Motivo: {reason}."
        ),
    }


async def analyze_with_claude(
    features: Dict[str, Any],
    vt_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Envía las features a Claude y devuelve el veredicto estructurado.

    Si no hay API key, si la llamada falla o si la respuesta no es JSON
    válido, devolvemos un veredicto heurístico generado localmente.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return _fallback_response(features, "ANTHROPIC_API_KEY no configurada")

    prompt = _build_prompt(features, vt_result)

    try:
        client = Anthropic(api_key=api_key)
        # La librería oficial es síncrona; FastAPI la ejecuta en su threadpool
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=CLAUDE_MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
        )

        # La respuesta es una lista de bloques de contenido
        raw_text = "".join(
            getattr(block, "text", "") for block in (message.content or [])
        ).strip()

        parsed = _extract_json(raw_text)
        if not parsed:
            logger.warning("Claude no devolvió JSON válido: %s", raw_text[:200])
            return _fallback_response(features, "respuesta no parseable")

        # Normalizamos y validamos los campos esperados
        return _normalize_response(parsed)
    except Exception as exc:
        logger.exception("Fallo llamando a Claude: %s", exc)
        return _fallback_response(features, f"error API ({exc.__class__.__name__})")


def _normalize_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Garantiza que la respuesta cumple el contrato esperado por la API."""
    try:
        score = int(data.get("score", 0))
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(100, score))

    verdict_raw = str(data.get("verdict", "")).upper().strip()
    if verdict_raw not in {"PHISHING", "SOSPECHOSO", "LEGÍTIMO", "LEGITIMO"}:
        # Si la IA usa un veredicto inesperado, lo derivamos del score
        verdict = (
            "PHISHING" if score >= 61
            else "SOSPECHOSO" if score >= 31
            else "LEGÍTIMO"
        )
    else:
        verdict = "LEGÍTIMO" if verdict_raw == "LEGITIMO" else verdict_raw

    indicators_raw = data.get("indicators") or []
    indicators: List[Dict[str, str]] = []
    for item in indicators_raw:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity", "low")).lower()
        if sev not in {"high", "medium", "low"}:
            sev = "low"
        indicators.append({
            "name": str(item.get("name", "")).strip() or "Indicador",
            "severity": sev,
            "detail": str(item.get("detail", "")).strip(),
        })

    explanation = str(data.get("explanation", "")).strip()

    return {
        "score": score,
        "verdict": verdict,
        "indicators": indicators,
        "explanation": explanation,
    }
