"""
Router que expone los endpoints de análisis:
  POST /api/analyze/url
  POST /api/analyze/email

Orquesta los servicios (extracción de features, VirusTotal, URLScan y
Claude) y persiste los resultados en la base de datos.

NOTA: este módulo NO usa `from __future__ import annotations`. La razón
es que el decorador `@limiter.limit` de slowapi cambia la firma de la
función, y FastAPI necesita las anotaciones EVALUADAS en runtime para
detectar correctamente el body Pydantic. Con annotations diferidas
(PEP 563), todas las anotaciones quedan como ForwardRef strings y la
detección falla devolviendo 422 ("missing in query").
"""

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Type, TypeVar
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.analysis import Analysis
from app.services import (
    claude_analyzer,
    email_extractor,
    url_extractor,
    urlscan,
    virustotal,
)
from app.services.rate_limit import analyze_limit, limiter
from app.services.text_sanitizer import safe_string, strip_html
from app.services.url_validator import UnsafeURLError, validate_public_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analyze", tags=["analyze"])

_T = TypeVar("_T", bound=BaseModel)


# ---------------- Esquemas Pydantic ----------------


class URLAnalysisRequest(BaseModel):
    """Cuerpo de la petición para analizar una URL."""
    url: str = Field(..., min_length=3, max_length=2048, description="URL a analizar")


class EmailAnalysisRequest(BaseModel):
    """Cuerpo de la petición para analizar el contenido de un email."""
    content: str = Field(..., min_length=10, max_length=50_000, description="Texto del email")


# ---------------- Helpers ----------------


async def _parse_json_body(request: Request, model: Type[_T]) -> _T:
    """
    Valida el JSON *después* de entrar al handler.

    Si el body fuera un parámetro `Body()` de FastAPI, la validación 422
    ocurriría antes de ejecutar el decorador de slowapi y esas peticiones
    no contarían para el rate limit.
    """
    try:
        data = await request.json()
    except Exception as exc:
        raise RequestValidationError(
            [
                {
                    "type": "json_invalid",
                    "loc": ("body",),
                    "msg": "JSON inválido",
                    "input": None,
                    "ctx": {"error": str(exc)},
                }
            ]
        ) from exc
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc



def _persist_analysis(
    db: Session,
    *,
    analysis_type: str,
    input_data: str,
    domain: str | None,
    ai_result: Dict[str, Any],
) -> Analysis:
    """
    Guarda un registro minimizado del análisis.

    El contenido analizado sólo se conserva como huella SHA-256; el texto,
    la URL completa, la explicación y los indicadores se devuelven al
    usuario en la respuesta pero no se almacenan.
    """
    normalized = safe_string(input_data, max_len=50_000).strip()
    clean_domain = safe_string(domain, max_len=255).strip().lower() if domain else ""
    record = Analysis(
        id=str(uuid.uuid4()),
        type=analysis_type,
        score=int(ai_result["score"]),
        verdict=ai_result["verdict"],
        analysis_mode=ai_result.get("analysis_mode"),
        target_domain=clean_domain or None,
        input_hash=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        timestamp=datetime.utcnow(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


# ---------------- Endpoints ----------------


@router.post("/url")
@limiter.limit(analyze_limit)
async def analyze_url_endpoint(
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Analiza una URL combinando:
      1. Features locales (longitud, palabras clave, whois, etc.).
      2. VirusTotal (si está disponible).
      3. URLScan.io (si está disponible).
      4. Veredicto final generado por Claude.

    El cuerpo se valida dentro del handler para que el rate limit cuente
    también las peticiones malformadas (422).
    """
    payload = await _parse_json_body(request, URLAnalysisRequest)
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La URL no puede estar vacía.",
        )

    # Validación de formato + anti-SSRF antes de tocar ningún servicio.
    # La resolución DNS y WHOIS son bloqueantes: se ejecutan en un hilo.
    try:
        safe_url = await asyncio.to_thread(validate_public_url, raw_url)
    except UnsafeURLError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    try:
        # 1. Extracción local de features (incluye la consulta WHOIS)
        features = await asyncio.to_thread(url_extractor.extract_url_features, safe_url)

        # 2 y 3. Consultas externas (toleran fallos individuales)
        vt_result = await virustotal.analyze_url(features.get("url", raw_url))
        urlscan_result = await urlscan.analyze_url(features.get("url", raw_url))

        # Combinamos toda la información en el payload que ve la IA
        features["urlscan"] = {
            "available": urlscan_result.get("available", False),
            "malicious": urlscan_result.get("malicious", False),
            "total_results": urlscan_result.get("total_results", 0),
        }

        # 4. Veredicto final con Claude
        ai_result = await claude_analyzer.analyze_with_claude(
            features, vt_result, analysis_type="url"
        )

        vt_positives = int(vt_result.get("positives") or 0) if vt_result.get("available") else 0

        analyzed_url = features.get("url", safe_url)
        record = _persist_analysis(
            db,
            analysis_type="url",
            input_data=analyzed_url,
            domain=urlparse(analyzed_url).hostname,
            ai_result=ai_result,
        )

        # Exponemos el veredicto al middleware de auditoría sin loguear la URL
        request.state.audit_verdict = record.verdict

        return {
            "id": record.id,
            "url": analyzed_url,
            "score": record.score,
            "verdict": record.verdict,
            "indicators": ai_result.get("indicators", []),
            "ai_explanation": ai_result.get("explanation", ""),
            "virustotal_detections": vt_positives,
            "virustotal_available": bool(vt_result.get("available")),
            "virustotal_total_engines": int(vt_result.get("total_engines") or 0),
            "analysis_mode": ai_result["analysis_mode"],
            "analysis_label": ai_result["analysis_label"],
            "discrepancy": ai_result.get("discrepancy"),
            "timestamp": record.timestamp.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error analizando URL: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno analizando la URL.",
        )


@router.post("/email")
@limiter.limit(analyze_limit)
async def analyze_email_endpoint(
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Analiza el contenido de un email sospechoso.

    Si el email incluye URLs, también se analiza la primera de ellas con
    VirusTotal para enriquecer el contexto que ve la IA.

    El cuerpo se valida dentro del handler para que el rate limit cuente
    también las peticiones malformadas (422).
    """
    payload = await _parse_json_body(request, EmailAnalysisRequest)
    # Strip de HTML/JS/CSS antes de persistir o enviar texto a la IA. Aunque
    # PhishGuard nunca renderiza este contenido, eliminamos carga activa por
    # defensa en profundidad y para reducir prompt-injection.
    sanitized_content = strip_html(payload.content).strip()
    if not sanitized_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El contenido del email no puede estar vacío.",
        )

    try:
        # El extractor recibe el contenido original (sin renderizarlo) porque
        # las cabeceras "Nombre <email>" y los <a href> engañosos se perderían
        # al quitar el HTML. Internamente sólo expone texto ya saneado.
        features = email_extractor.extract_email_features(payload.content)

        # Si encontramos URLs, enriquecemos con datos de VirusTotal de la primera
        urls = features.get("urls_found") or []
        vt_result: Dict[str, Any] | None = None
        if urls:
            vt_result = await virustotal.analyze_url(urls[0])

        ai_result = await claude_analyzer.analyze_with_claude(
            features, vt_result, analysis_type="email"
        )

        record = _persist_analysis(
            db,
            analysis_type="email",
            input_data=sanitized_content,
            domain=features.get("sender_domain") or None,
            ai_result=ai_result,
        )

        request.state.audit_verdict = record.verdict

        # La estructura de respuesta para email omite url y virustotal_detections
        return {
            "id": record.id,
            "score": record.score,
            "verdict": record.verdict,
            "indicators": ai_result.get("indicators", []),
            "ai_explanation": ai_result.get("explanation", ""),
            "analysis_mode": ai_result["analysis_mode"],
            "analysis_label": ai_result["analysis_label"],
            "discrepancy": ai_result.get("discrepancy"),
            "timestamp": record.timestamp.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error analizando email: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno analizando el email.",
        )
