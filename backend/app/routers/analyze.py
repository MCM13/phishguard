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

import logging
import uuid
from datetime import datetime
from typing import Annotated, Any, Dict

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
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
from app.services.rate_limit import limiter
from app.services.text_sanitizer import safe_string, strip_html
from app.services.url_validator import UnsafeURLError, validate_public_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analyze", tags=["analyze"])


# ---------------- Esquemas Pydantic ----------------


class URLAnalysisRequest(BaseModel):
    """Cuerpo de la petición para analizar una URL."""
    url: str = Field(..., min_length=3, max_length=2048, description="URL a analizar")


class EmailAnalysisRequest(BaseModel):
    """Cuerpo de la petición para analizar el contenido de un email."""
    content: str = Field(..., min_length=10, max_length=50_000, description="Texto del email")


# ---------------- Helpers ----------------


def _persist_analysis(
    db: Session,
    *,
    analysis_type: str,
    input_data: str,
    url: str | None,
    ai_result: Dict[str, Any],
    vt_positives: int | None,
) -> Analysis:
    """Crea y guarda el registro de análisis en la base de datos."""
    record = Analysis(
        id=str(uuid.uuid4()),
        type=analysis_type,
        # safe_string elimina caracteres de control y normaliza Unicode
        # antes de persistir, evitando guardar bytes raros en SQLite.
        input_data=safe_string(input_data, max_len=10_000),
        url=safe_string(url, max_len=2048) if url else None,
        score=int(ai_result["score"]),
        verdict=ai_result["verdict"],
        indicators=ai_result.get("indicators", []),
        ai_explanation=safe_string(ai_result.get("explanation", ""), max_len=5_000),
        virustotal_detections=vt_positives,
        timestamp=datetime.utcnow(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


# ---------------- Endpoints ----------------


@router.post("/url")
@limiter.limit("10/minute")
async def analyze_url_endpoint(
    request: Request,
    # Annotated[Model, Body()] es obligatorio cuando se combina con
    # `from __future__ import annotations` + @limiter.limit, porque el
    # decorador altera la firma y FastAPI necesita la anotación explícita.
    payload: Annotated[URLAnalysisRequest, Body()],
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Analiza una URL combinando:
      1. Features locales (longitud, palabras clave, whois, etc.).
      2. VirusTotal (si está disponible).
      3. URLScan.io (si está disponible).
      4. Veredicto final generado por Claude.
    """
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La URL no puede estar vacía.",
        )

    # Validación de formato + anti-SSRF antes de tocar ningún servicio
    try:
        safe_url = validate_public_url(raw_url)
    except UnsafeURLError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    try:
        # 1. Extracción local de features
        features = url_extractor.extract_url_features(safe_url)

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
        ai_result = await claude_analyzer.analyze_with_claude(features, vt_result)

        vt_positives = int(vt_result.get("positives") or 0) if vt_result.get("available") else 0

        record = _persist_analysis(
            db,
            analysis_type="url",
            input_data=safe_url,
            url=features.get("url", safe_url),
            ai_result=ai_result,
            vt_positives=vt_positives,
        )

        # Exponemos el veredicto al middleware de auditoría sin loguear la URL
        request.state.audit_verdict = record.verdict

        return {
            "id": record.id,
            "url": record.url,
            "score": record.score,
            "verdict": record.verdict,
            "indicators": record.indicators,
            "ai_explanation": record.ai_explanation,
            "virustotal_detections": record.virustotal_detections,
            "virustotal_available": bool(vt_result.get("available")),
            "virustotal_total_engines": int(vt_result.get("total_engines") or 0),
            "timestamp": record.timestamp.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error analizando URL: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno analizando la URL: {exc.__class__.__name__}",
        )


@router.post("/email")
@limiter.limit("10/minute")
async def analyze_email_endpoint(
    request: Request,
    payload: Annotated[EmailAnalysisRequest, Body()],
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Analiza el contenido de un email sospechoso.

    Si el email incluye URLs, también se analiza la primera de ellas con
    VirusTotal para enriquecer el contexto que ve la IA.
    """
    # Strip de HTML/JS/CSS antes de cualquier procesamiento. Aunque PhishGuard
    # nunca renderiza este contenido, eliminamos carga activa por defensa en
    # profundidad y para reducir prompt-injection vía emails maliciosos.
    sanitized_content = strip_html(payload.content).strip()
    if not sanitized_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El contenido del email no puede estar vacío.",
        )

    try:
        features = email_extractor.extract_email_features(sanitized_content)

        # Si encontramos URLs, enriquecemos con datos de VirusTotal de la primera
        urls = features.get("urls_found") or []
        vt_result: Dict[str, Any] | None = None
        if urls:
            vt_result = await virustotal.analyze_url(urls[0])

        ai_result = await claude_analyzer.analyze_with_claude(features, vt_result)

        record = _persist_analysis(
            db,
            analysis_type="email",
            input_data=sanitized_content,
            url=None,
            ai_result=ai_result,
            vt_positives=None,
        )

        request.state.audit_verdict = record.verdict

        # La estructura de respuesta para email omite url y virustotal_detections
        return {
            "id": record.id,
            "score": record.score,
            "verdict": record.verdict,
            "indicators": record.indicators,
            "ai_explanation": record.ai_explanation,
            "timestamp": record.timestamp.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error analizando email: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno analizando el email: {exc.__class__.__name__}",
        )
