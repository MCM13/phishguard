"""
Router con endpoints de consulta:
  GET /api/history  -> historial paginado de análisis
  GET /api/stats    -> estadísticas globales agregadas
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.analysis import Analysis
from app.services.anthropic_rate_limit import get_usage_status
from app.services.rate_limit import limiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["history"])


@router.get("/history")
@limiter.limit("30/minute")
def get_history(
    request: Request,
    page: int = Query(1, ge=1, description="Número de página (1-indexada)"),
    page_size: int = Query(20, ge=1, le=100, description="Resultados por página"),
    verdict: Optional[str] = Query(
        None,
        description="Filtra por veredicto: PHISHING, SOSPECHOSO o LEGÍTIMO",
    ),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Devuelve el listado paginado de análisis ordenados del más reciente al más antiguo."""
    try:
        query = db.query(Analysis)

        if verdict:
            normalized = verdict.upper().strip()
            if normalized == "LEGITIMO":
                normalized = "LEGÍTIMO"
            if normalized not in {"PHISHING", "SOSPECHOSO", "LEGÍTIMO"}:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Veredicto inválido. Usa PHISHING, SOSPECHOSO o LEGÍTIMO.",
                )
            query = query.filter(Analysis.verdict == normalized)

        total = query.count()
        items = (
            query.order_by(Analysis.timestamp.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        return {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size if total else 0,
            "items": [item.to_dict() for item in items],
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error consultando historial: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno consultando el historial.",
        )


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Devuelve estadísticas globales:
      - total_analyzed: total de análisis realizados
      - phishing_detected: cuántos fueron marcados como PHISHING
      - detection_rate: porcentaje de phishing sobre el total (0-100)
      - avg_score: score medio de todos los análisis
    """
    try:
        total = db.query(func.count(Analysis.id)).scalar() or 0
        phishing = (
            db.query(func.count(Analysis.id))
            .filter(Analysis.verdict == "PHISHING")
            .scalar()
            or 0
        )
        avg_score = db.query(func.avg(Analysis.score)).scalar() or 0.0

        detection_rate = (phishing / total * 100.0) if total else 0.0

        return {
            "total_analyzed": int(total),
            "phishing_detected": int(phishing),
            "detection_rate": round(float(detection_rate), 2),
            "avg_score": round(float(avg_score), 2),
            "anthropic_quota": get_usage_status(),
        }
    except Exception as exc:
        logger.exception("Error calculando estadísticas: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno calculando las estadísticas.",
        )
