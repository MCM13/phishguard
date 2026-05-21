"""
Control de cuota de llamadas a la API de Anthropic.

Evita agotar los créditos limitando cuántas peticiones a Claude se permiten
por hora y por día. Los contadores se persisten en SQLite para que sobrevivan
reinicios del contenedor.

Variables de entorno:
  ANTHROPIC_MAX_PER_HOUR  — Máximo por hora (0 = sin límite horario)
  ANTHROPIC_MAX_PER_DAY   — Máximo por día (0 = sin límite diario)

Si ambos son 0, no hay restricción (no recomendado en producción).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import func

from app.database import SessionLocal
from app.models.anthropic_usage import AnthropicUsageLog

logger = logging.getLogger(__name__)


def _parse_limit(name: str, default: int) -> int:
    """Lee un límite entero desde el entorno. 0 significa ilimitado."""
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Valor inválido para %s=%r, usando %s", name, raw, default)
        return default
    return max(0, value)


# Límites por defecto conservadores para no vaciar créditos en producción/demo
MAX_PER_HOUR = _parse_limit("ANTHROPIC_MAX_PER_HOUR", default=10)
MAX_PER_DAY = _parse_limit("ANTHROPIC_MAX_PER_DAY", default=20)


def _count_since(since: datetime) -> int:
    """Cuenta llamadas registradas desde una marca temporal."""
    db = SessionLocal()
    try:
        return (
            db.query(func.count(AnthropicUsageLog.id))
            .filter(AnthropicUsageLog.called_at >= since)
            .scalar()
            or 0
        )
    finally:
        db.close()


def get_usage_status() -> Dict[str, Any]:
    """
    Devuelve el estado actual de consumo para exponer en /api/stats.

    Incluye límites configurados, uso actual y peticiones restantes.
    """
    used_hour, used_day = _get_counts()

    def _window(used: int, limit: int) -> Dict[str, Any]:
        if limit <= 0:
            return {
                "limit": None,
                "used": used,
                "remaining": None,
                "unlimited": True,
            }
        remaining = max(0, limit - used)
        return {
            "limit": limit,
            "used": used,
            "remaining": remaining,
            "unlimited": False,
        }

    hour_info = _window(used_hour, MAX_PER_HOUR)
    day_info = _window(used_day, MAX_PER_DAY)

    # Hay cuota si al menos una ventana está ilimitada o tiene remaining > 0
    can_call = True
    block_reason: Optional[str] = None

    if MAX_PER_HOUR > 0 and hour_info["remaining"] == 0:
        can_call = False
        block_reason = (
            f"Límite horario alcanzado ({used_hour}/{MAX_PER_HOUR} llamadas a Claude). "
            "Inténtalo de nuevo más tarde."
        )
    if MAX_PER_DAY > 0 and day_info["remaining"] == 0:
        can_call = False
        block_reason = (
            f"Límite diario alcanzado ({used_day}/{MAX_PER_DAY} llamadas a Claude). "
            "Se reinicia a medianoche UTC."
        )

    return {
        "enabled": MAX_PER_HOUR > 0 or MAX_PER_DAY > 0,
        "can_call_claude": can_call,
        "block_reason": block_reason,
        "hourly": hour_info,
        "daily": day_info,
    }


def _get_counts() -> Tuple[int, int]:
    """Devuelve (usadas última hora, usadas hoy UTC)."""
    now = datetime.utcnow()
    hour_start = now - timedelta(hours=1)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return _count_since(hour_start), _count_since(day_start)


def check_and_consume_quota() -> Tuple[bool, Optional[str]]:
    """
    Comprueba si queda cuota y, si es así, registra una nueva llamada.

    Returns:
        (True, None) si se puede llamar a Claude.
        (False, mensaje) si se superó el límite horario o diario.
    """
    # Sin límites configurados: sin restricción ni registro en BD
    if MAX_PER_HOUR <= 0 and MAX_PER_DAY <= 0:
        return True, None

    used_hour, used_day = _get_counts()

    if MAX_PER_HOUR > 0 and used_hour >= MAX_PER_HOUR:
        reason = (
            f"Límite horario alcanzado ({used_hour}/{MAX_PER_HOUR} llamadas a Claude). "
            "Inténtalo de nuevo más tarde."
        )
        logger.warning("Cuota Anthropic agotada: %s", reason)
        return False, reason

    if MAX_PER_DAY > 0 and used_day >= MAX_PER_DAY:
        reason = (
            f"Límite diario alcanzado ({used_day}/{MAX_PER_DAY} llamadas a Claude). "
            "Se reinicia a medianoche UTC."
        )
        logger.warning("Cuota Anthropic agotada: %s", reason)
        return False, reason

    _record_call()
    return True, None


def _record_call() -> None:
    """Persiste un registro de consumo en la base de datos."""
    db = SessionLocal()
    try:
        db.add(AnthropicUsageLog(called_at=datetime.utcnow()))
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception("No se pudo registrar uso de Anthropic: %s", exc)
    finally:
        db.close()
