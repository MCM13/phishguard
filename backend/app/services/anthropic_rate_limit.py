"""
Control de cuota de llamadas a la API de Anthropic.

Evita agotar los créditos limitando cuántas peticiones a Claude se permiten
por hora y por día. Los contadores se persisten en SQLite para que sobrevivan
reinicios del proceso (no del disco efímero de Render).

Variables de entorno (se leen en cada comprobación, no al importar):
  ANTHROPIC_MAX_PER_HOUR  — Máximo por hora (0 = sin límite horario, por defecto 10)
  ANTHROPIC_MAX_PER_DAY   — Máximo por día UTC (0 = sin límite diario, por defecto 20)

Si ambos son 0, no hay restricción (no recomendado en producción).
Cuando se agota la cuota, el análisis continúa en modo heurístico sin IA.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import func

from app.database import SessionLocal
from app.models.anthropic_usage import AnthropicUsageLog

logger = logging.getLogger(__name__)

DEFAULT_MAX_PER_HOUR = 10
DEFAULT_MAX_PER_DAY = 20

# Serializa "comprobar + registrar" para que peticiones concurrentes en el
# mismo proceso no superen la cuota. Con varios workers/procesos haría falta
# un bloqueo en la base de datos.
_quota_lock = threading.Lock()


def _parse_limit(name: str, default: int) -> int:
    """Lee un límite entero desde el entorno. 0 significa ilimitado."""
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Valor inválido para %s=%r, usando %s", name, raw, default)
        return default
    return max(0, value)


def max_per_hour() -> int:
    return _parse_limit("ANTHROPIC_MAX_PER_HOUR", DEFAULT_MAX_PER_HOUR)


def max_per_day() -> int:
    return _parse_limit("ANTHROPIC_MAX_PER_DAY", DEFAULT_MAX_PER_DAY)


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


def _get_counts() -> Tuple[int, int]:
    """Devuelve (usadas última hora, usadas hoy UTC)."""
    now = datetime.utcnow()
    hour_start = now - timedelta(hours=1)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return _count_since(hour_start), _count_since(day_start)


def _block_reason(used_hour: int, used_day: int, limit_hour: int, limit_day: int) -> Optional[str]:
    if limit_day > 0 and used_day >= limit_day:
        return (
            f"Límite diario alcanzado ({used_day}/{limit_day} llamadas a Claude). "
            "Se reinicia a medianoche UTC."
        )
    if limit_hour > 0 and used_hour >= limit_hour:
        return (
            f"Límite horario alcanzado ({used_hour}/{limit_hour} llamadas a Claude). "
            "Inténtalo de nuevo más tarde."
        )
    return None


def get_usage_status() -> Dict[str, Any]:
    """
    Devuelve el estado actual de consumo para exponer en /api/stats.

    Incluye límites configurados, uso actual y peticiones restantes.
    """
    limit_hour, limit_day = max_per_hour(), max_per_day()
    used_hour, used_day = _get_counts()

    def _window(used: int, limit: int) -> Dict[str, Any]:
        if limit <= 0:
            return {"limit": None, "used": used, "remaining": None, "unlimited": True}
        return {
            "limit": limit,
            "used": used,
            "remaining": max(0, limit - used),
            "unlimited": False,
        }

    reason = _block_reason(used_hour, used_day, limit_hour, limit_day)
    return {
        "enabled": limit_hour > 0 or limit_day > 0,
        "can_call_claude": reason is None,
        "block_reason": reason,
        "hourly": _window(used_hour, limit_hour),
        "daily": _window(used_day, limit_day),
    }


def check_and_consume_quota() -> Tuple[bool, Optional[str]]:
    """
    Comprueba si queda cuota y, si es así, registra una nueva llamada.

    Returns:
        (True, None) si se puede llamar a Claude.
        (False, mensaje) si se superó el límite horario o diario.
    """
    limit_hour, limit_day = max_per_hour(), max_per_day()
    # Sin límites configurados: sin restricción ni registro en BD
    if limit_hour <= 0 and limit_day <= 0:
        return True, None

    with _quota_lock:
        used_hour, used_day = _get_counts()
        reason = _block_reason(used_hour, used_day, limit_hour, limit_day)
        if reason:
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
