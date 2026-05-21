"""
Middleware de auditoría: registra una entrada JSON por cada petición HTTP.

Datos registrados:
  ts_utc       - Marca temporal ISO-8601 UTC.
  ip           - IP del cliente (respetando X-Forwarded-For).
  method       - Verbo HTTP.
  path         - Ruta solicitada (sin query string).
  status       - Código HTTP devuelto.
  latency_ms   - Duración de la petición en milisegundos.
  verdict      - (Opcional) Veredicto del análisis si el handler lo expuso
                 en request.state.audit_verdict.
  rate_limited - (Opcional) True si la petición fue rechazada por rate limit.

Lo que NO se registra (a propósito):
  - API keys ni cabeceras de autorización.
  - Body de la petición (puede contener URLs/emails de víctimas).
  - User-Agent completo (sólo el primer fragmento).
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Canal dedicado para auditoría — no propaga al root logger para mantener
# los registros separados del logging normal de la aplicación.
_audit_logger = logging.getLogger("phishguard.audit")
_audit_logger.propagate = False
if not _audit_logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger.addHandler(handler)
    _audit_logger.setLevel(logging.INFO)


def _client_ip(request: Request) -> str:
    """Resuelve la IP real del cliente, respetando X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",", 1)[0].strip()
        if first:
            return first
    if request.client:
        return request.client.host or "unknown"
    return "unknown"


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Emite una línea JSON por cada petición HTTP procesada."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        status_code = 500
        response: Response

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
            entry: Dict[str, Any] = {
                "ts_utc": datetime.now(timezone.utc).isoformat(),
                "ip": _client_ip(request),
                "method": request.method,
                "path": request.url.path,
                "status": status_code,
                "latency_ms": latency_ms,
            }

            # Información opcional adjuntada por los handlers
            verdict = getattr(request.state, "audit_verdict", None)
            if verdict:
                entry["verdict"] = verdict

            if status_code == 429:
                entry["rate_limited"] = True

            # User-Agent recortado para identificar clientes sin exponer fingerprint
            ua = request.headers.get("user-agent", "")
            if ua:
                entry["ua"] = ua[:80]

            _audit_logger.info(json.dumps(entry, ensure_ascii=False))
