"""
Autenticación de administrador para los endpoints de consulta del historial.

PhishGuard no tiene usuarios: el historial sólo lo consulta quien conoce el
token definido en la variable de entorno ADMIN_TOKEN. El cliente lo envía en
la cabecera `Authorization: Bearer <token>`.

Si ADMIN_TOKEN no está definido, el historial queda cerrado para todos
(fail closed). La respuesta de error es siempre la misma, sin indicar si
falta el token, si es incorrecto o si el servidor no lo tiene configurado;
ese motivo sólo se registra en el log de auditoría.
"""

from __future__ import annotations

import hmac
import logging
import os

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

MIN_RECOMMENDED_LENGTH = 24


def configured_token() -> str:
    return os.getenv("ADMIN_TOKEN", "").strip()


def warn_if_weak_configuration() -> None:
    """Avisa al arrancar si el historial va a quedar inaccesible o mal protegido."""
    token = configured_token()
    if not token:
        logger.warning("ADMIN_TOKEN no definido: /api/history responderá 401 a todas las peticiones.")
    elif len(token) < MIN_RECOMMENDED_LENGTH:
        logger.warning(
            "ADMIN_TOKEN tiene menos de %d caracteres; usa un valor aleatorio más largo.",
            MIN_RECOMMENDED_LENGTH,
        )


def _bearer_token(request: Request) -> str:
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    return value.strip() if scheme.lower() == "bearer" else ""


def require_admin(request: Request) -> None:
    """Lanza 401 si la petición no trae el token de administrador correcto."""
    expected = configured_token()
    provided = _bearer_token(request)

    if not provided:
        reason = "missing_token"
    elif not expected:
        reason = "server_not_configured"
    elif not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        reason = "invalid_token"
    else:
        return

    request.state.audit_event = "admin_auth_failed"
    request.state.audit_reason = reason
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No autorizado.",
        headers={"WWW-Authenticate": "Bearer"},
    )
