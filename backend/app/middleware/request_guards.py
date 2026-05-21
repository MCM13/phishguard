"""
Middlewares de protección contra abusos básicos:

  * MaxBodySizeMiddleware     — Rechaza bodies mayores a MAX_BODY_BYTES.
  * RequestTimeoutMiddleware  — Limita el tiempo total de la petición.
  * JSONContentTypeMiddleware — Exige Content-Type: application/json en POST/PUT/PATCH.

Todos se aplican de forma independiente y devuelven respuestas con códigos
HTTP estándar (413 / 504 / 415) y mensajes en español.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

# Límite máximo del body de una petición HTTP entrante (1 MB).
MAX_BODY_BYTES = 1 * 1024 * 1024

# Tiempo máximo total de procesamiento por petición.
REQUEST_TIMEOUT_SECONDS = 30.0

# Métodos cuyo body se valida con Content-Type.
_METHODS_WITH_BODY = {"POST", "PUT", "PATCH"}


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Aborta peticiones cuyo body supere MAX_BODY_BYTES."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # 1) Si el cliente envía Content-Length declarado, lo comprobamos
        #    antes de leer un solo byte del body.
        cl_header = request.headers.get("content-length")
        if cl_header:
            try:
                declared = int(cl_header)
            except ValueError:
                return _too_large_response("Cabecera Content-Length inválida.")
            if declared > MAX_BODY_BYTES:
                return _too_large_response(
                    f"El body excede el máximo permitido ({MAX_BODY_BYTES} bytes)."
                )

        # 2) Defensa adicional para peticiones chunked: envolvemos `receive`
        #    para acumular el tamaño real y abortar si lo sobrepasa.
        body_size = 0
        original_receive = request.receive

        async def limited_receive():
            nonlocal body_size
            message = await original_receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"") or b""
                body_size += len(chunk)
                if body_size > MAX_BODY_BYTES:
                    raise _BodyTooLargeError()
            return message

        # Reemplazamos el callable de receive del scope ASGI
        request._receive = limited_receive  # type: ignore[attr-defined]

        try:
            return await call_next(request)
        except _BodyTooLargeError:
            return _too_large_response(
                f"El body excede el máximo permitido ({MAX_BODY_BYTES} bytes)."
            )


class _BodyTooLargeError(Exception):
    """Marcador interno para señalizar overflow del body."""


def _too_large_response(detail: str) -> JSONResponse:
    return JSONResponse(status_code=413, content={"detail": detail})


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """Cancela la petición si supera REQUEST_TIMEOUT_SECONDS."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        try:
            return await asyncio.wait_for(
                call_next(request),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Timeout en petición %s %s tras %.1fs",
                request.method,
                request.url.path,
                REQUEST_TIMEOUT_SECONDS,
            )
            return JSONResponse(
                status_code=504,
                content={
                    "detail": (
                        "La petición tardó demasiado en procesarse. "
                        "Inténtalo de nuevo en unos segundos."
                    )
                },
            )


class JSONContentTypeMiddleware(BaseHTTPMiddleware):
    """
    Garantiza que las peticiones con body usen Content-Type: application/json.

    Sólo se aplica a métodos que pueden llevar body (POST, PUT, PATCH) y
    cuando hay un Content-Length > 0. Las peticiones GET/HEAD/OPTIONS y los
    bodies vacíos se dejan pasar sin tocar.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.method.upper() not in _METHODS_WITH_BODY:
            return await call_next(request)

        content_length = request.headers.get("content-length", "0")
        try:
            length = int(content_length)
        except ValueError:
            length = 0

        if length <= 0:
            return await call_next(request)

        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            return JSONResponse(
                status_code=415,
                content={
                    "detail": (
                        "Content-Type no soportado. Esta API sólo acepta "
                        "application/json."
                    )
                },
            )

        return await call_next(request)
