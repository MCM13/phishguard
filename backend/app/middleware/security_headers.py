"""
Middleware que inyecta cabeceras de seguridad HTTP en todas las respuestas.

Implementa las recomendaciones de OWASP Secure Headers Project.
Referencia: https://owasp.org/www-project-secure-headers/
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# Cabeceras estáticas que se aplican a todas las respuestas
_STATIC_HEADERS = {
    # Evita que el navegador "adivine" el tipo MIME y ejecute como script
    # contenido devuelto con un Content-Type distinto.
    "X-Content-Type-Options": "nosniff",
    # Bloquea cualquier intento de embeber la API en un <iframe> (clickjacking).
    "X-Frame-Options": "DENY",
    # Histórico: navegadores antiguos. Hoy XSS se mitiga vía CSP, pero la
    # cabecera se mantiene por defensa en profundidad.
    "X-XSS-Protection": "1; mode=block",
    # No filtra el referer completo cuando se navega a otros orígenes.
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Niega permisos sensibles del navegador para esta API.
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # CSP estricta: la API sólo devuelve JSON, no necesita cargar nada externo.
    "Content-Security-Policy": "default-src 'self'",
}

# HSTS sólo se inyecta cuando la petición viene por HTTPS (RFC 6797).
_HSTS_VALUE = "max-age=31536000; includeSubDomains"


def _is_https(request: Request) -> bool:
    """
    Determina si la petición original fue HTTPS.

    Considera tanto el esquema directo como la cabecera X-Forwarded-Proto
    inyectada por proxies/CDNs (Render, Cloudflare...).
    """
    if request.url.scheme == "https":
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
    return forwarded_proto.startswith("https")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inyecta cabeceras de seguridad HTTP en cada respuesta saliente."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        for header, value in _STATIC_HEADERS.items():
            # No sobrescribimos si el handler ya ha definido un valor propio.
            response.headers.setdefault(header, value)

        if _is_https(request):
            response.headers.setdefault("Strict-Transport-Security", _HSTS_VALUE)

        return response
