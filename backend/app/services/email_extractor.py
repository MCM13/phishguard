"""
Servicio de extracción de features de emails sospechosos.

Recibe el texto crudo de un email (puede incluir cabeceras y cuerpo) y
extrae las señales relevantes: remitente, asunto, URLs incluidas, palabras
sospechosas en español/inglés, presencia de archivos adjuntos, urgencia,
amenazas, etc.
"""

from __future__ import annotations

import email
import re
from email import policy
from typing import Any, Dict, List


# URL regex razonablemente permisiva (acepta http/https y dominios sueltos)
URL_REGEX = re.compile(
    r"https?://[^\s<>\"'\)]+|www\.[^\s<>\"'\)]+",
    re.IGNORECASE,
)

# Palabras que típicamente aparecen en emails de phishing
SUSPICIOUS_PHRASES: List[str] = [
    # Urgencia
    "urgente", "inmediato", "ahora mismo", "última oportunidad",
    "urgent", "immediately", "act now", "last chance",
    # Amenazas / cuentas
    "suspendid", "bloquead", "verificar cuenta", "confirmar identidad",
    "suspended", "blocked", "verify your account", "confirm your identity",
    # Premios / dinero
    "premio", "ganador", "lotería", "herencia", "transferencia",
    "winner", "prize", "lottery", "inheritance", "wire transfer",
    # Credenciales
    "contraseña", "usuario", "tarjeta de crédito", "número de cuenta",
    "password", "username", "credit card", "account number",
    # Enlaces engañosos
    "haz clic aquí", "pulsa aquí", "click here", "click below",
]


def _parse_email(content: str):
    """Intenta parsear el contenido como un email RFC. Si falla, devuelve None."""
    if not content:
        return None
    try:
        return email.message_from_string(content, policy=policy.default)
    except Exception:
        return None


def _get_body(msg) -> str:
    """Extrae el cuerpo en texto plano de un email multipart o simple."""
    if msg is None:
        return ""
    try:
        if msg.is_multipart():
            parts = []
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        parts.append(part.get_content())
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if isinstance(payload, bytes):
                            parts.append(payload.decode(errors="ignore"))
            return "\n".join(parts)
        else:
            try:
                return msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, bytes):
                    return payload.decode(errors="ignore")
                return str(msg.get_payload() or "")
    except Exception:
        return ""


def extract_email_features(content: str) -> Dict[str, Any]:
    """
    Extrae las señales relevantes del contenido de un email.

    Funciona tanto si el usuario pega el email completo con cabeceras como
    si sólo pega el cuerpo del mensaje.
    """
    content = content or ""
    msg = _parse_email(content)

    # Si conseguimos parsearlo como RFC obtenemos cabeceras; si no, todo es body
    if msg is not None and msg.get("from"):
        sender = str(msg.get("from") or "")
        subject = str(msg.get("subject") or "")
        reply_to = str(msg.get("reply-to") or "")
        body = _get_body(msg) or content
        attachments = [
            part.get_filename()
            for part in (msg.walk() if msg.is_multipart() else [])
            if part.get_filename()
        ]
    else:
        sender = ""
        subject = ""
        reply_to = ""
        body = content
        attachments = []

    # URLs encontradas en el cuerpo
    urls = list({u.rstrip(".,;:)") for u in URL_REGEX.findall(body)})

    # Buscar frases sospechosas en cuerpo + asunto
    haystack = (subject + "\n" + body).lower()
    phrase_hits = [p for p in SUSPICIOUS_PHRASES if p in haystack]

    # Comprobación remitente vs reply-to (clásico indicador de phishing)
    sender_domain = _extract_domain_from_address(sender)
    reply_domain = _extract_domain_from_address(reply_to)
    mismatched_reply_to = bool(
        sender_domain and reply_domain and sender_domain != reply_domain
    )

    features: Dict[str, Any] = {
        "sender": sender,
        "sender_domain": sender_domain,
        "reply_to": reply_to,
        "subject": subject,
        "body_length": len(body),
        "body_preview": body[:500],
        "urls_found": urls,
        "url_count": len(urls),
        "suspicious_phrases": phrase_hits,
        "suspicious_phrase_count": len(phrase_hits),
        "has_attachments": bool(attachments),
        "attachments": attachments,
        "mismatched_reply_to": mismatched_reply_to,
    }
    return features


def _extract_domain_from_address(address: str) -> str:
    """Devuelve el dominio de una dirección de email como 'a@b.com' -> 'b.com'."""
    if not address:
        return ""
    match = re.search(r"[\w\.-]+@([\w\.-]+)", address)
    return match.group(1).lower() if match else ""
