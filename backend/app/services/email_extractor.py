"""
Servicio de extracción de features de emails sospechosos.

Recibe el texto crudo de un email (puede incluir cabeceras y cuerpo, en
texto plano o HTML) y extrae las señales relevantes: remitente visible y
real, Reply-To, URLs, enlaces cuyo texto no coincide con su destino,
lenguaje de urgencia o amenaza, peticiones de credenciales o pagos y
adjuntos con extensiones peligrosas.

El contenido se parsea pero nunca se renderiza ni se ejecuta. El HTML se
analiza antes de eliminarlo porque los enlaces engañosos sólo son visibles
en las etiquetas <a>.
"""

from __future__ import annotations

import email
import re
from email import policy
from email.utils import parseaddr
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.services.domain_utils import (
    brands_in_text,
    domain_belongs_to_brand,
    normalize_text,
    registrable_domain,
)
from app.services.text_sanitizer import strip_html

# URL regex razonablemente permisiva (acepta http/https y dominios sueltos)
URL_REGEX = re.compile(
    r"https?://[^\s<>\"'\)]+|www\.[^\s<>\"'\)]+",
    re.IGNORECASE,
)

# Los cuantificadores están acotados para que un HTML malicioso con miles de
# `<a` sin cerrar no dispare un backtracking cuadrático.
_ANCHOR_REGEX = re.compile(
    r"<a\b[^>]{0,2000}?\bhref\s*=\s*[\"']?([^\"'\s>]{1,2048})[\"']?[^>]{0,2000}>(.{0,500}?)</a\s*>",
    re.IGNORECASE | re.DOTALL,
)
# Representación en texto plano de un enlace HTML: "texto visible <destino>"
_PLAINTEXT_LINK_REGEX = re.compile(
    r"((?:https?://|www\.)[^\s<>]{1,300})\s*<(https?://[^>\s]{1,2048})>",
    re.IGNORECASE,
)
_DOMAIN_IN_TEXT_REGEX = re.compile(
    r"(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})",
    re.IGNORECASE,
)
_FILENAME_HEADER_REGEX = re.compile(
    r"(?:file)?name\*?\s*=\s*\"?([^\";\r\n]{1,255})", re.IGNORECASE
)

# Las frases se comparan sobre texto normalizado (minúsculas y sin tildes).
# Un `*` final indica que se acepta cualquier sufijo (suspendid -> suspendida).
URGENCY_PHRASES: List[str] = [
    "urgente", "urgencia", "inmediato", "inmediatamente", "de inmediato",
    "ahora mismo", "lo antes posible", "ultima oportunidad", "ultimo aviso",
    "24 horas", "48 horas", "caduca hoy", "expira hoy", "plazo limite",
    "urgent", "immediately", "act now", "last chance", "final notice",
    "within 24 hours", "within 48 hours", "as soon as possible", "expires today",
]
THREAT_PHRASES: List[str] = [
    "suspendid*", "bloquead*", "desactivad*", "cerrar su cuenta", "cerraremos",
    "acciones legales", "accion legal", "multa", "sancion", "denuncia",
    "perdera el acceso", "perderas el acceso", "actividad inusual",
    "actividad sospechosa", "acceso no autorizado",
    "suspended", "blocked", "locked", "deactivated", "legal action",
    "will be closed", "lose access", "unusual activity", "suspicious activity",
    "unauthorized access",
]
CREDENTIAL_PHRASES: List[str] = [
    "contrasena", "password", "credenciales", "credentials",
    "verifica tu cuenta", "verifique su cuenta", "verificar su cuenta",
    "verificar tu cuenta", "verify your account", "confirma tu identidad",
    "confirme su identidad", "confirmar su identidad", "confirm your identity",
    "inicia sesion", "inicie sesion", "sign in", "log in",
    "codigo de verificacion", "verification code", "pin", "cvv", "cvc",
    "numero de tarjeta", "card number", "datos bancarios", "bank details",
    "usuario y contrasena",
]
PAYMENT_PHRASES: List[str] = [
    "pago pendiente", "realice el pago", "realizar el pago", "realiza el pago",
    "abone", "transferencia", "bizum", "tarjeta de credito", "factura pendiente",
    "tasa de aduana", "gastos de envio", "reembolso", "criptomoneda", "bitcoin",
    "tarjeta regalo", "wire transfer", "payment required", "pay now",
    "overdue", "outstanding invoice", "customs fee", "refund", "gift card",
    "credit card",
]
LURE_PHRASES: List[str] = [
    "premio", "ganador", "loteria", "herencia", "sorteo",
    "winner", "prize", "lottery", "inheritance",
]

# Extensiones de adjunto: "high" = ejecutables o scripts; "medium" =
# contenedores, documentos con macros o HTML que suelen esconder la carga.
DANGEROUS_EXTENSIONS: Dict[str, str] = {
    **{ext: "high" for ext in (
        "exe", "scr", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
        "wsh", "ps1", "msi", "jar", "hta", "lnk", "cpl", "reg", "dll", "apk",
    )},
    **{ext: "medium" for ext in (
        "zip", "rar", "7z", "iso", "img", "docm", "xlsm", "pptm", "html", "htm",
    )},
}
_MENTIONED_FILE_REGEX = re.compile(
    r"\b[\w\-]{1,100}(?:\.[\w\-]{1,10})*\.(" + "|".join(DANGEROUS_EXTENSIONS) + r")\b",
    re.IGNORECASE,
)


def _compile_phrases(phrases: List[str]) -> List[Tuple[str, re.Pattern]]:
    compiled = []
    for phrase in phrases:
        if phrase.endswith("*"):
            pattern = rf"(?<![a-z0-9]){re.escape(phrase[:-1])}[a-z]*"
        else:
            pattern = rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])"
        compiled.append((phrase.rstrip("*"), re.compile(pattern)))
    return compiled


_PHRASE_GROUPS = {
    "urgency": _compile_phrases(URGENCY_PHRASES),
    "threat": _compile_phrases(THREAT_PHRASES),
    "credentials": _compile_phrases(CREDENTIAL_PHRASES),
    "payment": _compile_phrases(PAYMENT_PHRASES),
    "lure": _compile_phrases(LURE_PHRASES),
}


def _parse_email(content: str):
    """Intenta parsear el contenido como un email RFC. Si falla, devuelve None."""
    if not content:
        return None
    try:
        return email.message_from_string(content, policy=policy.default)
    except Exception:
        return None


def _get_body(msg) -> str:
    """Extrae el cuerpo (texto plano y HTML) de un email multipart o simple."""
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


def _host_of(url: str) -> str:
    candidate = url if "://" in url else f"http://{url}"
    try:
        return (urlparse(candidate).hostname or "").lower()
    except ValueError:
        return ""


def _find_link_mismatches(raw_body: str) -> Tuple[List[Dict[str, str]], List[str]]:
    """
    Busca enlaces cuyo texto visible muestra un dominio distinto del destino.

    Devuelve (discrepancias, URLs de destino encontradas en los href).
    """
    mismatches: List[Dict[str, str]] = []
    hrefs: List[str] = []

    candidates: List[Tuple[str, str]] = []
    for href, inner in _ANCHOR_REGEX.findall(raw_body):
        candidates.append((strip_html(inner), href.strip()))
    for shown, target in _PLAINTEXT_LINK_REGEX.findall(raw_body):
        candidates.append((shown, target))

    for shown, href in candidates:
        scheme = href.split(":", 1)[0].lower() if ":" in href else ""
        if scheme in ("javascript", "data", "vbscript"):
            mismatches.append({
                "shown": shown[:120],
                "target": f"{scheme}:",
                "reason": "El enlace ejecuta código o datos en lugar de abrir una web.",
            })
            continue
        if scheme in ("http", "https"):
            hrefs.append(href)
        target_host = _host_of(href)
        match = _DOMAIN_IN_TEXT_REGEX.search(shown or "")
        if not target_host or not match:
            continue
        shown_domain = registrable_domain(match.group(1))
        target_domain = registrable_domain(target_host)
        if shown_domain and target_domain and shown_domain != target_domain:
            mismatches.append({
                "shown": shown_domain,
                "target": target_domain,
                "reason": "El texto del enlace muestra un dominio distinto del destino real.",
            })
    return mismatches, hrefs


def _phrase_hits(haystack: str) -> Dict[str, List[str]]:
    return {
        group: [label for label, pattern in patterns if pattern.search(haystack)]
        for group, patterns in _PHRASE_GROUPS.items()
    }


def _display_name_mismatch(display_name: str, sender_domain: str) -> Optional[str]:
    """
    Detecta si el nombre visible del remitente no corresponde a su dominio real.

    Casos: el nombre visible contiene otro dominio o email ("soporte@paypal.com"
    <x@otro.test>), o nombra una marca cuyo dominio oficial no es el del remitente.
    """
    if not display_name or not sender_domain:
        return None

    real = registrable_domain(sender_domain)
    for found in _DOMAIN_IN_TEXT_REGEX.findall(display_name):
        shown = registrable_domain(found)
        if shown and shown != real:
            return f"El nombre visible muestra '{shown}' pero el email real es de '{real}'."

    for brand in sorted(brands_in_text(display_name)):
        if not domain_belongs_to_brand(sender_domain, brand):
            return (
                f"El nombre visible menciona '{brand}' pero el dominio real del "
                f"remitente es '{real}'."
            )
    return None


def _dangerous_files(names: List[str]) -> List[Dict[str, str]]:
    found = []
    for name in names:
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in DANGEROUS_EXTENSIONS:
            found.append({"filename": name[:120], "risk": DANGEROUS_EXTENSIONS[ext]})
    return found


def extract_email_features(content: str) -> Dict[str, Any]:
    """
    Extrae las señales relevantes del contenido de un email.

    Funciona tanto si el usuario pega el email completo con cabeceras como
    si sólo pega el cuerpo del mensaje (en texto plano o HTML).
    """
    content = content or ""
    msg = _parse_email(content)

    # Si conseguimos parsearlo como RFC obtenemos cabeceras; si no, todo es body
    if msg is not None and msg.get("from"):
        sender = str(msg.get("from") or "")
        subject = str(msg.get("subject") or "")
        reply_to = str(msg.get("reply-to") or "")
        raw_body = _get_body(msg) or content
        attachments = [
            part.get_filename()
            for part in (msg.walk() if msg.is_multipart() else [])
            if part.get_filename()
        ]
    else:
        sender = ""
        subject = ""
        reply_to = ""
        raw_body = content
        attachments = []

    # Si el usuario pegó cabeceras MIME de adjuntos sin que el parser las
    # reconozca como partes, recuperamos los nombres del texto crudo.
    for name in _FILENAME_HEADER_REGEX.findall(content):
        name = name.strip()
        if name and name not in attachments:
            attachments.append(name)

    link_mismatches, href_urls = _find_link_mismatches(raw_body)
    body = strip_html(raw_body)

    # URLs encontradas en el cuerpo visible y en los href de los enlaces
    urls = list(dict.fromkeys(
        [u.rstrip(".,;:)") for u in URL_REGEX.findall(body)] + href_urls
    ))

    haystack = normalize_text(subject + "\n" + body)
    hits = _phrase_hits(haystack)
    phrase_hits = [p for group in hits.values() for p in group]

    display_name, sender_address = parseaddr(sender)
    _, reply_address = parseaddr(reply_to)
    sender_domain = _extract_domain_from_address(sender_address or sender)
    reply_domain = _extract_domain_from_address(reply_address or reply_to)
    mismatched_reply_to = bool(
        sender_domain
        and reply_domain
        and registrable_domain(sender_domain) != registrable_domain(reply_domain)
    )
    display_mismatch = _display_name_mismatch(display_name, sender_domain)

    # Ficheros con extensión peligrosa mencionados en el texto (sin contar URLs)
    text_without_urls = URL_REGEX.sub(" ", body)
    mentioned_files = [m.group(0) for m in _MENTIONED_FILE_REGEX.finditer(text_without_urls)]

    features: Dict[str, Any] = {
        "sender": sender,
        "sender_display_name": display_name,
        "sender_domain": sender_domain,
        "display_name_mismatch": bool(display_mismatch),
        "display_name_mismatch_detail": display_mismatch or "",
        "reply_to": reply_to,
        "reply_to_domain": reply_domain,
        "mismatched_reply_to": mismatched_reply_to,
        "subject": subject,
        "body_length": len(body),
        "body_preview": body[:500],
        "urls_found": urls,
        "url_count": len(urls),
        "link_text_mismatches": link_mismatches,
        "urgency_phrases": hits["urgency"],
        "threat_phrases": hits["threat"],
        "credential_requests": hits["credentials"],
        "payment_requests": hits["payment"],
        "lure_phrases": hits["lure"],
        "suspicious_phrases": phrase_hits,
        "suspicious_phrase_count": len(phrase_hits),
        "has_attachments": bool(attachments),
        "attachments": attachments,
        "dangerous_attachments": _dangerous_files(attachments),
        "mentioned_dangerous_files": _dangerous_files(mentioned_files),
    }
    return features


def _extract_domain_from_address(address: str) -> str:
    """Devuelve el dominio de una dirección de email como 'a@b.com' -> 'b.com'."""
    if not address:
        return ""
    match = re.search(r"[\w\.\-+]+@([\w\.-]+)", address)
    return match.group(1).lower().rstrip(".") if match else ""
