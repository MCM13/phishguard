"""
Sanitización de cadenas de texto antes de procesarlas o guardarlas.

  * `strip_html(text)`  — Elimina cualquier marca HTML/JS/CSS del contenido.
  * `safe_string(text)` — Quita caracteres de control y normaliza el texto.

No se renderiza HTML en ningún punto de PhishGuard (ni backend ni
frontend), pero por defensa en profundidad eliminamos cualquier carga
útil HTML antes de mandar el texto a Claude, a las APIs externas o a la
base de datos. Esto reduce la superficie de prompt injection vía
contenido HTML/script en emails maliciosos.
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Optional

# Bloques peligrosos que deben eliminarse junto con su contenido.
_DANGEROUS_BLOCKS = re.compile(
    r"<(script|style|iframe|object|embed|svg)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)

# Bloques peligrosos sin etiqueta de cierre (auto-cerradas o malformadas).
_DANGEROUS_OPEN = re.compile(
    r"<(script|style|iframe|object|embed|svg)\b[^>]*/?>",
    re.IGNORECASE,
)

# Cualquier otra etiqueta HTML.
_ANY_HTML_TAG = re.compile(r"<[^>]+>")

# Caracteres de control ASCII (\x00-\x08, \x0B, \x0C, \x0E-\x1F, \x7F).
# Excluimos \t (\x09), \n (\x0A), \r (\x0D) que son saltos legítimos.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

# Espacios en blanco consecutivos para colapsar.
_MULTI_WS = re.compile(r"[ \t]{2,}")


def strip_html(text: Optional[str]) -> str:
    """
    Elimina cualquier HTML/JS/CSS del texto, dejando sólo el contenido textual.

    No es un sanitizador para reinyectar HTML; es un *stripper* irreversible
    cuyo único propósito es neutralizar contenido activo antes de procesar.
    """
    if not text:
        return ""

    cleaned = _DANGEROUS_BLOCKS.sub(" ", text)
    cleaned = _DANGEROUS_OPEN.sub(" ", cleaned)
    cleaned = _ANY_HTML_TAG.sub(" ", cleaned)

    # Decodificamos entidades (&amp; → &) tras quitar tags, para no
    # reintroducir HTML accidentalmente.
    cleaned = html.unescape(cleaned)

    # Eliminamos caracteres de control salvo saltos legítimos.
    cleaned = _CONTROL_CHARS.sub("", cleaned)

    # Colapsamos espacios excesivos pero preservamos saltos de línea
    cleaned = _MULTI_WS.sub(" ", cleaned)
    return cleaned.strip()


def safe_string(text: Optional[str], max_len: int = 10_000) -> str:
    """
    Saneamiento ligero para cadenas que se persistirán o devolverán.

    1. Convierte a str si no lo es.
    2. Normaliza Unicode (NFC) para evitar homoglifos creados con combining
       characters.
    3. Elimina caracteres de control.
    4. Trunca a `max_len`.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    normalized = unicodedata.normalize("NFC", text)
    normalized = _CONTROL_CHARS.sub("", normalized)

    if len(normalized) > max_len:
        normalized = normalized[:max_len]
    return normalized
