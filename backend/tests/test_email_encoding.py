"""
Cuerpos de email con tildes y eñes, con y sin charset declarado.

Encontrado en la prueba con la IA real: sin Content-Type (lo normal al pegar
un email), el cuerpo perdía los caracteres no ASCII ("cerámica" -> "cer\ufffdmica")
y las reglas con tilde dejaban de detectar frases.
"""

from __future__ import annotations

import base64

import pytest

from app.services import email_extractor
from tests.conftest import PHISHING_EMAIL

TEXT = "Su contraseña y el número de tarjeta caducan en 3 días. Taza de cerámica: 12 €."

PHISHING_BODY = (
    "Estimado cliente: es su última oportunidad. Detectamos actividad inusual y "
    "perderá el acceso a su cuenta. Inicie sesión e introduzca su contraseña, el "
    "número de tarjeta y el código de verificación. Si no, recibirá una sanción."
)

HEADERS = "From: Soporte <soporte@banco-ejemplo.test>\nSubject: Aviso de seguridad\n"


def _b64(text: str, encoding: str) -> str:
    return base64.b64encode(text.encode(encoding)).decode()


def _multipart(plain_headers: str, plain: str, html_headers: str, html: str) -> str:
    return (
        HEADERS
        + 'Content-Type: multipart/alternative; boundary="SEP"\n\n'
        + f"--SEP\n{plain_headers}\n\n{plain}\n"
        + f"--SEP\n{html_headers}\n\n{html}\n"
        + "--SEP--\n"
    )


EMAILS = {
    "sin-content-type": HEADERS + "\n{body}\n",
    "charset-utf8-8bit": HEADERS + "Content-Type: text/plain; charset=utf-8\n\n{body}\n",
    "charset-latin1-8bit": HEADERS + "Content-Type: text/plain; charset=iso-8859-1\n\n{body}\n",
    "charset-desconocido": HEADERS + "Content-Type: text/plain; charset=x-inventado\n\n{body}\n",
    "html-sin-charset": HEADERS + "Content-Type: text/html\n\n<p>{body}</p>\n",
}


def _body(raw: str) -> str:
    return email_extractor._get_body(email_extractor._parse_email(raw))


@pytest.mark.parametrize("template", EMAILS.values(), ids=EMAILS.keys())
def test_cuerpo_8bit_se_conserva_intacto(template):
    assert TEXT in _body(template.format(body=TEXT))


def test_multipart_sin_charset_conserva_ambas_partes():
    raw = _multipart("Content-Type: text/plain", TEXT, "Content-Type: text/html", f"<b>{TEXT}</b>")

    body = _body(raw)

    assert body.count(TEXT) == 2


@pytest.mark.parametrize("encoding, declared", [
    ("utf-8", None),
    ("cp1252", None),
    ("utf-8", "utf-8"),
    ("cp1252", "windows-1252"),
    ("utf-8", "x-inventado"),
    ("cp1252", "utf-8"),
], ids=["utf8-sin-charset", "cp1252-sin-charset", "utf8-declarado", "cp1252-declarado",
        "charset-desconocido", "charset-erroneo"])
def test_base64_se_decodifica_sin_perder_caracteres(encoding, declared):
    ctype = "text/plain" + (f"; charset={declared}" if declared else "")
    raw = (
        HEADERS + f"Content-Type: {ctype}\nContent-Transfer-Encoding: base64\n\n"
        + _b64(TEXT, encoding) + "\n"
    )

    assert _body(raw).strip() == TEXT


def test_quoted_printable_utf8():
    raw = (
        HEADERS + "Content-Type: text/plain; charset=utf-8\n"
        "Content-Transfer-Encoding: quoted-printable\n\n"
        "Su contrase=C3=B1a caduca en 3 d=C3=ADas.\n"
    )
    assert "Su contraseña caduca en 3 días." in _body(raw)


def test_bytes_que_ninguna_codificacion_acepta_no_se_pierden():
    data = "contraseña".encode("latin-1") + b"\x81\x8d"
    assert email_extractor._decode_bytes(data, None) == data.decode("latin-1")


def test_cabecera_con_tildes_en_el_remitente_y_asunto():
    raw = 'From: "Atención al Cliente" <avisos@banco-ejemplo.test>\nSubject: Verificación de su número\n\nTexto.\n'
    features = email_extractor.extract_email_features(raw)

    assert features["sender_display_name"] == "Atención al Cliente"
    assert features["subject"] == "Verificación de su número"


VARIANTS = {
    "sin-content-type": HEADERS + "\n" + PHISHING_BODY + "\n",
    "charset-utf8-8bit": HEADERS + "Content-Type: text/plain; charset=utf-8\n\n" + PHISHING_BODY + "\n",
    "multipart-sin-charset": _multipart("Content-Type: text/plain", PHISHING_BODY,
                                        "Content-Type: text/html", f"<p>{PHISHING_BODY}</p>"),
    "base64-cp1252": (HEADERS + "Content-Type: text/plain\nContent-Transfer-Encoding: base64\n\n"
                      + _b64(PHISHING_BODY, "cp1252") + "\n"),
    "solo-cuerpo": PHISHING_BODY,
}


@pytest.mark.parametrize("raw", VARIANTS.values(), ids=VARIANTS.keys())
def test_reglas_con_tilde_detectan_las_frases(raw):
    features = email_extractor.extract_email_features(raw)

    assert PHISHING_BODY in features["body_preview"] or features["body_preview"] in PHISHING_BODY
    assert "\ufffd" not in features["body_preview"]
    assert {"contrasena", "numero de tarjeta", "codigo de verificacion", "inicie sesion"} <= set(
        features["credential_requests"]
    )
    assert {"perdera el acceso", "actividad inusual", "sancion"} <= set(features["threat_phrases"])
    assert "ultima oportunidad" in features["urgency_phrases"]


def test_endpoint_sin_content_type_conserva_el_texto_y_detecta_phishing(client):
    body = client.post("/api/analyze/email", json={"content": VARIANTS["sin-content-type"]}).json()

    assert body["analysis_mode"] == "fallback"
    assert body["verdict"] == "PHISHING"
    details = " ".join(i["detail"] for i in body["indicators"])
    assert "contrasena" in details or "contraseña" in details


def test_email_de_phishing_de_la_suite_ya_no_pierde_la_enie():
    features = email_extractor.extract_email_features(PHISHING_EMAIL)

    assert "contraseña" in features["body_preview"]
    assert "contrasena" in features["credential_requests"]
