"""RF-02, RF-04, RF-08: análisis de email y motor heurístico sin IA."""

from __future__ import annotations

import pytest

from app.services import email_extractor
from tests.conftest import BENIGN_EMAIL, PHISHING_EMAIL


def test_rf02_analiza_email_completo(client):
    response = client.post("/api/analyze/email", json={"content": PHISHING_EMAIL})

    assert response.status_code == 200
    body = response.json()
    assert {"id", "score", "verdict", "indicators", "ai_explanation", "analysis_mode"} <= set(body)


def test_rf02_rechaza_email_de_menos_de_10_caracteres(client):
    assert client.post("/api/analyze/email", json={"content": "corto"}).status_code == 422


def test_rf04_extrae_senales_del_email():
    features = email_extractor.extract_email_features(PHISHING_EMAIL)

    assert features["sender_domain"] == "paypa1-soporte.test"
    assert features["mismatched_reply_to"] is True
    assert features["display_name_mismatch"] is True
    assert features["urgency_phrases"]
    assert features["credential_requests"]
    assert any("paypal-login.verify-account.test" in u for u in features["urls_found"])
    assert features["link_text_mismatches"], "el texto del enlace muestra paypal.com pero apunta a otro dominio"
    assert features["mentioned_dangerous_files"] or features["dangerous_attachments"]


def test_rf04_detecta_peticiones_de_pago_y_adjuntos_peligrosos():
    email = """From: Aduanas <avisos@correos-envios.test>
Subject: Paquete retenido
Content-Type: multipart/mixed; boundary="SEP"

--SEP
Content-Type: text/plain; charset=utf-8

Su paquete esta retenido. Realice el pago de la tasa de aduana por Bizum hoy mismo.
--SEP
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="albaran.js"

ZmljdGljaW8=
--SEP--
"""
    features = email_extractor.extract_email_features(email)

    assert features["payment_requests"]
    assert features["has_attachments"] is True
    assert [a["filename"] for a in features["dangerous_attachments"]] == ["albaran.js"]


def test_rf08_email_de_phishing_en_modo_sin_ia_no_sale_legitimo(client):
    body = client.post("/api/analyze/email", json={"content": PHISHING_EMAIL}).json()

    assert body["analysis_mode"] == "fallback"
    assert body["analysis_label"] == "Análisis limitado (sin IA)"
    assert body["verdict"] != "LEGÍTIMO"
    assert body["verdict"] == "PHISHING"
    assert body["score"] >= 61
    assert body["indicators"]


def test_rf08_email_sin_senales_en_modo_sin_ia_es_no_concluyente(client):
    body = client.post("/api/analyze/email", json={"content": BENIGN_EMAIL}).json()

    assert body["analysis_mode"] == "fallback"
    assert body["verdict"] == "NO CONCLUYENTE"


@pytest.mark.parametrize("payload", [
    ("/api/analyze/email", {"content": BENIGN_EMAIL}),
    ("/api/analyze/email", {"content": "Reunion manana a las 10 en la sala 2."}),
    ("/api/analyze/url", {"url": "https://www.example.com/"}),
    ("/api/analyze/url", {"url": "https://docs.example.test/manual"}),
])
def test_rf08_el_modo_sin_ia_nunca_declara_legitimo(client, payload):
    path, data = payload
    body = client.post(path, json=data).json()

    assert body["analysis_mode"] == "fallback"
    assert body["verdict"] in {"PHISHING", "SOSPECHOSO", "NO CONCLUYENTE"}
