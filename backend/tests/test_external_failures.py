"""RF-09: los fallos de VirusTotal, URLScan, Anthropic y WHOIS no tumban el sistema."""

from __future__ import annotations

import sys
import types

import httpx
import pytest

from app.services import url_extractor
from tests.conftest import PHISHING_EMAIL, REAL_DOMAIN_AGE

URL = "https://login.example.test/"


def _connection_error(request):
    raise httpx.ConnectError("conexión rechazada (simulada)", request=request)


def _timeout(request):
    raise httpx.ReadTimeout("timeout (simulado)", request=request)


@pytest.mark.parametrize("handler", [
    _connection_error,
    _timeout,
    lambda request: httpx.Response(500, text="error interno"),
    lambda request: httpx.Response(429, json={"error": "quota"}),
    lambda request: httpx.Response(200, text="esto no es json"),
], ids=["conexion", "timeout", "http500", "http429", "json-invalido"])
def test_rf09_virustotal_y_urlscan_caidos(client, monkeypatch, mock_http, handler):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "clave-ficticia")
    monkeypatch.setenv("URLSCAN_API_KEY", "clave-ficticia")
    mock_http(handler)

    response = client.post("/api/analyze/url", json={"url": URL})

    assert response.status_code == 200
    assert response.json()["virustotal_available"] is False
    hosts = {r.url.host for r in mock_http.requests}
    assert {"www.virustotal.com", "urlscan.io"} <= hosts


def test_rf09_virustotal_caido_en_analisis_de_email(client, monkeypatch, mock_http):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "clave-ficticia")
    mock_http(_connection_error)

    response = client.post("/api/analyze/email", json={"content": PHISHING_EMAIL})

    assert response.status_code == 200
    assert response.json()["verdict"] == "PHISHING"


@pytest.mark.parametrize("error", [
    RuntimeError("detalle interno sk-ant-FICTICIA"),
    TimeoutError("la API tardó demasiado"),
    ConnectionError("sin red"),
])
def test_rf09_anthropic_caido_usa_respaldo_sin_filtrar_detalles(client, fake_claude, error):
    fake_claude.error = error

    response = client.post("/api/analyze/email", json={"content": PHISHING_EMAIL})

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_mode"] == "fallback"
    assert body["verdict"] == "PHISHING"
    assert str(error) not in response.text
    assert type(error).__name__ not in response.text


def test_rf09_whois_caido(client, monkeypatch):
    def broken_whois(domain):
        raise OSError("whois no disponible (simulado)")

    # Mock: módulo whois que falla, con la función real de url_extractor
    monkeypatch.setitem(sys.modules, "whois", types.SimpleNamespace(whois=broken_whois))
    monkeypatch.setattr(url_extractor, "_get_domain_age_days", REAL_DOMAIN_AGE)

    assert url_extractor._get_domain_age_days("example.test") is None
    response = client.post("/api/analyze/url", json={"url": URL})
    assert response.status_code == 200


def test_rf09_todo_caido_a_la_vez(client, monkeypatch, mock_http, fake_claude):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "clave-ficticia")
    monkeypatch.setenv("URLSCAN_API_KEY", "clave-ficticia")
    mock_http(_connection_error)
    fake_claude.error = RuntimeError("caído")

    response = client.post("/api/analyze/url", json={"url": URL})

    assert response.status_code == 200
    assert response.json()["analysis_mode"] == "fallback"
