"""RNF-02 (cabeceras OWASP), RNF-03 (anti-SSRF), RNF-04 (entradas), RNF-09 (errores)."""

from __future__ import annotations

import ipaddress

import pytest

from app.routers import analyze
from app.services import url_validator, virustotal
from tests.conftest import REAL_RESOLVE_HOSTNAME

OWASP_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
    "content-security-policy": "default-src 'self'",
}


# ---------------- RNF-02 ----------------

@pytest.mark.parametrize("method, path, kwargs", [
    ("get", "/", {}),
    ("get", "/api/stats", {}),
    ("get", "/api/history", {}),
    ("get", "/no-existe", {}),
    ("post", "/api/analyze/url", {"json": {"url": "ftp://example.com/"}}),
])
def test_rnf02_cabeceras_owasp_en_todas_las_respuestas(client, method, path, kwargs):
    response = getattr(client, method)(path, **kwargs)

    for header, value in OWASP_HEADERS.items():
        assert response.headers.get(header) == value, header
    assert "strict-transport-security" not in response.headers


def test_rnf02_hsts_solo_con_https(client):
    response = client.get("/", headers={"X-Forwarded-Proto": "https"})
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"


# ---------------- RNF-03 ----------------

@pytest.fixture
def no_external_calls(monkeypatch):
    async def fail(url):
        raise AssertionError(f"no debería consultarse VirusTotal para {url}")
    monkeypatch.setattr(virustotal, "analyze_url", fail)


@pytest.mark.parametrize("url", [
    "http://localhost/admin",
    "http://LOCALHOST:8000/",
    "http://127.0.0.1/",
    "http://127.1.2.3:8080/",
    "http://0.0.0.0/",
    "http://10.0.0.1/",
    "http://172.16.5.4/",
    "http://192.168.1.10/router",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://[fd00::1]/",
    "http://224.0.0.1/",
])
def test_rnf03_bloquea_destinos_internos(client, no_external_calls, url):
    response = client.post("/api/analyze/url", json={"url": url})

    assert response.status_code == 400


def test_rnf03_bloquea_dominio_que_resuelve_a_ip_privada(client, monkeypatch, no_external_calls):
    # Mock DNS: el dominio ficticio resuelve a una IP interna (DNS rebinding)
    monkeypatch.setattr(
        url_validator, "_resolve_hostname",
        lambda host: (ipaddress.ip_address("93.184.216.34"), ipaddress.ip_address("10.20.30.40")),
    )

    response = client.post("/api/analyze/url", json={"url": "https://intranet.example.test/"})

    assert response.status_code == 400
    assert "privada" in response.json()["detail"]


@pytest.mark.parametrize("url", [
    "ftp://example.com/fichero",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "example.com/sin-esquema",
    "http:///sin-host",
])
def test_rnf03_solo_http_y_https(client, no_external_calls, url):
    assert client.post("/api/analyze/url", json={"url": url}).status_code == 400


def test_rnf03_dns_que_no_resuelve_no_bloquea(monkeypatch):
    import socket

    def no_dns(*args, **kwargs):
        raise socket.gaierror("sin resolución (simulado)")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    monkeypatch.setattr(url_validator, "_resolve_hostname", REAL_RESOLVE_HOSTNAME)
    assert url_validator.validate_public_url("https://recien-creado.example.test/") == "https://recien-creado.example.test/"


# ---------------- RNF-04 ----------------

@pytest.mark.parametrize("path, payload, expected", [
    ("/api/analyze/url", {}, 422),
    ("/api/analyze/url", {"url": "ab"}, 422),
    ("/api/analyze/url", {"url": "https://example.com/" + "a" * 2100}, 422),
    ("/api/analyze/url", {"url": 12345}, 422),
    ("/api/analyze/url", {"url": "   "}, 400),
    ("/api/analyze/email", {}, 422),
    ("/api/analyze/email", {"content": "x" * 9}, 422),
    ("/api/analyze/email", {"content": "x" * 50_001}, 422),
    ("/api/analyze/email", {"content": "<script>alert('xss')</script><b></b>"}, 400),
])
def test_rnf04_entradas_invalidas(client, path, payload, expected):
    assert client.post(path, json=payload).status_code == expected


def test_rnf04_json_malformado(client):
    response = client.post(
        "/api/analyze/url", content=b"{url: sin comillas", headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_rnf04_solo_json(client):
    response = client.post(
        "/api/analyze/url", content=b"url=https://example.com/",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 415


def test_rnf04_cuerpo_maximo_1mb(client):
    big = b'{"content": "' + b"a" * (1024 * 1024 + 10) + b'"}'
    response = client.post("/api/analyze/email", content=big, headers={"Content-Type": "application/json"})
    assert response.status_code == 413


@pytest.mark.parametrize("params", [
    {"page": 0}, {"page": "uno"}, {"page_size": 0}, {"page_size": 101},
])
def test_rnf04_parametros_de_historial_invalidos(client, admin_headers, params):
    assert client.get("/api/history", params=params, headers=admin_headers).status_code == 422


def test_rnf04_veredicto_de_filtro_invalido(client, admin_headers):
    response = client.get("/api/history", params={"verdict": "DROP TABLE"}, headers=admin_headers)
    assert response.status_code == 400


# ---------------- RNF-09 ----------------

def test_rnf09_error_interno_es_generico(client, monkeypatch):
    def explode(url):
        raise RuntimeError("ruta /app/secreto.py línea 42")

    monkeypatch.setattr(analyze.url_extractor, "extract_url_features", explode)

    response = client.post("/api/analyze/url", json={"url": "https://www.example.com/"})

    assert response.status_code == 500
    assert response.json() == {"detail": "Error interno analizando la URL."}
    assert "RuntimeError" not in response.text
    assert "secreto" not in response.text
