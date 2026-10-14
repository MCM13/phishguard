"""RNF-01: rate limit por IP, sin bypass mediante X-Forwarded-For."""

from __future__ import annotations

import json

from starlette.requests import Request

from app.services.client_ip import get_client_ip

URL = "https://www.example.com/"


def _request(peer: str, *xff: str) -> Request:
    headers = [(b"x-forwarded-for", value.encode()) for value in xff]
    return Request({"type": "http", "headers": headers, "client": (peer, 12345)})


def test_rnf01_analisis_limitado_con_429_y_retry_after(client, monkeypatch, audit_log):
    monkeypatch.setenv("RATE_LIMIT_ANALYZE", "3/minute")

    codes = [client.post("/api/analyze/url", json={"url": URL}).status_code for _ in range(4)]

    assert codes == [200, 200, 200, 429]
    last = client.post("/api/analyze/url", json={"url": URL})
    assert last.headers["retry-after"] == "60"
    assert json.loads(audit_log[-1])["rate_limited"] is True


def test_rnf01_xff_falso_no_evita_el_bloqueo_sin_proxy(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ANALYZE", "3/minute")

    codes = [
        client.post(
            "/api/analyze/url", json={"url": URL},
            headers={"X-Forwarded-For": f"198.51.100.{i}"},
        ).status_code
        for i in range(6)
    ]

    assert codes == [200, 200, 200, 429, 429, 429]


def test_rnf01_xff_falso_no_evita_el_bloqueo_detras_de_render(client, monkeypatch):
    """Con 1 proxy de confianza, el cliente sólo controla lo que hay a la izquierda."""
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("RATE_LIMIT_ANALYZE", "3/minute")

    codes = [
        client.post(
            "/api/analyze/url", json={"url": URL},
            headers={"X-Forwarded-For": f"198.51.100.{i}, 192.0.2.{i}, 203.0.113.7"},
        ).status_code
        for i in range(6)
    ]

    assert codes == [200, 200, 200, 429, 429, 429]


def test_rnf01_historial_limita_intentos_de_token(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_HISTORY", "5/minute")

    codes = [
        client.get("/api/history", headers={"Authorization": f"Bearer intento-{i}"}).status_code
        for i in range(7)
    ]

    assert codes == [401] * 5 + [429] * 2


def test_rnf01_historial_sin_token_cuenta_para_el_limite_por_defecto(client, monkeypatch):
    """El 401 de ADMIN_TOKEN no debe saltarse el rate limit (30/min por defecto)."""
    monkeypatch.setenv("RATE_LIMIT_HISTORY", "30/minute")

    codes = [client.get("/api/history").status_code for _ in range(35)]

    assert codes[:30] == [401] * 30
    assert codes[30:] == [429] * 5


def test_rnf01_analisis_invalido_422_tambien_cuenta(client, monkeypatch):
    """FastAPI no debe devolver 422 antes de que slowapi cuente la petición."""
    monkeypatch.setenv("RATE_LIMIT_ANALYZE", "3/minute")

    codes = [
        client.post("/api/analyze/url", json={"url": "ab"}).status_code
        for _ in range(5)
    ]

    assert codes == [422, 422, 422, 429, 429]


def test_rnf01_stats_tiene_limite(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_STATS", "2/minute")

    codes = [client.get("/api/stats").status_code for _ in range(3)]

    assert codes == [200, 200, 429]


def test_get_client_ip_sin_proxy_usa_el_socket(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "0")
    assert get_client_ip(_request("10.1.1.1", "198.51.100.9")) == "10.1.1.1"


def test_get_client_ip_toma_la_entrada_anadida_por_el_proxy(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    assert get_client_ip(_request("10.1.1.1", "198.51.100.9, 203.0.113.7")) == "203.0.113.7"
    # Varias cabeceras equivalen a una lista concatenada
    assert get_client_ip(_request("10.1.1.1", "198.51.100.9", "203.0.113.8")) == "203.0.113.8"

    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "2")
    assert get_client_ip(_request("10.1.1.1", "198.51.100.9, 203.0.113.7, 10.0.0.2")) == "203.0.113.7"


def test_get_client_ip_rechaza_valores_no_fiables(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    assert get_client_ip(_request("10.1.1.1", "no-es-una-ip")) == "10.1.1.1"
    assert get_client_ip(_request("10.1.1.1")) == "10.1.1.1"

    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "3")
    assert get_client_ip(_request("10.1.1.1", "198.51.100.9")) == "10.1.1.1"

    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "uno")
    assert get_client_ip(_request("10.1.1.1", "198.51.100.9")) == "10.1.1.1"


def test_get_client_ip_solo_acepta_cabecera_desde_redes_de_confianza(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8")

    assert get_client_ip(_request("10.1.1.1", "203.0.113.7")) == "203.0.113.7"
    assert get_client_ip(_request("192.0.2.50", "203.0.113.7")) == "192.0.2.50"
