"""RF-01, RF-03, RF-05, RF-06: análisis de URL y fuentes de reputación."""

from __future__ import annotations

import asyncio

import httpx

from app.services import url_extractor, urlscan, virustotal

SUSPICIOUS_URL = "http://paypal-secure-login.verify-account.test/confirm"


def test_rf01_analiza_url_y_devuelve_contrato_completo(client):
    response = client.post("/api/analyze/url", json={"url": "https://www.example.com/"})

    assert response.status_code == 200
    body = response.json()
    for key in (
        "id", "url", "score", "verdict", "indicators", "ai_explanation",
        "virustotal_detections", "analysis_mode", "analysis_label", "timestamp",
    ):
        assert key in body
    assert 0 <= body["score"] <= 100
    assert isinstance(body["indicators"], list)


def test_rf03_extrae_las_15_caracteristicas_de_la_url():
    features = url_extractor.extract_url_features(SUSPICIOUS_URL)

    assert set(features) == {
        "url", "domain", "tld", "url_length", "subdomain_count", "subdomain",
        "suspicious_keywords", "suspicious_keyword_count", "suspicious_characters",
        "suspicious_character_count", "unusual_tld", "uses_https", "uses_ip_address",
        "domain_age_days", "young_domain",
    }
    assert features["uses_https"] is False
    assert features["unusual_tld"] is True
    assert "login" in features["suspicious_keywords"]
    assert features["subdomain_count"] >= 1


def test_rf05_virustotal_cuenta_positivos(monkeypatch, mock_http):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "clave-ficticia")
    mock_http(lambda request: httpx.Response(200, json={
        "data": {"attributes": {
            "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 6},
            "reputation": -10,
        }}
    }))

    result = asyncio.run(virustotal.analyze_url("https://www.example.com/"))

    assert result["available"] is True
    assert result["positives"] == 4
    assert result["total_engines"] == 70
    assert mock_http.requests[0].url.host == "www.virustotal.com"


def test_rf05_url_desconocida_en_virustotal_se_envia_y_da_resultado_neutro(monkeypatch, mock_http):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "clave-ficticia")
    mock_http(lambda request: httpx.Response(404 if request.method == "GET" else 200, json={}))

    result = asyncio.run(virustotal.analyze_url("https://nuevo.example.test/"))

    assert result["available"] is False
    assert [r.method for r in mock_http.requests] == ["GET", "POST"]


def test_rf05_detecciones_de_virustotal_llegan_a_la_respuesta(client, monkeypatch, mock_http):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "clave-ficticia")
    mock_http(lambda request: httpx.Response(200, json={
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 50}}}
    }))

    body = client.post("/api/analyze/url", json={"url": SUSPICIOUS_URL}).json()

    assert body["virustotal_available"] is True
    assert body["virustotal_detections"] == 5
    assert body["verdict"] == "PHISHING"


def test_rf06_urlscan_detecta_informe_malicioso(monkeypatch, mock_http):
    monkeypatch.setenv("URLSCAN_API_KEY", "clave-ficticia")
    mock_http(lambda request: httpx.Response(200, json={
        "total": 2,
        "results": [
            {"verdicts": {"overall": {"malicious": False}}},
            {"verdicts": {"overall": {"malicious": True, "score": 100}}},
        ],
    }))

    result = asyncio.run(urlscan.analyze_url("https://login.example.test/"))

    assert result["available"] is True
    assert result["malicious"] is True
    assert mock_http.requests[0].url.params["q"] == "domain:login.example.test"


def test_urlscan_no_envia_escaneo_ni_expone_path_o_query(monkeypatch, mock_http):
    """
    Minimización: no se hace POST /scan/ (que indexaría la URL) y la búsqueda
    solo lleva el hostname, nunca tokens ni emails de la query.
    """
    monkeypatch.setenv("URLSCAN_API_KEY", "clave-ficticia")
    mock_http(lambda request: httpx.Response(200, json={"total": 0, "results": []}))

    dirty = (
        "https://reset.example.test/recover"
        "?token=secreto-de-prueba&email=victima%40example.com"
    )
    asyncio.run(urlscan.analyze_url(dirty))

    assert urlscan.REQUIRED_SCAN_VISIBILITY == "unlisted"
    assert len(mock_http.requests) == 1
    req = mock_http.requests[0]
    assert req.method == "GET"
    assert "/scan" not in str(req.url)
    assert str(req.url).startswith("https://urlscan.io/api/v1/search/")
    assert req.url.params["q"] == "domain:reset.example.test"
    sent = str(req.url)
    assert "token" not in sent
    assert "secreto" not in sent
    assert "victima" not in sent
    assert "email" not in sent
