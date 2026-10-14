"""RF-07 (veredicto con IA) y RNF-07 (cuota configurable de Anthropic)."""

from __future__ import annotations

import json

from app.services import anthropic_rate_limit


def test_rf07_respuesta_de_la_ia_se_normaliza(client, fake_claude):
    fake_claude.response_text = "Aquí va el análisis:\n" + json.dumps({
        "score": 150,
        "verdict": "legitimo",
        "indicators": [{"name": "Dominio conocido", "severity": "crítica", "detail": "ok"}, "basura"],
        "explanation": "Parece legítimo.",
    })

    body = client.post("/api/analyze/url", json={"url": "https://www.example.com/"}).json()

    assert fake_claude.calls == 1
    assert body["analysis_mode"] == "ai"
    assert body["analysis_label"] == "Análisis con IA"
    assert body["score"] == 100
    assert body["verdict"] == "LEGÍTIMO"
    assert body["indicators"] == [{"name": "Dominio conocido", "severity": "low", "detail": "ok"}]


def test_rf07_respuesta_no_json_de_la_ia_activa_el_respaldo(client, fake_claude):
    fake_claude.response_text = "Lo siento, no puedo ayudar con eso."

    body = client.post("/api/analyze/url", json={"url": "https://www.example.com/"}).json()

    assert body["analysis_mode"] == "fallback"
    assert body["verdict"] != "LEGÍTIMO"


def test_rnf07_cuota_diaria_configurable_por_entorno(client, fake_claude, monkeypatch):
    fake_claude.response_text = json.dumps({"score": 5, "verdict": "LEGÍTIMO", "indicators": [], "explanation": "ok"})
    monkeypatch.setenv("ANTHROPIC_MAX_PER_DAY", "2")
    monkeypatch.setenv("ANTHROPIC_MAX_PER_HOUR", "0")

    modes = [
        client.post("/api/analyze/url", json={"url": f"https://www.example.com/{i}"}).json()["analysis_mode"]
        for i in range(3)
    ]

    assert modes == ["ai", "ai", "fallback"]
    assert fake_claude.calls == 2
    quota = client.get("/api/stats").json()["anthropic_quota"]
    assert quota["daily"] == {"limit": 2, "used": 2, "remaining": 0, "unlimited": False}
    assert quota["can_call_claude"] is False

    monkeypatch.setenv("ANTHROPIC_MAX_PER_DAY", "5")
    assert anthropic_rate_limit.check_and_consume_quota() == (True, None)


def test_rnf07_cuota_horaria(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MAX_PER_HOUR", "1")
    monkeypatch.setenv("ANTHROPIC_MAX_PER_DAY", "0")

    assert anthropic_rate_limit.check_and_consume_quota()[0] is True
    allowed, reason = anthropic_rate_limit.check_and_consume_quota()
    assert allowed is False
    assert "horario" in reason


def test_rnf07_valor_invalido_usa_el_por_defecto(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MAX_PER_DAY", "muchas")
    assert anthropic_rate_limit.max_per_day() == anthropic_rate_limit.DEFAULT_MAX_PER_DAY
