"""RF-10, RF-11, RF-12: persistencia minimizada, historial protegido y estadísticas."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta

import pytest

from app.database import SessionLocal
from app.models.analysis import Analysis
from tests.conftest import ADMIN_TOKEN, DB_PATH, PHISHING_EMAIL

SECRET_MARKER = "CUERPO-PRIVADO-7f3a91"


def _seed(n: int, verdict: str = "SOSPECHOSO") -> None:
    db = SessionLocal()
    try:
        base = datetime(2026, 1, 1)
        for i in range(n):
            db.add(Analysis(
                id=str(uuid.uuid4()), type="url", score=40, verdict=verdict,
                analysis_mode="fallback", target_domain=f"d{i}.example.test",
                input_hash="0" * 64, timestamp=base + timedelta(minutes=i),
            ))
        db.commit()
    finally:
        db.close()


@pytest.mark.parametrize("headers, reason", [
    ({}, "missing_token"),
    ({"Authorization": "Bearer token-incorrecto"}, "invalid_token"),
    ({"Authorization": f"Basic {ADMIN_TOKEN}"}, "missing_token"),
    ({"Authorization": f"Bearer {ADMIN_TOKEN}x"}, "invalid_token"),
])
def test_historial_sin_token_valido_da_401_generico_y_se_audita(client, audit_log, headers, reason):
    response = client.get("/api/history", headers=headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "No autorizado."}
    assert response.headers["www-authenticate"] == "Bearer"
    entry = json.loads(audit_log[-1])
    assert entry["path"] == "/api/history"
    assert entry["event"] == "admin_auth_failed"
    assert entry["reason"] == reason
    assert ADMIN_TOKEN not in audit_log[-1]


def test_historial_cerrado_si_el_servidor_no_tiene_token(client, monkeypatch, audit_log):
    monkeypatch.setenv("ADMIN_TOKEN", "")

    response = client.get("/api/history", headers={"Authorization": "Bearer cualquier-cosa"})

    assert response.status_code == 401
    assert json.loads(audit_log[-1])["reason"] == "server_not_configured"


def test_historial_con_token_da_200_sin_cuerpos_de_email(client, admin_headers):
    email = PHISHING_EMAIL + f"\nReferencia interna: {SECRET_MARKER}\n"
    client.post("/api/analyze/email", json={"content": email})
    client.post("/api/analyze/url", json={"url": f"https://login.example.test/?ref={SECRET_MARKER}"})

    response = client.get("/api/history", headers=admin_headers)

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 2
    for item in items:
        assert set(item) == {"id", "type", "score", "verdict", "analysis_mode", "domain", "fingerprint", "timestamp"}
    assert SECRET_MARKER not in response.text
    assert "Verifique su cuenta" not in response.text
    assert {i["domain"] for i in items} == {"paypa1-soporte.test", "login.example.test"}


def test_rf10_se_guarda_solo_lo_minimo(client):
    url = f"https://login.example.test/reset?user={SECRET_MARKER}"
    client.post("/api/analyze/url", json={"url": url})

    columns = {c.name for c in Analysis.__table__.columns}
    assert columns == {"id", "type", "score", "verdict", "analysis_mode", "target_domain", "input_hash", "timestamp"}

    db = SessionLocal()
    try:
        row = db.query(Analysis).one()
    finally:
        db.close()
    assert row.target_domain == "login.example.test"
    assert row.input_hash == hashlib.sha256(url.encode()).hexdigest()
    assert SECRET_MARKER.encode() not in DB_PATH.read_bytes()


def test_rf11_paginacion_y_filtro(client, admin_headers):
    _seed(25)
    _seed(3, verdict="PHISHING")

    page = client.get("/api/history", params={"page": 3, "page_size": 10}, headers=admin_headers).json()
    assert page["total"] == 28
    assert page["total_pages"] == 3
    assert len(page["items"]) == 8

    newest = client.get("/api/history", params={"page_size": 1}, headers=admin_headers).json()["items"][0]
    assert newest["domain"] == "d24.example.test"

    phishing = client.get("/api/history", params={"verdict": "phishing"}, headers=admin_headers).json()
    assert phishing["total"] == 3
    assert all(i["verdict"] == "PHISHING" for i in phishing["items"])

    legit = client.get("/api/history", params={"verdict": "LEGITIMO"}, headers=admin_headers)
    assert legit.status_code == 200
    inconclusive = client.get("/api/history", params={"verdict": "NO_CONCLUYENTE"}, headers=admin_headers)
    assert inconclusive.status_code == 200


def test_rf12_estadisticas(client):
    _seed(3, verdict="PHISHING")
    _seed(1, verdict="SOSPECHOSO")

    stats = client.get("/api/stats").json()

    assert stats["total_analyzed"] == 4
    assert stats["phishing_detected"] == 3
    assert stats["detection_rate"] == 75.0
    assert stats["avg_score"] == 40.0
    assert {"enabled", "can_call_claude", "hourly", "daily"} <= set(stats["anthropic_quota"])
