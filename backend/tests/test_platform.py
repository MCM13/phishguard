"""RF-15 (API documentada), RNF-05 (no root), RNF-06 (auditoría), RNF-09 (sin /docs en producción), RNF-12 (configuración)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from app.cors_config import get_allowed_origins
from tests.conftest import ADMIN_TOKEN, PHISHING_EMAIL

BACKEND_DIR = Path(__file__).resolve().parents[1]


def test_rf15_api_documentada(client):
    spec = client.get("/openapi.json")

    assert spec.status_code == 200
    paths = spec.json()["paths"]
    assert {"/api/analyze/url", "/api/analyze/email", "/api/history", "/api/stats"} <= set(paths)


def test_docs_desactivados_en_produccion():
    """La app lee ENVIRONMENT al importarse, así que se comprueba en un proceso aparte."""
    script = textwrap.dedent("""
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        codes = [client.get(p).status_code for p in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect")]
        print(codes, client.get("/").status_code)
    """)
    for value, expected in (("production", "[404, 404, 404, 404] 200"), ("development", "[200, 200, 200, 200] 200")):
        env = {**os.environ, "ENVIRONMENT": value, "PYTHONPATH": str(BACKEND_DIR)}
        result = subprocess.run(
            [sys.executable, "-c", script], env=env, cwd=BACKEND_DIR,
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().splitlines()[-1] == expected, value


def test_health(client):
    assert client.get("/").json()["status"] == "ok"


def test_rnf05_contenedor_sin_root_y_sin_proxy_headers_de_uvicorn():
    dockerfile = (BACKEND_DIR / "Dockerfile").read_text(encoding="utf-8")

    assert "USER appuser" in dockerfile
    assert "--no-proxy-headers" in dockerfile


def test_rnf06_auditoria_json_sin_cuerpos_ni_secretos(client, audit_log, admin_headers):
    marker = "MARCA-DEL-CUERPO-0c1d"
    client.post("/api/analyze/email", json={"content": PHISHING_EMAIL + marker})
    client.get("/api/history", headers=admin_headers)

    entries = [json.loads(line) for line in audit_log]
    analyze_entry = next(e for e in entries if e["path"] == "/api/analyze/email")
    assert analyze_entry["status"] == 200
    assert analyze_entry["verdict"] == "PHISHING"
    assert {"ts_utc", "ip", "method", "status", "latency_ms"} <= set(analyze_entry)
    joined = "\n".join(audit_log)
    assert marker not in joined
    assert "paypa1-soporte" not in joined
    assert ADMIN_TOKEN not in joined


def test_rnf12_cors_desde_entorno(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://app.example.test/, https://app.example.test")
    monkeypatch.setenv("FRONTEND_URL", "https://www.example.test")

    assert get_allowed_origins() == ["https://app.example.test", "https://www.example.test"]


def test_rnf12_cors_rechaza_origen_no_permitido(client):
    allowed = client.options(
        "/api/stats",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
    )
    denied = client.options(
        "/api/stats",
        headers={"Origin": "https://atacante.example.test", "Access-Control-Request-Method": "GET"},
    )

    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "access-control-allow-origin" not in denied.headers
