"""
Configuración común de la suite.

Los tests no hacen ninguna petición de red real. Las APIs externas
(VirusTotal, URLScan, Anthropic), WHOIS y la resolución DNS se SIMULAN con
mocks sólo aquí, en los tests; el código de la aplicación no tiene modos de
prueba. Todas las URLs usadas son ficticias (example.com y dominios .test).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

# El motor de SQLAlchemy se crea al importar app.database, así que el entorno
# debe estar listo antes de importar la aplicación.
_TMP_DIR = Path(tempfile.mkdtemp(prefix="phishguard-tests-"))
DB_PATH = _TMP_DIR / "test.db"
ADMIN_TOKEN = "token-de-pruebas-ficticio-0123456789"

os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH.as_posix()}"
os.environ["ADMIN_TOKEN"] = ADMIN_TOKEN
os.environ["ALLOWED_ORIGINS"] = "http://localhost:3000"
for _var in ("ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "FRONTEND_URL"):
    os.environ[_var] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app.database import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.analysis import Analysis  # noqa: E402
from app.models.anthropic_usage import AnthropicUsageLog  # noqa: E402
from app.services import claude_analyzer, url_extractor, url_validator  # noqa: E402
from app.services.rate_limit import limiter  # noqa: E402

# Tablas creadas aunque el primer test no arranque la app con TestClient
init_db()

PUBLIC_TEST_IP = ipaddress.ip_address("93.184.216.34")
_REAL_ASYNC_CLIENT = httpx.AsyncClient
REAL_DOMAIN_AGE = url_extractor._get_domain_age_days
REAL_RESOLVE_HOSTNAME = url_validator._resolve_hostname

PHISHING_EMAIL = """From: "PayPal Seguridad" <alertas@paypa1-soporte.test>
Reply-To: cobros@otro-dominio.test
Subject: URGENTE: su cuenta ha sido suspendida
Content-Type: text/html; charset=utf-8

<p>Detectamos actividad inusual. Su cuenta sera bloqueada en 24 horas.</p>
<p>Verifique su cuenta e introduzca su contraseña y el numero de tarjeta:
<a href="http://paypal-login.verify-account.test/confirm">https://www.paypal.com/signin</a></p>
<p>Descargue el adjunto factura.pdf.exe</p>
"""

BENIGN_EMAIL = "Hola equipo, os paso el acta de la reunion del martes. Un saludo."


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_headers():
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Estado limpio y sin red en cada test."""
    for var in ("ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY"):
        monkeypatch.setenv(var, "")
    for var in (
        "TRUSTED_PROXY_HOPS", "TRUSTED_PROXY_CIDRS", "TRUST_CF_CONNECTING_IP",
        "RATE_LIMIT_ANALYZE", "RATE_LIMIT_HISTORY", "RATE_LIMIT_STATS",
        "ANTHROPIC_MAX_PER_DAY", "ANTHROPIC_MAX_PER_HOUR",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ADMIN_TOKEN", ADMIN_TOKEN)

    # Mock: WHOIS y DNS nunca salen a la red durante los tests.
    monkeypatch.setattr(url_extractor, "_get_domain_age_days", lambda domain: None)
    monkeypatch.setattr(url_validator, "_resolve_hostname", lambda host: (PUBLIC_TEST_IP,))

    limiter.reset()
    db = SessionLocal()
    try:
        db.query(Analysis).delete()
        db.query(AnthropicUsageLog).delete()
        db.commit()
    finally:
        db.close()
    yield


@pytest.fixture
def mock_http(monkeypatch):
    """
    Mock: sustituye httpx.AsyncClient (usado por VirusTotal y URLScan) por uno
    con transporte simulado. Devuelve una función para registrar el handler.
    """
    state = {"handler": None, "requests": []}

    def install(handler):
        state["handler"] = handler

    def dispatch(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        return state["handler"](request)

    def fake_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(dispatch)
        return _REAL_ASYNC_CLIENT(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)
    install.requests = state["requests"]
    return install


class FakeAnthropic:
    """Mock del SDK de Anthropic: devuelve el texto configurado o lanza el error."""

    calls = 0
    response_text = ""
    error: Exception | None = None
    last_request: dict = {}

    def __init__(self, api_key: str, **options):
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        FakeAnthropic.calls += 1
        FakeAnthropic.last_request = kwargs
        if FakeAnthropic.error is not None:
            raise FakeAnthropic.error
        return SimpleNamespace(content=[SimpleNamespace(text=FakeAnthropic.response_text)])


@pytest.fixture
def fake_claude(monkeypatch):
    """Activa la IA con una clave ficticia y el SDK simulado."""
    FakeAnthropic.calls = 0
    FakeAnthropic.response_text = ""
    FakeAnthropic.error = None
    FakeAnthropic.last_request = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "clave-ficticia-de-test")
    monkeypatch.setattr(claude_analyzer, "Anthropic", FakeAnthropic)
    return FakeAnthropic


class AuditCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


@pytest.fixture
def audit_log():
    """Captura el canal phishguard.audit (no propaga al root, caplog no lo ve)."""
    handler = AuditCapture()
    logger = logging.getLogger("phishguard.audit")
    logger.addHandler(handler)
    yield handler.lines
    logger.removeHandler(handler)
