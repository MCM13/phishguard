"""
H-04: las llamadas bloqueantes (SDK de Anthropic, WHOIS, DNS) no bloquean el event loop.

WHOIS y la IA se simulan con funciones que duermen en el hilo (time.sleep).
Mientras tanto, otra corrutina debe poder seguir ejecutándose.
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx

from app.main import app
from app.services import claude_analyzer, url_extractor

SLOW = 0.6


async def _ticks_during(coro) -> tuple[int, object]:
    ticks = 0
    stop = False

    async def ticker():
        nonlocal ticks
        while not stop:
            ticks += 1
            await asyncio.sleep(0.02)

    task = asyncio.create_task(ticker())
    try:
        result = await coro
    finally:
        stop = True
        await task
    return ticks, result


def test_llamada_a_claude_fuera_del_event_loop(fake_claude, monkeypatch):
    original = fake_claude._create

    def slow_create(self, **kwargs):
        time.sleep(SLOW)
        return original(self, **kwargs)

    monkeypatch.setattr(fake_claude, "_create", slow_create)
    fake_claude.response_text = json.dumps({
        "score": 5, "verdict": "LEGÍTIMO", "indicators": [], "explanation": "ok",
    })

    ticks, result = asyncio.run(_ticks_during(
        claude_analyzer.analyze_with_claude({"url": "https://www.example.com/"}, None, "url")
    ))

    assert result["analysis_mode"] == "ai"
    assert ticks >= 10, "el event loop estuvo bloqueado durante la llamada a la IA"


def test_whois_no_bloquea_otras_peticiones(client, monkeypatch):
    def slow_whois(domain):
        time.sleep(SLOW)
        return None

    monkeypatch.setattr(url_extractor, "_get_domain_age_days", slow_whois)

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            finished = []

            async def analyze():
                response = await http.post("/api/analyze/url", json={"url": "https://www.example.com/"})
                finished.append("analyze")
                return response

            async def health():
                await asyncio.sleep(0.1)
                response = await http.get("/")
                finished.append("health")
                return response

            slow, fast = await asyncio.gather(analyze(), health())
            return slow.status_code, fast.status_code, finished

    slow_status, fast_status, order = asyncio.run(scenario())

    assert (slow_status, fast_status) == (200, 200)
    assert order == ["health", "analyze"], "la petición de salud esperó a que terminara WHOIS"
