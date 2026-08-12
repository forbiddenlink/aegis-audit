"""Tests for outbound alerting.

The alert path is a data-exfil surface: it posts scan results to a URL that can
come from CI config an attacker may influence. These tests pin the guardrails
(https-only, provider allowlist, HTML escaping) and the fire-and-forget
resilience, so a regression cannot silently turn alerts into an SSRF/exfil
primitive or crash a scan on a flaky webhook.
"""

from datetime import datetime, timezone

import httpx
import pytest

from aegisaudit.models import ScanResult, ScanSummary
from aegisaudit.notifications import (
    _webhook_allowed,
    send_telegram,
    send_webhook,
)


def _result(score: float = 95.0, targets=None) -> ScanResult:
    return ScanResult(
        tool_version="0.1.0",
        targets=targets if targets is not None else ["https://example.com"],
        started_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, 12, 1, tzinfo=timezone.utc),
        summary=ScanSummary(
            counts_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            overall_score=score,
        ),
    )


# --- allowlist / scheme enforcement ---------------------------------------


@pytest.mark.parametrize(
    "url,allowed",
    [
        ("https://hooks.slack.com/services/T/B/x", True),
        ("https://discord.com/api/webhooks/1/x", True),
        ("https://canary.discord.com/api/webhooks/1/x", True),
        ("https://ptb.discord.com/api/webhooks/1/x", True),
        # http is refused even on an allowlisted host
        ("http://hooks.slack.com/services/T/B/x", False),
        # arbitrary hosts are refused
        ("https://evil.example.com/webhook", False),
        # look-alike suffix must not match (endswith guard is on ".host")
        ("https://hooks.slack.com.evil.com/x", False),
        ("https://notdiscord.com/x", False),
        ("", False),
    ],
)
def test_webhook_allowlist(url, allowed):
    assert _webhook_allowed(url) is allowed


def test_send_webhook_refuses_non_allowlisted(monkeypatch):
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: calls.append((a, k)))
    send_webhook("https://evil.example.com/x", _result())
    assert calls == []  # nothing was sent


def test_send_webhook_empty_url_is_noop(monkeypatch):
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: calls.append(1))
    send_webhook("", _result())
    assert calls == []


# --- payload shape --------------------------------------------------------


def test_send_webhook_discord_payload(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json

    monkeypatch.setattr(httpx, "post", fake_post)
    url = "https://discord.com/api/webhooks/1/abc"
    send_webhook(url, _result(score=55.0, targets=["https://a.test"]))

    assert captured["url"] == url
    assert "embeds" in captured["json"]
    embed = captured["json"]["embeds"][0]
    assert embed["color"] == 0xFF0000  # red for a failing score
    assert "55.0" in embed["title"]


def test_send_webhook_slack_payload(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        httpx, "post", lambda url, json=None, timeout=None: captured.update(url=url, json=json)
    )
    url = "https://hooks.slack.com/services/T/B/x"
    send_webhook(url, _result(score=95.0))

    assert captured["url"] == url
    assert "text" in captured["json"]
    assert "white_check_mark" in captured["json"]["text"]  # green for a passing score


def test_send_webhook_swallows_transport_error(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("network down")

    monkeypatch.setattr(httpx, "post", boom)
    # Fire-and-forget: a broken webhook must not fail the scan.
    send_webhook("https://hooks.slack.com/services/T/B/x", _result())


# --- telegram -------------------------------------------------------------


def test_send_telegram_noop_without_credentials(monkeypatch):
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: calls.append(1))
    send_telegram("", "123", _result())
    send_telegram("token", "", _result())
    assert calls == []


def test_send_telegram_escapes_html_in_target(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        httpx, "post", lambda url, json=None, timeout=None: captured.update(url=url, json=json)
    )
    # A scanned target carrying HTML must not break out of the parse_mode=HTML body.
    send_telegram("tok", "chat1", _result(targets=["https://x.test/<script>"]))

    body = captured["json"]["text"]
    assert "<script>" not in body
    assert "&lt;script&gt;" in body
    assert captured["json"]["parse_mode"] == "HTML"


def test_send_telegram_swallows_transport_error(monkeypatch):
    monkeypatch.setattr(
        httpx, "post", lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("down"))
    )
    send_telegram("tok", "chat1", _result())  # must not raise
