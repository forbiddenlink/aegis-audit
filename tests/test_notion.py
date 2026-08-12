"""Notion push integration (optional alert sink)."""

from datetime import datetime, timezone

import httpx

from aegisaudit.integrations.notion import _status, push_to_notion
from aegisaudit.models import ScanResult, ScanSummary


def _result(score: float = 95.0, targets=None) -> ScanResult:
    return ScanResult(
        tool_version="0.1.0",
        targets=targets if targets is not None else ["https://example.com"],
        finished_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
        summary=ScanSummary(
            counts_by_severity={"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
            overall_score=score,
        ),
    )


def test_status_thresholds():
    assert _status(90.0) == "pass"
    assert _status(70.0) == "warn"
    assert _status(69.9) == "fail"


def test_push_noop_without_credentials(monkeypatch):
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: calls.append(1))
    push_to_notion(_result(), db_id="", token="tok")
    push_to_notion(_result(), db_id="db", token="")
    assert calls == []


def test_push_payload_shape(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        httpx,
        "post",
        lambda url, headers=None, json=None, timeout=None: captured.update(
            url=url, headers=headers, json=json
        ),
    )
    push_to_notion(_result(score=55.0), db_id="db123", token="tok")

    assert captured["url"].endswith("/pages")
    assert captured["headers"]["Authorization"] == "Bearer tok"
    props = captured["json"]["properties"]
    assert captured["json"]["parent"]["database_id"] == "db123"
    assert props["Score"]["number"] == 55.0
    assert props["Critical"]["number"] == 1
    assert props["Status"]["select"]["name"] == "fail"


def test_push_scan_type_is_audit_for_non_http_targets(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        httpx, "post", lambda url, headers=None, json=None, timeout=None: captured.update(json=json)
    )
    push_to_notion(_result(targets=["./src"]), db_id="db", token="tok")
    assert captured["json"]["properties"]["Scan Type"]["select"]["name"] == "audit"


def test_push_swallows_transport_error(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "post", boom)
    push_to_notion(_result(), db_id="db", token="tok")  # must not raise
