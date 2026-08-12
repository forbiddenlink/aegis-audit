"""Scan-history persistence (SQLite trend store)."""

from datetime import datetime, timezone

from aegisaudit.history import ScanHistory
from aegisaudit.models import ScanResult, ScanSummary


def _result(score: float, targets, finished=True) -> ScanResult:
    return ScanResult(
        tool_version="0.1.0",
        targets=targets,
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc) if finished else None,
        summary=ScanSummary(overall_score=score),
    )


def test_add_and_get_history_roundtrip(tmp_path):
    db = ScanHistory(db_path=tmp_path / "h.db")
    db.add_scan(_result(90.0, ["https://a.test"]))
    db.add_scan(_result(70.0, ["https://b.test", "https://c.test"]))

    rows = db.get_history()
    assert len(rows) == 2
    # newest first
    assert rows[0]["score"] == 70.0
    assert set(rows[0]["targets"]) == {"https://b.test", "https://c.test"}
    assert rows[1]["score"] == 90.0


def test_get_history_respects_limit(tmp_path):
    db = ScanHistory(db_path=tmp_path / "h.db")
    for i in range(5):
        db.add_scan(_result(float(i), [f"https://{i}.test"]))
    assert len(db.get_history(limit=2)) == 2


def test_add_scan_without_finished_at_uses_now(tmp_path):
    db = ScanHistory(db_path=tmp_path / "h.db")
    db.add_scan(_result(50.0, ["https://x.test"], finished=False))
    rows = db.get_history()
    assert rows[0]["timestamp"]  # a timestamp was recorded, not left null


def test_creates_db_parent_directory(tmp_path):
    nested = tmp_path / "deep" / "dir" / "h.db"
    ScanHistory(db_path=nested)
    assert nested.parent.is_dir()
