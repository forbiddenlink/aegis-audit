from typing import Any, Dict

import httpx

from aegisaudit.models import ScanResult, Severity

_NOTION_API = "https://api.notion.com/v1"
_NOTION_VERSION = "2022-06-28"


def _status(score: float) -> str:
    if score >= 90:
        return "pass"
    if score >= 70:
        return "warn"
    return "fail"


def push_to_notion(result: ScanResult, db_id: str, token: str) -> None:
    if not db_id or not token:
        return

    counts = result.summary.counts_by_severity
    score = result.summary.overall_score
    target = ", ".join(result.targets)[:200]
    ts = (result.finished_at or result.started_at).strftime("%Y-%m-%d %H:%M")
    scan_type = "audit" if not any(t.startswith("http") for t in result.targets) else "url"

    properties: Dict[str, Any] = {
        "Name": {"title": [{"text": {"content": f"{target} — {ts}"}}]},
        "Score": {"number": round(score, 1)},
        "Critical": {"number": counts.get(Severity.CRITICAL, 0)},
        "High": {"number": counts.get(Severity.HIGH, 0)},
        "Scan Type": {"select": {"name": scan_type}},
        "Status": {"select": {"name": _status(score)}},
        "Target": {"rich_text": [{"text": {"content": target}}]},
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Notion-Version": _NOTION_VERSION,
        "Content-Type": "application/json",
    }

    try:
        httpx.post(
            f"{_NOTION_API}/pages",
            headers=headers,
            json={"parent": {"database_id": db_id}, "properties": properties},
            timeout=10.0,
        )
    except Exception as e:
        print(f"Failed to push to Notion: {e}")
