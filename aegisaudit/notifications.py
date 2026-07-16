from typing import Any, Dict

import httpx
from aegisaudit.models import ScanResult, Severity


def send_webhook(url: str, result: ScanResult) -> None:
    """
    Send a scan summary to a Slack/Discord compatible webhook.
    """
    if not url:
        return

    score = result.summary.overall_score
    color = 0x00FF00  # Green
    if score < 70:
        color = 0xFF0000  # Red
    elif score < 90:
        color = 0xFFFF00  # Yellow

    # Discord format
    payload: Dict[str, Any]
    if "discord" in url:
        payload = {
            "embeds": [
                {
                    "title": f"AegisAudit Scan: {score:.1f}/100",
                    "color": color,
                    "fields": [
                        {"name": "Targets", "value": ", ".join(result.targets)[:100]},
                        {
                            "name": "High Severity",
                            "value": str(result.summary.counts_by_severity[Severity.HIGH]),
                        },
                        {"name": "Total Issues", "value": str(len(result.findings))},
                    ],
                    "footer": {"text": f"AegisAudit v{result.tool_version}"},
                }
            ]
        }
    else:
        # Slack format (simplified)
        emoji = "white_check_mark"
        if score < 70:
            emoji = "rotating_light"
        elif score < 90:
            emoji = "warning"

        payload = {
            "text": f":{emoji}: *AegisAudit Scan Complete*\n*Score*: {score:.1f}/100\n*Targets*: {', '.join(result.targets)}\n*High Issues*: {result.summary.counts_by_severity[Severity.HIGH]}"
        }

    try:
        # Fire and forget
        httpx.post(url, json=payload, timeout=5.0)
    except Exception as e:
        print(f"Failed to send webhook: {e}")
