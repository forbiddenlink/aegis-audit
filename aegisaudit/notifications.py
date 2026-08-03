import html
from typing import Any, Dict
from urllib.parse import urlsplit

import httpx
from aegisaudit.models import ScanResult, Severity

# Outbound alert destinations must be https and one of the known chat providers.
# The webhook URL can come from CI config an attacker may influence; posting
# scan data (target list, summary) to an arbitrary host would be an SSRF /
# data-exfil primitive.
_ALLOWED_WEBHOOK_HOSTS = (
    "hooks.slack.com",
    "discord.com",
    "discordapp.com",
    "ptb.discord.com",
    "canary.discord.com",
)


def _webhook_allowed(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme != "https":
        return False
    host = (parts.hostname or "").lower()
    return any(host == h or host.endswith("." + h) for h in _ALLOWED_WEBHOOK_HOSTS)


def send_webhook(url: str, result: ScanResult) -> None:
    """
    Send a scan summary to a Slack/Discord compatible webhook.
    """
    if not url:
        return

    if not _webhook_allowed(url):
        print(f"Refusing to send webhook to non-allowlisted destination: {url}")
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


def send_telegram(token: str, chat_id: str, result: ScanResult) -> None:
    if not token or not chat_id:
        return

    score = result.summary.overall_score
    counts = result.summary.counts_by_severity
    critical = counts.get(Severity.CRITICAL, 0)
    high = counts.get(Severity.HIGH, 0)
    medium = counts.get(Severity.MEDIUM, 0)
    low = counts.get(Severity.LOW, 0)

    emoji = "✅" if score >= 90 else ("⚠️" if score >= 70 else "🚨")
    # Targets are attacker-influenceable (a scanned URL) and this message is
    # sent with parse_mode=HTML, so escape before interpolating.
    target = html.escape(", ".join(result.targets)[:200])
    ts = (result.finished_at or result.started_at).strftime("%Y-%m-%d %H:%M UTC")

    text = (
        f"{emoji} <b>AegisAudit</b> — {score:.1f}/100\n"
        f"<b>Target:</b> {target}\n"
        f"<b>Critical:</b> {critical} | <b>High:</b> {high} | "
        f"<b>Medium:</b> {medium} | <b>Low:</b> {low}\n"
        f"<i>{ts}</i>"
    )

    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=5.0,
        )
    except Exception as e:
        print(f"Failed to send Telegram alert: {e}")
