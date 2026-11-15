"""Render aegis summary.json as Markdown for the GitHub job summary."""

import json
import sys
from pathlib import Path


def render(path: Path) -> str:
    if not path.is_file():
        return "### Aegis Audit\n\nNo summary was written (the scan did not finish).\n"
    data = json.loads(path.read_text())
    counts = data.get("counts_by_severity") or {}
    lines = [
        "### Aegis Audit",
        "",
        f"- Status: **{data.get('status', 'unknown')}**",
        f"- Score: **{data.get('overall_score', 'n/a')}** / 100",
        f"- Worst severity: {data.get('severity', 'n/a')}",
        f"- Findings: {data.get('finding_count', 0)}"
        + (f" ({', '.join(f'{k}: {v}' for k, v in counts.items())})" if counts else ""),
    ]
    if data.get("failed_target_count"):
        lines.append(f"- Targets that could not be scanned: {data['failed_target_count']}")
    top = data.get("top_findings") or []
    if top:
        lines += ["", "| Severity | Finding | Where |", "|---|---|---|"]
        for f in top:
            where = f.get("url") or (f"line {f['line']}" if f.get("line") else "")
            title = str(f.get("title", "")).replace("|", "\\|")
            lines.append(f"| {f.get('severity')} | {title} | {where} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.stdout.write(render(Path(sys.argv[1])))
