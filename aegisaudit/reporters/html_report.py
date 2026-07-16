from importlib.resources import files
from pathlib import Path

from jinja2 import Template

from aegisaudit.history import ScanHistory
from aegisaudit.models import ScanResult


def generate_html_report(result: ScanResult, output_path: Path) -> None:
    """Generate a user-friendly HTML report using Jinja2."""
    # Read the template as package data. Resolving it by walking up from
    # __file__ only worked from a git checkout: once installed, it pointed at
    # site-packages/templates/, which does not exist, so the default
    # `--format all` crashed for every user who pip-installed the tool.
    template_source = (
        files("aegisaudit").joinpath("templates", "report.html.j2").read_text(encoding="utf-8")
    )
    template = Template(template_source)

    # Fetch recent history for the chart
    history_db = ScanHistory()
    # Get last 10 scans for context
    history_rows = history_db.get_history(limit=10)
    # Reverse so it's chronological (Trend line needs Left->Right as Old->New)
    history_data = sorted(history_rows, key=lambda x: x["id"])

    html_content = template.render(
        result=result,
        title=f"AegisAudit Report - {result.targets[0] if result.targets else 'Scan'}",
        summary=result.summary,
        findings=result.findings,
        history=history_data,
    )

    with open(output_path, "w") as f:
        f.write(html_content)
