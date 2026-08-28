import json
from pathlib import Path
from typing import Any

from aegisaudit.models import ScanResult, Severity

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _worst_severity(result: ScanResult) -> Severity:
    if not result.findings:
        return Severity.INFO
    return max(
        (finding.severity for finding in result.findings),
        key=lambda severity: SEVERITY_RANK[severity],
    )


def _status_for(result: ScanResult, worst: Severity) -> str:
    if result.failed_targets or worst in {Severity.HIGH, Severity.CRITICAL}:
        return "fail"
    if worst in {Severity.LOW, Severity.MEDIUM}:
        return "warn"
    return "ok"


def to_summary(result: ScanResult) -> dict[str, Any]:
    worst = _worst_severity(result)
    return {
        "source": "aegis-audit",
        "status": _status_for(result, worst),
        "severity": worst.value,
        "overall_score": result.summary.overall_score,
        "finding_count": len(result.findings),
        "failed_target_count": len(result.failed_targets),
        "counts_by_severity": result.summary.counts_by_severity,
        "targets": result.targets,
        "failed_targets": result.failed_targets,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
        "top_findings": [
            {
                "id": finding.id,
                "severity": finding.severity.value,
                "title": finding.title,
                "url": finding.url,
                "line": finding.line,
            }
            for finding in sorted(
                result.findings,
                key=lambda finding: SEVERITY_RANK[finding.severity],
                reverse=True,
            )[:5]
        ],
    }


def generate_summary_report(result: ScanResult, output_path: Path) -> None:
    """Generate compact JSON for dashboards, CI, and hq aggregation."""
    with open(output_path, "w") as f:
        json.dump(to_summary(result), f, indent=2)
        f.write("\n")
