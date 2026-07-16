import json
from pathlib import Path
from typing import Any, Dict, Optional

from aegisaudit.models import ScanResult, Severity

# SARIF 2.1.0 defines exactly four values for result.level: none, note, warning,
# error. There is no "critical". Mapping severity to level alone therefore
# collapses CRITICAL, MEDIUM and LOW into "warning" -- which is how a hardcoded
# private key ended up displayed as a routine warning.
LEVEL_BY_SEVERITY: Dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}

# GitHub renders the Critical/High/Medium/Low badge in the Security tab from
# `security-severity`, not from `level`. It is a GitHub extension (not OASIS),
# it lives on the RULE, and it must be a STRING holding 0.1-10.0.
#   >= 9.0 Critical | 7.0-8.9 High | 4.0-6.9 Medium | 0.1-3.9 Low
# https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
SECURITY_SEVERITY_BY_SEVERITY: Dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}


def level_for(severity: Severity) -> str:
    """Map a finding severity to a valid SARIF result.level."""
    return LEVEL_BY_SEVERITY[severity]


def security_severity_for(severity: Severity) -> Optional[str]:
    """Map a finding severity to GitHub's `security-severity` score.

    Returns None for INFO: it is observational, not a security alert, so it is
    deliberately not promoted into GitHub's security severity scale (whose
    lowest defined band starts at 0.1).
    """
    return SECURITY_SEVERITY_BY_SEVERITY.get(severity)


def generate_sarif_report(result: ScanResult, output_path: Path) -> None:
    """Generate a SARIF 2.1.0 report suitable for GitHub code scanning."""
    rules = []
    seen_rules = set()

    for finding in result.findings:
        if finding.id in seen_rules:
            continue
        seen_rules.add(finding.id)

        properties: Dict[str, Any] = {"tags": finding.tags, "precision": "high"}
        security_severity = security_severity_for(finding.severity)
        if security_severity is not None:
            properties["security-severity"] = security_severity

        references = ", ".join(finding.references) if finding.references else "None"
        rules.append(
            {
                "id": finding.id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {"level": level_for(finding.severity)},
                "help": {
                    "text": f"{finding.description}\n\nRemediation: {finding.remediation}",
                    "markdown": (
                        f"**{finding.description}**\n\n"
                        f"### Remediation\n{finding.remediation}\n\n"
                        f"### References\n{references}"
                    ),
                },
                "properties": properties,
            }
        )

    sarif_results = []
    for finding in result.findings:
        physical_location: Dict[str, Any] = {
            # Must be repo-root-relative. An absolute path such as
            # /home/runner/work/repo/repo/src/x.py matches nothing in the
            # GitHub tree, so the alert cannot be attached to a file.
            "artifactLocation": {"uri": finding.url},
        }
        # Omit the region entirely when the line is unknown rather than
        # inventing line 1.
        if finding.line is not None:
            physical_location["region"] = {"startLine": finding.line}

        sarif_results.append(
            {
                "ruleId": finding.id,
                "level": level_for(finding.severity),
                "message": {"text": finding.description},
                "locations": [{"physicalLocation": physical_location}],
            }
        )

    sarif_log = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": result.tool_name,
                        "version": result.tool_version,
                        "informationUri": "https://github.com/forbiddenlink/aegis-audit",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    with open(output_path, "w") as f:
        json.dump(sarif_log, f, indent=2)
