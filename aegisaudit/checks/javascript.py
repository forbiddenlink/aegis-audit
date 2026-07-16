from typing import Any, Dict, List
import re
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig


def check_javascript(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings: List[Finding] = []

    if "text/html" not in artifact.content_type:
        return findings

    # Passive regex signatures for common libraries
    # NOTE: This is "best effort" passive detection. Active scanning would try to Execute() JS.
    signatures: Dict[str, Dict[str, Any]] = {
        "jQuery": {
            "pattern": r"jquery[.-](\d+\.\d+\.\d+)",
            "vulnerable": lambda v: v.startswith("1.") or v.startswith("2."),  # Broad brush for MVP
        },
        "Bootstrap": {
            "pattern": r"bootstrap[.-](\d+\.\d+\.\d+)",
            "vulnerable": lambda v: v.startswith("3.") or v.startswith("4.0"),
        },
        "AngularJS": {
            "pattern": r"angular[.-](\d+\.\d+\.\d+)",
            "vulnerable": lambda v: v.startswith("1."),
        },
    }

    for lib, rule in signatures.items():
        matches = re.findall(rule["pattern"], artifact.body_snippet, re.IGNORECASE)
        for version in matches:
            if rule["vulnerable"](version):
                findings.append(
                    Finding(
                        id=f"vuln-js-{lib.lower()}",
                        severity=Severity.MEDIUM,
                        title=f"Vulnerable {lib} Version Detected",
                        description=f"Passive detection found {lib} version {version}, which may be end-of-life or vulnerable.",
                        evidence=f"Matched version: {version}",
                        url=artifact.url,
                        remediation=f"Upgrade {lib} to the latest stable version.",
                        tags=["supply-chain", "javascript", "outdated"],
                    )
                )

    # Sourcemap detection
    if "sourceMappingURL=" in artifact.body_snippet:
        findings.append(
            Finding(
                id="sourcemap-exposed",
                severity=Severity.INFO,
                title="Source Maps Exposed",
                description="Production JavaScript contains source map links, which may assist reverse engineering.",
                url=artifact.url,
                remediation="Remove source maps from production builds.",
                tags=["info-leak"],
            )
        )

    return findings
