from typing import Any, Dict, List
import re
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig


def check_javascript(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings: List[Finding] = []

    if "text/html" not in artifact.content_type:
        return findings

    # Passive regex signatures for common libraries.
    # NOTE: This is "best effort" passive detection. Active scanning would try to Execute() JS.
    # `min_safe` is the first release with the relevant XSS/prototype-pollution
    # advisories fixed; a detected version below it is flagged. This replaces a
    # blanket "any 1.x/2.x" heuristic that both over-reported patched old
    # releases and missed later vulnerable majors (e.g. jQuery 3.x < 3.5.0).
    signatures: Dict[str, Dict[str, Any]] = {
        "jQuery": {
            "pattern": r"jquery[.-](\d+\.\d+\.\d+)",
            "min_safe": (3, 5, 0),  # CVE-2020-11022/11023 XSS fixed in 3.5.0
        },
        "Bootstrap": {
            "pattern": r"bootstrap[.-](\d+\.\d+\.\d+)",
            "min_safe": (4, 3, 1),  # XSS advisories fixed in 4.3.1
        },
        "AngularJS": {
            "pattern": r"angular[.-](\d+\.\d+\.\d+)",
            "min_safe": (99, 0, 0),  # AngularJS 1.x is entirely end-of-life
        },
    }

    def _below(version: str, floor: tuple[int, ...]) -> bool:
        try:
            parsed = tuple(int(p) for p in version.split("."))
        except ValueError:
            return False
        return parsed < floor

    for lib, rule in signatures.items():
        matches = re.findall(rule["pattern"], artifact.body_snippet, re.IGNORECASE)
        for version in matches:
            if _below(version, rule["min_safe"]):
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
