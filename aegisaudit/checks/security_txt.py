from typing import List
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig


def check_security_txt(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    """Validate an RFC 9116 security.txt.

    Checks are pure functions of one artifact, so this only fires for a
    security.txt target. `--probe` now expands every target with
    `/.well-known/security.txt`, so the common "file entirely missing" case is
    reachable: a 4xx/5xx there is reported as a missing file rather than an
    invalid one.
    """
    findings: List[Finding] = []

    if not artifact.url.endswith("security.txt"):
        return findings

    if artifact.status_code >= 400:
        findings.append(
            Finding(
                id="sectxt-missing",
                severity=Severity.LOW,
                title="Missing security.txt",
                description=(
                    "No RFC 9116 security.txt was served at "
                    "/.well-known/security.txt "
                    f"(HTTP {artifact.status_code})."
                ),
                url=artifact.url,
                remediation="Publish /.well-known/security.txt with Contact and Expires fields.",
                references=["https://securitytxt.org/"],
                tags=["security.txt"],
            )
        )
        return findings

    if "Contact:" not in artifact.body_snippet:
        findings.append(
            Finding(
                id="sectxt-no-contact",
                severity=Severity.HIGH,
                title="Invalid security.txt",
                description="security.txt is missing the mandatory 'Contact:' field.",
                url=artifact.url,
                remediation="Add 'Contact: ...' to provide a disclosure contact.",
                references=["https://securitytxt.org/"],
                tags=["security.txt"],
            )
        )
    if "Expires:" not in artifact.body_snippet:
        findings.append(
            Finding(
                id="sectxt-no-expires",
                severity=Severity.MEDIUM,
                title="Missing Expires Field",
                description="security.txt must have an 'Expires:' field.",
                url=artifact.url,
                remediation="Add 'Expires: <date>' to the file.",
                tags=["security.txt"],
            )
        )

    return findings
