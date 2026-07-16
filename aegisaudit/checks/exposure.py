from typing import List
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig


def check_exposure(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings: List[Finding] = []

    # We only care if the request succeeded (200 OK)
    if artifact.status_code != 200:
        return findings

    # Check for .env file leakage
    if artifact.url.endswith("/.env"):
        # Verify it looks like an env file (key=value)
        if "=" in artifact.body_snippet and "\n" in artifact.body_snippet:
            findings.append(
                Finding(
                    id="conf-env-exposed",
                    severity=Severity.HIGH,
                    title="Environment File Exposed",
                    description="A .env file is publicly accessible and appears to contain configuration data.",
                    evidence=artifact.body_snippet[:100],
                    url=artifact.url,
                    remediation="Block access to .env files in your web server configuration immediately.",
                    tags=["exposure", "config"],
                )
            )

    # Check for Git exposure
    if artifact.url.endswith("/.git/HEAD"):
        if "ref: refs/" in artifact.body_snippet:
            findings.append(
                Finding(
                    id="git-repo-exposed",
                    severity=Severity.HIGH,
                    title="Git Repository Exposed",
                    description="The .git/HEAD file is accessible, indicating the entire Git repository might be downloadable.",
                    url=artifact.url,
                    remediation="Block access to .git directories.",
                    tags=["exposure", "git"],
                )
            )

    return findings
