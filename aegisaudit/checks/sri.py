from typing import List
import re
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig


def check_sri(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings: List[Finding] = []

    # We only care about HTML
    if "text/html" not in artifact.content_type:
        return findings

    # Heuristic: Find <script src="..."> or <link rel="stylesheet" href="...">
    # Check if they are external (start with http) and lack integrity attribute.

    # Crude regex for script tags with src
    script_pattern = re.compile(r'<script[^>]+src=["\'](http[^"\']+)["\'][^>]*>', re.IGNORECASE)

    # Find all scripts
    for match in script_pattern.finditer(artifact.body_snippet):
        tag = match.group(0)
        src = match.group(1)

        # Skip if same origin (simplified check: assumes external starts with http/https and isn't just a path)
        # Note: Ideally we compare domains. but "http" check is decent for MVP 3rd party detection.
        # If the scan target is example.com, loading https://example.com/js/app.js is internal.
        # Loading https://cdn.jquery.com/ is external.
        # For strictness, if it starts with http, we check integrity.

        if "integrity=" not in tag:
            findings.append(
                Finding(
                    id="missing-sri",
                    severity=Severity.MEDIUM,
                    title="Missing Subresource Integrity",
                    description=f"External script loaded without integrity check: {src}",
                    url=artifact.url,
                    remediation=f"Add integrity='sha384-...' to the script tag for {src}",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
                    ],
                    tags=["sri", "supply-chain"],
                )
            )

    return findings
