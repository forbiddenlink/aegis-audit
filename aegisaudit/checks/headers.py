from typing import List
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig


def check_headers(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings = []
    headers = {k.lower(): v for k, v in artifact.headers.items()}
    policy = config.policy.get("required_headers", {})

    # HSTS
    hsts_policy = policy.get("strict-transport-security", {})
    if "strict-transport-security" not in headers:
        findings.append(
            Finding(
                id="missing-hsts",
                severity=Severity.HIGH,
                title="Missing HSTS Header",
                description="HTTP Strict Transport Security (HSTS) header is missing.",
                url=artifact.url,
                remediation="Add 'Strict-Transport-Security' header with a max-age of at least 6 months.",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
                ],
                tags=["headers", "hsts"],
            )
        )
    else:
        # The header is present -- now enforce the attributes the policy
        # declares (max-age floor, includeSubDomains). Previously these policy
        # keys existed but nothing read them, so a 1-second max-age scored clean.
        hsts_value = headers["strict-transport-security"].lower()
        max_age = 0
        for part in hsts_value.split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    max_age = 0
        min_max_age = hsts_policy.get("min_max_age", 15552000)
        if max_age < min_max_age:
            findings.append(
                Finding(
                    id="weak-hsts-max-age",
                    severity=Severity.MEDIUM,
                    title="HSTS max-age Too Short",
                    description=(f"HSTS max-age is {max_age}s, below the required {min_max_age}s."),
                    evidence=headers["strict-transport-security"],
                    url=artifact.url,
                    remediation=f"Set max-age to at least {min_max_age} (180 days).",
                    tags=["headers", "hsts"],
                )
            )
        if hsts_policy.get("include_subdomains", True) and "includesubdomains" not in hsts_value:
            findings.append(
                Finding(
                    id="hsts-no-subdomains",
                    severity=Severity.LOW,
                    title="HSTS Missing includeSubDomains",
                    description="HSTS header does not cover subdomains.",
                    evidence=headers["strict-transport-security"],
                    url=artifact.url,
                    remediation="Add 'includeSubDomains' to the Strict-Transport-Security header.",
                    tags=["headers", "hsts"],
                )
            )

    # Referrer-Policy and Permissions-Policy: presence checks driven by policy.
    for header_name, finding_id, title in (
        ("referrer-policy", "missing-referrer-policy", "Missing Referrer-Policy"),
        ("permissions-policy", "missing-permissions-policy", "Missing Permissions-Policy"),
    ):
        if policy.get(header_name, {}).get("required", True) and header_name not in headers:
            findings.append(
                Finding(
                    id=finding_id,
                    severity=Severity.LOW,
                    title=title,
                    description=f"{header_name} header is missing.",
                    url=artifact.url,
                    remediation=f"Set a '{header_name}' header.",
                    tags=["headers"],
                )
            )

    # CSP
    if "content-security-policy" not in headers:
        if policy.get("content-security-policy", {}).get("required", True):
            findings.append(
                Finding(
                    id="missing-csp",
                    severity=Severity.MEDIUM,
                    title="Missing Content Security Policy",
                    description="Content-Security-Policy header is missing, allowing potential XSS.",
                    url=artifact.url,
                    remediation="Implement a Content Security Policy to restrict resource loading.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                    ],
                    tags=["headers", "csp"],
                )
            )

    # X-Content-Type-Options
    if "x-content-type-options" not in headers:
        findings.append(
            Finding(
                id="missing-xcto",
                severity=Severity.LOW,
                title="Missing X-Content-Type-Options",
                description="X-Content-Type-Options header is missing.",
                url=artifact.url,
                remediation="Set 'X-Content-Type-Options: nosniff'.",
                tags=["headers"],
            )
        )
    elif headers["x-content-type-options"].lower() != "nosniff":
        findings.append(
            Finding(
                id="bad-xcto",
                severity=Severity.LOW,
                title="Invalid X-Content-Type-Options",
                description=f"Expected 'nosniff', got '{headers['x-content-type-options']}'",
                evidence=headers["x-content-type-options"],
                url=artifact.url,
                remediation="Set 'X-Content-Type-Options: nosniff'.",
                tags=["headers"],
            )
        )

    # Info Disclosure (Server headers)
    for banned in config.policy.get("banned_headers", []):
        if banned in headers:
            findings.append(
                Finding(
                    id=f"leaked-{banned}",
                    severity=Severity.INFO,
                    title=f"Information Leakage: {banned}",
                    description=f"Server is disclosing technology details via the '{banned}' header.",
                    evidence=f"{banned}: {headers[banned]}",
                    url=artifact.url,
                    remediation=f"Configure the server to suppress the '{banned}' header.",
                    tags=["headers", "info-leak"],
                )
            )

    return findings
