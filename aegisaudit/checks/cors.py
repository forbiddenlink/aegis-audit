from typing import List
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig

# `.invalid` is reserved (RFC 2606) and can never resolve, so no real site can
# be an allowed origin by coincidence: a server that echoes it back is
# reflecting whatever Origin it is sent.
CORS_PROBE_ORIGIN = "https://example.invalid"

_REF = "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing"
_REMEDIATION = (
    "Compare the Origin request header against a fixed allowlist and only echo "
    "origins on it. Never reflect an arbitrary Origin, and only send "
    "Access-Control-Allow-Credentials: true to origins you trust."
)


def check_cors(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    """Classify the CORS response to an anonymous cross-origin GET.

    Only fires for an artifact fetched as an Origin probe (``request_origin``
    set): without an Origin request header, Access-Control-Allow-Origin says
    nothing about whether the server reflects origins. No finding is the pass
    state, as for every other check; a probe that could not be fetched is
    reported through ``ScanResult.failed_targets`` instead.
    """
    findings: List[Finding] = []
    origin = artifact.request_origin
    if not origin:
        return findings

    headers = {k.lower(): v for k, v in artifact.headers.items()}
    allow_origin = headers.get("access-control-allow-origin", "").strip()
    if not allow_origin:
        return findings

    # The CORS spec only recognises the exact, case-sensitive value "true".
    credentials = headers.get("access-control-allow-credentials", "").strip() == "true"
    evidence = f"Origin: {origin} -> Access-Control-Allow-Origin: {allow_origin}"
    if artifact.final_url and artifact.final_url != artifact.url:
        evidence += f"; response from {artifact.final_url} after redirect"
    if credentials:
        evidence += "; Access-Control-Allow-Credentials: true"

    if allow_origin == origin and credentials:
        findings.append(
            Finding(
                id="cors-reflected-origin-credentials",
                severity=Severity.HIGH,
                title="CORS Reflects Any Origin With Credentials",
                description=(
                    "The server echoed an arbitrary Origin back in Access-Control-Allow-Origin "
                    "and set Access-Control-Allow-Credentials: true. Any website can make "
                    "credentialed requests as a signed-in visitor and read the responses."
                ),
                evidence=evidence,
                url=artifact.url,
                remediation=_REMEDIATION,
                references=[_REF],
                tags=["cors"],
            )
        )
    elif allow_origin == origin:
        findings.append(
            Finding(
                id="cors-reflected-origin",
                severity=Severity.MEDIUM,
                title="CORS Reflects Any Origin",
                description=(
                    "The server echoed an arbitrary Origin back in Access-Control-Allow-Origin. "
                    "Without credentials, any website can still read this response from a "
                    "visitor's browser, including content only reachable from a private network."
                ),
                evidence=evidence,
                url=artifact.url,
                remediation=_REMEDIATION,
                references=[_REF],
                tags=["cors"],
            )
        )
    elif allow_origin == "*" and credentials:
        findings.append(
            Finding(
                id="cors-wildcard-with-credentials",
                severity=Severity.LOW,
                title="CORS Wildcard Combined With Credentials",
                description=(
                    "Access-Control-Allow-Origin is * together with "
                    "Access-Control-Allow-Credentials: true. Browsers reject this "
                    "combination, so it is not exploitable, but it is a misconfiguration "
                    "that shows the intended policy is unclear."
                ),
                evidence=evidence,
                url=artifact.url,
                remediation=(
                    "Drop Access-Control-Allow-Credentials, or replace * with an explicit "
                    "allowlisted origin."
                ),
                references=[_REF],
                tags=["cors"],
            )
        )
    elif allow_origin == "*":
        findings.append(
            Finding(
                id="cors-wildcard",
                severity=Severity.INFO,
                title="CORS Allows Any Origin (Wildcard)",
                description=(
                    "Access-Control-Allow-Origin is * without credentials. This is valid for "
                    "public resources; confirm nothing on this URL is meant to be private."
                ),
                evidence=evidence,
                url=artifact.url,
                references=[_REF],
                tags=["cors"],
            )
        )

    return findings
