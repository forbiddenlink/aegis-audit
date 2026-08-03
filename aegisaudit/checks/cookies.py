"""Cookie security checks.

Inspects the attributes that actually matter on a Set-Cookie -- Secure,
HttpOnly, SameSite -- rather than just the presence of cookies. The raw
Set-Cookie lines come from ScanArtifact.set_cookie_headers because a folded
name->value dict loses every attribute.
"""

from typing import List, Optional, Tuple

from aegisaudit.config import AegisConfig
from aegisaudit.models import Finding, ScanArtifact, Severity


def _parse_cookie(line: str) -> Tuple[str, List[str]]:
    """Return (cookie_name, [lowercased attribute tokens]) for one Set-Cookie."""
    parts = [p.strip() for p in line.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and parts[0] else ""
    attrs = [p.lower() for p in parts[1:]]
    return name, attrs


def _samesite_value(attrs: List[str]) -> Optional[str]:
    for a in attrs:
        if a.startswith("samesite="):
            return a.split("=", 1)[1]
    return None


def check_cookies(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings: List[Finding] = []
    is_https = artifact.url.startswith("https://")

    for line in artifact.set_cookie_headers:
        name, attrs = _parse_cookie(line)
        if not name:
            continue
        has_secure = any(a == "secure" for a in attrs)
        has_httponly = any(a == "httponly" for a in attrs)
        samesite = _samesite_value(attrs)

        if is_https and not has_secure:
            findings.append(
                Finding(
                    id="cookie-missing-secure",
                    severity=Severity.MEDIUM,
                    title="Cookie Missing Secure Flag",
                    description=f"Cookie '{name}' is set over HTTPS without the Secure attribute.",
                    evidence=name,
                    url=artifact.url,
                    remediation="Add the 'Secure' attribute so the cookie is only sent over HTTPS.",
                    tags=["cookies"],
                )
            )
        if not has_httponly:
            findings.append(
                Finding(
                    id="cookie-missing-httponly",
                    severity=Severity.LOW,
                    title="Cookie Missing HttpOnly Flag",
                    description=f"Cookie '{name}' lacks the HttpOnly attribute; readable from JavaScript.",
                    evidence=name,
                    url=artifact.url,
                    remediation="Add 'HttpOnly' unless the cookie must be read by client-side script.",
                    tags=["cookies"],
                )
            )
        if samesite is None:
            findings.append(
                Finding(
                    id="cookie-missing-samesite",
                    severity=Severity.LOW,
                    title="Cookie Missing SameSite Attribute",
                    description=f"Cookie '{name}' has no SameSite attribute; defaults are inconsistent across browsers.",
                    evidence=name,
                    url=artifact.url,
                    remediation="Set 'SameSite=Lax' (or Strict/None as appropriate).",
                    tags=["cookies"],
                )
            )

    # Any cookie set over plain HTTP is exposed in transit regardless of flags.
    if artifact.url.startswith("http://") and artifact.cookies:
        findings.append(
            Finding(
                id="cookies-over-http",
                severity=Severity.HIGH,
                title="Cookies Set Over HTTP",
                description="Cookies are being set on an unencrypted connection.",
                evidence=str(list(artifact.cookies.keys())),
                url=artifact.url,
                remediation="Serve over HTTPS and mark cookies Secure.",
                tags=["cookies"],
            )
        )

    return findings
