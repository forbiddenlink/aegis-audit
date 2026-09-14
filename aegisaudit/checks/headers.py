"""HTTP security-header checks.

Presence checks are driven by ``config.policy``. Quality checks follow the
Mozilla HTTP Observatory and OWASP Secure Headers Project baselines: a CSP
that exists but allows ``'unsafe-inline'`` / ``'unsafe-eval'`` / broad
script sources is not a pass, and clickjacking protection is satisfied by
either ``X-Frame-Options`` or CSP ``frame-ancestors`` (not both required).
"""

from typing import Dict, List, Mapping

from aegisaudit.config import AegisConfig
from aegisaudit.models import Finding, ScanArtifact, Severity

_CSP_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
_XFO_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
_COOP_REF = "https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy"

_UNSAFE_INLINE = "'unsafe-inline'"
_UNSAFE_EVAL = "'unsafe-eval'"
_BROAD_SOURCES = frozenset({"*", "https:", "http:", "data:", "ftp:"})
_HASH_OR_NONCE_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
_WEAK_REFERRER = frozenset({"unsafe-url", "no-referrer-when-downgrade"})
_VALID_XFO = frozenset({"deny", "sameorigin"})


def _parse_csp(value: str) -> Dict[str, List[str]]:
    """Split a CSP header into directive -> source-list.

    Duplicate directives are ignored (first wins), matching the CSP spec.
    """
    directives: Dict[str, List[str]] = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        tokens = chunk.split()
        name = tokens[0].lower()
        if name in directives:
            continue
        directives[name] = [token.lower() for token in tokens[1:]]
    return directives


def _has_nonce_or_hash(sources: List[str]) -> bool:
    return any(source.startswith(_HASH_OR_NONCE_PREFIXES) for source in sources)


def _effective_script_src(csp: Mapping[str, List[str]]) -> List[str]:
    """script-src, falling back to default-src, with Observatory exceptions.

    A nonce or hash on script-src causes browsers to ignore ``'unsafe-inline'``.
    ``'strict-dynamic'`` plus a nonce/hash ignores host allowlists and
    ``'unsafe-inline'`` / ``'self'``.
    """
    sources = list(csp.get("script-src") or csp.get("default-src") or [])
    hashed = _has_nonce_or_hash(sources)
    if hashed and _UNSAFE_INLINE in sources:
        sources = [source for source in sources if source != _UNSAFE_INLINE]
    if hashed and "'strict-dynamic'" in sources:
        sources = [
            source
            for source in sources
            if source not in _BROAD_SOURCES
            and source not in ("'self'", _UNSAFE_INLINE)
            and not (source.endswith(":") and not source.startswith("'"))
        ]
    return sources


def _effective_object_src(csp: Mapping[str, List[str]]) -> List[str]:
    return list(csp.get("object-src") or csp.get("default-src") or [])


def _csp_quality_findings(artifact: ScanArtifact, csp_header: str) -> List[Finding]:
    """Flag Observatory-style CSP footguns when a policy is present."""
    findings: List[Finding] = []
    csp = _parse_csp(csp_header)
    script_src = _effective_script_src(csp)
    object_src = _effective_object_src(csp)

    if _UNSAFE_INLINE in script_src:
        findings.append(
            Finding(
                id="csp-unsafe-inline",
                severity=Severity.MEDIUM,
                title="CSP Allows unsafe-inline Scripts",
                description=(
                    "script-src (or default-src) includes 'unsafe-inline', which "
                    "defeats XSS protection for inline scripts."
                ),
                evidence=csp_header,
                url=artifact.url,
                remediation="Remove 'unsafe-inline' from script-src; use nonces or hashes.",
                references=[_CSP_REF],
                tags=["headers", "csp"],
            )
        )

    eval_sources = script_src or list(csp.get("default-src") or [])
    if _UNSAFE_EVAL in eval_sources or _UNSAFE_EVAL in csp.get("script-src", []):
        findings.append(
            Finding(
                id="csp-unsafe-eval",
                severity=Severity.MEDIUM,
                title="CSP Allows unsafe-eval",
                description="script-src (or default-src) includes 'unsafe-eval', allowing eval()-based XSS.",
                evidence=csp_header,
                url=artifact.url,
                remediation="Remove 'unsafe-eval' from script-src.",
                references=[_CSP_REF],
                tags=["headers", "csp"],
            )
        )

    if not script_src or _BROAD_SOURCES.intersection(script_src):
        findings.append(
            Finding(
                id="csp-broad-script-src",
                severity=Severity.MEDIUM,
                title="CSP script-src Is Too Broad",
                description=(
                    "script-src (or default-src) is missing or allows a scheme/wildcard "
                    "such as *, https:, or data:, so any script origin can run."
                ),
                evidence=csp_header,
                url=artifact.url,
                remediation="Restrict script-src to 'self' plus named hosts, or use nonces with 'strict-dynamic'.",
                references=[_CSP_REF],
                tags=["headers", "csp"],
            )
        )

    if not object_src or _BROAD_SOURCES.intersection(object_src):
        findings.append(
            Finding(
                id="csp-broad-object-src",
                severity=Severity.LOW,
                title="CSP object-src Is Unrestricted",
                description="object-src is missing (and default-src does not restrict it) or allows a wildcard/scheme.",
                evidence=csp_header,
                url=artifact.url,
                remediation="Set object-src 'none' unless the page must load plugins.",
                references=[_CSP_REF],
                tags=["headers", "csp"],
            )
        )

    if "base-uri" not in csp:
        findings.append(
            Finding(
                id="csp-missing-base-uri",
                severity=Severity.LOW,
                title="CSP Missing base-uri",
                description="Without base-uri, an injected <base> tag can hijack relative URLs.",
                evidence=csp_header,
                url=artifact.url,
                remediation="Add base-uri 'none' or base-uri 'self'.",
                references=[_CSP_REF],
                tags=["headers", "csp"],
            )
        )

    return findings


def _clickjacking_findings(artifact: ScanArtifact, headers: Mapping[str, str]) -> List[Finding]:
    """X-Frame-Options or CSP frame-ancestors — either is enough (Observatory)."""
    findings: List[Finding] = []
    xfo = headers.get("x-frame-options")
    csp = (
        _parse_csp(headers["content-security-policy"])
        if "content-security-policy" in headers
        else {}
    )
    has_frame_ancestors = "frame-ancestors" in csp

    if has_frame_ancestors:
        return findings

    if xfo is None:
        findings.append(
            Finding(
                id="missing-clickjacking-protection",
                severity=Severity.MEDIUM,
                title="Missing Clickjacking Protection",
                description=(
                    "Neither X-Frame-Options nor CSP frame-ancestors is set, so the page "
                    "can be framed by any origin."
                ),
                url=artifact.url,
                remediation=(
                    "Set Content-Security-Policy frame-ancestors 'none' (or 'self'), "
                    "or X-Frame-Options: DENY."
                ),
                references=[_XFO_REF],
                tags=["headers"],
            )
        )
        return findings

    if xfo.strip().lower() not in _VALID_XFO:
        findings.append(
            Finding(
                id="invalid-xfo",
                severity=Severity.LOW,
                title="Invalid X-Frame-Options",
                description=(
                    f"X-Frame-Options is '{xfo}'. ALLOW-FROM is obsolete; use DENY, "
                    "SAMEORIGIN, or CSP frame-ancestors."
                ),
                evidence=xfo,
                url=artifact.url,
                remediation="Replace with X-Frame-Options: DENY or CSP frame-ancestors.",
                references=[_XFO_REF],
                tags=["headers"],
            )
        )
    return findings


def check_headers(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings: List[Finding] = []
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

    if "referrer-policy" in headers:
        value = headers["referrer-policy"].strip().lower()
        if value in _WEAK_REFERRER:
            findings.append(
                Finding(
                    id="weak-referrer-policy",
                    severity=Severity.LOW,
                    title="Weak Referrer-Policy",
                    description=(
                        f"Referrer-Policy is '{headers['referrer-policy']}', which leaks "
                        "full URLs to other origins."
                    ),
                    evidence=headers["referrer-policy"],
                    url=artifact.url,
                    remediation="Use strict-origin-when-cross-origin, strict-origin, or no-referrer.",
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
                    references=[_CSP_REF],
                    tags=["headers", "csp"],
                )
            )
    else:
        findings.extend(_csp_quality_findings(artifact, headers["content-security-policy"]))

    findings.extend(_clickjacking_findings(artifact, headers))

    # COOP is extra-credit in Observatory (bonus, not a hard fail). Report as
    # INFO so it shows up without deducting from the score.
    if "cross-origin-opener-policy" not in headers:
        findings.append(
            Finding(
                id="missing-coop",
                severity=Severity.INFO,
                title="Missing Cross-Origin-Opener-Policy",
                description=(
                    "COOP is not set, so the document may share a browsing context "
                    "group with cross-origin popups (Spectre isolation)."
                ),
                url=artifact.url,
                remediation="Set Cross-Origin-Opener-Policy: same-origin.",
                references=[_COOP_REF],
                tags=["headers"],
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
