"""Header checks: HSTS, CSP quality, clickjacking, COOP, Referrer-Policy.

Quality assertions follow Mozilla HTTP Observatory / OWASP Secure Headers:
a CSP that exists but allows 'unsafe-inline' is not a pass, and clickjacking
protection is satisfied by either X-Frame-Options or CSP frame-ancestors.
"""

import pytest

from aegisaudit.checks.headers import check_headers
from aegisaudit.config import AegisConfig, ScopeConfig
from aegisaudit.models import ScanArtifact, Severity


@pytest.fixture
def base_config():
    return AegisConfig()


@pytest.fixture
def base_artifact():
    return ScanArtifact(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
        cookies={},
        body_snippet="<html><body>Test</body></html>",
        content_type="text/html",
    )


def _ids(artifact, config=None):
    return {f.id for f in check_headers(artifact, config or AegisConfig())}


class TestHSTSHeader:
    def test_missing_hsts(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        hsts_findings = [f for f in findings if f.id == "missing-hsts"]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == Severity.HIGH

    def test_hsts_present_valid(self, base_artifact, base_config):
        base_artifact.headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"
        assert "missing-hsts" not in _ids(base_artifact, base_config)
        assert "weak-hsts-max-age" not in _ids(base_artifact, base_config)
        assert "hsts-no-subdomains" not in _ids(base_artifact, base_config)

    def test_hsts_short_max_age(self, base_artifact, base_config):
        base_artifact.headers["strict-transport-security"] = "max-age=3600"
        ids = _ids(base_artifact, base_config)
        assert "weak-hsts-max-age" in ids
        assert "missing-hsts" not in ids

    def test_hsts_missing_includesubdomains(self, base_artifact, base_config):
        base_artifact.headers["strict-transport-security"] = "max-age=31536000"
        assert "hsts-no-subdomains" in _ids(base_artifact, base_config)


class TestCSPHeader:
    def test_missing_csp(self, base_artifact, base_config):
        findings = [f for f in check_headers(base_artifact, base_config) if f.id == "missing-csp"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_csp_present_restricted(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = (
            "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'"
        )
        ids = _ids(base_artifact, base_config)
        assert "missing-csp" not in ids
        assert "csp-unsafe-inline" not in ids
        assert "csp-unsafe-eval" not in ids
        assert "csp-broad-script-src" not in ids
        assert "csp-broad-object-src" not in ids
        assert "csp-missing-base-uri" not in ids

    def test_csp_unsafe_inline(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = (
            "default-src 'self'; script-src 'unsafe-inline'"
        )
        ids = _ids(base_artifact, base_config)
        assert "csp-unsafe-inline" in ids
        assert "missing-csp" not in ids

    def test_csp_unsafe_eval(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-eval'"
        )
        assert "csp-unsafe-eval" in _ids(base_artifact, base_config)

    def test_csp_wildcard_script_src(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = "script-src *; object-src 'none'"
        assert "csp-broad-script-src" in _ids(base_artifact, base_config)

    def test_csp_https_scheme_in_script_src(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = "script-src https:; object-src 'none'"
        assert "csp-broad-script-src" in _ids(base_artifact, base_config)

    def test_csp_nonce_ignores_unsafe_inline(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = (
            "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'"
        )
        assert "csp-unsafe-inline" not in _ids(base_artifact, base_config)

    def test_csp_missing_base_uri(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = "default-src 'self'; object-src 'none'"
        assert "csp-missing-base-uri" in _ids(base_artifact, base_config)


class TestClickjacking:
    def test_missing_xfo_and_frame_ancestors(self, base_artifact, base_config):
        assert "missing-clickjacking-protection" in _ids(base_artifact, base_config)

    def test_xfo_deny_is_enough(self, base_artifact, base_config):
        base_artifact.headers["x-frame-options"] = "DENY"
        ids = _ids(base_artifact, base_config)
        assert "missing-clickjacking-protection" not in ids
        assert "invalid-xfo" not in ids

    def test_xfo_sameorigin_is_enough(self, base_artifact, base_config):
        base_artifact.headers["x-frame-options"] = "SAMEORIGIN"
        assert "missing-clickjacking-protection" not in _ids(base_artifact, base_config)

    def test_csp_frame_ancestors_is_enough(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = (
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'"
        )
        assert "missing-clickjacking-protection" not in _ids(base_artifact, base_config)

    def test_allow_from_is_invalid(self, base_artifact, base_config):
        base_artifact.headers["x-frame-options"] = "ALLOW-FROM https://evil.test"
        assert "invalid-xfo" in _ids(base_artifact, base_config)


class TestReferrerPolicy:
    def test_missing_referrer_policy(self, base_artifact, base_config):
        assert "missing-referrer-policy" in _ids(base_artifact, base_config)

    def test_weak_referrer_policy(self, base_artifact, base_config):
        base_artifact.headers["referrer-policy"] = "unsafe-url"
        ids = _ids(base_artifact, base_config)
        assert "weak-referrer-policy" in ids
        assert "missing-referrer-policy" not in ids


class TestXContentTypeOptions:
    def test_missing_xcto(self, base_artifact, base_config):
        assert "missing-xcto" in _ids(base_artifact, base_config)

    def test_xcto_nosniff(self, base_artifact, base_config):
        base_artifact.headers["x-content-type-options"] = "nosniff"
        ids = _ids(base_artifact, base_config)
        assert "missing-xcto" not in ids
        assert "bad-xcto" not in ids


class TestPermissionsPolicy:
    def test_missing_permissions_policy(self, base_artifact, base_config):
        assert "missing-permissions-policy" in _ids(base_artifact, base_config)

    def test_permissions_policy_present(self, base_artifact, base_config):
        base_artifact.headers["permissions-policy"] = "geolocation=(), camera=()"
        assert "missing-permissions-policy" not in _ids(base_artifact, base_config)


class TestCrossOriginPolicies:
    def test_missing_coop_is_info(self, base_artifact, base_config):
        findings = [f for f in check_headers(base_artifact, base_config) if f.id == "missing-coop"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_coop_present(self, base_artifact, base_config):
        base_artifact.headers["cross-origin-opener-policy"] = "same-origin"
        assert "missing-coop" not in _ids(base_artifact, base_config)


class TestInfoLeakage:
    def test_server_header_present(self, base_artifact, base_config):
        base_artifact.headers["server"] = "Apache/2.4.41"
        findings = [f for f in check_headers(base_artifact, base_config) if f.id == "leaked-server"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_x_powered_by_present(self, base_artifact, base_config):
        base_artifact.headers["x-powered-by"] = "PHP/7.4.3"
        assert "leaked-x-powered-by" in _ids(base_artifact, base_config)


class TestScopeIsNotAHeaderConcern:
    """The scope allowlist is enforced in the SSRF/fetch layer, not in checks."""

    def test_scope_allow_does_not_change_header_findings(self, base_artifact):
        scoped = AegisConfig(scope=ScopeConfig(allow=["example.com"]))
        assert check_headers(base_artifact, scoped) == check_headers(base_artifact, AegisConfig())

    def test_non_allowlisted_url_shows_findings(self, base_config):
        artifact = ScanArtifact(
            url="https://notallowed.com",
            final_url="https://notallowed.com",
            status_code=200,
            headers={},
            cookies={},
            body_snippet="<html></html>",
            content_type="text/html",
        )
        assert len(check_headers(artifact, base_config)) > 0
