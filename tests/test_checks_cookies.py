import pytest
from aegisaudit.models import ScanArtifact, Severity
from aegisaudit.checks.cookies import check_cookies
from aegisaudit.config import AegisConfig


@pytest.fixture
def base_config():
    return AegisConfig()


@pytest.fixture
def https_artifact():
    """Artifact from HTTPS site."""
    return ScanArtifact(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
        cookies={},
        body_snippet="<html><body>Test</body></html>",
        content_type="text/html",
    )


@pytest.fixture
def http_artifact():
    """Artifact from HTTP site."""
    return ScanArtifact(
        url="http://example.com",
        final_url="http://example.com",
        status_code=200,
        headers={},
        cookies={},
        body_snippet="<html><body>Test</body></html>",
        content_type="text/html",
    )


class TestSecureFlag:
    """Tests for Secure cookie attribute."""

    def test_no_cookies(self, https_artifact, base_config):
        """No cookies set should result in no findings."""
        findings = check_cookies(https_artifact, base_config)
        assert len(findings) == 0

    def test_secure_flag_on_https(self, https_artifact, base_config):
        """HTTPS with proper setup should not trigger cookie-over-http finding."""
        https_artifact.cookies = {"session": "abc123"}
        findings = check_cookies(https_artifact, base_config)
        # HTTPS shouldn't trigger cookies-over-http finding
        http_findings = [f for f in findings if "http" in f.id.lower()]
        assert len(http_findings) == 0


class TestHTTPContext:
    """Tests for cookies on HTTP (not HTTPS) sites."""

    def test_http_site_with_cookies_triggers_warning(self, http_artifact, base_config):
        """On HTTP site with cookies, should warn about unencrypted cookies."""
        http_artifact.cookies = {"session": "abc123"}
        findings = check_cookies(http_artifact, base_config)
        # Should warn about cookies over HTTP
        assert len(findings) >= 1
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_http_site_without_cookies_no_warning(self, http_artifact, base_config):
        """On HTTP site without cookies, should not warn."""
        findings = check_cookies(http_artifact, base_config)
        assert len(findings) == 0


class TestEdgeCases:
    """Tests for edge cases and malformed cookies."""

    def test_empty_set_cookie_header(self, https_artifact, base_config):
        """Empty Set-Cookie header should not crash."""
        https_artifact.headers["set-cookie"] = ""
        findings = check_cookies(https_artifact, base_config)
        assert isinstance(findings, list)

    def test_malformed_cookie(self, https_artifact, base_config):
        """Malformed cookie should be handled gracefully."""
        https_artifact.headers["set-cookie"] = ";;;invalid;;;"
        findings = check_cookies(https_artifact, base_config)
        assert isinstance(findings, list)

    def test_cookie_with_unusual_attributes(self, https_artifact, base_config):
        """Cookie with Domain and Max-Age should still be checked."""
        https_artifact.headers["set-cookie"] = (
            "session=abc; Domain=.example.com; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
        )
        findings = check_cookies(https_artifact, base_config)
        # Should have no critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
