"""Tests for the SSRF guard (aegisaudit/ssrf.py)."""

import pytest

from aegisaudit.ssrf import SSRFError, validate_url


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # AWS/GCP metadata (link-local)
        "http://127.0.0.1/",  # loopback
        "http://localhost/",  # loopback by name
        "http://10.0.0.5/",  # RFC1918
        "http://192.168.1.1/",  # RFC1918
        "http://172.16.0.1/",  # RFC1918
        "http://metadata.google.internal/",  # metadata hostname
        "http://[::1]/",  # IPv6 loopback
    ],
)
def test_blocks_internal_and_metadata(url):
    with pytest.raises(SSRFError):
        validate_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
    ],
)
def test_blocks_non_http_schemes(url):
    with pytest.raises(SSRFError):
        validate_url(url)


def test_allowlist_rejects_off_list_host():
    with pytest.raises(SSRFError):
        validate_url("https://evil.example/", allow=["good.example"])


def test_allowlist_accepts_subdomain():
    # api.good.example is a subdomain of an allowlisted host; public DNS resolve
    # is required, so this asserts only that the allowlist logic doesn't reject
    # it before resolution when allow_private short-circuits the IP check.
    validate_url("https://api.good.example/", allow=["good.example"], allow_private=True)


def test_allow_private_permits_loopback():
    # Explicit opt-in for scanning an intentionally-internal target.
    validate_url("http://127.0.0.1/", allow_private=True)


def test_ipv4_mapped_ipv6_is_unwrapped():
    # ::ffff:127.0.0.1 must not smuggle a loopback address past the v4 checks.
    with pytest.raises(SSRFError):
        validate_url("http://[::ffff:127.0.0.1]/")
