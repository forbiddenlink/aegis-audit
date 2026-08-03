"""Regression tests for fixes from the launch-readiness audit."""

import time

from aegisaudit.checks.cookies import check_cookies
from aegisaudit.checks.headers import check_headers
from aegisaudit.checks.javascript import check_javascript
from aegisaudit.checks.secrets import check_secrets
from aegisaudit.checks.security_txt import check_security_txt
from aegisaudit.config import AegisConfig
from aegisaudit.models import ScanArtifact
from aegisaudit.sast.ignore import IgnoreRules
from aegisaudit.sast.scanner import SASTScanner


def _artifact(**kw) -> ScanArtifact:
    base = dict(
        url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        headers={},
        cookies={},
        set_cookie_headers=[],
        body_snippet="",
        content_type="text/html",
    )
    base.update(kw)
    return ScanArtifact(**base)  # type: ignore[arg-type]


CFG = AegisConfig()


# --- H3: cookie flags -------------------------------------------------------
def test_cookie_missing_flags_flagged_over_https():
    art = _artifact(set_cookie_headers=["sid=abc; Path=/"], cookies={"sid": "abc"})
    ids = {f.id for f in check_cookies(art, CFG)}
    assert "cookie-missing-secure" in ids
    assert "cookie-missing-httponly" in ids
    assert "cookie-missing-samesite" in ids


def test_cookie_with_all_flags_is_clean():
    art = _artifact(
        set_cookie_headers=["sid=abc; Secure; HttpOnly; SameSite=Lax"],
        cookies={"sid": "abc"},
    )
    assert check_cookies(art, CFG) == []


# --- H4: declared header policy is enforced ---------------------------------
def test_weak_hsts_and_missing_policy_headers_flagged():
    art = _artifact(headers={"strict-transport-security": "max-age=100"})
    ids = {f.id for f in check_headers(art, CFG)}
    assert "weak-hsts-max-age" in ids
    assert "hsts-no-subdomains" in ids
    assert "missing-referrer-policy" in ids
    assert "missing-permissions-policy" in ids


def test_strong_hsts_not_flagged_for_maxage():
    art = _artifact(
        headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }
    )
    ids = {f.id for f in check_headers(art, CFG)}
    assert "weak-hsts-max-age" not in ids
    assert "hsts-no-subdomains" not in ids
    assert "missing-referrer-policy" not in ids


# --- M5: security.txt missing vs invalid ------------------------------------
def test_security_txt_missing_is_reported():
    art = _artifact(url="https://example.com/.well-known/security.txt", status_code=404)
    ids = {f.id for f in check_security_txt(art, CFG)}
    assert ids == {"sectxt-missing"}


# --- ReDoS: email regex stays fast on an adversarial body -------------------
def test_email_regex_no_catastrophic_backtracking():
    hostile = "a@" + "." * 50_000
    art = _artifact(body_snippet=hostile)
    start = time.monotonic()
    check_secrets(art, CFG)
    assert time.monotonic() - start < 1.0


# --- L3: version-aware JS library detection ---------------------------------
def test_jquery_version_awareness():
    vuln = _artifact(body_snippet='<script src="jquery-3.4.1.min.js">')
    assert any(f.id == "vuln-js-jquery" for f in check_javascript(vuln, CFG))
    # 3.5.0 is the first patched release -- must not be flagged.
    safe = _artifact(body_snippet='<script src="jquery-3.6.0.min.js">')
    assert not any(f.id == "vuln-js-jquery" for f in check_javascript(safe, CFG))


# --- H1: malformed .aegisignore degrades instead of crashing ----------------
def test_malformed_ignore_file_does_not_raise(tmp_path):
    (tmp_path / ".aegisignore").write_bytes(b"\xff\xfe not utf-8 \x00")
    rules = IgnoreRules.from_root(tmp_path)  # must not raise
    assert rules.patterns == []


# --- H7: SAST dedup keeps distinct lines of the same rule -------------------
def test_sast_keeps_two_findings_on_different_lines(tmp_path):
    (tmp_path / "bad.py").write_text("eval('1')\nx = 2\neval('3')\n")
    result = SASTScanner().scan(tmp_path)
    eval_lines = sorted(f.line for f in result.findings if f.id == "eval-detected")
    assert eval_lines == [1, 3]
