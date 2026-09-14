import logging
from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from aegisaudit.checks.dns import check_dns
from aegisaudit.config import AegisConfig
from aegisaudit.models import ScanArtifact


def artifact():
    return ScanArtifact(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
        cookies={},
        body_snippet="",
        content_type="text/html",
    )


def _txt(value: str) -> Mock:
    record = Mock()
    record.to_text.return_value = '"' + value + '"'
    return record


def _resolver(*, spf=None, dmarc=None, caa=False, spf_error=None):
    def resolve(domain, record_type):
        if domain == "example.com" and record_type == "TXT":
            if spf_error is not None:
                raise spf_error
            if spf is None:
                raise dns.resolver.NoAnswer()
            return [_txt(spf)]
        if domain == "_dmarc.example.com" and record_type == "TXT":
            if dmarc is None:
                raise dns.resolver.NXDOMAIN()
            return [_txt(dmarc)]
        if record_type == "CAA":
            if not caa:
                raise dns.resolver.NXDOMAIN()
            return [Mock()]
        raise dns.resolver.NoAnswer()

    return resolve


@pytest.mark.parametrize("failure", [dns.exception.Timeout(), dns.resolver.NoNameservers()])
def test_spf_lookup_failure_is_not_a_missing_record(monkeypatch, caplog, failure):
    monkeypatch.setattr(
        dns.resolver, "resolve", _resolver(spf_error=failure, dmarc="v=DMARC1; p=reject")
    )
    with caplog.at_level(logging.INFO):
        findings = check_dns(artifact(), AegisConfig())
    assert not any(f.id == "missing-spf" for f in findings)
    assert "SPF lookup failed" in caplog.text


@pytest.mark.parametrize("response", [[], dns.resolver.NoAnswer(), dns.resolver.NXDOMAIN()])
def test_confirmed_absent_spf_is_reported(monkeypatch, response):
    def resolve(domain, record_type):
        if domain == "example.com" and record_type == "TXT":
            if isinstance(response, Exception):
                raise response
            return response
        if domain == "_dmarc.example.com":
            return [_txt("v=DMARC1; p=reject")]
        if record_type == "CAA":
            return [Mock()]
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    assert any(f.id == "missing-spf" for f in check_dns(artifact(), AegisConfig()))


@pytest.mark.parametrize("policy, weak", [("v=spf1 -all", False), ("v=spf1 +all", True)])
def test_existing_spf_policy_still_checked(monkeypatch, policy, weak):
    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        _resolver(spf=policy, dmarc="v=DMARC1; p=reject", caa=True),
    )
    findings = check_dns(artifact(), AegisConfig())
    assert not any(f.id == "missing-spf" for f in findings)
    assert any(f.id == "spf-allow-all" for f in findings) is weak


def test_dmarc_p_none_is_reported(monkeypatch):
    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        _resolver(spf="v=spf1 -all", dmarc="v=DMARC1; p=none; rua=mailto:d@example.com", caa=True),
    )
    findings = check_dns(artifact(), AegisConfig())
    assert any(f.id == "dmarc-policy-none" for f in findings)
    assert not any(f.id == "missing-dmarc" for f in findings)


def test_dmarc_reject_is_clean(monkeypatch):
    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        _resolver(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject", caa=True),
    )
    ids = {f.id for f in check_dns(artifact(), AegisConfig())}
    assert "dmarc-policy-none" not in ids
    assert "missing-dmarc" not in ids


def test_missing_dmarc_is_reported(monkeypatch):
    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        _resolver(spf="v=spf1 -all", dmarc=None, caa=True),
    )
    assert any(f.id == "missing-dmarc" for f in check_dns(artifact(), AegisConfig()))
