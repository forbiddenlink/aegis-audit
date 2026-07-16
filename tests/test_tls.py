"""TLS certificate validation tests.

check_tls connected with a validating SSL context and then swallowed every
exception, so an expired, self-signed, hostname-mismatched, or
untrusted-chain certificate -- exactly the conditions a posture scanner exists
to report -- produced no finding at all. The classifier maps an OpenSSL
verification message to a finding; it is unit-tested here, and the live path is
exercised manually against badssl.com.
"""

from aegisaudit.checks.tls import classify_cert_error
from aegisaudit.models import Severity


class TestClassifyCertError:
    def test_expired(self):
        f = classify_cert_error("certificate has expired")
        assert f.id == "cert-expired"
        assert f.severity == Severity.HIGH

    def test_hostname_mismatch(self):
        f = classify_cert_error("Hostname mismatch, certificate is not valid for 'example.com'.")
        assert f.id == "cert-hostname-mismatch"
        assert f.severity == Severity.HIGH

    def test_self_signed(self):
        f = classify_cert_error("self-signed certificate")
        assert f.id == "cert-self-signed"

    def test_self_signed_in_chain_is_an_untrusted_chain(self):
        """A self-signed root at the top of the chain is an untrusted CA, not a
        self-signed leaf."""
        f = classify_cert_error("self-signed certificate in certificate chain")
        assert f.id == "cert-untrusted-chain"

    def test_untrusted_chain(self):
        f = classify_cert_error("unable to get local issuer certificate")
        assert f.id == "cert-untrusted-chain"

    def test_unknown_reason_still_reports_a_finding(self):
        """An unrecognized verification failure must still surface, not vanish."""
        f = classify_cert_error("some brand new openssl error string")
        assert f.id == "cert-invalid"
        assert f.severity == Severity.HIGH

    def test_finding_is_tagged_tls(self):
        assert "tls" in classify_cert_error("certificate has expired").tags

    def test_reason_is_carried_into_the_description(self):
        f = classify_cert_error("unable to get local issuer certificate")
        assert "unable to get local issuer certificate" in f.description
