from typing import List
import ssl
import socket
import sys
from datetime import datetime
from urllib.parse import urlparse
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig


def classify_cert_error(message: str) -> Finding:
    """Map an OpenSSL certificate-verification message to a finding.

    Kept separate from the network path so it is testable offline. The message
    comes from ssl.SSLCertVerificationError.verify_message.
    """
    m = message.lower()
    if "expired" in m:
        cid, title = "cert-expired", "SSL Certificate Expired"
        remediation = "Renew the SSL certificate immediately."
    elif "hostname mismatch" in m or "not valid for" in m:
        cid, title = "cert-hostname-mismatch", "Certificate Hostname Mismatch"
        remediation = "Serve a certificate whose subject alternative names include this hostname."
    elif (
        "self-signed certificate in certificate chain" in m
        or "self signed certificate in certificate chain" in m
    ):
        # A self-signed root at the top of the chain = an untrusted CA, not a
        # single self-signed leaf. Classify it by the trust failure.
        cid, title = "cert-untrusted-chain", "Untrusted Certificate Chain"
        remediation = "Install the full intermediate chain, or use a certificate from a trusted CA."
    elif "self-signed" in m or "self signed" in m:
        cid, title = "cert-self-signed", "Self-Signed Certificate"
        remediation = "Use a certificate issued by a trusted certificate authority."
    elif "unable to get" in m and "issuer" in m:
        cid, title = "cert-untrusted-chain", "Untrusted Certificate Chain"
        remediation = "Install the full intermediate chain, or use a certificate from a trusted CA."
    else:
        cid, title = "cert-invalid", "Invalid TLS Certificate"
        remediation = "Investigate the certificate: it failed validation."

    return Finding(
        id=cid,
        severity=Severity.HIGH,
        title=title,
        description=f"The server's certificate failed validation: {message}",
        url="",  # filled in by the caller, which knows the scanned URL
        remediation=remediation,
        tags=["tls", "crypto"],
    )


def check_tls(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings: List[Finding] = []

    # Only relevant for HTTPS
    if not artifact.url.startswith("https://"):
        return findings

    parsed = urlparse(artifact.url)
    hostname = parsed.hostname
    port = parsed.port or 443
    if not hostname:
        return findings

    try:
        # A validating context: on an expired / self-signed / hostname-mismatched
        # / untrusted certificate, wrap_socket raises SSLCertVerificationError.
        # The previous code caught that with a blanket except and dropped it, so
        # a broken certificate produced no finding at all -- the single most
        # important thing a TLS check should catch.
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # getpeercert() returns None when the peer presented no
                # certificate that could be validated; guard before indexing.
                # Check Expiration
                not_after_str = cert.get("notAfter") if cert else None
                if isinstance(not_after_str, str):
                    # Format: Sep 18 20:41:51 2024 GMT
                    expires = datetime.strptime(not_after_str, r"%b %d %H:%M:%S %Y %Z")
                    days_left = (expires - datetime.now()).days

                    if days_left < 0:
                        findings.append(
                            Finding(
                                id="cert-expired",
                                severity=Severity.HIGH,
                                title="SSL Certificate Expired",
                                description=f"The certificate expired {abs(days_left)} days ago.",
                                url=artifact.url,
                                remediation="Renew the SSL certificate immediately.",
                                tags=["tls", "crypto"],
                            )
                        )
                    elif days_left < 30:
                        findings.append(
                            Finding(
                                id="cert-expiring-soon",
                                severity=Severity.MEDIUM,
                                title="SSL Certificate Expiring Soon",
                                description=f"The certificate expires in {days_left} days.",
                                url=artifact.url,
                                remediation="Renew the SSL certificate.",
                                tags=["tls", "crypto"],
                            )
                        )

                # TLS Protocol Check
                # ssock.version() returns the protocol version negotiated (e.g. TLSv1.3)
                protocol = ssock.version()
                if protocol in ["TLSv1", "TLSv1.1"]:
                    findings.append(
                        Finding(
                            id="deprecated-tls",
                            severity=Severity.HIGH,
                            title=f"Deprecated TLS Version ({protocol})",
                            description=f"Server negotiated an insecure protocol version: {protocol}.",
                            url=artifact.url,
                            remediation="Disable TLS 1.0/1.1 and enforce TLS 1.2 or 1.3.",
                            tags=["tls", "crypto"],
                        )
                    )

    except ssl.SSLCertVerificationError as exc:
        finding = classify_cert_error(exc.verify_message or str(exc))
        finding.url = artifact.url
        findings.append(finding)
    except Exception as exc:
        # Genuine connection problems (timeout, refused, DNS) are not a
        # certificate verdict; don't manufacture a finding from them. But leave
        # a diagnostic trail on stderr so a healthy host and an unreachable one
        # aren't silently identical in the report.
        print(f"TLS check could not connect to {artifact.url}: {exc}", file=sys.stderr)

    return findings
