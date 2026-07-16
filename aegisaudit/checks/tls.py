from typing import List
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig


def check_tls(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings: List[Finding] = []

    # Only relevant for HTTPS
    if not artifact.url.startswith("https://"):
        return findings

    try:
        parsed = urlparse(artifact.url)
        hostname = parsed.hostname
        port = parsed.port or 443

        # We need a synchronous socket connection to inspect the certificate
        # This duplicates some work but allows deep inspection not always exposed by httpx
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

    except Exception:
        # Don't crash on connection errors, just log
        pass

    return findings
