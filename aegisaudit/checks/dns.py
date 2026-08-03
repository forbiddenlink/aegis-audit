import logging
from typing import List
import dns.resolver
from urllib.parse import urlparse
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig

logger = logging.getLogger(__name__)


def check_dns(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings = []

    try:
        domain = urlparse(artifact.final_url).netloc
        # Strip port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        # SPF Check
        has_spf = False
        try:
            txt_records = dns.resolver.resolve(domain, "TXT")
            for r in txt_records:
                txt = r.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    has_spf = True
                    # Basic check for strictness
                    if "+all" in txt:
                        findings.append(
                            Finding(
                                id="spf-allow-all",
                                severity=Severity.HIGH,
                                title="Weak SPF Record",
                                description="SPF record allows all IPs (+all), rendering it useless.",
                                evidence=txt,
                                url=artifact.url,
                                remediation="Change +all to -all or ~all.",
                                tags=["dns", "email"],
                            )
                        )
                    break
        except Exception:
            pass  # No TXT records or timeout

        if not has_spf:
            findings.append(
                Finding(
                    id="missing-spf",
                    severity=Severity.MEDIUM,
                    title="Missing SPF Record",
                    description="Sender Policy Framework (SPF) record is missing.",
                    url=artifact.url,
                    remediation="Add a TXT record for SPF to prevent email spoofing.",
                    tags=["dns", "email"],
                )
            )

        # DMARC Check
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dns.resolver.resolve(dmarc_domain, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            findings.append(
                Finding(
                    id="missing-dmarc",
                    severity=Severity.MEDIUM,
                    title="Missing DMARC Record",
                    description="DMARC record is missing at _dmarc subdomain.",
                    url=artifact.url,
                    remediation="Configure DMARC to enforce SPF/DKIM policies.",
                    tags=["dns", "email"],
                )
            )
        except Exception:
            pass

        # CAA Check (Certificate Authority Authorization)
        try:
            dns.resolver.resolve(domain, "CAA")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            findings.append(
                Finding(
                    id="missing-caa",
                    severity=Severity.LOW,
                    title="Missing CAA Record",
                    description="No Certificate Authority Authorization (CAA) record found.",
                    url=artifact.url,
                    remediation="Add CAA records to restrict which CAs can issue certificates for your domain.",
                    tags=["dns", "pki"],
                )
            )
        except Exception:
            pass

    except Exception as e:
        # DNS failures shouldn't crash the scanner
        logger.warning("DNS check failed: %s", e)

    return findings
