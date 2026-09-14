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
        spf_lookup_complete = False
        try:
            txt_records = dns.resolver.resolve(domain, "TXT")
            spf_lookup_complete = True
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
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            spf_lookup_complete = True
        except Exception as exc:
            spf_lookup_complete = False
            logger.info("SPF lookup failed for %s: %s", domain, exc)

        if spf_lookup_complete and not has_spf:
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

        # DMARC Check. Presence alone is not protection: p=none is monitor-only
        # (Mozilla Observatory / DMARC spec) and still lets spoofed mail through.
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_answers = dns.resolver.resolve(dmarc_domain, "TXT")
            dmarc_txt = None
            for record in dmarc_answers:
                txt = record.to_text().strip('"')
                if txt.lower().startswith("v=dmarc1"):
                    dmarc_txt = txt
                    break
            if dmarc_txt is None:
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
            else:
                policy_tag = None
                for part in dmarc_txt.split(";"):
                    part = part.strip().lower()
                    if part.startswith("p="):
                        policy_tag = part.split("=", 1)[1].strip()
                        break
                if policy_tag == "none":
                    findings.append(
                        Finding(
                            id="dmarc-policy-none",
                            severity=Severity.MEDIUM,
                            title="DMARC Policy Is none",
                            description=(
                                "DMARC is published with p=none, which only monitors. "
                                "Spoofed mail is still delivered."
                            ),
                            evidence=dmarc_txt,
                            url=artifact.url,
                            remediation="Raise the policy to p=quarantine or p=reject once reports look clean.",
                            tags=["dns", "email"],
                        )
                    )
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
