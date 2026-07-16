from typing import List, Callable
from aegisaudit.models import ScanArtifact, Finding, ScanResult
from aegisaudit.config import AegisConfig
from aegisaudit.scoring import calculate_score

# Import checks
from aegisaudit.checks.headers import check_headers
from aegisaudit.checks.cookies import check_cookies
from aegisaudit.checks.https import check_https
from aegisaudit.checks.security_txt import check_security_txt
from aegisaudit.checks.sri import check_sri
from aegisaudit.checks.dns import check_dns
from aegisaudit.checks.javascript import check_javascript
from aegisaudit.checks.tls import check_tls
from aegisaudit.checks.secrets import check_secrets
from aegisaudit.checks.exposure import check_exposure

CHECK_MODULES: List[Callable[[ScanArtifact, AegisConfig], List[Finding]]] = [
    check_headers,
    check_cookies,
    check_https,
    check_security_txt,
    check_sri,
    check_dns,
    check_javascript,
    check_tls,
    check_secrets,
    check_exposure,
]


class Runner:
    def __init__(self, config: AegisConfig):
        self.config = config

    def run_checks(self, artifacts: List[ScanArtifact]) -> ScanResult:
        all_findings = []

        for artifact in artifacts:
            for check_func in CHECK_MODULES:
                findings = check_func(artifact, self.config)
                all_findings.extend(findings)

        # Calculate Summary using Scoring Engine
        summary = calculate_score(all_findings)

        return ScanResult(
            targets=[a.url for a in artifacts],
            findings=all_findings,
            summary=summary,
            config_snapshot=self.config.model_dump(mode="json"),
        )
