from concurrent.futures import ThreadPoolExecutor
from typing import List, Callable, Tuple, Set
from urllib.parse import urlparse
from aegisaudit.models import ScanArtifact, Finding, ScanResult, Severity
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

# Deterministic ordering for findings collected out of order by the thread pool.
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _sort_key(f: Finding) -> Tuple[str, int, str, int]:
    return (f.url, _SEVERITY_RANK.get(f.severity, 9), f.id, f.line or 0)


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """Collapse identical findings raised against the same host.

    --probe expands one target into several same-host URLs (the page, /.env,
    /.git/HEAD). Every check runs against every artifact, so host-level findings
    (missing HSTS, missing SPF, a leaked Server header) were emitted once per
    probe URL -- inflating both the report and the score deduction.

    Two findings are "the same issue" when they share an id, a host, and a
    description. The description keeps genuinely distinct findings apart: two
    external scripts each missing SRI differ in their described src, and two
    different sites missing HSTS differ in their host, so both are preserved.
    """
    seen: Set[Tuple[str, str, str]] = set()
    result: List[Finding] = []
    for finding in findings:
        host = urlparse(finding.url).netloc
        key = (finding.id, host, finding.description)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


class Runner:
    def __init__(self, config: AegisConfig):
        self.config = config

    def _check_artifact(self, artifact: ScanArtifact) -> List[Finding]:
        findings: List[Finding] = []
        for check_func in CHECK_MODULES:
            findings.extend(check_func(artifact, self.config))
        return findings

    def run_checks(self, artifacts: List[ScanArtifact]) -> ScanResult:
        all_findings: List[Finding] = []

        # Each artifact's checks are independent, and the network-bound ones
        # (DNS resolution, TLS handshake) dominate wall-clock. Running one
        # artifact per worker overlaps that I/O instead of scanning targets one
        # at a time. Findings come back out of order, so sort for determinism.
        if len(artifacts) > 1:
            workers = min(max(1, self.config.limits.max_concurrency), len(artifacts))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for result in pool.map(self._check_artifact, artifacts):
                    all_findings.extend(result)
        else:
            for artifact in artifacts:
                all_findings.extend(self._check_artifact(artifact))

        all_findings = dedupe_findings(all_findings)
        all_findings.sort(key=_sort_key)

        # Calculate Summary using Scoring Engine
        summary = calculate_score(all_findings)

        return ScanResult(
            targets=[a.url for a in artifacts],
            findings=all_findings,
            summary=summary,
            config_snapshot=self.config.model_dump(mode="json"),
        )
