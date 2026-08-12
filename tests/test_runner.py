"""Tests for the scan orchestrator.

Covers the parts of Runner that the per-check tests do not: the serial vs
thread-pool fan-out, cross-artifact dedupe, deterministic ordering of findings
that come back from the pool out of order, and that the score is computed over
the deduped set. CHECK_MODULES is stubbed so these exercise the orchestration
logic without any network (the real DNS/TLS checks make live calls).
"""

import aegisaudit.runner as runner_mod
from aegisaudit.config import AegisConfig
from aegisaudit.models import Finding, ScanArtifact, Severity


def _artifact(url: str) -> ScanArtifact:
    return ScanArtifact(
        url=url,
        final_url=url,
        status_code=200,
        headers={},
        cookies={},
        set_cookie_headers=[],
        body_snippet="",
        content_type="text/html",
    )


def _finding(id_: str, url: str, sev: Severity = Severity.MEDIUM, desc: str = "d") -> Finding:
    # "headers" maps to a scoring category; the scorer hard-errors on findings
    # whose tags map to none, so a real tag is required to reach the score path.
    return Finding(id=id_, severity=sev, title=id_, description=desc, url=url, tags=["headers"])


def _stub_checks(monkeypatch, func) -> None:
    """Replace the real check pipeline with a single deterministic check."""
    monkeypatch.setattr(runner_mod, "CHECK_MODULES", [func])


def test_run_checks_single_artifact_serial(monkeypatch):
    _stub_checks(monkeypatch, lambda art, cfg: [_finding("high-x", art.url, Severity.HIGH)])

    result = runner_mod.Runner(AegisConfig()).run_checks([_artifact("https://a.test/")])

    assert result.targets == ["https://a.test/"]
    assert len(result.findings) == 1
    assert result.findings[0].id == "high-x"
    # score deducted from the pool for one HIGH (100 - 40)
    assert result.summary.overall_score == 60.0
    # config is snapshotted for reproducibility
    assert result.config_snapshot is not None


def test_run_checks_multiple_artifacts_parallel(monkeypatch):
    # >1 artifact takes the ThreadPoolExecutor branch.
    _stub_checks(monkeypatch, lambda art, cfg: [_finding("missing-hsts", art.url, Severity.HIGH)])

    artifacts = [_artifact(f"https://h{i}.test/") for i in range(4)]
    result = runner_mod.Runner(AegisConfig()).run_checks(artifacts)

    # Distinct hosts -> not deduped -> one finding each.
    assert len(result.findings) == 4
    assert {f.url for f in result.findings} == {a.url for a in artifacts}


def test_run_checks_dedupes_same_host_finding(monkeypatch):
    # Same id + host + description across probe URLs collapses to one.
    def check(art, cfg):
        return [_finding("missing-hsts", "https://x.test/", Severity.HIGH, "no hsts")]

    _stub_checks(monkeypatch, check)
    artifacts = [_artifact("https://x.test/"), _artifact("https://x.test/.env")]

    result = runner_mod.Runner(AegisConfig()).run_checks(artifacts)

    assert len(result.findings) == 1
    # scored once, not twice: 100 - 40, not 100 - 80
    assert result.summary.overall_score == 60.0


def test_run_checks_orders_findings_deterministically(monkeypatch):
    # Emit findings low-to-high; runner must sort by (url, severity rank, id).
    def check(art, cfg):
        return [
            _finding("z-low", "https://a.test/", Severity.LOW),
            _finding("a-crit", "https://a.test/", Severity.CRITICAL),
            _finding("m-med", "https://a.test/", Severity.MEDIUM),
        ]

    _stub_checks(monkeypatch, check)
    result = runner_mod.Runner(AegisConfig()).run_checks([_artifact("https://a.test/")])

    order = [f.id for f in result.findings]
    assert order == ["a-crit", "m-med", "z-low"]  # critical first, info last


def test_run_checks_no_findings_scores_full(monkeypatch):
    _stub_checks(monkeypatch, lambda art, cfg: [])
    result = runner_mod.Runner(AegisConfig()).run_checks([_artifact("https://a.test/")])

    assert result.findings == []
    assert result.summary.overall_score == 100.0
