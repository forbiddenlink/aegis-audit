"""Tests for the scoring engine.

The scoring engine is the product's core output: a single grade that a user
(or a CI gate) acts on. These tests exist because a scoring regression is
indistinguishable from "everything is fine" without them.
"""

import pytest

from aegisaudit.models import Finding, Severity
from aegisaudit.scoring import calculate_score


def finding(severity: Severity, tags: list[str], id: str = "test-finding") -> Finding:
    return Finding(
        id=id,
        severity=severity,
        title="Test finding",
        description="Test finding",
        url="https://example.com",
        tags=tags,
    )


class TestFindingsAffectScore:
    """Every finding a scanner reports must move the score. The alternative is
    a tool that reports a CRITICAL and grades itself 100/100."""

    def test_critical_secret_does_not_score_100(self):
        """Regression: a hardcoded private key scored 100.0/100 because its
        tags matched no scoring category and were silently discarded."""
        result = calculate_score([finding(Severity.CRITICAL, ["secrets", "crypto", "sast"])])
        assert result.overall_score < 100.0

    def test_exposed_env_file_does_not_score_100(self):
        """Regression: an exposed .env is the worst thing `scan` can find and
        deducted exactly zero."""
        result = calculate_score([finding(Severity.HIGH, ["exposure", "config"])])
        assert result.overall_score < 100.0

    def test_exposed_git_repo_does_not_score_100(self):
        result = calculate_score([finding(Severity.HIGH, ["exposure", "git"])])
        assert result.overall_score < 100.0

    def test_vulnerable_dependency_does_not_score_100(self):
        result = calculate_score([finding(Severity.HIGH, ["sast", "dependency", "python"])])
        assert result.overall_score < 100.0

    @pytest.mark.parametrize(
        "severity",
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
    )
    def test_every_actionable_severity_moves_the_score(self, severity):
        """INFO is excluded by design; everything else must cost something."""
        result = calculate_score([finding(severity, ["headers"])])
        assert result.overall_score < 100.0


class TestNoSilentlyDiscardedFindings:
    """The root cause of the 100/100 bug was a silent `if cat is not None` skip.
    An unmapped tag must never be swallowed."""

    def test_unmapped_tag_raises_rather_than_scoring_100(self):
        with pytest.raises(ValueError, match="uncategorized|unmapped|unknown"):
            calculate_score([finding(Severity.CRITICAL, ["totally-unknown-tag"])])

    def test_finding_with_no_tags_raises(self):
        with pytest.raises(ValueError, match="uncategorized|unmapped|unknown"):
            calculate_score([finding(Severity.CRITICAL, [])])


class TestNoFreePoints:
    """Categories that were never checked must not donate a free 100 to the
    score. Under the old weighted average, 25% of the weight could never be
    deducted for an HTTPS target, which put a floor of 25/100 under every scan
    and gave example.com an 87.2 despite failing every header check."""

    def test_critical_alone_scores_zero_not_a_diluted_average(self):
        """A CRITICAL is disqualifying. It must not be averaged back up to 80
        by seven untouched categories sitting at 100."""
        result = calculate_score([finding(Severity.CRITICAL, ["headers"])])
        assert result.overall_score == 0.0

    def test_clean_scan_scores_100(self):
        result = calculate_score([])
        assert result.overall_score == 100.0

    def test_info_findings_do_not_reduce_score(self):
        result = calculate_score([finding(Severity.INFO, ["headers"])])
        assert result.overall_score == 100.0


class TestSeverityOrdering:
    """A worse finding must never score better than a milder one."""

    def test_critical_scores_worse_than_low(self):
        crit = calculate_score([finding(Severity.CRITICAL, ["headers"])]).overall_score
        low = calculate_score([finding(Severity.LOW, ["headers"])]).overall_score
        assert crit < low

    def test_more_findings_score_worse_than_fewer(self):
        one = calculate_score([finding(Severity.MEDIUM, ["headers"], id="a")]).overall_score
        two = calculate_score(
            [
                finding(Severity.MEDIUM, ["headers"], id="a"),
                finding(Severity.MEDIUM, ["cookies"], id="b"),
            ]
        ).overall_score
        assert two < one


class TestCounts:
    def test_counts_by_severity_reflects_findings(self):
        result = calculate_score(
            [
                finding(Severity.HIGH, ["headers"], id="a"),
                finding(Severity.HIGH, ["cookies"], id="b"),
                finding(Severity.LOW, ["tls"], id="c"),
            ]
        )
        assert result.counts_by_severity[Severity.HIGH] == 2
        assert result.counts_by_severity[Severity.LOW] == 1
