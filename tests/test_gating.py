"""CI gate decision logic.

The gate turns a scan into an exit code, and a gate that fails open is a silent
security hole: CI would go green on a leaked key. These lock the boundaries
(format/severity parsing, the at-or-above count, and the opt-in fail rules).
"""

import pytest

from aegisaudit.gating import (
    findings_at_or_above,
    gate_failure_reason,
    parse_formats,
    parse_severity,
)
from aegisaudit.models import Finding, ScanResult, ScanSummary, Severity


def _result(severities=(), score: float = 100.0) -> ScanResult:
    findings = [
        Finding(id=f"f{i}", severity=s, title="t", description="d", url="https://x.test")
        for i, s in enumerate(severities)
    ]
    return ScanResult(
        targets=["https://x.test"],
        findings=findings,
        summary=ScanSummary(overall_score=score),
    )


# --- parse_formats --------------------------------------------------------


def test_parse_formats_comma_and_repeat():
    assert parse_formats(["json,sarif"]) == {"json", "sarif"}
    assert parse_formats(["json", "html"]) == {"json", "html"}
    assert parse_formats(["summary"]) == {"summary"}


def test_parse_formats_all_expands():
    assert parse_formats(["all"]) == {"json", "sarif", "html", "summary"}


def test_parse_formats_ignores_blank_parts():
    assert parse_formats(["json,,"]) == {"json"}


def test_parse_formats_unknown_raises():
    with pytest.raises(ValueError, match="Unknown format"):
        parse_formats(["pdf"])


def test_parse_formats_empty_raises():
    # A silent "no formats" once wrote zero reports while exiting 0.
    with pytest.raises(ValueError, match="No output format"):
        parse_formats([" , "])


# --- parse_severity -------------------------------------------------------


def test_parse_severity_valid():
    assert parse_severity("HIGH") == Severity.HIGH


def test_parse_severity_unknown_raises():
    with pytest.raises(ValueError, match="Unknown severity"):
        parse_severity("spicy")


# --- findings_at_or_above -------------------------------------------------


def test_findings_at_or_above_is_inclusive_floor():
    r = _result([Severity.LOW, Severity.HIGH, Severity.CRITICAL])
    assert findings_at_or_above(r, Severity.HIGH) == 2  # high + critical, not low
    assert findings_at_or_above(r, Severity.INFO) == 3
    assert findings_at_or_above(r, Severity.CRITICAL) == 1


# --- gate_failure_reason --------------------------------------------------


def test_gate_is_noop_when_no_options_set():
    # Opt-in: a critical finding still passes the gate if no flag is given.
    assert gate_failure_reason(_result([Severity.CRITICAL], score=0.0)) is None


def test_gate_fail_on_trips():
    reason = gate_failure_reason(_result([Severity.HIGH]), fail_on=Severity.HIGH)
    assert reason is not None and "at or above" in reason


def test_gate_fail_on_passes_below_threshold():
    assert gate_failure_reason(_result([Severity.LOW]), fail_on=Severity.HIGH) is None


def test_gate_fail_under_trips_and_boundary_is_exclusive():
    assert gate_failure_reason(_result(score=79.9), fail_under=80.0) is not None
    # exactly at the floor passes (strictly-below fails)
    assert gate_failure_reason(_result(score=80.0), fail_under=80.0) is None
