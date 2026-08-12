"""Baseline diffing: identity, persistence, and suppression."""

import json

import pytest

from aegisaudit.baseline import (
    BaselineError,
    apply_baseline,
    fingerprint,
    load_baseline,
    write_baseline,
)
from aegisaudit.models import Finding, ScanResult, ScanSummary, Severity


def _finding(id_="eval-use", url="src/app.py", desc="use of eval()", line=10, sev=Severity.HIGH):
    return Finding(
        id=id_, severity=sev, title="t", description=desc, url=url, line=line, tags=["headers"]
    )


def _result(findings):
    return ScanResult(targets=["src"], findings=findings, summary=ScanSummary())


# --- fingerprint identity -------------------------------------------------


def test_fingerprint_is_stable_across_line_drift():
    # Same rule + path + description, different line -> same fingerprint.
    assert fingerprint(_finding(line=10)) == fingerprint(_finding(line=99))


def test_fingerprint_ignores_evidence():
    a = _finding()
    b = _finding()
    b.evidence = "AKIA_SECRET_LEAK"  # evidence must not shift identity
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_by_rule_path_and_description():
    base = fingerprint(_finding())
    assert fingerprint(_finding(id_="other-rule")) != base
    assert fingerprint(_finding(url="src/other.py")) != base
    assert fingerprint(_finding(desc="different")) != base


# --- persistence ----------------------------------------------------------


def test_write_then_load_roundtrip(tmp_path):
    path = tmp_path / "baseline.json"
    n = write_baseline(path, [_finding(), _finding(id_="b"), _finding()], tool_version="0.1.0")
    assert n == 2  # duplicates collapse
    loaded = load_baseline(path)
    assert fingerprint(_finding()) in loaded


def test_baseline_file_stores_only_hashes_not_evidence(tmp_path):
    path = tmp_path / "baseline.json"
    f = _finding(desc="hardcoded AWS key")
    f.evidence = "AKIAIOSFODNN7EXAMPLE"
    write_baseline(path, [f], tool_version="0.1.0")
    text = path.read_text()
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "hardcoded AWS key" not in text  # description is hashed, not stored


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "nope.json")


def test_load_malformed_json_raises(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("{not json")
    with pytest.raises(BaselineError):
        load_baseline(p)


def test_load_wrong_shape_raises(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"nope": []}))
    with pytest.raises(BaselineError):
        load_baseline(p)


def test_load_fingerprints_not_a_list_raises(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"fingerprints": "oops"}))
    with pytest.raises(BaselineError):
        load_baseline(p)


# --- suppression ----------------------------------------------------------


def test_apply_baseline_suppresses_known_and_keeps_new():
    old = _finding(id_="eval-use")
    new = _finding(id_="exec-use", desc="use of exec()")
    baseline = {fingerprint(old)}

    filtered, suppressed = apply_baseline(_result([old, new]), baseline)

    assert suppressed == 1
    assert [f.id for f in filtered.findings] == ["exec-use"]


def test_apply_baseline_rescores_to_new_findings_only():
    old = _finding(id_="eval-use", sev=Severity.HIGH)  # would be -40
    baseline = {fingerprint(old)}
    filtered, _ = apply_baseline(_result([old]), baseline)
    # Only baselined findings remain -> nothing new -> full score.
    assert filtered.summary.overall_score == 100.0


def test_apply_empty_baseline_is_identity():
    findings = [_finding(), _finding(id_="x", desc="d2")]
    filtered, suppressed = apply_baseline(_result(findings), set())
    assert suppressed == 0
    assert len(filtered.findings) == 2
