"""SARIF 2.1.0 conformance tests.

SARIF's `result.level` enum is only none/note/warning/error -- there is no
"critical". A tool that stops at `level` therefore reports a leaked private key
to GitHub's Security tab as an indistinguishable "warning". GitHub derives its
Critical/High/Medium/Low badge from `rules[].properties["security-severity"]`,
a *string* holding 0.1-10.0, with >=9.0 rendering as Critical.

Ref: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

import json

import pytest

from aegisaudit.models import Finding, ScanResult, Severity
from aegisaudit.reporters import generate_sarif_report

VALID_SARIF_LEVELS = {"none", "note", "warning", "error"}


def finding(severity: Severity, id: str = "f1", line: int | None = None, url: str = "src/a.py"):
    return Finding(
        id=id,
        severity=severity,
        title="Test finding",
        description="Test description",
        url=url,
        line=line,
        tags=["secrets"],
    )


def write_sarif(tmp_path, findings):
    result = ScanResult(targets=["."], findings=findings)
    out = tmp_path / "report.sarif"
    generate_sarif_report(result, out)
    return json.loads(out.read_text())


def rule_for(sarif, rule_id):
    return next(r for r in sarif["runs"][0]["tool"]["driver"]["rules"] if r["id"] == rule_id)


class TestSeverityIsNotFlattened:
    def test_critical_is_distinguishable_from_medium(self):
        """Regression: CRITICAL and MEDIUM both fell through to 'warning',
        so a hardcoded private key and a missing header looked identical."""
        # security-severity is what GitHub actually renders.
        from aegisaudit.reporters.sarif_report import security_severity_for

        assert float(security_severity_for(Severity.CRITICAL)) >= 9.0
        assert float(security_severity_for(Severity.HIGH)) >= 7.0
        assert float(security_severity_for(Severity.CRITICAL)) > float(
            security_severity_for(Severity.MEDIUM)
        )

    def test_critical_rule_carries_security_severity_at_least_9(self, tmp_path):
        sarif = write_sarif(tmp_path, [finding(Severity.CRITICAL, id="leaked-key")])
        rule = rule_for(sarif, "leaked-key")
        assert float(rule["properties"]["security-severity"]) >= 9.0

    def test_security_severity_is_a_string_not_a_number(self, tmp_path):
        """GitHub requires this property as a string; a float is rejected."""
        sarif = write_sarif(tmp_path, [finding(Severity.CRITICAL, id="leaked-key")])
        assert isinstance(rule_for(sarif, "leaked-key")["properties"]["security-severity"], str)

    @pytest.mark.parametrize("severity", list(Severity))
    def test_level_is_always_a_valid_sarif_enum_value(self, tmp_path, severity):
        sarif = write_sarif(tmp_path, [finding(severity, id="x")])
        assert sarif["runs"][0]["results"][0]["level"] in VALID_SARIF_LEVELS

    def test_critical_and_high_are_errors(self, tmp_path):
        sarif = write_sarif(
            tmp_path, [finding(Severity.CRITICAL, id="a"), finding(Severity.HIGH, id="b")]
        )
        assert {r["level"] for r in sarif["runs"][0]["results"]} == {"error"}


class TestLocations:
    def test_line_number_is_emitted_as_region_startline(self, tmp_path):
        """Without a region GitHub anchors the alert to line 1 of the file."""
        sarif = write_sarif(tmp_path, [finding(Severity.HIGH, line=42)])
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 42

    def test_no_region_emitted_when_line_unknown(self, tmp_path):
        """Better to omit the region than to invent line 1."""
        sarif = write_sarif(tmp_path, [finding(Severity.HIGH, line=None)])
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "region" not in loc

    def test_artifact_uri_is_relative_not_absolute(self, tmp_path):
        """An absolute local path (/home/runner/work/...) matches nothing in the
        GitHub repo tree, so the alert cannot be rendered against a file."""
        sarif = write_sarif(tmp_path, [finding(Severity.HIGH, url="src/app.py")])
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        assert not uri.startswith("/")


class TestSchemaConformance:
    def test_sarif_validates_against_the_official_2_1_0_schema(self, tmp_path):
        jsonschema = pytest.importorskip("jsonschema")
        schema_file = tmp_path.parent / "sarif-schema-2.1.0.json"
        if not schema_file.exists():
            pytest.skip("SARIF schema not cached locally")
        sarif = write_sarif(tmp_path, [finding(Severity.CRITICAL, line=3)])
        jsonschema.validate(sarif, json.loads(schema_file.read_text()))
