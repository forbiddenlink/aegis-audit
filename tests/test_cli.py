"""CLI behaviour tests, with emphasis on CI gating.

A scanner that cannot fail a build is decorative. Before these tests the only
`typer.Exit` in the whole CLI was "no targets specified", so both commands
exited 0 no matter what they found -- a tool positioned on CI gating had no
gate.

Exit code convention follows semgrep / osv-scanner, the dominant one:
    0   clean (or findings present but below the gate)
    1   findings tripped the gate
    >=2 tool/usage error, distinct from "found something"
"""

import json

from typer.testing import CliRunner

from aegisaudit.cli import app

runner = CliRunner()

AWS_KEY_FILE = "KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
PRIVATE_KEY_FILE = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n"


class TestAuditGating:
    def test_exits_0_when_nothing_found(self, tmp_path):
        (tmp_path / "clean.py").write_text("print('ok')\n")
        result = runner.invoke(
            app, ["audit", str(tmp_path), "--out", str(tmp_path / "o"), "--format", "json"]
        )
        assert result.exit_code == 0

    def test_exits_0_by_default_even_with_findings(self, tmp_path):
        """Gating is opt-in: without --fail-on/--fail-under, reporting is
        non-blocking, matching `semgrep scan` and `trivy` defaults."""
        (tmp_path / "bad.py").write_text(AWS_KEY_FILE)
        result = runner.invoke(
            app, ["audit", str(tmp_path), "--out", str(tmp_path / "o"), "--format", "json"]
        )
        assert result.exit_code == 0

    def test_fail_on_high_exits_1_when_a_high_is_present(self, tmp_path):
        (tmp_path / "bad.py").write_text(AWS_KEY_FILE)
        result = runner.invoke(
            app,
            [
                "audit",
                str(tmp_path),
                "--out",
                str(tmp_path / "o"),
                "--format",
                "json",
                "--fail-on",
                "high",
            ],
        )
        assert result.exit_code == 1

    def test_fail_on_high_exits_1_when_a_critical_is_present(self, tmp_path):
        """--fail-on is a floor: anything at or above it trips the gate."""
        (tmp_path / "key.pem").write_text(PRIVATE_KEY_FILE)
        result = runner.invoke(
            app,
            [
                "audit",
                str(tmp_path),
                "--out",
                str(tmp_path / "o"),
                "--format",
                "json",
                "--fail-on",
                "high",
            ],
        )
        assert result.exit_code == 1

    def test_fail_on_critical_exits_0_when_only_high_present(self, tmp_path):
        (tmp_path / "bad.py").write_text(AWS_KEY_FILE)
        result = runner.invoke(
            app,
            [
                "audit",
                str(tmp_path),
                "--out",
                str(tmp_path / "o"),
                "--format",
                "json",
                "--fail-on",
                "critical",
            ],
        )
        assert result.exit_code == 0

    def test_fail_under_exits_1_when_score_below_threshold(self, tmp_path):
        (tmp_path / "key.pem").write_text(PRIVATE_KEY_FILE)
        result = runner.invoke(
            app,
            [
                "audit",
                str(tmp_path),
                "--out",
                str(tmp_path / "o"),
                "--format",
                "json",
                "--fail-under",
                "50",
            ],
        )
        assert result.exit_code == 1

    def test_fail_under_exits_0_when_score_meets_threshold(self, tmp_path):
        (tmp_path / "clean.py").write_text("print('ok')\n")
        result = runner.invoke(
            app,
            [
                "audit",
                str(tmp_path),
                "--out",
                str(tmp_path / "o"),
                "--format",
                "json",
                "--fail-under",
                "50",
            ],
        )
        assert result.exit_code == 0

    def test_invalid_fail_on_value_is_a_usage_error_not_a_finding(self, tmp_path):
        """Exit >=2 distinguishes 'the tool broke' from 'the tool found
        something'. CI needs to tell those apart."""
        (tmp_path / "clean.py").write_text("print('ok')\n")
        result = runner.invoke(
            app,
            [
                "audit",
                str(tmp_path),
                "--out",
                str(tmp_path / "o"),
                "--format",
                "json",
                "--fail-on",
                "bogus",
            ],
        )
        assert result.exit_code >= 2


class TestFormatParsing:
    def test_comma_separated_formats_are_honoured_by_audit(self, tmp_path):
        out = tmp_path / "o"
        (tmp_path / "clean.py").write_text("print('ok')\n")
        runner.invoke(app, ["audit", str(tmp_path), "--out", str(out), "--format", "json,sarif"])
        assert (out / "report.json").exists()
        assert (out / "report.sarif").exists()

    def test_repeated_format_flags_are_honoured(self, tmp_path):
        out = tmp_path / "o"
        (tmp_path / "clean.py").write_text("print('ok')\n")
        runner.invoke(
            app,
            ["audit", str(tmp_path), "--out", str(out), "--format", "json", "--format", "sarif"],
        )
        assert (out / "report.json").exists()
        assert (out / "report.sarif").exists()

    def test_unknown_format_is_a_usage_error_rather_than_silently_writing_nothing(self, tmp_path):
        """Regression: `scan --format json,html` matched no branch and wrote
        zero reports, silently, exit 0."""
        (tmp_path / "clean.py").write_text("print('ok')\n")
        result = runner.invoke(
            app, ["audit", str(tmp_path), "--out", str(tmp_path / "o"), "--format", "nonsense"]
        )
        assert result.exit_code >= 2


class TestAuditReportContents:
    def test_json_report_score_reflects_findings(self, tmp_path):
        (tmp_path / "key.pem").write_text(PRIVATE_KEY_FILE)
        out = tmp_path / "o"
        runner.invoke(app, ["audit", str(tmp_path), "--out", str(out), "--format", "json"])
        data = json.loads((out / "report.json").read_text())
        assert data["summary"]["overall_score"] < 100.0
