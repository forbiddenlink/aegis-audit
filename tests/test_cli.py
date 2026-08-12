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


class TestBaseline:
    """`--baseline` gates only on findings that are new since the baseline."""

    def _bad(self, tmp_path):
        (tmp_path / "bad.py").write_text(AWS_KEY_FILE)

    def test_update_baseline_writes_and_exits_0(self, tmp_path):
        self._bad(tmp_path)
        bl = tmp_path / "baseline.json"
        result = runner.invoke(
            app,
            ["audit", str(tmp_path), "--out", str(tmp_path / "o"), "--format", "json",
             "--baseline", str(bl), "--update-baseline"],
        )
        assert result.exit_code == 0
        assert bl.exists()
        # The finding's evidence (the fake AWS key) must not be persisted.
        assert "AKIAIOSFODNN7EXAMPLE" not in bl.read_text()

    def test_baselined_finding_no_longer_trips_gate(self, tmp_path):
        self._bad(tmp_path)
        bl = tmp_path / "baseline.json"
        out = str(tmp_path / "o")
        runner.invoke(
            app,
            ["audit", str(tmp_path), "--out", out, "--format", "json",
             "--baseline", str(bl), "--update-baseline"],
        )
        # Same finding, now baselined: --fail-on high must pass.
        result = runner.invoke(
            app,
            ["audit", str(tmp_path), "--out", out, "--format", "json",
             "--baseline", str(bl), "--fail-on", "high"],
        )
        assert result.exit_code == 0

    def test_new_finding_still_trips_gate_against_baseline(self, tmp_path):
        self._bad(tmp_path)
        bl = tmp_path / "baseline.json"
        out = str(tmp_path / "o")
        runner.invoke(
            app,
            ["audit", str(tmp_path), "--out", out, "--format", "json",
             "--baseline", str(bl), "--update-baseline"],
        )
        # Introduce a NEW finding not in the baseline.
        (tmp_path / "new.py").write_text(PRIVATE_KEY_FILE)
        result = runner.invoke(
            app,
            ["audit", str(tmp_path), "--out", out, "--format", "json",
             "--baseline", str(bl), "--fail-on", "high"],
        )
        assert result.exit_code == 1

    def test_update_baseline_without_path_is_usage_error(self, tmp_path):
        self._bad(tmp_path)
        result = runner.invoke(
            app,
            ["audit", str(tmp_path), "--out", str(tmp_path / "o"), "--update-baseline"],
        )
        assert result.exit_code >= 2

    def test_missing_baseline_file_is_usage_error(self, tmp_path):
        self._bad(tmp_path)
        result = runner.invoke(
            app,
            ["audit", str(tmp_path), "--out", str(tmp_path / "o"), "--format", "json",
             "--baseline", str(tmp_path / "nope.json")],
        )
        assert result.exit_code >= 2
