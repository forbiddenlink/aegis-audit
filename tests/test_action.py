"""The composite GitHub Action must stay in step with the CLI it wraps."""

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml
from typer.testing import CliRunner

from aegisaudit.cli import app

ROOT = Path(__file__).resolve().parent.parent
ACTION = yaml.safe_load((ROOT / "action.yml").read_text())
RUN_STEPS = [s for s in ACTION["runs"]["steps"] if "run" in s]


def test_is_a_composite_action_with_the_documented_inputs():
    assert ACTION["runs"]["using"] == "composite"
    assert {"mode", "target", "fail-on", "fail-under", "baseline", "upload-sarif"} <= set(
        ACTION["inputs"]
    )


def test_inputs_are_never_interpolated_into_shell_scripts():
    """`${{ inputs.x }}` inside `run:` is script injection; pass them via env."""
    for step in RUN_STEPS:
        assert "${{ inputs." not in step["run"], step.get("name")


def test_third_party_actions_are_pinned_to_a_full_sha():
    for step in ACTION["runs"]["steps"]:
        if "uses" in step:
            assert re.search(r"@[0-9a-f]{40}$", step["uses"]), step["uses"]


def test_every_flag_the_action_passes_exists_on_the_cli():
    script = next(s["run"] for s in RUN_STEPS if s.get("id") == "aegis")
    flags = set(re.findall(r"(--[a-z][a-z-]+)", script))
    runner = CliRunner()
    help_text = (
        runner.invoke(app, ["scan", "--help"]).output
        + runner.invoke(app, ["audit", "--help"]).output
    )
    # Rich wraps long option names; collapse whitespace and box characters.
    help_text = re.sub(r"[\s│╭╮╰╯─]+", "", help_text)
    for flag in flags:
        assert flag.replace("-", "") in help_text.replace("-", ""), flag


def test_summary_script_renders_score_and_top_findings(tmp_path):
    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(
            {
                "status": "fail",
                "severity": "high",
                "overall_score": 71.5,
                "finding_count": 2,
                "failed_target_count": 0,
                "counts_by_severity": {"high": 1, "low": 1},
                "top_findings": [
                    {
                        "id": "SEC-1",
                        "severity": "high",
                        "title": "Hardcoded key",
                        "url": None,
                        "line": 7,
                    }
                ],
            }
        )
    )
    out = subprocess.run(
        [sys.executable, str(ROOT / "action" / "summary.py"), str(summary)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "71.5" in out
    assert "Hardcoded key" in out
    assert "high" in out


def test_summary_script_degrades_when_no_report_was_written(tmp_path):
    result = subprocess.run(
        [sys.executable, str(ROOT / "action" / "summary.py"), str(tmp_path / "missing.json")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "no summary" in result.stdout.lower()
