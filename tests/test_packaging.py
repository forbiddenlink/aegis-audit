"""Tests that the package ships everything it needs at runtime.

These exist because `--format all` (the default for both commands) crashed with
FileNotFoundError for anyone who installed the package, since the Jinja2
template lived outside the package tree and was resolved by walking up from
__file__. It only ever worked from a git checkout. CI did not catch it: the
self-scan step is marked continue-on-error.
"""

from importlib.metadata import version
from importlib.resources import files

from aegisaudit.models import ScanResult, ScanSummary


class TestVersionHasOneSourceOfTruth:
    """The version was hardcoded in three places (pyproject, models.py,
    fetcher.py's User-Agent). Nothing kept them in step, so a release could
    stamp reports with a version that was never published."""

    def test_tool_version_matches_installed_package_version(self):
        assert ScanResult(targets=[]).tool_version == version("aegisaudit")

    def test_user_agent_matches_installed_package_version(self):
        from aegisaudit.fetcher import DEFAULT_USER_AGENT

        assert version("aegisaudit") in DEFAULT_USER_AGENT

    def test_user_agent_has_no_placeholder_url(self):
        from aegisaudit.fetcher import DEFAULT_USER_AGENT

        assert "your/aegisaudit" not in DEFAULT_USER_AGENT


class TestTemplateIsPackaged:
    def test_report_template_is_importable_as_package_data(self):
        """The template must resolve through the package, not a path relative to
        the repo checkout."""
        resource = files("aegisaudit").joinpath("templates", "report.html.j2")
        assert resource.is_file()

    def test_report_template_is_not_resolved_by_walking_out_of_the_package(self):
        """Guards the specific regression: `Path(__file__).parent.parent.parent`
        escapes the package and lands in site-packages/ once installed."""
        source = files("aegisaudit").joinpath("reporters", "html_report.py").read_text()
        assert "parent.parent.parent" not in source


class TestHtmlReportWorksFromAnyCwd:
    def test_generate_html_report_does_not_depend_on_cwd(self, tmp_path, monkeypatch):
        """An installed user runs from their own project, not from the aegis
        checkout."""
        from aegisaudit.reporters import generate_html_report

        monkeypatch.chdir(tmp_path)
        result = ScanResult(targets=["https://example.com"], findings=[], summary=ScanSummary())
        output = tmp_path / "report.html"

        generate_html_report(result, output)

        assert output.exists()
        assert output.stat().st_size > 0
