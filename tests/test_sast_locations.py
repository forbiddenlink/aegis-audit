"""The SAST scanner must report locations a SARIF consumer can use.

Line numbers were computed and then discarded into a human-readable `evidence`
string ("File: x.py:12 - Match: ..."), so nothing downstream could anchor an
alert to a line. Paths were emitted absolute, which matches nothing in a
GitHub repo tree.
"""

from aegisaudit.sast.scanner import SASTScanner


class TestFindingsCarryLineNumbers:
    def test_secret_finding_reports_the_line_it_was_found_on(self, tmp_path):
        target = tmp_path / "config.py"
        target.write_text("# line 1\n# line 2\nKEY = 'AKIAIOSFODNN7EXAMPLE'\n")

        findings = SASTScanner().scan(tmp_path).findings

        secret = next(f for f in findings if "secret" in f.id)
        assert secret.line == 3

    def test_static_analysis_finding_reports_its_line(self, tmp_path):
        target = tmp_path / "danger.py"
        target.write_text("x = 1\ny = 2\neval('1+1')\n")

        findings = SASTScanner().scan(tmp_path).findings

        evil = next(f for f in findings if f.id == "eval-detected")
        assert evil.line == 3


class TestPathsAreRelativeToScanRoot:
    def test_finding_url_is_relative_to_the_scanned_directory(self, tmp_path):
        (tmp_path / "src").mkdir()
        target = tmp_path / "src" / "config.py"
        target.write_text("KEY = 'AKIAIOSFODNN7EXAMPLE'\n")

        findings = SASTScanner().scan(tmp_path).findings

        secret = next(f for f in findings if "secret" in f.id)
        assert secret.url == "src/config.py"
        assert not secret.url.startswith("/")
