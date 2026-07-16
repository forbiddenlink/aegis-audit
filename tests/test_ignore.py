"""Suppression via .aegisignore.

Without a suppression mechanism the tool is unusable on any repo that contains
security test fixtures -- including its own. `aegis audit .` on this repo
reported 8 findings, every one of them a deliberately fake key in tests/.
A secret scanner that cannot be told "this one is a fixture" trains its users
to ignore it, which is worse than not running it.

Follows the gitignore-style convention used by .gitleaksignore/.semgrepignore.
"""

from aegisaudit.sast.scanner import SASTScanner

AWS_KEY = "KEY = 'AKIAIOSFODNN7EXAMPLE'\n"


def scan(path):
    return SASTScanner().scan(path).findings


class TestAegisIgnore:
    def test_findings_are_reported_when_no_ignore_file_exists(self, tmp_path):
        (tmp_path / "app.py").write_text(AWS_KEY)
        assert len(scan(tmp_path)) == 1

    def test_exact_path_is_ignored(self, tmp_path):
        (tmp_path / "app.py").write_text(AWS_KEY)
        (tmp_path / ".aegisignore").write_text("app.py\n")
        assert scan(tmp_path) == []

    def test_glob_pattern_is_ignored(self, tmp_path):
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_keys.py").write_text(AWS_KEY)
        (tmp_path / ".aegisignore").write_text("tests/*\n")
        assert scan(tmp_path) == []

    def test_directory_prefix_pattern_is_ignored_recursively(self, tmp_path):
        (tmp_path / "tests" / "deep").mkdir(parents=True)
        (tmp_path / "tests" / "deep" / "fixtures.py").write_text(AWS_KEY)
        (tmp_path / ".aegisignore").write_text("tests/\n")
        assert scan(tmp_path) == []

    def test_non_matching_pattern_does_not_suppress(self, tmp_path):
        (tmp_path / "app.py").write_text(AWS_KEY)
        (tmp_path / ".aegisignore").write_text("docs/*\n")
        assert len(scan(tmp_path)) == 1

    def test_comments_and_blank_lines_are_skipped(self, tmp_path):
        (tmp_path / "app.py").write_text(AWS_KEY)
        (tmp_path / ".aegisignore").write_text("# a comment\n\napp.py\n")
        assert scan(tmp_path) == []

    def test_the_ignore_file_itself_is_never_scanned(self, tmp_path):
        """A suppression file naturally names the things it suppresses, so
        scanning it reports the very patterns the user just excluded."""
        (tmp_path / ".aegisignore").write_text(f"# suppress the sample key {AWS_KEY}\napp.py\n")
        (tmp_path / "app.py").write_text(AWS_KEY)
        assert scan(tmp_path) == []

    def test_ignoring_everything_does_not_crash_scoring(self, tmp_path):
        (tmp_path / "app.py").write_text(AWS_KEY)
        (tmp_path / ".aegisignore").write_text("*\n")
        result = SASTScanner().scan(tmp_path)
        assert result.findings == []
        assert result.summary.overall_score == 100.0
