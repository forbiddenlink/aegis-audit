"""Suppression rules for source scanning (.aegisignore).

Every credible secret scanner needs one: repositories legitimately contain
fake keys in test fixtures, documentation examples, and vendored samples. With
no way to suppress them, users learn to ignore the tool's output entirely.

Format follows the .gitleaksignore / .semgrepignore convention:
    - one glob per line, relative to the scan root, POSIX separators
    - '#' starts a comment; blank lines ignored
    - a trailing '/' (or a bare directory name) ignores that directory's whole
      subtree
"""

from pathlib import Path, PurePosixPath
from typing import List

IGNORE_FILENAME = ".aegisignore"

# Always skipped: scanning these produces noise, never signal.
DEFAULT_EXCLUDES = (
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "htmlcov",
    "dist",
    "build",
)


class IgnoreRules:
    """Decides whether a path is excluded from scanning."""

    def __init__(self, patterns: List[str]):
        self.patterns = patterns

    @classmethod
    def from_root(cls, root: Path) -> "IgnoreRules":
        ignore_file = root / IGNORE_FILENAME
        if not ignore_file.is_file():
            return cls([])
        # A malformed (non-UTF-8) ignore file must not crash the whole scan: an
        # uncaught exception here exits 1, colliding with the "gate tripped"
        # exit code the CLI treats as a real finding. Degrade to no rules.
        try:
            text = ignore_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            import sys

            print(
                f"Warning: could not read {IGNORE_FILENAME} (not UTF-8?); "
                "proceeding with no ignore rules.",
                file=sys.stderr,
            )
            return cls([])
        return cls(cls._parse(text))

    @staticmethod
    def _parse(text: str) -> List[str]:
        patterns = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
        return patterns

    def matches(self, relative_path: str) -> bool:
        """True if `relative_path` (POSIX, relative to the scan root) is
        suppressed."""
        for pattern in self.patterns:
            if pattern.endswith("/"):
                # "tests/" suppresses the whole subtree.
                if relative_path.startswith(pattern) or relative_path == pattern.rstrip("/"):
                    return True
                continue

            # PurePosixPath.match is pathname-aware: `*` does not cross a path
            # separator, so `src/*.py` matches src/app.py but not
            # src/deep/nested.py. fnmatch let `*` span `/` and suppressed nested
            # files the user never excluded.
            if PurePosixPath(relative_path).match(pattern):
                return True

            # A bare directory name ("tests") also suppresses its subtree, which
            # is what users expect from gitignore-style syntax.
            if relative_path.startswith(f"{pattern}/"):
                return True

        return False
