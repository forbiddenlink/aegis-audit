import os
from pathlib import Path
from aegisaudit.models import ScanResult
from aegisaudit.sast.ignore import DEFAULT_EXCLUDES, IGNORE_FILENAME, IgnoreRules
from aegisaudit.sast.secrets import scan_file_for_secrets
from aegisaudit.sast.static import scan_python_ast
from aegisaudit.sast.dependencies import check_python_dependencies, check_node_dependencies
from aegisaudit.scoring import calculate_score

# Files larger than this are skipped: the secret/AST scan reads the whole file
# into memory, so a committed multi-GB binary or dataset would spike memory and
# wall-clock with no security signal to gain.
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB


class SASTScanner:
    def __init__(self) -> None:
        pass

    def scan(self, root_path: Path) -> ScanResult:
        all_findings = []
        ignore_rules = IgnoreRules.from_root(root_path)

        # 1. Dependency Checks (Root level primarily)
        all_findings.extend(check_python_dependencies(root_path))
        all_findings.extend(check_node_dependencies(root_path))

        # 2. Walk files
        for root, dirs, files in os.walk(root_path):
            # Prune noise directories in-place so os.walk does not descend into
            # them at all.
            dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDES]

            for file in files:
                file_path = Path(root) / file

                # Report locations relative to the scan root. An absolute path
                # (e.g. /home/runner/work/repo/repo/src/x.py in CI) matches
                # nothing in a GitHub repo tree, so SARIF alerts cannot be
                # attached to a file.
                display_path = file_path.relative_to(root_path).as_posix()

                # The ignore file names the very patterns it suppresses, so
                # scanning it reports back everything the user just excluded.
                if display_path == IGNORE_FILENAME:
                    continue

                if ignore_rules.matches(display_path):
                    continue

                # Skip files too large to scan economically (see MAX_FILE_BYTES).
                try:
                    if file_path.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue  # broken symlink, race, permissions

                # Secrets Scan (All text files)
                all_findings.extend(scan_file_for_secrets(file_path, display_path))

                # Static Analysis (Python)
                if file_path.suffix == ".py":
                    all_findings.extend(scan_python_ast(file_path, display_path))

        # Post-process findings to filter duplicates. The line is part of the
        # key: two eval() calls on different lines of the same file are two real
        # findings, and keying on (id, url) alone silently dropped the second,
        # undercounting issues and inflating the score.
        unique = {}
        for f in all_findings:
            key = (f.id, f.url, f.line)
            if key not in unique:
                unique[key] = f

        all_findings = list(unique.values())

        summary = calculate_score(all_findings)

        return ScanResult(
            targets=[str(root_path)], findings=all_findings, summary=summary, config_snapshot={}
        )
