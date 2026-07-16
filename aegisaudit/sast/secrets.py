import re
from pathlib import Path
from typing import List, Optional
from aegisaudit.models import Finding, Severity

# Reuse some patterns from checks/secrets.py but optimized for file scanning
PATTERNS = {
    "AWS Access Key": {
        # Anchored on the AWS key-ID prefixes. The previous pattern was a bare
        # [A-Z0-9]{20}, which matched any 20-character uppercase alphanumeric
        # run: scanning this repo reported a hash in uv.lock as a HIGH severity
        # AWS key. An access key ID is identifiable precisely BY its prefix.
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
        "regex": r"(?<![A-Z0-9])(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])",
        "severity": Severity.HIGH,
        "tags": ["secrets", "aws"],
    },
    "Google API Key": {
        "regex": r"AIza[0-9A-Za-z-_]{35}",
        "severity": Severity.MEDIUM,
        "tags": ["secrets", "google"],
    },
    "Generic Private Key": {
        "regex": r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "tags": ["secrets", "crypto"],
    },
    "Slack Token": {
        "regex": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        "severity": Severity.HIGH,
        "tags": ["secrets", "slack"],
    },
}


def scan_file_for_secrets(path: Path, display_path: Optional[str] = None) -> List[Finding]:
    """Scan one file for hardcoded secrets.

    display_path is the location reported on the finding. It should be relative
    to the scan root so SARIF consumers can match it against a repo tree.
    """
    findings = []
    location = display_path if display_path is not None else str(path)
    try:
        # Read file safely
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return []  # Skip binary files

        for name, rule in PATTERNS.items():
            matches = re.finditer(rule["regex"], content)
            for m in matches:
                # Get line number
                line_no = content[: m.start()].count("\n") + 1

                findings.append(
                    Finding(
                        id=f"sast-secret-{name.lower().replace(' ', '-')}",
                        severity=rule["severity"],
                        title=f"Hardcoded {name}",
                        description=f"Found potential {name} in source code.",
                        evidence=f"File: {path.name}:{line_no} - Match: {m.group(0)[:10]}...",
                        url=location,
                        line=line_no,
                        remediation="Use environment variables or a secret manager. Do not commit secrets.",
                        tags=rule["tags"] + ["sast"],
                    )
                )
                # Stop after one match per type per file to reduce noise
                break

    except Exception:
        pass

    return findings
