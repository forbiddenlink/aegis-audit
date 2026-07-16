"""Dependency vulnerability scanning.

Shells out to pip-audit (Python) and npm audit (Node) and turns their JSON into
findings. The parsing is split into pure functions so it is testable without the
network or either tool installed.

Replaces a shell-out to `safety`, whose `check` command is deprecated and whose
`scan` command is login-gated -- and which was never a declared dependency, so
it silently produced nothing. pip-audit (PyPA / Trail of Bits, Apache-2.0) is
the maintained, anonymous, free replacement.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from aegisaudit.models import Finding, Severity

# npm reports a real severity; pip-audit's sources (OSV / PyPI Advisory DB) do
# not attach a normalized one, so a Python dependency vuln with no severity is
# reported as MEDIUM rather than overclaimed as HIGH.
NPM_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_GHSA_IN_URL = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)


def _run(cmd: List[str], cwd: Path) -> Dict[str, Any]:
    """Run a scanner and return its parsed JSON, or {} if it could not run.

    pip-audit and npm audit exit non-zero (1) precisely when they FIND
    vulnerabilities, and still write their full JSON report to stdout. So a
    non-zero exit is not a failure -- only unparseable stdout (tool absent,
    crashed, network error) is, and that degrades to an empty result.
    """
    try:
        result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    except FileNotFoundError:
        return {}
    if not result.stdout:
        return {}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def parse_pip_audit(data: Dict[str, Any], location: str) -> List[Finding]:
    """Turn pip-audit --format json output into findings."""
    findings: List[Finding] = []
    for dep in data.get("dependencies", []):
        name = dep.get("name", "unknown")
        version = dep.get("version", "unknown")
        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id", "unknown")
            aliases = vuln.get("aliases", [])
            fixes = vuln.get("fix_versions", [])
            ids = ", ".join([vuln_id, *aliases])
            description = vuln.get("description", "").strip()

            remediation = (
                f"Upgrade {name} to {', '.join(fixes)} or later."
                if fixes
                else f"No fixed version is available yet for {name}; review the advisory."
            )
            findings.append(
                Finding(
                    id=f"vuln-pypi-{name}-{vuln_id}",
                    # pip-audit does not rate severity; report a neutral MEDIUM
                    # rather than overclaim.
                    severity=Severity.MEDIUM,
                    title=f"Vulnerable Python package: {name} {version}",
                    description=f"{ids}: {description}" if description else ids,
                    url=location,
                    remediation=remediation,
                    references=[a for a in aliases if a.upper().startswith(("CVE-", "GHSA-"))],
                    tags=["sast", "dependency", "python"],
                )
            )
    return findings


def parse_npm_audit(data: Dict[str, Any], location: str) -> List[Finding]:
    """Turn npm audit --json output (npm v7+) into findings."""
    findings: List[Finding] = []
    for pkg_name, entry in data.get("vulnerabilities", {}).items():
        for via in entry.get("via", []):
            # A string `via` is a pointer to another vulnerable package; that
            # package's own entry carries the real advisory, so skip it here to
            # avoid double-counting.
            if not isinstance(via, dict):
                continue

            severity = NPM_SEVERITY.get(via.get("severity", ""), Severity.MEDIUM)
            title = via.get("title", "Known vulnerability")
            url = via.get("url", "")
            ghsa = _GHSA_IN_URL.search(url)
            advisory_id = ghsa.group(0) if ghsa else via.get("source", "unknown")

            description = f"{title} ({advisory_id})."
            if via.get("range"):
                description += f" Affected range: {via['range']}."

            findings.append(
                Finding(
                    id=f"vuln-npm-{pkg_name}-{advisory_id}",
                    severity=severity,
                    title=f"Vulnerable npm package: {pkg_name}",
                    description=description,
                    url=location,
                    remediation="Run 'npm audit fix', or upgrade to a version outside the affected range.",
                    references=[url] if url else [],
                    tags=["sast", "dependency", "node"],
                )
            )
    return findings


def check_python_dependencies(path: Path) -> List[Finding]:
    requirements = path / "requirements.txt"
    if requirements.exists():
        # --no-deps + --disable-pip: scan exactly the pinned requirements
        # without building a throwaway venv. (Still queries OSV/PyPI over the
        # network for the advisory data itself.)
        cmd = [
            "pip-audit",
            "-r",
            "requirements.txt",
            "--format",
            "json",
            "--no-deps",
            "--disable-pip",
        ]
        location = "requirements.txt"
    elif (path / "pyproject.toml").exists():
        # Project-path mode resolves and scans pyproject.toml.
        cmd = ["pip-audit", "--format", "json"]
        location = "pyproject.toml"
    else:
        return []

    return parse_pip_audit(_run(cmd, path), location)


def check_node_dependencies(path: Path) -> List[Finding]:
    if not (path / "package.json").exists():
        return []
    return parse_npm_audit(_run(["npm", "audit", "--json"], path), "package.json")
