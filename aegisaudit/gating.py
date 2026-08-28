"""CI gating policy: turning a scan result into a pass/fail decision.

Kept separate from the CLI so the policy is testable on its own, and so the
"should this fail the build" question has exactly one answer in one place.

Exit code convention follows semgrep and osv-scanner, the dominant one among
security scanners:
    0    clean, or findings present but below the gate
    1    findings tripped the gate
    >=2  tool/usage error

That distinction matters: CI must be able to tell "the scanner found a leaked
key" from "the scanner crashed". Tools that collapse both into exit 1
(gitleaks, pip-audit) make a broken scan look like a clean one.
"""

from aegisaudit.models import ScanResult, Severity

VALID_FORMATS: set[str] = {"json", "sarif", "html", "summary"}

# Ascending. Used to resolve "--fail-on high" to "high or worse".
SEVERITY_ORDER: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def parse_formats(values: list[str]) -> set[str]:
    """Resolve --format values into a set of report formats.

    Accepts repeated flags (--format json --format sarif) and comma-separated
    values (--format json,sarif). Only `audit` handled the comma form; `scan`
    did not, so `scan --format json,html` matched no branch and silently wrote
    zero reports while still exiting 0. An unrecognised format is an error
    here rather than a silent no-op.
    """
    formats: set[str] = set()
    for value in values:
        for part in value.split(","):
            part = part.strip().lower()
            if not part:
                continue
            if part == "all":
                formats.update(VALID_FORMATS)
            elif part in VALID_FORMATS:
                formats.add(part)
            else:
                valid = ", ".join(sorted(VALID_FORMATS | {"all"}))
                raise ValueError(f"Unknown format {part!r}. Valid formats: {valid}.")
    if not formats:
        raise ValueError("No output format selected.")
    return formats


def parse_severity(value: str) -> Severity:
    """Resolve a --fail-on value to a Severity."""
    try:
        return Severity(value.strip().lower())
    except ValueError:
        valid = ", ".join(s.value for s in SEVERITY_ORDER)
        raise ValueError(f"Unknown severity {value!r}. Valid severities: {valid}.") from None


def findings_at_or_above(result: ScanResult, threshold: Severity) -> int:
    """Count findings at or above a severity floor."""
    floor = SEVERITY_ORDER.index(threshold)
    return sum(1 for f in result.findings if SEVERITY_ORDER.index(f.severity) >= floor)


def gate_failure_reason(
    result: ScanResult,
    fail_on: Severity | None = None,
    fail_under: float | None = None,
) -> str | None:
    """Return why the build should fail, or None if it passes.

    Gating is opt-in: with neither option set this always returns None, so
    reporting stays non-blocking by default (matching `semgrep scan` and
    `trivy`).
    """
    if fail_on is not None:
        count = findings_at_or_above(result, fail_on)
        if count:
            return f"{count} finding(s) at or above severity '{fail_on.value}' (--fail-on)."

    if fail_under is not None and result.summary.overall_score < fail_under:
        return (
            f"Score {result.summary.overall_score:.1f} is below the required "
            f"{fail_under:.1f} (--fail-under)."
        )

    return None
