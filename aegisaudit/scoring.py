"""Scoring engine.

Model: a deduction pool. Start at 100, subtract a fixed penalty per finding,
floor at 0. Category subscores are reported alongside for triage, but they are
NOT averaged into the overall score.

Why a pool and not a weighted average of per-category scores (the previous
model): under a weighted average, every category that was never checked still
sat at 100.0 and still carried its full weight, donating free points. For an
HTTPS target, `cookies`, `csp` and `security.txt` could never be deducted at
all, which put a hard floor of 25/100 under every possible scan. Excluding
absent categories from the denominator instead breaks monotonicity: a lone
CRITICAL scores 0, and adding an unrelated LOW finding would *raise* it to ~32.
A pool is monotonic by construction -- another finding can only ever lower the
score -- and has no unreachable weight.
"""

from typing import Dict, List

from aegisaudit.models import Finding, ScanSummary, Severity

# Every tag that identifies which part of a security posture a finding belongs
# to. Tags not listed here (e.g. "aws", "sast", "outdated") are descriptive
# markers, not categories -- a finding only needs ONE tag from this table.
#
# A finding whose tags match nothing here is a bug, not a zero-cost finding.
# See resolve_category().
TAG_TO_CATEGORY: Dict[str, str] = {
    # Response headers. CSP is a header; it is not a separate category. It used
    # to be, but findings were tagged ["headers", "csp"] and the resolver took
    # the first match, so the csp category could never receive a deduction and
    # silently donated a free 5% to every score.
    "headers": "headers",
    "hsts": "headers",
    "csp": "headers",
    "cookies": "cookies",
    "https": "https",
    "mixed-content": "https",
    "tls": "tls",
    "crypto": "tls",
    "dns": "dns",
    "supply-chain": "supply-chain",
    "sri": "supply-chain",
    "security.txt": "security.txt",
    # Below this line: categories that findings emitted but that had no scoring
    # category at all, so every one of them cost zero. `aegis audit` emitted
    # only these, which is why a SAST run could only ever return 100.0/100.
    "exposure": "exposure",
    "secrets": "secrets",
    "dependency": "dependencies",
    "python-ast": "code",
    "pii": "pii",
    "info-leak": "info-leak",
}

# When a finding carries several category tags, the most security-relevant one
# wins. Resolution must be deterministic and must not depend on the order the
# check module happened to list its tags.
CATEGORY_PRIORITY: List[str] = [
    "secrets",
    "exposure",
    "dependencies",
    "code",
    "tls",
    "https",
    "headers",
    "cookies",
    "supply-chain",
    "dns",
    "security.txt",
    "pii",
    "info-leak",
]

# Penalty per finding, in points off a 100-point pool.
#
# CRITICAL is disqualifying by design: a live private key or an exposed .git is
# not worth "40 points", it means the posture has failed. INFO is
# observational and costs nothing.
PENALTIES: Dict[Severity, float] = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 40.0,
    Severity.MEDIUM: 15.0,
    Severity.LOW: 5.0,
    Severity.INFO: 0.0,
}


def resolve_category(finding: Finding) -> str:
    """Return the scoring category for a finding.

    Raises ValueError if no tag maps to a category. This is deliberate. The
    previous implementation skipped unmapped findings silently, which meant a
    CRITICAL hardcoded private key contributed nothing and the tool reported
    100.0/100 while printing that same CRITICAL to the console. A scoring
    engine that discards input it does not understand cannot be trusted, so an
    unmapped tag is a hard error at scan time rather than a quietly perfect
    score.
    """
    matched = {TAG_TO_CATEGORY[tag] for tag in finding.tags if tag in TAG_TO_CATEGORY}

    if not matched:
        raise ValueError(
            f"Finding {finding.id!r} has uncategorized tags {finding.tags!r}: no tag maps to a "
            f"scoring category. Map one of its tags in TAG_TO_CATEGORY (aegisaudit/scoring.py). "
            f"Findings must never be silently unscored."
        )

    for category in CATEGORY_PRIORITY:
        if category in matched:
            return category

    # A tag mapped to a category absent from CATEGORY_PRIORITY: the two tables
    # have drifted apart.
    raise ValueError(
        f"Finding {finding.id!r} resolved to unknown category {matched!r}, which is absent "
        f"from CATEGORY_PRIORITY (aegisaudit/scoring.py)."
    )


def calculate_score(findings: List[Finding]) -> ScanSummary:
    """Score a set of findings on a 0-100 deduction pool."""
    # str keys (Severity is a str enum) so this matches ScanSummary's
    # dict[str, int]; indexing with a Severity member still works via str
    # equality.
    counts: Dict[str, int] = {severity.value: 0 for severity in Severity}
    deductions: Dict[str, float] = {}

    for finding in findings:
        counts[finding.severity] += 1
        category = resolve_category(finding)
        deductions[category] = deductions.get(category, 0.0) + PENALTIES[finding.severity]

    overall = max(0.0, 100.0 - sum(deductions.values()))

    # Subscores are per-category health, for triage only. Categories with no
    # findings are omitted rather than reported as 100 -- "we found nothing"
    # and "we did not check" are different claims, and conflating them is what
    # produced the free points in the first place.
    category_scores = {
        category: max(0.0, 100.0 - deduction) for category, deduction in sorted(deductions.items())
    }

    return ScanSummary(
        counts_by_severity=counts,
        category_scores=category_scores,
        overall_score=overall,
    )
