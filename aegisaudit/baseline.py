"""Baseline diffing: fail CI only on findings that are new since a baseline.

A scanner pointed at an existing codebase reports every pre-existing issue on
day one, which is too noisy to gate on -- so teams either never turn the gate on
or blanket-ignore it. A baseline records the findings that were present when it
was captured; a later scan then surfaces (and gates on) only what changed.

Two deliberate properties:

- Findings are identified by a fingerprint of (rule id, location, description),
  NOT the line number. Line numbers drift as unrelated code is added above a
  finding; keying on them would make every insertion look like a brand-new
  issue. The trade-off is that two findings of the same rule with the same
  description at the same path collapse to one baseline entry, which is the
  standard baseline behaviour.
- The baseline stores only fingerprints -- opaque hashes -- never the finding
  text or evidence. A secret detected in the source must not be copied into a
  file that gets committed to record that it was detected.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List, Set, Tuple

from aegisaudit.models import Finding, ScanResult
from aegisaudit.scoring import calculate_score

BASELINE_VERSION = 1


class BaselineError(ValueError):
    """The baseline file could not be read or is not a valid baseline."""


def fingerprint(finding: Finding) -> str:
    """A stable identity for a finding across scans.

    Uses the rule id, the location (file path for SAST, URL for a web scan),
    and the description. The line number and the evidence are intentionally
    excluded: the line drifts, and the evidence can contain a secret.
    """
    raw = "\0".join([finding.id, finding.url, finding.description])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def write_baseline(path: Path, findings: List[Finding], tool_version: str) -> int:
    """Write the fingerprints of ``findings`` to ``path``. Returns the count."""
    fingerprints = sorted({fingerprint(f) for f in findings})
    document = {
        "version": BASELINE_VERSION,
        "tool_version": tool_version,
        "fingerprints": fingerprints,
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return len(fingerprints)


def load_baseline(path: Path) -> Set[str]:
    """Load the fingerprint set from a baseline file.

    Raises BaselineError on a missing file, malformed JSON, or a document that
    is not a baseline, so the CLI can report a usage error (exit >=2) rather
    than silently treating every finding as new and failing an unrelated gate.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from None
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline {path} is not valid JSON: {exc}") from None
    if not isinstance(document, dict) or "fingerprints" not in document:
        raise BaselineError(f"baseline {path} is missing a 'fingerprints' list")
    fingerprints = document["fingerprints"]
    if not isinstance(fingerprints, list):
        raise BaselineError(f"baseline {path} 'fingerprints' is not a list")
    return set(fingerprints)


def apply_baseline(result: ScanResult, baseline: Set[str]) -> Tuple[ScanResult, int]:
    """Drop findings already present in ``baseline`` and rescore.

    Returns the filtered result and the number of findings suppressed. The
    score is recomputed over the surviving findings so a baselined scan reports
    the posture of what is *new*, which is what the gate then acts on.
    """
    surviving = [f for f in result.findings if fingerprint(f) not in baseline]
    suppressed = len(result.findings) - len(surviving)
    filtered = result.model_copy(
        update={"findings": surviving, "summary": calculate_score(surviving)}
    )
    return filtered, suppressed
