"""Finding model constraints.

SARIF regions are 1-indexed; a startLine of 0 or a negative line is invalid and
GitHub code scanning rejects it. The line field must therefore refuse
non-positive values at construction rather than let them reach the reporter.
"""

import pytest
from pydantic import ValidationError

from aegisaudit.models import Finding, Severity


def _finding(**kw):
    base = dict(id="x", severity=Severity.HIGH, title="t", description="d", url="u")
    base.update(kw)
    return Finding(**base)


class TestFindingLine:
    def test_none_is_allowed(self):
        assert _finding(line=None).line is None

    def test_positive_line_is_allowed(self):
        assert _finding(line=1).line == 1

    def test_zero_is_rejected(self):
        with pytest.raises(ValidationError):
            _finding(line=0)

    def test_negative_is_rejected(self):
        with pytest.raises(ValidationError):
            _finding(line=-5)
