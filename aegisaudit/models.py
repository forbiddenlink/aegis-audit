from datetime import datetime
from enum import Enum
from importlib.metadata import PackageNotFoundError, version
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field


def _tool_version() -> str:
    """Read the version from installed package metadata.

    Single source of truth: pyproject.toml. The version used to be hardcoded
    here and again in fetcher.py's User-Agent, with nothing keeping either in
    step with the packaged version.
    """
    try:
        return version("aegisaudit")
    except PackageNotFoundError:  # running from a source tree, not installed
        return "0.0.0+unknown"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    description: str
    evidence: Optional[str] = None
    url: str
    # 1-indexed source line, when the finding refers to a location in a file.
    # SARIF consumers need this as a real region: without it, GitHub anchors the
    # alert to line 1 of the file rather than the offending line. A SARIF
    # startLine must be >= 1, so reject 0 or negative at construction rather
    # than emit an invalid region.
    line: Optional[int] = Field(default=None, ge=1)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class ScanArtifact(BaseModel):
    """Raw response data collected from a URL."""

    url: str
    final_url: str
    status_code: int
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body_snippet: str  # Truncated body for analysis
    content_type: str
    timestamp: datetime = Field(default_factory=datetime.now)


class ScanSummary(BaseModel):
    counts_by_severity: Dict[str, int] = Field(default_factory=dict)
    category_scores: Dict[str, float] = Field(default_factory=dict)
    overall_score: float = 0.0

    @property
    def total_findings(self) -> int:
        """Total number of findings across all severities."""
        return sum(self.counts_by_severity.values())


class ScanResult(BaseModel):
    tool_name: str = "AegisAudit"
    tool_version: str = Field(default_factory=_tool_version)
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None
    targets: List[str]
    findings: List[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    config_snapshot: Optional[Dict[str, Any]] = None
