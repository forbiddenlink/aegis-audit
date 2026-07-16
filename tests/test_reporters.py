import pytest
import json
from aegisaudit.models import ScanResult, ScanSummary, Finding, Severity
from aegisaudit.reporters.json_report import generate_json_report
from aegisaudit.reporters.sarif_report import generate_sarif_report
from aegisaudit.reporters.html_report import generate_html_report


@pytest.fixture
def sample_scan_result():
    """Create a sample scan result for testing."""
    return ScanResult(
        tool_version="0.1.0",
        targets=["https://example.com"],
        findings=[
            Finding(
                id="missing-hsts",
                severity=Severity.HIGH,
                title="Missing HSTS Header",
                description="HTTP Strict Transport Security header is missing.",
                url="https://example.com",
                remediation="Add 'Strict-Transport-Security' header.",
                tags=["headers", "hsts"],
            ),
            Finding(
                id="missing-csp",
                severity=Severity.MEDIUM,
                title="Missing Content Security Policy",
                description="CSP header is missing.",
                url="https://example.com",
                remediation="Implement CSP.",
                tags=["headers", "csp"],
            ),
            Finding(
                id="info-leak",
                severity=Severity.LOW,
                title="Server Header Disclosure",
                description="Server header reveals technology details.",
                url="https://example.com",
                remediation="Suppress server header.",
                tags=["headers", "info-leak"],
            ),
        ],
        summary=ScanSummary(
            counts_by_severity={"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0},
            overall_score=65.0,
        ),
    )


class TestJSONReport:
    """Tests for JSON report generation."""

    def test_json_report_created(self, sample_scan_result, tmp_path):
        """JSON report file should be created."""
        output_file = tmp_path / "report.json"
        generate_json_report(sample_scan_result, output_file)

        assert output_file.exists()

    def test_json_report_valid_json(self, sample_scan_result, tmp_path):
        """JSON report should be valid JSON."""
        output_file = tmp_path / "report.json"
        generate_json_report(sample_scan_result, output_file)

        with open(output_file) as f:
            data = json.load(f)

        assert isinstance(data, dict)

    def test_json_report_contains_findings(self, sample_scan_result, tmp_path):
        """JSON report should contain all findings."""
        output_file = tmp_path / "report.json"
        generate_json_report(sample_scan_result, output_file)

        with open(output_file) as f:
            data = json.load(f)

        assert "findings" in data
        assert len(data["findings"]) == 3

    def test_json_report_contains_summary(self, sample_scan_result, tmp_path):
        """JSON report should contain summary."""
        output_file = tmp_path / "report.json"
        generate_json_report(sample_scan_result, output_file)

        with open(output_file) as f:
            data = json.load(f)

        assert "summary" in data
        assert sum(data["summary"]["counts_by_severity"].values()) == 3
        assert abs(data["summary"]["overall_score"] - 65.0) < 0.01


class TestSARIFReport:
    """Tests for SARIF report generation."""

    def test_sarif_report_created(self, sample_scan_result, tmp_path):
        """SARIF report file should be created."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)

        assert output_file.exists()

    def test_sarif_report_valid_json(self, sample_scan_result, tmp_path):
        """SARIF report should be valid JSON."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)

        with open(output_file) as f:
            data = json.load(f)

        assert isinstance(data, dict)

    def test_sarif_report_version(self, sample_scan_result, tmp_path):
        """SARIF report should have correct version."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)

        with open(output_file) as f:
            data = json.load(f)

        assert "version" in data
        assert data["version"] == "2.1.0"

    def test_sarif_report_contains_runs(self, sample_scan_result, tmp_path):
        """SARIF report should contain runs array."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)

        with open(output_file) as f:
            data = json.load(f)

        assert "runs" in data
        assert len(data["runs"]) >= 1

    def test_sarif_report_contains_results(self, sample_scan_result, tmp_path):
        """SARIF report should contain results."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)

        with open(output_file) as f:
            data = json.load(f)

        results = data["runs"][0]["results"]
        assert len(results) == 3

    def test_sarif_severity_mapping(self, sample_scan_result, tmp_path):
        """SARIF report should map severity levels correctly."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)

        with open(output_file) as f:
            data = json.load(f)

        results = data["runs"][0]["results"]
        # Implementation: HIGH -> error, INFO -> note, everything else -> warning
        levels = [r["level"] for r in results]
        assert "error" in levels  # HIGH finding
        assert "warning" in levels  # MEDIUM and LOW findings both map to warning


class TestHTMLReport:
    """Tests for HTML report generation."""

    def test_html_report_created(self, sample_scan_result, tmp_path):
        """HTML report file should be created."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)

        assert output_file.exists()

    def test_html_report_not_empty(self, sample_scan_result, tmp_path):
        """HTML report should have content."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)

        content = output_file.read_text()
        assert len(content) > 100

    def test_html_report_contains_title(self, sample_scan_result, tmp_path):
        """HTML report should contain title."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)

        content = output_file.read_text()
        assert "<title>" in content
        assert "AegisAudit" in content or "Report" in content

    def test_html_report_contains_findings(self, sample_scan_result, tmp_path):
        """HTML report should display findings."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)

        content = output_file.read_text()
        assert "Missing HSTS" in content
        assert "Content Security Policy" in content

    def test_html_report_contains_score(self, sample_scan_result, tmp_path):
        """HTML report should display overall score."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)

        content = output_file.read_text()
        assert "65" in content or "score" in content.lower()

    def test_html_report_valid_html(self, sample_scan_result, tmp_path):
        """HTML report should have basic HTML structure."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)

        content = output_file.read_text()
        assert "<html" in content.lower()
        assert "</html>" in content.lower()
        assert "<body" in content.lower()
        assert "</body>" in content.lower()

    def test_html_report_escapes_finding_content(self, tmp_path):
        """Finding text comes from scanned pages (script srcs, matched
        strings), so it is attacker-controlled. Rendered without escaping, a
        crafted page turns the report itself into stored XSS when opened."""
        result = ScanResult(
            tool_version="0.1.0",
            targets=["https://x.test"],
            findings=[
                Finding(
                    id="xss-probe",
                    severity=Severity.HIGH,
                    title="<script>alert('title')</script>",
                    description="<img src=x onerror=alert('desc')>",
                    url="https://x.test/<script>alert('url')</script>",
                    evidence="<script>alert('evidence')</script>",
                )
            ],
            summary=ScanSummary(counts_by_severity={"high": 1}, overall_score=0.0),
        )
        output_file = tmp_path / "report.html"
        generate_html_report(result, output_file)
        content = output_file.read_text()
        # No live injected tags: the payload's angle brackets must be escaped so
        # neither a <script> nor an <img onerror> element is created.
        assert "<script>alert(" not in content
        assert "<img src=x" not in content
        # The escaped form is present, proving the content still rendered.
        assert "&lt;script&gt;alert(" in content
        assert "&lt;img src=x onerror=alert(" in content

    def test_html_report_styles_and_counts_critical(self, tmp_path):
        """Critical is the most severe class; it must have a styled badge and be
        counted in the summary. The per-finding badge must use the severity
        value ('critical'), not the enum's repr ('Severity.CRITICAL'), or the
        CSS never matches and the badge renders unstyled."""
        result = ScanResult(
            tool_version="0.1.0",
            targets=["https://x.test"],
            findings=[
                Finding(
                    id="pk",
                    severity=Severity.CRITICAL,
                    title="Private key",
                    description="d",
                    url="https://x.test",
                )
            ],
            summary=ScanSummary(counts_by_severity={"critical": 1}, overall_score=0.0),
        )
        output_file = tmp_path / "report.html"
        generate_html_report(result, output_file)
        content = output_file.read_text()
        assert 'class="severity critical"' in content
        assert "Severity.CRITICAL" not in content
        # A CSS rule for the critical badge exists.
        assert ".critical {" in content or ".critical{" in content


class TestReportWithNoFindings:
    """Tests for reports with clean scan results."""

    def test_empty_findings_json(self, tmp_path):
        """JSON report should handle empty findings."""
        clean_result = ScanResult(
            tool_version="0.1.0",
            targets=["https://secure-example.com"],
            findings=[],
            summary=ScanSummary(
                counts_by_severity={},
                overall_score=100.0,
            ),
        )

        output_file = tmp_path / "clean.json"
        generate_json_report(clean_result, output_file)

        with open(output_file) as f:
            data = json.load(f)

        assert sum(data["summary"]["counts_by_severity"].values()) == 0
        assert abs(data["summary"]["overall_score"] - 100.0) < 0.01

    def test_empty_findings_html(self, tmp_path):
        """HTML report should handle empty findings gracefully."""
        clean_result = ScanResult(
            tool_version="0.1.0",
            targets=["https://secure-example.com"],
            findings=[],
            summary=ScanSummary(
                counts_by_severity={},
                overall_score=100.0,
            ),
        )

        output_file = tmp_path / "clean.html"
        generate_html_report(clean_result, output_file)

        content = output_file.read_text()
        assert "100" in content or "perfect" in content.lower() or "no findings" in content.lower()
