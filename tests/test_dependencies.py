"""Dependency-scanner parsing tests.

The old code shelled out to `safety` (deprecated, login-gated, and absent from
this project's dependencies so it silently no-op'd) and parsed `npm audit` down
to bare severity counts with no CVE, package, or version -- two `pass` + TODO
branches. These tests drive pure parsers over the real JSON shapes emitted by
pip-audit and npm audit, so they run without the network or either tool present.
"""

from aegisaudit.models import Severity
from aegisaudit.sast.dependencies import parse_npm_audit, parse_pip_audit

# Trimmed but structurally real pip-audit --format json output.
PIP_AUDIT_JSON = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.19.1",
            "vulns": [
                {
                    "id": "PYSEC-2018-28",
                    "fix_versions": ["2.20.0"],
                    "aliases": ["GHSA-x84v-xcm2-53pg", "CVE-2018-18074"],
                    "description": "Requests before 2.20.0 sends the Authorization header on redirect.",
                }
            ],
        },
        {"name": "rich", "version": "13.0.0", "vulns": []},
    ],
    "fixes": [],
}

# Trimmed but structurally real npm audit --json output (npm v7+).
NPM_AUDIT_JSON = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "lodash": {
            "name": "lodash",
            "severity": "critical",
            "isDirect": True,
            "via": [
                {
                    "source": 1106918,
                    "name": "lodash",
                    "title": "Prototype Pollution in lodash",
                    "url": "https://github.com/advisories/GHSA-jf85-cpcp-j695",
                    "severity": "critical",
                    "cvss": {"score": 9.1},
                    "range": "<4.17.12",
                }
            ],
            "range": "<=4.17.4",
            "fixAvailable": {"name": "lodash", "version": "4.17.21"},
        },
        # A transitive entry: `via` holds a string pointing at another package,
        # not an advisory object. It must not create a junk finding.
        "some-wrapper": {
            "name": "some-wrapper",
            "severity": "critical",
            "isDirect": True,
            "via": ["lodash"],
            "range": "*",
            "fixAvailable": False,
        },
    },
    "metadata": {
        "vulnerabilities": {
            "info": 0,
            "low": 0,
            "moderate": 0,
            "high": 0,
            "critical": 1,
            "total": 1,
        }
    },
}


class TestPipAuditParsing:
    def test_reports_one_finding_per_vulnerability(self):
        findings = parse_pip_audit(PIP_AUDIT_JSON, "requirements.txt")
        assert len(findings) == 1

    def test_finding_names_the_package_and_advisory_id(self):
        f = parse_pip_audit(PIP_AUDIT_JSON, "requirements.txt")[0]
        assert "requests" in f.title
        assert "PYSEC-2018-28" in f.description

    def test_finding_surfaces_the_cve_and_fix_version(self):
        f = parse_pip_audit(PIP_AUDIT_JSON, "requirements.txt")[0]
        assert "CVE-2018-18074" in f.description
        assert "2.20.0" in f.remediation

    def test_finding_is_tagged_as_a_python_dependency(self):
        f = parse_pip_audit(PIP_AUDIT_JSON, "requirements.txt")[0]
        assert "dependency" in f.tags
        assert "python" in f.tags

    def test_clean_project_yields_no_findings(self):
        assert parse_pip_audit({"dependencies": [], "fixes": []}, "requirements.txt") == []


class TestNpmAuditParsing:
    def test_reports_the_direct_advisory(self):
        findings = parse_npm_audit(NPM_AUDIT_JSON, "package.json")
        assert any("lodash" in f.title for f in findings)

    def test_maps_npm_severity_to_our_severity(self):
        findings = parse_npm_audit(NPM_AUDIT_JSON, "package.json")
        lodash = next(f for f in findings if "lodash" in f.title)
        assert lodash.severity == Severity.CRITICAL

    def test_surfaces_the_advisory_title_and_url(self):
        f = next(f for f in parse_npm_audit(NPM_AUDIT_JSON, "package.json") if "lodash" in f.title)
        assert "Prototype Pollution" in f.description
        assert "GHSA-jf85-cpcp-j695" in f.description

    def test_transitive_string_via_does_not_create_a_finding(self):
        """`via: ["lodash"]` is a pointer, not an advisory. The advisory is
        already reported on lodash's own entry."""
        findings = parse_npm_audit(NPM_AUDIT_JSON, "package.json")
        assert not any("some-wrapper" in f.title for f in findings)

    def test_moderate_maps_to_medium(self):
        data = {
            "vulnerabilities": {
                "x": {
                    "name": "x",
                    "severity": "moderate",
                    "via": [{"title": "t", "url": "u", "severity": "moderate"}],
                }
            }
        }
        f = parse_npm_audit(data, "package.json")[0]
        assert f.severity == Severity.MEDIUM

    def test_clean_project_yields_no_findings(self):
        assert parse_npm_audit({"vulnerabilities": {}}, "package.json") == []
