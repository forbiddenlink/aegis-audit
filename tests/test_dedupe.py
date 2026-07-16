"""Finding de-duplication.

A scan of one target with --probe expands into several URLs on the same host
(the page, /.env, /.git/HEAD). Every check runs against every artifact, so
host-level findings -- missing HSTS, missing SPF, a leaked Server header --
were emitted once per probe URL. That tripled the noise and, worse, tripled the
score deduction: three copies of "missing HSTS" took 120 points off a
100-point pool.

De-duplication collapses identical findings on the same host while preserving
genuinely distinct ones (two different scripts each missing SRI) and findings
on different hosts (a multi-target scan where several sites lack HSTS).
"""

from aegisaudit.models import Finding, Severity
from aegisaudit.runner import dedupe_findings


def f(id: str, url: str, description: str = "d", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(id=id, severity=severity, title="t", description=description, url=url)


class TestDedupe:
    def test_same_finding_on_same_host_collapses(self):
        findings = [
            f("missing-hsts", "http://site.com/"),
            f("missing-hsts", "http://site.com/.env"),
            f("missing-hsts", "http://site.com/.git/HEAD"),
        ]
        assert len(dedupe_findings(findings)) == 1

    def test_same_id_on_different_hosts_is_kept(self):
        """Two different sites both missing HSTS are two findings, not one."""
        findings = [
            f("missing-hsts", "http://a.com/"),
            f("missing-hsts", "http://b.com/"),
        ]
        assert len(dedupe_findings(findings)) == 2

    def test_same_id_same_host_different_detail_is_kept(self):
        """Two external scripts each missing SRI are two real findings."""
        findings = [
            f("missing-sri", "http://site.com/", "script a.js has no integrity"),
            f("missing-sri", "http://site.com/", "script b.js has no integrity"),
        ]
        assert len(dedupe_findings(findings)) == 2

    def test_order_is_preserved(self):
        findings = [
            f("missing-csp", "http://site.com/"),
            f("missing-hsts", "http://site.com/"),
            f("missing-csp", "http://site.com/.env"),
        ]
        result = dedupe_findings(findings)
        assert [x.id for x in result] == ["missing-csp", "missing-hsts"]

    def test_empty(self):
        assert dedupe_findings([]) == []
