"""Subresource Integrity: third-party scripts and stylesheets only."""

from aegisaudit.checks.sri import check_sri
from aegisaudit.config import AegisConfig
from aegisaudit.models import ScanArtifact

CFG = AegisConfig()


def _artifact(body: str, url: str = "https://example.com/app") -> ScanArtifact:
    return ScanArtifact(
        url=url,
        final_url=url,
        status_code=200,
        headers={},
        cookies={},
        body_snippet=body,
        content_type="text/html",
    )


def test_external_script_without_integrity():
    art = _artifact('<script src="https://cdn.jquery.com/jquery.js"></script>')
    assert any(f.id == "missing-sri" for f in check_sri(art, CFG))


def test_external_stylesheet_without_integrity():
    art = _artifact('<link rel="stylesheet" href="https://cdn.example.net/app.css">')
    findings = check_sri(art, CFG)
    assert any(f.id == "missing-sri" and "stylesheet" in f.description for f in findings)


def test_same_origin_script_is_not_flagged():
    art = _artifact('<script src="https://example.com/app.js"></script>')
    assert check_sri(art, CFG) == []


def test_relative_script_is_not_flagged():
    art = _artifact('<script src="/static/app.js"></script>')
    assert check_sri(art, CFG) == []


def test_integrity_before_src_is_accepted():
    art = _artifact(
        '<script integrity="sha384-abc" src="https://cdn.jquery.com/jquery.js"></script>'
    )
    assert check_sri(art, CFG) == []


def test_stylesheet_with_integrity_is_clean():
    art = _artifact(
        '<link rel="stylesheet" href="https://cdn.example.net/app.css" integrity="sha384-abc">'
    )
    assert check_sri(art, CFG) == []


def test_non_html_is_skipped():
    art = ScanArtifact(
        url="https://example.com/app.json",
        final_url="https://example.com/app.json",
        status_code=200,
        headers={},
        cookies={},
        body_snippet='<script src="https://cdn.jquery.com/jquery.js"></script>',
        content_type="application/json",
    )
    assert check_sri(art, CFG) == []
