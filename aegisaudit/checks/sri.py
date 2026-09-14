"""Subresource Integrity checks for third-party scripts and stylesheets."""

from typing import List
from urllib.parse import urlparse
import re

from aegisaudit.config import AegisConfig
from aegisaudit.models import Finding, ScanArtifact, Severity

_SRI_REF = "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"

# Attribute order is not stable across sites, so match the tag then inspect it.
_SCRIPT_TAG = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
_LINK_TAG = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_ATTR = re.compile(r"""(?:src|href)=["']([^"']+)["']""", re.IGNORECASE)
_REL_STYLESHEET = re.compile(r"""rel=["']stylesheet["']""", re.IGNORECASE)


def _is_external(resource_url: str, page_url: str) -> bool:
    """SRI is for third-party hosts; same-origin tags are out of scope."""
    resource_host = urlparse(resource_url).netloc.lower()
    page_host = urlparse(page_url).netloc.lower()
    return bool(resource_host) and resource_host != page_host


def _missing_sri_finding(artifact: ScanArtifact, kind: str, src: str) -> Finding:
    return Finding(
        id="missing-sri",
        severity=Severity.MEDIUM,
        title="Missing Subresource Integrity",
        description=f"External {kind} loaded without integrity check: {src}",
        url=artifact.url,
        remediation=f"Add integrity='sha384-...' (and crossorigin='anonymous') to the {kind} tag for {src}",
        references=[_SRI_REF],
        tags=["sri", "supply-chain"],
    )


def check_sri(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings: List[Finding] = []

    if "text/html" not in artifact.content_type:
        return findings

    page_url = artifact.final_url or artifact.url

    for match in _SCRIPT_TAG.finditer(artifact.body_snippet):
        tag = match.group(0)
        src_match = _ATTR.search(tag)
        if src_match is None:
            continue
        src = src_match.group(1)
        if not src.lower().startswith("http"):
            continue
        if not _is_external(src, page_url):
            continue
        if "integrity=" not in tag.lower():
            findings.append(_missing_sri_finding(artifact, "script", src))

    for match in _LINK_TAG.finditer(artifact.body_snippet):
        tag = match.group(0)
        if _REL_STYLESHEET.search(tag) is None:
            continue
        href_match = _ATTR.search(tag)
        if href_match is None:
            continue
        href = href_match.group(1)
        if not href.lower().startswith("http"):
            continue
        if not _is_external(href, page_url):
            continue
        if "integrity=" not in tag.lower():
            findings.append(_missing_sri_finding(artifact, "stylesheet", href))

    return findings
