"""Sitemap-driven URL discovery for `scan --sitemap`.

Expands a single sitemap URL into the pages it lists so a whole site can be
scanned, not just one URL. Two safety properties matter because the sitemap is
attacker-controlled content:

- Parsing uses defusedxml, so a hostile sitemap cannot mount an entity-expansion
  (billion-laughs) or external-entity (XXE) attack that stdlib xml.etree would
  execute.
- Discovery is bounded: at most ``max_urls`` targets and a fixed number of child
  sitemaps, so a sitemap listing millions of URLs (or a deep index tree) cannot
  turn one scan into an unbounded crawl. Every discovered URL is still fetched
  through the SSRF guard by the caller.
"""

from __future__ import annotations

from typing import Awaitable, Callable, List, Optional, Tuple

from defusedxml import ElementTree as ET

# One level of sitemap-index expansion, capped. A sitemapindex points at child
# sitemaps; we fetch those but do not recurse into indexes they might contain,
# which bounds the fan-out.
MAX_CHILD_SITEMAPS = 20


class SitemapError(ValueError):
    """The sitemap XML could not be parsed."""


def _localname(tag: str) -> str:
    """Strip the XML namespace so tags match regardless of the declared ns."""
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(xml_text: str) -> Tuple[List[str], List[str]]:
    """Parse sitemap XML into (page_urls, child_sitemap_urls).

    A ``<urlset>`` yields page URLs; a ``<sitemapindex>`` yields child sitemap
    URLs. Exactly one of the two lists is populated, matching the sitemaps.org
    schema where a document is one kind or the other.
    """
    try:
        root = ET.fromstring(xml_text)
    except Exception as exc:  # defusedxml raises on entity/DTD abuse too
        raise SitemapError(f"could not parse sitemap XML: {exc}") from None

    locs = [
        el.text.strip()
        for el in root.iter()
        if _localname(el.tag) == "loc" and el.text and el.text.strip()
    ]
    if _localname(root.tag) == "sitemapindex":
        return [], locs
    return locs, []


async def discover_sitemap_urls(
    fetch_text: Callable[[str], Awaitable[Optional[str]]],
    sitemap_url: str,
    max_urls: int,
) -> Tuple[List[str], bool]:
    """Discover page URLs from a sitemap, following one level of index nesting.

    ``fetch_text`` is an async ``(url) -> Optional[str]`` that fetches through
    the SSRF guard (returning None on a blocked/failed fetch). Returns the
    deduped, order-preserving list of URLs capped at ``max_urls``, and a flag
    that is True when the cap dropped some — so the caller can say so rather than
    silently scanning a subset.
    """
    text = await fetch_text(sitemap_url)
    if text is None:
        return [], False

    page_urls, child_sitemaps = parse_sitemap(text)

    seen = set(page_urls)
    ordered = list(page_urls)

    for child in child_sitemaps[:MAX_CHILD_SITEMAPS]:
        if len(ordered) >= max_urls:
            break
        child_text = await fetch_text(child)
        if child_text is None:
            continue
        child_pages, _ = parse_sitemap(child_text)  # one level only; ignore nested indexes
        for url in child_pages:
            if url not in seen:
                seen.add(url)
                ordered.append(url)

    truncated = len(ordered) > max_urls
    return ordered[:max_urls], truncated
