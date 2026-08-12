"""Sitemap parsing and bounded discovery."""

import pytest

from aegisaudit.sitemap import (
    SitemapError,
    discover_sitemap_urls,
    parse_sitemap,
)

URLSET = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://a.test/</loc></url>
  <url><loc>https://a.test/about</loc></url>
</urlset>"""

INDEX = """<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://a.test/sitemap-1.xml</loc></sitemap>
  <sitemap><loc>https://a.test/sitemap-2.xml</loc></sitemap>
</sitemapindex>"""

# Classic billion-laughs; defusedxml must refuse to expand it.
BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<urlset><url><loc>&lol3;</loc></url></urlset>"""


# --- parse ----------------------------------------------------------------


def test_parse_urlset_returns_page_urls():
    pages, children = parse_sitemap(URLSET)
    assert pages == ["https://a.test/", "https://a.test/about"]
    assert children == []


def test_parse_index_returns_child_sitemaps():
    pages, children = parse_sitemap(INDEX)
    assert pages == []
    assert children == ["https://a.test/sitemap-1.xml", "https://a.test/sitemap-2.xml"]


def test_parse_malformed_raises():
    with pytest.raises(SitemapError):
        parse_sitemap("<urlset><url><loc>unclosed")


def test_parse_rejects_entity_expansion():
    # defusedxml raises rather than expanding the entity bomb.
    with pytest.raises(SitemapError):
        parse_sitemap(BILLION_LAUGHS)


# --- discovery (fetch_text injected, no network) --------------------------


def _fetcher(mapping):
    async def fetch_text(url):
        return mapping.get(url)

    return fetch_text


async def test_discover_flat_urlset():
    urls, truncated = await discover_sitemap_urls(
        _fetcher({"https://a.test/sitemap.xml": URLSET}),
        "https://a.test/sitemap.xml",
        max_urls=200,
    )
    assert urls == ["https://a.test/", "https://a.test/about"]
    assert truncated is False


async def test_discover_expands_one_level_of_index():
    child1 = URLSET
    child2 = URLSET.replace("a.test/", "b.test/")
    mapping = {
        "https://a.test/sitemap.xml": INDEX,
        "https://a.test/sitemap-1.xml": child1,
        "https://a.test/sitemap-2.xml": child2,
    }
    urls, _ = await discover_sitemap_urls(_fetcher(mapping), "https://a.test/sitemap.xml", 200)
    assert "https://a.test/about" in urls
    assert "https://b.test/about" in urls


async def test_discover_caps_and_flags_truncation():
    urls, truncated = await discover_sitemap_urls(
        _fetcher({"https://a.test/sitemap.xml": URLSET}),
        "https://a.test/sitemap.xml",
        max_urls=1,
    )
    assert len(urls) == 1
    assert truncated is True


async def test_discover_returns_empty_when_sitemap_unfetchable():
    urls, truncated = await discover_sitemap_urls(
        _fetcher({}),  # fetch_text returns None
        "https://a.test/sitemap.xml",
        max_urls=200,
    )
    assert urls == []
    assert truncated is False


async def test_discover_skips_unfetchable_child():
    mapping = {
        "https://a.test/sitemap.xml": INDEX,
        # sitemap-1.xml missing (fetch_text -> None), sitemap-2.xml present
        "https://a.test/sitemap-2.xml": URLSET.replace("a.test/", "b.test/"),
    }
    urls, _ = await discover_sitemap_urls(_fetcher(mapping), "https://a.test/sitemap.xml", 200)
    assert "https://b.test/about" in urls  # the reachable child still contributes


async def test_discover_stops_fetching_children_once_capped():
    # Cap is already met by nothing-from-parent + first child; second child's
    # fetch must be skipped rather than fetched-then-trimmed.
    fetched = []

    async def fetch_text(url):
        fetched.append(url)
        if url == "https://a.test/sitemap.xml":
            return INDEX
        return URLSET

    urls, truncated = await discover_sitemap_urls(fetch_text, "https://a.test/sitemap.xml", 2)
    assert len(urls) == 2
    # parent + first child fetched; second child skipped by the cap
    assert "https://a.test/sitemap-2.xml" not in fetched


async def test_discover_dedupes_across_children():
    # Both children list the same URL; it should appear once.
    mapping = {
        "https://a.test/sitemap.xml": INDEX,
        "https://a.test/sitemap-1.xml": URLSET,
        "https://a.test/sitemap-2.xml": URLSET,
    }
    urls, _ = await discover_sitemap_urls(_fetcher(mapping), "https://a.test/sitemap.xml", 200)
    assert urls.count("https://a.test/") == 1
