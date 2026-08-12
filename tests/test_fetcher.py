"""Fetcher concurrency and rate-limit tests.

Two bugs motivated these:
  - Semaphore(int(rate_per_sec)) is Semaphore(0) for any rate below 1, which
    blocks forever.
  - The scan loop awaited each fetch in turn, so the async client and the
    semaphore never produced any concurrency -- N targets took N x the
    per-request delay in series.
"""

import asyncio

import httpx

from aegisaudit.config import AegisConfig, LimitsConfig
from aegisaudit.fetcher import Fetcher


def config(**limits) -> AegisConfig:
    cfg = AegisConfig()
    cfg.limits = LimitsConfig(**limits)
    return cfg


def mock_fetcher(cfg: AegisConfig, handler) -> Fetcher:
    """A Fetcher whose HTTP calls are served by an in-process handler."""
    fetcher = Fetcher(cfg)
    fetcher.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return fetcher


def ok_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})


class TestRateLimitDoesNotHang:
    def test_sub_one_rate_completes(self):
        """rate_per_sec below 1 used to make Semaphore(0) and hang forever."""

        async def run():
            fetcher = mock_fetcher(config(rate_per_sec=0.5), ok_handler)
            try:
                # A short deadline turns a hang into a failure instead of a
                # frozen test run.
                return await asyncio.wait_for(fetcher.fetch("https://example.com"), timeout=5.0)
            finally:
                await fetcher.close()

        artifact = asyncio.run(run())
        assert artifact is not None
        assert artifact.status_code == 200


class TestConcurrency:
    def test_fetch_many_returns_all_artifacts(self):
        urls = [f"https://example.com/{i}" for i in range(5)]

        async def run():
            fetcher = mock_fetcher(config(rate_per_sec=100), ok_handler)
            try:
                return await fetcher.fetch_many(urls)
            finally:
                await fetcher.close()

        artifacts = asyncio.run(run())
        assert len(artifacts) == 5
        assert {a.url for a in artifacts} == set(urls)

    def test_requests_actually_run_concurrently(self):
        """Proves the loop is not serialized: with a concurrency budget above 1,
        more than one request is in flight at once."""
        in_flight = 0
        peak = 0

        async def slow_handler(request: httpx.Request) -> httpx.Response:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.05)
            in_flight -= 1
            return httpx.Response(200, text="x", headers={"content-type": "text/html"})

        async def run():
            fetcher = mock_fetcher(config(rate_per_sec=100, max_concurrency=4), slow_handler)
            try:
                await fetcher.fetch_many([f"https://example.com/{i}" for i in range(8)])
            finally:
                await fetcher.close()

        asyncio.run(run())
        assert peak > 1

    def test_concurrency_cap_is_respected(self):
        in_flight = 0
        peak = 0

        async def slow_handler(request: httpx.Request) -> httpx.Response:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.02)
            in_flight -= 1
            return httpx.Response(200, text="x", headers={"content-type": "text/html"})

        async def run():
            fetcher = mock_fetcher(config(rate_per_sec=100, max_concurrency=2), slow_handler)
            try:
                await fetcher.fetch_many([f"https://example.com/{i}" for i in range(8)])
            finally:
                await fetcher.close()

        asyncio.run(run())
        assert peak <= 2


class TestFailuresDoNotSinkTheBatch:
    def test_one_failing_url_does_not_drop_the_others(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/boom":
                raise httpx.ConnectError("nope")
            return httpx.Response(200, text="x", headers={"content-type": "text/html"})

        async def run():
            fetcher = mock_fetcher(config(rate_per_sec=100), handler)
            try:
                return await fetcher.fetch_many(
                    [
                        "https://example.com/ok",
                        "https://example.com/boom",
                        "https://example.com/ok2",
                    ]
                )
            finally:
                await fetcher.close()

        artifacts = asyncio.run(run())
        # The failing one is dropped; the two good ones survive.
        assert len(artifacts) == 2


class TestGetText:
    def test_returns_full_untruncated_body(self):
        big = "<url>" * 100000  # far larger than max_html_bytes

        def handler(request):
            return httpx.Response(200, text=big, headers={"content-type": "application/xml"})

        async def run():
            fetcher = mock_fetcher(config(rate_per_sec=100), handler)
            try:
                return await fetcher.get_text("https://example.com/sitemap.xml")
            finally:
                await fetcher.close()

        text = asyncio.run(run())
        assert text == big  # get_text does not truncate the way fetch() does

    def test_returns_none_on_transport_error(self):
        def handler(request):
            raise httpx.ConnectError("down")

        async def run():
            fetcher = mock_fetcher(config(rate_per_sec=100), handler)
            try:
                return await fetcher.get_text("https://example.com/sitemap.xml")
            finally:
                await fetcher.close()

        assert asyncio.run(run()) is None


class TestRedirectsAreRevalidated:
    def test_follows_and_returns_final_body(self):
        def handler(request):
            if request.url.path == "/start":
                return httpx.Response(302, headers={"location": "https://example.com/final"})
            return httpx.Response(200, text="arrived", headers={"content-type": "text/html"})

        async def run():
            fetcher = mock_fetcher(config(rate_per_sec=100), handler)
            try:
                return await fetcher.fetch("https://example.com/start")
            finally:
                await fetcher.close()

        artifact = asyncio.run(run())
        assert artifact is not None
        assert artifact.body_snippet == "arrived"

    def test_too_many_redirects_is_dropped(self):
        def handler(request):
            # Always redirect onward -> exceeds max_redirects.
            n = int(request.url.path.strip("/") or "0")
            return httpx.Response(302, headers={"location": f"https://example.com/{n + 1}"})

        async def run():
            fetcher = mock_fetcher(config(rate_per_sec=100, max_redirects=2), handler)
            try:
                return await fetcher.fetch("https://example.com/0")
            finally:
                await fetcher.close()

        assert asyncio.run(run()) is None  # SSRFError -> dropped, not raised
