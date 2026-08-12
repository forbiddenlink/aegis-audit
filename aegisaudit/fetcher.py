import asyncio
import logging
from typing import Optional

import httpx

from aegisaudit.config import AegisConfig
from aegisaudit.models import ScanArtifact, _tool_version
from aegisaudit.ssrf import SSRFError, validate_url

logger = logging.getLogger(__name__)

# Identify the scanner honestly, and point operators at the project so they can
# tell an audit apart from an attack in their logs.
DEFAULT_USER_AGENT = f"AegisAudit/{_tool_version()} (+https://github.com/forbiddenlink/aegis-audit)"


class Fetcher:
    def __init__(self, config: AegisConfig):
        self.config = config
        # follow_redirects is OFF: redirects are followed manually in fetch() so
        # every hop can be re-validated by the SSRF guard. Letting httpx follow
        # them automatically would jump to an internal/metadata host with no
        # check. verify defaults on (see LimitsConfig.insecure).
        self.client = httpx.AsyncClient(
            verify=not config.limits.insecure,
            follow_redirects=False,
            timeout=config.limits.timeout_sec,
            headers={"User-Agent": DEFAULT_USER_AGENT},
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=10),
        )
        # Concurrency budget, always at least 1 so the fetcher can never block
        # on an empty semaphore.
        self.semaphore = asyncio.Semaphore(max(1, config.limits.max_concurrency))
        # Rate-limit spacing is serialized on its own lock so waits happen one
        # at a time (real spacing between request starts) instead of every
        # concurrent worker sleeping in parallel while holding a request slot,
        # which let the rate limit burst up to the concurrency budget.
        self._rate_lock = asyncio.Lock()

    async def close(self) -> None:
        await self.client.aclose()

    async def fetch_many(self, urls: list[str]) -> list[ScanArtifact]:
        """Fetch every URL concurrently, bounded by the concurrency budget.

        Replaces a caller-side `for url: await fetch(url)` loop that ran the
        requests one at a time, so neither the async client nor the semaphore
        did anything. Failed fetches are dropped, not raised, so one dead host
        does not sink the batch.
        """
        results = await asyncio.gather(*(self.fetch(url) for url in urls))
        return [artifact for artifact in results if artifact is not None]

    async def _respect_rate_limit(self) -> None:
        # Guard against a non-positive rate so a misconfigured value can't
        # divide by zero or sleep forever. The lock serializes the delay so it
        # spaces request starts rather than running in parallel across workers.
        rate = self.config.limits.rate_per_sec
        if rate > 0:
            async with self._rate_lock:
                await asyncio.sleep(1.0 / rate)

    def _validate(self, url: str) -> None:
        """SSRF-gate a destination, honouring the configured scope."""
        validate_url(
            url,
            allow=self.config.scope.allow,
            allow_private=self.config.scope.allow_private,
        )

    async def _get(self, url: str) -> httpx.Response:
        """Validate the destination and every redirect hop, returning the final
        response.

        Redirects are followed manually so each hop is re-validated by the SSRF
        guard. An attacker's target can 3xx to an internal/metadata host;
        auto-following would leak its body into reports and outbound webhooks.
        """
        self._validate(url)
        current = url
        response = await self.client.get(current)
        hops = 0
        while response.is_redirect:
            if hops >= self.config.limits.max_redirects:
                raise SSRFError(f"too many redirects (>{self.config.limits.max_redirects})")
            location = response.headers.get("location", "")
            current = str(response.url.join(location))
            self._validate(current)
            hops += 1
            response = await self.client.get(current)
        return response

    async def fetch(self, url: str) -> Optional[ScanArtifact]:
        await self._respect_rate_limit()
        async with self.semaphore:
            try:
                response = await self._get(url)

                # Truncate body if needed
                body_content = response.text
                if len(body_content) > self.config.limits.max_html_bytes:
                    body_content = body_content[: self.config.limits.max_html_bytes]

                return ScanArtifact(
                    url=url,
                    final_url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    cookies=dict(response.cookies),
                    set_cookie_headers=response.headers.get_list("set-cookie"),
                    content_type=response.headers.get("content-type", ""),
                    body_snippet=body_content,
                )
            except SSRFError as e:
                # A blocked destination is a security event, not a transient
                # error -- surface it at warning level even without -v.
                logger.warning("Blocked (SSRF guard) %s: %s", url, e)
                return None
            except Exception as e:
                logger.warning("Error fetching %s: %s", url, e)
                return None

    async def get_text(self, url: str) -> Optional[str]:
        """Guarded fetch returning the full response body, untruncated.

        Used for sitemap XML, where truncating the body (as fetch() does for
        HTML pages) would corrupt the document mid-tag. The SSRF guard and rate
        limit still apply -- a sitemap URL is as attacker-influenced as any
        other target.
        """
        await self._respect_rate_limit()
        async with self.semaphore:
            try:
                return (await self._get(url)).text
            except SSRFError as e:
                logger.warning("Blocked (SSRF guard) %s: %s", url, e)
                return None
            except Exception as e:
                logger.warning("Error fetching %s: %s", url, e)
                return None
