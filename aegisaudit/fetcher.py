import httpx
import asyncio
from typing import Optional
from aegisaudit.models import ScanArtifact, _tool_version
from aegisaudit.config import AegisConfig

# Identify the scanner honestly, and point operators at the project so they can
# tell an audit apart from an attack in their logs.
DEFAULT_USER_AGENT = f"AegisAudit/{_tool_version()} (+https://github.com/forbiddenlink/aegis-audit)"


class Fetcher:
    def __init__(self, config: AegisConfig):
        self.config = config
        self.client = httpx.AsyncClient(
            verify=False,  # We want to inspect certs, not block on them (passive mode)
            follow_redirects=True,
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

    async def fetch(self, url: str) -> Optional[ScanArtifact]:
        await self._respect_rate_limit()
        async with self.semaphore:
            try:
                response = await self.client.get(url)

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
                    content_type=response.headers.get("content-type", ""),
                    body_snippet=body_content,
                )
            except Exception as e:
                # In a real tool, log this failure prominently
                print(f"Error fetching {url}: {e}")
                return None
