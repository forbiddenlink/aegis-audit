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
        self.semaphore = asyncio.Semaphore(
            int(config.limits.rate_per_sec)
        )  # Rough rate limit approx

    async def close(self):
        await self.client.aclose()

    async def fetch(self, url: str) -> Optional[ScanArtifact]:
        async with self.semaphore:
            try:
                # Basic rate limiting delay
                await asyncio.sleep(1.0 / self.config.limits.rate_per_sec)

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
