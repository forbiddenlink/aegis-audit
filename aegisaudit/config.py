from typing import List, Optional, Dict, Any
from pathlib import Path
import yaml
from pydantic import BaseModel, HttpUrl, Field
from aegisaudit.policy import DEFAULT_POLICY


class ScopeConfig(BaseModel):
    # Hostname allowlist. When non-empty, only these hosts (and their
    # subdomains) may be fetched -- enforced in the SSRF guard, not just
    # advisory. Empty means "any public host".
    allow: List[str] = Field(default_factory=list)
    # Permit fetching private / loopback / link-local / metadata addresses.
    # Off by default: a scanner that follows a target's redirect into cloud
    # metadata is an SSRF credential-theft primitive. Turn on only for scanning
    # an intentionally-internal target from inside its own network.
    allow_private: bool = False


class TargetsConfig(BaseModel):
    urls: List[str] = Field(default_factory=list)
    urls_file: Optional[Path] = None
    sitemap: Optional[HttpUrl] = None


class LimitsConfig(BaseModel):
    rate_per_sec: float = 2.0
    timeout_sec: float = 10.0
    max_html_bytes: int = 200_000
    # How many requests may be in flight at once. Distinct from rate_per_sec:
    # concurrency is "how many parallel", rate is "how fast each". They were
    # conflated into one Semaphore(int(rate_per_sec)), which became Semaphore(0)
    # and hung whenever the rate dropped below 1.
    max_concurrency: int = 10
    # Verify TLS certificates on the content fetch. On by default so an on-path
    # attacker cannot feed forged content into the report/regex/webhook
    # pipeline. Certificate *inspection* (expiry, weak protocol) is a separate
    # validating connection in checks/tls.py, so disabling verification here
    # bought nothing but MITM exposure. Set insecure=True (or --insecure) to
    # scan a target whose cert is intentionally broken.
    insecure: bool = False
    # Max redirect hops to follow. Each hop is re-validated by the SSRF guard.
    max_redirects: int = 5


class AegisConfig(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    targets: TargetsConfig = Field(default_factory=TargetsConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    policy: Dict[str, Any] = Field(default_factory=lambda: DEFAULT_POLICY)


def load_config(config_path: Optional[Path] = None) -> AegisConfig:
    """Load configuration from a YAML file or return defaults."""
    if not config_path or not config_path.exists():
        return AegisConfig()

    with open(config_path, "r") as f:
        data = yaml.safe_load(f) or {}

    return AegisConfig(**data)
