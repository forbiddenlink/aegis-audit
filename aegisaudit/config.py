from typing import List, Optional, Dict, Any
from pathlib import Path
import yaml
from pydantic import BaseModel, ConfigDict, HttpUrl, Field
from aegisaudit.policy import DEFAULT_POLICY


# Reject unknown keys everywhere in the config tree. Pydantic's default silently
# drops them, so a typo like `allowlist_urls` (the real field is `scope.allow`)
# or an indentation slip in the YAML would leave the scanner running with
# defaults while the operator believes a restriction is in force. For a security
# tool that is the same failure class it refuses elsewhere (never silently
# unscored, never mistake an incomplete scan for a clean one): a mis-set control
# must fail loudly, not no-op. `policy` stays a free-form dict by design.
_STRICT = ConfigDict(extra="forbid")


class ScopeConfig(BaseModel):
    model_config = _STRICT
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
    model_config = _STRICT
    urls: List[str] = Field(default_factory=list)
    urls_file: Optional[Path] = None
    sitemap: Optional[HttpUrl] = None


class LimitsConfig(BaseModel):
    model_config = _STRICT
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
    model_config = _STRICT
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
