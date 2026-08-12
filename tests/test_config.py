"""Config loading and strictness.

The config models reject unknown keys (extra="forbid"). A mis-set control on a
security scanner must fail loudly, not silently fall back to a permissive
default: a typo'd `allowlist_urls` (real field: `scope.allow`) once left the
scanner running unscoped while the operator thought a restriction applied.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from aegisaudit.config import AegisConfig, LimitsConfig, ScopeConfig, load_config


def test_unknown_top_level_key_is_rejected():
    with pytest.raises(ValidationError):
        AegisConfig(allowlist_urls=["example.com"])  # meant scope.allow


def test_unknown_nested_key_is_rejected():
    with pytest.raises(ValidationError):
        ScopeConfig(allow_privte=True)  # typo of allow_private
    with pytest.raises(ValidationError):
        LimitsConfig(max_concurency=4)  # typo of max_concurrency


def test_known_config_still_builds():
    cfg = AegisConfig(scope=ScopeConfig(allow=["example.com"], allow_private=False))
    assert cfg.scope.allow == ["example.com"]


def test_load_config_rejects_typo_in_yaml(tmp_path: Path):
    bad = tmp_path / "aegis.yml"
    bad.write_text("scope:\n  allowlist: [example.com]\n")  # wrong key under scope
    with pytest.raises(ValidationError):
        load_config(bad)


def test_load_config_missing_file_returns_defaults(tmp_path: Path):
    assert load_config(tmp_path / "nope.yml").scope.allow == []
