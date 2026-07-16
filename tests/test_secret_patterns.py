"""False-positive and true-positive tests for secret detection.

A scanner is judged on both directions. Running `aegis audit` on this repo used
to produce 5 findings, 5 of which were false positives -- including a HIGH
"AWS Access Key" that was actually a hash in uv.lock -- because the pattern was
`[A-Z0-9]{20}` with no key-prefix anchor. Real AWS key IDs begin with a known
4-character prefix (AKIA, ASIA, ABIA, ACCA, A3T...), which is what makes them
identifiable.
"""

import re

import pytest

from aegisaudit.checks.secrets import check_secrets
from aegisaudit.config import AegisConfig
from aegisaudit.models import ScanArtifact
from aegisaudit.sast.secrets import PATTERNS

AWS_REGEX = re.compile(PATTERNS["AWS Access Key"]["regex"])

# Documented AWS example key IDs.
REAL_AWS_KEYS = [
    "AKIAIOSFODNN7EXAMPLE",  # long-term access key
    "ASIAY34FZKBOKMUTVV7A",  # temporary STS key
]

NOT_AWS_KEYS = [
    "9019209617D0E7A1B2C3",  # a hash, as found in uv.lock
    "ABCDEFGHIJKLMNOPQRST",  # 20 uppercase letters
    "0123456789ABCDEF0123",  # hex blob
    "CONTENTSECURITYPOLIC",  # a word
    "XXXXXXXXXXXXXXXXXXXX",  # placeholder
]


class TestAwsKeyPattern:
    @pytest.mark.parametrize("key", REAL_AWS_KEYS)
    def test_detects_real_aws_key_ids(self, key):
        assert AWS_REGEX.search(f"AWS_ACCESS_KEY_ID={key}")

    @pytest.mark.parametrize("blob", NOT_AWS_KEYS)
    def test_does_not_flag_arbitrary_20_char_uppercase_strings(self, blob):
        """Regression: uv.lock hashes were reported as HIGH severity AWS keys."""
        assert not AWS_REGEX.search(blob)

    def test_does_not_flag_a_lockfile_hash_line(self):
        line = 'sha256 = "9019209617D0E7A1B2C3"  # noqa'
        assert not AWS_REGEX.search(line)


class TestWebSecretsCheckSharesTheSamePattern:
    def _artifact(self, body: str) -> ScanArtifact:
        return ScanArtifact(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            headers={},
            cookies={},
            body_snippet=body,
            content_type="text/html",
        )

    def test_html_with_a_hash_is_not_reported_as_an_aws_key(self):
        findings = check_secrets(self._artifact("<p>9019209617D0E7A1B2C3</p>"), AegisConfig())
        assert not [f for f in findings if "aws" in f.id]

    def test_html_with_a_real_aws_key_is_reported(self):
        findings = check_secrets(
            self._artifact("<script>var k='AKIAIOSFODNN7EXAMPLE';</script>"), AegisConfig()
        )
        assert [f for f in findings if "aws" in f.id]
