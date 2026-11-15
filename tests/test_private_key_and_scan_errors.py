"""Private-key detection must cover PKCS#8 and encrypted keys; scan errors must surface."""

import os

import pytest

from aegisaudit.sast.scanner import SASTScanner
from aegisaudit.sast.secrets import scan_file_for_secrets

# Built at runtime so this file never contains a literal PEM header.
BEGIN = "-----BEGIN "
END = "-----"


def header(kind: str) -> str:
    return BEGIN + kind + END


@pytest.mark.parametrize(
    "kind",
    [
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "PRIVATE KEY",  # PKCS#8
        "ENCRYPTED PRIVATE KEY",  # PKCS#8 encrypted
        "PGP PRIVATE KEY BLOCK",
    ],
)
def test_private_key_forms_detected(tmp_path, kind):
    p = tmp_path / "k.txt"
    p.write_text(header(kind) + "\nAAAA\n")
    findings = scan_file_for_secrets(p)
    assert [f.id for f in findings] == ["sast-secret-generic-private-key"]


def test_public_key_not_flagged(tmp_path):
    p = tmp_path / "pub.txt"
    p.write_text(header("PUBLIC KEY") + "\nAAAA\n")
    assert scan_file_for_secrets(p) == []


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs POSIX permissions")
def test_unreadable_file_is_reported_not_silently_clean(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_text("x")
    p.chmod(0)
    try:
        errors: list = []
        assert scan_file_for_secrets(p, "secret.txt", errors=errors) == []
        assert errors == ["secret.txt"]

        result = SASTScanner().scan(tmp_path)
        assert result.failed_targets == ["secret.txt"]
    finally:
        p.chmod(0o644)


def test_binary_file_is_skipped_without_error(tmp_path):
    p = tmp_path / "b.bin"
    p.write_bytes(b"\xff\xfe\x00\x80")
    errors: list = []
    assert scan_file_for_secrets(p, "b.bin", errors=errors) == []
    assert errors == []
