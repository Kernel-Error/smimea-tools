import hashlib
import base64

import pytest

from smimea_common import hash_local_part


def test_hash_local_part_basic():
    """Known email produces expected hash and domain."""
    expected_hash = base64.b16encode(
        hashlib.sha256(b"user").digest()[:28]
    ).decode().lower()

    result_hash, result_domain = hash_local_part("user@example.com")

    assert result_hash == expected_hash
    assert result_domain == "example.com"


def test_hash_local_part_returns_56_char_hex():
    """Hash output is always 56 hex characters (28 bytes)."""
    result_hash, _ = hash_local_part("anything@test.org")
    assert len(result_hash) == 56
    assert all(c in "0123456789abcdef" for c in result_hash)


def test_hash_local_part_domain_preserved():
    """Domain part is returned unchanged."""
    _, domain = hash_local_part("user@My.Domain.Example")
    assert domain == "My.Domain.Example"


@pytest.mark.xfail(
    reason="Issue #1: local-part not lowercased before hashing per RFC 8162",
    strict=True,
)
def test_hash_local_part_lowercase_before_hash():
    """RFC 8162 requires lowercasing the local-part before SHA-256."""
    hash_mixed, _ = hash_local_part("Test.User@example.com")
    hash_lower, _ = hash_local_part("test.user@example.com")
    assert hash_mixed == hash_lower


@pytest.mark.xfail(
    reason="Issue #4: no input validation for email format",
    strict=True,
)
def test_hash_local_part_no_at_sign():
    """Input without @ should raise ValueError with a clear message."""
    with pytest.raises(ValueError, match="[Ii]nvalid email"):
        hash_local_part("no-at-sign")


@pytest.mark.xfail(
    reason="Issue #4: no input validation for email format",
    strict=True,
)
def test_hash_local_part_multiple_at_signs():
    """Input with multiple @ should raise ValueError with a clear message."""
    with pytest.raises(ValueError, match="[Ii]nvalid email"):
        hash_local_part("user@@example.com")
