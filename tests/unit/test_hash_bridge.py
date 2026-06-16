"""Unit tests — core.security.hash (bridge module, no DB/Redis)."""

import hashlib

from core.security.hash import get_password_hash, verify_password


# ---------------------------------------------------------------------------
# get_password_hash — bridge to core.security.password.hash_password
# ---------------------------------------------------------------------------

def test_get_password_hash_returns_input_unchanged():
    """The bridge is a pass-through."""
    hex_pw = hashlib.sha256("test".encode()).hexdigest()
    assert get_password_hash(hex_pw) == hex_pw


def test_get_password_hash_with_real_double_sha256():
    plaintext = "my-password"
    double_hash = hashlib.sha256(hashlib.sha256(plaintext.encode()).hexdigest().encode()).hexdigest()
    assert get_password_hash(double_hash) == double_hash


# ---------------------------------------------------------------------------
# verify_password — bridge to core.security.password.verify_password
# ---------------------------------------------------------------------------

def test_verify_password_matches():
    assert verify_password("abc", "abc") is True


def test_verify_password_no_match():
    assert verify_password("abc", "xyz") is False


def test_verify_password_real_double_sha256():
    plaintext = "correct-password"
    computed = hashlib.sha256(hashlib.sha256(plaintext.encode()).hexdigest().encode()).hexdigest()
    assert verify_password(computed, computed) is True


def test_verify_password_empty():
    assert verify_password("", "") is True
    assert verify_password("", "non-empty") is False
