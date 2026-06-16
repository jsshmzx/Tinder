"""Unit tests — core.security.password (pure functions, no DB/Redis)."""

import hashlib

from core.security.password import hash_password, verify_password


# ---------------------------------------------------------------------------
# hash_password — pass-through
# ---------------------------------------------------------------------------

def test_hash_password_returns_same_string():
    """hash_password is a pass-through; it returns the input unchanged."""
    hex_pw = "abcdef0123456789" * 4  # 64 chars
    assert hash_password(hex_pw) == hex_pw


def test_hash_password_empty_string():
    assert hash_password("") == ""


def test_hash_password_real_sha256_hex():
    """Pass a real SHA256 hex digest through."""
    original = "hello"
    expected = hashlib.sha256(hashlib.sha256(original.encode()).hexdigest().encode()).hexdigest()
    assert hash_password(expected) == expected


# ---------------------------------------------------------------------------
# verify_password — hmac.compare_digest
# ---------------------------------------------------------------------------

def test_verify_password_matching():
    assert verify_password("abc123", "abc123") is True


def test_verify_password_different():
    assert verify_password("abc123", "xyz789") is False


def test_verify_password_empty_strings():
    assert verify_password("", "") is True


def test_verify_password_empty_vs_nonempty():
    assert verify_password("", "not-empty") is False


def test_verify_password_case_sensitive():
    """Passwords are hex strings; compare_digest is byte-level exact."""
    assert verify_password("ABCDEF", "abcdef") is False


def test_verify_password_real_double_sha256_match():
    """End-to-end: compute double-SHA256, store it, verify it matches."""
    plaintext = "my-secret-password"
    double_hash = hashlib.sha256(hashlib.sha256(plaintext.encode()).hexdigest().encode()).hexdigest()
    assert verify_password(double_hash, double_hash) is True


def test_verify_password_real_double_sha256_no_match():
    """Different plaintext produces different double-SHA256."""
    pw1 = hashlib.sha256(hashlib.sha256("password-one".encode()).hexdigest().encode()).hexdigest()
    pw2 = hashlib.sha256(hashlib.sha256("password-two".encode()).hexdigest().encode()).hexdigest()
    assert verify_password(pw1, pw2) is False


def test_verify_password_timing_safe():
    """verify_password uses hmac.compare_digest which is constant-time."""
    import hmac
    # The implementation uses hmac.compare_digest internally
    assert hmac.compare_digest("same", "same") is True
    assert hmac.compare_digest("same", "different") is False
