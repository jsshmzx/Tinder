"""Unit tests — core.security.jwt_handler (token structure, no DB/Redis).

Uses monkeypatch to set JWT_SECRET_KEY so tokens can be created/decoded within the same process.
"""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from core.security.jwt_handler import (
    create_access_token,
    create_temp_token,
    decode_access_token,
    generate_refresh_token,
)

JWT_SECRET = "test-only-secret-key-for-unit-tests-do-not-use-in-prod"


@pytest.fixture(autouse=True)
def _jwt_secret(monkeypatch):
    """Ensure JWT_SECRET_KEY is set for the duration of each test."""
    monkeypatch.setattr("core.config.settings.JWT_SECRET_KEY", JWT_SECRET)
    # Also update the module-level ALGORITHM alias
    from core import security
    monkeypatch.setattr(security.jwt_handler, "ALGORITHM", "HS256")


def test_create_access_token_returns_string():
    token = create_access_token("user-123")
    assert isinstance(token, str)
    assert len(token) > 10


def test_create_access_token_contains_three_parts(token_jwt_header):
    """A JWT has three dot-separated parts: header.payload.signature."""
    token = create_access_token("user-123")
    parts = token.split(".")
    assert len(parts) == 3


def test_decode_access_token_returns_payload(token_jwt_header):
    token = create_access_token("user-456")
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "user-456"


def test_decode_access_token_invalid_returns_none():
    assert decode_access_token("not.a.valid.token") is None


def test_decode_access_token_wrong_secret_returns_none():
    from jose import jwt
    bad_secret = "wrong-secret"
    token = jwt.encode(
        {"exp": datetime.now(timezone.utc) + timedelta(hours=1), "sub": "user-1"},
        bad_secret,
        algorithm="HS256",
    )
    assert decode_access_token(token) is None


def test_create_access_token_subject_converted_to_string():
    token = create_access_token(99)
    payload = decode_access_token(token)
    assert payload["sub"] == "99"


def test_create_access_token_has_exp():
    token = create_access_token("user-1")
    payload = decode_access_token(token)
    assert "exp" in payload


def test_create_access_token_expires_in_future():
    token = create_access_token("user-1")
    payload = decode_access_token(token)
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    assert exp > datetime.now(timezone.utc)


def test_create_access_token_custom_expires_delta():
    token = create_access_token("user-1", expires_delta=timedelta(minutes=5))
    payload = decode_access_token(token)
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    diff = exp - datetime.now(timezone.utc)
    assert diff.total_seconds() <= 300 + 5  # 5 min + clock tolerance


def test_different_subjects_produce_different_tokens():
    t1 = create_access_token("user-a")
    t2 = create_access_token("user-b")
    assert t1 != t2


def test_generate_refresh_token_returns_tuple():
    plaintext, token_hash = generate_refresh_token()
    assert isinstance(plaintext, str)
    assert isinstance(token_hash, str)


def test_generate_refresh_token_hash_matches():
    plaintext, token_hash = generate_refresh_token()
    expected = hashlib.sha256(plaintext.encode()).hexdigest()
    assert token_hash == expected


def test_generate_refresh_token_unique_each_call():
    p1, h1 = generate_refresh_token()
    p2, h2 = generate_refresh_token()
    assert p1 != p2
    assert h1 != h2


def test_generate_refresh_token_url_safe():
    """token_urlsafe should not contain +, /, or =."""
    plaintext, _ = generate_refresh_token()
    assert "+" not in plaintext
    assert "/" not in plaintext
    assert "=" not in plaintext


def test_create_temp_token_returns_string():
    token = create_temp_token("user-uuid-1", "register_complete")
    assert isinstance(token, str)
    assert len(token) > 10


def test_create_temp_token_has_purpose():
    token = create_temp_token("user-uuid-1", "register_complete")
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["purpose"] == "register_complete"
    assert payload["sub"] == "user-uuid-1"


def test_create_temp_token_custom_expiry():
    token = create_temp_token("user-uuid-1", "register_complete", expires_minutes=10)
    payload = decode_access_token(token)
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    diff = exp - datetime.now(timezone.utc)
    assert diff.total_seconds() <= 600 + 5  # 10 min + clock tolerance


def test_create_temp_token_different_purposes():
    t1 = create_temp_token("u-1", "purpose-a")
    t2 = create_temp_token("u-1", "purpose-b")
    assert t1 != t2
    assert decode_access_token(t1)["purpose"] == "purpose-a"
    assert decode_access_token(t2)["purpose"] == "purpose-b"


@pytest.fixture(scope="module")
def token_jwt_header():
    """A no-op fixture to satisfy pytest's fixture-scoping expectations."""
    return None
