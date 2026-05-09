"""Unit tests — modules.api.v1.auth (no database, no Redis)."""

import importlib
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.security.hash import get_password_hash
from modules.api.v1 import auth as auth_v1


def test_jwt_handler_raises_when_secret_key_missing(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    import core.security.jwt_handler as m
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        importlib.reload(m)
    # Restore so subsequent tests work
    monkeypatch.setenv("JWT_SECRET_KEY", "test-only-secret-key-do-not-use-in-prod")
    importlib.reload(m)


def test_generate_refresh_token_returns_distinct_plaintext_and_hash():
    from core.security.jwt_handler import generate_refresh_token
    import hashlib
    plaintext, token_hash = generate_refresh_token()
    assert len(plaintext) > 20
    assert token_hash == hashlib.sha256(plaintext.encode()).hexdigest()
    # Each call produces a unique token
    plaintext2, _ = generate_refresh_token()
    assert plaintext != plaintext2


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(auth_v1.router, prefix="/api/v1")
    return TestClient(app)


def _mock_get_session():
    @asynccontextmanager
    async def _session_ctx():
        yield object()

    return _session_ctx


def test_login_success_returns_bearer_token(client, monkeypatch):
    plain_password = "password123"
    hashed_password = get_password_hash(plain_password)
    user = SimpleNamespace(uuid="user-uuid-1", password=hashed_password)

    async def fake_find_by_username_or_email(session, login_identifier):
        assert login_identifier == "alice"
        return user

    async def fake_update(self, uuid, data):
        return {}

    async def fake_create_rt(user_uuid, token_hash):
        pass

    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_v1.UsersDAO,
        "find_by_username_or_email",
        fake_find_by_username_or_email,
        raising=False,
    )
    monkeypatch.setattr(auth_v1.UsersDAO, "update", fake_update, raising=False)
    monkeypatch.setattr(auth_v1, "create_access_token", lambda subject: "mock-token-v1")
    monkeypatch.setattr(
        auth_v1, "generate_refresh_token", lambda: ("mock-refresh-token", "mock-hash")
    )
    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "create", fake_create_rt, raising=False)

    response = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": plain_password},
    )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "mock-token-v1",
        "refresh_token": "mock-refresh-token",
        "token_type": "bearer",
    }


def test_login_returns_401_when_user_not_found(client, monkeypatch):
    async def fake_find_by_username_or_email(session, login_identifier):
        return None

    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_v1.UsersDAO,
        "find_by_username_or_email",
        fake_find_by_username_or_email,
        raising=False,
    )

    response = client.post(
        "/api/v1/auth/login",
        data={"username": "unknown", "password": "whatever"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"
    assert response.headers["www-authenticate"] == "Bearer"


def test_login_returns_401_when_password_invalid(client, monkeypatch):
    user = SimpleNamespace(uuid="user-uuid-2", password=get_password_hash("correct-password"))

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_v1.UsersDAO,
        "find_by_username_or_email",
        fake_find_by_username_or_email,
        raising=False,
    )

    response = client.post(
        "/api/v1/auth/login",
        data={"username": "bob", "password": "wrong-password"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"
    assert response.headers["www-authenticate"] == "Bearer"


def test_read_users_me_returns_current_user_payload(client):
    app = client.app
    app.dependency_overrides[auth_v1.get_current_user] = lambda: {
        "uuid": "u-1",
        "real_name": "Alice",
        "user_role": "admin",
    }

    response = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer token"})

    assert response.status_code == 200
    assert response.json() == {"uuid": "u-1", "real_name": "Alice", "role": "admin"}

    app.dependency_overrides.clear()
