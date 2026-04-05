"""Unit tests — modules.auth.auth_router (no database, no Redis)."""

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.security.hash import get_password_hash
from modules.auth import auth_router


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(auth_router.router, prefix="/api/auth")
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

    async def fake_find_by_uuid_or_real_name(session, username):
        assert username == "alice"
        return user

    monkeypatch.setattr(auth_router, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_router.UsersDAO,
        "find_by_uuidOrRealName",
        fake_find_by_uuid_or_real_name,
        raising=False,
    )
    monkeypatch.setattr(auth_router, "create_access_token", lambda subject: "mock-token")

    response = client.post(
        "/api/auth/login",
        data={"username": "alice", "password": plain_password},
    )

    assert response.status_code == 200
    assert response.json() == {"access_token": "mock-token", "token_type": "bearer"}


def test_login_returns_401_when_user_not_found(client, monkeypatch):
    async def fake_find_by_uuid_or_real_name(session, username):
        return None

    monkeypatch.setattr(auth_router, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_router.UsersDAO,
        "find_by_uuidOrRealName",
        fake_find_by_uuid_or_real_name,
        raising=False,
    )

    response = client.post(
        "/api/auth/login",
        data={"username": "unknown", "password": "whatever"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"
    assert response.headers["www-authenticate"] == "Bearer"


def test_login_returns_401_when_password_invalid(client, monkeypatch):
    user = SimpleNamespace(uuid="user-uuid-2", password=get_password_hash("correct-password"))

    async def fake_find_by_uuid_or_real_name(session, username):
        return user

    monkeypatch.setattr(auth_router, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_router.UsersDAO,
        "find_by_uuidOrRealName",
        fake_find_by_uuid_or_real_name,
        raising=False,
    )

    response = client.post(
        "/api/auth/login",
        data={"username": "bob", "password": "wrong-password"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"
    assert response.headers["www-authenticate"] == "Bearer"


def test_read_users_me_returns_current_user_payload(client):
    app = client.app
    app.dependency_overrides[auth_router.get_current_user] = lambda: {
        "uuid": "u-1",
        "real_name": "Alice",
        "user_role": "admin",
    }

    response = client.get("/api/auth/me", headers={"Authorization": "Bearer token"})

    assert response.status_code == 200
    assert response.json() == {"uuid": "u-1", "real_name": "Alice", "role": "admin"}

    app.dependency_overrides.clear()
