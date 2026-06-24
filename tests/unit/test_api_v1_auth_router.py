"""Unit tests — modules.api.v1.auth (no database, no Redis)."""

import hashlib
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.security.hash import get_password_hash
from core.security.password import hash_password as _hash_password, verify_password as _verify_password
from modules.api.v1 import auth as auth_v1


def _sha256_hex(text: str) -> str:
    """Compute double SHA256 hex of a plain string (matching the client-side hashing)."""
    return hashlib.sha256(hashlib.sha256(text.encode()).hexdigest().encode()).hexdigest()


def test_jwt_handler_raises_when_secret_key_missing(monkeypatch):
    from core.security.jwt_handler import create_access_token
    monkeypatch.setattr("core.config.settings.JWT_SECRET_KEY", "")
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        create_access_token(subject="test")
    monkeypatch.setattr("core.config.settings.JWT_SECRET_KEY", "test-only-secret-key-do-not-use-in-prod")


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
    app.include_router(auth_v1.router)
    return TestClient(app)


def _mock_get_session():
    @asynccontextmanager
    async def _session_ctx():
        yield object()

    return _session_ctx


def test_login_success_returns_bearer_token(client, monkeypatch):
    plain_password = "password123"
    hex_password = _sha256_hex(plain_password)
    hashed_password = _hash_password(hex_password)
    user = SimpleNamespace(uuid="user-uuid-1", password=hashed_password, current_status="normal")

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
        "/auth/login",
        json={"username": "alice", "password": hex_password},
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
        "/auth/login",
        json={"username": "unknown", "password": _sha256_hex("whatever")},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"
    assert response.headers["www-authenticate"] == "Bearer"


def test_login_returns_401_when_password_invalid(client, monkeypatch):
    plain_correct = "correct-password"
    hex_correct = _sha256_hex(plain_correct)
    wrong_plain = "wrong-password"
    hex_wrong = _sha256_hex(wrong_plain)
    stored_hash = _hash_password(hex_correct)
    user = SimpleNamespace(uuid="user-uuid-2", password=stored_hash, current_status="normal")

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    def fake_verify(plain, stored):
        return _verify_password(plain, stored)

    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_v1.UsersDAO,
        "find_by_username_or_email",
        fake_find_by_username_or_email,
        raising=False,
    )
    monkeypatch.setattr(auth_v1, "verify_password", fake_verify, raising=False)

    response = client.post(
        "/auth/login",
        json={"username": "bob", "password": hex_wrong},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"
    assert response.headers["www-authenticate"] == "Bearer"


def test_read_users_me_returns_current_user_payload(client, monkeypatch):
    """The /me endpoint is on the users router, not the auth router.
    We test it here by including the users router alongside auth."""
    from modules.api.v1 import users as users_v1
    from core.middleware.auth.dependencies import get_current_user

    app = FastAPI()
    app.include_router(auth_v1.router)
    app.include_router(users_v1.router)
    app.dependency_overrides[get_current_user] = lambda: {
        "uuid": "u-1",
        "real_name": "Alice",
        "user_role": "admin",
        "current_status": "normal",
    }

    async def fake_find_by_uuid(self, uuid):
        return {
            "uuid": uuid,
            "username": None,
            "email": None,
            "avatar_url": None,
            "nickname": "Alice",
            "real_name": "Alice",
            "class": None,
            "class_type": None,
            "joined_at": None,
            "current_status": "normal",
            "last_login_at": None,
            "score": 0,
            "user_role": "admin",
            "title": None,
            "invited_by": None,
            "views": 0,
            "is_verified": False,
        }

    monkeypatch.setattr(users_v1.UsersDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    test_client = TestClient(app)
    response = test_client.get("/users/me")

    assert response.status_code == 200
    data = response.json()
    assert data["uuid"] == "u-1"
    assert data["real_name"] == "Alice"
    assert data["user_role"] == "admin"


def test_refresh_token_success(client, monkeypatch):
    import hashlib
    plaintext = "valid-refresh-token"
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    record = {"user_uuid": "user-uuid-1", "token_hash": token_hash}

    async def fake_find_active(h):
        return record if h == token_hash else None

    async def fake_revoke(h):
        pass

    async def fake_create(user_uuid, token_hash):
        pass

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "find_active", fake_find_active, raising=False)
    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "revoke", fake_revoke, raising=False)
    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "create", fake_create, raising=False)
    # Mock UsersDAO().find_by_uuid to return a valid user (refresh now validates user)
    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "real_name": "Test", "current_status": "normal"}
    monkeypatch.setattr(auth_v1.UsersDAO, "find_by_uuid", fake_find_by_uuid, raising=False)
    monkeypatch.setattr(auth_v1, "create_access_token", lambda subject: "new-access-token")
    monkeypatch.setattr(
        auth_v1, "generate_refresh_token", lambda: ("new-refresh-token", "new-hash")
    )

    response = client.post("/auth/refresh", json={"refresh_token": plaintext})

    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "new-access-token"
    assert data["refresh_token"] == "new-refresh-token"
    assert data["token_type"] == "bearer"


def test_refresh_token_returns_401_for_unknown_token(client, monkeypatch):
    async def fake_find_active(h):
        return None

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "find_active", fake_find_active, raising=False)

    response = client.post("/auth/refresh", json={"refresh_token": "bogus-token"})

    assert response.status_code == 401
    assert response.json()["detail"] == "无效或已吊销的 Refresh Token"


def test_logout_revokes_refresh_token(client, monkeypatch):
    import hashlib
    plaintext = "my-refresh-token"
    expected_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    revoked_hashes = []

    async def fake_revoke(h):
        revoked_hashes.append(h)

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "revoke", fake_revoke, raising=False)
    client.app.dependency_overrides[auth_v1.get_current_user] = lambda: {"uuid": "u-1"}

    response = client.post(
        "/auth/logout",
        json={"refresh_token": plaintext},
        headers={"Authorization": "Bearer token"},
    )
    client.app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"message": "已登出"}
    assert expected_hash in revoked_hashes


def test_logout_requires_authentication(client):
    response = client.post(
        "/auth/logout",
        json={"refresh_token": "any-token"},
    )
    assert response.status_code == 401


def test_login_returns_403_when_disabled(client, monkeypatch):
    """disabled 状态的用户登录返回 403."""
    plain_password = "password123"
    hex_password = _sha256_hex(plain_password)
    hashed_password = _hash_password(hex_password)
    user = SimpleNamespace(
        uuid="user-uuid-disabled",
        password=hashed_password,
        current_status="disabled",
    )

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_v1.UsersDAO,
        "find_by_username_or_email",
        fake_find_by_username_or_email,
        raising=False,
    )
    # 跳过限流检查
    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 0)

    response = client.post(
        "/auth/login",
        json={"username": "disabled_user", "password": hex_password},
    )

    assert response.status_code == 403
    assert "账号已被禁用" in response.json()["detail"]


def test_login_returns_403_when_banned(client, monkeypatch):
    """banned 状态的用户登录返回 403."""
    plain_password = "password123"
    hex_password = _sha256_hex(plain_password)
    hashed_password = _hash_password(hex_password)
    user = SimpleNamespace(
        uuid="user-uuid-banned",
        password=hashed_password,
        current_status="banned",
    )

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_v1.UsersDAO,
        "find_by_username_or_email",
        fake_find_by_username_or_email,
        raising=False,
    )
    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 0)

    response = client.post(
        "/auth/login",
        json={"username": "banned_user", "password": hex_password},
    )

    assert response.status_code == 403
    assert "账号已被禁用" in response.json()["detail"]


def test_login_returns_429_when_ip_rate_limited(client, monkeypatch):
    """IP 级别限流：_login_redis_incr 返回超过 IP 阈值 → 429."""
    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 21 if "ip:" in key else 0)

    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": _sha256_hex("whatever")},
    )

    assert response.status_code == 429
    assert "过于频繁" in response.json()["detail"]


def test_login_returns_429_when_username_rate_limited(client, monkeypatch):
    """用户名级别限流：_login_redis_incr 返回超过用户名阈值 → 429."""
    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 6 if "un:" in key else 0)

    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": _sha256_hex("whatever")},
    )

    assert response.status_code == 429
    assert "过于频繁" in response.json()["detail"]


def test_refresh_returns_401_when_user_not_found(client, monkeypatch):
    """refresh 时用户不存在返回 401."""
    import hashlib

    plaintext = "some-refresh-token"
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    record = {"user_uuid": "nonexistent-uuid", "token_hash": token_hash}

    async def fake_find_active(h):
        return record if h == token_hash else None

    async def fake_find_by_uuid(self, uuid):
        return None

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "find_active", fake_find_active, raising=False)
    monkeypatch.setattr(auth_v1.UsersDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.post("/auth/refresh", json={"refresh_token": plaintext})

    assert response.status_code == 401
    assert response.json()["detail"] == "用户不存在"


def test_refresh_returns_401_when_user_disabled(client, monkeypatch):
    """refresh 时用户已被禁用返回 401."""
    import hashlib

    plaintext = "some-refresh-token"
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    record = {"user_uuid": "disabled-uuid", "token_hash": token_hash}

    async def fake_find_active(h):
        return record if h == token_hash else None

    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "current_status": "disabled"}

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "find_active", fake_find_active, raising=False)
    monkeypatch.setattr(auth_v1.UsersDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.post("/auth/refresh", json={"refresh_token": plaintext})

    assert response.status_code == 401
    assert response.json()["detail"] == "账号已被禁用"


def test_login_pending_deletion_recovers(client, monkeypatch):
    """pending_deletion 且在冷却期内的用户登录后自动恢复为 normal."""
    from datetime import datetime, timedelta

    plain_password = "password123"
    hex_password = _sha256_hex(plain_password)
    hashed_password = _hash_password(hex_password)
    future_deletion = datetime.now() + timedelta(days=15)
    user = SimpleNamespace(
        uuid="user-uuid-pending",
        password=hashed_password,
        current_status="pending_deletion",
        deletion_scheduled_at=future_deletion,
    )

    updated_data = {}

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    async def fake_update(self, uuid, data):
        updated_data.update(data)
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
    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 0)
    monkeypatch.setattr(auth_v1, "create_access_token", lambda subject: "mock-token-v1")
    monkeypatch.setattr(
        auth_v1, "generate_refresh_token", lambda: ("mock-refresh-token", "mock-hash")
    )
    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "create", fake_create_rt, raising=False)

    response = client.post(
        "/auth/login",
        json={"username": "pending_user", "password": hex_password},
    )

    assert response.status_code == 200
    # 验证 update 调用恢复了状态
    assert updated_data.get("current_status") == "normal"
    assert updated_data.get("deletion_scheduled_at") is None


def test_login_pending_deletion_expired(client, monkeypatch):
    """pending_deletion 且已过冷却期的用户登录返回 403."""
    from datetime import datetime, timedelta

    plain_password = "password123"
    hex_password = _sha256_hex(plain_password)
    hashed_password = _hash_password(hex_password)
    past_deletion = datetime.now() - timedelta(days=1)
    user = SimpleNamespace(
        uuid="user-uuid-expired",
        password=hashed_password,
        current_status="pending_deletion",
        deletion_scheduled_at=past_deletion,
    )

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_v1.UsersDAO,
        "find_by_username_or_email",
        fake_find_by_username_or_email,
        raising=False,
    )
    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 0)

    response = client.post(
        "/auth/login",
        json={"username": "expired_user", "password": hex_password},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "账号已永久注销"
