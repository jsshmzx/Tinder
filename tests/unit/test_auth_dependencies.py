"""Unit tests — core.middleware.auth.dependencies (mocked, no DB/Redis)."""

from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from core.middleware.auth.dependencies import (
    RoleChecker,
    MinRoleChecker,
    get_temp_user,
    invalidate_user_cache,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_get_current_user(user=None):
    if user is None:
        user = {
            "uuid": "user-1",
            "user_role": "superadmin",
            "current_status": "normal",
        }
    return lambda: user


# ---------------------------------------------------------------------------
# RoleChecker
# ---------------------------------------------------------------------------

def test_role_checker_allows_when_role_matches(monkeypatch):
    """RoleChecker allows when user has the exact allowed role."""
    from modules.api.v1 import auth as auth_v1

    app = FastAPI()

    @app.get("/protected")
    async def protected(user: dict = Depends(RoleChecker(["superadmin"]))):
        return {"user": user["uuid"], "role": user["user_role"]}

    app.dependency_overrides[auth_v1.get_current_user] = lambda: {
        "uuid": "u-super",
        "user_role": "superadmin",
        "current_status": "normal",
    }

    client = TestClient(app)
    resp = client.get("/protected")
    assert resp.status_code == 200
    assert resp.json()["role"] == "superadmin"


def test_role_checker_allows_higher_role(monkeypatch):
    """superadmin passes a songlist_editor gate."""
    from modules.api.v1 import auth as auth_v1

    app = FastAPI()

    @app.get("/protected")
    async def protected(user: dict = Depends(RoleChecker(["songlist_editor"]))):
        return {"role": user["user_role"]}

    app.dependency_overrides[auth_v1.get_current_user] = lambda: {
        "uuid": "u-super",
        "user_role": "superadmin",
        "current_status": "normal",
    }

    client = TestClient(app)
    resp = client.get("/protected")
    assert resp.status_code == 200
    assert resp.json()["role"] == "superadmin"


def test_role_checker_blocks_lower_role(monkeypatch):
    """normal-user fails a songlist_editor gate."""
    from modules.api.v1 import auth as auth_v1

    app = FastAPI()

    @app.get("/protected")
    async def protected(user: dict = Depends(RoleChecker(["songlist_editor"]))):
        return {"role": user["user_role"]}

    app.dependency_overrides[auth_v1.get_current_user] = lambda: {
        "uuid": "u-normal",
        "user_role": "normal-user",
        "current_status": "normal",
    }

    client = TestClient(app)
    resp = client.get("/protected")
    assert resp.status_code == 403


def test_role_checker_multiple_allowed_roles(monkeypatch):
    """With multiple allowed roles, user passes if >= min level."""
    from modules.api.v1 import auth as auth_v1

    app = FastAPI()

    @app.get("/protected")
    async def protected(user: dict = Depends(RoleChecker(["normal-user", "superadmin"]))):
        return {"role": user["user_role"]}

    # songlist_editor should pass because min allowed is normal-user
    app.dependency_overrides[auth_v1.get_current_user] = lambda: {
        "uuid": "u-editor",
        "user_role": "songlist_editor",
        "current_status": "normal",
    }

    client = TestClient(app)
    resp = client.get("/protected")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# MinRoleChecker
# ---------------------------------------------------------------------------

def test_min_role_checker_passes_superadmin_for_superadmin(monkeypatch):
    from modules.api.v1 import auth as auth_v1

    app = FastAPI()

    @app.get("/admin")
    async def endpoint(user: dict = Depends(MinRoleChecker("superadmin"))):
        return {"role": user["user_role"]}

    app.dependency_overrides[auth_v1.get_current_user] = lambda: {
        "uuid": "u-1",
        "user_role": "superadmin",
        "current_status": "normal",
    }

    client = TestClient(app)
    resp = client.get("/admin")
    assert resp.status_code == 200


def test_min_role_checker_passes_superadmin_for_songlist_editor(monkeypatch):
    from modules.api.v1 import auth as auth_v1

    app = FastAPI()

    @app.get("/editor")
    async def endpoint(user: dict = Depends(MinRoleChecker("songlist_editor"))):
        return {"role": user["user_role"]}

    app.dependency_overrides[auth_v1.get_current_user] = lambda: {
        "uuid": "u-1",
        "user_role": "superadmin",
        "current_status": "normal",
    }

    client = TestClient(app)
    resp = client.get("/editor")
    assert resp.status_code == 200


def test_min_role_checker_blocks_normal_user_for_songlist_editor(monkeypatch):
    from modules.api.v1 import auth as auth_v1

    app = FastAPI()

    @app.get("/editor")
    async def endpoint(user: dict = Depends(MinRoleChecker("songlist_editor"))):
        return {"role": user["user_role"]}

    app.dependency_overrides[auth_v1.get_current_user] = lambda: {
        "uuid": "u-1",
        "user_role": "normal-user",
        "current_status": "normal",
    }

    client = TestClient(app)
    resp = client.get("/editor")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# invalidate_user_cache
# ---------------------------------------------------------------------------

def test_invalidate_user_cache_no_redis(monkeypatch):
    """When Redis is unavailable, invalidate_user_cache does nothing silently."""
    monkeypatch.setattr(
        "core.middleware.auth.dependencies.redis_conn",
        SimpleNamespace(get_client=lambda: None),
    )
    # Should not raise
    invalidate_user_cache("any-uuid")


def test_invalidate_user_cache_calls_redis_delete(monkeypatch):
    """When Redis is available, it calls delete on the cache key."""
    deleted_keys = []

    class FakeRedisClient:
        def delete(self, *keys):
            deleted_keys.extend(keys)

    class FakeRedisConn:
        def get_client(self):
            return FakeRedisClient()

    monkeypatch.setattr(
        "core.middleware.auth.dependencies.redis_conn",
        FakeRedisConn(),
    )
    invalidate_user_cache("target-uuid")
    assert "auth:user:target-uuid" in deleted_keys


# ---------------------------------------------------------------------------
# get_temp_user
# ---------------------------------------------------------------------------

def test_get_temp_user_valid_token(monkeypatch):
    """get_temp_user succeeds with a valid temp token that has purpose='register_complete'."""
    # Ensure JWT_SECRET_KEY is set
    monkeypatch.setattr("core.config.settings.JWT_SECRET_KEY", "test-jwt-secret-for-unit-tests")

    from core.security.jwt_handler import create_temp_token
    from core.database.dao.users import UsersDAO

    token = create_temp_token("user-temp-1", "register_complete", expires_minutes=10)

    async def fake_find_by_uuid(self, uuid):
        if uuid == "user-temp-1":
            return {"uuid": uuid, "nickname": "TempUser"}
        return None

    monkeypatch.setattr(UsersDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    app = FastAPI()

    @app.get("/temp")
    async def endpoint(user: dict = Depends(get_temp_user)):
        return user

    client = TestClient(app)
    resp = client.get("/temp", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["uuid"] == "user-temp-1"


def test_get_temp_user_wrong_purpose_returns_401(monkeypatch):
    """A regular access token (no purpose) is rejected by get_temp_user."""
    monkeypatch.setattr("core.config.settings.JWT_SECRET_KEY", "test-jwt-secret-for-unit-tests")

    from core.security.jwt_handler import create_access_token

    token = create_access_token("user-1")

    app = FastAPI()

    @app.get("/temp")
    async def endpoint(user: dict = Depends(get_temp_user)):
        return user

    client = TestClient(app)
    resp = client.get("/temp", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
