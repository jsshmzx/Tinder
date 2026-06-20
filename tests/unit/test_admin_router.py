"""Unit tests — modules.api.v1.admin (mocked dependencies, no DB/Redis)."""

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from modules.api.v1 import admin as admin_v1
from core.middleware.auth.dependencies import get_current_user
from core.database.connection.pgsql import get_session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _fake_session(*args, **kwargs):
    """A no-op async context manager that yields a fake session."""
    yield SimpleNamespace()


@pytest.fixture()
def admin_client(monkeypatch):
    """Build a TestClient with get_current_user overridden to superadmin."""
    user = {
        "uuid": "admin-uuid",
        "user_role": "superadmin",
        "current_status": "normal",
    }

    app = FastAPI()
    app.include_router(admin_v1.router)
    app.dependency_overrides[get_current_user] = lambda: user

    # Wire get_session to our fake
    monkeypatch.setattr(admin_v1, "get_session", _fake_session)

    return TestClient(app)


async def _mock_search_users(session, keyword=None, status=None, role=None, limit=100, offset=0):
    return [
        {"uuid": "u-1", "nickname": "Alice", "user_role": "normal-user"},
        {"uuid": "u-2", "nickname": "Bob", "user_role": "normal-user"},
    ]


async def _mock_count_users(session, keyword=None, status=None, role=None):
    return 2


async def _mock_get_user_stats(session):
    return {"total": 2, "normal": 1, "disabled": 0, "banned": 0, "pending_deletion": 0}


async def _mock_create(self, data):
    return {**data, "uuid": "new-uuid", "created": True}


async def _mock_update(self, uuid, data):
    if uuid == "nonexistent-uuid":
        return None
    return {"uuid": uuid, **data, "updated": True}


async def _mock_delete(self, uuid):
    if uuid == "nonexistent-uuid":
        return False
    return True


def _mock_invalidate(*args, **kwargs):
    pass


# ---------------------------------------------------------------------------
# GET /admin/users
# ---------------------------------------------------------------------------


def test_admin_list_users_returns_list(admin_client, monkeypatch):
    monkeypatch.setattr(admin_v1.UsersDAO, "search_users", _mock_search_users, raising=False)

    resp = admin_client.get("/admin/users")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["uuid"] == "u-1"


def test_admin_list_users_requires_superadmin(admin_client, monkeypatch):
    """A normal-user should be blocked."""
    admin_client.app.dependency_overrides[get_current_user] = lambda: {
        "uuid": "u-normal",
        "user_role": "normal-user",
        "current_status": "normal",
    }
    resp = admin_client.get("/admin/users")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /admin/users/stats
# ---------------------------------------------------------------------------


def test_admin_users_stats(admin_client, monkeypatch):
    monkeypatch.setattr(admin_v1.UsersDAO, "get_user_stats", _mock_get_user_stats, raising=False)

    resp = admin_client.get("/admin/users/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2


# ---------------------------------------------------------------------------
# POST /admin/users
# ---------------------------------------------------------------------------


def test_admin_create_user(admin_client, monkeypatch):
    monkeypatch.setattr(admin_v1.UsersDAO, "create", _mock_create, raising=False)
    monkeypatch.setattr(admin_v1, "invalidate_user_cache", _mock_invalidate)

    resp = admin_client.post(
        "/admin/users",
        json={"nickname": "NewUser", "user_role": "normal-user"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["uuid"] == "new-uuid"
    assert data["nickname"] == "NewUser"


def test_admin_create_user_hashes_password(admin_client, monkeypatch):
    """When payload contains password, get_password_hash is called on it."""
    captured_passwords = []

    async def capture_create(self, data):
        if "password" in data:
            captured_passwords.append(data["password"])
        return {**data, "uuid": "new-uuid"}

    monkeypatch.setattr(admin_v1.UsersDAO, "create", capture_create, raising=False)
    monkeypatch.setattr(admin_v1, "invalidate_user_cache", _mock_invalidate)

    # Patch get_password_hash to capture the value it receives
    captured_input = []

    def capture_hash(password):
        captured_input.append(password)
        return password  # pass-through (real impl returns hex as-is)

    monkeypatch.setattr(admin_v1, "get_password_hash", capture_hash, raising=False)

    resp = admin_client.post(
        "/admin/users",
        json={"nickname": "SecureUser", "password": "secret123"},
    )
    assert resp.status_code == 200
    # get_password_hash should have been called with the plain password
    assert len(captured_input) == 1
    assert captured_input[0] == "secret123"
    # The stored password in create payload should be the hashed value
    assert len(captured_passwords) == 1
    assert captured_passwords[0] == "secret123"  # hash is pass-through


# ---------------------------------------------------------------------------
# PATCH /admin/users/{user_uuid}
# ---------------------------------------------------------------------------


def test_admin_update_user(admin_client, monkeypatch):
    monkeypatch.setattr(admin_v1.UsersDAO, "update", _mock_update, raising=False)
    monkeypatch.setattr(admin_v1, "invalidate_user_cache", _mock_invalidate)

    resp = admin_client.patch(
        "/admin/users/u-1",
        json={"nickname": "UpdatedName"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["uuid"] == "u-1"
    assert data["nickname"] == "UpdatedName"


def test_admin_update_user_returns_404_when_not_found(admin_client, monkeypatch):
    monkeypatch.setattr(admin_v1.UsersDAO, "update", _mock_update, raising=False)

    resp = admin_client.patch(
        "/admin/users/nonexistent-uuid",
        json={"nickname": "Ghost"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /admin/users/{user_uuid}
# ---------------------------------------------------------------------------


def test_admin_delete_user(admin_client, monkeypatch):
    monkeypatch.setattr(admin_v1.UsersDAO, "delete", _mock_delete, raising=False)
    monkeypatch.setattr(admin_v1, "invalidate_user_cache", _mock_invalidate)

    resp = admin_client.delete("/admin/users/u-1")
    assert resp.status_code == 200
    assert resp.json()["success"] is True


def test_admin_delete_user_returns_404(admin_client, monkeypatch):
    monkeypatch.setattr(admin_v1.UsersDAO, "delete", _mock_delete, raising=False)

    resp = admin_client.delete("/admin/users/nonexistent-uuid")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /admin/users/{user_uuid}/disable
# ---------------------------------------------------------------------------

def test_admin_disable_user(admin_client, monkeypatch):
    async def capture_update(self, uuid, data):
        return {"uuid": uuid, **data}

    monkeypatch.setattr(admin_v1.UsersDAO, "update", capture_update, raising=False)
    monkeypatch.setattr(admin_v1, "invalidate_user_cache", _mock_invalidate)

    resp = admin_client.post("/admin/users/u-1/disable")
    assert resp.status_code == 200
    data = resp.json()
    assert data["current_status"] == "disabled"


def test_admin_disable_user_returns_404(admin_client, monkeypatch):
    async def capture_update(self, uuid, data):
        if uuid == "nonexistent-uuid":
            return None
        return {"uuid": uuid, **data}

    monkeypatch.setattr(admin_v1.UsersDAO, "update", capture_update, raising=False)

    resp = admin_client.post("/admin/users/nonexistent-uuid/disable")
    assert resp.status_code == 404


def test_admin_disable_user_requires_superadmin(admin_client, monkeypatch):
    admin_client.app.dependency_overrides[get_current_user] = lambda: {
        "uuid": "u-normal",
        "user_role": "normal-user",
        "current_status": "normal",
    }
    resp = admin_client.post("/admin/users/u-1/disable")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /admin/users/{user_uuid}/enable
# ---------------------------------------------------------------------------

def test_admin_enable_user(admin_client, monkeypatch):
    async def capture_update(self, uuid, data):
        return {"uuid": uuid, **data}

    monkeypatch.setattr(admin_v1.UsersDAO, "update", capture_update, raising=False)
    monkeypatch.setattr(admin_v1, "invalidate_user_cache", _mock_invalidate)

    resp = admin_client.post("/admin/users/u-1/enable")
    assert resp.status_code == 200
    data = resp.json()
    assert data["current_status"] == "normal"


# ---------------------------------------------------------------------------
# POST /admin/users/{user_uuid}/ban
# ---------------------------------------------------------------------------

def test_admin_ban_user(admin_client, monkeypatch):
    async def capture_update(self, uuid, data):
        return {"uuid": uuid, **data}

    monkeypatch.setattr(admin_v1.UsersDAO, "update", capture_update, raising=False)
    monkeypatch.setattr(admin_v1, "invalidate_user_cache", _mock_invalidate)

    resp = admin_client.post("/admin/users/u-1/ban")
    assert resp.status_code == 200
    data = resp.json()
    assert data["current_status"] == "banned"


# ---------------------------------------------------------------------------
# POST /admin/users/{user_uuid}/unban
# ---------------------------------------------------------------------------

def test_admin_unban_user(admin_client, monkeypatch):
    async def capture_update(self, uuid, data):
        return {"uuid": uuid, **data}

    monkeypatch.setattr(admin_v1.UsersDAO, "update", capture_update, raising=False)
    monkeypatch.setattr(admin_v1, "invalidate_user_cache", _mock_invalidate)

    resp = admin_client.post("/admin/users/u-1/unban")
    assert resp.status_code == 200
    data = resp.json()
    assert data["current_status"] == "normal"
