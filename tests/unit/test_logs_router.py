"""Unit tests — modules.api.v1.logs (mocked DAOs, no DB)."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.middleware.auth.dependencies import get_current_user
from modules.api.v1 import logs as logs_v1


def _build_client(user: dict):
    app = FastAPI()
    app.include_router(logs_v1.router)
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def test_system_logs_requires_superadmin(monkeypatch):
    async def fake_search(*args, **kwargs):
        return [], 0
    monkeypatch.setattr(logs_v1.SystemLogsDAO, "search", fake_search, raising=False)

    client = _build_client({"uuid": "u-1", "user_role": "normal-user"})
    resp = client.get("/logs/system")
    assert resp.status_code == 403


def test_system_logs_returns_paginated_response(monkeypatch):
    async def fake_search(*args, **kwargs):
        return [{"uuid": "log-1", "event_type": "TEST"}], 1
    monkeypatch.setattr(logs_v1.SystemLogsDAO, "search", fake_search, raising=False)

    client = _build_client({"uuid": "admin-1", "user_role": "superadmin"})
    resp = client.get("/logs/system")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["uuid"] == "log-1"


def test_personal_logs_normal_user_can_query_self(monkeypatch):
    captured = {}

    async def fake_search(*args, **kwargs):
        captured["user_uuids"] = kwargs.get("user_uuids")
        return [{"uuid": "log-1", "user_uuid": "u-1"}], 1
    monkeypatch.setattr(logs_v1.PersonalLogsDAO, "search", fake_search, raising=False)

    client = _build_client({"uuid": "u-1", "user_role": "normal-user"})
    resp = client.get("/logs/personal")
    assert resp.status_code == 200
    assert captured["user_uuids"] == ["u-1"]


def test_personal_logs_normal_user_cannot_query_others(monkeypatch):
    async def fake_search(*args, **kwargs):
        return [], 0
    monkeypatch.setattr(logs_v1.PersonalLogsDAO, "search", fake_search, raising=False)

    client = _build_client({"uuid": "u-1", "user_role": "normal-user"})
    resp = client.get("/logs/personal?user_uuid=u-2")
    assert resp.status_code == 403


def test_personal_logs_admin_can_query_specific_user(monkeypatch):
    captured = {}

    async def fake_search(*args, **kwargs):
        captured["user_uuids"] = kwargs.get("user_uuids")
        return [{"uuid": "log-1", "user_uuid": "u-2"}], 1
    monkeypatch.setattr(logs_v1.PersonalLogsDAO, "search", fake_search, raising=False)

    client = _build_client({"uuid": "admin-1", "user_role": "superadmin"})
    resp = client.get("/logs/personal?user_uuid=u-2")
    assert resp.status_code == 200
    assert captured["user_uuids"] == ["u-2"]


def test_personal_logs_by_user_path_normal_user_blocked(monkeypatch):
    async def fake_search(*args, **kwargs):
        return [], 0
    monkeypatch.setattr(logs_v1.PersonalLogsDAO, "search", fake_search, raising=False)

    client = _build_client({"uuid": "u-1", "user_role": "normal-user"})
    resp = client.get("/logs/personal/u-2")
    assert resp.status_code == 403


def test_personal_logs_by_user_path_admin_allowed(monkeypatch):
    captured = {}

    async def fake_search(*args, **kwargs):
        captured["user_uuids"] = kwargs.get("user_uuids")
        return [{"uuid": "log-1", "user_uuid": "u-2"}], 1
    monkeypatch.setattr(logs_v1.PersonalLogsDAO, "search", fake_search, raising=False)

    client = _build_client({"uuid": "admin-1", "user_role": "superadmin"})
    resp = client.get("/logs/personal/u-2")
    assert resp.status_code == 200
    assert captured["user_uuids"] == ["u-2"]
