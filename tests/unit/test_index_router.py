"""Unit tests — modules.index.index (no database, no Redis)."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from modules.index.index import app as index_router, get_system_info


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client() -> TestClient:
    """Minimal app with only the index router; no lifespan DB/Redis setup."""
    app = FastAPI()
    app.include_router(index_router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET / — HTTP layer
# ---------------------------------------------------------------------------

def test_root_status_200(client):
    print("\n[TEST] GET / → 应返回 HTTP 200")
    assert client.get("/").status_code == 200


def test_root_content_type_json(client):
    print("\n[TEST] GET / → Content-Type 应为 application/json")
    assert "application/json" in client.get("/").headers["content-type"]


def test_root_has_required_fields(client):
    print("\n[TEST] GET / → 响应体应包含 name、system_time、system_version 字段")
    data = client.get("/").json()
    assert "name" in data
    assert "system_time" in data
    assert "system_version" in data


def test_root_app_name_is_tinder(client):
    print("\n[TEST] GET / → name 字段值应为 'Tinder'")
    assert client.get("/").json()["name"] == "Tinder"


# ---------------------------------------------------------------------------
# get_system_info — pure-function
# ---------------------------------------------------------------------------

def test_get_system_info_returns_dict():
    print("\n[TEST] get_system_info() → 应返回 dict 类型")
    assert isinstance(get_system_info(), dict)


def test_get_system_info_name_value():
    print("\n[TEST] get_system_info() → name 字段值应为 'Tinder'")
    assert get_system_info()["name"] == "Tinder"


def test_get_system_info_has_system_time():
    print("\n[TEST] get_system_info() → 应包含非空的 system_time")
    assert get_system_info()["system_time"] is not None


def test_get_system_info_has_system_version():
    print("\n[TEST] get_system_info() → system_version 应为字符串")
    assert isinstance(get_system_info()["system_version"], str)
