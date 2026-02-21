"""Integration tests for the / (root) endpoint via FastAPI TestClient."""

from modules.index.index import get_system_info


# ---------------------------------------------------------------------------
# Tests using the shared `client` fixture from conftest.py
# ---------------------------------------------------------------------------


def test_root_returns_200(client):
    response = client.get("/")
    assert response.status_code == 200


def test_root_returns_json_content_type(client):
    response = client.get("/")
    assert "application/json" in response.headers["content-type"]


def test_root_response_has_required_fields(client):
    data = client.get("/").json()
    assert "name" in data
    assert "system_time" in data
    assert "system_version" in data


def test_root_app_name_is_tinder(client):
    data = client.get("/").json()
    assert data["name"] == "Tinder"


# ---------------------------------------------------------------------------
# Pure-unit tests for get_system_info helper
# ---------------------------------------------------------------------------


def test_get_system_info_returns_dict():
    info = get_system_info()
    assert isinstance(info, dict)


def test_get_system_info_name():
    assert get_system_info()["name"] == "Tinder"


def test_get_system_info_has_system_time():
    info = get_system_info()
    assert "system_time" in info
    assert info["system_time"] is not None


def test_get_system_info_has_system_version():
    info = get_system_info()
    assert "system_version" in info
    assert isinstance(info["system_version"], str)
