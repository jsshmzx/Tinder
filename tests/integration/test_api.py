"""Integration tests — API endpoints with real PostgreSQL + Redis backend.

Covers:
  * GET / returns 200 with expected JSON shape (through full app stack)
  * Non-existent routes return 404
"""

import pytest


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------

def test_root_status_200(integration_client):
    print("\n[TEST][API] GET / → 完整应用栈下应返回 HTTP 200")
    assert integration_client.get("/").status_code == 200


def test_root_json_fields(integration_client):
    print("\n[TEST][API] GET / → 响应体应包含 name、system_time、system_version 字段")
    data = integration_client.get("/").json()
    assert "name" in data
    assert "system_time" in data
    assert "system_version" in data


def test_root_app_name(integration_client):
    print("\n[TEST][API] GET / → name 字段值应为 'Tinder'")
    assert integration_client.get("/").json()["name"] == "Tinder"


def test_root_content_type(integration_client):
    print("\n[TEST][API] GET / → Content-Type 应为 application/json")
    assert "application/json" in integration_client.get("/").headers["content-type"]


# ---------------------------------------------------------------------------
# 404 for unknown routes
# ---------------------------------------------------------------------------

def test_unknown_route_returns_404(integration_client):
    print("\n[TEST][API] GET /nonexistent → 应返回 HTTP 404")
    assert integration_client.get("/nonexistent").status_code == 404
