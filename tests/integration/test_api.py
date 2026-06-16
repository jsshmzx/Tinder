"""Integration tests — API endpoints with real PostgreSQL + Redis backend.

Covers:
  * GET / returns 200 with expected JSON shape (through full app stack)
  * Non-existent routes return 404
"""

import pytest


def test_root_status_200(integration_client):
    """GET / should return HTTP 200 through the full application stack."""
    assert integration_client.get("/").status_code == 200


def test_root_json_fields(integration_client):
    """Response body should contain name, system_time, system_version fields."""
    data = integration_client.get("/").json()
    assert "name" in data
    assert "system_time" in data
    assert "system_version" in data


def test_root_app_name(integration_client):
    """name field should equal 'Tinder'."""
    assert integration_client.get("/").json()["name"] == "Tinder"


def test_root_content_type(integration_client):
    """Content-Type header should be application/json."""
    assert "application/json" in integration_client.get("/").headers["content-type"]


def test_unknown_route_returns_404(integration_client):
    """Unknown routes should return 404."""
    assert integration_client.get("/nonexistent").status_code == 404
