"""Unit tests — core.middleware.log_context.LogContextMiddleware."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.helper.CustomLog.index import get_log_context
from core.middleware.log_context import LogContextMiddleware


def _build_client():
    app = FastAPI()
    app.add_middleware(LogContextMiddleware)

    @app.get("/context")
    def read_context():
        ctx = get_log_context()
        return {
            "trace_id": ctx.trace_id,
            "client_ip": ctx.client_ip,
            "user_agent": ctx.user_agent,
            "request_method": ctx.request_method,
            "request_url": ctx.request_url,
            "user_uuid": ctx.user_uuid,
        }

    return TestClient(app)


def test_log_context_middleware_sets_trace_id_and_request_meta():
    client = _build_client()
    resp = client.get("/context", headers={"User-Agent": "test-ua"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["trace_id"] is not None
    assert len(data["trace_id"]) == 36  # UUID4
    assert data["client_ip"] == "testclient"
    assert data["user_agent"] == "test-ua"
    assert data["request_method"] == "GET"
    assert data["request_url"].endswith("/context")
    assert data["user_uuid"] is None


def test_log_context_middleware_resolves_user_uuid_from_token():
    from core.security.jwt_handler import create_access_token

    token = create_access_token("user-uuid-123")
    client = _build_client()
    resp = client.get(
        "/context",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["user_uuid"] == "user-uuid-123"
