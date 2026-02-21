"""Unit tests for core.middleware.firewall.helpers (pure/stateless functions only)."""

import json
from unittest.mock import MagicMock

from core.middleware.firewall.helpers import (
    build_reject_response,
    detect_attack,
    extract_token,
    get_client_ip,
)


# ---------------------------------------------------------------------------
# detect_attack
# ---------------------------------------------------------------------------


def test_detect_attack_xss_script_tag():
    assert detect_attack("<script>alert(1)</script>") == "xss"


def test_detect_attack_xss_javascript_scheme():
    assert detect_attack("javascript:alert(1)") == "xss"


def test_detect_attack_xss_onerror_attribute():
    assert detect_attack('<img src=x onerror="alert(1)">') == "xss"


def test_detect_attack_sql_injection_select():
    assert detect_attack("SELECT * FROM users WHERE id=1") == "sql_injection"


def test_detect_attack_sql_injection_or_clause():
    assert detect_attack("' OR '1'='1") == "sql_injection"


def test_detect_attack_sql_injection_comment():
    assert detect_attack("admin'--") == "sql_injection"


def test_detect_attack_safe_path():
    assert detect_attack("/api/v1/users") is None


def test_detect_attack_empty_string():
    assert detect_attack("") is None


# ---------------------------------------------------------------------------
# get_client_ip
# ---------------------------------------------------------------------------


def _mock_request(headers: dict | None = None, client_host: str | None = None):
    request = MagicMock()
    request.headers = headers or {}
    if client_host is not None:
        request.client = MagicMock()
        request.client.host = client_host
    else:
        request.client = None
    return request


def test_get_client_ip_prefers_x_forwarded_for():
    request = _mock_request(headers={"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
    assert get_client_ip(request) == "1.2.3.4"


def test_get_client_ip_falls_back_to_x_real_ip():
    request = _mock_request(headers={"X-Real-IP": " 10.0.0.1 "})
    assert get_client_ip(request) == "10.0.0.1"


def test_get_client_ip_falls_back_to_client_host():
    request = _mock_request(client_host="192.168.1.100")
    assert get_client_ip(request) == "192.168.1.100"


def test_get_client_ip_returns_unknown_when_no_info():
    request = _mock_request()
    assert get_client_ip(request) == "unknown"


# ---------------------------------------------------------------------------
# extract_token
# ---------------------------------------------------------------------------


def test_extract_token_from_bearer_header():
    request = MagicMock()
    request.headers = {"Authorization": "Bearer mytoken123"}
    assert extract_token(request) == "mytoken123"


def test_extract_token_from_query_param():
    request = MagicMock()
    request.headers = {}
    request.query_params = {"token": "querytoken456"}
    assert extract_token(request) == "querytoken456"


def test_extract_token_returns_none_when_absent():
    request = MagicMock()
    request.headers = {}
    request.query_params = {}
    assert extract_token(request) is None


def test_extract_token_ignores_non_bearer_auth():
    request = MagicMock()
    request.headers = {"Authorization": "Basic dXNlcjpwYXNz"}
    request.query_params = {}
    assert extract_token(request) is None


# ---------------------------------------------------------------------------
# build_reject_response
# ---------------------------------------------------------------------------


def test_build_reject_response_status_code():
    response = build_reject_response("Forbidden")
    assert response.status_code == 403


def test_build_reject_response_body_contains_detail():
    response = build_reject_response("You are banned")
    body = json.loads(response.body)
    assert body["detail"] == "You are banned"
