"""Unit tests — core.middleware.firewall.helpers (pure / stateless functions)."""

import json
from unittest.mock import MagicMock

from core.middleware.firewall.helpers import (
    build_reject_response,
    detect_attack,
    extract_token,
    get_client_ip,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mock_request(headers: dict | None = None, client_host: str | None = None,
                  query_params: dict | None = None):
    request = MagicMock()
    request.headers = headers or {}
    request.query_params = query_params or {}
    if client_host is not None:
        request.client = MagicMock()
        request.client.host = client_host
    else:
        request.client = None
    return request


# ---------------------------------------------------------------------------
# detect_attack — XSS
# ---------------------------------------------------------------------------

def test_detect_attack_xss_script_tag():
    print("\n[TEST] detect_attack: <script> 标签 → 识别为 xss")
    assert detect_attack("<script>alert(1)</script>") == "xss"


def test_detect_attack_xss_javascript_scheme():
    print("\n[TEST] detect_attack: javascript: 协议 → 识别为 xss")
    assert detect_attack("javascript:alert(1)") == "xss"


def test_detect_attack_xss_onerror_attribute():
    print("\n[TEST] detect_attack: onerror= 属性 → 识别为 xss")
    assert detect_attack('<img src=x onerror="alert(1)">') == "xss"


# ---------------------------------------------------------------------------
# detect_attack — SQL Injection
# ---------------------------------------------------------------------------

def test_detect_attack_sqli_select_from():
    print("\n[TEST] detect_attack: SELECT ... FROM ... → 识别为 sql_injection")
    assert detect_attack("SELECT * FROM users WHERE id=1") == "sql_injection"


def test_detect_attack_sqli_or_clause():
    print("\n[TEST] detect_attack: OR '1'='1 → 识别为 sql_injection")
    assert detect_attack("' OR '1'='1") == "sql_injection"


def test_detect_attack_sqli_comment():
    print("\n[TEST] detect_attack: SQL 注释符 -- → 识别为 sql_injection")
    assert detect_attack("admin'--") == "sql_injection"


# ---------------------------------------------------------------------------
# detect_attack — safe inputs
# ---------------------------------------------------------------------------

def test_detect_attack_safe_api_path():
    print("\n[TEST] detect_attack: 正常 API 路径 → 返回 None")
    assert detect_attack("/api/v1/users") is None


def test_detect_attack_empty_string():
    print("\n[TEST] detect_attack: 空字符串 → 返回 None")
    assert detect_attack("") is None


# ---------------------------------------------------------------------------
# get_client_ip — header precedence
# ---------------------------------------------------------------------------

def test_get_client_ip_x_forwarded_for_first():
    print("\n[TEST] get_client_ip: X-Forwarded-For 优先级最高，取第一个地址")
    request = mock_request(headers={"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
    assert get_client_ip(request) == "1.2.3.4"


def test_get_client_ip_x_real_ip_fallback():
    print("\n[TEST] get_client_ip: 无 X-Forwarded-For 时使用 X-Real-IP")
    request = mock_request(headers={"X-Real-IP": " 10.0.0.1 "})
    assert get_client_ip(request) == "10.0.0.1"


def test_get_client_ip_client_host_fallback():
    print("\n[TEST] get_client_ip: 无代理头时使用 request.client.host")
    request = mock_request(client_host="192.168.1.100")
    assert get_client_ip(request) == "192.168.1.100"


def test_get_client_ip_unknown_when_no_info():
    print("\n[TEST] get_client_ip: 无任何来源信息时返回 'unknown'")
    request = mock_request()
    assert get_client_ip(request) == "unknown"


# ---------------------------------------------------------------------------
# extract_token
# ---------------------------------------------------------------------------

def test_extract_token_from_bearer_header():
    print("\n[TEST] extract_token: 从 Authorization: Bearer <token> 头中提取 token")
    token_value = "mytoken123"
    request = mock_request(headers={"Authorization": f"Bearer {token_value}"})
    assert extract_token(request) == token_value


def test_extract_token_from_query_param():
    print("\n[TEST] extract_token: 从查询参数 ?token= 中提取 token")
    request = mock_request(query_params={"token": "querytoken456"})
    assert extract_token(request) == "querytoken456"


def test_extract_token_returns_none_when_absent():
    print("\n[TEST] extract_token: 无 token 时返回 None")
    request = mock_request()
    assert extract_token(request) is None


def test_extract_token_ignores_non_bearer_auth():
    print("\n[TEST] extract_token: Basic 认证头不提取 token，返回 None")
    request = mock_request(headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert extract_token(request) is None


# ---------------------------------------------------------------------------
# build_reject_response
# ---------------------------------------------------------------------------

def test_build_reject_response_status_403():
    print("\n[TEST] build_reject_response: 返回 HTTP 403 状态码")
    response = build_reject_response("Forbidden")
    assert response.status_code == 403


def test_build_reject_response_body_detail():
    print("\n[TEST] build_reject_response: 响应体中包含 detail 字段")
    response = build_reject_response("You are banned")
    body = json.loads(response.body)
    assert body["detail"] == "You are banned"
