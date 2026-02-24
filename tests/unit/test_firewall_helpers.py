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
# detect_attack — XSS（增强检测）
# ---------------------------------------------------------------------------

def test_detect_attack_xss_svg_onload():
    print("\n[TEST] detect_attack: <svg onload=...> → 识别为 xss")
    assert detect_attack('<svg onload="alert(1)">') == "xss"


def test_detect_attack_xss_data_uri():
    print("\n[TEST] detect_attack: data:text/html → 识别为 xss")
    assert detect_attack("data:text/html,<script>alert(1)</script>") == "xss"


def test_detect_attack_xss_document_write():
    print("\n[TEST] detect_attack: document.write → 识别为 xss")
    assert detect_attack('document.write("xss")') == "xss"


def test_detect_attack_xss_innerhtml():
    print("\n[TEST] detect_attack: .innerHTML= → 识别为 xss")
    assert detect_attack('el.innerHTML="<img src=x>"') == "xss"


def test_detect_attack_xss_fromcharcode():
    print("\n[TEST] detect_attack: String.fromCharCode → 识别为 xss")
    assert detect_attack("String.fromCharCode(88,83,83)") == "xss"


def test_detect_attack_xss_prompt():
    print("\n[TEST] detect_attack: prompt() → 识别为 xss")
    assert detect_attack("prompt(1)") == "xss"


# ---------------------------------------------------------------------------
# detect_attack — SQL 注入（增强检测）
# ---------------------------------------------------------------------------

def test_detect_attack_sqli_union_all_select():
    print("\n[TEST] detect_attack: UNION ALL SELECT → 识别为 sql_injection")
    assert detect_attack("1 UNION ALL SELECT 1,2,3") == "sql_injection"


def test_detect_attack_sqli_sleep():
    print("\n[TEST] detect_attack: SLEEP(5) → 识别为 sql_injection")
    assert detect_attack("1 AND SLEEP(5)") == "sql_injection"


def test_detect_attack_sqli_benchmark():
    print("\n[TEST] detect_attack: BENCHMARK() → 识别为 sql_injection")
    assert detect_attack("BENCHMARK(10000000,SHA1('test'))") == "sql_injection"


def test_detect_attack_sqli_load_file():
    print("\n[TEST] detect_attack: LOAD_FILE() → 识别为 sql_injection")
    assert detect_attack("LOAD_FILE('/etc/passwd')") == "sql_injection"


def test_detect_attack_sqli_information_schema():
    print("\n[TEST] detect_attack: information_schema → 识别为 sql_injection")
    assert detect_attack("SELECT table_name FROM information_schema.tables") == "sql_injection"


def test_detect_attack_sqli_hex_encoding():
    print("\n[TEST] detect_attack: 长十六进制字面量 → 识别为 sql_injection")
    assert detect_attack("0x41424344454647") == "sql_injection"


# ---------------------------------------------------------------------------
# detect_attack — 路径穿越
# ---------------------------------------------------------------------------

def test_detect_attack_path_traversal_dotdot_slash():
    print("\n[TEST] detect_attack: ../../etc/passwd → 识别为 path_traversal")
    assert detect_attack("../../etc/passwd") == "path_traversal"


def test_detect_attack_path_traversal_encoded():
    print("\n[TEST] detect_attack: URL 编码的 ../ → 识别为 path_traversal")
    assert detect_attack("%2e%2e%2f%2e%2e%2f") == "path_traversal"


def test_detect_attack_path_traversal_etc_shadow():
    print("\n[TEST] detect_attack: /etc/shadow → 识别为 path_traversal")
    assert detect_attack("/etc/shadow") == "path_traversal"


def test_detect_attack_path_traversal_dotenv():
    print("\n[TEST] detect_attack: /.env → 识别为 path_traversal")
    assert detect_attack("/.env") == "path_traversal"


def test_detect_attack_path_traversal_git():
    print("\n[TEST] detect_attack: /.git/ → 识别为 path_traversal")
    assert detect_attack("/.git/config") == "path_traversal"


def test_detect_attack_path_traversal_windows():
    print("\n[TEST] detect_attack: \\windows\\ → 识别为 path_traversal")
    assert detect_attack("..\\windows\\system32") == "path_traversal"


# ---------------------------------------------------------------------------
# detect_attack — 命令注入
# ---------------------------------------------------------------------------

def test_detect_attack_cmdi_semicolon_cat():
    print("\n[TEST] detect_attack: ; cat /tmp/data → 识别为 command_injection")
    assert detect_attack("; cat /tmp/data") == "command_injection"


def test_detect_attack_cmdi_pipe_ls():
    print("\n[TEST] detect_attack: | ls -la → 识别为 command_injection")
    assert detect_attack("| ls -la") == "command_injection"


def test_detect_attack_cmdi_backtick():
    print("\n[TEST] detect_attack: 反引号命令 → 识别为 command_injection")
    assert detect_attack("`whoami`") == "command_injection"


def test_detect_attack_cmdi_dollar_paren():
    print("\n[TEST] detect_attack: $(id) 子命令 → 识别为 command_injection")
    assert detect_attack("$(id)") == "command_injection"


def test_detect_attack_cmdi_bin_bash():
    print("\n[TEST] detect_attack: /bin/bash → 识别为 command_injection")
    assert detect_attack("/bin/bash -c 'echo hacked'") == "command_injection"


# ---------------------------------------------------------------------------
# detect_attack — SSRF
# ---------------------------------------------------------------------------

def test_detect_attack_ssrf_localhost():
    print("\n[TEST] detect_attack: http://localhost → 识别为 ssrf")
    assert detect_attack("http://localhost/admin") == "ssrf"


def test_detect_attack_ssrf_private_ip():
    print("\n[TEST] detect_attack: http://192.168.x.x → 识别为 ssrf")
    assert detect_attack("http://192.168.1.1/api") == "ssrf"


def test_detect_attack_ssrf_metadata_endpoint():
    print("\n[TEST] detect_attack: AWS 元数据端点 → 识别为 ssrf")
    assert detect_attack("http://169.254.169.254/latest/meta-data/") == "ssrf"


def test_detect_attack_ssrf_gopher_protocol():
    print("\n[TEST] detect_attack: gopher:// 协议 → 识别为 ssrf")
    assert detect_attack("gopher://evil.com:25/") == "ssrf"


def test_detect_attack_ssrf_file_protocol():
    print("\n[TEST] detect_attack: file:///tmp/data → 识别为 ssrf")
    assert detect_attack("file:///tmp/data") == "ssrf"


# ---------------------------------------------------------------------------
# detect_attack — safe inputs (新增场景仍应通过)
# ---------------------------------------------------------------------------

def test_detect_attack_safe_normal_url():
    print("\n[TEST] detect_attack: 正常完整 URL → 返回 None")
    assert detect_attack("https://example.com/api/v1/users?page=1") is None


def test_detect_attack_safe_chinese_text():
    print("\n[TEST] detect_attack: 正常中文文本 → 返回 None")
    assert detect_attack("你好世界") is None


def test_detect_attack_safe_json_body():
    print("\n[TEST] detect_attack: 正常 JSON 数据 → 返回 None")
    assert detect_attack('{"name": "Alice", "age": 30}') is None


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
