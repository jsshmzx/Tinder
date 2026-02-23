"""Integration tests — FirewallMiddleware against real Redis + PostgreSQL.

Covers:
  * Normal requests are passed through (HTTP 200)
  * Normal requests are logged in request_logs table
  * XSS pattern in URL path -> HTTP 403
  * SQL injection pattern in Referer header -> HTTP 403
  * Crawler User-Agent -> HTTP 403
  * Banned IP -> HTTP 403
  * Rate-limit (> 20 req/s from same IP) -> HTTP 403
"""

import asyncio

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flush_firewall_keys(client_ip: str, redis_client) -> None:
    """Remove all Firewall Redis keys for a given IP to start each test clean."""
    for prefix in ("fw:rate:", "fw:viol:", "fw:ban:"):
        redis_client.delete(f"{prefix}{client_ip}")


# ---------------------------------------------------------------------------
# Normal request
# ---------------------------------------------------------------------------

def test_normal_request_passes(integration_client, redis_client):
    print("\n[TEST][Firewall] 正常请求应通过防火墙，返回 HTTP 200")
    _flush_firewall_keys("testclient", redis_client)
    response = integration_client.get("/")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Request log recording
# ---------------------------------------------------------------------------

def test_normal_request_is_logged_in_request_logs(integration_client, redis_client):
    print("\n[TEST][Firewall] 正常请求应将主路径写入 request_logs 表")
    _flush_firewall_keys("testclient", redis_client)

    from core.database.dao.request_logs import RequestLogsDAO

    response = integration_client.get("/")
    assert response.status_code == 200

    record = asyncio.run(
        RequestLogsDAO().find_by_path("/")
    )
    assert record is not None
    assert record["request_path"] == "/"
    assert record["frequency"] >= 1


# ---------------------------------------------------------------------------
# XSS detection
# ---------------------------------------------------------------------------

def test_xss_in_path_is_blocked(integration_client, redis_client):
    print("\n[TEST][Firewall] URL 路径中含 XSS 特征 -> 应被拒绝 (HTTP 403)")
    _flush_firewall_keys("testclient", redis_client)
    response = integration_client.get("/<script>alert(1)</script>")
    assert response.status_code == 403
    assert "detail" in response.json()


def test_xss_javascript_scheme_is_blocked(integration_client, redis_client):
    print("\n[TEST][Firewall] 查询参数中含 javascript: 协议 -> 应被拒绝 (HTTP 403)")
    _flush_firewall_keys("testclient", redis_client)
    response = integration_client.get("/?x=javascript:alert(1)")
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# SQL injection detection (via Referer header -- not URL-encoded)
# ---------------------------------------------------------------------------

def test_sqli_in_referer_is_blocked(integration_client, redis_client):
    print("\n[TEST][Firewall] Referer 头中含 SQL 注入特征 -> 应被拒绝 (HTTP 403)")
    _flush_firewall_keys("testclient", redis_client)
    response = integration_client.get(
        "/", headers={"Referer": "' OR '1'='1"}
    )
    assert response.status_code == 403


def test_sqli_select_from_in_referer_is_blocked(integration_client, redis_client):
    print("\n[TEST][Firewall] Referer 头中含 SELECT FROM -> 应被拒绝 (HTTP 403)")
    _flush_firewall_keys("testclient", redis_client)
    response = integration_client.get(
        "/", headers={"Referer": "SELECT * FROM users WHERE id=1"}
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Crawler User-Agent
# ---------------------------------------------------------------------------

def test_crawler_ua_is_blocked(integration_client, redis_client):
    print("\n[TEST][Firewall] 爬虫 User-Agent (python-requests) -> 应被拒绝 (HTTP 403)")
    _flush_firewall_keys("testclient", redis_client)
    response = integration_client.get(
        "/", headers={"User-Agent": "python-requests/2.31.0"}
    )
    assert response.status_code == 403


def test_scrapy_ua_is_blocked(integration_client, redis_client):
    print("\n[TEST][Firewall] 爬虫 User-Agent (Scrapy) -> 应被拒绝 (HTTP 403)")
    _flush_firewall_keys("testclient", redis_client)
    response = integration_client.get(
        "/", headers={"User-Agent": "Scrapy/2.11.0 (+https://scrapy.org)"}
    )
    assert response.status_code == 403


def test_normal_browser_ua_passes(integration_client, redis_client):
    print("\n[TEST][Firewall] 正常浏览器 User-Agent -> 应通过防火墙 (HTTP 200)")
    _flush_firewall_keys("testclient", redis_client)
    response = integration_client.get(
        "/",
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Banned IP
# ---------------------------------------------------------------------------

def test_banned_ip_is_rejected(integration_app, redis_client):
    print("\n[TEST][Firewall] 已封禁 IP -> 应直接拒绝 (HTTP 403)")
    banned_ip = "10.99.99.99"
    _flush_firewall_keys(banned_ip, redis_client)

    # Manually ban the IP in Redis
    redis_client.set(f"fw:ban:{banned_ip}", "1", ex=60)

    client = TestClient(integration_app, raise_server_exceptions=False)
    response = client.get("/", headers={"X-Forwarded-For": banned_ip})
    assert response.status_code == 403

    # Clean up
    redis_client.delete(f"fw:ban:{banned_ip}")


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_rate_limit_triggers_after_threshold(integration_app, redis_client):
    print("\n[TEST][Firewall] 同一 IP 超过速率阈值 (>20 req/s) -> 应被限流 (HTTP 403)")
    rate_ip = "10.88.88.88"
    _flush_firewall_keys(rate_ip, redis_client)

    client = TestClient(integration_app, raise_server_exceptions=False)

    # Force the rate counter above the threshold without actually sending
    # 20+ requests (which would be slow): pre-seed the Redis counter.
    key = f"fw:rate:{rate_ip}"
    redis_client.set(key, 25, ex=1)  # already at 25 -- above the 20 req/s limit

    response = client.get("/", headers={"X-Forwarded-For": rate_ip})
    assert response.status_code == 403

    # Clean up
    _flush_firewall_keys(rate_ip, redis_client)
