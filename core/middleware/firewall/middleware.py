from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from core.helper.ContainerCustomLog.index import custom_log
from core.middleware.firewall.config import (
    _BAN_THRESHOLD,
    _CRAWLER_UA_PATTERNS,
    _INSPECTED_HEADERS,
)
from core.middleware.firewall.helpers import (
    ban_ip,
    build_reject_response,
    detect_attack,
    extract_token,
    get_client_ip,
    increment_violation,
    is_banned,
    is_rate_exceeded,
    record_illegal_request,
    record_request_log,
    resolve_user_from_token,
)


class FirewallMiddleware(BaseHTTPMiddleware):
    """应用层防火墙中间件（增强版 — 参考雷池 WAF 多引擎检测思路）。

    检测顺序：
    1. IP 封禁检查
    2. 高频访问（速率限制）
    3. 常见爬虫 User-Agent
    4. 攻击特征检测（XSS / SQL 注入 / 路径穿越 / 命令注入 / SSRF）
       检查范围：URL 路径 + 查询参数 + Cookie + 重要请求头
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        ip = get_client_ip(request)
        ua = request.headers.get("User-Agent", "")
        path = request.url.path
        query = str(request.url.query)

        # ------------------------------------------------------------------ #
        # 1. IP 封禁检查                                                       #
        # ------------------------------------------------------------------ #
        if is_banned(ip):
            return build_reject_response("您的 IP 已被封禁，请 24 小时后重试。")

        # ------------------------------------------------------------------ #
        # 2. 速率限制（超高频访问 > 20次/s）                                    #
        # ------------------------------------------------------------------ #
        if is_rate_exceeded(ip):
            attack_type = "rate_limit"
            user = await self._resolve_user(request)
            await record_illegal_request(user, attack_type, path, ip, ua)
            viol_count = increment_violation(ip)
            if viol_count >= _BAN_THRESHOLD:
                ban_ip(ip)
            custom_log("WARNING", f"[Firewall] 速率超限 ip={ip} path={path}")
            return build_reject_response("请求过于频繁，请稍后再试。")

        # ------------------------------------------------------------------ #
        # 3. 爬虫 User-Agent 检测                                               #
        # ------------------------------------------------------------------ #
        if ua and _CRAWLER_UA_PATTERNS.search(ua):
            attack_type = "crawler"
            user = await self._resolve_user(request)
            await record_illegal_request(user, attack_type, path, ip, ua)
            viol_count = increment_violation(ip)
            if viol_count >= _BAN_THRESHOLD:
                ban_ip(ip)
            custom_log("WARNING", f"[Firewall] 爬虫 UA 检测 ip={ip} ua={ua}")
            return build_reject_response("禁止爬虫访问。")

        # ------------------------------------------------------------------ #
        # 4 & 5. 攻击特征检测（XSS / SQL 注入 / 路径穿越 / 命令注入 / SSRF）   #
        #   检查范围：URL 路径 + 查询参数 + Cookie + 重要请求头               #
        #   参考雷池 WAF 多维度输入检测思路                                    #
        # ------------------------------------------------------------------ #
        combined = path + "?" + query if query else path
        attack_type = detect_attack(combined)

        # 检查配置的请求头列表
        if attack_type is None:
            for header_name in _INSPECTED_HEADERS:
                header_val = request.headers.get(header_name, "")
                if header_val:
                    attack_type = detect_attack(header_val)
                    if attack_type:
                        break

        # 检查 Cookie 值
        if attack_type is None:
            cookie_header = request.headers.get("Cookie", "")
            if cookie_header:
                attack_type = detect_attack(cookie_header)

        if attack_type:
            user = await self._resolve_user(request)
            await record_illegal_request(user, attack_type, path, ip, ua)
            viol_count = increment_violation(ip)
            if viol_count >= _BAN_THRESHOLD:
                ban_ip(ip)
            custom_log("WARNING", f"[Firewall] {attack_type} 攻击检测 ip={ip} path={path}")
            return build_reject_response("请求包含非法内容，已被拦截。")

        # ------------------------------------------------------------------ #
        # 正常请求，放行并记录访问路径                                           #
        # ------------------------------------------------------------------ #
        await record_request_log(path)
        return await call_next(request)

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------

    @staticmethod
    async def _resolve_user(request: Request) -> str:
        """尝试从请求中解析 token 并返回对应用户，失败时返回 'unknown'。"""
        token = extract_token(request)
        if not token:
            return "unknown"
        return await resolve_user_from_token(token)
