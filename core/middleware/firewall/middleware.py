from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from core.helper.ContainerCustomLog.index import custom_log
from core.middleware.firewall.config import _BAN_THRESHOLD, _CRAWLER_UA_PATTERNS
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
    resolve_user_from_token,
)


class FirewallMiddleware(BaseHTTPMiddleware):
    """应用层防火墙中间件。

    检测顺序：
    1. IP 封禁检查
    2. 高频访问（速率限制）
    3. 常见爬虫 User-Agent
    4. XSS 攻击特征
    5. SQL 注入特征
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
        # 4 & 5. XSS / SQL 注入检测（检查 URL 路径和查询参数）                  #
        # ------------------------------------------------------------------ #
        combined = path + "?" + query if query else path
        attack_type = detect_attack(combined)
        if attack_type is None:
            # 也检查常用请求头中的注入
            referer = request.headers.get("Referer", "")
            attack_type = detect_attack(referer)

        if attack_type:
            user = await self._resolve_user(request)
            await record_illegal_request(user, attack_type, path, ip, ua)
            viol_count = increment_violation(ip)
            if viol_count >= _BAN_THRESHOLD:
                ban_ip(ip)
            custom_log("WARNING", f"[Firewall] {attack_type} 攻击检测 ip={ip} path={path}")
            return build_reject_response("请求包含非法内容，已被拦截。")

        # ------------------------------------------------------------------ #
        # 正常请求，放行                                                        #
        # ------------------------------------------------------------------ #
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
