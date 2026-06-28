"""请求链路日志上下文中间件。

为每个请求生成唯一的 trace_id，并收集客户端 IP、User-Agent、请求方法、
请求 URL 以及（可选）当前用户 UUID，通过 LogContext 在请求链路中传递，
使系统日志与个人日志真正具备链路追踪能力。
"""

import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from core.helper.CustomLog.index import LogContext, reset_log_context, set_log_context
from core.middleware.firewall.helpers import extract_token, get_client_ip
from core.security.jwt_handler import decode_access_token


def _resolve_user_uuid(request: Request) -> str | None:
    """尝试从请求 token 中解析用户 UUID，失败返回 None。"""
    token = extract_token(request)
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        if payload:
            return payload.get("sub")
    except Exception:
        # token 无效或密钥未配置时不应影响主请求
        pass
    return None


class LogContextMiddleware(BaseHTTPMiddleware):
    """在每个请求开始时设置 LogContext，请求结束时重置。"""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        ctx = LogContext(
            trace_id=str(uuid.uuid4()),
            client_ip=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            request_method=request.method,
            request_url=str(request.url),
            user_uuid=_resolve_user_uuid(request),
        )
        token = set_log_context(ctx)
        try:
            return await call_next(request)
        finally:
            reset_log_context(token)
