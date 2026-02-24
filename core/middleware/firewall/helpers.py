import uuid as uuid_lib
from datetime import datetime

from fastapi import Request
from fastapi.responses import JSONResponse

from core.database.connection.redis import redis_conn
from core.helper.ContainerCustomLog.index import custom_log
from core.middleware.firewall.config import (
    _BAN_DURATION,
    _BAN_THRESHOLD,
    _CMDI_PATTERNS,
    _KEY_BAN,
    _KEY_RATE,
    _KEY_VIOL,
    _MAX_REQUESTS_PER_SECOND,
    _PATH_TRAVERSAL_PATTERNS,
    _SQLI_PATTERNS,
    _SSRF_PATTERNS,
    _XSS_PATTERNS,
)


def get_client_ip(request: Request) -> str:
    """从请求中提取客户端真实 IP（兼容反向代理）。"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    if request.client:
        return request.client.host
    return "unknown"


async def resolve_user_from_token(token: str) -> str:
    """通过 token 查询其所有者 uuid，失败时返回 'unknown'。"""
    try:
        from sqlalchemy import func, or_, select

        from core.database.connection.db import get_session
        from core.database.dao.tokens import Token

        async with get_session() as session:
            stmt = select(Token.belong_to).where(
                Token.uuid == token,
                or_(Token.expired_at.is_(None), Token.expired_at > func.now()),
                Token.current_status != "revoked",
            )
            result = (await session.scalars(stmt)).first()
            return result if result else "unknown"
    except Exception:
        return "unknown"


def extract_token(request: Request) -> str | None:
    """从请求头 Authorization 或查询参数 token 中提取 token。"""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return request.query_params.get("token") or None


async def record_illegal_request(
    user: str,
    attack_type: str,
    path: str,
    ip: str,
    ua: str,
) -> None:
    """将违规请求写入 illegal_requests 表，失败时仅打印日志不中断流程。"""
    try:
        from core.database.connection.db import get_session
        from core.database.dao.illegal_requests import IllegalRequest

        record = IllegalRequest(
            uuid=str(uuid_lib.uuid4()),
            user=user,
            happened_at=datetime.now(),
            type=attack_type,
            path=path,
            ip=ip,
            ua=ua,
        )
        async with get_session() as session:
            session.add(record)
    except Exception as exc:
        custom_log("ERROR", f"[Firewall] 写入 illegal_requests 失败: {exc}")


def increment_violation(ip: str) -> int:
    """在 Redis 中累加 IP 违规计数，返回当前计数值。"""
    try:
        client = redis_conn.get_client()
        if client is None:
            return 0
        key = f"{_KEY_VIOL}{ip}"
        count = client.incr(key)
        # 每次递增时刷新过期时间为 24h，保证封禁窗口滑动
        client.expire(key, _BAN_DURATION)
        return count
    except Exception as exc:
        custom_log("ERROR", f"[Firewall] Redis 违规计数失败: {exc}")
        return 0


def ban_ip(ip: str) -> None:
    """在 Redis 中标记 IP 为封禁状态，有效期 24 小时。"""
    try:
        client = redis_conn.get_client()
        if client is None:
            return
        client.set(f"{_KEY_BAN}{ip}", "1", ex=_BAN_DURATION)
        custom_log("WARNING", f"[Firewall] IP 已封禁 24h: {ip}")
    except Exception as exc:
        custom_log("ERROR", f"[Firewall] Redis 封禁 IP 失败: {exc}")


def is_banned(ip: str) -> bool:
    """检查 IP 是否在 Redis 封禁名单中。"""
    try:
        client = redis_conn.get_client()
        if client is None:
            return False
        return bool(client.exists(f"{_KEY_BAN}{ip}"))
    except Exception:
        return False


def is_rate_exceeded(ip: str) -> bool:
    """检查 IP 是否超过每秒 20 次的请求速率限制。"""
    try:
        client = redis_conn.get_client()
        if client is None:
            return False
        key = f"{_KEY_RATE}{ip}"
        count = client.incr(key)
        if count == 1:
            client.expire(key, 1)  # 1 秒窗口
        return count > _MAX_REQUESTS_PER_SECOND
    except Exception:
        return False


def build_reject_response(reason: str) -> JSONResponse:
    """构建 403 拒绝响应。"""
    return JSONResponse(
        status_code=403,
        content={"detail": reason},
    )


def detect_attack(text: str) -> str | None:
    """检测文本中的攻击特征，返回攻击类型字符串或 None。

    检测顺序（参考雷池 WAF 多引擎检测思路）：
    XSS → SQL 注入 → 路径穿越 → 命令注入 → SSRF
    """
    if not text:
        return None
    if _XSS_PATTERNS.search(text):
        return "xss"
    if _SQLI_PATTERNS.search(text):
        return "sql_injection"
    if _PATH_TRAVERSAL_PATTERNS.search(text):
        return "path_traversal"
    if _CMDI_PATTERNS.search(text):
        return "command_injection"
    if _SSRF_PATTERNS.search(text):
        return "ssrf"
    return None


async def record_request_log(path: str) -> None:
    """将正常请求的主路径（不含查询参数）写入 request_logs 表，失败时仅打印日志不中断流程。"""
    try:
        from core.database.dao.request_logs import RequestLogsDAO

        await RequestLogsDAO().upsert_by_path(path)
    except Exception as exc:
        custom_log("ERROR", f"[Firewall] 写入 request_logs 失败: {exc}")
