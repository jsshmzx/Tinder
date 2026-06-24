import hashlib
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from core.config import settings
from core.database.connection.pgsql import get_session
from core.database.dao.users import UsersDAO
from core.database.dao.refresh_tokens import RefreshTokensDAO
from core.security.hash import verify_password
from core.security.jwt_handler import create_access_token, generate_refresh_token
from core.middleware.auth.dependencies import get_current_user
from core.helper.CustomLog.index import CustomLog

router = APIRouter(prefix="/auth", tags=["Auth v1"])


class LoginRequest(BaseModel):
    """JSON 登录请求体。"""

    username: str = Field(..., min_length=1, description="用户名或邮箱")
    password: str = Field(..., min_length=1, description="SHA256 双重哈希后的 hex 字符串（64 字符）")


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


def _login_redis_incr(key: str, ttl: int) -> int:
    """递增 Redis 计数器，返回递增后的值。"""
    from core.database.connection.redis import redis_conn
    client = redis_conn.get_client()
    if client is None:
        return 0
    try:
        count = client.incr(key)
        if count == 1:
            client.expire(key, ttl)
        return count
    except Exception:
        return 0


@router.post("/login", response_model=dict[str, Any])
async def login(request: Request, body: LoginRequest):
    """用户登录，返回 Access Token 和 Refresh Token。

    支持 username 或 email 作为登录标识。
    密码为客户端 SHA256 双重哈希后的 64 字符 hex 字符串。
    若账号处于 pending_deletion 冷却期中，自动恢复为 normal。
    """

    # 速率限制：IP 级别和用户名级别
    client_ip = request.client.host if request.client else "unknown"
    ip_key = f"login_atm:ip:{client_ip}:min"
    un_key = f"login_atm:un:{body.username}:min"

    ip_count = _login_redis_incr(ip_key, settings.LOGIN_RATE_WINDOW_SECONDS)
    un_count = _login_redis_incr(un_key, settings.LOGIN_RATE_WINDOW_SECONDS)

    if ip_count > settings.LOGIN_MAX_ATTEMPTS_PER_IP_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="登录尝试过于频繁，请稍后再试",
        )
    if un_count > settings.LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="登录尝试过于频繁，请稍后再试",
        )

    async with get_session() as session:
        user = await UsersDAO.find_by_username_or_email(session, body.username)
        if not user or not user.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户名或密码错误",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not verify_password(body.password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户名或密码错误",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 检查账号状态
        user_uuid = str(user.uuid)
        status_val = user.current_status

        if status_val in ("disabled", "banned"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="账号已被禁用，如有疑问请联系管理员",
            )

        if status_val == "pending_deletion":
            deletion_time = user.deletion_scheduled_at
            now_utc = datetime.now()
            if deletion_time and deletion_time > now_utc:
                # 冷却期内登录 → 自动恢复
                await UsersDAO().update(user_uuid, {
                    "current_status": "normal",
                    "deletion_scheduled_at": None,
                })
                CustomLog("SUCCESS", f"[Login] uuid={user_uuid} 冷却期内登录，账号已恢复")
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="账号已永久注销",
                )

    access_token = create_access_token(subject=user_uuid)
    plaintext, token_hash = generate_refresh_token()

    await RefreshTokensDAO.create(user_uuid=user_uuid, token_hash=token_hash)
    await UsersDAO().update(user_uuid, {
        "last_login_at": datetime.now(),
        "last_login_ip": client_ip,
    })

    return {
        "access_token": access_token,
        "refresh_token": plaintext,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=dict[str, Any])
async def refresh_tokens(body: RefreshRequest):
    """使用 Refresh Token 换取新的 Access Token 和 Refresh Token（轮转）。"""
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    record = await RefreshTokensDAO.find_active(token_hash)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效或已吊销的 Refresh Token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_uuid = record["user_uuid"]

    # 校验用户是否存在且未被禁用
    user = await UsersDAO().find_by_uuid(user_uuid)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户不存在",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.get("current_status") in ("disabled", "banned"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="账号已被禁用",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await RefreshTokensDAO.revoke(token_hash)

    access_token = create_access_token(subject=user_uuid)
    plaintext, new_hash = generate_refresh_token()
    await RefreshTokensDAO.create(user_uuid=user_uuid, token_hash=new_hash)

    return {
        "access_token": access_token,
        "refresh_token": plaintext,
        "token_type": "bearer",
    }


@router.post("/logout", response_model=dict[str, Any])
async def logout(body: LogoutRequest, _: dict = Depends(get_current_user)):
    """登出当前设备，吊销 Refresh Token。Access Token 在有效期内自然失效。"""
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    await RefreshTokensDAO.revoke(token_hash)
    return {"message": "已登出"}
