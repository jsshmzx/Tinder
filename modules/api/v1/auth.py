import hashlib
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from core.database.connection.pgsql import get_session
from core.database.dao.users import UsersDAO
from core.database.dao.refresh_tokens import RefreshTokensDAO
from core.security.hash import verify_password
from core.security.jwt_handler import create_access_token, generate_refresh_token
from core.middleware.auth.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["Auth v1"])


@router.post("/login", response_model=dict[str, Any])
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """用户登录，返回 Access Token 和 Refresh Token。"""
    async with get_session() as session:
        user = await UsersDAO.find_by_username_or_email(session, form_data.username)
        if not user or not user.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户名或密码错误",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not verify_password(form_data.password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户名或密码错误",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user_uuid = str(user.uuid)
    access_token = create_access_token(subject=user_uuid)
    plaintext, token_hash = generate_refresh_token()

    await RefreshTokensDAO.create(user_uuid=user_uuid, token_hash=token_hash)
    await UsersDAO().update(user_uuid, {
        "last_login_at": datetime.now(timezone.utc),
        "last_login_ip": request.client.host if request.client else None,
    })

    return {
        "access_token": access_token,
        "refresh_token": plaintext,
        "token_type": "bearer",
    }


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


@router.get("/me", response_model=dict[str, Any])
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """获取当前登录用户信息。"""
    return {
        "uuid": current_user.get("uuid"),
        "real_name": current_user.get("real_name"),
        "role": current_user.get("user_role"),
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

    await RefreshTokensDAO.revoke(token_hash)

    user_uuid = record["user_uuid"]
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
