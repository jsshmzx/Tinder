import uuid
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from core.database.connection.pgsql import get_session
from core.database.dao.users import UsersDAO, User
from core.security.hash import get_password_hash, verify_password
from core.security.jwt_handler import create_access_token
from core.middleware.auth.dependencies import get_current_user

router = APIRouter()

@router.post("/login", response_model=dict[str, Any])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """用户登录并获取 JWT token。"""
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

        access_token = create_access_token(subject=user.uuid)
        return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=dict[str, Any])
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """获取当前登录用户信息。"""
    return {"uuid": current_user.get("uuid"), "real_name": current_user.get("real_name"), "role": current_user.get("user_role")}
