from typing import List

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from core.database.connection.pgsql import get_session
from core.database.dao.users import UsersDAO, User
from core.security.jwt_handler import decode_access_token
from core.security.rbac import role_includes

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """基于提供的 JWT token 获取当前用户信息。"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    user_uuid: str | None = payload.get("sub")
    if user_uuid is None:
        raise credentials_exception

    user_dict = await UsersDAO().find_by_uuid(user_uuid)
    if user_dict is None:
        raise credentials_exception
    return user_dict

class RoleChecker:
    """检查用户是否具有所需的角色权限。"""

    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("user_role")
        if not role_includes(user_role, self.allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"操作未授权。需要的角色: {self.allowed_roles}"
            )
        return user


class MinRoleChecker:
    """检查用户角色是否 >= 目标角色。

    - superadmin >= songlist_editor >= normal-user
    """

    def __init__(self, required_role: str):
        self.required_role = required_role

    def __call__(self, user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("user_role")
        if not role_includes(user_role, [self.required_role]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"操作未授权。需要的最小角色: {self.required_role}",
            )
        return user
