import json
from typing import List

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer

from core.config import settings
from core.database.connection.pgsql import get_session
from core.database.connection.redis import redis_conn
from core.database.dao.users import UsersDAO, User
from core.security.jwt_handler import decode_access_token
from core.security.rbac import role_includes
from core.helper.ContainerCustomLog.index import custom_log

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")
temp_token_scheme = HTTPBearer()

USER_CACHE_PREFIX = "auth:user:"
USER_CACHE_TTL_SECONDS = settings.AUTH_USER_CACHE_TTL_SECONDS


def _get_user_cache_key(user_uuid: str) -> str:
    return f"{USER_CACHE_PREFIX}{user_uuid}"


def invalidate_user_cache(user_uuid: str) -> None:
    """主动失效用户缓存。

    注意：为了避免在没有 Redis 的情况下影响主流程，这里只记录日志，不抛异常。
    """
    client = redis_conn.get_client()
    if client is None:
        return
    try:
        client.delete(_get_user_cache_key(user_uuid))
    except Exception as exc:
        custom_log("WARNING", f"[RBAC] 用户缓存失效失败 uuid={user_uuid} exc={exc}")

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

    client = redis_conn.get_client()
    if client is not None:
        try:
            cached = client.get(_get_user_cache_key(user_uuid))
            if cached:
                return json.loads(cached)
        except Exception as exc:
            custom_log("WARNING", f"[RBAC] Redis 读取用户缓存失败 uuid={user_uuid} exc={exc}")

    user_dict = await UsersDAO().find_by_uuid(user_uuid)
    if user_dict is None:
        raise credentials_exception
    user_dict.pop("password", None)

    if client is not None:
        try:
            client.setex(
                _get_user_cache_key(user_uuid),
                USER_CACHE_TTL_SECONDS,
                json.dumps(user_dict, ensure_ascii=False, default=str),
            )
        except Exception as exc:
            custom_log("WARNING", f"[RBAC] Redis 写入用户缓存失败 uuid={user_uuid} exc={exc}")
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


async def get_temp_user(
    credentials: HTTPAuthorizationCredentials = Depends(temp_token_scheme),
) -> dict:
    """验证临时 token（purpose="register_complete"），返回用户字典。

    与 get_current_user 区别：
    - 不检查用户角色
    - 要求 payload.purpose == "register_complete"
    - 不读取 Redis 缓存（临时 token 一次性使用）
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无效或已过期的临时凭证",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise credentials_exception

    purpose = payload.get("purpose")
    if purpose != "register_complete":
        raise credentials_exception

    user_uuid: str | None = payload.get("sub")
    if user_uuid is None:
        raise credentials_exception

    user_dict = await UsersDAO().find_by_uuid(user_uuid)
    if user_dict is None:
        raise credentials_exception

    user_dict.pop("password", None)
    return user_dict
