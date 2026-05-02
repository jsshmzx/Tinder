from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from core.database.dao.users import UsersDAO
from core.middleware.auth.dependencies import MinRoleChecker, invalidate_user_cache
from core.security.hash import get_password_hash
from core.security.rbac import Role


router = APIRouter(prefix="/admin", tags=["Admin v1"])


@router.get("/users", response_model=list[dict[str, Any]])
async def admin_list_users(
    limit: int = 100,
    offset: int = 0,
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：查看所有用户。

    仅 superadmin 可访问。
    """
    return await UsersDAO().find_all(limit=limit, offset=offset)


@router.post("/users", response_model=dict[str, Any])
async def admin_create_user(
    payload: dict[str, Any],
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：创建用户。

    允许写入 users 表的部分字段；如包含 password，会被 hash 后写入。
    """
    if payload.get("password"):
        payload["password"] = get_password_hash(str(payload["password"]))
    created = await UsersDAO().create(payload)
    invalidate_user_cache(created.get("uuid") or "")
    return created


@router.patch("/users/{user_uuid}", response_model=dict[str, Any])
async def admin_update_user(
    user_uuid: str,
    payload: dict[str, Any],
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：编辑用户信息（含角色）。"""
    if payload.get("password"):
        payload["password"] = get_password_hash(str(payload["password"]))
    updated = await UsersDAO().update(user_uuid, payload)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)
    return updated


@router.delete("/users/{user_uuid}", response_model=dict[str, Any])
async def admin_delete_user(
    user_uuid: str,
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：删除用户。"""
    ok = await UsersDAO().delete(user_uuid)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)
    return {"success": True}


@router.post("/users/{user_uuid}/disable", response_model=dict[str, Any])
async def admin_disable_user(
    user_uuid: str,
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：禁用用户（通过 current_status 标记）。"""
    updated = await UsersDAO().update(user_uuid, {"current_status": "disabled"})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)
    return updated

