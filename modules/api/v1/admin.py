from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from core.database.connection.pgsql import get_session
from core.database.dao.users import UsersDAO
from core.middleware.auth.dependencies import MinRoleChecker, invalidate_user_cache
from core.security.hash import get_password_hash
from core.security.rbac import Role
from core.helper.ContainerCustomLog.index import custom_log


router = APIRouter(prefix="/admin", tags=["Admin v1"])


@router.get("/users", response_model=list[dict[str, Any]])
async def admin_list_users(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    keyword: str | None = Query(None, description="搜索关键词（用户名/邮箱/昵称/真实姓名）"),
    status: str | None = Query(None, description="按状态筛选（normal/disabled/banned/pending_deletion）"),
    role: str | None = Query(None, description="按角色筛选（superadmin/songlist_editor/normal-user）"),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：分页搜索用户列表。

    支持关键词模糊搜索、状态筛选、角色筛选。
    仅 superadmin 可访问。
    """
    async with get_session() as session:
        return await UsersDAO.search_users(
            session, keyword=keyword, status=status, role=role,
            limit=limit, offset=offset,
        )


@router.get("/users/total", response_model=dict[str, Any])
async def admin_users_total(
    keyword: str | None = Query(None),
    status: str | None = Query(None),
    role: str | None = Query(None),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：获取用户总数（可选筛选）。"""
    async with get_session() as session:
        total = await UsersDAO.count_users(session, keyword=keyword, status=status, role=role)
    return {"total": total}


@router.get("/users/stats", response_model=dict[str, Any])
async def admin_users_stats(
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：用户统计（总数 + 各状态分布）。"""
    async with get_session() as session:
        return await UsersDAO.get_user_stats(session)


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
    """管理员：编辑用户信息（含角色、状态）。"""
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
    """管理员：禁用用户。"""
    updated = await UsersDAO().update(user_uuid, {"current_status": "disabled"})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)
    custom_log("SUCCESS", f"[Admin] 禁用用户 uuid={user_uuid}")
    return updated


@router.post("/users/{user_uuid}/enable", response_model=dict[str, Any])
async def admin_enable_user(
    user_uuid: str,
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：启用用户。"""
    updated = await UsersDAO().update(user_uuid, {"current_status": "normal"})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)
    custom_log("SUCCESS", f"[Admin] 启用用户 uuid={user_uuid}")
    return updated


@router.post("/users/{user_uuid}/ban", response_model=dict[str, Any])
async def admin_ban_user(
    user_uuid: str,
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：封禁用户。"""
    updated = await UsersDAO().update(user_uuid, {"current_status": "banned"})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)
    custom_log("SUCCESS", f"[Admin] 封禁用户 uuid={user_uuid}")
    return updated


@router.post("/users/{user_uuid}/unban", response_model=dict[str, Any])
async def admin_unban_user(
    user_uuid: str,
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：解除封禁。"""
    updated = await UsersDAO().update(user_uuid, {"current_status": "normal"})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)
    custom_log("SUCCESS", f"[Admin] 解封用户 uuid={user_uuid}")
    return updated

