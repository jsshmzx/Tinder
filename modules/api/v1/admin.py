import uuid as uuid_lib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select as sa_select

from core.config import settings
from core.database.connection.pgsql import get_session
from core.database.connection.redis import redis_conn
from core.database.dao.users import UsersDAO, User
from core.middleware.auth.dependencies import MinRoleChecker, invalidate_user_cache, get_current_user, USER_CACHE_PREFIX
from core.security.hash import get_password_hash
from core.security.rbac import Role
from core.helper.ContainerCustomLog.index import custom_log


router = APIRouter(prefix="/admin", tags=["Admin v1"])


def _verify_super_password(password: str) -> None:
    """校验超级密码 SUPER_PASSWORD。

    从 settings.SUPER_PASSWORD 读取，校验失败抛 403。
    """
    if not settings.SUPER_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="超级密码未配置，请联系管理员",
        )
    if password != settings.SUPER_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="超级密码错误",
        )


def _batch_invalidate_user_cache(uuids: list[str]) -> None:
    """批量失效 Redis 用户缓存，使用 pipeline 减少网络往返。"""
    client = redis_conn.get_client()
    if client is None:
        return
    try:
        pipe = client.pipeline()
        for uid in uuids:
            pipe.delete(f"{USER_CACHE_PREFIX}{uid}")
        pipe.execute()
    except Exception as exc:
        custom_log("WARNING", f"[Admin] 批量缓存失效失败 count={len(uuids)} exc={exc}")


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
    if "uuid" not in payload or not payload["uuid"]:
        payload["uuid"] = str(uuid_lib.uuid4())
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


@router.delete("/users/batch", response_model=dict[str, Any])
async def admin_batch_delete_users(
    payload: dict[str, Any],
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：批量删除用户（单个事务，删除多个用户）。

    安全限制：
    1. 必须提供超级密码 (SUPER_PASSWORD)
    2. 不能包含当前登录的管理员自己
    3. 不能包含 superadmin 角色
    """
    uuids: list[str] = payload.get("uuids", [])
    if not uuids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="未提供要删除的用户 UUID 列表")

    # 1. 校验超级密码
    super_password = payload.get("super_password", "")
    _verify_super_password(super_password)

    # 2. 不能删除自己
    if current_user["uuid"] in uuids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="批量删除列表中包含当前登录的管理员账户，已取消操作",
        )

    async with get_session() as session:
        # 单次查询所有待删除用户的角色信息，避免 N+1
        rows = (await session.execute(
            sa_select(User.uuid, User.user_role).where(User.uuid.in_(uuids))
        )).all()
        if rows:
            role_map: dict[str, str] = dict(rows)  # type: ignore[arg-type]
            for uid in uuids:
                if role_map.get(uid) == Role.SUPERADMIN.value:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="批量删除不能包含超级管理员账户",
                    )

        deleted_count = await UsersDAO.batch_delete(session, uuids)

    # 批量失效 Redis 缓存（使用 pipeline 减少网络往返）
    _batch_invalidate_user_cache(uuids)
    custom_log("SUCCESS", f"[Admin] 批量删除用户 count={len(uuids)} actual_deleted={deleted_count}")
    return {"deleted": deleted_count}


@router.delete("/users/{user_uuid}", response_model=dict[str, Any])
async def admin_delete_user(
    user_uuid: str,
    payload: dict[str, Any],
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：删除用户。

    安全限制：
    1. 必须提供超级密码 (SUPER_PASSWORD)
    2. 不能删除当前登录的管理员自己
    3. 同为超级管理员不能直接删除同级的超级管理员
    4. 系统中仅剩 2 个超级管理员时，不能再删除其中任何一个
    """
    # 1. 校验超级密码
    super_password = payload.get("super_password", "")
    _verify_super_password(super_password)

    # 2. 不能删除自己
    if user_uuid == current_user["uuid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能删除当前登录的管理员账户",
        )

    async with get_session() as session:
        target_user = await UsersDAO().find_by_uuid(user_uuid)
        if target_user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")

        target_role = target_user.get("user_role")

        # 3. 同为 superadmin 不能直接删除同级 superadmin
        if target_role == Role.SUPERADMIN.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="超级管理员不能直接删除同级管理员",
            )

        # 4. 系统中超级管理员仅剩 2 个（或更少）时，不允许再删除其中任何一个
        superadmin_count = await UsersDAO.count_by_role(session, Role.SUPERADMIN.value)
        if superadmin_count <= 2 and target_role in (
            Role.SUPERADMIN.value, Role.SONGLIST_EDITOR.value,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"系统中仅剩 {superadmin_count} 个超级管理员，不能再删除管理员账户",
            )

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

