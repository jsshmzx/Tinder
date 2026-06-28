import json
import re
import uuid as uuid_lib
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select as sa_select

from core.config import settings
from core.database.connection.pgsql import get_session
from core.database.connection.redis import redis_conn
from core.database.dao.register_questions import RegisterQuestionsDAO
from core.database.dao.refresh_tokens import RefreshTokensDAO
from core.database.dao.users import UsersDAO, User
from core.helper.CustomLog.index import CustomLog
from core.middleware.auth.dependencies import USER_CACHE_PREFIX, MinRoleChecker, get_current_user, invalidate_user_cache
from core.security.hash import get_password_hash
from core.security.rbac import Role


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


def _client_ip(request: Request) -> str:
    """获取客户端真实 IP。"""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _log_user_personal_event(
    *,
    request: Request,
    user_uuid: str,
    event_type: str,
    content: str,
    status: str = "SUCCESS",
    before_data: dict[str, Any] | None = None,
    after_data: dict[str, Any] | None = None,
    target_type: str = "USER",
    target_name: str | None = None,
) -> None:
    """记录一条以目标用户为主体的个人日志。"""
    CustomLog(
        "SUCCESS" if status == "SUCCESS" else "WARNING",
        content,
        sid=True,
        sidp="personal",
        log_type="admin",
        event_type=event_type,
        status=status,
        user_uuid=user_uuid,
        target_type=target_type,
        target_id=user_uuid,
        target_name=target_name,
        before_data=before_data,
        after_data=after_data,
        client_ip=_client_ip(request),
        request_method=request.method,
        request_url=str(request.url),
        user_agent=request.headers.get("user-agent"),
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
        CustomLog("WARNING", f"[Admin] 批量缓存失效失败 count={len(uuids)} exc={exc}")


class ResetPasswordRequest(BaseModel):
    """管理员重置密码请求体。"""
    super_password: str = Field(..., description="超级密码")
    new_password: str = Field(..., min_length=64, max_length=64, description="新密码（64 字符 SHA256 hex）")

    @field_validator("new_password")
    @classmethod
    def password_must_be_hex64(cls, v: str) -> str:
        if not re.fullmatch(r"[a-fA-F0-9]{64}", v):
            raise ValueError("密码必须为 64 字符 SHA256 哈希值（hex）")
        return v


class SensitiveDataRequest(BaseModel):
    """敏感信息查看请求体。"""
    super_password: str = Field(..., description="超级密码")
    uuids: list[str] = Field(..., min_length=1, max_length=50, description="要查询的用户 UUID 列表")


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
    request: Request,
    user_uuid: str,
    payload: dict[str, Any],
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：编辑用户信息（含角色、状态）。"""
    target_user = await UsersDAO().find_by_uuid(user_uuid)
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")

    if payload.get("password"):
        payload["password"] = get_password_hash(str(payload["password"]))

    updated = await UsersDAO().update(user_uuid, payload)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)

    # 记录变更字段的 before/after，敏感字段 password 不记录
    changed_keys = {k for k in payload.keys() if k != "password"}
    before_data = {k: target_user.get(k) for k in changed_keys if k in target_user}
    after_data = {k: updated.get(k) for k in changed_keys if k in updated}
    _log_user_personal_event(
        request=request,
        user_uuid=user_uuid,
        event_type="USER_UPDATE",
        content=f"[Admin] 管理员 {current_user.get('uuid')} 更新用户信息",
        before_data=before_data,
        after_data=after_data,
    )
    return updated


@router.delete("/users/batch", response_model=dict[str, Any])
async def admin_batch_delete_users(
    request: Request,
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

    # 为每个被删除用户记录个人日志，并记录一条系统日志
    for uid in uuids:
        _log_user_personal_event(
            request=request,
            user_uuid=uid,
            event_type="USER_DELETE",
            content=f"[Admin] 管理员 {current_user.get('uuid')} 批量删除用户",
        )
    CustomLog(
        "SUCCESS",
        f"[Admin] 批量删除用户 count={len(uuids)} actual_deleted={deleted_count}",
        sid=True,
        sidp="system",
        log_type="admin",
        event_type="USER_BATCH_DELETE",
        client_ip=_client_ip(request),
        request_method=request.method,
        request_url=str(request.url),
        user_agent=request.headers.get("user-agent"),
    )
    return {"deleted": deleted_count}


@router.delete("/users/{user_uuid}", response_model=dict[str, Any])
async def admin_delete_user(
    request: Request,
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

    _log_user_personal_event(
        request=request,
        user_uuid=user_uuid,
        event_type="USER_DELETE",
        content=f"[Admin] 管理员 {current_user.get('uuid')} 删除用户",
        before_data={"user_role": target_role, "current_status": target_user.get("current_status")},
    )
    return {"success": True}


@router.post("/users/{user_uuid}/disable", response_model=dict[str, Any])
async def admin_disable_user(
    request: Request,
    user_uuid: str,
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：禁用用户。"""
    target_user = await UsersDAO().find_by_uuid(user_uuid)
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")

    updated = await UsersDAO().update(user_uuid, {"current_status": "disabled"})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)

    _log_user_personal_event(
        request=request,
        user_uuid=user_uuid,
        event_type="USER_DISABLE",
        content=f"[Admin] 管理员 {current_user.get('uuid')} 禁用用户",
        before_data={"current_status": target_user.get("current_status")},
        after_data={"current_status": "disabled"},
    )
    return updated


@router.post("/users/{user_uuid}/enable", response_model=dict[str, Any])
async def admin_enable_user(
    request: Request,
    user_uuid: str,
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：启用用户。"""
    target_user = await UsersDAO().find_by_uuid(user_uuid)
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")

    updated = await UsersDAO().update(user_uuid, {"current_status": "normal"})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)

    _log_user_personal_event(
        request=request,
        user_uuid=user_uuid,
        event_type="USER_ENABLE",
        content=f"[Admin] 管理员 {current_user.get('uuid')} 启用用户",
        before_data={"current_status": target_user.get("current_status")},
        after_data={"current_status": "normal"},
    )
    return updated


@router.post("/users/{user_uuid}/ban", response_model=dict[str, Any])
async def admin_ban_user(
    request: Request,
    user_uuid: str,
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：封禁用户。"""
    target_user = await UsersDAO().find_by_uuid(user_uuid)
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")

    updated = await UsersDAO().update(user_uuid, {"current_status": "banned"})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)

    _log_user_personal_event(
        request=request,
        user_uuid=user_uuid,
        event_type="USER_BAN",
        content=f"[Admin] 管理员 {current_user.get('uuid')} 封禁用户",
        before_data={"current_status": target_user.get("current_status")},
        after_data={"current_status": "banned"},
    )
    return updated


@router.post("/users/{user_uuid}/unban", response_model=dict[str, Any])
async def admin_unban_user(
    request: Request,
    user_uuid: str,
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：解除封禁。"""
    target_user = await UsersDAO().find_by_uuid(user_uuid)
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")

    updated = await UsersDAO().update(user_uuid, {"current_status": "normal"})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    invalidate_user_cache(user_uuid)

    _log_user_personal_event(
        request=request,
        user_uuid=user_uuid,
        event_type="USER_UNBAN",
        content=f"[Admin] 管理员 {current_user.get('uuid')} 解除封禁",
        before_data={"current_status": target_user.get("current_status")},
        after_data={"current_status": "normal"},
    )
    return updated


@router.post("/users/{user_uuid}/reset-password", response_model=dict[str, Any])
async def admin_reset_password(
    request: Request,
    user_uuid: str,
    payload: ResetPasswordRequest,
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员重置用户密码。

    安全限制：
    1. 必须提供超级密码 (SUPER_PASSWORD)
    2. 新密码必须是 64 字符 SHA256 hex
    3. 重置后撤销该用户所有 refresh token，强制重新登录

    允许重置任何用户的密码（包括管理员自己的）。
    """
    # 1. 校验超级密码
    _verify_super_password(payload.super_password)

    # 2. 哈希新密码并更新
    new_hashed = get_password_hash(payload.new_password)
    updated = await UsersDAO().update(user_uuid, {"password": new_hashed})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")

    # 3. 撤销所有 refresh token，强制用户重新登录
    await RefreshTokensDAO.revoke_all_for_user(user_uuid)

    # 4. 失效 Redis 缓存
    invalidate_user_cache(user_uuid)

    _log_user_personal_event(
        request=request,
        user_uuid=user_uuid,
        event_type="PASSWORD_RESET",
        content=f"[Admin] 管理员 {current_user.get('uuid')} 重置用户密码",
    )
    return {"message": "密码重置成功"}


@router.post("/users/sensitive-data", response_model=dict[str, Any])
async def admin_sensitive_data(
    request: Request,
    payload: SensitiveDataRequest,
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员查看用户敏感信息（真实姓名、班级）。

    安全限制：
    1. 必须提供超级密码 (SUPER_PASSWORD)
    2. 每次最多查询 50 个用户
    """
    # 1. 校验超级密码
    _verify_super_password(payload.super_password)

    # 2. 批量查询用户
    async with get_session() as session:
        users = await UsersDAO.find_by_uuids(session, payload.uuids)

    # 3. 只返回 real_name 和 class
    result: dict[str, dict[str, str | None]] = {}
    for user in users:
        uuid = user.get("uuid", "")
        result[uuid] = {
            "real_name": user.get("real_name"),
            "class": user.get("class"),
        }

    CustomLog(
        "INFO",
        f"[Admin] 管理员 {current_user.get('uuid')} 查看敏感信息 count={len(payload.uuids)}",
        sid=True,
        sidp="system",
        log_type="admin",
        event_type="SENSITIVE_DATA_VIEW",
        client_ip=_client_ip(request),
        request_method=request.method,
        request_url=str(request.url),
        user_agent=request.headers.get("user-agent"),
    )
    return {"data": result}


# =========================================================================
# 注册问题管理
# =========================================================================

class QuestionCreateRequest(BaseModel):
    """创建题目请求体。"""
    question: str = Field(..., min_length=1, max_length=500, description="题目内容")
    question_type: Literal["choice", "true_false", "fill_blank"] = Field(..., description="题目类型")
    answer: str = Field(..., min_length=1, max_length=200, description="正确答案")
    options: list[str] | None = Field(None, description="选择题选项列表")
    question_level: str | None = Field(None, description="题目难度")

    @field_validator("options")
    @classmethod
    def choice_options_must_have_at_least_two(cls, v: list[str] | None, info):
        if info.data.get("question_type") == "choice":
            if not v or len(v) < 2:
                raise ValueError("选择题至少需要 2 个选项")
            if len(v) != len(set(v)):
                raise ValueError("选项不能重复")
        return v

    @model_validator(mode="after")
    def choice_answer_must_be_in_options(self):
        if self.question_type == "choice" and self.options:
            if self.answer not in self.options:
                raise ValueError("答案必须在选项中")
        if self.question_type == "true_false":
            if self.answer.lower() not in ("true", "false"):
                raise ValueError("判断题答案只能为 true 或 false")
        return self


class QuestionUpdateRequest(BaseModel):
    """更新题目请求体（所有字段可选）。"""
    question: str | None = Field(None, min_length=1, max_length=500)
    answer: str | None = Field(None, min_length=1, max_length=200)
    options: list[str] | None = Field(None)
    question_level: str | None = Field(None)
    current_status: str | None = Field(None)

    @model_validator(mode="after")
    def at_least_one_field(self):
        if not any([self.question, self.answer, self.options is not None,
                    self.question_level, self.current_status]):
            raise ValueError("至少需要提供一个修改字段")
        return self


class StatusUpdateRequest(BaseModel):
    """状态更新请求体。"""
    status: Literal["active", "inactive"] = Field(..., description="目标状态")


class BatchDeleteRequest(BaseModel):
    """批量删除请求体。"""
    uuids: list[str] = Field(..., min_length=1, description="要删除的题目 UUID 列表")


class BatchStatusRequest(BaseModel):
    """批量状态更新请求体。"""
    uuids: list[str] = Field(..., min_length=1, description="要更新的题目 UUID 列表")
    status: Literal["active", "inactive"] = Field(..., description="目标状态")


@router.get("/questions/stats", response_model=dict[str, Any])
async def admin_questions_stats(
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：题目统计（按题型分布）。"""
    total = await RegisterQuestionsDAO.count_questions()
    choice_count = await RegisterQuestionsDAO.count_by_type("choice")
    true_false_count = await RegisterQuestionsDAO.count_by_type("true_false")
    fill_blank_count = await RegisterQuestionsDAO.count_by_type("fill_blank")
    return {
        "total": total,
        "choice": choice_count,
        "true_false": true_false_count,
        "fill_blank": fill_blank_count,
    }


@router.get("/questions", response_model=list[dict[str, Any]])
async def admin_list_questions(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    keyword: str | None = Query(None, description="搜索关键词（模糊匹配题目内容）"),
    question_type: str | None = Query(None, alias="type", description="按题型筛选"),
    status: str | None = Query(None, description="按状态筛选（active/inactive）"),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：分页搜索题目列表。"""
    return await RegisterQuestionsDAO.search_questions(
        keyword=keyword, question_type=question_type, status=status,
        limit=limit, offset=offset,
    )


@router.get("/questions/total", response_model=dict[str, Any])
async def admin_questions_total(
    keyword: str | None = Query(None),
    question_type: str | None = Query(None, alias="type"),
    status: str | None = Query(None),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：获取题目总数（可选筛选）。"""
    total = await RegisterQuestionsDAO.count_questions(
        keyword=keyword, question_type=question_type, status=status,
    )
    return {"total": total}


@router.post("/questions", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def admin_create_question(
    payload: QuestionCreateRequest,
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：创建题目。"""
    data = payload.model_dump(exclude_none=True)
    data["uuid"] = str(uuid_lib.uuid4())
    data["created_by"] = current_user["uuid"]
    data["current_status"] = "active"
    if data.get("options") is not None:
        data["options"] = json.dumps(data["options"], ensure_ascii=False)
    created = await RegisterQuestionsDAO().create(data)
    return created


@router.post("/questions/batch-delete", response_model=dict[str, Any])
async def admin_batch_delete_questions(
    payload: BatchDeleteRequest,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：批量删除题目。"""
    deleted = await RegisterQuestionsDAO.batch_delete_by_uuids(payload.uuids)
    CustomLog("SUCCESS", f"[Admin] 批量删除题目 count={len(payload.uuids)} actual_deleted={deleted}")
    return {"deleted": deleted}


@router.patch("/questions/batch-status", response_model=dict[str, Any])
async def admin_batch_update_question_status(
    payload: BatchStatusRequest,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：批量切换题目状态。"""
    updated = await RegisterQuestionsDAO.batch_update_status(payload.uuids, payload.status)
    CustomLog("SUCCESS", f"[Admin] 管理员批量切换题目状态 count={len(payload.uuids)} actual_updated={updated} -> {payload.status}")
    return {"updated": updated}


@router.patch("/questions/{question_uuid}", response_model=dict[str, Any])
async def admin_update_question(
    question_uuid: str,
    payload: QuestionUpdateRequest,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：编辑题目。"""
    # 先查找题目，获取当前 question_type 以便校验
    existing = await RegisterQuestionsDAO().find_by_uuid(question_uuid)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="题目不存在")

    data = payload.model_dump(exclude_none=True)
    if "answer" in data and existing.get("question_type") == "true_false":
        if data["answer"].lower() not in ("true", "false"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="判断题答案只能为 true 或 false",
            )
    # Cross-validate answer vs options for choice questions
    if "answer" in data and "options" in data and existing.get("question_type") == "choice":
        new_options = data.get("options")
        if new_options is not None:
            import json as _json
            if isinstance(new_options, str):
                parsed_options = _json.loads(new_options)
            else:
                parsed_options = new_options
            if data["answer"] not in parsed_options:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="更新后的答案必须在选项中",
                )
    # Nullify options when question_type changes away from choice
    if "question_type" in data:
        existing_type = existing.get("question_type")
        new_type = data["question_type"]
        if existing_type == "choice" and new_type != "choice":
            data["options"] = None
    if "options" in data:
        if data["options"] is not None:
            data["options"] = json.dumps(data["options"], ensure_ascii=False)
    if not data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="未提供要修改的字段")

    updated = await RegisterQuestionsDAO().update(question_uuid, data)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="题目不存在")
    CustomLog("SUCCESS", f"[Admin] 管理员编辑题目 uuid={question_uuid}")
    return updated


@router.delete("/questions/{question_uuid}", response_model=dict[str, Any])
async def admin_delete_question(
    question_uuid: str,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：删除单题。"""
    ok = await RegisterQuestionsDAO().delete(question_uuid)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="题目不存在")
    CustomLog("SUCCESS", f"[Admin] 管理员删除题目 uuid={question_uuid}")
    return {"success": True}


class ConfigViewRequest(BaseModel):
    """查看系统配置请求体。"""
    super_password: str = Field(..., description="超级密码")


# 敏感配置项：值用 ****** 屏蔽
_SENSITIVE_KEYS: set[str] = {
    "DATABASE_URL",
    "REDIS_URL",
    "JWT_SECRET_KEY",
    "SUPER_PASSWORD",
}

# 配置分组定义：(分组名, [(key, 中文说明), ...])
_CONFIG_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    ("服务器", [
        ("SERVER_HOST", "监听地址"),
        ("SERVER_PORT", "监听端口"),
        ("SERVER_RELOAD", "热重载"),
        ("APP_ENV", "运行环境"),
        ("TZ", "时区"),
    ]),
    ("API", [
        ("API_V1_PREFIX", "API v1 前缀"),
    ]),
    ("CORS", [
        ("CORS_ALLOW_ORIGINS", "允许来源"),
        ("CORS_ALLOW_CREDENTIALS", "允许凭证"),
    ]),
    ("数据库", [
        ("DATABASE_URL", "连接地址"),
        ("DB_POOL_PRE_PING", "连接池预检"),
    ]),
    ("Redis", [
        ("REDIS_URL", "连接地址"),
        ("REDIS_INITIAL_RETRY_INTERVAL", "初始重试间隔（秒）"),
        ("REDIS_MAX_RETRY_INTERVAL", "最大重试间隔（秒）"),
        ("REDIS_HEARTBEAT_INTERVAL", "心跳间隔（秒）"),
    ]),
    ("JWT", [
        ("JWT_SECRET_KEY", "签名密钥"),
        ("ACCESS_TOKEN_EXPIRE_MINUTES", "访问令牌有效期（分钟）"),
        ("TEMP_TOKEN_EXPIRE_MINUTES", "临时令牌有效期（分钟）"),
        ("JWT_ALGORITHM", "签名算法"),
    ]),
    ("用户认证", [
        ("AUTH_USER_CACHE_TTL_SECONDS", "认证缓存 TTL（秒）"),
    ]),
    ("防火墙", [
        ("FW_ENABLED", "总开关"),
        ("FW_MAX_REQUESTS_PER_SECOND", "每秒最大请求数"),
        ("FW_BAN_THRESHOLD", "封禁触发阈值"),
        ("FW_BAN_DURATION", "封禁时长（秒）"),
    ]),
    ("登录限流", [
        ("LOGIN_MAX_ATTEMPTS_PER_IP_PER_MINUTE", "单 IP 每分钟最大尝试次数"),
        ("LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_MINUTE", "单用户名每分钟最大尝试次数"),
        ("LOGIN_RATE_WINDOW_SECONDS", "限流窗口（秒）"),
    ]),
    ("注册", [
        ("REG_MAX_IP_ATTEMPTS_PER_DAY", "单 IP 每日最大注册次数"),
        ("REG_MAX_NAME_ATTEMPTS_PER_DAY", "单姓名每日最大注册次数"),
        ("REG_MAX_SHEET_ATTEMPTS", "答题卷最大尝试次数"),
        ("REG_MAX_SHEETS_PER_IP_PER_DAY", "单 IP 每日最大答题卷数"),
        ("REG_CORRECT_THRESHOLD", "及格正确题数"),
        ("REG_QUESTION_COUNT", "题目数量"),
        ("REG_SHEET_TTL_SECONDS", "答题卷有效期（秒）"),
        ("ACCOUNT_DELETION_GRACE_DAYS", "账户注销宽限期（天）"),
        ("MAX_PWD_CHG_ATTEMPTS_PER_DAY", "每日最大改密次数"),
    ]),
    ("定时任务", [
        ("CRON_CLEANUP_INTERVAL_HOURS", "清理任务间隔（小时）"),
    ]),
    ("安全清理", [
        ("REFRESH_TOKEN_CLEANUP_DAYS", "刷新令牌清理天数"),
    ]),
    ("超级密码", [
        ("SUPER_PASSWORD", "超级密码"),
    ]),
]


@router.post("/config", response_model=dict[str, Any])
async def admin_view_config(
    request: Request,
    payload: ConfigViewRequest,
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员查看系统配置（只读）。

    安全限制：
    1. 必须为 superadmin 角色
    2. 必须提供正确的超级密码
    3. 敏感配置项（数据库连接串、密钥等）用 ****** 屏蔽
    """
    _verify_super_password(payload.super_password)

    groups: list[dict[str, Any]] = []
    for group_name, items in _CONFIG_GROUPS:
        config_items: list[dict[str, Any]] = []
        for key, description in items:
            raw_value = getattr(settings, key, None)
            if key in _SENSITIVE_KEYS:
                display_value = "******" if raw_value else ""
            else:
                display_value = raw_value
            config_items.append({
                "key": key,
                "value": display_value,
                "description": description,
            })
        groups.append({
            "group": group_name,
            "items": config_items,
        })

    CustomLog(
        "INFO",
        f"[Admin] 管理员 {current_user.get('uuid')} 查看系统配置",
        sid=True,
        sidp="system",
        log_type="admin",
        event_type="CONFIG_VIEW",
        client_ip=_client_ip(request),
        request_method=request.method,
        request_url=str(request.url),
        user_agent=request.headers.get("user-agent"),
    )
    return {"groups": groups}


@router.patch("/questions/{question_uuid}/status", response_model=dict[str, Any])
async def admin_update_question_status(
    question_uuid: str,
    payload: StatusUpdateRequest,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：单题切换状态。"""
    updated = await RegisterQuestionsDAO().update(question_uuid, {"current_status": payload.status})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="题目不存在")
    CustomLog("SUCCESS", f"[Admin] 管理员切换题目状态 uuid={question_uuid} -> {payload.status}")
    return updated
