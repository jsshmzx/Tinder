import json
import uuid as uuid_lib
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select as sa_select

from core.config import settings
from core.database.connection.pgsql import get_session
from core.database.connection.redis import redis_conn
from core.database.dao.register_questions import RegisterQuestionsDAO
from core.database.dao.users import UsersDAO, User
from core.middleware.auth.dependencies import MinRoleChecker, invalidate_user_cache, get_current_user, USER_CACHE_PREFIX
from core.security.hash import get_password_hash
from core.security.rbac import Role
from core.helper.CustomLog.index import CustomLog


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
        CustomLog("WARNING", f"[Admin] 批量缓存失效失败 count={len(uuids)} exc={exc}")


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
    CustomLog("SUCCESS", f"[Admin] 批量删除用户 count={len(uuids)} actual_deleted={deleted_count}")
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
    CustomLog("SUCCESS", f"[Admin] 禁用用户 uuid={user_uuid}")
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
    CustomLog("SUCCESS", f"[Admin] 启用用户 uuid={user_uuid}")
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
    CustomLog("SUCCESS", f"[Admin] 封禁用户 uuid={user_uuid}")
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
    CustomLog("SUCCESS", f"[Admin] 解封用户 uuid={user_uuid}")
    return updated


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

