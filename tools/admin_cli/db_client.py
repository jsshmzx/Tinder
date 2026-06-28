"""DB 模式客户端：直接通过 DAO/数据库连接操作。"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import text

from core.database.connection.pgsql import get_session


class DbClient:
    """直接通过 DAO/数据库连接操作的客户端。"""

    # ------------------------------------------------------------------
    # 原始 SQL
    # ------------------------------------------------------------------

    async def run_sql(self, sql: str) -> list[dict[str, Any]]:
        async with get_session() as session:
            result = await session.execute(text(sql))
            rows = result.mappings().all()
            return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # 用户
    # ------------------------------------------------------------------

    async def list_users(
        self,
        *,
        keyword: str | None = None,
        status: str | None = None,
        role: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        from core.database.dao.users import UsersDAO

        async with get_session() as session:
            return await UsersDAO.search_users(
                session,
                keyword=keyword,
                status=status,
                role=role,
                limit=limit,
                offset=offset,
            )

    async def count_users(
        self,
        *,
        keyword: str | None = None,
        status: str | None = None,
        role: str | None = None,
    ) -> int:
        from core.database.dao.users import UsersDAO

        async with get_session() as session:
            return await UsersDAO.count_users(
                session, keyword=keyword, status=status, role=role
            )

    async def get_user(self, user_uuid: str) -> dict[str, Any] | None:
        from core.database.dao.users import UsersDAO

        dao = UsersDAO()
        return await dao.find_by_uuid(user_uuid)

    async def update_user(
        self, user_uuid: str, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        from core.database.dao.users import UsersDAO
        from core.security.hash import get_password_hash

        if "password" in payload:
            payload["password"] = get_password_hash(payload["password"])
        dao = UsersDAO()
        return await dao.update(user_uuid, payload)

    async def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        from core.database.dao.users import UsersDAO
        from core.security.hash import get_password_hash

        if "uuid" not in payload or not payload["uuid"]:
            payload["uuid"] = str(uuid.uuid4())
        if "password" in payload:
            payload["password"] = get_password_hash(payload["password"])
        dao = UsersDAO()
        return await dao.create(payload)

    async def delete_user(self, user_uuid: str) -> bool:
        from core.database.dao.users import UsersDAO

        dao = UsersDAO()
        result = await dao.delete(user_uuid)
        return result is not None and result > 0

    async def set_user_status(
        self, user_uuid: str, action: str
    ) -> dict[str, Any] | None:
        from core.database.dao.users import UsersDAO

        status_map = {
            "ban": "banned",
            "unban": "normal",
            "disable": "disabled",
            "enable": "normal",
        }
        if action not in status_map:
            raise ValueError(f"不支持的状态操作: {action}")
        dao = UsersDAO()
        return await dao.update(user_uuid, {"current_status": status_map[action]})

    async def reset_password(
        self, user_uuid: str, new_password: str
    ) -> dict[str, Any] | None:
        from core.database.dao.refresh_tokens import RefreshTokensDAO
        from core.database.dao.users import UsersDAO
        from core.security.hash import get_password_hash
        from admin_cli.base import double_sha256_hex

        hashed = get_password_hash(double_sha256_hex(new_password))
        dao = UsersDAO()
        updated = await dao.update(user_uuid, {"password": hashed})
        if updated:
            await RefreshTokensDAO.revoke_all_for_user(user_uuid)
        return updated

    # ------------------------------------------------------------------
    # 注册问题
    # ------------------------------------------------------------------

    async def list_questions(
        self,
        *,
        keyword: str | None = None,
        question_type: str | None = None,
        status: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        from core.database.dao.register_questions import RegisterQuestionsDAO

        return await RegisterQuestionsDAO.search_questions(
            keyword=keyword,
            question_type=question_type,
            status=status,
            limit=limit,
            offset=offset,
        )

    async def count_questions(
        self,
        *,
        keyword: str | None = None,
        question_type: str | None = None,
        status: str | None = None,
    ) -> int:
        from core.database.dao.register_questions import RegisterQuestionsDAO

        return await RegisterQuestionsDAO.count_questions(
            keyword=keyword, question_type=question_type, status=status
        )

    async def get_question(self, question_uuid: str) -> dict[str, Any] | None:
        from core.database.dao.register_questions import RegisterQuestionsDAO

        dao = RegisterQuestionsDAO()
        return await dao.find_by_uuid(question_uuid)

    async def create_question(self, payload: dict[str, Any]) -> dict[str, Any]:
        from core.database.dao.register_questions import RegisterQuestionsDAO

        if "uuid" not in payload or not payload["uuid"]:
            payload["uuid"] = str(uuid.uuid4())
        dao = RegisterQuestionsDAO()
        return await dao.create(payload)

    async def update_question(
        self, question_uuid: str, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        from core.database.dao.register_questions import RegisterQuestionsDAO

        dao = RegisterQuestionsDAO()
        return await dao.update(question_uuid, payload)

    async def delete_question(self, question_uuid: str) -> bool:
        from core.database.dao.register_questions import RegisterQuestionsDAO

        dao = RegisterQuestionsDAO()
        result = await dao.delete(question_uuid)
        return result is not None and result > 0

    # ------------------------------------------------------------------
    # 日志
    # ------------------------------------------------------------------

    async def search_system_logs(self, **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
        from core.database.dao.system_logs import SystemLogsDAO

        return await SystemLogsDAO.search(**kwargs)

    async def search_personal_logs(
        self, **kwargs: Any
    ) -> tuple[list[dict[str, Any]], int]:
        from core.database.dao.personal_logs import PersonalLogsDAO

        return await PersonalLogsDAO.search(**kwargs)


# ---------------------------------------------------------------------------
# 日志参数转换
# ---------------------------------------------------------------------------


def build_log_params(source: Any) -> dict[str, Any]:
    """将 argparse Namespace 或 dict 转换为 API 请求参数。"""
    if isinstance(source, dict):
        raw = source
    else:
        raw = {
            "event_type": getattr(source, "event_type", None),
            "log_type": getattr(source, "log_type", None),
            "status": getattr(source, "status", None),
            "severity": getattr(source, "severity", None),
            "trace_id": getattr(source, "trace_id", None),
            "client_ip": getattr(source, "client_ip", None),
            "keyword": getattr(source, "keyword", None),
            "start_time": getattr(source, "start_time", None),
            "end_time": getattr(source, "end_time", None),
            "limit": getattr(source, "limit", 20),
            "offset": getattr(source, "offset", 0),
        }
    return {k: v for k, v in raw.items() if v not in (None, "")}


def build_log_db_kwargs(source: Any) -> dict[str, Any]:
    """将 argparse Namespace 或 dict 转换为 DAO 搜索参数（自动解析 ISO 时间）。"""
    kwargs = build_log_params(source).copy()
    for key in ("start_time", "end_time"):
        if kwargs.get(key):
            kwargs[key] = datetime.fromisoformat(kwargs[key])
    return kwargs
