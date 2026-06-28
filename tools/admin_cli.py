#!/usr/bin/env python3
"""Tinder 全系统管理 CLI。

支持两种模式：
- api: 通过 HTTP API 登录后操作（需要 superadmin 账号）
- db:  直接操作数据库（需要 DATABASE_URL 环境变量）

示例:
    python tools/admin_cli.py --mode api users list
    python tools/admin_cli.py --mode api --username admin --password xxx users reset-password <uuid>
    python tools/admin_cli.py --mode db users get <uuid>
    python tools/admin_cli.py --mode db db sql "SELECT * FROM users LIMIT 5"
    python tools/admin_cli.py --mode api shell
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import shlex
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

# 将项目根目录加入 sys.path，以便直接运行时导入 core 等模块
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# 密码哈希辅助（与前端登录逻辑保持一致）
# ---------------------------------------------------------------------------


def double_sha256_hex(value: str) -> str:
    """对字符串做两次 SHA-256，返回 64 字符 hex。"""
    first = hashlib.sha256(value.encode()).hexdigest()
    return hashlib.sha256(first.encode()).hexdigest()


# ---------------------------------------------------------------------------
# API 模式客户端
# ---------------------------------------------------------------------------


class ApiClient:
    """通过 HTTP API 调用后端的管理员客户端。"""

    def __init__(self, base_url: str) -> None:
        import httpx

        self.base_url = base_url.rstrip("/")
        self.token: str | None = None
        self._httpx = httpx
        self._client: Any | None = None

    def _client_sync(self) -> Any:
        if self._client is None:
            self._client = self._httpx.Client(base_url=self.base_url, timeout=30)
        return self._client

    def login(self, username: str, password: str) -> dict[str, Any]:
        payload = {"username": username, "password": double_sha256_hex(password)}
        resp = self._client_sync().post("/api/v1/auth/login", json=payload)
        resp.raise_for_status()
        data = resp.json()
        self.token = data.get("access_token")
        return data

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> Any:
        if not self.token:
            raise RuntimeError("尚未登录，请先调用 login()")
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = self._client_sync().request(
            method, path, params=params, json=json_data, headers=headers
        )
        try:
            resp.raise_for_status()
        except Exception as exc:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise RuntimeError(f"API 错误 ({resp.status_code}): {detail}") from exc
        if resp.status_code == 204:
            return None
        return resp.json()

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, json_data: dict[str, Any] | None = None) -> Any:
        return self.request("POST", path, json_data=json_data)

    def patch(self, path: str, json_data: dict[str, Any] | None = None) -> Any:
        return self.request("PATCH", path, json_data=json_data)

    def delete(self, path: str, json_data: dict[str, Any] | None = None) -> Any:
        return self.request("DELETE", path, json_data=json_data)


# ---------------------------------------------------------------------------
# DB 模式客户端
# ---------------------------------------------------------------------------


class DbClient:
    """直接通过 DAO/数据库连接操作的客户端。"""

    async def run_sql(self, sql: str) -> list[dict[str, Any]]:
        from sqlalchemy import text

        from core.database.connection.pgsql import get_session

        async with get_session() as session:
            result = await session.execute(text(sql))
            rows = result.mappings().all()
            return [dict(row) for row in rows]

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

        hashed = get_password_hash(double_sha256_hex(new_password))
        dao = UsersDAO()
        updated = await dao.update(user_uuid, {"password": hashed})
        if updated:
            await RefreshTokensDAO.revoke_all_for_user(user_uuid)
        return updated

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

    async def search_system_logs(self, **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
        from core.database.dao.system_logs import SystemLogsDAO

        return await SystemLogsDAO.search(**kwargs)

    async def search_personal_logs(
        self, **kwargs: Any
    ) -> tuple[list[dict[str, Any]], int]:
        from core.database.dao.personal_logs import PersonalLogsDAO

        return await PersonalLogsDAO.search(**kwargs)


# ---------------------------------------------------------------------------
# 统一的 CLI 接口
# ---------------------------------------------------------------------------


class AdminCli:
    """命令行入口，根据 mode 选择 API 或 DB 后端。"""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.api: ApiClient | None = None
        self.db: DbClient | None = None

    def _ensure_api(self) -> ApiClient:
        if self.api is None:
            raise RuntimeError("当前不是 API 模式")
        return self.api

    def _ensure_db(self) -> DbClient:
        if self.db is None:
            raise RuntimeError("当前不是 DB 模式")
        return self.db

    async def setup(self) -> None:
        if self.args.mode == "api":
            self.api = ApiClient(self.args.api_url)
            if self.args.username and self.args.password:
                self.api.login(self.args.username, self.args.password)
        elif self.args.mode == "db":
            self.db = DbClient()
            from sqlalchemy import text

            from core.database.connection.pgsql import get_session

            async with get_session() as session:
                await session.execute(text("SELECT 1"))
        else:
            raise ValueError(f"未知模式: {self.args.mode}")

    def login_if_needed(self) -> None:
        """API 模式下如果尚未登录则交互式提示。"""
        if self.args.mode != "api" or self.api is None:
            return
        if self.api.token:
            return
        username = self.args.username or input("用户名: ")
        password = self.args.password or getpass.getpass("密码: ")
        self.api.login(username, password)
        print("登录成功")

    def _super_password(self, override: str | None = None) -> str:
        return override or self.args.super_password or getpass.getpass("超级密码: ")

    # ------------------------------------------------------------------
    # 用户管理命令
    # ------------------------------------------------------------------

    def cmd_users_list(self, sub: argparse.Namespace) -> None:
        params = {
            "keyword": sub.keyword,
            "status": sub.status,
            "role": sub.role,
            "limit": sub.limit,
            "offset": sub.offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().get("/api/v1/admin/users", params)
            print_json(data)
        else:
            rows = asyncio.run(
                self._ensure_db().list_users(
                    keyword=sub.keyword,
                    status=sub.status,
                    role=sub.role,
                    limit=sub.limit,
                    offset=sub.offset,
                )
            )
            print_json(rows)

    def cmd_users_get(self, sub: argparse.Namespace) -> None:
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().get(f"/api/v1/admin/users/{sub.uuid}")
            print_json(data)
        else:
            row = asyncio.run(self._ensure_db().get_user(sub.uuid))
            print_json(row)

    def cmd_users_create(self, sub: argparse.Namespace) -> None:
        payload = _load_json_or_prompt(sub.data, "创建用户数据 (JSON):")
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().post("/api/v1/admin/users", json_data=payload)
            print_json(data)
        else:
            row = asyncio.run(self._ensure_db().create_user(payload))
            print_json(row)

    def cmd_users_update(self, sub: argparse.Namespace) -> None:
        payload = _load_json_or_prompt(sub.data, "更新用户数据 (JSON):")
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().patch(
                f"/api/v1/admin/users/{sub.uuid}", json_data=payload
            )
            print_json(data)
        else:
            row = asyncio.run(self._ensure_db().update_user(sub.uuid, payload))
            print_json(row)

    def cmd_users_delete(self, sub: argparse.Namespace) -> None:
        super_password = self._super_password(sub.super_password)
        if self.args.mode == "api":
            self.login_if_needed()
            self._ensure_api().delete(
                f"/api/v1/admin/users/{sub.uuid}",
                json_data={"super_password": super_password},
            )
            print("删除成功")
        else:
            ok = asyncio.run(self._ensure_db().delete_user(sub.uuid))
            print("删除成功" if ok else "删除失败或用户不存在")

    def cmd_users_reset_password(self, sub: argparse.Namespace) -> None:
        super_password = self._super_password(sub.super_password)
        new_password = sub.new_password or _generate_random_password(12)
        if self.args.mode == "api":
            self.login_if_needed()
            self._ensure_api().post(
                f"/api/v1/admin/users/{sub.uuid}/reset-password",
                json_data={
                    "super_password": super_password,
                    "new_password": double_sha256_hex(new_password),
                },
            )
        else:
            asyncio.run(self._ensure_db().reset_password(sub.uuid, new_password))
        print("密码重置成功")
        print(f"新密码: {new_password}")
        print("请将该密码告知用户，登录时系统会自动做双重哈希。")

    def cmd_users_status(self, sub: argparse.Namespace) -> None:
        action = sub.action
        if self.args.mode == "api":
            self.login_if_needed()
            self._ensure_api().post(f"/api/v1/admin/users/{sub.uuid}/{action}")
            print(f"操作 {action} 成功")
        else:
            asyncio.run(self._ensure_db().set_user_status(sub.uuid, action))
            print(f"操作 {action} 成功")

    # ------------------------------------------------------------------
    # 注册问题管理命令
    # ------------------------------------------------------------------

    def cmd_questions_list(self, sub: argparse.Namespace) -> None:
        params = {
            "keyword": sub.keyword,
            "type": sub.type,
            "status": sub.status,
            "limit": sub.limit,
            "offset": sub.offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().get("/api/v1/admin/questions", params)
            print_json(data)
        else:
            rows = asyncio.run(
                self._ensure_db().list_questions(
                    keyword=sub.keyword,
                    question_type=sub.type,
                    status=sub.status,
                    limit=sub.limit,
                    offset=sub.offset,
                )
            )
            print_json(rows)

    def cmd_questions_get(self, sub: argparse.Namespace) -> None:
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().get(f"/api/v1/admin/questions/{sub.uuid}")
            print_json(data)
        else:
            row = asyncio.run(self._ensure_db().get_question(sub.uuid))
            print_json(row)

    def cmd_questions_create(self, sub: argparse.Namespace) -> None:
        payload = _load_json_or_prompt(sub.data, "创建题目数据 (JSON):")
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().post("/api/v1/admin/questions", json_data=payload)
            print_json(data)
        else:
            row = asyncio.run(self._ensure_db().create_question(payload))
            print_json(row)

    def cmd_questions_update(self, sub: argparse.Namespace) -> None:
        payload = _load_json_or_prompt(sub.data, "更新题目数据 (JSON):")
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().patch(
                f"/api/v1/admin/questions/{sub.uuid}", json_data=payload
            )
            print_json(data)
        else:
            row = asyncio.run(self._ensure_db().update_question(sub.uuid, payload))
            print_json(row)

    def cmd_questions_delete(self, sub: argparse.Namespace) -> None:
        if self.args.mode == "api":
            self.login_if_needed()
            self._ensure_api().delete(f"/api/v1/admin/questions/{sub.uuid}")
            print("删除成功")
        else:
            ok = asyncio.run(self._ensure_db().delete_question(sub.uuid))
            print("删除成功" if ok else "删除失败或题目不存在")

    # ------------------------------------------------------------------
    # 系统配置与日志
    # ------------------------------------------------------------------

    def cmd_config(self, sub: argparse.Namespace) -> None:
        if self.args.mode == "api":
            self.login_if_needed()
            super_password = self._super_password(getattr(sub, "super_password", None))
            data = self._ensure_api().post(
                "/api/v1/admin/config",
                json_data={"super_password": super_password},
            )
            print_json(data)
        else:
            from core.config import settings

            print("系统配置（只读，敏感字段已屏蔽）：")
            for key in sorted(dir(settings)):
                if key.startswith("_"):
                    continue
                value = getattr(settings, key)
                if isinstance(value, (str, int, float, bool, list)):
                    print(f"  {key} = {value}")

    def cmd_logs_system(self, sub: argparse.Namespace) -> None:
        params = _log_params(sub)
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().get("/api/v1/logs/system", params)
            _print_paginated_logs(data)
        else:
            items, total = asyncio.run(
                self._ensure_db().search_system_logs(**_db_log_kwargs(sub))
            )
            print_json({"total": total, "items": items})

    def cmd_logs_personal(self, sub: argparse.Namespace) -> None:
        params = _log_params(sub)
        path = "/api/v1/logs/personal"
        if sub.user_uuid:
            path = f"/api/v1/logs/personal/{sub.user_uuid}"
        if self.args.mode == "api":
            self.login_if_needed()
            data = self._ensure_api().get(path, params)
            _print_paginated_logs(data)
        else:
            kwargs = _db_log_kwargs(sub)
            if sub.user_uuid:
                kwargs["user_uuids"] = [sub.user_uuid]
            items, total = asyncio.run(
                self._ensure_db().search_personal_logs(**kwargs)
            )
            print_json({"total": total, "items": items})

    # ------------------------------------------------------------------
    # 直接 SQL
    # ------------------------------------------------------------------

    def cmd_db_sql(self, sub: argparse.Namespace) -> None:
        if self.args.mode != "db":
            raise RuntimeError("db sql 命令仅在 --mode db 下可用")
        rows = asyncio.run(self._ensure_db().run_sql(sub.sql))
        print_json(rows)

    # ------------------------------------------------------------------
    # 交互式 Shell
    # ------------------------------------------------------------------

    def cmd_shell(self, sub: argparse.Namespace) -> None:
        if self.args.mode == "api":
            self.login_if_needed()
        print("Tinder Admin Shell")
        print("输入 'help' 查看可用命令，'exit' 退出。")
        while True:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line or line in ("exit", "quit"):
                break
            if line == "help":
                _print_shell_help()
                continue
            try:
                self._dispatch_shell(line)
            except SystemExit:
                pass
            except Exception as exc:
                print(f"错误: {exc}")

    def _dispatch_shell(self, line: str) -> None:
        parts = shlex.split(line)
        if not parts:
            return
        cmd, *rest = parts
        if cmd == "users":
            parser = _build_users_subparser()
            parsed = parser.parse_args(rest)
            self._run_users_cmd(parsed)
        elif cmd == "questions":
            parser = _build_questions_subparser()
            parsed = parser.parse_args(rest)
            self._run_questions_cmd(parsed)
        elif cmd == "logs":
            parser = _build_logs_subparser()
            parsed = parser.parse_args(rest)
            self._run_logs_cmd(parsed)
        elif cmd == "config":
            self.cmd_config(argparse.Namespace())
        elif cmd == "db":
            if len(rest) < 2 or rest[0] != "sql":
                raise ValueError("用法: db sql <SQL>")
            self.cmd_db_sql(argparse.Namespace(sql=" ".join(rest[1:])))
        else:
            raise ValueError(f"未知命令: {cmd}")

    def _run_users_cmd(self, parsed: argparse.Namespace) -> None:
        action = parsed.action
        if action in ("ban", "unban", "disable", "enable"):
            parsed.action = action
            self.cmd_users_status(parsed)
        else:
            getattr(self, f"cmd_users_{action}")(parsed)

    def _run_questions_cmd(self, parsed: argparse.Namespace) -> None:
        getattr(self, f"cmd_questions_{parsed.action}")(parsed)

    def _run_logs_cmd(self, parsed: argparse.Namespace) -> None:
        getattr(self, f"cmd_logs_{parsed.action}")(parsed)


# ---------------------------------------------------------------------------
# 命令行参数解析
# ---------------------------------------------------------------------------


def _build_users_subparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="users")
    sub = parser.add_subparsers(dest="action", required=True)

    list_p = sub.add_parser("list", help="列出用户")
    list_p.add_argument("--keyword", help="关键词搜索")
    list_p.add_argument("--status", help="按状态筛选")
    list_p.add_argument("--role", help="按角色筛选")
    list_p.add_argument("--limit", type=int, default=20)
    list_p.add_argument("--offset", type=int, default=0)

    get_p = sub.add_parser("get", help="查看用户详情")
    get_p.add_argument("uuid", help="用户 UUID")

    create_p = sub.add_parser("create", help="创建用户")
    create_p.add_argument("--data", help="JSON 数据（不提供则交互式输入）")

    update_p = sub.add_parser("update", help="更新用户")
    update_p.add_argument("uuid", help="用户 UUID")
    update_p.add_argument("--data", help="JSON 数据（不提供则交互式输入）")

    delete_p = sub.add_parser("delete", help="删除用户")
    delete_p.add_argument("uuid", help="用户 UUID")
    delete_p.add_argument("--super-password", help="超级密码")

    reset_p = sub.add_parser("reset-password", help="重置用户密码")
    reset_p.add_argument("uuid", help="用户 UUID")
    reset_p.add_argument("--super-password", help="超级密码")
    reset_p.add_argument("--new-password", help="新密码（不提供则自动生成）")

    for action in ("ban", "unban", "disable", "enable"):
        p = sub.add_parser(action, help=f"{action} 用户")
        p.add_argument("uuid", help="用户 UUID")

    return parser


def _build_questions_subparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="questions")
    sub = parser.add_subparsers(dest="action", required=True)

    list_p = sub.add_parser("list", help="列出题目")
    list_p.add_argument("--keyword", help="关键词搜索")
    list_p.add_argument("--type", help="按题型筛选")
    list_p.add_argument("--status", help="按状态筛选")
    list_p.add_argument("--limit", type=int, default=20)
    list_p.add_argument("--offset", type=int, default=0)

    get_p = sub.add_parser("get", help="查看题目详情")
    get_p.add_argument("uuid", help="题目 UUID")

    create_p = sub.add_parser("create", help="创建题目")
    create_p.add_argument("--data", help="JSON 数据（不提供则交互式输入）")

    update_p = sub.add_parser("update", help="更新题目")
    update_p.add_argument("uuid", help="题目 UUID")
    update_p.add_argument("--data", help="JSON 数据（不提供则交互式输入）")

    delete_p = sub.add_parser("delete", help="删除题目")
    delete_p.add_argument("uuid", help="题目 UUID")

    return parser


def _build_logs_subparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logs")
    sub = parser.add_subparsers(dest="action", required=True)

    for name in ("system", "personal"):
        p = sub.add_parser(name, help=f"查询{name}日志")
        p.add_argument("--event-type", help="事件类型")
        p.add_argument("--log-type", help="日志类型")
        p.add_argument("--status", help="状态")
        p.add_argument("--severity", help="严重级别")
        p.add_argument("--trace-id", help="Trace ID")
        p.add_argument("--client-ip", help="客户端 IP")
        p.add_argument("--keyword", help="内容关键词")
        p.add_argument("--start-time", help="开始时间 ISO")
        p.add_argument("--end-time", help="结束时间 ISO")
        p.add_argument("--limit", type=int, default=20)
        p.add_argument("--offset", type=int, default=0)

    personal = sub.add_parser("personal", help="查询个人日志")
    personal.add_argument("--user-uuid", help="指定用户 UUID")

    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Tinder 全系统管理 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --mode api users list
  %(prog)s --mode api --username admin --password xxx users reset-password <uuid>
  %(prog)s --mode db users get <uuid>
  %(prog)s --mode db db sql "SELECT * FROM users LIMIT 5"
  %(prog)s --mode api shell
        """.strip(),
    )
    parser.add_argument(
        "--mode",
        choices=("api", "db"),
        default="api",
        help="运行模式：api 通过接口调用，db 直连数据库",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:1912",
        help="API 模式下的基础 URL",
    )
    parser.add_argument("--username", help="API 登录用户名")
    parser.add_argument("--password", help="API 登录密码（推荐交互式输入）")
    parser.add_argument(
        "--super-password", help="高危操作所需的超级密码（推荐交互式输入）"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("login", help="API 登录并显示 Token")
    sub.add_parser("shell", help="进入交互式 Shell")

    users_p = sub.add_parser("users", help="用户管理")
    users_p.add_subparsers(dest="_ignore")
    users_p.epilog = "完整子命令见 help"

    questions_p = sub.add_parser("questions", help="注册问题管理")
    questions_p.add_subparsers(dest="_ignore")

    logs_p = sub.add_parser("logs", help="日志查询")
    logs_p.add_subparsers(dest="_ignore")

    config_p = sub.add_parser("config", help="查看系统配置")
    config_p.add_argument("--super-password", help="超级密码")

    db_p = sub.add_parser("db", help="直接数据库操作（仅 db 模式）")
    db_sql_p = db_p.add_subparsers(dest="db_action", required=True)
    sql_p = db_sql_p.add_parser("sql", help="执行原始 SQL")
    sql_p.add_argument("sql", help="SQL 语句")

    return parser


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def _load_json_or_prompt(data: str | None, prompt: str) -> dict[str, Any]:
    if data:
        return json.loads(data)
    raw = input(prompt)
    return json.loads(raw)


def _generate_random_password(length: int = 12) -> str:
    import secrets

    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(chars) for _ in range(length))


def _log_params(sub: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = {
        "event_type": getattr(sub, "event_type", None),
        "log_type": getattr(sub, "log_type", None),
        "status": getattr(sub, "status", None),
        "severity": getattr(sub, "severity", None),
        "trace_id": getattr(sub, "trace_id", None),
        "client_ip": getattr(sub, "client_ip", None),
        "keyword": getattr(sub, "keyword", None),
        "start_time": getattr(sub, "start_time", None),
        "end_time": getattr(sub, "end_time", None),
        "limit": getattr(sub, "limit", 20),
        "offset": getattr(sub, "offset", 0),
    }
    return {k: v for k, v in params.items() if v is not None}


def _db_log_kwargs(sub: argparse.Namespace) -> dict[str, Any]:
    kwargs: dict[str, Any] = _log_params(sub).copy()
    for key in ("start_time", "end_time"):
        if kwargs.get(key):
            kwargs[key] = datetime.fromisoformat(kwargs[key])
    return kwargs


def _print_paginated_logs(data: dict[str, Any]) -> None:
    total = data.get("total", 0)
    items = data.get("items", data if isinstance(data, list) else [])
    print(f"共 {total} 条")
    print_json(items)


def print_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def _print_shell_help() -> None:
    print("""
可用命令:
  users list [--keyword ...] [--status ...] [--role ...]
  users get <uuid>
  users create
  users update <uuid>
  users delete <uuid>
  users reset-password <uuid> [--new-password ...]
  users ban|unban|disable|enable <uuid>
  questions list [--keyword ...] [--type ...] [--status ...]
  questions get <uuid>
  questions create
  questions update <uuid>
  questions delete <uuid>
  logs system|personal [...]
  config
  db sql <SQL>          (仅 db 模式)
  help
  exit
""")


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------


def main() -> int:
    if not sys.argv[1:] or sys.argv[1] in ("-h", "--help"):
        build_parser().print_help()
        return 0

    # 先解析全局选项，定位到主命令
    base_parser = argparse.ArgumentParser(add_help=False)
    base_parser.add_argument("--mode", choices=("api", "db"), default="api")
    base_parser.add_argument("--api-url", default="http://localhost:1912")
    base_parser.add_argument("--username")
    base_parser.add_argument("--password")
    base_parser.add_argument("--super-password")
    base_args, remainder = base_parser.parse_known_args()

    if not remainder:
        build_parser().print_help()
        return 0

    cli = AdminCli(base_args)
    asyncio.run(cli.setup())

    command = remainder[0]
    if command == "login":
        cli.login_if_needed()
        print(f"access_token: {cli.api.token if cli.api else 'N/A'}")
        return 0
    if command == "shell":
        cli.cmd_shell(argparse.Namespace())
        return 0

    if command == "users":
        parsed = _build_users_subparser().parse_args(remainder[1:])
        cli._run_users_cmd(parsed)
        return 0
    if command == "questions":
        parsed = _build_questions_subparser().parse_args(remainder[1:])
        cli._run_questions_cmd(parsed)
        return 0
    if command == "logs":
        parsed = _build_logs_subparser().parse_args(remainder[1:])
        cli._run_logs_cmd(parsed)
        return 0
    if command == "config":
        parsed = argparse.Namespace(
            super_password=base_args.super_password or None
        )
        cli.cmd_config(parsed)
        return 0
    if command == "db":
        if len(remainder) < 3 or remainder[1] != "sql":
            print("用法: db sql <SQL>", file=sys.stderr)
            return 1
        cli.cmd_db_sql(argparse.Namespace(sql=remainder[2]))
        return 0

    print(f"未知命令: {command}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
