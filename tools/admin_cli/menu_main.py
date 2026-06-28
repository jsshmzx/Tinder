"""顶层主菜单：选择模式 → 登录 → 选择资源。"""

from __future__ import annotations

from typing import Any

from admin_cli.api_client import ApiClient
from admin_cli import config, db as db_cmd, logs, questions, shell, users
from admin_cli.context import AdminContext
from admin_cli.db_client import DbClient
from admin_cli.menu import (
    confirm,
    prompt,
    prompt_choice,
    run_menu,
)


def show_main_menu(ctx: AdminContext) -> None:
    """显示顶层主菜单并循环处理用户选择。"""
    run_menu(
        "Tinder 管理 CLI — 主菜单",
        [
            ("1", "用户管理 (users)", lambda: users.run_interactive(ctx)),
            ("2", "注册问题管理 (questions)", lambda: questions.run_interactive(ctx)),
            ("3", "日志查询 (logs)", lambda: logs.run_interactive(ctx)),
            ("4", "系统配置 (config)", lambda: config.run_interactive(ctx)),
            ("5", "直接执行 SQL (仅 DB 模式)", lambda: db_cmd.run_interactive(ctx)),
            ("6", "进入 Shell 模式", lambda: shell.run_shell(ctx)),
        ],
        allow_back=False,
    )


# ---------------------------------------------------------------------------
# 引导式启动（mode + 登录）
# ---------------------------------------------------------------------------


def bootstrap(initial: dict[str, Any] | None = None) -> AdminContext | None:
    """交互式引导用户选择模式、完成登录，并返回 AdminContext。

    ``initial`` 字典可传入 ``mode``、``api_url``、``username``、``password``、``super_password`` 等，
    已提供的值将作为默认提示，避免重复输入。返回 ``None`` 表示用户取消。
    """
    initial = initial or {}
    default_mode = initial.get("mode") or "api"
    mode = prompt_choice(
        "请选择运行模式：",
        [("api", "API 模式（通过 HTTP API）"), ("db", "DB 模式（直连数据库）")],
        default=default_mode,
    )
    if mode not in ("api", "db"):
        print("已取消。")
        return None

    args_dict: dict[str, Any] = {"mode": mode, "api_url": "http://localhost:1912"}
    if initial.get("api_url"):
        args_dict["api_url"] = initial["api_url"]

    api: ApiClient | None = None
    db_client: DbClient | None = None

    if mode == "api":
        url = initial.get("api_url") or prompt("API 基础 URL", "http://localhost:1912")
        api = ApiClient(url)
        username = initial.get("username") or prompt("用户名", required=True)
        password = initial.get("password") or prompt("密码", required=True)
        try:
            api.login(username, password)
            print("登录成功！")
        except Exception as exc:
            print(f"登录失败: {exc}")
            if not confirm("仍要进入只读菜单？", default=False):
                return None
    else:
        # DB 模式：探测连接
        import asyncio

        from sqlalchemy import text

        from core.database.connection.pgsql import get_session

        async def _probe() -> None:
            async with get_session() as session:
                await session.execute(text("SELECT 1"))

        try:
            asyncio.run(_probe())
            print("数据库连接成功！")
        except Exception as exc:
            print(f"数据库连接失败: {exc}")
            return None
        db_client = DbClient()

    ctx = AdminContext(
        args=_FakeArgs(args_dict),
        api=api,
        db=db_client,
    )
    show_main_menu(ctx)
    return ctx


class _FakeArgs:
    """轻量命名空间对象，兼容 AdminContext 对 argparse.Namespace 的依赖。"""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getattr__(self, item: str) -> Any:
        if item in self._data:
            return self._data[item]
        return None
