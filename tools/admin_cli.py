#!/usr/bin/env python3
"""Tinder 全系统管理 CLI —— 交互式入口。

两种使用方式：

1. 交互式（默认）：
    python tools/admin_cli.py
    启动后通过编号菜单选择模式、资源与具体操作。

2. 命令行（脚本场景）：
    python tools/admin_cli.py --mode api --username admin users list
    python tools/admin_cli.py --mode db users get <uuid>
    python tools/admin_cli.py --mode db db sql "SELECT * FROM users LIMIT 5"

``--non-interactive`` 在提供子命令但参数不足时直接报错，跳过交互。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT))
# 将 tools/ 加入 sys.path，以便子模块以 ``admin_cli.xxx`` 形式互相导入
# （与 tools/seed_data.py 既有约定保持一致）
sys.path.insert(0, str(_TOOLS_DIR))

# ---------------------------------------------------------------------------
# 旧的 from core.database... 这一行已下沉到子模块，按需延迟导入
# ---------------------------------------------------------------------------


def main() -> int:
    from admin_cli import config as config_cmd
    from admin_cli import db as db_cmd
    from admin_cli import logs as logs_cmd
    from admin_cli import questions as questions_cmd
    from admin_cli import users as users_cmd
    from admin_cli.api_client import ApiClient
    from admin_cli.context import AdminContext
    from admin_cli.db_client import DbClient
    from admin_cli.menu_main import bootstrap
    from admin_cli.parsers import build_base_parser, build_top_parser
    from admin_cli.shell import run_shell

    # 仅 --help
    if not sys.argv[1:] or sys.argv[1] in ("-h", "--help"):
        build_top_parser().print_help()
        return 0

    top = build_top_parser().parse_args()

    # 没有指定 mode → 进入交互式引导
    if top.mode is None:
        bootstrap(
            initial={
                "api_url": top.api_url,
                "username": top.username,
                "password": top.password,
                "super_password": top.super_password,
            }
        )
        return 0

    # 解析 base + 子命令
    base_parser = build_base_parser()
    base_args, remainder = base_parser.parse_known_args(sys.argv[1:])

    if not remainder:
        # 没有子命令：进入交互式主菜单（使用 CLI 参数做默认）
        ctx = _build_context(base_args)
        from admin_cli.menu_main import show_main_menu

        show_main_menu(ctx)
        return 0

    ctx = _build_context(base_args)
    command = remainder[0]

    if command == "login":
        ctx.ensure_login()
        print(f"access_token: {ctx.api.token if ctx.api else 'N/A'}")
        return 0
    if command == "shell":
        run_shell(ctx)
        return 0
    if command == "users":
        from admin_cli.parsers import build_users_subparser

        parsed = build_users_subparser().parse_args(remainder[1:])
        users_cmd.dispatch(ctx, parsed)
        return 0
    if command == "questions":
        from admin_cli.parsers import build_questions_subparser

        parsed = build_questions_subparser().parse_args(remainder[1:])
        questions_cmd.dispatch(ctx, parsed)
        return 0
    if command == "logs":
        from admin_cli.parsers import build_logs_subparser

        parsed = build_logs_subparser().parse_args(remainder[1:])
        logs_cmd.dispatch(ctx, parsed)
        return 0
    if command == "config":
        config_cmd.dispatch(ctx, argparse.Namespace(super_password=base_args.super_password))
        return 0
    if command == "db":
        if len(remainder) < 3 or remainder[1] != "sql":
            print("用法: db sql <SQL>", file=sys.stderr)
            return 1
        db_cmd.run(ctx, argparse.Namespace(sql=remainder[2]))
        return 0

    print(f"未知命令: {command}", file=sys.stderr)
    return 1


def _build_context(base_args: argparse.Namespace) -> AdminContext:
    """根据模式构造 AdminContext（仅做最小探测，不做完整登录）。"""
    ctx = AdminContext(args=base_args)
    if base_args.mode == "api":
        ctx.api = ApiClient(base_args.api_url)
    elif base_args.mode == "db":
        ctx.db = DbClient()
    return ctx


if __name__ == "__main__":
    sys.exit(main())
