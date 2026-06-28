"""交互式 Shell 循环（兼容旧的 ``admin_cli shell`` 子命令）。"""

from __future__ import annotations

import argparse
import shlex

from tools.admin_cli import config, db, logs, questions, users
from tools.admin_cli.context import AdminContext


def run_shell(ctx: AdminContext, sub: argparse.Namespace | None = None) -> None:
    """REPL 循环。"""
    if ctx.mode == "api":
        ctx.ensure_login()
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
            _print_help()
            continue
        try:
            _dispatch(ctx, line)
        except SystemExit:
            raise
        except Exception as exc:
            print(f"错误: {exc}")


def _dispatch(ctx: AdminContext, line: str) -> None:
    parts = shlex.split(line)
    if not parts:
        return
    cmd, *rest = parts
    if cmd == "users":
        users.run_interactive(ctx)
    elif cmd == "questions":
        questions.run_interactive(ctx)
    elif cmd == "logs":
        logs.run_interactive(ctx)
    elif cmd == "config":
        config.run_interactive(ctx)
    elif cmd == "db":
        if not rest or rest[0] != "sql":
            raise ValueError("用法: db sql <SQL>")
        db.run(ctx, argparse.Namespace(sql=" ".join(rest[1:])))
    elif cmd in ("menu", "main"):
        from admin_cli.menu_main import show_main_menu

        show_main_menu(ctx)
    else:
        raise ValueError(f"未知命令: {cmd}")


def _print_help() -> None:
    print(
        """
可用命令:
  users         进入用户管理菜单
  questions     进入注册问题管理菜单
  logs          进入日志查询菜单
  config        查看系统配置
  db sql <SQL>  直接执行 SQL（仅 db 模式）
  menu          回到顶层主菜单
  help          显示本帮助
  exit          退出 Shell
"""
    )
