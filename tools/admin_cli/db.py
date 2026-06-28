"""直接 SQL 命令（仅 DB 模式）。"""

from __future__ import annotations

import argparse

from admin_cli.base import print_json, run_async
from admin_cli.context import AdminContext
from admin_cli.menu import prompt


def run_interactive(ctx: AdminContext) -> None:
    print("--- 直接执行 SQL（仅 DB 模式） ---")
    sql = prompt("SQL 语句", required=True)
    run(ctx, argparse.Namespace(sql=sql))


def run(ctx: AdminContext, sub: argparse.Namespace) -> None:
    if ctx.mode != "db":
        raise RuntimeError("db sql 命令仅在 --mode db 下可用")
    rows = run_async(ctx.require_db().run_sql(sub.sql))
    print_json(rows)


def dispatch(ctx: AdminContext, sub: argparse.Namespace) -> None:
    run(ctx, sub)
