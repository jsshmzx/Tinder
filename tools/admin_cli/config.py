"""系统配置命令。"""

from __future__ import annotations

import argparse

from admin_cli.base import print_json
from admin_cli.context import AdminContext


def run_interactive(ctx: AdminContext) -> None:
    """交互式展示配置：先确认超级密码，再拉取并打印。"""
    super_pwd = ctx.super_password()
    show(ctx, argparse.Namespace(super_password=super_pwd))


def show(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    super_pwd = (
        getattr(sub, "super_password", None)
        if sub is not None
        else None
    ) or ctx.super_password()
    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().post(
            "/api/v1/admin/config",
            json_data={"super_password": super_pwd},
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


def dispatch(ctx: AdminContext, sub: argparse.Namespace) -> None:
    show(ctx, sub)
