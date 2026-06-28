"""用户管理命令。"""

from __future__ import annotations

import argparse
from typing import Any

from tools.admin_cli.base import (
    generate_random_password,
    parse_json_or_prompt,
    print_json,
    run_async,
)
from tools.admin_cli.context import AdminContext
from tools.admin_cli.menu import (
    confirm,
    prompt,
    prompt_choice,
    prompt_int,
    render_table,
    run_menu,
)

# 用户表渲染列
_USER_COLUMNS: list[tuple[str, str]] = [
    ("uuid", "UUID"),
    ("username", "用户名"),
    ("role", "角色"),
    ("current_status", "状态"),
]

# 状态操作映射
_STATUS_ACTIONS: list[tuple[str, str, str]] = [
    ("1", "ban", "封禁 (ban)"),
    ("2", "unban", "解封 (unban)"),
    ("3", "disable", "禁用 (disable)"),
    ("4", "enable", "启用 (enable)"),
]


# ---------------------------------------------------------------------------
# 交互式入口
# ---------------------------------------------------------------------------


def run_interactive(ctx: AdminContext) -> None:
    """用户管理交互式菜单。"""
    run_menu(
        "用户管理",
        [
            ("1", "列出用户", lambda: list_users(ctx, None)),
            ("2", "查看用户详情", lambda: get_user(ctx, None)),
            ("3", "创建用户", lambda: create_user(ctx, None)),
            ("4", "更新用户", lambda: update_user(ctx, None)),
            ("5", "删除用户", lambda: delete_user(ctx, None)),
            ("6", "重置密码", lambda: reset_password(ctx, None)),
            ("7", "封禁/解封/禁用/启用", lambda: change_status(ctx)),
        ],
    )


# ---------------------------------------------------------------------------
# 列表
# ---------------------------------------------------------------------------


def list_users(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    params = _collect_list_params(sub)
    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().get("/api/v1/admin/users", params)
        items = data if isinstance(data, list) else data.get("items", [])
        total = data.get("total") if isinstance(data, dict) else None
    else:
        items = run_async(
            ctx.require_db().list_users(
                keyword=params.get("keyword"),
                status=params.get("status"),
                role=params.get("role"),
                limit=params.get("limit", 20),
                offset=params.get("offset", 0),
            )
        )
        total = None
    if total is not None:
        print(f"共 {total} 条")
    render_table(items, _USER_COLUMNS)


def _collect_list_params(sub: argparse.Namespace | None) -> dict[str, Any]:
    """解析列表过滤参数；sub 为空或字段全空时进入交互。"""
    if sub is None or all(
        getattr(sub, attr, None) is None
        for attr in ("keyword", "status", "role", "limit", "offset")
    ):
        print("--- 列出用户 ---")
        return {
            "keyword": prompt("关键词 (留空跳过)") or None,
            "status": prompt("状态 (normal/banned/disabled, 留空跳过)") or None,
            "role": prompt("角色 (user/admin/superadmin, 留空跳过)") or None,
            "limit": prompt_int("每页数量", 20, minimum=1, maximum=200),
            "offset": (prompt_int("页码", 1, minimum=1) - 1) * 20,
        }
    return {
        "keyword": sub.keyword,
        "status": sub.status,
        "role": sub.role,
        "limit": sub.limit,
        "offset": sub.offset,
    }


# ---------------------------------------------------------------------------
# 详情
# ---------------------------------------------------------------------------


def get_user(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    user_uuid = _resolve_uuid(ctx, sub, prompt_label="查看用户")
    if not user_uuid:
        return
    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().get(f"/api/v1/admin/users/{user_uuid}")
    else:
        data = run_async(ctx.require_db().get_user(user_uuid))
    print_json(data)


def _resolve_uuid(
    ctx: AdminContext,
    sub: argparse.Namespace | None,
    *,
    prompt_label: str,
) -> str | None:
    """解析 UUID：先取命令行参数，否则弹出列表供选择，最后兜底为手工输入。"""
    if sub is not None and getattr(sub, "uuid", None):
        return sub.uuid
    print(f"--- {prompt_label} ---")
    if confirm("从用户列表中挑选？", default=True):
        items = _list_users_for_pick(ctx)
        picked = pick_from_list("请选择用户：", items, _USER_COLUMNS)
        if picked:
            return picked.get("uuid")
    return prompt("用户 UUID") or None


def _list_users_for_pick(ctx: AdminContext, limit: int = 50) -> list[dict[str, Any]]:
    """拉取一批用户供交互式挑选使用。"""
    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().get("/api/v1/admin/users", {"limit": limit})
        return data if isinstance(data, list) else data.get("items", [])
    return run_async(ctx.require_db().list_users(limit=limit))


# ---------------------------------------------------------------------------
# 创建
# ---------------------------------------------------------------------------


def create_user(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    if sub is not None and sub.data:
        payload = parse_json_or_prompt(sub.data, "创建用户数据 (JSON):")
    else:
        print("--- 创建用户 ---")
        username = prompt("用户名", required=True)
        password = prompt("密码 (留空自动生成)", "")
        if not password:
            password = generate_random_password(12)
            print(f"  已自动生成密码: {password}")
        payload = {
            "username": username,
            "password": password,
            "email": prompt("邮箱 (留空跳过)") or None,
            "phone": prompt("手机号 (留空跳过)") or None,
            "role": prompt_choice(
                "选择角色:",
                [("user", "普通用户"), ("admin", "管理员"), ("superadmin", "超级管理员")],
                default="user",
            ),
            "current_status": prompt_choice(
                "选择状态:",
                [("normal", "正常"), ("banned", "封禁"), ("disabled", "禁用")],
                default="normal",
            ),
        }
        payload = {k: v for k, v in payload.items() if v not in (None, "")}
        print("即将创建的用户:")
        print_json(payload)
        if not confirm("确认创建？", default=False):
            print("已取消")
            return

    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().post("/api/v1/admin/users", json_data=payload)
    else:
        data = run_async(ctx.require_db().create_user(payload))
    print_json(data)


# ---------------------------------------------------------------------------
# 更新
# ---------------------------------------------------------------------------


def update_user(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    user_uuid = _resolve_uuid(ctx, sub, prompt_label="更新用户")
    if not user_uuid:
        return
    if sub is not None and sub.data:
        payload = parse_json_or_prompt(sub.data, "更新用户数据 (JSON):")
    else:
        print("--- 更新用户字段 (留空跳过对应字段) ---")
        payload = {
            "username": prompt("新用户名 (留空跳过)") or None,
            "email": prompt("新邮箱 (留空跳过)") or None,
            "phone": prompt("新手机号 (留空跳过)") or None,
            "role": prompt_choice(
                "新角色 (回车跳过):",
                [("", "跳过"), ("user", "普通用户"), ("admin", "管理员"), ("superadmin", "超级管理员")],
                default="",
            ),
            "current_status": prompt_choice(
                "新状态 (回车跳过):",
                [("", "跳过"), ("normal", "正常"), ("banned", "封禁"), ("disabled", "禁用")],
                default="",
            ),
        }
        payload = {k: v for k, v in payload.items() if v not in (None, "")}
        if not payload:
            print("无更新内容，已取消。")
            return
        print("即将更新为:")
        print_json(payload)
        if not confirm("确认更新？", default=False):
            print("已取消")
            return

    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().patch(f"/api/v1/admin/users/{user_uuid}", json_data=payload)
    else:
        data = run_async(ctx.require_db().update_user(user_uuid, payload))
    print_json(data)


# ---------------------------------------------------------------------------
# 删除
# ---------------------------------------------------------------------------


def delete_user(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    user_uuid = _resolve_uuid(ctx, sub, prompt_label="删除用户")
    if not user_uuid:
        return
    super_pwd = ctx.super_password(getattr(sub, "super_password", None) if sub else None)
    if not confirm("确认删除该用户？此操作不可恢复！", default=False):
        print("已取消")
        return
    if ctx.mode == "api":
        ctx.ensure_login()
        ctx.require_api().delete(
            f"/api/v1/admin/users/{user_uuid}",
            json_data={"super_password": super_pwd},
        )
        print("删除成功")
    else:
        ok = run_async(ctx.require_db().delete_user(user_uuid))
        print("删除成功" if ok else "删除失败或用户不存在")


# ---------------------------------------------------------------------------
# 重置密码
# ---------------------------------------------------------------------------


def reset_password(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    user_uuid = _resolve_uuid(ctx, sub, prompt_label="重置密码")
    if not user_uuid:
        return
    super_pwd = ctx.super_password(getattr(sub, "super_password", None) if sub else None)
    new_password = getattr(sub, "new_password", None) if sub else None
    if not new_password:
        new_password = prompt("新密码 (留空自动生成)", "")
        if not new_password:
            new_password = generate_random_password(12)
    from admin_cli.base import double_sha256_hex

    if ctx.mode == "api":
        ctx.ensure_login()
        ctx.require_api().post(
            f"/api/v1/admin/users/{user_uuid}/reset-password",
            json_data={
                "super_password": super_pwd,
                "new_password": double_sha256_hex(new_password),
            },
        )
    else:
        run_async(ctx.require_db().reset_password(user_uuid, new_password))
    print("密码重置成功")
    print(f"新密码: {new_password}")
    print("请将该密码告知用户，登录时系统会自动做双重哈希。")


# ---------------------------------------------------------------------------
# 状态变更
# ---------------------------------------------------------------------------


def change_status(ctx: AdminContext) -> None:
    print("--- 变更用户状态 ---")
    user_uuid = _resolve_uuid(ctx, None, prompt_label="变更状态")
    if not user_uuid:
        return
    # 把 (key, action, label) 转换为 (key, label) 以便 prompt_choice 展示
    options = [(key, label) for key, _action, label in _STATUS_ACTIONS]
    selected = prompt_choice("选择操作：", options)
    action = next(a for k, a, _ in _STATUS_ACTIONS if k == selected)
    if ctx.mode == "api":
        ctx.ensure_login()
        ctx.require_api().post(f"/api/v1/admin/users/{user_uuid}/{action}")
    else:
        run_async(ctx.require_db().set_user_status(user_uuid, action))
    print(f"操作 {action} 成功")


# ---------------------------------------------------------------------------
# argparse 派发辅助
# ---------------------------------------------------------------------------


def dispatch(ctx: AdminContext, sub: argparse.Namespace) -> None:
    """根据 sub.action 派发到具体方法。"""
    action = sub.action
    if action in ("ban", "unban", "disable", "enable"):
        # 兼容 argparse 子命令
        change_status_with_uuid(ctx, action, getattr(sub, "uuid", None))
        return
    handler = {
        "list": list_users,
        "get": get_user,
        "create": create_user,
        "update": update_user,
        "delete": delete_user,
        "reset-password": reset_password,
    }.get(action)
    if handler is None:
        raise ValueError(f"未知 users 子命令: {action}")
    handler(ctx, sub)


def change_status_with_uuid(
    ctx: AdminContext, action: str, user_uuid: str | None
) -> None:
    """处理 CLI 子命令 ``users <ban|unban|disable|enable> <uuid>``。

    命令行已提供 UUID 时直接使用；否则进入交互式选择。
    """
    if user_uuid:
        target = user_uuid
    else:
        target = _resolve_uuid(ctx, None, prompt_label=f"{action} 用户")
    if not target:
        return
    if ctx.mode == "api":
        ctx.ensure_login()
        ctx.require_api().post(f"/api/v1/admin/users/{target}/{action}")
    else:
        run_async(ctx.require_db().set_user_status(target, action))
    print(f"操作 {action} 成功")
