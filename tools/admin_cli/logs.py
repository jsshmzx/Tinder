"""日志查询命令。"""

from __future__ import annotations

import argparse
from typing import Any

from admin_cli.base import run_async
from admin_cli.context import AdminContext
from admin_cli.db_client import build_log_db_kwargs, build_log_params
from admin_cli.menu import (
    confirm,
    prompt,
    prompt_int,
    render_table,
    run_menu,
)

_LOG_COLUMNS: list[tuple[str, str]] = [
    ("id", "ID"),
    ("trace_id", "Trace ID"),
    ("event_type", "事件类型"),
    ("log_type", "日志类型"),
    ("severity", "级别"),
    ("status", "状态"),
    ("client_ip", "客户端 IP"),
    ("created_at", "时间"),
]


def run_interactive(ctx: AdminContext) -> None:
    run_menu(
        "日志查询",
        [
            ("1", "查询系统日志 (仅 superadmin)", lambda: query_system(ctx, None)),
            ("2", "查询个人日志", lambda: query_personal(ctx, None)),
        ],
    )


# ---------------------------------------------------------------------------
# 公共查询逻辑
# ---------------------------------------------------------------------------


def _collect_log_params(
    sub: argparse.Namespace | None, *, kind: str
) -> dict[str, Any]:
    """交互式收集日志查询参数。"""
    if sub is not None and any(
        getattr(sub, attr, None) is not None
        for attr in (
            "event_type",
            "log_type",
            "status",
            "severity",
            "trace_id",
            "client_ip",
            "keyword",
            "start_time",
            "end_time",
            "limit",
            "offset",
        )
    ):
        return build_log_params(sub)
    print(f"--- 查询 {kind} 日志 (留空跳过对应字段) ---")
    params: dict[str, Any] = {
        "event_type": prompt("事件类型") or None,
        "log_type": prompt("日志类型") or None,
        "status": prompt("状态") or None,
        "severity": prompt("严重级别 (info/warn/error)") or None,
        "trace_id": prompt("Trace ID") or None,
        "client_ip": prompt("客户端 IP") or None,
        "keyword": prompt("内容关键词") or None,
        "start_time": prompt("开始时间 (ISO, 如 2026-01-01T00:00:00)") or None,
        "end_time": prompt("结束时间 (ISO)") or None,
    }
    if not confirm("使用分页？", default=True):
        params["limit"] = prompt_int("返回数量", 20, minimum=1, maximum=500)
        params["offset"] = 0
    else:
        params["limit"] = prompt_int("每页数量", 20, minimum=1, maximum=500)
        params["offset"] = (prompt_int("页码", 1, minimum=1) - 1) * params["limit"]
    return {k: v for k, v in params.items() if v not in (None, "")}


def _print_log_result(data: Any) -> None:
    if isinstance(data, dict) and "items" in data:
        print(f"共 {data.get('total', 0)} 条")
        render_table(data.get("items", []), _LOG_COLUMNS)
    elif isinstance(data, list):
        render_table(data, _LOG_COLUMNS)
    else:
        from tools.admin_cli.base import print_json

        print_json(data)


# ---------------------------------------------------------------------------
# 系统日志
# ---------------------------------------------------------------------------


def query_system(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    params = _collect_log_params(sub, kind="系统")
    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().get("/api/v1/logs/system", params)
    else:
        items, total = run_async(
            ctx.require_db().search_system_logs(**build_log_db_kwargs(sub) if sub else params)
        )
        data = {"total": total, "items": items}
    _print_log_result(data)


# ---------------------------------------------------------------------------
# 个人日志
# ---------------------------------------------------------------------------


def query_personal(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    params = _collect_log_params(sub, kind="个人")
    user_uuid = getattr(sub, "user_uuid", None) if sub else None
    if not user_uuid and confirm("指定某个用户 UUID？(仅 superadmin 可见他人日志)", default=False):
        user_uuid = prompt("用户 UUID", required=True)
    if ctx.mode == "api":
        ctx.ensure_login()
        path = "/api/v1/logs/personal"
        if user_uuid:
            path = f"/api/v1/logs/personal/{user_uuid}"
            params.pop("user_uuid", None)
        data = ctx.require_api().get(path, params)
    else:
        kwargs = build_log_db_kwargs(params)
        if user_uuid:
            kwargs["user_uuids"] = [user_uuid]
        items, total = run_async(ctx.require_db().search_personal_logs(**kwargs))
        data = {"total": total, "items": items}
    _print_log_result(data)


# ---------------------------------------------------------------------------
# argparse 派发
# ---------------------------------------------------------------------------


def dispatch(ctx: AdminContext, sub: argparse.Namespace) -> None:
    if sub.action == "system":
        query_system(ctx, sub)
    elif sub.action == "personal":
        query_personal(ctx, sub)
    else:
        raise ValueError(f"未知 logs 子命令: {sub.action}")
