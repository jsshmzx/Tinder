"""注册问题管理命令。"""

from __future__ import annotations

import argparse
from typing import Any

from admin_cli.base import parse_json_or_prompt, print_json, run_async
from admin_cli.context import AdminContext
from admin_cli.menu import (
    confirm,
    pick_from_list,
    prompt,
    prompt_choice,
    prompt_int,
    render_table,
    run_menu,
)

_QUESTION_COLUMNS: list[tuple[str, str]] = [
    ("uuid", "UUID"),
    ("title", "题目标题"),
    ("question_type", "类型"),
    ("status", "状态"),
]


def run_interactive(ctx: AdminContext) -> None:
    run_menu(
        "注册问题管理",
        [
            ("1", "列出题目", lambda: list_questions(ctx, None)),
            ("2", "查看题目详情", lambda: get_question(ctx, None)),
            ("3", "创建题目", lambda: create_question(ctx, None)),
            ("4", "更新题目", lambda: update_question(ctx, None)),
            ("5", "删除题目", lambda: delete_question(ctx, None)),
        ],
    )


# ---------------------------------------------------------------------------
# 列表
# ---------------------------------------------------------------------------


def list_questions(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    params = _collect_list_params(sub)
    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().get("/api/v1/admin/questions", params)
        items = data if isinstance(data, list) else data.get("items", [])
        total = data.get("total") if isinstance(data, dict) else None
    else:
        items = run_async(
            ctx.require_db().list_questions(
                keyword=params.get("keyword"),
                question_type=params.get("type"),
                status=params.get("status"),
                limit=params.get("limit", 20),
                offset=params.get("offset", 0),
            )
        )
        total = None
    if total is not None:
        print(f"共 {total} 条")
    render_table(items, _QUESTION_COLUMNS)


def _collect_list_params(sub: argparse.Namespace | None) -> dict[str, Any]:
    if sub is None or all(
        getattr(sub, attr, None) is None
        for attr in ("keyword", "type", "status", "limit", "offset")
    ):
        print("--- 列出题目 ---")
        return {
            "keyword": prompt("关键词 (留空跳过)") or None,
            "type": prompt("题型 (留空跳过)") or None,
            "status": prompt("状态 (active/inactive, 留空跳过)") or None,
            "limit": prompt_int("每页数量", 20, minimum=1, maximum=200),
            "offset": (prompt_int("页码", 1, minimum=1) - 1) * 20,
        }
    return {
        "keyword": sub.keyword,
        "type": sub.type,
        "status": sub.status,
        "limit": sub.limit,
        "offset": sub.offset,
    }


# ---------------------------------------------------------------------------
# 详情
# ---------------------------------------------------------------------------


def get_question(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    qid = _resolve_uuid(ctx, sub, prompt_label="查看题目")
    if not qid:
        return
    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().get(f"/api/v1/admin/questions/{qid}")
    else:
        data = run_async(ctx.require_db().get_question(qid))
    print_json(data)


def _resolve_uuid(
    ctx: AdminContext,
    sub: argparse.Namespace | None,
    *,
    prompt_label: str,
) -> str | None:
    if sub is not None and getattr(sub, "uuid", None):
        return sub.uuid
    print(f"--- {prompt_label} ---")
    if confirm("从题目列表中挑选？", default=True):
        items = _list_questions_for_pick(ctx)
        picked = pick_from_list("请选择题目：", items, _QUESTION_COLUMNS)
        if picked:
            return picked.get("uuid")
    return prompt("题目 UUID") or None


def _list_questions_for_pick(ctx: AdminContext, limit: int = 50) -> list[dict[str, Any]]:
    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().get("/api/v1/admin/questions", {"limit": limit})
        return data if isinstance(data, list) else data.get("items", [])
    return run_async(ctx.require_db().list_questions(limit=limit))


# ---------------------------------------------------------------------------
# 创建
# ---------------------------------------------------------------------------


def create_question(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    if sub is not None and sub.data:
        payload = parse_json_or_prompt(sub.data, "创建题目数据 (JSON):")
    else:
        print("--- 创建题目 ---")
        payload = {
            "title": prompt("题目标题", required=True),
            "description": prompt("题目描述 (留空跳过)") or None,
            "question_type": prompt_choice(
                "题型:",
                [("single", "单选"), ("multiple", "多选"), ("text", "文本")],
                default="single",
            ),
            "status": prompt_choice(
                "状态:",
                [("active", "启用"), ("inactive", "停用")],
                default="active",
            ),
        }
        payload = {k: v for k, v in payload.items() if v not in (None, "")}
        print("即将创建的题目:")
        print_json(payload)
        if not confirm("确认创建？", default=False):
            print("已取消")
            return

    if ctx.mode == "api":
        ctx.ensure_login()
        data = ctx.require_api().post("/api/v1/admin/questions", json_data=payload)
    else:
        data = run_async(ctx.require_db().create_question(payload))
    print_json(data)


# ---------------------------------------------------------------------------
# 更新
# ---------------------------------------------------------------------------


def update_question(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    qid = _resolve_uuid(ctx, sub, prompt_label="更新题目")
    if not qid:
        return
    if sub is not None and sub.data:
        payload = parse_json_or_prompt(sub.data, "更新题目数据 (JSON):")
    else:
        print("--- 更新题目 (留空跳过对应字段) ---")
        payload = {
            "title": prompt("新标题 (留空跳过)") or None,
            "description": prompt("新描述 (留空跳过)") or None,
            "question_type": prompt_choice(
                "新题型 (回车跳过):",
                [("", "跳过"), ("single", "单选"), ("multiple", "多选"), ("text", "文本")],
                default="",
            ),
            "status": prompt_choice(
                "新状态 (回车跳过):",
                [("", "跳过"), ("active", "启用"), ("inactive", "停用")],
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
        data = ctx.require_api().patch(
            f"/api/v1/admin/questions/{qid}", json_data=payload
        )
    else:
        data = run_async(ctx.require_db().update_question(qid, payload))
    print_json(data)


# ---------------------------------------------------------------------------
# 删除
# ---------------------------------------------------------------------------


def delete_question(ctx: AdminContext, sub: argparse.Namespace | None) -> None:
    qid = _resolve_uuid(ctx, sub, prompt_label="删除题目")
    if not qid:
        return
    if not confirm("确认删除该题目？", default=False):
        print("已取消")
        return
    if ctx.mode == "api":
        ctx.ensure_login()
        ctx.require_api().delete(f"/api/v1/admin/questions/{qid}")
        print("删除成功")
    else:
        ok = run_async(ctx.require_db().delete_question(qid))
        print("删除成功" if ok else "删除失败或题目不存在")


# ---------------------------------------------------------------------------
# argparse 派发
# ---------------------------------------------------------------------------


def dispatch(ctx: AdminContext, sub: argparse.Namespace) -> None:
    handler = {
        "list": list_questions,
        "get": get_question,
        "create": create_question,
        "update": update_question,
        "delete": delete_question,
    }.get(sub.action)
    if handler is None:
        raise ValueError(f"未知 questions 子命令: {sub.action}")
    handler(ctx, sub)
