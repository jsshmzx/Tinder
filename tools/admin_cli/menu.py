"""交互式 Q&A 辅助函数：菜单、确认、列表选择、列表分页等。"""

from __future__ import annotations

import getpass
import sys
from typing import Any, Callable, Iterable, Sequence


# ---------------------------------------------------------------------------
# 基础输入辅助
# ---------------------------------------------------------------------------


def prompt(message: str, default: str | None = None, *, required: bool = False) -> str:
    """读取一行输入，支持默认值。"""
    suffix = f" [默认: {default}]" if default is not None else ""
    raw = input(f"{message}{suffix}: ").strip()
    if not raw and default is not None:
        return default
    if not raw and required:
        print("该项为必填，请重新输入。", file=sys.stderr)
        return prompt(message, default, required=True)
    return raw


def prompt_int(
    message: str,
    default: int | None = None,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """读取整数，支持最小/最大值校验。"""
    while True:
        raw = prompt(message, str(default) if default is not None else None)
        try:
            value = int(raw)
        except ValueError:
            print("请输入合法的整数。", file=sys.stderr)
            continue
        if minimum is not None and value < minimum:
            print(f"不能小于 {minimum}。", file=sys.stderr)
            continue
        if maximum is not None and value > maximum:
            print(f"不能大于 {maximum}。", file=sys.stderr)
            continue
        return value


def prompt_secret(message: str) -> str:
    """读取不回显的密码。"""
    return getpass.getpass(f"{message}: ")


def confirm(message: str, default: bool = False) -> bool:
    """询问 y/n。"""
    suffix = "[Y/n]" if default else "[y/N]"
    raw = input(f"{message} {suffix}: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def prompt_choice(message: str, options: Sequence[tuple[str, str]], default: str | None = None) -> str:
    """让用户从编号选项中选一个，返回选项的 key。"""
    print(message)
    for key, label in options:
        marker = " *" if key == default else ""
        print(f"  {key}) {label}{marker}")
    keys = [k for k, _ in options]
    while True:
        raw = input(f"请输入编号 [默认: {default or keys[0]}]: ").strip() or (default or keys[0])
        if raw in keys:
            return raw
        print(f"无效编号，可选: {', '.join(keys)}", file=sys.stderr)


# ---------------------------------------------------------------------------
# 列表/分页
# ---------------------------------------------------------------------------


def render_table(
    rows: Iterable[dict[str, Any]],
    columns: Sequence[tuple[str, str]],
    *,
    max_rows: int | None = None,
) -> list[dict[str, Any]]:
    """以表格形式打印若干行；返回实际打印的列表（便于选择）。"""
    materialized = list(rows)
    if max_rows is not None:
        materialized = materialized[:max_rows]
    if not materialized:
        print("  (无数据)")
        return []

    widths: list[int] = []
    for key, header in columns:
        values = [str(row.get(key, "")) for row in materialized]
        widths.append(max(len(header), *(len(v) for v in values)))

    header_line = "  " + "  ".join(
        header.ljust(w) for (_, header), w in zip(columns, widths)
    )
    sep_line = "  " + "  ".join("-" * w for w in widths)
    print(header_line)
    print(sep_line)
    for idx, row in enumerate(materialized, start=1):
        cells = []
        for (key, _), width in zip(columns, widths):
            value = str(row.get(key, ""))
            if key == "index":
                value = str(idx)
            cells.append(value.ljust(width))
        print("  " + "  ".join(cells))
    return materialized


def pick_from_list(
    message: str,
    rows: Sequence[dict[str, Any]],
    columns: Sequence[tuple[str, str]],
) -> dict[str, Any] | None:
    """让用户从列表中挑选一行；返回所选项（无数据/取消时返回 None）。"""
    if not rows:
        print("(无可选项)")
        return None
    print(message)
    rendered = render_table(rows, [("index", "#"), *columns])
    while True:
        raw = input("请输入编号（或 0 取消）: ").strip()
        if raw in ("0", "q", "quit", ""):
            return None
        try:
            idx = int(raw)
        except ValueError:
            print("请输入合法数字。", file=sys.stderr)
            continue
        if 1 <= idx <= len(rendered):
            return rendered[idx - 1]
        print(f"编号超出范围 (1-{len(rendered)})", file=sys.stderr)


# ---------------------------------------------------------------------------
# 菜单循环
# ---------------------------------------------------------------------------


def run_menu(
    title: str,
    options: Sequence[tuple[str, str, Callable[[], None]]],
    *,
    allow_back: bool = True,
) -> None:
    """显示一个编号菜单并循环执行用户选择。"""
    while True:
        print()
        print("=" * 60)
        print(f"  {title}")
        print("=" * 60)
        for key, label, _ in options:
            print(f"  {key}) {label}")
        if allow_back:
            print("  0) 返回上级")
        raw = input("请输入编号: ").strip()
        if allow_back and raw in ("0", "q", "quit", "back", ""):
            return
        for key, _label, handler in options:
            if raw == key:
                try:
                    handler()
                except (KeyboardInterrupt, EOFError):
                    print()
                except SystemExit:
                    raise
                except Exception as exc:  # 交互中吞掉非致命错误
                    print(f"错误: {exc}", file=sys.stderr)
                break
        else:
            print(f"无效编号: {raw}", file=sys.stderr)
