#!/usr/bin/env python3
"""
交互式测试数据生成器 — 引导式问答，支持多表选择。

用法:
  python tools/seed_data.py                        # 交互式菜单，多选表
  python tools/seed_data.py --quick                # 全部默认值，无交互
  python tools/seed_data.py --only users,songs     # 仅指定表，无交互
"""

import argparse
import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from seed_data.base import get_session, USER_UUIDS, load_existing_users

# ── 表注册表 ──────────────────────────────────────────────────────
# (key, display_name, module_name, needs_users_flag)
TABLES = [
    ("1",  "用户",         "users",               True),
    ("2",  "歌曲",         "songs",               True),
    ("3",  "说说",         "wall_sayings",        True),
    ("4",  "评论",         "comments",            True),
    ("5",  "标签",         "tags",                True),
    ("6",  "任务",         "tasks",               True),
    ("7",  "商铺/餐馆",    "stores_and_restaurants", False),
    ("8",  "歌单安排",     "song_arrangements",   True),
    ("9",  "注册问题",     "register_questions",  True),
    ("10", "API令牌",      "tokens",              True),
    ("11", "投票",         "vote",                True),
    ("12", "收藏",         "favourites",          True),
    ("13", "寻物/寻人",    "wall_looking_for",    True),
    ("14", "关联关系",     "relations",           False),
]

ALL_KEY = "15"


def print_menu():
    """打印编号菜单。"""
    print("\n" + "=" * 60)
    print("  Tinder 测试数据生成器")
    print("=" * 60)
    print("要生成哪些表的数据？（可多选，逗号分隔，如 1,3,5）")
    for key, name, *_ in TABLES:
        print(f"  {key:>2}) {name}")
    print(f"  {ALL_KEY}) 全部")
    print(f"   0) 退出")


def parse_selection(raw: str) -> list[str]:
    """解析用户输入的逗号分隔编号，返回模块名列表。"""
    raw = raw.strip().replace("，", ",")
    if raw == ALL_KEY:
        return [entry[2] for entry in TABLES]

    selected = []
    for part in raw.split(","):
        part = part.strip()
        for key, _name, module, _ in TABLES:
            if part == key:
                selected.append(module)
                break
    return selected


async def run_generator(module_name: str, session, interactive: bool) -> None:
    """动态导入并运行一个生成器模块。"""
    if module_name == "users" and USER_UUIDS and interactive:
        skip = input(f"\n当前已有 {len(USER_UUIDS)} 个用户 UUID 可用。跳过用户生成？(y/n) [y]: ").strip().lower()
        if skip in ("", "y", "yes"):
            return

    mod = __import__(f"seed_data.{module_name}", fromlist=["generate"])
    await mod.generate(session, interactive=interactive)


async def main():
    parser = argparse.ArgumentParser(description="Tinder 交互式测试数据生成器")
    parser.add_argument("--quick", action="store_true", help="跳过交互，全部使用默认值生成所有表")
    parser.add_argument("--only", type=str, help="仅生成指定表（逗号分隔），如: users,songs")
    args = parser.parse_args()

    # ── --quick 模式 ──────────────────────────────────────────────
    if args.quick:
        print("=" * 60)
        print("  Quick 模式 — 全部默认值")
        print("=" * 60)
        async with get_session() as session:
            await load_existing_users(session)
            for _, _, module_name, _ in TABLES:
                await run_generator(module_name, session, interactive=False)
        print(f"\n{'='*60}")
        print("  全部数据生成完毕！（默认密码: password123）")
        print(f"{'='*60}")
        return

    # ── --only 模式 ──────────────────────────────────────────────
    if args.only:
        names = [n.strip() for n in args.only.split(",")]
        print(f"选择生成: {', '.join(names)}")
        async with get_session() as session:
            await load_existing_users(session)
            for name in names:
                await run_generator(name, session, interactive=False)
        print(f"\n✅ 指定表数据生成完毕！（默认密码: password123）")
        return

    # ── 交互式模式 ────────────────────────────────────────────────
    async with get_session() as session:
        await load_existing_users(session)

        while True:
            print_menu()
            raw = input("请输入编号: ").strip()
            if raw == "0":
                print("已退出。")
                return

            selected = parse_selection(raw)
            if not selected:
                print("⚠️  请选择有效的编号")
                continue

            needs_users = any(module == "users" for module in selected)
            if not needs_users and not USER_UUIDS:
                print("\n⚠️  注意：部分表依赖用户数据，建议先生成用户。")
                add_users = input("是否先添加用户？(y/n) [y]: ").strip().lower()
                if add_users in ("", "y", "yes"):
                    await run_generator("users", session, interactive=True)

            for module_name in selected:
                await run_generator(module_name, session, interactive=True)

            again = input("\n还要继续生成其他表吗？(y/n) [n]: ").strip().lower()
            if again not in ("y", "yes", "是"):
                break

        print(f"\n{'='*60}")
        print("  全部数据生成完毕！（默认密码: password123）")
        print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
