"""Test tags generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _choice, _maybe, _input_int,
    ensure_users_exist,
)

TAG_NAMES = [
    "热门", "推荐", "最新", "校园", "生活", "学习", "美食",
    "旅行", "音乐", "电影", "读书", "运动", "游戏", "科技",
    "动漫", "摄影", "情感", "搞笑", "励志", "冷知识",
    "校园活动", "社团", "考研", "就业", "留学",
]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  标签生成")
    print(f"{'='*60}")

    if interactive:
        await ensure_users_exist(session, interactive)
        count = _input_int("要生成多少个标签？[默认: 20]: ", 20)
    else:
        count = 20

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "tag_name": random.choice(TAG_NAMES),
            "created_by": random.choice(USER_UUIDS) if USER_UUIDS and _maybe(0.6) else None,
            "current_status": _choice("active", "active", "inactive"),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO tags (uuid, tag_name, created_by, current_status)
                VALUES (:uuid, :tag_name, :created_by, :current_status)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个标签")
    except Exception as e:
        print(f"❌ 插入标签失败: {e}")
