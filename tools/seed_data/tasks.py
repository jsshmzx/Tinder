"""Test tasks generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _input_int,
    ensure_users_exist,
)

PARTS = ["前端", "后端", "数据库", "UI设计", "测试", "文案", "运营", "项目管理", "数据分析"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  任务生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过任务生成")
            return
        count = _input_int("要生成多少个任务？[默认: 30]: ", 30)
    else:
        if not USER_UUIDS:
            return
        count = 30

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "content": fake.sentence(nb_words=12),
            "parts": random.choice(PARTS),
            "assigner": random.choice(USER_UUIDS),
            "status": _choice("todo", "in_progress", "done", "cancelled", "archived"),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO tasks (uuid, content, parts, assigner, status)
                VALUES (:uuid, :content, :parts, :assigner, :status)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个任务")
    except Exception as e:
        print(f"❌ 插入任务失败: {e}")
