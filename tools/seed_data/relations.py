"""Test relations generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import _input_int

TYPES = ["tag_song", "tag_saying", "tag_user", "user_song"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  关联关系生成")
    print(f"{'='*60}")

    if interactive:
        count = _input_int("要生成多少条关联关系？[默认: 50]: ", 50)
    else:
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "tags_uuid": str(uuid.uuid4()),
            "related_uuid": str(uuid.uuid4()),
            "relation_type": random.choice(TYPES),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO relations (tags_uuid, related_uuid, relation_type)
                VALUES (:tags_uuid, :related_uuid, :relation_type)
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条关联关系")
    except Exception as e:
        print(f"❌ 插入关联关系失败: {e}")
