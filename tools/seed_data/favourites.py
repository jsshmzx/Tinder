"""Test favourites generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _input_int,
    ensure_users_exist,
)

TYPES = ["song", "saying", "store", "comment"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  收藏记录生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过收藏生成")
            return
        count = _input_int("要生成多少条收藏记录？[默认: 50]: ", 50)
    else:
        if not USER_UUIDS:
            return
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "user_uuid": random.choice(USER_UUIDS),
            "types": random.choice(TYPES),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO favourites (uuid, user_uuid, types)
                VALUES (:uuid, :user_uuid, :types)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条收藏记录")
    except Exception as e:
        print(f"❌ 插入收藏失败: {e}")
