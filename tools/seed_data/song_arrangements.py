"""Test song_arrangements generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _input_int,
    ensure_users_exist,
)


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  歌单安排生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过歌单安排生成")
            return
        count = _input_int("要生成多少个歌单安排？[默认: 10]: ", 10)
    else:
        if not USER_UUIDS:
            return
        count = 10

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "week_number": random.randint(1, 52),
            "content": fake.sentence(nb_words=8),
            "created_by": random.choice(USER_UUIDS),
            "likes": random.randint(0, 999),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO song_arrangements
                    (uuid, week_number, content, created_by, likes)
                VALUES
                    (:uuid, :week_number, :content, :created_by, :likes)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个歌单安排")
    except Exception as e:
        print(f"❌ 插入歌单安排失败: {e}")
