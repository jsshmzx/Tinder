"""Test vote records generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _input_int,
    ensure_users_exist,
)

VOTE_TYPES = ["song", "comment", "saying", "store"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  投票记录生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过投票生成")
            return
        count = _input_int("要生成多少条投票记录？[默认: 50]: ", 50)
    else:
        if not USER_UUIDS:
            return
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "vote_type": random.choice(VOTE_TYPES),
            "committed_by": random.choice(USER_UUIDS),
            "content": str(random.randint(1, 1000)),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO vote (uuid, vote_type, committed_by, content)
                VALUES (:uuid, :vote_type, :committed_by, :content)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条投票记录")
    except Exception as e:
        print(f"❌ 插入投票失败: {e}")
