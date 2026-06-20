"""Test wall_looking_for (lost & found) generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _choice, _input_int,
    ensure_users_exist,
)

TYPES = ["lost_item", "found_item", "looking_for_person"]
CLUES_LIST = [
    "黑色钱包，内有身份证和学生证",
    "白色AirPods，带蓝色硅胶套",
    "蓝色水杯，贴有姓名标签",
    "黑色笔记本，封面有涂鸦",
    "红色雨伞，折叠款",
]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  寻物/寻人生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过寻物寻人生成")
            return
        count = _input_int("要生成多少条记录？[默认: 20]: ", 20)
    else:
        if not USER_UUIDS:
            return
        count = 20

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "current_status": _choice("active", "active", "resolved", "expired"),
            "real_status": _choice("pending", "confirmed", "rejected"),
            "seeker": random.choice(USER_UUIDS),
            "looking_for_type": random.choice(TYPES),
            "helper": random.choice(USER_UUIDS + [None] * 3) if random.choice([True, False]) else None,
            "clues": random.choice(CLUES_LIST),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO wall_looking_for
                    (uuid, current_status, real_status, seeker,
                     looking_for_type, helper, clues)
                VALUES
                    (:uuid, :current_status, :real_status, :seeker,
                     :looking_for_type, :helper, :clues)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条寻物/寻人记录")
    except Exception as e:
        print(f"❌ 插入寻物/寻人失败: {e}")
