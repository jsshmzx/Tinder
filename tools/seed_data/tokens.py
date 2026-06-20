"""Test API tokens generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _choice, _maybe, _input_int,
    ensure_users_exist,
)

PERMISSIONS = ["read", "write", "admin", "read:users", "write:users", "read:songs", "write:songs"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  API令牌生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过令牌生成")
            return
        count = _input_int("要生成多少个API令牌？[默认: 20]: ", 20)
    else:
        if not USER_UUIDS:
            return
        count = 20

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "belong_to": random.choice(USER_UUIDS),
            "permission": random.choice(PERMISSIONS),
            "assigner": random.choice(USER_UUIDS) if _maybe(0.6) else None,
            "current_status": _choice("active", "active", "expired", "revoked"),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO tokens
                    (uuid, belong_to, permission, assigner, current_status)
                VALUES
                    (:uuid, :belong_to, :permission, :assigner, :current_status)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个API令牌")
    except Exception as e:
        print(f"❌ 插入令牌失败: {e}")
