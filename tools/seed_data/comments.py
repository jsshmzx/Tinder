"""Test comments generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _maybe, _input_int,
    ensure_users_exist,
)

TEMPLATES = [
    "说得好！", "赞一个", "同意楼上", "厉害厉害",
    "学到了，谢谢分享", "这个观点我不同意", "哈哈哈笑死",
    "路过看看", "收藏了", "顶一下", "好文！",
    "加油！", "辛苦了", "写的真棒", "期待更多内容",
]
PLACES = ["wall_sayings", "songs", "comments"]
LOCATIONS = ["北京", "上海", "广州", "深圳", "杭州", "成都"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  评论生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过评论生成")
            return
        count = _input_int("要生成多少条评论？[默认: 50]: ", 50)
    else:
        if not USER_UUIDS:
            return
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "status": _choice("active", "active", "hidden", "deleted"),
            "comment_place": random.choice(PLACES),
            "author": random.choice(USER_UUIDS),
            "content": random.choice(TEMPLATES),
            "ip_address": fake.ipv4(),
            "user_agent": _choice(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
                "Mozilla/5.0 (Linux; Android 13)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            ),
            "location": _choice(random.choice(LOCATIONS), None),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO comments
                    (uuid, status, comment_place, author, content,
                     ip_address, user_agent, location)
                VALUES
                    (:uuid, :status, :comment_place, :author, :content,
                     :ip_address, :user_agent, :location)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条评论")
    except Exception as e:
        print(f"❌ 插入评论失败: {e}")
