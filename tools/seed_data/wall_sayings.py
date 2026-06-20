"""Test wall_sayings generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _maybe, _input_int,
    ensure_users_exist,
)

TEMPLATES = [
    "今天天气真好，适合出去玩！",
    "新的一天，加油！",
    "分享一首好听的歌: {song}",
    "今天考试了，感觉还不错",
    "有没有人一起去吃饭？",
    "深夜emo时间...",
    "开心！今天遇到了好事",
    "推荐一部好看的电影",
    "大家周末有什么安排？",
    "早安，打工人！",
    "深夜放毒，刚吃了烧烤",
    "今天跑了个五公里，舒服",
    "这个学期的课好难啊",
    "想家了...",
    "终于放假了！开熏！",
]
SONGS = ["晴天", "七里香", "孤勇者", "起风了", "成都"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  说说生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过说说生成")
            return
        count = _input_int("要生成多少条说说？[默认: 50]: ", 50)
    else:
        if not USER_UUIDS:
            return
        count = 50

    values = []
    for _ in range(count):
        content = random.choice(TEMPLATES).format(song=random.choice(SONGS))
        values.append({
            "uuid": str(uuid.uuid4()),
            "author_uuid": random.choice(USER_UUIDS),
            "content": content,
            "saying_status": _choice("published", "published", "published", "draft", "deleted"),
            "saying_type": _choice("moment", "share", "qa", "confession"),
            "likes": random.randint(0, 999),
            "share_count": random.randint(0, 99),
            "views": random.randint(0, 9999),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO wall_sayings
                    (uuid, author_uuid, content, saying_status, saying_type,
                     likes, share_count, views)
                VALUES
                    (:uuid, :author_uuid, :content, :saying_status, :saying_type,
                     :likes, :share_count, :views)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条说说")
    except Exception as e:
        print(f"❌ 插入说说失败: {e}")
