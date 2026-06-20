"""Test songs generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _maybe, _input_int,
    ensure_users_exist,
)

SONG_NAMES = [
    "晴天", "七里香", "夜曲", "告白气球", "稻香", "青花瓷", "兰亭序",
    "一路向北", "演员", "丑八怪", "孤勇者", "光年之外", "起风了",
    "红色高跟鞋", "小幸运", "追光者", "大鱼", "凉凉", "消愁", "成都",
    "平凡之路", "南山南", "春风十里", "理想三旬", "往后余生",
]
SINGERS = [
    "周杰伦", "薛之谦", "陈奕迅", "邓紫棋", "林俊杰", "王菲",
    "毛不易", "赵雷", "朴树", "李荣浩", "张靓颖", "周深",
    "张韶涵", "田馥甄",
]
PLATFORMS = ["网易云音乐", "QQ音乐", "酷狗音乐", "Apple Music", "Spotify"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  歌曲生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            pass
        count = _input_int("要生成多少首歌曲？[默认: 50]: ", 50)
    else:
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "name": random.choice(SONG_NAMES),
            "singer": random.choice(SINGERS),
            "platform": random.choice(PLATFORMS),
            "status": _choice("active", "active", "inactive", "archived"),
            "vote": random.randint(0, 999),
            "recommend_by": random.choice(USER_UUIDS) if USER_UUIDS and _maybe(0.6) else None,
            "recommend_words": fake.sentence(nb_words=6) if _maybe(0.4) else None,
            "reason": fake.sentence(nb_words=10) if _maybe(0.5) else None,
        })

    try:
        await session.execute(
            text("""
                INSERT INTO songs (uuid, name, singer, platform, status, vote,
                                   recommend_by, recommend_words, reason)
                VALUES (:uuid, :name, :singer, :platform, :status, :vote,
                        :recommend_by, :recommend_words, :reason)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 首歌曲")
    except Exception as e:
        print(f"❌ 插入歌曲失败: {e}")
