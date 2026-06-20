"""Test stores_and_restaurants generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import _choice, _input_int

PREFIXES = ["老王", "小李", "阿明", "大壮", "小美", "阿强", "刘叔", "陈姐", "张哥", "胖哥"]
TYPES = ["烧烤", "奶茶", "麻辣烫", "炸鸡", "火锅", "面馆", "甜品", "咖啡", "煎饼", "寿司"]
LOCATIONS = ["食堂三楼", "商业街A区", "北门对面", "南门右侧", "东区宿舍楼下", "教学楼B栋旁"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  商铺/餐馆生成")
    print(f"{'='*60}")

    if interactive:
        count = _input_int("要生成多少间商铺？[默认: 20]: ", 20)
    else:
        count = 20

    values = []
    for _ in range(count):
        name = f"{random.choice(PREFIXES)}{random.choice(TYPES)}"
        values.append({
            "uuid": str(uuid.uuid4()),
            "name": name,
            "location": random.choice(LOCATIONS),
            "likes": random.randint(0, 999),
            "ratings": round(random.uniform(1.0, 5.0), 2),
            "status": _choice("open", "open", "open", "closed", "renovating"),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO stores_and_restaurants
                    (uuid, name, location, likes, ratings, status)
                VALUES
                    (:uuid, :name, :location, :likes, :ratings, :status)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 间商铺")
    except Exception as e:
        print(f"❌ 插入商铺失败: {e}")
