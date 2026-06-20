"""Test register_questions generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _maybe, _input_int,
    ensure_users_exist,
)

QA_PAIRS = [
    ("你的小学名称是什么？", "第一小学"),
    ("你最喜欢的科目是什么？", "数学"),
    ("你的宠物名字是什么？", "旺财"),
    ("你最想去的地方是哪里？", "日本"),
    ("你最喜欢的歌手是谁？", "周杰伦"),
    ("你的生日是？", "2000-01-01"),
    ("你父亲的名字是？", "张三"),
    ("你母亲的名字是？", "李四"),
    ("你的座右铭是？", "天道酬勤"),
    ("你的幸运数字是？", "7"),
]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  注册问题生成")
    print(f"{'='*60}")

    if interactive:
        await ensure_users_exist(session, interactive)
        count = _input_int("要生成多少个注册问题？[默认: 15]: ", 15)
    else:
        count = 15

    values = []
    for i in range(count):
        if i < len(QA_PAIRS):
            q, a = QA_PAIRS[i]
        else:
            q, a = fake.sentence(nb_words=6), fake.word()
        values.append({
            "uuid": str(uuid.uuid4()),
            "question": q,
            "answer": a,
            "created_by": random.choice(USER_UUIDS) if USER_UUIDS else None,
            "question_level": _choice("low", "medium", "high"),
            "question_type": _choice("text", "choice", "date"),
            "current_status": _choice("active", "active", "inactive"),
            "options": None,
        })

    try:
        await session.execute(
            text("""
                INSERT INTO register_questions
                    (uuid, question, answer, created_by, question_level,
                     question_type, current_status, options)
                VALUES
                    (:uuid, :question, :answer, :created_by, :question_level,
                     :question_type, :current_status, :options)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个注册问题")
    except Exception as e:
        print(f"❌ 插入注册问题失败: {e}")
