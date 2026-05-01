"""register_questions 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from typing import Any

from sqlalchemy import Integer, Text, func, select
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.pgsql import Base, get_session
from core.database.dao.base import BaseDAO


class RegisterQuestions(Base):
    """register_questions 表的 ORM 模型。"""

    __tablename__ = "register_questions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    answer: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str | None] = mapped_column(Text)
    # 数据库列名为 question_level，属性名对应映射
    question_level: Mapped[str | None] = mapped_column("question_level", Text)
    question_type: Mapped[str | None] = mapped_column(Text)
    current_status: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())


class RegisterQuestionsDAO(BaseDAO):
    """register_questions 表的数据访问对象。"""

    MODEL = RegisterQuestions

    @staticmethod
    async def find_random_active(count: int = 5) -> list[dict[str, Any]]:
        """从 current_status='active' 的题库中随机抽取指定数量的题目。

        使用数据库层面的随机排序，避免一次性加载全表数据。
        返回含 uuid、question、answer 字段的字典列表。
        """
        async with get_session() as session:
            objs = await session.scalars(
                select(RegisterQuestions)
                .where(RegisterQuestions.current_status == "active")
                .order_by(func.random())
                .limit(count)
            )
            return [
                {
                    "uuid": o.uuid,
                    "question": o.question,
                    "answer": o.answer,
                }
                for o in objs
            ]