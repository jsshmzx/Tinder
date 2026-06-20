"""register_questions 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from typing import Any

from sqlalchemy import Integer, Text, func, or_, select
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
    options: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(Text)  # 创建者 uuid 或用户名（可选）
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

    @staticmethod
    async def search_questions(
        keyword: str | None = None,
        question_type: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """分页搜索题目，支持 keyword 模糊匹配 question，type/status 精确筛选。"""
        async with get_session() as session:
            stmt = select(RegisterQuestions)
            conditions = []
            if keyword:
                conditions.append(RegisterQuestions.question.ilike(f"%{keyword}%"))
            if question_type:
                conditions.append(RegisterQuestions.question_type == question_type)
            if status:
                conditions.append(RegisterQuestions.current_status == status)
            if conditions:
                stmt = stmt.where(*conditions)
            objs = await session.scalars(
                stmt.order_by(RegisterQuestions.id.desc()).limit(limit).offset(offset)
            )
            return [RegisterQuestionsDAO._to_dict(o) for o in objs]

    @staticmethod
    async def count_questions(
        keyword: str | None = None,
        question_type: str | None = None,
        status: str | None = None,
    ) -> int:
        """按条件统计题目总数。"""
        async with get_session() as session:
            stmt = select(func.count(RegisterQuestions.id))
            conditions = []
            if keyword:
                conditions.append(RegisterQuestions.question.ilike(f"%{keyword}%"))
            if question_type:
                conditions.append(RegisterQuestions.question_type == question_type)
            if status:
                conditions.append(RegisterQuestions.current_status == status)
            if conditions:
                stmt = stmt.where(*conditions)
            result = await session.execute(stmt)
            return result.scalar() or 0

    @staticmethod
    async def count_by_type(question_type: str) -> int:
        """按题型统计题目数。"""
        async with get_session() as session:
            result = await session.execute(
                select(func.count(RegisterQuestions.id))
                .where(RegisterQuestions.question_type == question_type)
            )
            return result.scalar() or 0

    @staticmethod
    async def batch_delete_by_uuids(uuids: list[str]) -> int:
        """批量删除题目，返回实际删除数量。"""
        async with get_session() as session:
            result = await session.execute(
                RegisterQuestions.__table__.delete().where(RegisterQuestions.uuid.in_(uuids))
            )
            return result.rowcount

    @staticmethod
    async def batch_update_status(uuids: list[str], status: str) -> int:
        """批量更新题目状态，返回实际更新数量。"""
        async with get_session() as session:
            result = await session.execute(
                RegisterQuestions.__table__.update()
                .where(RegisterQuestions.uuid.in_(uuids))
                .values(current_status=status)
            )
            return result.rowcount