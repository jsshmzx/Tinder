"""users 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Integer, Text, func, select, or_
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession

from core.database.connection.pgsql import Base
from core.database.dao.base import BaseDAO


class User(Base):
    """users 表的 ORM 模型。"""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    username: Mapped[str | None] = mapped_column(Text, unique=True)
    email: Mapped[str | None] = mapped_column(Text, unique=True)
    avatar_url: Mapped[str | None] = mapped_column(Text)
    nickname: Mapped[str | None] = mapped_column(Text)
    real_name: Mapped[str | None] = mapped_column(Text)
    class_: Mapped[str | None] = mapped_column("class", Text)
    class_type: Mapped[str | None] = mapped_column(Text)
    joined_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())
    current_status: Mapped[str | None] = mapped_column(Text)
    last_login_at: Mapped[datetime | None] = mapped_column(TIMESTAMP)
    last_login_ip: Mapped[str | None] = mapped_column(Text)
    score: Mapped[int | None] = mapped_column(Integer, default=0)
    user_role: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str | None] = mapped_column(Text)
    invited_by: Mapped[str | None] = mapped_column(Text)
    views: Mapped[int | None] = mapped_column(Integer, default=0)
    other_info: Mapped[Any | None] = mapped_column(JSONB)
    is_verified: Mapped[bool | None] = mapped_column(Boolean)
    password: Mapped[str | None] = mapped_column(Text)


class UsersDAO(BaseDAO):
    """users 表的数据访问对象。"""

    MODEL = User

    @staticmethod
    async def find_by_username_or_email(session: AsyncSession, login_identifier: str) -> User | None:
        """根据 username 或 email 查询用户，返回 User ORM 对象或 None。"""
        result = await session.scalars(
            select(User).where(
                or_(User.username == login_identifier, User.email == login_identifier)
            )
        )
        return result.first()

    @staticmethod
    async def find_duplicate_student(session: AsyncSession, real_name: str, class_: str) -> User | None:
        """检查是否存在同名同班级的学生，存在则返回该用户，否则返回 None。

        用于注册时防止重复注册。
        """
        result = await session.scalars(
            select(User).where(
                User.real_name == real_name,
                User.class_ == class_,
            )
        )
        return result.first()

    @staticmethod
    async def find_duplicate_student_exclude_self(
        session: AsyncSession, real_name: str, class_: str, exclude_uuid: str
    ) -> User | None:
        """检查是否存在同名同班级但不同 uuid 的学生，存在则返回该用户，否则返回 None。

        用于修改个人信息时防止与其他用户产生冲突（排除自身）。
        """
        result = await session.scalars(
            select(User).where(
                User.real_name == real_name,
                User.class_ == class_,
                User.uuid != exclude_uuid,
            )
        )
        return result.first()
