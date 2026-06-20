"""users 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Integer, Text, func, select, or_, and_, delete as sa_delete
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
    deletion_scheduled_at: Mapped[datetime | None] = mapped_column(TIMESTAMP)


class UsersDAO(BaseDAO):
    """users 表的数据访问对象。"""

    MODEL = User

    @staticmethod
    async def is_role_valid(role: str | None) -> bool:
        if role is None:
            return True
        return role in {"superadmin", "songlist_editor", "normal-user"}

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

    @staticmethod
    async def find_password_hash(session: AsyncSession, user_uuid: str) -> str | None:
        """查询用户密码哈希，仅返回 password 字段。"""
        result = await session.execute(
            select(User.password).where(User.uuid == user_uuid).limit(1)
        )
        row = result.first()
        return row[0] if row else None

    @staticmethod
    async def find_by_username(session: AsyncSession, username: str) -> User | None:
        """根据 username 精确查找用户，不存在返回 None。"""
        result = await session.scalars(
            select(User).where(User.username == username)
        )
        return result.first()

    @staticmethod
    async def count_users(
        session: AsyncSession,
        keyword: str | None = None,
        status: str | None = None,
        role: str | None = None,
    ) -> int:
        """根据条件统计用户总数。"""
        conditions = []
        if keyword:
            pattern = f"%{keyword}%"
            conditions.append(
                or_(
                    User.username.ilike(pattern),
                    User.email.ilike(pattern),
                    User.real_name.ilike(pattern),
                    User.nickname.ilike(pattern),
                )
            )
        if status:
            conditions.append(User.current_status == status)
        if role:
            conditions.append(User.user_role == role)

        query = select(func.count(User.id))
        if conditions:
            query = query.where(and_(*conditions))
        result = await session.execute(query)
        return result.scalar() or 0

    @staticmethod
    async def search_users(
        session: AsyncSession,
        keyword: str | None = None,
        status: str | None = None,
        role: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """分页搜索用户，支持关键词、状态、角色过滤。"""
        conditions = []
        if keyword:
            pattern = f"%{keyword}%"
            conditions.append(
                or_(
                    User.username.ilike(pattern),
                    User.email.ilike(pattern),
                    User.real_name.ilike(pattern),
                    User.nickname.ilike(pattern),
                )
            )
        if status:
            conditions.append(User.current_status == status)
        if role:
            conditions.append(User.user_role == role)

        query = select(User).order_by(User.id)
        if conditions:
            query = query.where(and_(*conditions))
        query = query.limit(limit).offset(offset)

        objs = (await session.scalars(query)).all()
        dao = UsersDAO()
        return [dao._to_dict(o) for o in objs]

    @staticmethod
    async def batch_delete(session: AsyncSession, uuids: list[str]) -> int:
        """批量删除用户（单条 SQL DELETE 语句）。"""
        result = await session.execute(sa_delete(User).where(User.uuid.in_(uuids)))
        await session.commit()
        return result.rowcount

    @staticmethod
    async def count_by_role(session: AsyncSession, role: str) -> int:
        """统计指定角色的用户总数。"""
        result = await session.execute(
            select(func.count(User.id)).where(User.user_role == role)
        )
        return result.scalar() or 0

    @staticmethod
    async def get_user_stats(session: AsyncSession) -> dict[str, int]:
        """获取用户统计信息。"""
        total_result = await session.execute(select(func.count(User.id)))
        total = total_result.scalar() or 0

        result = await session.execute(
            select(User.current_status, func.count(User.id)).group_by(User.current_status)
        )
        status_counts = {row[0] or "unknown": row[1] for row in result.all()}

        return {
            "total": total,
            "normal": status_counts.get("normal", 0),
            "disabled": status_counts.get("disabled", 0),
            "banned": status_counts.get("banned", 0),
            "pending_deletion": status_counts.get("pending_deletion", 0),
        }
