"""tokens 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from typing import Any

from sqlalchemy import Index, Integer, Text, func, or_, select
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.db import Base, get_session
from core.database.dao.base import BaseDAO


class Token(Base):
    """tokens 表的 ORM 模型。"""

    __tablename__ = "tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    belong_to: Mapped[str] = mapped_column(Text, nullable=False)
    permission: Mapped[str] = mapped_column(Text, nullable=False)
    assigner: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())
    expired_at: Mapped[datetime | None] = mapped_column(TIMESTAMP)
    current_status: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("idx_tokens_belong_to", "belong_to"),
        Index("idx_tokens_expired_at", "expired_at"),
    )


class TokensDAO(BaseDAO):
    """tokens 表的数据访问对象。"""

    MODEL = Token

    def find_by_belong_to(self, belong_to: str) -> list[dict[str, Any]]:
        """查询指定用户的所有 token。"""
        with get_session() as session:
            objs = session.scalars(
                select(Token).where(Token.belong_to == belong_to)
            )
            return [self._to_dict(o) for o in objs]

    def find_active_by_belong_to(self, belong_to: str) -> list[dict[str, Any]]:
        """查询指定用户的所有未过期 token。"""
        with get_session() as session:
            objs = session.scalars(
                select(Token).where(
                    Token.belong_to == belong_to,
                    or_(Token.expired_at.is_(None), Token.expired_at > func.now()),
                    Token.current_status != "revoked",
                )
            )
            return [self._to_dict(o) for o in objs]


