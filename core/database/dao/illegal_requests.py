"""illegal_requests 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from typing import Any

from sqlalchemy import Index, Integer, Text, func, select
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.db import Base, get_session
from core.database.dao.base import BaseDAO


class IllegalRequest(Base):
    """illegal_requests 表的 ORM 模型。"""

    __tablename__ = "illegal_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    # "user" is a PostgreSQL reserved word; mapped_column("user", ...) handles quoting
    user: Mapped[str] = mapped_column("user", Text, nullable=False, server_default="unknown")
    happened_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())
    type: Mapped[str] = mapped_column(Text, nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str] = mapped_column(Text, nullable=False)
    ua: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("idx_illegal_requests_ip", "ip"),
        Index("idx_illegal_requests_happened_at", "happened_at"),
    )


class IllegalRequestsDAO(BaseDAO):
    """illegal_requests 表的数据访问对象。"""

    MODEL = IllegalRequest

    def find_by_ip(self, ip: str, limit: int = 100) -> list[dict[str, Any]]:
        """查询指定 IP 的所有违规记录。"""
        with get_session() as session:
            objs = session.scalars(
                select(IllegalRequest)
                .where(IllegalRequest.ip == ip)
                .order_by(IllegalRequest.happened_at.desc())
                .limit(limit)
            )
            return [self._to_dict(o) for o in objs]

    def find_by_user(self, user: str, limit: int = 100) -> list[dict[str, Any]]:
        """查询指定用户的所有违规记录。"""
        with get_session() as session:
            objs = session.scalars(
                select(IllegalRequest)
                .where(IllegalRequest.user == user)
                .order_by(IllegalRequest.happened_at.desc())
                .limit(limit)
            )
            return [self._to_dict(o) for o in objs]


