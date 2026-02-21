"""request_logs 表的数据访问对象（含 ORM 模型定义）。

request_logs 表使用 request_path 作为唯一键（无 uuid 字段）。
"""

from datetime import datetime
from typing import Any

from sqlalchemy import Integer, Text, UniqueConstraint, func, select
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.db import Base, get_session
from core.database.dao.base import BaseDAO


class RequestLog(Base):
    """request_logs 表的 ORM 模型。"""

    __tablename__ = "request_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_path: Mapped[str] = mapped_column(Text, nullable=False)
    frequency: Mapped[int | None] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())

    __table_args__ = (UniqueConstraint("request_path"),)


class RequestLogsDAO(BaseDAO):
    """request_logs 表的数据访问对象。

    request_logs 表使用 request_path 作为唯一键（非 uuid），
    额外提供按 request_path 查询/更新的方法。
    """

    MODEL = RequestLog

    def find_by_uuid(self, uuid: str) -> dict[str, Any] | None:
        raise NotImplementedError(
            "request_logs 表不包含 uuid 字段，请使用 find_by_path"
        )

    def update(self, uuid: str, data: dict[str, Any]) -> dict[str, Any] | None:
        raise NotImplementedError(
            "request_logs 表不包含 uuid 字段，请使用 upsert_by_path"
        )

    def delete(self, uuid: str) -> bool:
        raise NotImplementedError(
            "request_logs 表不包含 uuid 字段，请使用 delete_by_path"
        )

    def find_by_path(self, request_path: str) -> dict[str, Any] | None:
        with get_session() as session:
            obj = session.scalars(
                select(RequestLog).where(RequestLog.request_path == request_path)
            ).first()
            return self._to_dict(obj) if obj else None

    def upsert_by_path(self, request_path: str) -> dict[str, Any]:
        """若记录不存在则插入，存在则将 frequency 加一。"""
        with get_session() as session:
            stmt = (
                pg_insert(RequestLog)
                .values(request_path=request_path, frequency=1)
                .on_conflict_do_update(
                    index_elements=["request_path"],
                    set_={"frequency": RequestLog.__table__.c.frequency + 1},
                )
            )
            session.execute(stmt)
            session.flush()
            obj = session.scalars(
                select(RequestLog).where(RequestLog.request_path == request_path)
            ).first()
            return self._to_dict(obj)

    def delete_by_path(self, request_path: str) -> bool:
        with get_session() as session:
            obj = session.scalars(
                select(RequestLog).where(RequestLog.request_path == request_path)
            ).first()
            if obj is None:
                return False
            session.delete(obj)
            return True


