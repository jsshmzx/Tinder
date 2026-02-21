"""relations 表的数据访问对象（含 ORM 模型定义）。

relations 表没有独立的 uuid 主键，使用自增 id 作为主键。
"""

from datetime import datetime
from typing import Any

from sqlalchemy import Integer, Text, func, select
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.db import Base, get_session
from core.database.dao.base import BaseDAO


class Relation(Base):
    """relations 表的 ORM 模型。"""

    __tablename__ = "relations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tags_uuid: Mapped[str] = mapped_column(Text, nullable=False)
    related_uuid: Mapped[str] = mapped_column(Text, nullable=False)
    relation_type: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())


class RelationsDAO(BaseDAO):
    """relations 表的数据访问对象。

    relations 表没有独立的 uuid 主键，额外提供按 id 查询/删除的方法。
    """

    MODEL = Relation

    def find_by_uuid(self, uuid: str) -> dict[str, Any] | None:
        raise NotImplementedError("relations 表不包含 uuid 字段，请使用 find_by_id")

    def update(self, uuid: str, data: dict[str, Any]) -> dict[str, Any] | None:
        raise NotImplementedError("relations 表不包含 uuid 字段，请使用 update_by_id")

    def delete(self, uuid: str) -> bool:
        raise NotImplementedError("relations 表不包含 uuid 字段，请使用 delete_by_id")

    def find_by_id(self, record_id: int) -> dict[str, Any] | None:
        with get_session() as session:
            obj = session.scalars(
                select(Relation).where(Relation.id == record_id)
            ).first()
            return self._to_dict(obj) if obj else None

    def find_by_tags_uuid(self, tags_uuid: str) -> list[dict[str, Any]]:
        with get_session() as session:
            objs = session.scalars(
                select(Relation).where(Relation.tags_uuid == tags_uuid)
            )
            return [self._to_dict(o) for o in objs]

    def update_by_id(self, record_id: int, data: dict[str, Any]) -> dict[str, Any] | None:
        with get_session() as session:
            obj = session.scalars(
                select(Relation).where(Relation.id == record_id)
            ).first()
            if obj is None:
                return None
            for k, v in self._data_to_kwargs(data).items():
                setattr(obj, k, v)
            session.flush()
            session.refresh(obj)
            return self._to_dict(obj)

    def delete_by_id(self, record_id: int) -> bool:
        with get_session() as session:
            obj = session.scalars(
                select(Relation).where(Relation.id == record_id)
            ).first()
            if obj is None:
                return False
            session.delete(obj)
            return True


