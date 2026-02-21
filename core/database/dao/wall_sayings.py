"""wall_sayings 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from typing import Any

from sqlalchemy import Integer, Text, func
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.db import Base
from core.database.dao.base import BaseDAO


class WallSaying(Base):
    """wall_sayings 表的 ORM 模型。"""

    __tablename__ = "wall_sayings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    author_uuid: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str | None] = mapped_column(Text)
    saying_status: Mapped[str | None] = mapped_column(Text)
    saying_type: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP)
    other_info: Mapped[Any | None] = mapped_column(JSONB)
    likes: Mapped[int | None] = mapped_column(Integer, default=0)
    share_count: Mapped[int | None] = mapped_column(Integer, default=0)
    views: Mapped[int | None] = mapped_column(Integer, default=0)


class WallSayingsDAO(BaseDAO):
    """wall_sayings 表的数据访问对象。"""

    MODEL = WallSaying
