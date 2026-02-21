"""system_reports 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime

from sqlalchemy import Integer, Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.db import Base
from core.database.dao.base import BaseDAO


class SystemReport(Base):
    """system_reports 表的 ORM 模型。"""

    __tablename__ = "system_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    content: Mapped[str | None] = mapped_column(Text)
    frequency: Mapped[int | None] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())


class SystemReportsDAO(BaseDAO):
    """system_reports 表的数据访问对象。"""

    MODEL = SystemReport
