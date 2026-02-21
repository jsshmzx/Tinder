"""personal_logs 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime

from sqlalchemy import Integer, Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.db import Base
from core.database.dao.base import BaseDAO


class PersonalLog(Base):
    """personal_logs 表的 ORM 模型。"""

    __tablename__ = "personal_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    user_uuid: Mapped[str] = mapped_column(Text, nullable=False)
    log_level: Mapped[str | None] = mapped_column(Text)
    log_type: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())


class PersonalLogsDAO(BaseDAO):
    """personal_logs 表的数据访问对象。"""

    MODEL = PersonalLog
