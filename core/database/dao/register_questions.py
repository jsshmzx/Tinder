"""register_questions表的数据访问对象"""

from datetime import datetime

import UUID
from sqlalchemy import Integer, Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.pgsql import Base
from core.database.dao.base import BaseDAO

class RegisterQuestions(Base):
    """register_questions表的ORM模型"""

    __tablename__ = "register_questions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[UUID] = mapped_column(Text, nullable=False)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    answer: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[int] = mapped_column(Text, nullable=False)
    level: Mapped[str] = mapped_column(Text, nullable=False)
    question_type: Mapped[str] = mapped_column(Text, nullable=False)
    current_status: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())
class RegisterQuestionsDAO(BaseDAO):
    """RegisterQuestions表的数据访问对象"""

    MODEL = RegisterQuestions