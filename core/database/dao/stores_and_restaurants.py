"""stores_and_restaurants 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from decimal import Decimal

from sqlalchemy import Integer, Numeric, Text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.db import Base
from core.database.dao.base import BaseDAO


class StoreOrRestaurant(Base):
    """stores_and_restaurants 表的 ORM 模型。"""

    __tablename__ = "stores_and_restaurants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    location: Mapped[str | None] = mapped_column(Text)
    likes: Mapped[int | None] = mapped_column(Integer, default=0)
    start_date: Mapped[datetime | None] = mapped_column(TIMESTAMP)
    end_date: Mapped[datetime | None] = mapped_column(TIMESTAMP)
    ratings: Mapped[Decimal | None] = mapped_column(Numeric(4, 2))
    status: Mapped[str | None] = mapped_column(Text)


class StoresAndRestaurantsDAO(BaseDAO):
    """stores_and_restaurants 表的数据访问对象。"""

    MODEL = StoreOrRestaurant
