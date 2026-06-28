"""personal_logs 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from typing import Any

from sqlalchemy import Integer, Text, false, func, select
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.pgsql import Base, get_session
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

    # 结构化日志扩展字段
    event_type: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(Text, server_default="SUCCESS")
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[str | None] = mapped_column(Text)
    target_name: Mapped[str | None] = mapped_column(Text)
    before_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    after_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    operation_result: Mapped[str | None] = mapped_column(Text)
    client_ip: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    request_method: Mapped[str | None] = mapped_column(Text)
    request_url: Mapped[str | None] = mapped_column(Text)
    trace_id: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(Text)
    error_msg: Mapped[str | None] = mapped_column(Text)
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class PersonalLogsDAO(BaseDAO):
    """personal_logs 表的数据访问对象。"""

    MODEL = PersonalLog

    @classmethod
    async def search(
        cls,
        *,
        user_uuids: list[str] | None = None,
        event_type: str | None = None,
        log_type: str | None = None,
        status: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        trace_id: str | None = None,
        client_ip: str | None = None,
        keyword: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """按条件分页查询个人日志，返回记录列表与总数。

        user_uuids 用于权限过滤：普通用户传自己的 uuid，管理员可传多个。
        """
        async with get_session() as session:
            stmt = select(PersonalLog)
            count_stmt = select(func.count(PersonalLog.id))

            filters = []
            if user_uuids is None:
                pass  # 无权限过滤，管理员可查看全部
            elif user_uuids:
                filters.append(PersonalLog.user_uuid.in_(user_uuids))
            else:
                filters.append(false())
            if event_type:
                filters.append(PersonalLog.event_type == event_type)
            if log_type:
                filters.append(PersonalLog.log_type == log_type)
            if status:
                filters.append(PersonalLog.status == status)
            if target_type:
                filters.append(PersonalLog.target_type == target_type)
            if target_id:
                filters.append(PersonalLog.target_id == target_id)
            if trace_id:
                filters.append(PersonalLog.trace_id == trace_id)
            if client_ip:
                filters.append(PersonalLog.client_ip == client_ip)
            if start_time:
                filters.append(PersonalLog.created_at >= start_time)
            if end_time:
                filters.append(PersonalLog.created_at <= end_time)
            if keyword:
                filters.append(PersonalLog.content.ilike(f"%{keyword}%"))

            if filters:
                stmt = stmt.where(*filters)
                count_stmt = count_stmt.where(*filters)

            stmt = stmt.order_by(PersonalLog.created_at.desc()).limit(limit).offset(offset)

            objs = await session.scalars(stmt)
            total = (await session.scalar(count_stmt)) or 0
            return [cls._to_dict(o) for o in objs], total
