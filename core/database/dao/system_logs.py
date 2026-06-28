"""system_logs 表的数据访问对象（含 ORM 模型定义）。"""

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Integer, Text, func, select
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.pgsql import Base, get_session
from core.database.dao.base import BaseDAO


class SystemLog(Base):
    """system_logs 表的 ORM 模型。"""

    __tablename__ = "system_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    log_level: Mapped[str | None] = mapped_column(Text)
    log_type: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP, server_default=func.now())
    being_flagged: Mapped[bool | None] = mapped_column(Boolean, server_default="false")
    content: Mapped[str | None] = mapped_column(Text)
    system_version: Mapped[str | None] = mapped_column(Text)

    # 结构化日志扩展字段
    event_type: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(Text, server_default="SUCCESS")
    severity: Mapped[str | None] = mapped_column(Text)
    service_name: Mapped[str | None] = mapped_column(Text)
    host_name: Mapped[str | None] = mapped_column(Text)
    host_ip: Mapped[str | None] = mapped_column(Text)
    process_id: Mapped[str | None] = mapped_column(Text)
    trace_id: Mapped[str | None] = mapped_column(Text)
    client_ip: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    request_method: Mapped[str | None] = mapped_column(Text)
    request_url: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(Text)
    error_msg: Mapped[str | None] = mapped_column(Text)
    metric_value: Mapped[str | None] = mapped_column(Text)
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class SystemLogsDAO(BaseDAO):
    """system_logs 表的数据访问对象。"""

    MODEL = SystemLog

    @classmethod
    async def search(
        cls,
        *,
        event_type: str | None = None,
        log_type: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        service_name: str | None = None,
        trace_id: str | None = None,
        client_ip: str | None = None,
        keyword: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """按条件分页查询系统日志，返回记录列表与总数。"""
        async with get_session() as session:
            stmt = select(SystemLog)
            count_stmt = select(func.count(SystemLog.id))

            filters = []
            if event_type:
                filters.append(SystemLog.event_type == event_type)
            if log_type:
                filters.append(SystemLog.log_type == log_type)
            if status:
                filters.append(SystemLog.status == status)
            if severity:
                filters.append(SystemLog.severity == severity)
            if service_name:
                filters.append(SystemLog.service_name == service_name)
            if trace_id:
                filters.append(SystemLog.trace_id == trace_id)
            if client_ip:
                filters.append(SystemLog.client_ip == client_ip)
            if start_time:
                filters.append(SystemLog.created_at >= start_time)
            if end_time:
                filters.append(SystemLog.created_at <= end_time)
            if keyword:
                filters.append(SystemLog.content.ilike(f"%{keyword}%"))

            if filters:
                stmt = stmt.where(*filters)
                count_stmt = count_stmt.where(*filters)

            stmt = stmt.order_by(SystemLog.created_at.desc()).limit(limit).offset(offset)

            objs = await session.scalars(stmt)
            total = (await session.scalar(count_stmt)) or 0
            return [cls._to_dict(o) for o in objs], total
