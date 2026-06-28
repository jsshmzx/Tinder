"""日志查询接口（系统日志 + 个人日志）。

所有查询均受权限控制：
- /system：仅 superadmin
- /personal：本人或 superadmin
"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from core.database.dao.personal_logs import PersonalLogsDAO
from core.database.dao.system_logs import SystemLogsDAO
from core.middleware.auth.dependencies import get_current_user
from core.security.log_permissions import (
    can_access_system_logs,
    get_permitted_user_uuids,
    require_system_log_access,
)

router = APIRouter(prefix="/logs", tags=["Logs v1"])


class PaginatedLogResponse(BaseModel):
    """分页日志响应。"""

    total: int
    items: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# System logs
# ---------------------------------------------------------------------------


@router.get("/system", response_model=PaginatedLogResponse)
async def query_system_logs(
    _: dict = Depends(require_system_log_access),
    event_type: str | None = Query(None, description="事件类型"),
    log_type: str | None = Query(None, description="日志类型"),
    status: str | None = Query(None, description="结果状态"),
    severity: str | None = Query(None, description="严重程度"),
    service_name: str | None = Query(None, description="服务名"),
    trace_id: str | None = Query(None, description="追踪 ID"),
    client_ip: str | None = Query(None, description="客户端 IP"),
    keyword: str | None = Query(None, description="内容关键词"),
    start_time: datetime | None = Query(None, description="开始时间"),
    end_time: datetime | None = Query(None, description="结束时间"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """查询系统日志（仅 superadmin）。"""
    items, total = await SystemLogsDAO.search(
        event_type=event_type,
        log_type=log_type,
        status=status,
        severity=severity,
        service_name=service_name,
        trace_id=trace_id,
        client_ip=client_ip,
        keyword=keyword,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    return {"total": total, "items": items}


# ---------------------------------------------------------------------------
# Personal logs
# ---------------------------------------------------------------------------


@router.get("/personal", response_model=PaginatedLogResponse)
async def query_personal_logs(
    current_user: dict = Depends(get_current_user),
    user_uuid: str | None = Query(None, description="指定用户 UUID（仅管理员可用）"),
    event_type: str | None = Query(None, description="事件类型"),
    log_type: str | None = Query(None, description="日志类型"),
    status: str | None = Query(None, description="结果状态"),
    target_type: str | None = Query(None, description="操作对象类型"),
    target_id: str | None = Query(None, description="操作对象 ID"),
    trace_id: str | None = Query(None, description="追踪 ID"),
    client_ip: str | None = Query(None, description="客户端 IP"),
    keyword: str | None = Query(None, description="内容关键词"),
    start_time: datetime | None = Query(None, description="开始时间"),
    end_time: datetime | None = Query(None, description="结束时间"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """查询个人日志。

    普通用户只能查看自己的日志；superadmin 可查看任意用户或全部日志。
    """
    permitted_uuids = get_permitted_user_uuids(current_user, user_uuid)

    items, total = await PersonalLogsDAO.search(
        user_uuids=permitted_uuids,
        event_type=event_type,
        log_type=log_type,
        status=status,
        target_type=target_type,
        target_id=target_id,
        trace_id=trace_id,
        client_ip=client_ip,
        keyword=keyword,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    return {"total": total, "items": items}


@router.get("/personal/{user_uuid}", response_model=PaginatedLogResponse)
async def query_personal_logs_by_user(
    user_uuid: str,
    current_user: dict = Depends(get_current_user),
    event_type: str | None = Query(None, description="事件类型"),
    log_type: str | None = Query(None, description="日志类型"),
    status: str | None = Query(None, description="结果状态"),
    target_type: str | None = Query(None, description="操作对象类型"),
    target_id: str | None = Query(None, description="操作对象 ID"),
    trace_id: str | None = Query(None, description="追踪 ID"),
    client_ip: str | None = Query(None, description="客户端 IP"),
    keyword: str | None = Query(None, description="内容关键词"),
    start_time: datetime | None = Query(None, description="开始时间"),
    end_time: datetime | None = Query(None, description="结束时间"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """按用户查询个人日志（权限受 query_personal_logs 相同规则约束）。"""
    permitted_uuids = get_permitted_user_uuids(current_user, user_uuid)

    items, total = await PersonalLogsDAO.search(
        user_uuids=permitted_uuids,
        event_type=event_type,
        log_type=log_type,
        status=status,
        target_type=target_type,
        target_id=target_id,
        trace_id=trace_id,
        client_ip=client_ip,
        keyword=keyword,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    return {"total": total, "items": items}
