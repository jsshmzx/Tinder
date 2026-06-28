"""CustomLog — 自定义日志系统 (CtLog)。

支持四种日志级别 (INFO/WARNING/ERROR/SUCCESS)、两种输出样式 (CT/NORMAL)、
控制台输出开关 (PrintOut)、数据库存储开关 (SiD)、日志分类 (SiDP: system/personal)
及日志类型 (LogType)。CT 样式为原 custom_log 的彩色输出，NORMAL 为纯文本打印。

扩展能力：支持结构化日志字段（event_type、trace_id、client_ip、target_type 等），
并提供 LogContext 在请求链路中传递公共上下文。
"""

import asyncio
import contextvars
import datetime
import socket
import uuid
from dataclasses import dataclass, field
from typing import Any

# ANSI 颜色代码
_GREEN = "\033[92m"
_ORANGE = "\033[38;5;208m"
_RED = "\033[91m"
_RESET = "\033[0m"

_LEVEL_CONFIG: dict[str, tuple[str, str]] = {
    "SUCCESS": (_GREEN, "[SUCCESS]"),
    "WARNING": (_ORANGE, "[WARNING]"),
    "ERROR": (_RED, "[ERROR]"),
    "INFO": (_RESET, "[INFO]"),
}

# 日志级别到严重程度的映射
_LEVEL_TO_SEVERITY: dict[str, str] = {
    "INFO": "INFO",
    "SUCCESS": "INFO",
    "WARNING": "WARN",
    "ERROR": "ERROR",
}


@dataclass
class LogContext:
    """可在请求链路中共享的日志上下文。"""

    trace_id: str | None = None
    client_ip: str | None = None
    user_agent: str | None = None
    request_method: str | None = None
    request_url: str | None = None
    user_uuid: str | None = None
    extra_data: dict[str, Any] = field(default_factory=dict)

    def merge(self, **overrides: Any) -> "LogContext":
        """返回一个合并了覆盖值的新上下文。"""
        data = {
            "trace_id": overrides.get("trace_id", self.trace_id),
            "client_ip": overrides.get("client_ip", self.client_ip),
            "user_agent": overrides.get("user_agent", self.user_agent),
            "request_method": overrides.get("request_method", self.request_method),
            "request_url": overrides.get("request_url", self.request_url),
            "user_uuid": overrides.get("user_uuid", self.user_uuid),
            "extra_data": {
                **(self.extra_data or {}),
                **(overrides.get("extra_data") or {}),
            },
        }
        return LogContext(**data)


_log_context_var: contextvars.ContextVar[LogContext | None] = contextvars.ContextVar(
    "custom_log_context", default=None
)


def get_log_context() -> LogContext:
    """获取当前上下文；若不存在则返回空上下文。"""
    ctx = _log_context_var.get()
    return ctx if ctx is not None else LogContext()


def set_log_context(ctx: LogContext | None) -> contextvars.Token:
    """设置当前线程/协程的日志上下文，返回 Token 便于重置。"""
    return _log_context_var.set(ctx)


def reset_log_context(token: contextvars.Token) -> None:
    """重置日志上下文。"""
    _log_context_var.reset(token)


def _json_safe(value: Any) -> Any:
    """将值递归转换为 JSON 安全类型。

    目前处理 datetime/date 对象；其他不可序列化类型会被丢弃或转为字符串。
    """
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, datetime.date):
        return value.isoformat()
    return value


class CustomLog:
    """自定义日志类。

    参数:
        log_level: 日志级别 (INFO/WARNING/ERROR/SUCCESS)，不区分大小写。
        content: 日志内容文本。
        log_style: 输出样式 (CT/NORMAL)。CT 为带颜色的格式化输出，
                   NORMAL 为纯文本打印。
        print_out: 是否在控制台输出日志。
        sid (Store In DB): 是否将日志持久化到数据库。
        sidp (Place): 日志分类 — "system"（系统日志）或 "personal"（个人日志）。
        log_type: 数据库日志类型字段 (如 "auth", "rbac", "firewall", "cron" 等)。
        user_uuid: 个人日志需要的用户 UUID（仅在 sidp="personal" 时需要）。

        以下为结构化扩展字段:
        event_type, status, client_ip, user_agent, request_method, request_url,
        trace_id, error_code, error_msg, target_type, target_id, target_name,
        before_data, after_data, operation_result, service_name, host_name,
        host_ip, process_id, metric_value, extra_data
    """

    def __init__(
        self,
        log_level: str = "INFO",
        content: str = "",
        log_style: str = "CT",
        print_out: bool = True,
        sid: bool = False,
        sidp: str = "system",
        log_type: str | None = None,
        user_uuid: str | None = None,
        event_type: str | None = None,
        status: str | None = "SUCCESS",
        client_ip: str | None = None,
        user_agent: str | None = None,
        request_method: str | None = None,
        request_url: str | None = None,
        trace_id: str | None = None,
        error_code: str | None = None,
        error_msg: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        target_name: str | None = None,
        before_data: dict[str, Any] | None = None,
        after_data: dict[str, Any] | None = None,
        operation_result: str | None = None,
        service_name: str | None = None,
        host_name: str | None = None,
        host_ip: str | None = None,
        process_id: str | None = None,
        metric_value: str | None = None,
        extra_data: dict[str, Any] | None = None,
    ):
        self.log_level = log_level.upper()
        self.content = content if isinstance(content, str) else str(content) if content is not None else ""
        self.log_style = log_style.upper()
        self.print_out = print_out
        self.sid = sid
        self.sidp = sidp
        self.log_type = log_type
        self.user_uuid = (
            user_uuid if isinstance(user_uuid, str) else str(user_uuid) if user_uuid is not None else None
        )

        # 与当前上下文合并，显式参数优先级高于上下文
        ctx = get_log_context()
        self.event_type = event_type
        self.status = status.upper() if status else "SUCCESS"
        self.client_ip = client_ip or ctx.client_ip
        self.user_agent = user_agent or ctx.user_agent
        self.request_method = request_method or ctx.request_method
        self.request_url = request_url or ctx.request_url
        raw_trace_id = trace_id or ctx.trace_id
        self.trace_id = (
            raw_trace_id
            if isinstance(raw_trace_id, str)
            else str(raw_trace_id)
            if raw_trace_id is not None
            else str(uuid.uuid4())
        )
        self.error_code = error_code
        self.error_msg = error_msg
        self.target_type = target_type
        self.target_id = target_id
        self.target_name = target_name
        self.before_data = before_data
        self.after_data = after_data
        self.operation_result = operation_result
        self.service_name = service_name
        self.host_name = host_name or socket.gethostname()
        self.host_ip = host_ip
        self.process_id = process_id
        self.metric_value = metric_value
        self.extra_data = {**(ctx.extra_data or {}), **(extra_data or {})}

        self._execute()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute(self) -> None:
        """执行日志输出与存储。"""
        if self.print_out:
            self._print()
        if self.sid:
            self._store()

    def _print(self) -> None:
        """根据样式将日志输出到控制台。"""
        if self.log_style == "NORMAL":
            print(f"[{self.log_level}] {self.content}")
        else:
            color, label = _LEVEL_CONFIG.get(
                self.log_level,
                (_RESET, f"[{self.log_level}]"),
            )
            trace = f" [{self.trace_id}]" if self.trace_id else ""
            print(f"{color} {label}{trace} {self.content}{_RESET}")

    def _store(self) -> None:
        """异步将日志写入数据库（fire-and-forget）。"""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # 无运行中的事件循环，跳过 DB 写入
        loop.create_task(self._async_store())

    async def _async_store(self) -> None:
        """实际执行数据库写入的异步方法。"""
        try:
            from core.database.connection.pgsql import get_session

            if self.sidp == "system":
                from core.database.dao.system_logs import SystemLog

                async with get_session() as session:
                    session.add(
                        SystemLog(
                            uuid=str(uuid.uuid4()),
                            log_level=self.log_level,
                            log_type=self.log_type,
                            content=self.content,
                            event_type=self.event_type,
                            status=self.status,
                            severity=_LEVEL_TO_SEVERITY.get(self.log_level, "INFO"),
                            service_name=self.service_name,
                            host_name=self.host_name,
                            host_ip=self.host_ip,
                            process_id=self.process_id,
                            trace_id=self.trace_id,
                            client_ip=self.client_ip,
                            user_agent=self.user_agent,
                            request_method=self.request_method,
                            request_url=self.request_url,
                            error_code=self.error_code,
                            error_msg=self.error_msg,
                            metric_value=self.metric_value,
                            extra_data=_json_safe(self.extra_data) if self.extra_data else None,
                        )
                    )
            elif self.sidp == "personal" and (self.user_uuid or get_log_context().user_uuid):
                from core.database.dao.personal_logs import PersonalLog

                user_uuid = self.user_uuid or get_log_context().user_uuid
                async with get_session() as session:
                    session.add(
                        PersonalLog(
                            uuid=str(uuid.uuid4()),
                            user_uuid=user_uuid,
                            log_level=self.log_level,
                            log_type=self.log_type,
                            content=self.content,
                            event_type=self.event_type,
                            status=self.status,
                            target_type=self.target_type,
                            target_id=self.target_id,
                            target_name=self.target_name,
                            before_data=_json_safe(self.before_data) if self.before_data else None,
                            after_data=_json_safe(self.after_data) if self.after_data else None,
                            operation_result=self.operation_result,
                            client_ip=self.client_ip,
                            user_agent=self.user_agent,
                            request_method=self.request_method,
                            request_url=self.request_url,
                            trace_id=self.trace_id,
                            error_code=self.error_code,
                            error_msg=self.error_msg,
                            extra_data=_json_safe(self.extra_data) if self.extra_data else None,
                        )
                    )
        except Exception:
            # 日志存储失败不应影响主流程；生产环境建议接入监控告警
            pass


# 简化别名
CtLog = CustomLog
