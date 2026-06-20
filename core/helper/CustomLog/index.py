"""CustomLog — 自定义日志系统 (CtLog)。

支持四种日志级别 (INFO/WARNING/ERROR/SUCCESS)、两种输出样式 (CT/NORMAL)、
控制台输出开关 (PrintOut)、数据库存储开关 (SiD)、日志分类 (SiDP: system/personal)
及日志类型 (LogType)。CT 样式为原 custom_log 的彩色输出，NORMAL 为纯文本打印。
"""

import asyncio
import uuid

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
    ):
        self.log_level = log_level.upper()
        self.content = content
        self.log_style = log_style.upper()
        self.print_out = print_out
        self.sid = sid
        self.sidp = sidp
        self.log_type = log_type
        self.user_uuid = user_uuid
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
            print(f"{color} {label} {self.content}{_RESET}")

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
            if self.sidp == "system":
                from core.database.connection.pgsql import get_session
                from core.database.dao.system_logs import SystemLog

                async with get_session() as session:
                    session.add(
                        SystemLog(
                            uuid=str(uuid.uuid4()),
                            log_level=self.log_level,
                            log_type=self.log_type,
                            content=self.content,
                        )
                    )
            elif self.sidp == "personal" and self.user_uuid:
                from core.database.connection.pgsql import get_session
                from core.database.dao.personal_logs import PersonalLog

                async with get_session() as session:
                    session.add(
                        PersonalLog(
                            uuid=str(uuid.uuid4()),
                            user_uuid=self.user_uuid,
                            log_level=self.log_level,
                            log_type=self.log_type,
                            content=self.content,
                        )
                    )
        except Exception:
            pass  # 日志存储失败不影响主流程


# 简化别名
CtLog = CustomLog
