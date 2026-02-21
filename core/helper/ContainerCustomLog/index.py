# ANSI 颜色代码
_GREEN = "\033[92m"
_ORANGE = "\033[38;5;208m"
_RED = "\033[91m"
_RESET = "\033[0m"

_LEVEL_CONFIG = {
    "SUCCESS": (_GREEN, "[SUCCESS]"),
    "WARNING": (_ORANGE, "[WARNING]"),
    "ERROR": (_RED, "[ERROR]"),
}


def custom_log(log_level: str, log_content: str) -> None:
    """打印自定义颜色日志。

    Args:
        log_level: 日志级别，支持 'SUCCESS'、'WARNING'、'ERROR'（不区分大小写）。
        log_content: 日志内容。
    """
    level_key = log_level.upper()
    color, label = _LEVEL_CONFIG.get(level_key, (_RESET, f"[{level_key}]"))
    print(f"{color} {label} {log_content}{_RESET}")
