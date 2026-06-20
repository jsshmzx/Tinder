"""集中式配置模块。

所有程序相关变量统一从此读取，优先级：
    .env 文件  →  环境变量  →  os.getenv("KEY", "默认值")

导入方式::

    from core.config import settings
    port = settings.SERVER_PORT
"""

import json
import os

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# 加载 .env（必须在读取任何配置之前执行）
# ---------------------------------------------------------------------------
load_dotenv()


# ---------------------------------------------------------------------------
# 内部辅助
# ---------------------------------------------------------------------------

def _bool(name: str, default: bool) -> bool:
    """从环境变量读取布尔值，支持 true/1/yes/false/0/no。"""
    val = os.getenv(name, str(default)).lower()
    return val in ("true", "1", "yes")


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def _str(name: str, default: str) -> str:
    return os.getenv(name, default)


def _list(name: str, default: list) -> list:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Settings 单例
# ---------------------------------------------------------------------------

class Settings:
    """集中式配置，每个属性对应 .env 中的一个变量。"""

    # === 服务器 ===
    SERVER_HOST: str = _str("SERVER_HOST", "0.0.0.0")
    SERVER_PORT: int = _int("SERVER_PORT", 1912)
    SERVER_RELOAD: bool = _bool("SERVER_RELOAD", True)
    APP_ENV: str = _str("APP_ENV", "development").lower()

    # === 时区 ===
    TZ: str = _str("TZ", "Asia/Shanghai")

    # === API ===
    API_V1_PREFIX: str = _str("API_V1_PREFIX", "/api/v1")

    # === CORS ===
    CORS_ALLOW_ORIGINS: list = _list("CORS_ALLOW_ORIGINS", ["*"])
    CORS_ALLOW_CREDENTIALS: bool = _bool("CORS_ALLOW_CREDENTIALS", True)

    # === 数据库 ===
    DATABASE_URL: str = _str("DATABASE_URL", "")
    DB_POOL_PRE_PING: bool = _bool("DB_POOL_PRE_PING", True)

    # === Redis ===
    REDIS_URL: str = _str("REDIS_URL", "")
    REDIS_INITIAL_RETRY_INTERVAL: int = _int("REDIS_INITIAL_RETRY_INTERVAL", 2)
    REDIS_MAX_RETRY_INTERVAL: int = _int("REDIS_MAX_RETRY_INTERVAL", 60)
    REDIS_HEARTBEAT_INTERVAL: int = _int("REDIS_HEARTBEAT_INTERVAL", 10)

    # === JWT ===
    JWT_SECRET_KEY: str = _str("JWT_SECRET_KEY", "")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = _int("ACCESS_TOKEN_EXPIRE_MINUTES", 60)
    TEMP_TOKEN_EXPIRE_MINUTES: int = _int("TEMP_TOKEN_EXPIRE_MINUTES", 15)
    JWT_ALGORITHM: str = _str("JWT_ALGORITHM", "HS256")

    # === 用户认证缓存 ===
    AUTH_USER_CACHE_TTL_SECONDS: int = _int("AUTH_USER_CACHE_TTL_SECONDS", 60)

    # === 防火墙 ===
    FW_ENABLED: bool = _bool("FW_ENABLED", True)
    FW_MAX_REQUESTS_PER_SECOND: int = _int("FW_MAX_REQUESTS_PER_SECOND", 20)
    FW_BAN_THRESHOLD: int = _int("FW_BAN_THRESHOLD", 10)
    FW_BAN_DURATION: int = _int("FW_BAN_DURATION", 86400)

    # === 登录限流 ===
    LOGIN_MAX_ATTEMPTS_PER_IP_PER_MINUTE: int = _int("LOGIN_MAX_ATTEMPTS_PER_IP_PER_MINUTE", 20)
    LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_MINUTE: int = _int("LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_MINUTE", 5)
    LOGIN_RATE_WINDOW_SECONDS: int = _int("LOGIN_RATE_WINDOW_SECONDS", 60)

    # === 注册 ===
    REG_MAX_IP_ATTEMPTS_PER_DAY: int = _int("REG_MAX_IP_ATTEMPTS_PER_DAY", 10)
    REG_MAX_NAME_ATTEMPTS_PER_DAY: int = _int("REG_MAX_NAME_ATTEMPTS_PER_DAY", 3)
    REG_MAX_SHEET_ATTEMPTS: int = _int("REG_MAX_SHEET_ATTEMPTS", 3)
    REG_MAX_SHEETS_PER_IP_PER_DAY: int = _int("REG_MAX_SHEETS_PER_IP_PER_DAY", 4)
    REG_CORRECT_THRESHOLD: int = _int("REG_CORRECT_THRESHOLD", 3)
    REG_QUESTION_COUNT: int = _int("REG_QUESTION_COUNT", 5)
    REG_SHEET_TTL_SECONDS: int = _int("REG_SHEET_TTL_SECONDS", 86400)
    ACCOUNT_DELETION_GRACE_DAYS: int = _int("ACCOUNT_DELETION_GRACE_DAYS", 30)
    MAX_PWD_CHG_ATTEMPTS_PER_DAY: int = _int("MAX_PWD_CHG_ATTEMPTS_PER_DAY", 10)

    # === 定时任务 ===
    CRON_CLEANUP_INTERVAL_HOURS: int = _int("CRON_CLEANUP_INTERVAL_HOURS", 1)

    # === 安全清理 ===
    REFRESH_TOKEN_CLEANUP_DAYS: int = _int("REFRESH_TOKEN_CLEANUP_DAYS", 7)


# 全局单例
settings = Settings()
