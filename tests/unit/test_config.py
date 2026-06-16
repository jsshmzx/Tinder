"""Unit tests — core.config.Settings (no DB/Redis).

Settings uses class-level attributes evaluated at import time, so env var
tests must be done differently.  We test defaults (which are stable) and
use the module-level ``settings`` singleton for attribute existence checks.
"""

from core.config import settings


# ---------------------------------------------------------------------------
# Default values (stable regardless of env)
# ---------------------------------------------------------------------------

def test_settings_server_port_default():
    assert settings.SERVER_PORT == 1912


def test_settings_server_host_default():
    assert settings.SERVER_HOST == "0.0.0.0"


def test_settings_api_v1_prefix_default():
    assert settings.API_V1_PREFIX == "/api/v1"


def test_settings_jwt_algorithm_default():
    assert settings.JWT_ALGORITHM == "HS256"


def test_settings_cors_allow_credentials():
    assert settings.CORS_ALLOW_CREDENTIALS is True


def test_settings_tz_default():
    assert settings.TZ == "Asia/Shanghai"


def test_settings_access_token_expire_minutes():
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 60


def test_settings_temp_token_expire_minutes():
    assert settings.TEMP_TOKEN_EXPIRE_MINUTES == 15


def test_settings_auth_user_cache_ttl():
    assert settings.AUTH_USER_CACHE_TTL_SECONDS == 60


def test_settings_fw_defaults():
    assert settings.FW_MAX_REQUESTS_PER_SECOND == 20
    assert settings.FW_BAN_THRESHOLD == 10
    assert settings.FW_BAN_DURATION == 86400


def test_settings_login_rate_defaults():
    assert settings.LOGIN_MAX_ATTEMPTS_PER_IP_PER_MINUTE == 20
    assert settings.LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_MINUTE == 5
    assert settings.LOGIN_RATE_WINDOW_SECONDS == 60


def test_settings_reg_defaults():
    assert settings.REG_MAX_IP_ATTEMPTS_PER_DAY == 10
    assert settings.REG_MAX_NAME_ATTEMPTS_PER_DAY == 3
    assert settings.REG_MAX_SHEET_ATTEMPTS == 3
    assert settings.REG_MAX_SHEETS_PER_IP_PER_DAY == 4
    assert settings.REG_CORRECT_THRESHOLD == 3
    assert settings.REG_QUESTION_COUNT == 5
    assert settings.REG_SHEET_TTL_SECONDS == 86400


def test_settings_account_deletion_grace_days():
    assert settings.ACCOUNT_DELETION_GRACE_DAYS == 30


def test_settings_max_pwd_chg_attempts():
    assert settings.MAX_PWD_CHG_ATTEMPTS_PER_DAY == 10


def test_settings_cron_interval():
    assert settings.CRON_CLEANUP_INTERVAL_HOURS == 1


def test_settings_refresh_token_cleanup_days():
    assert settings.REFRESH_TOKEN_CLEANUP_DAYS == 7


def test_settings_redis_defaults():
    assert settings.REDIS_INITIAL_RETRY_INTERVAL == 2
    assert settings.REDIS_MAX_RETRY_INTERVAL == 60
    assert settings.REDIS_HEARTBEAT_INTERVAL == 10


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

def test_global_settings_is_singleton():
    from core.config import Settings
    assert isinstance(settings, Settings)


def test_global_settings_has_common_attrs():
    assert hasattr(settings, "SERVER_PORT")
    assert hasattr(settings, "JWT_SECRET_KEY")
    assert hasattr(settings, "DATABASE_URL")
    assert hasattr(settings, "REDIS_URL")
    assert hasattr(settings, "API_V1_PREFIX")
    assert hasattr(settings, "CORS_ALLOW_ORIGINS")
    assert hasattr(settings, "APP_ENV")
