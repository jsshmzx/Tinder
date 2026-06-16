import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt, JWTError

from functools import lru_cache
 
 
@lru_cache(maxsize=1)
def _get_jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret:
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is not set. "
            "Set it to a long random string before starting the server."
        )
    return secret
 
 
@lru_cache(maxsize=1)
def _get_access_token_expire_minutes() -> int:
    return int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
 
 
ALGORITHM = "HS256"
 
# Backward-compatible module-level aliases (lazy-loaded via functions)
def __getattr__(name: str):
    if name == "SECRET_KEY":
        return _get_jwt_secret()
    if name == "ACCESS_TOKEN_EXPIRE_MINUTES":
        return _get_access_token_expire_minutes()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def create_access_token(subject: str | int, expires_delta: timedelta | None = None) -> str:
    """为指定的主体创建 JSON Web Token。"""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=_get_access_token_expire_minutes())
 
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, _get_jwt_secret(), algorithm=ALGORITHM)
    return encoded_jwt
 
 
def decode_access_token(token: str) -> dict[str, Any] | None:
    """解码 JSON Web Token。"""
    try:
        decoded_token = jwt.decode(token, _get_jwt_secret(), algorithms=[ALGORITHM])
        return decoded_token
    except JWTError:
        return None


def generate_refresh_token() -> tuple[str, str]:
    """Generate a cryptographically random refresh token.

    Returns (plaintext_token, sha256_hash). Store only the hash.
    """
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash


def create_temp_token(subject: str, purpose: str, expires_minutes: int = 15) -> str:
    """创建临时 JWT token，仅用于特定目的（如注册完成）。

    与 create_access_token 的区别：
    - payload 含 purpose 声明，get_temp_user 依赖据此放行
    - 默认 15 分钟过期

    Args:
        subject: 用户 uuid
        purpose: token 用途标识（如 "register_complete"）
        expires_minutes: 过期时间（分钟），默认 15

    Returns:
        JWT 字符串
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode = {"exp": expire, "sub": str(subject), "purpose": purpose}
    encoded_jwt = jwt.encode(to_encode, _get_jwt_secret(), algorithm=ALGORITHM)
    return encoded_jwt
