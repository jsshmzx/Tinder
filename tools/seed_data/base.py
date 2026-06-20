"""Shared utilities for seed data generators."""

import hashlib
import os
import random
import sys
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from faker import Faker
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from core.database.connection.pgsql import get_session as _get_db_session
from core.security.hash import get_password_hash

load_dotenv()

fake = Faker('zh_CN')

# Holds user UUIDs generated in the current session, for FK references
USER_UUIDS: list[str] = []


def _double_sha256(plain: str) -> str:
    """Compute SHA256(SHA256(plain)) → 64-char hex."""
    once = hashlib.sha256(plain.encode()).hexdigest()
    twice = hashlib.sha256(once.encode()).hexdigest()
    return twice


def _choice(*options: Any) -> Any:
    return random.choice(options)


def _maybe(none_rate: float = 0.15) -> bool:
    """Return True with probability (1 - none_rate)."""
    return random.random() > none_rate


def default_password() -> str:
    """Return the double-hashed default password for insertion."""
    return get_password_hash(_double_sha256("password123"))


def get_session():
    """Alias to core's get_session()."""
    return _get_db_session()


def _input_int(prompt: str, default: int) -> int:
    """Read an integer from stdin with a default value."""
    raw = input(prompt)
    if not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        print(f"  无效输入，使用默认值 {default}")
        return default


def _input_bool(prompt: str, default: bool = True) -> bool:
    """Read a y/n answer from stdin."""
    raw = input(prompt).strip().lower()
    if not raw:
        return default
    return raw in ('y', 'yes', '是')


async def ensure_users_exist(session: AsyncSession, interactive: bool) -> bool:
    """If USER_UUIDS is empty, ask the user whether to generate users first.

    Returns True if users are available afterward.
    """
    global USER_UUIDS
    if USER_UUIDS:
        return True

    if interactive:
        print("\n⚠️  当前没有用户数据，其他表的生成需要用户的外键引用。")
        if not _input_bool("是否先插入一些用户？(y/n) [y]: ", True):
            print("  已跳过用户生成，后续表将使用随机 UUID（可能违反外键约束）")
            return False

    from tools.seed_data import users  # late import to avoid circular deps at module level
    await users.generate(session, interactive=interactive)
    return bool(USER_UUIDS)


async def load_existing_users(session: AsyncSession, limit: int = 500) -> None:
    """Load existing user UUIDs from DB into USER_UUIDS list."""
    global USER_UUIDS
    if USER_UUIDS:
        return
    result = await session.execute(text("SELECT uuid FROM users LIMIT :lim"), {"lim": limit})
    rows = result.fetchall()
    USER_UUIDS.extend(str(row[0]) for row in rows)
