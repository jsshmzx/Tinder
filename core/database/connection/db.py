"""数据库 ORM 基础设施：声明式基类、异步 Engine 与 Session 管理。

典型用法::

    from core.database.connection.db import get_session, dispose_engine

    async with get_session() as session:
        session.add(obj)
"""

import os
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

__all__ = ["Base", "get_session", "dispose_engine"]

# ------------------------------------------------------------------
# 声明式基类（所有 ORM 模型均应继承此类）
# ------------------------------------------------------------------


class Base(DeclarativeBase):
    """所有 ORM 模型的声明式基类。"""


# ------------------------------------------------------------------
# 异步 Engine 与 Session 工厂（延迟初始化，避免导入时连接数据库）
# ------------------------------------------------------------------

_engine = None
_session_factory = None


def _get_engine():
    global _engine
    if _engine is None:
        url = os.environ.get("DATABASE_URL")
        if not url:
            raise EnvironmentError("环境变量 DATABASE_URL 未设置")
        # 使用 asyncpg 异步驱动
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgresql+psycopg2://"):
            url = url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
        _engine = create_async_engine(url, pool_pre_ping=True)
    return _engine


def _get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=_get_engine(),
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )
    return _session_factory


async def dispose_engine() -> None:
    """释放引擎，关闭连接池中的所有连接。在应用停止时调用。"""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


@asynccontextmanager
async def get_session() -> AsyncSession:
    """异步上下文管理器，自动提交或回滚，并在退出时关闭 session。

    示例::

        async with get_session() as session:
            session.add(some_object)
    """
    factory = _get_session_factory()
    session: AsyncSession = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()
