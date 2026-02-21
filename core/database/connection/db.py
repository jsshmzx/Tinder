"""数据库 ORM 基础设施：声明式基类、Engine 与 Session 管理。

典型用法::

    from core.database.connection.db import get_session, dispose_engine

    with get_session() as session:
        session.add(obj)
"""

import os
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

__all__ = ["Base", "get_session", "dispose_engine"]

# ------------------------------------------------------------------
# 声明式基类（所有 ORM 模型均应继承此类）
# ------------------------------------------------------------------


class Base(DeclarativeBase):
    """所有 ORM 模型的声明式基类。"""


# ------------------------------------------------------------------
# Engine 与 Session 工厂（延迟初始化，避免导入时连接数据库）
# ------------------------------------------------------------------

_engine = None
_session_factory = None


def _get_engine():
    global _engine
    if _engine is None:
        url = os.environ.get("DATABASE_URL")
        if not url:
            raise EnvironmentError("环境变量 DATABASE_URL 未设置")
        # SQLAlchemy 2.x 需要 postgresql+psycopg2:// 协议前缀
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        _engine = create_engine(url, pool_pre_ping=True)
    return _engine


def _get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=_get_engine(), autocommit=False, autoflush=False
        )
    return _session_factory


def dispose_engine() -> None:
    """释放引擎，关闭连接池中的所有连接。在应用停止时调用。"""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _session_factory = None


@contextmanager
def get_session() -> Session:
    """上下文管理器，自动提交或回滚，并在退出时关闭 session。

    示例::

        with get_session() as session:
            session.add(some_object)
    """
    factory = _get_session_factory()
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
