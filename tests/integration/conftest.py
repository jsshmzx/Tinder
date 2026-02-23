"""Integration-test fixtures — requires real PostgreSQL and Redis.

Environment variables expected:
  DATABASE_URL  e.g. postgresql://postgres:password@localhost:5432/tinder_test
  REDIS_URL     e.g. redis://localhost:6379/0
"""

import os

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


# ---------------------------------------------------------------------------
# Database setup / teardown
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def db_engine():
    """Create a synchronous SQLAlchemy engine connected to the test database
    and ensure all ORM-declared tables exist. Drops all tables when the session ends."""
    url = os.environ["DATABASE_URL"]
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

    engine = create_engine(url, pool_pre_ping=True)

    # Import every ORM model so that Base.metadata is fully populated.
    import core.database.dao.illegal_requests  # noqa: F401
    import core.database.dao.request_logs  # noqa: F401
    import core.database.dao.tokens  # noqa: F401
    import core.database.dao.users  # noqa: F401

    from core.database.connection.db import Base

    Base.metadata.create_all(engine)

    yield engine

    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="session")
def db_session_factory(db_engine):
    return sessionmaker(bind=db_engine, autocommit=False, autoflush=False)


# ---------------------------------------------------------------------------
# Redis setup / teardown
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def redis_client():
    """Connect to Redis and flush the test database before/after the session."""
    import redis as redis_lib

    url = os.environ["REDIS_URL"]
    client = redis_lib.from_url(url, decode_responses=True)
    client.flushdb()
    yield client
    client.flushdb()
    client.close()


# ---------------------------------------------------------------------------
# Full application fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def integration_app(db_engine):
    """A full FastAPI application with FirewallMiddleware and the index router,
    backed by the real test database and Redis (via environment variables)."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    from core.database.connection import db as db_module
    from core.middleware.firewall.index import FirewallMiddleware
    from modules.index.index import app as index_router

    # Build an async engine pointing at the same test database.
    async_url = os.environ["DATABASE_URL"]
    if async_url.startswith("postgresql://"):
        async_url = async_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif async_url.startswith("postgresql+psycopg2://"):
        async_url = async_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)

    async_engine = create_async_engine(async_url, pool_pre_ping=True, poolclass=NullPool)
    db_module._engine = async_engine
    db_module._session_factory = async_sessionmaker(
        bind=async_engine, autocommit=False, autoflush=False, expire_on_commit=False
    )

    # Point redis_conn at the test Redis.
    from core.database.connection.redis import redis_conn
    import redis as redis_lib

    redis_conn._client = redis_lib.from_url(
        os.environ["REDIS_URL"], decode_responses=True
    )

    app = FastAPI()
    app.add_middleware(CORSMiddleware, allow_origins=["*"],
                       allow_credentials=True, allow_methods=["*"],
                       allow_headers=["*"])
    app.add_middleware(FirewallMiddleware)
    app.include_router(index_router)
    return app


@pytest.fixture(scope="session")
def integration_client(integration_app):
    return TestClient(integration_app, raise_server_exceptions=False)
