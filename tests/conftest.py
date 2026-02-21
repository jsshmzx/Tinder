"""Shared fixtures for the test suite."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def test_app() -> FastAPI:
    """A minimal FastAPI app with only the index router registered (no lifespan)."""
    from modules.index.index import app as index_router

    app = FastAPI()
    app.include_router(index_router)
    return app


@pytest.fixture
def client(test_app: FastAPI) -> TestClient:
    """A synchronous TestClient wrapping the minimal test app."""
    return TestClient(test_app)
