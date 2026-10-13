"""Global test fixtures and helpers for AEGIS backend tests."""
from __future__ import annotations

import asyncio
from typing import AsyncGenerator
from unittest.mock import MagicMock
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

import app.database as db_mod
from app.config import settings
from app.main import app
from app.models.client import Client
from app.core.auth import get_auth_context, AuthContext

# Reconfigure database engine to NullPool during tests to avoid cross-loop pooled connection issues
db_mod.engine = create_async_engine(
    settings.DATABASE_URL,
    poolclass=NullPool,
)
db_mod.async_session = async_sessionmaker(
    db_mod.engine, class_=AsyncSession, expire_on_commit=False
)


def api_key_headers(client_or_key: str | Client | MagicMock) -> dict[str, str]:
    """Return headers with X-API-Key for the provided client or key string."""
    if isinstance(client_or_key, str):
        key = client_or_key
    elif hasattr(client_or_key, "api_key"):
        key = client_or_key.api_key
    else:
        key = "test-api-key"
    return {"X-API-Key": key, "Content-Type": "application/json"}


def jwt_headers(token: str) -> dict[str, str]:
    """Return headers with Bearer token."""
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture
def test_client_a() -> Client:
    """Mock/dummy tenant Client A."""
    c = Client(
        id="client-test-a",
        name="Test Tenant A",
        slug="tenant-a",
        api_key="aegis_test_key_a",
    )
    return c


@pytest.fixture
def test_client_b() -> Client:
    """Mock/dummy tenant Client B."""
    c = Client(
        id="client-test-b",
        name="Test Tenant B",
        slug="tenant-b",
        api_key="aegis_test_key_b",
    )
    return c


@pytest.fixture
async def client(test_client_a: Client) -> AsyncGenerator[AsyncClient, None]:
    """Async test client bound to ASGI app with default auth context override."""
    transport = ASGITransport(app=app)
    
    # Override auth context by default to resolve test_client_a
    async def override_auth_context():
        return AuthContext(
            client=test_client_a,
            user=None,
            role="admin",
            user_id="test-user-admin",
            email="admin@test.local",
        )
    
    app.dependency_overrides[get_auth_context] = override_auth_context
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
    app.dependency_overrides.pop(get_auth_context, None)
