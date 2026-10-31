"""Global test fixtures and helpers for AEGIS backend tests.

The suite runs against a real database (MySQL in development). Tests commit
rows, so every tenant fixture gets a random id/slug/api-key: otherwise rows
left behind by one test leak into the next one (for example an "empty list"
assertion seeing incidents created by an earlier campaign test).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from types import SimpleNamespace
from typing import AsyncGenerator
from unittest.mock import MagicMock

import pytest
from fastapi import Request
from httpx import AsyncClient, ASGITransport
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

import app.database as db_mod
from app.config import settings
from app.main import app
from app.models.action import Action
from app.models.client import Client
from app.models.incident import Incident
from app.models.user import User, UserRole
from app.core.auth import (
    AuthContext,
    create_user_jwt_token,
    decode_jwt_token,
    get_auth_context,
)

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


def jwt_headers(
    principal: str | User | SimpleNamespace,
    client: Client | None = None,
) -> dict[str, str]:
    """Return Bearer headers for a token string or a User-like principal.

    Passing a ``User`` builds a real, signed user JWT so the test client's
    auth override can exercise role checks (admin vs viewer) instead of
    silently treating every request as an admin.
    """
    if isinstance(principal, str):
        token = principal
    else:
        role = getattr(principal, "role", "admin")
        role = getattr(role, "value", role)
        token = create_user_jwt_token(
            user_id=getattr(principal, "id", None) or "test-user",
            email=getattr(principal, "email", None) or "user@test.local",
            role=role,
            client_id=(
                getattr(client, "id", None)
                or getattr(principal, "client_id", None)
            ),
        )
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _make_client(label: str) -> Client:
    suffix = uuid.uuid4().hex
    return Client(
        id=str(uuid.uuid4()),
        name=f"Test Tenant {label} {suffix[:8]}",
        slug=f"tenant-{label}-{suffix}",
        api_key=f"aegis_test_{label}_{suffix}",
        # A realistic per-tenant policy: block_ip auto-approves, destructive
        # actions never do. Tests that assert defaults rely on this shape.
        guardrails={
            "block_ip": "auto_approve",
            "isolate_host": "require_approval",
            "shutdown_service": "never_auto",
        },
    )


@pytest.fixture
def test_client_a() -> Client:
    """Mock/dummy tenant Client A with a unique id per test."""
    return _make_client("a")


@pytest.fixture
def test_client_b() -> Client:
    """Mock/dummy tenant Client B with a unique id per test."""
    return _make_client("b")


@pytest.fixture
def demo_client() -> Client:
    """A disposable tenant used by retention/global maintenance tests."""
    return _make_client("demo")


@pytest.fixture
async def db_session(
    test_client_a: Client,
    test_client_b: Client,
    demo_client: Client,
) -> AsyncGenerator[AsyncSession, None]:
    """Async DB session for tests that seed rows.

    Persists the in-memory tenant fixtures first: several models declare a
    foreign key to ``clients.id``, so seeding incidents without those rows
    fails on databases that enforce constraints (MySQL/Postgres).
    """
    async with db_mod.async_session() as session:
        for tenant in (test_client_a, test_client_b, demo_client):
            if await session.get(Client, tenant.id) is None:
                session.add(tenant)
        await session.commit()
        try:
            yield session
        finally:
            await session.rollback()


@pytest.fixture
async def sample_incident_a(
    db_session: AsyncSession, test_client_a: Client
) -> Incident:
    """An open high-severity incident owned by tenant A."""
    incident = Incident(
        id=str(uuid.uuid4()),
        client_id=test_client_a.id,
        title="SSH Brute Force from 45.33.32.156",
        description="Repeated failed SSH logins from a single source.",
        severity="high",
        status="open",
        source="log_watcher",
        source_ip="45.33.32.156",
        mitre_technique="T1110.001",
        mitre_tactic="Credential Access",
        detected_at=datetime.utcnow(),
    )
    db_session.add(incident)
    await db_session.commit()
    await db_session.refresh(incident)
    return incident


@pytest.fixture
async def sample_action_a(
    db_session: AsyncSession,
    test_client_a: Client,
    sample_incident_a: Incident,
) -> Action:
    """A pending, approval-gated block_ip action owned by tenant A."""
    action = Action(
        id=str(uuid.uuid4()),
        incident_id=sample_incident_a.id,
        client_id=test_client_a.id,
        action_type="block_ip",
        target=sample_incident_a.source_ip,
        parameters={},
        status="pending",
        requires_approval=True,
        ai_reasoning="Repeated SSH authentication failures",
    )
    db_session.add(action)
    await db_session.commit()
    await db_session.refresh(action)
    return action


@pytest.fixture
def admin_user_a(test_client_a: Client) -> User:
    """Admin principal for tenant A (JWT-addressable, not persisted)."""
    return User(
        id=str(uuid.uuid4()),
        email=f"admin-{uuid.uuid4().hex[:8]}@test.local",
        name="Tenant A Admin",
        password_hash="not-a-real-hash",
        role=UserRole.admin,
        client_id=test_client_a.id,
        is_active=True,
    )


@pytest.fixture
def viewer_user_a(test_client_a: Client) -> User:
    """Read-only principal for tenant A (JWT-addressable, not persisted)."""
    return User(
        id=str(uuid.uuid4()),
        email=f"viewer-{uuid.uuid4().hex[:8]}@test.local",
        name="Tenant A Viewer",
        password_hash="not-a-real-hash",
        role=UserRole.viewer,
        client_id=test_client_a.id,
        is_active=True,
    )


@pytest.fixture
async def unauth_client() -> AsyncGenerator[AsyncClient, None]:
    """Async test client WITHOUT the default auth override.

    Use for authentication/authorization tests that must observe the real
    401/403 behaviour instead of the admin override used by ``client``.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
async def client(
    test_client_a: Client,
    test_client_b: Client,
    admin_user_a: User,
) -> AsyncGenerator[AsyncClient, None]:
    """Async test client bound to the ASGI app.

    Defaults to tenant A as an admin (the historical behaviour), but honours
    Bearer JWTs: a viewer token yields a viewer AuthContext so role-gating
    tests are meaningful. X-API-Key selects tenant A or B; any other value
    still resolves to tenant A so callers that send a placeholder key keep
    working.
    """
    transport = ASGITransport(app=app)

    async def override_auth_context(request: Request) -> AuthContext:
        bearer = request.headers.get("authorization", "")
        if bearer.lower().startswith("bearer "):
            payload = decode_jwt_token(bearer.split(None, 1)[1])
            token_client = payload.get("client_id")
            resolved_client = (
                test_client_b if token_client == test_client_b.id else test_client_a
            )
            role = payload.get("role", "viewer")
            return AuthContext(
                client=resolved_client,
                user=SimpleNamespace(
                    id=payload.get("sub"),
                    email=payload.get("email"),
                    role=role,
                ),
                role=role,
                user_id=payload.get("sub"),
                email=payload.get("email"),
            )

        api_key = request.headers.get("x-api-key")
        resolved_client = (
            test_client_b if api_key == test_client_b.api_key else test_client_a
        )
        return AuthContext(
            client=resolved_client,
            user=None,
            role="admin",
            user_id=admin_user_a.id,
            email=admin_user_a.email,
        )

    app.dependency_overrides[get_auth_context] = override_auth_context
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
    app.dependency_overrides.pop(get_auth_context, None)
