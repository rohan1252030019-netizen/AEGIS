"""Unit tests for the public-demo identity + read-only sandbox."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.config import settings
from app.core import demo
from app.core.demo_sandbox import DemoSandboxMiddleware


PUBLISHED = "c6_vOoMiwHmU50GfuPUMp5G2doB0eXZaslXfpSAof7tBgQ"


@pytest.fixture(autouse=True)
def reset_demo_state():
    """Keep the process-global demo identity isolated per test."""
    demo.configure_demo_identity(None, None, published_key=False)
    yield
    demo.configure_demo_identity(None, None, published_key=False)


def test_read_only_methods_always_allowed():
    assert demo.is_write_allowed_for_demo("/api/v1/response/incidents", "GET")
    assert demo.is_write_allowed_for_demo("/api/v1/settings", "HEAD")
    assert demo.is_write_allowed_for_demo("/api/v1/anything", "OPTIONS")


def test_login_and_ask_are_the_only_write_allowlist():
    assert demo.is_write_allowed_for_demo("/api/v1/auth/login", "POST")
    assert demo.is_write_allowed_for_demo("/api/v1/auth/user/login", "POST")
    assert demo.is_write_allowed_for_demo("/api/v1/ask", "POST")
    assert demo.is_write_allowed_for_demo("/ask", "POST")
    # A path that merely shares the allowlisted prefix is not allowlisted.
    assert not demo.is_write_allowed_for_demo("/api/v1/ask/../response/incidents", "POST")
    assert not demo.is_write_allowed_for_demo("/api/v1/auth/change-password", "POST")


def test_destructive_writes_blocked():
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert not demo.is_write_allowed_for_demo(
            "/api/v1/response/incidents/abc/approve", method
        )
        assert not demo.is_write_allowed_for_demo("/api/v1/edr/kill-process", method)
        assert not demo.is_write_allowed_for_demo("/api/v1/setup/discover", method)


def test_published_key_is_recognised_without_demo_mode(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", False)
    monkeypatch.setattr(settings, "AEGIS_PUBLIC_DEMO_API_KEY", PUBLISHED)
    assert demo.is_public_demo_key(PUBLISHED) is True
    assert demo.is_public_demo_key("not-the-demo-key") is False
    assert demo.is_public_demo_key(None) is False


def test_demo_tenant_requires_an_active_demo_identity(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", False)
    demo.configure_demo_identity("tenant-1", published_key=False)
    # A plain self-host seeds a demo tenant with a random key: no sandbox.
    assert demo.demo_identity_active() is False
    assert demo.is_demo_tenant("tenant-1") is False
    assert demo.is_demo_client("tenant-1") is False

    # The published key (or explicit demo mode) activates the sandbox.
    demo.configure_demo_identity("tenant-1", published_key=True)
    assert demo.demo_identity_active() is True
    assert demo.is_demo_tenant("tenant-1") is True
    assert demo.is_demo_client("tenant-1") is True
    assert demo.is_demo_tenant("tenant-2") is False


def test_responder_guard_ignores_the_http_sandbox_switch(monkeypatch):
    """Even with AEGIS_DEMO_SANDBOX=false, the responder must not act."""
    monkeypatch.setattr(settings, "AEGIS_DEMO_SANDBOX", False)
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", True)
    demo.configure_demo_identity("tenant-1")

    assert demo.is_demo_client("tenant-1") is False  # HTTP sandbox opted out
    assert demo.is_demo_tenant("tenant-1") is True  # execution still simulated


def test_demo_token_identification(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", True)
    demo.configure_demo_identity("tenant-1", admin_user_id="admin-1")

    assert demo.token_belongs_to_demo({"sub": "admin-1"})
    assert demo.token_belongs_to_demo({"sub": "someone", "type": "user", "client_id": "tenant-1"})
    assert not demo.token_belongs_to_demo({"sub": "someone", "type": "user", "client_id": "tenant-2"})


def _sandboxed_app() -> Starlette:
    async def ok(request):
        return JSONResponse({"ok": True})

    app = Starlette(
        routes=[
            Route("/read", ok, methods=["GET"]),
            Route("/write", ok, methods=["POST"]),
            Route("/api/v1/auth/login", ok, methods=["POST"]),
            Route("/api/v1/ask", ok, methods=["POST"]),
        ]
    )
    app.add_middleware(DemoSandboxMiddleware)
    return app


@pytest.mark.asyncio
async def test_middleware_blocks_demo_writes_but_allows_reads_and_login(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", True)
    monkeypatch.setattr(settings, "AEGIS_DEMO_SANDBOX", True)
    monkeypatch.setattr(settings, "AEGIS_PUBLIC_DEMO_API_KEY", PUBLISHED)
    demo.configure_demo_identity("tenant-1")

    transport = ASGITransport(app=_sandboxed_app())
    headers = {"X-API-Key": PUBLISHED}
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        assert (await http.get("/read", headers=headers)).status_code == 200
        assert (await http.post("/api/v1/auth/login", headers=headers)).status_code == 200
        assert (await http.post("/api/v1/ask", headers=headers)).status_code == 200

        blocked = await http.post("/write", headers=headers)
        assert blocked.status_code == 403
        assert blocked.json()["demo_mode"] is True

        # An unrelated key is not treated as the demo.
        assert (await http.post("/write", headers={"X-API-Key": "other"})).status_code == 200
