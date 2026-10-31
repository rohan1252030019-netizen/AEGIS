"""Public-demo identity and sandbox.

The hosted AEGIS demo publishes one API key and one admin login on purpose so
that anybody can look around. Those credentials must never be able to change
host state, reach the network, or destroy data.

This module is the single source of truth for "is this request the public
demo?". It is deliberately dependency-light (config + JWT decode only) so the
ASGI middleware, the auth context and the responder can all use it without
circular imports.

Policy
------
* Read-only HTTP methods are always allowed.
* A small allow-list of write paths (login + AI chat) is allowed so the demo
  UI keeps working.
* Everything else that mutates state is rejected with HTTP 403 by
  :class:`app.core.demo_sandbox.DemoSandboxMiddleware`.
* Background responders additionally refuse to execute any action owned by
  the demo tenant (defence in depth: an event-driven auto-approval never
  passes through the middleware).
"""

from __future__ import annotations

import logging
import posixpath
import secrets
from typing import Any, Optional

from app.config import settings

logger = logging.getLogger("aegis.demo")

# The only write endpoints the public demo may call. Login keeps the demo
# reachable; /ask keeps the AI assistant usable. Everything else is read-only.
_DEMO_WRITE_ALLOWLIST: tuple[str, ...] = (
    "/api/v1/auth/login",
    "/api/v1/auth/user/login",
    "/api/v1/ask",
    "/ask",
)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_demo_client_id: Optional[str] = None
_demo_admin_user_id: Optional[str] = None
# True when the seeded demo tenant actually owns the published demo key. A
# fresh self-host also seeds a "demo" tenant, but with a random key — that
# deployment must NOT be sandboxed unless it opted into AEGIS_DEMO_MODE.
_demo_client_is_published = False


def configure_demo_identity(
    client_id: Optional[str],
    admin_user_id: Optional[str] = None,
    *,
    published_key: bool = False,
) -> None:
    """Record the seeded demo tenant / admin ids for this process.

    ``published_key`` must be True only when the seeded tenant's API key is
    the published demo key. It keeps first-boot self-hosted deployments out
    of the sandbox.
    """
    global _demo_client_id, _demo_admin_user_id, _demo_client_is_published
    _demo_client_id = client_id or None
    _demo_client_is_published = bool(published_key)
    if admin_user_id:
        _demo_admin_user_id = admin_user_id
    if _demo_client_id:
        logger.info(
            "Demo sandbox bound to client id %s (published=%s, demo_mode=%s)",
            _demo_client_id,
            _demo_client_is_published,
            bool(getattr(settings, "AEGIS_DEMO_MODE", False)),
        )


def demo_client_id() -> Optional[str]:
    return _demo_client_id


def demo_admin_user_id() -> Optional[str]:
    return _demo_admin_user_id


def sandbox_enabled() -> bool:
    """Demo guard is on by default; operators can opt out explicitly."""
    return bool(getattr(settings, "AEGIS_DEMO_SANDBOX", True))


def is_public_demo_key(api_key: Optional[str]) -> bool:
    """True when *api_key* is the published demo key.

    The key is compared against the configured value (which defaults to the
    well-known public key) in constant time. Keeping this check independent of
    ``AEGIS_DEMO_MODE`` means the published key is sandboxed even on a
    deployment that forgot to enable demo mode.
    """
    published = (getattr(settings, "AEGIS_PUBLIC_DEMO_API_KEY", "") or "").strip()
    if not published or not api_key:
        return False
    try:
        return secrets.compare_digest(str(api_key), published)
    except Exception:  # pragma: no cover - defensive
        return False


def demo_identity_active() -> bool:
    """Whether the seeded demo tenant should be sandboxed on this host.

    Two independent triggers:

    * ``AEGIS_DEMO_MODE=true`` — the deliberate public deployment; or
    * the seeded tenant really owns the published demo key.

    A first-boot self-host has neither, so its admin is never sandboxed.
    """
    return bool(getattr(settings, "AEGIS_DEMO_MODE", False) or _demo_client_is_published)


def is_demo_client(client_id: Optional[str]) -> bool:
    """True for the tenant that owns the public demo credentials.

    Honours the ``AEGIS_DEMO_SANDBOX`` switch so an operator can deliberately
    turn the HTTP sandbox off. The responder uses :func:`is_demo_tenant`
    instead, because executing an auto-approved action on the demo tenant must
    never touch the host even when the HTTP sandbox is disabled.
    """
    if not sandbox_enabled() or not is_demo_tenant(client_id):
        return False
    return True


def is_demo_tenant(client_id: Optional[str]) -> bool:
    """True when *client_id* is the public demo tenant on a demo host."""
    if not client_id or not demo_identity_active():
        return False
    return client_id == _demo_client_id


def is_demo_auth(auth: Any) -> bool:
    """True when an :class:`AuthContext` represents the public demo."""
    if auth is None:
        return False
    client = getattr(auth, "client", None)
    if client is None:
        return False
    if is_demo_client(getattr(client, "id", None)):
        return True
    # The published key remains sandboxed even if it was presented for a
    # tenant row that is not the one seeded at startup.
    return is_public_demo_key(getattr(client, "api_key", None))


def token_belongs_to_demo(payload: dict) -> bool:
    """True when a decoded JWT belongs to the demo tenant/admin."""
    if not sandbox_enabled() or not payload or not demo_identity_active():
        return False
    user_id = payload.get("sub")
    if _demo_admin_user_id and user_id == _demo_admin_user_id:
        return True
    if payload.get("type", "client") == "user":
        return is_demo_client(payload.get("client_id"))
    return is_demo_client(user_id)


def is_demo_request_identity(
    api_key: Optional[str],
    bearer_token: Optional[str],
) -> bool:
    """Identify a demo caller from raw request headers.

    API-key auth is matched against the published key. Bearer auth is decoded
    locally with the same secret used by the API. Any decode failure simply
    means "not the demo" — the normal auth layer will reject it.
    """
    if not sandbox_enabled():
        return False
    if is_public_demo_key(api_key):
        return True
    if bearer_token:
        try:
            from app.core.auth import decode_jwt_token

            payload = decode_jwt_token(bearer_token)
        except Exception:
            return False
        return token_belongs_to_demo(payload)
    return False


def _normalise_path(path: str) -> str:
    """Canonicalise a request path before allowlist comparison.

    Percent-decoding and collapsing ``.``/``..`` segments stops a caller from
    smuggling a destructive route past the prefix check as
    ``/api/v1/ask/../response/incidents`` (some proxies normalise that to the
    destructive route after this middleware has run).
    """
    from urllib.parse import unquote

    raw = unquote(path or "/").replace("\\", "/")
    normalised = posixpath.normpath("/" + raw.lstrip("/"))
    return normalised.rstrip("/") or "/"


def is_write_allowed_for_demo(path: str, method: str) -> bool:
    """Whether a demo caller may perform *method* on *path*."""
    if method.upper() in _SAFE_METHODS:
        return True
    normalised = _normalise_path(path)
    for allowed in _DEMO_WRITE_ALLOWLIST:
        allowed = allowed.rstrip("/")
        if normalised == allowed or normalised.startswith(allowed + "/"):
            return True
    return False


def sandbox_response_body(path: str) -> dict:
    return {
        "detail": (
            "This is a public read-only demo. Destructive actions are disabled; "
            "the dashboard, incidents, telemetry and AI assistant remain available."
        ),
        "demo_mode": True,
        "path": path,
    }
