"""ASGI middleware that keeps the public demo read-only.

Registered by ``app.main`` just inside CORS so 403 responses still carry CORS
headers (otherwise the browser would surface a misleading network error).
"""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.demo import (
    is_demo_request_identity,
    is_write_allowed_for_demo,
    sandbox_enabled,
    sandbox_response_body,
)

logger = logging.getLogger("aegis.demo.sandbox")


class DemoSandboxMiddleware(BaseHTTPMiddleware):
    """Reject state-changing requests made with the public demo credentials."""

    async def dispatch(self, request, call_next):
        if not sandbox_enabled():
            return await call_next(request)

        api_key = request.headers.get("x-api-key")
        authorization = request.headers.get("authorization", "")
        bearer = None
        if authorization.lower().startswith("bearer "):
            bearer = authorization[7:].strip()

        if not is_demo_request_identity(api_key, bearer):
            return await call_next(request)

        if is_write_allowed_for_demo(request.url.path, request.method):
            return await call_next(request)

        logger.info(
            "Demo sandbox blocked %s %s", request.method, request.url.path
        )
        return JSONResponse(
            status_code=403,
            content=sandbox_response_body(request.url.path),
        )
