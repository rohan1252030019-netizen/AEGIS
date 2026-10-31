"""Shared slowapi key function.

slowapi's stock ``get_remote_address`` uses the raw socket peer. Behind the
Render/Docker/Cloudflare proxies that peer is always a private proxy address,
so every visitor shares one rate-limit bucket (and X-Forwarded-For spoofing is
not handled). Reuse the same trusted-proxy-aware resolver as the WAF/DoS
middlewares so all limits converge on the real client IP.
"""

from __future__ import annotations

import logging

from slowapi.util import get_remote_address

logger = logging.getLogger("aegis.ratelimit")


def client_ip_key(request) -> str:
    try:
        from app.core.dos_middleware import _client_ip

        return _client_ip(request)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("trusted client-ip resolution failed: %s", exc)
        try:
            return get_remote_address(request)
        except Exception:
            return "unknown"
