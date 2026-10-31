"""Outbound URL validation (SSRF defence).

Used wherever an operator-supplied URL is fetched by the backend (webhooks,
notification tests, threat-sharing node registration). Resolving the hostname
and rejecting private/loopback/link-local/reserved answers keeps the server
from being used as a proxy into its own network or a cloud metadata endpoint.

This is a point-in-time check; callers that need stronger guarantees should
re-validate after DNS resolution at connect time (httpx does not expose that
hook here). It is still a large improvement over accepting arbitrary URLs.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

_BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}


class UnsafeOutboundURL(ValueError):
    pass


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _is_forbidden_ip(ip: ipaddress._BaseAddress) -> bool:
    # ``is_private`` deliberately excludes shared address space (100.64/10),
    # which is what Tailscale and carrier NAT use. Those are still internal
    # network targets for SSRF purposes.
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_outbound_url(
    url: str,
    *,
    require_https: bool = False,
    allow_private: bool = False,
) -> str:
    """Validate *url* and return it unchanged.

    Raises:
        UnsafeOutboundURL: empty/malformed scheme, blocked hostname, or a
            hostname that resolves to a private/reserved address.
    """
    if not url or not url.strip():
        raise UnsafeOutboundURL("URL is empty")

    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise UnsafeOutboundURL("URL must use http:// or https://")
    if require_https and parsed.scheme != "https":
        raise UnsafeOutboundURL("URL must use https://")
    if not parsed.hostname:
        raise UnsafeOutboundURL("URL has no hostname")
    if parsed.username or parsed.password:
        raise UnsafeOutboundURL("URL must not embed credentials")

    host = parsed.hostname.lower().rstrip(".")
    if host in _BLOCKED_HOSTS:
        raise UnsafeOutboundURL("URL points at a blocked hostname")

    # Literal IPs are checked directly; hostnames are resolved and every
    # returned address must be public.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if not allow_private and _is_forbidden_ip(literal):
            raise UnsafeOutboundURL("URL points at a private/reserved address")
        return url

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeOutboundURL(f"Could not resolve host: {exc}") from exc

    if not infos:
        raise UnsafeOutboundURL("Could not resolve host")

    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not allow_private and _is_forbidden_ip(ip):
            raise UnsafeOutboundURL("URL resolves to a private/reserved address")

    return url
