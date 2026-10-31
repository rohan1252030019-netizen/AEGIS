"""Unit tests for outbound URL validation (SSRF defence)."""

from __future__ import annotations

import pytest

from app.core.ssrf import UnsafeOutboundURL, validate_outbound_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost:8000/",
        "http://[::1]/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://100.64.0.1/",  # CGNAT / Tailscale
        "http://0.0.0.0/",
        "file:///etc/passwd",
        "ftp://example.com/",
    ],
)
def test_internal_and_non_http_targets_are_rejected(url):
    with pytest.raises(UnsafeOutboundURL):
        validate_outbound_url(url)


def test_public_literal_ip_is_allowed():
    # Literal IP: no DNS lookup needed, so the test stays offline.
    assert validate_outbound_url("https://93.184.216.34/hook") == "https://93.184.216.34/hook"


def test_allow_private_escape_hatch():
    assert (
        validate_outbound_url("http://127.0.0.1:9000/", allow_private=True)
        == "http://127.0.0.1:9000/"
    )
