"""Tests for log_watcher incident dedup + Tor escalation (v1.6.2).

Single-event pattern matching moved to ``correlation_engine``; the watcher's
remaining incident-creation path is the inline behavioural detector, which
calls ``_create_incident_from_log``. These tests exercise that method's
cooldown directly so they do not depend on event-bus wiring.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.log_watcher import LogWatcher


@pytest.fixture
def incident_sink(monkeypatch):
    """Capture incident creation without touching the database or AI engine."""
    client = SimpleNamespace(id="test-client")
    db = AsyncMock()
    db.get = AsyncMock(return_value=client)

    class _SessionCtx:
        async def __aenter__(self):
            return db

        async def __aexit__(self, *exc_info):
            return False

    monkeypatch.setattr("app.database.async_session", lambda: _SessionCtx())
    sink = AsyncMock(return_value=None)
    monkeypatch.setattr("app.services.ai_engine.ai_engine.process_alert", sink)
    monkeypatch.setattr(
        "app.services.notifier.notifier.notify_critical_event",
        AsyncMock(return_value=None),
    )
    monkeypatch.setenv("AEGIS_CLIENT_ID", client.id)
    monkeypatch.setattr("app.services.ip_intel._load_tor_exits", lambda: set())
    return sink


async def _log_incident(
    watcher: LogWatcher,
    source_ip: str,
    description: str = "Pattern 'scanner_detect' detected",
) -> None:
    await watcher._create_incident_from_log(
        line=f'2026-06-23: [HTTP] GET /?u=UNION 200 {source_ip} "sqlmap"',
        pattern_name="scanner_detect",
        threat_type="reconnaissance",
        severity="low",
        source_ip=source_ip,
        description=description,
    )


@pytest.mark.asyncio
async def test_identical_attacks_collapse_to_one_incident(incident_sink):
    """5 identical scanner_detect events from one IP must produce 1 incident."""
    lw = LogWatcher()
    for _ in range(5):
        await _log_incident(lw, "45.155.205.233")
    assert incident_sink.call_count == 1, (
        f"Expected 1 incident from 5 identical events, got "
        f"{incident_sink.call_count}"
    )


@pytest.mark.asyncio
async def test_url_variation_does_not_create_new_incident(incident_sink):
    """Same IP + same threat_type, different URL query strings → 1 incident."""
    lw = LogWatcher()
    for i in range(10):
        await _log_incident(
            lw,
            "45.155.205.233",
            description=f"Pattern 'scanner_detect' detected on /search?q=UNION+SELECT+{i}",
        )
    assert incident_sink.call_count == 1


@pytest.mark.asyncio
async def test_different_ips_still_create_separate_incidents(incident_sink):
    """Different source IPs with same threat_type MUST still create incidents."""
    lw = LogWatcher()
    await _log_incident(lw, "45.155.205.233")
    await _log_incident(lw, "45.155.205.234")
    assert incident_sink.call_count == 2


@pytest.mark.asyncio
async def test_tor_exit_ip_marked_in_description(incident_sink, monkeypatch):
    """Scanner_detect from a known Tor exit IP should annotate description."""
    monkeypatch.setattr(
        "app.services.ip_intel._load_tor_exits",
        lambda: {"185.220.101.42"},
    )
    block = MagicMock()
    monkeypatch.setattr("app.core.ip_blocker.ip_blocker_service.block_ip", block)

    lw = LogWatcher()
    await _log_incident(lw, "185.220.101.42")

    assert incident_sink.call_count == 1
    alert_data = incident_sink.call_args.args[0]
    assert alert_data["description"].startswith("[Tor exit]")
    block.assert_called_once_with("185.220.101.42")
