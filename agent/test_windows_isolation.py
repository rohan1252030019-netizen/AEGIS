"""
Unit tests for AEGIS Windows Host Network Isolation (FR-09).
Covers state machine, firewall rule construction, control plane preservation,
watchdog recovery lease, and safe idempotent restore.
Uses an injected mock command runner so tests execute safely on any platform without altering the host.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

from windows_isolation import IsolationState, IsolationStatus, WindowsHostIsolator


class MockFirewallRunner:
    """Mock runner tracking simulated netsh advfirewall rules."""

    def __init__(self):
        self.rules: dict[str, dict] = {}
        self.executed_commands: list[list[str]] = []

    def __call__(self, argv: list[str]) -> tuple[int, str, str]:
        self.executed_commands.append(argv)
        cmd_str = " ".join(argv)

        if "firewall add rule" in cmd_str:
            name = None
            action = "allow"
            for arg in argv:
                if arg.startswith("name="):
                    name = arg.split("=", 1)[1]
                elif arg.startswith("action="):
                    action = arg.split("=", 1)[1]
            if name:
                self.rules[name] = {"action": action, "argv": argv}
            return (0, "Ok.\n", "")

        elif "firewall delete rule" in cmd_str:
            name = None
            for arg in argv:
                if arg.startswith("name="):
                    name = arg.split("=", 1)[1]
            if name:
                self.rules.pop(name, None)
            return (0, "Deleted 1 rule(s).\n", "")

        elif "firewall show rule" in cmd_str:
            name = None
            for arg in argv:
                if arg.startswith("name="):
                    name = arg.split("=", 1)[1]
            if name and name in self.rules:
                return (0, f"Rule Name: {name}\nAction: {self.rules[name]['action']}\n", "")
            return (1, "No rules match criteria.\n", "")

        return (0, "", "")


@pytest.fixture
def temp_state_file(tmp_path: Path) -> Path:
    return tmp_path / "test_isolation_state.json"


@pytest.fixture
def mock_runner() -> MockFirewallRunner:
    return MockFirewallRunner()


@pytest.fixture
def isolator(temp_state_file: Path, mock_runner: MockFirewallRunner) -> WindowsHostIsolator:
    return WindowsHostIsolator(state_file=temp_state_file, command_runner=mock_runner)


class TestWindowsHostIsolation:
    def test_initial_state_is_normal(self, isolator: WindowsHostIsolator):
        assert isolator.status.state == IsolationState.NORMAL
        assert isolator.status.rules_applied == []

    def test_isolation_flow_and_rules_applied(
        self, isolator: WindowsHostIsolator, mock_runner: MockFirewallRunner
    ):
        status = isolator.isolate(
            server_target="http://192.168.1.100:8000/api/v1",
            initiator="analyst_alice",
            reason="Lateral movement detected",
            lease_seconds=600,
        )

        assert status.state == IsolationState.ISOLATED
        assert status.isolated_by == "analyst_alice"
        assert status.reason == "Lateral movement detected"
        assert "192.168.1.100" in status.server_ip
        assert status.lease_expires_at is not None

        # Verify dedicated rules were applied in mock firewall
        assert WindowsHostIsolator.RULE_BLOCK_IN in mock_runner.rules
        assert WindowsHostIsolator.RULE_BLOCK_OUT in mock_runner.rules
        assert WindowsHostIsolator.RULE_ALLOW_AEGIS_IN in mock_runner.rules
        assert WindowsHostIsolator.RULE_ALLOW_AEGIS_OUT in mock_runner.rules
        assert WindowsHostIsolator.RULE_ALLOW_DNS_OUT in mock_runner.rules
        assert WindowsHostIsolator.RULE_ALLOW_DHCP_OUT in mock_runner.rules

        # Ensure AEGIS server IP is preserved in rule
        aegis_out_rule = mock_runner.rules[WindowsHostIsolator.RULE_ALLOW_AEGIS_OUT]["argv"]
        assert any("remoteip=" in arg and "192.168.1.100" in arg for arg in aegis_out_rule)

    def test_isolation_idempotency(self, isolator: WindowsHostIsolator):
        # First call isolates
        s1 = isolator.isolate("http://192.168.1.100:8000")
        assert s1.state == IsolationState.ISOLATED

        # Second call re-applies safely without crash or duplicate errors
        s2 = isolator.isolate("http://192.168.1.100:8000")
        assert s2.state == IsolationState.ISOLATED

    def test_restoration_clears_only_aegis_rules(
        self, isolator: WindowsHostIsolator, mock_runner: MockFirewallRunner
    ):
        # Add unrelated pre-existing user rule to mock firewall
        mock_runner.rules["USER-CUSTOM-RULE"] = {"action": "allow", "argv": []}

        isolator.isolate("http://192.168.1.100:8000")
        assert WindowsHostIsolator.RULE_BLOCK_OUT in mock_runner.rules

        # Restore
        status = isolator.restore(initiator="analyst_alice", reason="Contained")
        assert status.state == IsolationState.NORMAL
        assert status.rules_applied == []

        # All AEGIS rules removed
        for r_name in list(mock_runner.rules.keys()):
            assert not r_name.startswith(WindowsHostIsolator.RULE_PREFIX)

        # Unrelated user rule must NOT be touched!
        assert "USER-CUSTOM-RULE" in mock_runner.rules

    def test_watchdog_auto_recovery_on_lease_expiry(
        self, isolator: WindowsHostIsolator, mock_runner: MockFirewallRunner
    ):
        # Isolate host with 1 second lease
        isolator.isolate("http://192.168.1.100:8000", lease_seconds=1)
        assert isolator.status.state == IsolationState.ISOLATED

        # Backdate the lease expiry timestamp
        past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        isolator.status.lease_expires_at = past_time.isoformat()
        isolator._save_state()

        # Watchdog check should auto-restore host
        expired = isolator.check_watchdog_lease()
        assert expired is True
        assert isolator.status.state == IsolationState.NORMAL
        assert WindowsHostIsolator.RULE_BLOCK_OUT not in mock_runner.rules

    def test_lease_renewal(self, isolator: WindowsHostIsolator):
        isolator.isolate("http://192.168.1.100:8000", lease_seconds=300)
        old_expiry = isolator.status.lease_expires_at

        isolator.renew_lease(additional_seconds=1800)
        new_expiry = isolator.status.lease_expires_at

        assert new_expiry > old_expiry

    def test_state_reconstruction_across_restarts(
        self, temp_state_file: Path, mock_runner: MockFirewallRunner
    ):
        isolator1 = WindowsHostIsolator(state_file=temp_state_file, command_runner=mock_runner)
        isolator1.isolate("http://192.168.1.100:8000", lease_seconds=3600)
        assert isolator1.status.state == IsolationState.ISOLATED

        # Create new isolator instance reading the same file (simulating agent restart)
        isolator2 = WindowsHostIsolator(state_file=temp_state_file, command_runner=mock_runner)
        assert isolator2.status.state == IsolationState.ISOLATED
        assert isolator2.status.lease_expires_at == isolator1.status.lease_expires_at
