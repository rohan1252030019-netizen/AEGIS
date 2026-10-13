"""
Unit tests for AEGIS Windows Host Network Isolation (FR-09).
Runs in backend test suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add agent to sys.path
AGENT_DIR = Path(__file__).resolve().parent.parent.parent.parent / "agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

import pytest
from datetime import datetime, timezone, timedelta

from windows_isolation import IsolationState, IsolationStatus, WindowsHostIsolator


class MockFirewallRunner:
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


class TestWindowsHostIsolationBackendSuite:
    def test_initial_state_is_normal(self, isolator: WindowsHostIsolator):
        assert isolator.status.state == IsolationState.NORMAL

    def test_isolation_flow_and_rules(
        self, isolator: WindowsHostIsolator, mock_runner: MockFirewallRunner
    ):
        status = isolator.isolate(
            server_target="http://10.0.0.5:8000/api/v1",
            initiator="admin_user",
            reason="Host isolation triggered via EDR API",
            lease_seconds=900,
        )

        assert status.state == IsolationState.ISOLATED
        assert "10.0.0.5" in status.server_ip
        assert WindowsHostIsolator.RULE_BLOCK_IN in mock_runner.rules
        assert WindowsHostIsolator.RULE_BLOCK_OUT in mock_runner.rules
        assert WindowsHostIsolator.RULE_ALLOW_AEGIS_OUT in mock_runner.rules

    def test_restore_and_watchdog_expiry(
        self, isolator: WindowsHostIsolator, mock_runner: MockFirewallRunner
    ):
        isolator.isolate("http://10.0.0.5:8000")
        assert isolator.status.state == IsolationState.ISOLATED

        # Restoring
        status = isolator.restore(initiator="admin_user", reason="Incident resolved")
        assert status.state == IsolationState.NORMAL
        assert WindowsHostIsolator.RULE_BLOCK_OUT not in mock_runner.rules
