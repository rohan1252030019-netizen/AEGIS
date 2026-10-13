"""
AEGIS EDR/MDR - Safe Windows Host Network Isolation (FR-09)
============================================================
Provides reliable, fail-safe network isolation of managed Windows endpoints.

Features:
  - Explicit State Machine: NORMAL -> ISOLATING -> ISOLATED -> RESTORING -> FAILED
  - Windows Defender Firewall dedicated rule group (prefixed with AEGIS-ISOLATE-)
  - Preserves AEGIS control-plane communication (server IP / port)
  - Preserves essential control protocols (DNS, DHCP, loopback) to prevent permanent loss of host
  - Default-deny policy applied to all other incoming and outgoing traffic
  - Watchdog recovery lease (auto-recovery upon expiration to prevent operator lockout)
  - Strictly idempotent: only AEGIS-owned firewall rules are ever added or removed
  - Never touches, flushes, or modifies pre-existing user or system firewall policies
  - Persistent state and lease file for survival / recovery across agent restarts
  - Pluggable command runner for unit testing and CI on non-Windows platforms
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import re
import socket
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("aegis.agent.isolation")

# ---------------------------------------------------------------------------
# State Machine Enum & Data Models
# ---------------------------------------------------------------------------

class IsolationState:
    NORMAL = "NORMAL"
    ISOLATING = "ISOLATING"
    ISOLATED = "ISOLATED"
    RESTORING = "RESTORING"
    FAILED = "FAILED"


@dataclass
class IsolationStatus:
    state: str = IsolationState.NORMAL
    isolated_at: Optional[str] = None
    isolated_by: Optional[str] = None
    reason: Optional[str] = None
    server_ip: Optional[str] = None
    lease_expires_at: Optional[str] = None
    lease_seconds: int = 900  # default 15 minutes
    error_message: Optional[str] = None
    rules_applied: list[str] = field(default_factory=list)
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Host Isolation Engine
# ---------------------------------------------------------------------------

class WindowsHostIsolator:
    """Manages host network isolation via Windows Defender Firewall."""

    RULE_PREFIX = "AEGIS-ISOLATE-"
    
    # Standard dedicated isolation rule names
    RULE_BLOCK_IN = f"{RULE_PREFIX}BLOCK-IN"
    RULE_BLOCK_OUT = f"{RULE_PREFIX}BLOCK-OUT"
    RULE_ALLOW_AEGIS_IN = f"{RULE_PREFIX}ALLOW-AEGIS-IN"
    RULE_ALLOW_AEGIS_OUT = f"{RULE_PREFIX}ALLOW-AEGIS-OUT"
    RULE_ALLOW_DNS_OUT = f"{RULE_PREFIX}ALLOW-DNS-OUT"
    RULE_ALLOW_DHCP_OUT = f"{RULE_PREFIX}ALLOW-DHCP-OUT"
    RULE_ALLOW_LOOPBACK_IN = f"{RULE_PREFIX}ALLOW-LOOPBACK-IN"
    RULE_ALLOW_LOOPBACK_OUT = f"{RULE_PREFIX}ALLOW-LOOPBACK-OUT"

    def __init__(
        self,
        state_file: Optional[Path] = None,
        command_runner: Optional[Callable[[list[str]], tuple[int, str, str]]] = None,
    ):
        """
        state_file: Path to JSON state file for persistence across restarts
        command_runner: Callable for executing shell commands in tests (argv -> returncode, stdout, stderr)
        """
        self.state_file = state_file or (Path(__file__).resolve().parent / ".isolation_state.json")
        self._custom_runner = command_runner
        self._lock = threading.Lock()
        self.status = self._load_state()

        # Reconcile state on initialization (in case of crash during isolation)
        self._reconcile_on_startup()

    # -----------------------------------------------------------------------
    # State Persistence & Recovery
    # -----------------------------------------------------------------------

    def _load_state(self) -> IsolationStatus:
        """Load state from persistent file or return default NORMAL."""
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                return IsolationStatus(**data)
            except Exception as exc:
                logger.warning("Could not read isolation state file: %s", exc)
        return IsolationStatus()

    def _save_state(self):
        """Persist current isolation state to disk."""
        try:
            self.status.updated_at = datetime.now(timezone.utc).isoformat()
            self.state_file.write_text(json.dumps(self.status.to_dict(), indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to persist isolation state: %s", exc)

    def _reconcile_on_startup(self):
        """Verify rules and state when agent initializes."""
        if self.status.state == IsolationState.ISOLATED:
            # Check if lease expired while agent was offline
            if self._is_lease_expired():
                logger.warning("Isolation lease expired while offline! Initiating auto-recovery restore...")
                self.restore(initiator="watchdog_startup", reason="Lease expired while agent was offline")
            else:
                logger.info("Agent restarted while host is ISOLATED. Verifying firewall rules...")
                verified = self._verify_rules_applied()
                if not verified:
                    logger.warning("Firewall rules missing despite ISOLATED state; marking FAILED.")
                    self.status.state = IsolationState.FAILED
                    self.status.error_message = "Enforcement rules missing upon agent startup"
                    self._save_state()

    # -----------------------------------------------------------------------
    # Privileges & Execution
    # -----------------------------------------------------------------------

    def is_elevated(self) -> bool:
        """Check if current process has Administrator privileges."""
        if self._custom_runner is not None:
            return True  # Mock environment
        if platform.system() != "Windows":
            return False
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _run_cmd(self, argv: list[str]) -> tuple[int, str, str]:
        """Execute a command via argv list, never shell=True."""
        if self._custom_runner is not None:
            return self._custom_runner(argv)

        try:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=20, shell=False)
            return (res.returncode, res.stdout, res.stderr)
        except Exception as exc:
            return (-1, "", str(exc))

    # -----------------------------------------------------------------------
    # Server IP Resolution
    # -----------------------------------------------------------------------

    @staticmethod
    def resolve_server_ip(server_target: Optional[str] = None) -> list[str]:
        """
        Extract and resolve IP address(es) for AEGIS server.
        Handles full URLs (http://192.168.1.100:8000), hostnames, and IP literals.
        """
        if not server_target:
            return ["127.0.0.1"]

        # Parse URL if provided
        host = server_target
        if "://" in server_target:
            parsed = urlparse(server_target)
            host = parsed.hostname or host
        elif ":" in server_target and not server_target.startswith("["):
            host = server_target.split(":")[0]

        ips = set()
        # Clean IPv4 / IPv6 literals
        try:
            socket.inet_aton(host)
            ips.add(host)
            return list(ips)
        except OSError:
            pass

        try:
            # Resolve DNS
            addrinfo = socket.getaddrinfo(host, None)
            for item in addrinfo:
                ip = item[4][0]
                ips.add(ip)
        except Exception as exc:
            logger.warning("Could not resolve AEGIS server host '%s': %s", host, exc)

        if not ips:
            # Fallback to localhost if unresolvable
            ips.add("127.0.0.1")

        return list(ips)

    # -----------------------------------------------------------------------
    # Isolation Enforcement
    # -----------------------------------------------------------------------

    def isolate(
        self,
        server_target: str,
        initiator: str = "operator",
        reason: str = "Incident containment",
        lease_seconds: int = 900,
    ) -> IsolationStatus:
        """
        Isolate host network with control-plane preservation.
        Idempotent: safe to invoke repeatedly.
        """
        with self._lock:
            # Check elevation
            if not self.is_elevated():
                err = "Elevation required: Host isolation requires administrative privileges."
                logger.error(err)
                self.status.state = IsolationState.FAILED
                self.status.error_message = err
                self._save_state()
                return self.status

            self.status.state = IsolationState.ISOLATING
            self.status.isolated_by = initiator
            self.status.reason = reason
            self.status.lease_seconds = lease_seconds
            self._save_state()

            # Resolve server IP
            server_ips = self.resolve_server_ip(server_target)
            server_ip_str = ",".join(server_ips)
            self.status.server_ip = server_ip_str

            logger.info("Initiating isolation: allowing server IPs=%s, lease=%ds", server_ip_str, lease_seconds)

            # Step 1: Clean any existing AEGIS isolation rules first for idempotency
            self._remove_all_aegis_rules()

            # Step 2: Apply ALLOW rules for AEGIS control-plane, DNS, DHCP, loopback
            applied_rules = []

            # 2a: Allow loopback
            r_loop_in = self._add_rule(
                name=self.RULE_ALLOW_LOOPBACK_IN,
                dir="in", action="allow", remoteip="127.0.0.1",
            )
            r_loop_out = self._add_rule(
                name=self.RULE_ALLOW_LOOPBACK_OUT,
                dir="out", action="allow", remoteip="127.0.0.1",
            )
            applied_rules.extend([self.RULE_ALLOW_LOOPBACK_IN, self.RULE_ALLOW_LOOPBACK_OUT])

            # 2b: Allow AEGIS server control plane
            r_aegis_in = self._add_rule(
                name=self.RULE_ALLOW_AEGIS_IN,
                dir="in", action="allow", remoteip=server_ip_str,
            )
            r_aegis_out = self._add_rule(
                name=self.RULE_ALLOW_AEGIS_OUT,
                dir="out", action="allow", remoteip=server_ip_str,
            )
            applied_rules.extend([self.RULE_ALLOW_AEGIS_IN, self.RULE_ALLOW_AEGIS_OUT])

            # 2c: Allow DNS (UDP/TCP port 53)
            self._add_rule(
                name=self.RULE_ALLOW_DNS_OUT,
                dir="out", action="allow", protocol="UDP", remoteport="53",
            )
            self._add_rule(
                name=f"{self.RULE_ALLOW_DNS_OUT}-TCP",
                dir="out", action="allow", protocol="TCP", remoteport="53",
            )
            applied_rules.append(self.RULE_ALLOW_DNS_OUT)

            # 2d: Allow DHCP (UDP ports 67, 68) to retain IP address lease
            self._add_rule(
                name=self.RULE_ALLOW_DHCP_OUT,
                dir="out", action="allow", protocol="UDP", remoteport="67,68",
            )
            applied_rules.append(self.RULE_ALLOW_DHCP_OUT)

            # Step 3: Apply default-deny rules (Block ALL other in & out)
            r_block_in = self._add_rule(name=self.RULE_BLOCK_IN, dir="in", action="block")
            r_block_out = self._add_rule(name=self.RULE_BLOCK_OUT, dir="out", action="block")
            applied_rules.extend([self.RULE_BLOCK_IN, self.RULE_BLOCK_OUT])

            # Step 4: Verify rules applied successfully
            if not self._verify_rules_applied():
                logger.error("Isolation rule verification failed! Rolling back to avoid half-isolated state.")
                self._remove_all_aegis_rules()
                self.status.state = IsolationState.FAILED
                self.status.error_message = "Firewall rules could not be verified after application."
                self._save_state()
                return self.status

            # Step 5: Transition to ISOLATED
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(seconds=lease_seconds)
            self.status.state = IsolationState.ISOLATED
            self.status.isolated_at = now.isoformat()
            self.status.lease_expires_at = expires_at.isoformat()
            self.status.rules_applied = applied_rules
            self.status.error_message = None
            self._save_state()

            logger.info("Host successfully ISOLATED. Lease expires at %s", self.status.lease_expires_at)
            return self.status

    # -----------------------------------------------------------------------
    # Restoration
    # -----------------------------------------------------------------------

    def restore(
        self,
        initiator: str = "operator",
        reason: str = "Remediation complete",
    ) -> IsolationStatus:
        """
        Restore normal network connectivity by removing only AEGIS-owned isolation rules.
        Idempotent: safe to invoke when already normal.
        """
        with self._lock:
            if not self.is_elevated():
                err = "Elevation required: Restoring network requires administrative privileges."
                logger.error(err)
                self.status.state = IsolationState.FAILED
                self.status.error_message = err
                self._save_state()
                return self.status

            self.status.state = IsolationState.RESTORING
            self._save_state()
            logger.info("Restoring normal host network connectivity (initiator=%s, reason=%s)...", initiator, reason)

            # Remove all AEGIS isolation rules
            self._remove_all_aegis_rules()

            # Verify removal
            if self._verify_rules_applied():
                logger.error("Some AEGIS isolation rules still linger after deletion attempt.")
                self.status.state = IsolationState.FAILED
                self.status.error_message = "Isolation rules failed to clear during restore."
                self._save_state()
                return self.status

            # Transition to NORMAL
            self.status.state = IsolationState.NORMAL
            self.status.isolated_at = None
            self.status.lease_expires_at = None
            self.status.rules_applied = []
            self.status.error_message = None
            self._save_state()

            logger.info("Host network restored to NORMAL successfully.")
            return self.status

    # -----------------------------------------------------------------------
    # Watchdog Lease Management
    # -----------------------------------------------------------------------

    def renew_lease(self, additional_seconds: int = 900) -> IsolationStatus:
        """Renew active isolation lease."""
        with self._lock:
            if self.status.state != IsolationState.ISOLATED:
                return self.status

            now = datetime.now(timezone.utc)
            new_expiry = now + timedelta(seconds=additional_seconds)
            self.status.lease_expires_at = new_expiry.isoformat()
            self.status.lease_seconds = additional_seconds
            self._save_state()
            logger.info("Isolation lease renewed until %s", self.status.lease_expires_at)
            return self.status

    def _is_lease_expired(self) -> bool:
        """Check if lease has expired."""
        if not self.status.lease_expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.status.lease_expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) > exp
        except Exception:
            return False

    def check_watchdog_lease(self) -> bool:
        """
        Check lease; if expired, automatically restores host network.
        Returns True if lease was expired and recovery was triggered.
        """
        if self.status.state == IsolationState.ISOLATED and self._is_lease_expired():
            logger.warning("WATCHDOG: Isolation lease EXPIRED! Automatically restoring connectivity to prevent lockout...")
            self.restore(initiator="watchdog", reason="Isolation lease expired")
            return True
        return False

    # -----------------------------------------------------------------------
    # Firewall Rule Low-Level Primitives (netsh)
    # -----------------------------------------------------------------------

    def _add_rule(
        self,
        name: str,
        dir: str,
        action: str,
        remoteip: Optional[str] = None,
        protocol: Optional[str] = None,
        remoteport: Optional[str] = None,
    ) -> bool:
        """Add a Windows Defender Firewall rule via netsh advfirewall."""
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}",
            f"dir={dir}",
            f"action={action}",
            "enable=yes",
        ]
        if remoteip:
            cmd.append(f"remoteip={remoteip}")
        if protocol:
            cmd.append(f"protocol={protocol}")
        if remoteport:
            cmd.append(f"remoteport={remoteport}")

        code, out, err = self._run_cmd(cmd)
        if code != 0:
            logger.warning("netsh add rule '%s' failed (code %d): %s %s", name, code, out, err)
            return False
        return True

    def _remove_rule_by_name(self, name: str) -> bool:
        """Remove a specific firewall rule by name."""
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        code, out, err = self._run_cmd(cmd)
        return code == 0

    def _remove_all_aegis_rules(self):
        """Remove ONLY AEGIS-owned isolation rules. Never touches other rules."""
        known_rules = [
            self.RULE_BLOCK_IN,
            self.RULE_BLOCK_OUT,
            self.RULE_ALLOW_AEGIS_IN,
            self.RULE_ALLOW_AEGIS_OUT,
            self.RULE_ALLOW_DNS_OUT,
            f"{self.RULE_ALLOW_DNS_OUT}-TCP",
            self.RULE_ALLOW_DHCP_OUT,
            self.RULE_ALLOW_LOOPBACK_IN,
            self.RULE_ALLOW_LOOPBACK_OUT,
        ]
        for rule_name in known_rules:
            self._remove_rule_by_name(rule_name)

    def _verify_rules_applied(self) -> bool:
        """Verify that the default deny rules are active."""
        cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={self.RULE_BLOCK_OUT}"]
        code, out, err = self._run_cmd(cmd)
        return code == 0 and ("Block" in out or "block" in out.lower() or "AEGIS-ISOLATE" in out)
