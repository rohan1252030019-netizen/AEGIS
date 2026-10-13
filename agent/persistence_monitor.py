"""
AEGIS EDR/MDR - Windows Persistence Monitoring (FR-03)
======================================================
Monitors Windows Registry autorun keys and Scheduled Tasks for persistence mechanisms.

Capabilities:
  - Scans HKCU and HKLM Run and RunOnce keys with explicit 32-bit and 64-bit registry views
  - Additional startup persistence locations (RunServices, Winlogon)
  - Scheduled task extraction and inspection (actions, executables, arguments)
  - Explainable risk scoring (0-100) with risk factor indicators:
      * Script launchers & LOLBins (powershell, cmd, wscript, mshta, rundll32, etc.)
      * Writable / temporary execution paths (AppData, Temp, Public, ProgramData)
      * Encoded commands and stealth flags (-enc, -w hidden, -nop, bypass)
      * Remote download cradles (DownloadString, certutil -urlcache, bitsadmin)
      * Missing target executables on disk
      * Allowlisting for common benign Windows components
  - Baseline tracking and delta diffing (added, modified, removed)
  - Duplicate alert suppression across scan cycles
  - Pluggable registry and task adapters for 100% testability on non-Windows CI
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("aegis.agent.persistence")

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class PersistenceItem:
    location_type: str             # "registry" or "scheduled_task"
    location: str                  # Registry key or TaskPath
    name: str                      # Value name or TaskName
    command: str                   # Executable path and command-line arguments
    view: str = "native"           # "64bit", "32bit", or "native"
    author: Optional[str] = None
    state: Optional[str] = None
    risk_score: int = 0            # 0 to 100
    risk_factors: list[str] = field(default_factory=list)
    severity: str = "low"          # "low", "medium", "high", "critical"
    target_exists: Optional[bool] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def fingerprint(self) -> str:
        """Deterministic fingerprint for baseline comparison."""
        raw = f"{self.location_type}|{self.location}|{self.name}|{self.command}|{self.view}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Heuristics & Risk Scoring Engine
# ---------------------------------------------------------------------------

_SUSPICIOUS_LAUNCHERS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "bash.exe", "cscript", "wscript", "mshta", "rundll32", "regsvr32", "certutil",
}

_STEALTH_FLAGS = [
    r"-enc\b", r"-encodedcommand\b", r"-windowstyle\s+hidden\b", r"-w\s+hidden\b",
    r"-nop\b", r"-noprofile\b", r"-executionpolicy\s+bypass\b", r"-ep\s+bypass\b",
    r"/s\s+/n\s+/u\s+/i", r"javascript:", r"vbscript:",
]

_CRADLE_PATTERNS = [
    r"downloadstring\b", r"invoke-webrequest\b", r"\biwr\s+", r"\bcurl\s+",
    r"\bwget\s+", r"certutil(\.exe)?\s+.*-urlcache", r"bitsadmin(\.exe)?\s+.*\/transfer",
]

_SUSPICIOUS_PATH_PATTERNS = [
    r"\\appdata\\local\\temp\b",
    r"\\windows\\temp\b",
    r"\\users\\public\b",
    r"\\appdata\\roaming\b",
    r"\\appdata\\local\b",
    r"\\programdata\\[^\\]+\.exe$",  # direct executable in ProgramData root
]

# Standard benign software entries
_BENIGN_ALLOWLIST = {
    "securityhealthsystray.exe",
    "securityhealth",
    "onedrive.exe",
    "onedrive",
    "msedge.exe",
    "vmtoolsd.exe",
    "vmware-tray.exe",
    "vboxclient.exe",
}


def _extract_target_binary(command_line: str) -> Optional[str]:
    """Safely extract the executable path from a command line string."""
    clean = command_line.strip()
    if not clean:
        return None

    # Quoted path
    if clean.startswith('"'):
        end = clean.find('"', 1)
        if end != -1:
            return clean[1:end]

    # First token
    parts = clean.split()
    return parts[0] if parts else None


def evaluate_persistence_risk(
    command_line: str,
    location: str,
    name: str,
    check_file_exists: bool = True,
) -> tuple[int, list[str], str, Optional[bool]]:
    """
    Evaluate explainable risk score (0-100) and severity for a persistence entry.
    Returns: (risk_score, risk_factors, severity, target_exists)
    """
    factors: list[str] = []
    score = 20  # base score for autorun / persistence presence
    lower_cmd = command_line.lower().strip()
    lower_name = name.lower().strip()

    # Check allowlist
    target_binary = _extract_target_binary(command_line)
    target_exists: Optional[bool] = None

    if target_binary:
        bin_name = Path(target_binary).name.lower()
        if bin_name in _BENIGN_ALLOWLIST or lower_name in _BENIGN_ALLOWLIST:
            # Benign baseline
            return (10, ["benign_allowlisted"], "low", True)

        if check_file_exists and platform.system() == "Windows":
            try:
                target_exists = Path(target_binary).exists()
                if not target_exists and not any(l in bin_name for l in _SUSPICIOUS_LAUNCHERS):
                    factors.append("missing_target_file")
                    score += 20
            except Exception:
                pass

    # 1. Suspicious launcher check
    for launcher in _SUSPICIOUS_LAUNCHERS:
        if launcher in lower_cmd:
            factors.append(f"script_launcher_{launcher.replace('.exe', '')}")
            score += 35
            break

    # 2. Stealth / obfuscation flags
    for flag_pat in _STEALTH_FLAGS:
        if re.search(flag_pat, lower_cmd, re.IGNORECASE):
            factors.append("encoded_or_stealth_arguments")
            score += 40
            break

    # 3. Network download cradle
    for cradle_pat in _CRADLE_PATTERNS:
        if re.search(cradle_pat, lower_cmd, re.IGNORECASE):
            factors.append("network_download_cradle")
            score += 45
            break

    # 4. Writable / temporary execution path
    for path_pat in _SUSPICIOUS_PATH_PATTERNS:
        if re.search(path_pat, lower_cmd, re.IGNORECASE):
            factors.append("user_writable_or_temp_path")
            score += 35
            break

    # 5. Direct script files (.vbs, .js, .bat, .cmd, .ps1, .hta)
    if re.search(r"\.(vbs|js|hta|ps1|bat|cmd)($|\s)", lower_cmd, re.IGNORECASE):
        factors.append("script_file_execution")
        score += 25

    # Clamp score to 100
    score = min(score, 100)

    # Classify severity
    if score >= 75:
        severity = "critical" if ("encoded_or_stealth_arguments" in factors or "network_download_cradle" in factors) else "high"
    elif score >= 50:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    return (score, factors, severity, target_exists)


# ---------------------------------------------------------------------------
# Registry Persistence Scanner
# ---------------------------------------------------------------------------

class RegistryPersistenceScanner:
    """Scans Windows Registry for autorun persistence keys."""

    REGISTRY_TARGETS = [
        # (Hive name, Hive constant name, Subkey path, supported views)
        ("HKCU", "HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run", ["native"]),
        ("HKCU", "HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", ["native"]),
        ("HKCU", "HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\RunServices", ["native"]),
        ("HKLM", "HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\Run", ["64bit", "32bit"]),
        ("HKLM", "HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", ["64bit", "32bit"]),
        ("HKLM", "HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\RunServices", ["64bit", "32bit"]),
        ("HKLM", "HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", ["64bit", "32bit"]),
        ("HKLM", "HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", ["64bit", "32bit"]),
    ]

    def __init__(self, registry_reader: Optional[Callable] = None):
        """
        registry_reader: Optional pluggable reader for mocking in non-Windows CI.
        Signature: (hive_str, subkey, view_str) -> list[tuple[name, value]]
        """
        self._custom_reader = registry_reader

    def scan(self) -> list[PersistenceItem]:
        """Perform full scan of all monitored registry locations."""
        if self._custom_reader is not None:
            return self._scan_with_custom_reader()

        if platform.system() != "Windows":
            logger.debug("RegistryPersistenceScanner: Non-Windows platform without mock reader; skipping.")
            return []

        import winreg  # Windows only

        items: list[PersistenceItem] = []
        hive_map = {
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        }

        for hive_name, hive_const_name, subkey, views in self.REGISTRY_TARGETS:
            hive_handle = hive_map.get(hive_const_name)
            if hive_handle is None:
                continue

            for view in views:
                access = winreg.KEY_READ
                if view == "64bit":
                    access |= getattr(winreg, "KEY_WOW64_64KEY", 0)
                elif view == "32bit":
                    access |= getattr(winreg, "KEY_WOW64_32KEY", 0)

                try:
                    with winreg.OpenKey(hive_handle, subkey, 0, access) as key:
                        count = winreg.QueryInfoKey(key)[1]
                        for idx in range(count):
                            try:
                                name, value, val_type = winreg.EnumValue(key, idx)
                                if not isinstance(value, str):
                                    value = str(value)

                                # For Winlogon, only monitor Userinit and Shell
                                if "Winlogon" in subkey and name.lower() not in ("userinit", "shell"):
                                    continue

                                score, factors, severity, exists = evaluate_persistence_risk(
                                    value, f"{hive_name}\\{subkey}", name
                                )

                                items.append(PersistenceItem(
                                    location_type="registry",
                                    location=f"{hive_name}\\{subkey}",
                                    name=name,
                                    command=value,
                                    view=view,
                                    risk_score=score,
                                    risk_factors=factors,
                                    severity=severity,
                                    target_exists=exists,
                                ))
                            except (OSError, PermissionError):
                                continue
                except (FileNotFoundError, OSError, PermissionError) as exc:
                    # Key does not exist on this machine or access denied
                    logger.debug("Registry key %s\\%s (%s) read skipped: %s", hive_name, subkey, view, exc)
                    continue

        return items

    def _scan_with_custom_reader(self) -> list[PersistenceItem]:
        """Scan using the injected registry_reader adapter."""
        items: list[PersistenceItem] = []
        for hive_name, hive_const_name, subkey, views in self.REGISTRY_TARGETS:
            for view in views:
                try:
                    entries = self._custom_reader(hive_name, subkey, view)
                    for name, value in entries:
                        if "Winlogon" in subkey and name.lower() not in ("userinit", "shell"):
                            continue
                        score, factors, severity, exists = evaluate_persistence_risk(
                            str(value), f"{hive_name}\\{subkey}", name, check_file_exists=False
                        )
                        items.append(PersistenceItem(
                            location_type="registry",
                            location=f"{hive_name}\\{subkey}",
                            name=name,
                            command=str(value),
                            view=view,
                            risk_score=score,
                            risk_factors=factors,
                            severity=severity,
                            target_exists=exists,
                        ))
                except Exception as e:
                    logger.debug("Custom registry reader failed on %s\\%s: %s", hive_name, subkey, e)
                    continue
        return items


# ---------------------------------------------------------------------------
# Scheduled Task Persistence Scanner
# ---------------------------------------------------------------------------

class ScheduledTaskPersistenceScanner:
    """Scans Windows Scheduled Tasks for suspicious persistence."""

    def __init__(self, task_runner: Optional[Callable[[], list[dict]]] = None):
        """
        task_runner: Optional pluggable callable returning task dictionaries
        Signature: () -> list[dict] where dict has TaskName, TaskPath, State, Actions, Author
        """
        self._custom_runner = task_runner

    def scan(self) -> list[PersistenceItem]:
        if self._custom_runner is not None:
            raw_tasks = self._custom_runner()
            return self._parse_tasks(raw_tasks)

        if platform.system() != "Windows":
            logger.debug("ScheduledTaskPersistenceScanner: Non-Windows platform; skipping.")
            return []

        raw_tasks = self._query_powershell_tasks()
        if not raw_tasks:
            raw_tasks = self._query_schtasks_csv()

        return self._parse_tasks(raw_tasks)

    def _query_powershell_tasks(self) -> list[dict]:
        """Query tasks via PowerShell Get-ScheduledTask."""
        ps_cmd = (
            "Get-ScheduledTask | "
            "Select-Object TaskName, TaskPath, State, Author, "
            "@{Name='Actions';Expression={($_.Actions | ForEach-Object { if ($_.Execute) { $_.Execute + ' ' + $_.Arguments } else { $_.Id } }) -join '; '}} | "
            "ConvertTo-Json -Depth 2"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=20, shell=False
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
        except Exception as exc:
            logger.debug("PowerShell task query failed: %s", exc)
        return []

    def _query_schtasks_csv(self) -> list[dict]:
        """Fallback to schtasks.exe /query /fo CSV /v."""
        tasks: list[dict] = []
        try:
            res = subprocess.run(
                ["schtasks.exe", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=20, shell=False
            )
            if res.returncode == 0 and res.stdout.strip():
                import csv
                import io
                reader = csv.DictReader(io.StringIO(res.stdout))
                for row in reader:
                    task_name = row.get("TaskName", "")
                    action = row.get("Task To Run", "") or row.get("Action", "")
                    if task_name and action:
                        tasks.append({
                            "TaskName": Path(task_name).name,
                            "TaskPath": str(Path(task_name).parent),
                            "State": row.get("Status", ""),
                            "Author": row.get("Author", ""),
                            "Actions": action,
                        })
        except Exception as exc:
            logger.debug("schtasks query failed: %s", exc)
        return tasks

    def _parse_tasks(self, raw_tasks: list[dict]) -> list[PersistenceItem]:
        items: list[PersistenceItem] = []
        for t in raw_tasks:
            name = t.get("TaskName") or ""
            path = t.get("TaskPath") or "\\"
            actions = str(t.get("Actions") or "").strip()
            author = t.get("Author")
            state = t.get("State")

            if not name or not actions:
                continue

            score, factors, severity, exists = evaluate_persistence_risk(
                actions, path, name, check_file_exists=False
            )

            items.append(PersistenceItem(
                location_type="scheduled_task",
                location=path,
                name=name,
                command=actions,
                view="native",
                author=author,
                state=state,
                risk_score=score,
                risk_factors=factors,
                severity=severity,
                target_exists=exists,
            ))
        return items


# ---------------------------------------------------------------------------
# Persistence Monitor (Manager with Baseline & Diffing)
# ---------------------------------------------------------------------------

class PersistenceMonitor:
    """
    Manages persistence scans, baseline state, and change detection.
    Prevents repeated duplicate alerts for unchanged entries across cycles.
    """

    def __init__(
        self,
        registry_scanner: Optional[RegistryPersistenceScanner] = None,
        task_scanner: Optional[ScheduledTaskPersistenceScanner] = None,
    ):
        self.registry_scanner = registry_scanner or RegistryPersistenceScanner()
        self.task_scanner = task_scanner or ScheduledTaskPersistenceScanner()
        self._baseline: dict[str, PersistenceItem] = {}  # key: (location_type, location, name) -> item
        self._alerted_fingerprints: set[str] = set()
        self.is_baseline_established: bool = False

    def scan_all(self) -> list[PersistenceItem]:
        """Perform raw scan across both registry and scheduled tasks."""
        results: list[PersistenceItem] = []
        try:
            results.extend(self.registry_scanner.scan())
        except Exception as e:
            logger.error("Registry scan error: %s", e)

        try:
            results.extend(self.task_scanner.scan())
        except Exception as e:
            logger.error("Scheduled task scan error: %s", e)

        return results

    def check_for_changes(self) -> dict[str, list[PersistenceItem]]:
        """
        Run a scan, compare against baseline, and detect changes.
        Returns a dict:
          {"added": [...], "modified": [...], "removed": [...]}
        """
        current_items = self.scan_all()
        current_map: dict[str, PersistenceItem] = {
            f"{item.location_type}::{item.location}::{item.name}": item
            for item in current_items
        }

        changes: dict[str, list[PersistenceItem]] = {
            "added": [],
            "modified": [],
            "removed": [],
        }

        if not self.is_baseline_established:
            # First run: establish baseline
            self._baseline = current_map
            for item in current_items:
                self._alerted_fingerprints.add(item.fingerprint)
            self.is_baseline_established = True
            logger.info("Persistence baseline established with %d items.", len(self._baseline))
            return changes

        # Check for added and modified
        for key, curr_item in current_map.items():
            if key not in self._baseline:
                changes["added"].append(curr_item)
                self._baseline[key] = curr_item
                self._alerted_fingerprints.add(curr_item.fingerprint)
            else:
                prev_item = self._baseline[key]
                if curr_item.fingerprint != prev_item.fingerprint:
                    changes["modified"].append(curr_item)
                    self._baseline[key] = curr_item
                    self._alerted_fingerprints.add(curr_item.fingerprint)

        # Check for removed
        for key, prev_item in list(self._baseline.items()):
            if key not in current_map:
                changes["removed"].append(prev_item)
                del self._baseline[key]

        return changes

    def generate_events(self, changes: dict[str, list[PersistenceItem]]) -> list[dict]:
        """
        Convert detected changes into structured AEGIS agent event payloads.
        Category: 'fim' (or 'persistence'), matching AEGIS schema.
        """
        events: list[dict] = []

        for item in changes.get("added", []):
            events.append({
                "category": "fim",
                "severity": item.severity,
                "title": f"PERSISTENCE ADDED: {item.name} ({item.location_type})",
                "details": {
                    "operation": "created",
                    "location_type": item.location_type,
                    "location": item.location,
                    "name": item.name,
                    "command": item.command,
                    "view": item.view,
                    "risk_score": item.risk_score,
                    "risk_factors": item.risk_factors,
                    "author": item.author,
                    "target_exists": item.target_exists,
                },
                "timestamp": item.timestamp,
            })

        for item in changes.get("modified", []):
            events.append({
                "category": "fim",
                "severity": item.severity,
                "title": f"PERSISTENCE MODIFIED: {item.name} ({item.location_type})",
                "details": {
                    "operation": "modified",
                    "location_type": item.location_type,
                    "location": item.location,
                    "name": item.name,
                    "command": item.command,
                    "view": item.view,
                    "risk_score": item.risk_score,
                    "risk_factors": item.risk_factors,
                    "author": item.author,
                    "target_exists": item.target_exists,
                },
                "timestamp": item.timestamp,
            })

        for item in changes.get("removed", []):
            events.append({
                "category": "fim",
                "severity": "info",
                "title": f"PERSISTENCE REMOVED: {item.name} ({item.location_type})",
                "details": {
                    "operation": "deleted",
                    "location_type": item.location_type,
                    "location": item.location,
                    "name": item.name,
                    "command": item.command,
                    "view": item.view,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        return events
