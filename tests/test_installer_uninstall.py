"""Tests for sentinel_mac/installer/uninstall.py helpers."""

import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from sentinel_mac.installer.uninstall import (
    collect_purge_targets,
    remove_paths,
    remove_plist,
    unload_launchagent,
)


class TestUnloadLaunchagent:
    """Test unload_launchagent() helper."""

    def test_bootout_success(self) -> None:
        """Modern bootout succeeds."""
        plist = Path("/tmp/test.plist")
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0)
            success, msg = unload_launchagent(plist)
            assert success
            assert "bootout" in msg

    def test_bootout_fails_unload_succeeds(self) -> None:
        """bootout fails, unload fallback succeeds."""
        plist = Path("/tmp/test.plist")
        with mock.patch("subprocess.run") as mock_run:
            # First call (bootout) fails, second call (unload) succeeds
            mock_run.side_effect = [
                mock.Mock(returncode=1, stderr="error"),
                mock.Mock(returncode=0, stderr=""),
            ]
            success, msg = unload_launchagent(plist)
            assert success
            assert "unload" in msg

    def test_both_fail_not_loaded(self) -> None:
        """Both fail but error indicates already unloaded."""
        plist = Path("/tmp/test.plist")
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock.Mock(returncode=1, stderr="No such process"),
                mock.Mock(returncode=1, stderr="No such process"),
            ]
            success, msg = unload_launchagent(plist)
            assert success
            assert "not loaded" in msg

    def test_both_fail_actual_error(self) -> None:
        """Both fail with actual error."""
        plist = Path("/tmp/test.plist")
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock.Mock(returncode=1, stderr="Permission denied"),
                mock.Mock(returncode=1, stderr="Permission denied"),
            ]
            success, msg = unload_launchagent(plist)
            assert not success
            assert "failed" in msg

    def test_timeout(self) -> None:
        """launchctl times out."""
        plist = Path("/tmp/test.plist")
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 5.0)
            success, msg = unload_launchagent(plist)
            assert not success
            assert "timed out" in msg


class TestRemovePlist:
    """Test remove_plist() helper."""

    def test_file_exists_delete_success(self) -> None:
        """Plist exists and is deleted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist = Path(tmpdir) / "test.plist"
            plist.write_text("test")
            assert plist.exists()
            assert remove_plist(plist)
            assert not plist.exists()

    def test_file_not_exists(self) -> None:
        """Plist does not exist — idempotent (returns True)."""
        plist = Path("/nonexistent/test.plist")
        assert remove_plist(plist)


class TestCollectPurgeTargets:
    """Test collect_purge_targets() helper."""

    def test_no_targets_exist(self) -> None:
        """No purge targets exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            config = Path(tmpdir) / "config.yaml"
            targets = collect_purge_targets(data_dir, config)
            assert targets == []

    def test_config_only(self) -> None:
        """Config file exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "config.yaml"
            config.write_text("test")
            data_dir = Path(tmpdir) / "data"
            targets = collect_purge_targets(data_dir, config)
            assert targets == [config]

    def test_events_files(self) -> None:
        """Event JSONL files exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            events_dir = data_dir / "events"
            events_dir.mkdir(parents=True)
            (events_dir / "2026-05-01.jsonl").write_text("test")
            (events_dir / "2026-05-02.jsonl").write_text("test")

            config = Path(tmpdir) / "config.yaml"
            targets = collect_purge_targets(data_dir, config)
            assert len(targets) == 2
            assert all(str(t).endswith(".jsonl") for t in targets)

    def test_skipped_versions(self) -> None:
        """skipped_versions.txt exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            updater_dir = data_dir / "updater"
            updater_dir.mkdir(parents=True)
            (updater_dir / "skipped_versions.txt").write_text("test")

            config = Path(tmpdir) / "config.yaml"
            targets = collect_purge_targets(data_dir, config)
            assert len(targets) == 1
            assert targets[0].name == "skipped_versions.txt"

    def test_all_targets(self) -> None:
        """All possible purge targets exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            config = Path(tmpdir) / "config.yaml"

            # Create all targets
            config.write_text("test")
            events_dir = data_dir / "events"
            events_dir.mkdir(parents=True)
            (events_dir / "2026-05-01.jsonl").write_text("test")
            updater_dir = data_dir / "updater"
            updater_dir.mkdir(parents=True)
            (updater_dir / "skipped_versions.txt").write_text("test")

            targets = collect_purge_targets(data_dir, config)
            assert len(targets) == 3


class TestRemovePaths:
    """Test remove_paths() helper."""

    def test_remove_single_file(self) -> None:
        """Remove a single file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = Path(tmpdir) / "file1.txt"
            file1.write_text("test")
            removed, errors = remove_paths([file1])
            assert removed == [file1]
            assert errors == []
            assert not file1.exists()

    def test_remove_multiple_files(self) -> None:
        """Remove multiple files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = Path(tmpdir) / "file1.txt"
            file2 = Path(tmpdir) / "file2.txt"
            file1.write_text("test1")
            file2.write_text("test2")
            removed, errors = remove_paths([file1, file2])
            assert len(removed) == 2
            assert errors == []

    def test_remove_directory(self) -> None:
        """Remove a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            (subdir / "file.txt").write_text("test")
            removed, errors = remove_paths([subdir])
            assert removed == [subdir]
            assert errors == []
            assert not subdir.exists()

    def test_mixed_success_and_error(self) -> None:
        """Mix of successful removals and errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = Path(tmpdir) / "file1.txt"
            file1.write_text("test")
            file2 = Path("/nonexistent/file2.txt")  # Will fail

            removed, errors = remove_paths([file1, file2])
            assert file1 in removed
            assert len(errors) == 1
            assert errors[0][0] == file2
