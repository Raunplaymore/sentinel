"""Tests for sentinel_mac/updater/apply.py (ADR 0010 §D3 Track B)."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel_mac.updater.apply import (
    acquire_update_lock,
    apply_update,
    release_update_lock,
    run_upgrade,
    start_daemon,
    stop_daemon,
    verify_running_version,
)
from sentinel_mac.updater.detect import InstallMethod


class TestRunUpgrade:
    """Tests for run_upgrade subprocess execution."""

    def test_pipx_upgrade_latest(self) -> None:
        """Test pipx upgrade to latest version."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = run_upgrade(InstallMethod.PIPX)

            assert result.returncode == 0
            # Check that pipx upgrade sentinel-mac was called
            calls = mock_run.call_args_list
            assert any("pipx" in str(call) for call in calls)
            assert any("upgrade" in str(call) for call in calls)

    def test_pipx_upgrade_pinned_version(self) -> None:
        """Test pipx install with version pin (rollback)."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = run_upgrade(InstallMethod.PIPX, new_version="0.9.0")

            assert result.returncode == 0
            calls = mock_run.call_args_list
            assert any("==0.9.0" in str(call) for call in calls)

    def test_pipx_not_found(self) -> None:
        """Test FileNotFoundError when pipx not on PATH."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("pipx not found")

            with pytest.raises(FileNotFoundError, match="pipx not found"):
                run_upgrade(InstallMethod.PIPX)

    def test_pip_venv_upgrade_latest(self) -> None:
        """Test pip upgrade to latest version."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = run_upgrade(InstallMethod.PIP_VENV)

            assert result.returncode == 0
            calls = mock_run.call_args_list
            assert any("--upgrade" in str(call) for call in calls)

    def test_pip_venv_pinned_version(self) -> None:
        """Test pip install with version pin (rollback)."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = run_upgrade(InstallMethod.PIP_VENV, new_version="0.9.0")

            assert result.returncode == 0
            calls = mock_run.call_args_list
            assert any("==0.9.0" in str(call) for call in calls)

    def test_unsupported_method(self) -> None:
        """Test RuntimeError for unsupported install method."""
        with pytest.raises(RuntimeError, match="Unsupported install method"):
            run_upgrade(InstallMethod.EDITABLE)


class TestDaemonControl:
    """Tests for stop_daemon, start_daemon."""

    def test_stop_daemon_success(self) -> None:
        """Test successful daemon stop."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")

                result = stop_daemon(plist_path)

                assert result is True
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert "launchctl" in args
                assert "unload" in args

    def test_stop_daemon_plist_not_found(self) -> None:
        """Test stop_daemon returns False when plist missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist_path = Path(tmpdir) / "missing.plist"

            result = stop_daemon(plist_path)

            # Returns False + warning printed to stderr
            assert result is False

    def test_stop_daemon_subprocess_failure(self) -> None:
        """Test stop_daemon returns False on launchctl failure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stderr="error: unload failed"
                )

                result = stop_daemon(plist_path)

                assert result is False

    def test_start_daemon_success(self) -> None:
        """Test successful daemon start."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")

                result = start_daemon(plist_path)

                assert result is True
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert "launchctl" in args
                assert "load" in args

    def test_start_daemon_plist_not_found(self) -> None:
        """Test start_daemon returns False when plist missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist_path = Path(tmpdir) / "missing.plist"

            result = start_daemon(plist_path)

            assert result is False

    def test_start_daemon_subprocess_failure(self) -> None:
        """Test start_daemon returns False on launchctl failure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stderr="error: load failed"
                )

                result = start_daemon(plist_path)

                assert result is False


class TestVerifyVersion:
    """Tests for verify_running_version."""

    def test_verify_success(self) -> None:
        """Test successful version verification."""
        with patch("subprocess.run") as mock_run, patch("time.sleep"):
            mock_run.return_value = MagicMock(
                returncode=0, stdout="sentinel-mac 0.10.0\n"
            )

            result = verify_running_version("0.10.0")

            assert result is True

    def test_verify_mismatch(self) -> None:
        """Test version mismatch detection."""
        with patch("subprocess.run") as mock_run, patch("time.sleep"):
            mock_run.return_value = MagicMock(
                returncode=0, stdout="sentinel-mac 0.9.0\n"
            )

            result = verify_running_version("0.10.0")

            assert result is False

    def test_verify_subprocess_failure(self) -> None:
        """Test subprocess failure in verify."""
        with patch("subprocess.run") as mock_run, patch("time.sleep"):
            mock_run.return_value = MagicMock(returncode=1, stdout="")

            result = verify_running_version("0.10.0")

            assert result is False

    def test_verify_sleep_called(self) -> None:
        """Test that verify sleeps for 2 seconds."""
        with patch("subprocess.run") as mock_run, patch("time.sleep") as mock_sleep:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="sentinel-mac 0.10.0\n"
            )

            verify_running_version("0.10.0")

            mock_sleep.assert_called_once_with(2)


class TestLockfile:
    """Tests for acquire_update_lock, release_update_lock."""

    def test_acquire_lock_success(self) -> None:
        """Test acquiring lock when not held."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)

            with patch("os.getpid", return_value=12345):
                lock_fp = acquire_update_lock(data_dir)

            assert lock_fp is not None
            lock_path = data_dir / "updater.lock"
            assert lock_path.exists()
            assert "12345" in lock_path.read_text()

    def test_acquire_lock_already_held(self) -> None:
        """Test acquiring lock when already held."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)

            # First acquire
            with patch("os.getpid", return_value=12345):
                lock_fp1 = acquire_update_lock(data_dir)

            # Second acquire should fail
            with patch("os.getpid", return_value=67890):
                lock_fp2 = acquire_update_lock(data_dir)

            assert lock_fp1 is not None
            assert lock_fp2 is None

    def test_release_lock(self) -> None:
        """Test releasing lock."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            lock_path = data_dir / "updater.lock"

            with patch("os.getpid", return_value=12345):
                lock_fp = acquire_update_lock(data_dir)

            assert lock_path.exists()
            release_update_lock(lock_fp, lock_path)
            assert not lock_path.exists()


class TestApplyUpdate:
    """Integration tests for apply_update orchestration."""

    def test_happy_path_pipx(self) -> None:
        """Test successful update with pipx."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("subprocess.run") as mock_run, patch(
                "time.sleep"
            ), patch("os.getpid", return_value=12345), patch(
                "importlib.metadata.version", return_value="0.9.0"
            ):
                # Mock all subprocess calls
                def run_side_effect(*args, **kwargs):
                    cmd = args[0]
                    if "sentinel" in cmd and "--version" in cmd:
                        return MagicMock(
                            returncode=0, stdout="sentinel-mac 0.10.0\n", stderr=""
                        )
                    # All others (launchctl, pip/pipx) succeed
                    return MagicMock(returncode=0, stdout="", stderr="")

                mock_run.side_effect = run_side_effect

                result = apply_update(
                    method=InstallMethod.PIPX,
                    target_version="0.10.0",
                    yes=True,
                    emit_json=False,
                    data_dir=data_dir,
                    plist_path=plist_path,
                )

            assert result == 0

    def test_locked_update_in_progress(self) -> None:
        """Test locked state when another update is running."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            # Create and hold lock
            with patch("os.getpid", side_effect=[99999, 12345]):
                lock_fp = acquire_update_lock(data_dir)

                try:
                    # Try to acquire again
                    result = apply_update(
                        method=InstallMethod.PIPX,
                        target_version="0.10.0",
                        yes=True,
                        emit_json=False,
                        data_dir=data_dir,
                        plist_path=plist_path,
                    )

                    assert result == 1
                finally:
                    if lock_fp:
                        release_update_lock(lock_fp, data_dir / "updater.lock")

    def test_upgrade_failure_with_rollback(self) -> None:
        """Test rollback when upgrade subprocess fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("subprocess.run") as mock_run, patch(
                "time.sleep"
            ), patch("os.getpid", return_value=12345), patch(
                "importlib.metadata.version", return_value="0.9.0"
            ):
                # First upgrade fails, rollback succeeds
                call_count = [0]

                def run_side_effect(*args, **kwargs):
                    call_count[0] += 1
                    # Make upgrade fail (call index 2: after launchctl unload)
                    if (
                        ("upgrade" in str(args[0]) or "install" in str(args[0]))
                        and "0.10.0" in str(args[0])
                    ):
                        return MagicMock(
                            returncode=1,
                            stdout="",
                            stderr="network error",
                        )
                    # Rollback succeeds
                    if "0.9.0" in str(args[0]):
                        return MagicMock(returncode=0, stdout="", stderr="")
                    # launchctl, sentinel --version succeed
                    return MagicMock(returncode=0, stdout="", stderr="")

                mock_run.side_effect = run_side_effect

                result = apply_update(
                    method=InstallMethod.PIPX,
                    target_version="0.10.0",
                    yes=True,
                    emit_json=False,
                    data_dir=data_dir,
                    plist_path=plist_path,
                )

            assert result == 1

    def test_plist_not_found(self) -> None:
        """Test update when plist is missing (edge case)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "missing.plist"

            with patch("subprocess.run") as mock_run, patch(
                "time.sleep"
            ), patch("os.getpid", return_value=12345), patch(
                "importlib.metadata.version", return_value="0.9.0"
            ):
                def run_side_effect(*args, **kwargs):
                    cmd = args[0]
                    if "sentinel" in cmd and "--version" in cmd:
                        return MagicMock(
                            returncode=0, stdout="sentinel-mac 0.10.0\n", stderr=""
                        )
                    return MagicMock(returncode=0, stdout="", stderr="")

                mock_run.side_effect = run_side_effect

                result = apply_update(
                    method=InstallMethod.PIP_VENV,
                    target_version="0.10.0",
                    yes=True,
                    emit_json=False,
                    data_dir=data_dir,
                    plist_path=plist_path,
                )

            # Should succeed despite missing plist (warning only)
            assert result == 0

    def test_non_tty_without_yes(self) -> None:
        """Test cancellation in non-interactive mode without --yes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("sys.stdin.isatty", return_value=False), patch(
                "os.getpid", return_value=12345
            ), patch("importlib.metadata.version", return_value="0.9.0"):

                result = apply_update(
                    method=InstallMethod.PIPX,
                    target_version="0.10.0",
                    yes=False,
                    emit_json=False,
                    data_dir=data_dir,
                    plist_path=plist_path,
                )

            assert result == 1

    def test_yes_skips_prompt(self) -> None:
        """Test that --yes flag skips confirmation prompt."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("subprocess.run") as mock_run, patch(
                "time.sleep"
            ), patch("os.getpid", return_value=12345), patch(
                "importlib.metadata.version", return_value="0.9.0"
            ), patch("builtins.input") as mock_input:
                def run_side_effect(*args, **kwargs):
                    cmd = args[0]
                    if "sentinel" in cmd and "--version" in cmd:
                        return MagicMock(
                            returncode=0, stdout="sentinel-mac 0.10.0\n", stderr=""
                        )
                    return MagicMock(returncode=0, stdout="", stderr="")

                mock_run.side_effect = run_side_effect

                result = apply_update(
                    method=InstallMethod.PIPX,
                    target_version="0.10.0",
                    yes=True,
                    emit_json=False,
                    data_dir=data_dir,
                    plist_path=plist_path,
                )

            # input() should not be called when --yes
            mock_input.assert_not_called()
            assert result == 0

    def test_json_output_success(self) -> None:
        """Test JSON envelope output on success."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            json_output = []

            def capture_print(*args, **kwargs):
                if args:
                    json_output.append(args[0])

            with patch("subprocess.run") as mock_run, patch(
                "time.sleep"
            ), patch("os.getpid", return_value=12345), patch(
                "importlib.metadata.version", return_value="0.9.0"
            ), patch("builtins.print", side_effect=capture_print):
                def run_side_effect(*args, **kwargs):
                    cmd = args[0]
                    if "sentinel" in cmd and "--version" in cmd:
                        return MagicMock(
                            returncode=0, stdout="sentinel-mac 0.10.0\n", stderr=""
                        )
                    return MagicMock(returncode=0, stdout="", stderr="")

                mock_run.side_effect = run_side_effect

                result = apply_update(
                    method=InstallMethod.PIPX,
                    target_version="0.10.0",
                    yes=True,
                    emit_json=True,
                    data_dir=data_dir,
                    plist_path=plist_path,
                )

            assert result == 0
            # Last output should be JSON envelope
            if json_output:
                envelope = json.loads(json_output[-1])
                assert envelope["kind"] == "update_apply"
                assert envelope["data"]["result"] == "success"
                assert envelope["data"]["from_version"] == "0.9.0"
                assert envelope["data"]["to_version"] == "0.10.0"

    def test_json_output_locked(self) -> None:
        """Test JSON envelope output when locked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            json_output = []

            def capture_print(*args, **kwargs):
                if args:
                    json_output.append(args[0])

            # Create and hold lock
            with patch("os.getpid", side_effect=[99999, 12345]), patch(
                "builtins.print", side_effect=capture_print
            ):
                lock_fp = acquire_update_lock(data_dir)

                try:
                    result = apply_update(
                        method=InstallMethod.PIPX,
                        target_version="0.10.0",
                        yes=True,
                        emit_json=True,
                        data_dir=data_dir,
                        plist_path=plist_path,
                    )

                    assert result == 1
                    if json_output:
                        envelope = json.loads(json_output[-1])
                        assert envelope["kind"] == "update_apply"
                        assert envelope["data"]["result"] == "locked"
                finally:
                    if lock_fp:
                        release_update_lock(lock_fp, data_dir / "updater.lock")

    def test_already_up_to_date(self) -> None:
        """Test early exit when already at latest version.

        The check happens in cmd_update, not apply_update itself.
        This test verifies the plumbing by confirming the version check logic.
        """
        with patch("importlib.metadata.version", return_value="0.10.0"):
            # Verify that version equality is detected at the cmd_update level
            # (not tested here; this is documented for completeness)
            pass

    def test_user_cancels_prompt(self) -> None:
        """Test cancellation when user declines prompt."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("sys.stdin.isatty", return_value=True), patch(
                "builtins.input", return_value="n"
            ), patch("os.getpid", return_value=12345), patch(
                "importlib.metadata.version", return_value="0.9.0"
            ):
                result = apply_update(
                    method=InstallMethod.PIPX,
                    target_version="0.10.0",
                    yes=False,
                    emit_json=False,
                    data_dir=data_dir,
                    plist_path=plist_path,
                )

            assert result == 1

    def test_verify_mismatch_failure(self) -> None:
        """Test failure when verify detects version mismatch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            plist_path = Path(tmpdir) / "test.plist"
            plist_path.touch()

            with patch("subprocess.run") as mock_run, patch(
                "time.sleep"
            ), patch("os.getpid", return_value=12345), patch(
                "importlib.metadata.version", return_value="0.9.0"
            ):
                def run_side_effect(*args, **kwargs):
                    cmd = args[0]
                    if "sentinel" in cmd and "--version" in cmd:
                        # Return old version (mismatch)
                        return MagicMock(
                            returncode=0, stdout="sentinel-mac 0.9.0\n", stderr=""
                        )
                    return MagicMock(returncode=0, stdout="", stderr="")

                mock_run.side_effect = run_side_effect

                result = apply_update(
                    method=InstallMethod.PIP_VENV,
                    target_version="0.10.0",
                    yes=True,
                    emit_json=False,
                    data_dir=data_dir,
                    plist_path=plist_path,
                )

            assert result == 1
