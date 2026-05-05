"""Tests for sentinel_mac/commands/uninstall.py command."""

import json
import tempfile
from pathlib import Path
from unittest import mock

from sentinel_mac.commands.uninstall import cmd_uninstall, dispatch


class FakeArgs:
    """Fake argparse.Namespace for testing."""

    def __init__(self, **kwargs: bool) -> None:
        self.purge = kwargs.get("purge", False)
        self.keep_launchagent = kwargs.get("keep_launchagent", False)
        self.yes = kwargs.get("yes", False)
        self.json = kwargs.get("json", False)


class TestCmdUninstallNotInstalled:
    """Test not-installed detection."""

    def test_not_installed_no_plist_no_config(self) -> None:
        """Neither plist nor config exists — exit 2."""
        with mock.patch("sentinel_mac.commands.uninstall._plist_path") as mock_plist, \
             mock.patch("sentinel_mac.commands.uninstall.resolve_config_path") as mock_cfg, \
             mock.patch("sentinel_mac.commands.uninstall.resolve_data_dir") as mock_data:
            mock_plist.return_value = Path("/nonexistent/test.plist")
            mock_cfg.return_value = Path("/nonexistent/config.yaml")
            mock_data.return_value = Path("/nonexistent/data")

            args = FakeArgs(yes=True)
            result = cmd_uninstall(args)
            assert result == 2

    def test_not_installed_json_output(self) -> None:
        """JSON output for not-installed state."""
        with mock.patch("sentinel_mac.commands.uninstall._plist_path") as mock_plist, \
             mock.patch("sentinel_mac.commands.uninstall.resolve_config_path") as mock_cfg, \
             mock.patch("sentinel_mac.commands.uninstall.resolve_data_dir") as mock_data, \
             mock.patch("builtins.print") as mock_print:
            mock_plist.return_value = Path("/nonexistent/test.plist")
            mock_cfg.return_value = Path("/nonexistent/config.yaml")
            mock_data.return_value = Path("/nonexistent/data")

            args = FakeArgs(yes=True, json=True)
            result = cmd_uninstall(args)
            assert result == 2
            mock_print.assert_called_once()
            output = json.loads(mock_print.call_args[0][0])
            assert output["kind"] == "uninstall"
            assert output["data"]["result"] == "not_installed"


class TestCmdUninstallConfirmation:
    """Test confirmation prompt behavior."""

    def test_non_tty_no_yes_flag(self) -> None:
        """Non-TTY without --yes → cancel with warning."""
        with mock.patch("sentinel_mac.commands.uninstall._plist_path") as mock_plist, \
             mock.patch("sentinel_mac.commands.uninstall.resolve_config_path") as mock_cfg, \
             mock.patch("sentinel_mac.commands.uninstall.resolve_data_dir") as mock_data, \
             mock.patch("sys.stdin.isatty", return_value=False):
            mock_plist.return_value = Path("/tmp/test.plist")
            mock_cfg.return_value = Path("/tmp/config.yaml")
            mock_data.return_value = Path("/tmp/data")
            (Path("/tmp/test.plist").parent).mkdir(exist_ok=True, parents=True)
            Path("/tmp/test.plist").touch()

            args = FakeArgs(yes=False)
            result = cmd_uninstall(args)
            assert result == 1

    def test_tty_user_cancels(self) -> None:
        """TTY with user responding 'n' → cancelled."""
        with mock.patch("sentinel_mac.commands.uninstall._plist_path") as mock_plist, \
             mock.patch("sentinel_mac.commands.uninstall.resolve_config_path") as mock_cfg, \
             mock.patch("sentinel_mac.commands.uninstall.resolve_data_dir") as mock_data, \
             mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("builtins.input", return_value="n"):
            mock_plist.return_value = Path("/tmp/test.plist")
            mock_cfg.return_value = Path("/tmp/config.yaml")
            mock_data.return_value = Path("/tmp/data")
            Path("/tmp/test.plist").parent.mkdir(exist_ok=True, parents=True)
            Path("/tmp/test.plist").touch()

            args = FakeArgs(yes=False)
            result = cmd_uninstall(args)
            assert result == 1


class TestCmdUninstallStandardMode:
    """Test standard uninstall (no --purge)."""

    def test_success_with_plist_and_config(self) -> None:
        """Successfully uninstall with both plist and config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist = Path(tmpdir) / "test.plist"
            config = Path(tmpdir) / "config.yaml"
            data_dir = Path(tmpdir) / "data"

            plist.write_text("test")
            config.write_text("test")
            data_dir.mkdir()

            with mock.patch("sentinel_mac.commands.uninstall._plist_path", return_value=plist), \
                 mock.patch("sentinel_mac.commands.uninstall.resolve_config_path", return_value=config), \
                 mock.patch("sentinel_mac.commands.uninstall.resolve_data_dir", return_value=data_dir), \
                 mock.patch("sentinel_mac.commands.uninstall.unload_launchagent") as mock_unload, \
                 mock.patch("builtins.print"):
                mock_unload.return_value = (True, "success")

                args = FakeArgs(yes=True)
                result = cmd_uninstall(args)
                assert result == 0
                assert not plist.exists()
                assert config.exists()  # Preserved in standard mode
                assert data_dir.exists()

    def test_preserves_artifacts_in_json(self) -> None:
        """JSON output includes preserved artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist = Path(tmpdir) / "test.plist"
            config = Path(tmpdir) / "config.yaml"
            data_dir = Path(tmpdir) / "data"

            plist.write_text("test")
            config.write_text("test")
            data_dir.mkdir()

            with mock.patch("sentinel_mac.commands.uninstall._plist_path", return_value=plist), \
                 mock.patch("sentinel_mac.commands.uninstall.resolve_config_path", return_value=config), \
                 mock.patch("sentinel_mac.commands.uninstall.resolve_data_dir", return_value=data_dir), \
                 mock.patch("sentinel_mac.commands.uninstall.unload_launchagent") as mock_unload, \
                 mock.patch("builtins.print") as mock_print:
                mock_unload.return_value = (True, "success")

                args = FakeArgs(yes=True, json=True)
                result = cmd_uninstall(args)
                assert result == 0
                output = json.loads(mock_print.call_args[0][0])
                assert str(config) in output["data"]["preserved_artifacts"]
                assert str(data_dir) in output["data"]["preserved_artifacts"]


class TestCmdUninstallPurgeMode:
    """Test --purge mode."""

    def test_purge_deletes_config_and_events(self) -> None:
        """--purge deletes config, events, and skipped_versions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist = Path(tmpdir) / "test.plist"
            config = Path(tmpdir) / "config.yaml"
            data_dir = Path(tmpdir) / "data"
            events_dir = data_dir / "events"

            plist.write_text("test")
            config.write_text("test")
            events_dir.mkdir(parents=True)
            (events_dir / "2026-05-01.jsonl").write_text("test")

            with mock.patch("sentinel_mac.commands.uninstall._plist_path", return_value=plist), \
                 mock.patch("sentinel_mac.commands.uninstall.resolve_config_path", return_value=config), \
                 mock.patch("sentinel_mac.commands.uninstall.resolve_data_dir", return_value=data_dir), \
                 mock.patch("sentinel_mac.commands.uninstall.unload_launchagent") as mock_unload, \
                 mock.patch("builtins.print"):
                mock_unload.return_value = (True, "success")

                args = FakeArgs(yes=True, purge=True)
                result = cmd_uninstall(args)
                assert result == 0
                assert not plist.exists()
                assert not config.exists()  # Deleted in purge mode
                assert not (events_dir / "2026-05-01.jsonl").exists()

    def test_purge_confirmation_message(self) -> None:
        """--purge shows stronger warning in confirmation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plist = Path(tmpdir) / "test.plist"
            config = Path(tmpdir) / "config.yaml"
            data_dir = Path(tmpdir) / "data"

            plist.write_text("test")

            with mock.patch("sentinel_mac.commands.uninstall._plist_path", return_value=plist), \
                 mock.patch("sentinel_mac.commands.uninstall.resolve_config_path", return_value=config), \
                 mock.patch("sentinel_mac.commands.uninstall.resolve_data_dir", return_value=data_dir), \
                 mock.patch("sys.stdin.isatty", return_value=True), \
                 mock.patch("builtins.input", return_value="y") as mock_input, \
                 mock.patch("sentinel_mac.commands.uninstall.unload_launchagent") as mock_unload, \
                 mock.patch("builtins.print"):
                mock_unload.return_value = (True, "success")

                args = FakeArgs(yes=False, purge=True)
                cmd_uninstall(args)
                # Check that input was called with purge warning
                prompt = mock_input.call_args[0][0]
                assert "DELETE YOUR EVENT LOG" in prompt


class TestDispatch:
    """Test dispatch() entry point."""

    def test_dispatch_parses_args(self) -> None:
        """dispatch() parses arguments and calls cmd_uninstall."""
        with mock.patch("sentinel_mac.commands.uninstall.cmd_uninstall") as mock_cmd, \
             mock.patch("sentinel_mac.commands.uninstall._plist_path"), \
             mock.patch("sentinel_mac.commands.uninstall.resolve_config_path"), \
             mock.patch("sentinel_mac.commands.uninstall.resolve_data_dir"):
            mock_cmd.return_value = 0

            result = dispatch(["--yes", "--json"])
            assert result == 0
            assert mock_cmd.called
