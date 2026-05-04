"""Tests for sentinel_mac.commands.update (ADR 0010 Track A)."""

import json
from unittest.mock import patch

from sentinel_mac.commands.update import dispatch


class TestUpdateCommand:
    """Test `sentinel update` command."""

    def test_check_up_to_date(self) -> None:
        """Should return 0 (success) when already up to date."""
        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.get_running_version",
            return_value="0.10.0",
        ), patch(
            "sentinel_mac.commands.update.fetch_latest_pypi_version",
            return_value="0.10.0",
        ), patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.PIP_VENV,
        ):
            exit_code = dispatch(["--check"])
            assert exit_code == 0

    def test_check_update_available(self) -> None:
        """Should return 2 (update available) when newer version exists."""
        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.get_running_version",
            return_value="0.9.0",
        ), patch(
            "sentinel_mac.commands.update.fetch_latest_pypi_version",
            return_value="0.10.0",
        ), patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.PIP_VENV,
        ):
            exit_code = dispatch(["--check"])
            assert exit_code == 2

    def test_check_network_timeout(self) -> None:
        """Should return 0 (not an error) when PyPI is unreachable."""
        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.get_running_version",
            return_value="0.9.0",
        ), patch(
            "sentinel_mac.commands.update.fetch_latest_pypi_version",
            return_value=None,
        ), patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.PIP_VENV,
        ):
            exit_code = dispatch(["--check"])
            assert exit_code == 0

    def test_editable_install_early_exit(self) -> None:
        """Should return 3 and exit early for editable installs."""
        from pathlib import Path

        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.EDITABLE,
        ), patch(
            "sentinel_mac.commands.update.get_source_root",
            return_value=Path("/tmp/source"),
        ), patch(
            "sentinel_mac.updater.version.get_running_version",
            return_value="0.9.0",
        ):
            exit_code = dispatch([])
            assert exit_code == 3

    def test_system_unsafe_early_exit(self) -> None:
        """Should return 3 and exit early for system Python installs."""
        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.SYSTEM_UNSAFE,
        ), patch(
            "sentinel_mac.updater.version.get_running_version",
            return_value="0.9.0",
        ):
            exit_code = dispatch([])
            assert exit_code == 3

    def test_homebrew_early_exit(self) -> None:
        """Should return 3 and exit early for Homebrew installs."""
        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.HOMEBREW,
        ), patch(
            "sentinel_mac.updater.version.get_running_version",
            return_value="0.9.0",
        ):
            exit_code = dispatch([])
            assert exit_code == 3

    def test_apply_not_implemented(self) -> None:
        """Should return 1 with placeholder message when --apply is used."""
        with patch(
            "sentinel_mac.updater.version.get_running_version",
            return_value="0.9.0",
        ):
            exit_code = dispatch(["--apply"])
            assert exit_code == 1

    def test_default_is_check(self) -> None:
        """Should default to --check when no flag is given."""
        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.get_running_version",
            return_value="0.10.0",
        ), patch(
            "sentinel_mac.commands.update.fetch_latest_pypi_version",
            return_value="0.10.0",
        ), patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.PIP_VENV,
        ):
            exit_code = dispatch([])
            assert exit_code == 0

    def test_json_output_up_to_date(self, capsys: object) -> None:
        """Should emit JSON envelope when --json flag is used (up to date)."""
        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.get_running_version",
            return_value="0.10.0",
        ), patch(
            "sentinel_mac.commands.update.fetch_latest_pypi_version",
            return_value="0.10.0",
        ), patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.PIP_VENV,
        ):
            dispatch(["--check", "--json"])
            captured = capsys.readouterr()
            data = json.loads(captured.out.strip())
            assert data["version"] == 1
            assert data["kind"] == "update_check"
            assert "generated_at" in data
            assert data["data"]["running"] == "0.10.0"
            assert data["data"]["latest"] == "0.10.0"

    def test_json_output_update_available(self, capsys: object) -> None:
        """Should emit JSON envelope when update is available."""
        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.get_running_version",
            return_value="0.9.0",
        ), patch(
            "sentinel_mac.commands.update.fetch_latest_pypi_version",
            return_value="0.10.0",
        ), patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.PIP_VENV,
        ):
            dispatch(["--check", "--json"])
            captured = capsys.readouterr()
            data = json.loads(captured.out.strip())
            assert data["version"] == 1
            assert data["kind"] == "update_check"
            assert data["data"]["running"] == "0.9.0"
            assert data["data"]["latest"] == "0.10.0"

    def test_json_output_editable(self, capsys: object) -> None:
        """Should emit JSON envelope for editable install error."""
        from pathlib import Path

        from sentinel_mac.updater.detect import InstallMethod

        with patch(
            "sentinel_mac.commands.update.detect_install_method",
            return_value=InstallMethod.EDITABLE,
        ), patch(
            "sentinel_mac.commands.update.get_source_root",
            return_value=Path("/tmp/source"),
        ), patch(
            "sentinel_mac.updater.version.get_running_version",
            return_value="0.9.0",
        ):
            dispatch(["--json"])
            captured = capsys.readouterr()
            data = json.loads(captured.out.strip())
            assert data["version"] == 1
            assert data["kind"] == "update_check"
            assert "message" in data["data"]
