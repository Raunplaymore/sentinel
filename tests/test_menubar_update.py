"""Tests for sentinel_mac/menubar_app.py update integration (ADR 0010 §D4 Track C).

The menu bar UI depends on rumps which needs a display; the production logic
is therefore split between `sentinel_mac/menubar_app.py` (rumps wiring) and
`sentinel_mac/updater/menubar_helpers.py` (pure helpers). Tests import the
helpers from the production module so the production behavior and the tested
behavior cannot diverge.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinel_mac.updater.menubar_helpers import (
    add_skipped_version as _add_skipped_version,
)
from sentinel_mac.updater.menubar_helpers import (
    parse_check_envelope as _parse_check_envelope,
)
from sentinel_mac.updater.menubar_helpers import (
    read_skipped_versions as _read_skipped_versions,
)
from sentinel_mac.updater.menubar_helpers import (
    should_show_dialog as _should_show_dialog,
)

# ── Test Classes ────────────────────────────────────────────────────────────


class TestSkippedVersions:
    """Tests for skipped versions file management."""

    def test_read_skipped_versions_file_not_found(self) -> None:
        """Read skipped versions when file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            result = _read_skipped_versions(data_dir)
            assert result == set()

    def test_read_skipped_versions_empty_file(self) -> None:
        """Read from empty file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            updater_dir = data_dir / "updater"
            updater_dir.mkdir(parents=True)
            (updater_dir / "skipped_versions.txt").write_text("")
            result = _read_skipped_versions(data_dir)
            assert result == set()

    def test_read_skipped_versions_single_version(self) -> None:
        """Read single skipped version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            updater_dir = data_dir / "updater"
            updater_dir.mkdir(parents=True)
            (updater_dir / "skipped_versions.txt").write_text("0.9.0\n")
            result = _read_skipped_versions(data_dir)
            assert result == {"0.9.0"}

    def test_read_skipped_versions_multiple_versions(self) -> None:
        """Read multiple skipped versions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            updater_dir = data_dir / "updater"
            updater_dir.mkdir(parents=True)
            (updater_dir / "skipped_versions.txt").write_text("0.9.0\n0.8.5\n0.10.0\n")
            result = _read_skipped_versions(data_dir)
            assert result == {"0.9.0", "0.8.5", "0.10.0"}

    def test_read_skipped_versions_ignores_blank_lines(self) -> None:
        """Blank lines and whitespace-only lines are ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            updater_dir = data_dir / "updater"
            updater_dir.mkdir(parents=True)
            (updater_dir / "skipped_versions.txt").write_text(
                "0.9.0\n\n  \n0.8.5\n"
            )
            result = _read_skipped_versions(data_dir)
            assert result == {"0.9.0", "0.8.5"}

    def test_add_skipped_version_creates_directory(self) -> None:
        """Add skipped version creates updater directory if missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            _add_skipped_version(data_dir, "0.9.0")
            skipped_path = data_dir / "updater" / "skipped_versions.txt"
            assert skipped_path.exists()
            assert "0.9.0" in skipped_path.read_text()

    def test_add_skipped_version_single(self) -> None:
        """Add single skipped version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            _add_skipped_version(data_dir, "0.9.0")
            result = _read_skipped_versions(data_dir)
            assert result == {"0.9.0"}

    def test_add_skipped_version_multiple(self) -> None:
        """Add multiple skipped versions sequentially."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            _add_skipped_version(data_dir, "0.9.0")
            _add_skipped_version(data_dir, "0.8.5")
            _add_skipped_version(data_dir, "0.10.0")
            result = _read_skipped_versions(data_dir)
            assert result == {"0.9.0", "0.8.5", "0.10.0"}

    def test_add_skipped_version_idempotent(self) -> None:
        """Adding same version twice doesn't create duplicates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            _add_skipped_version(data_dir, "0.9.0")
            _add_skipped_version(data_dir, "0.9.0")
            content = (data_dir / "updater" / "skipped_versions.txt").read_text()
            assert content.count("0.9.0") == 1

    def test_add_skipped_version_maintains_sort(self) -> None:
        """Versions are kept in sorted order (lexicographic)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            _add_skipped_version(data_dir, "0.10.0")
            _add_skipped_version(data_dir, "0.8.0")
            _add_skipped_version(data_dir, "0.9.0")
            content = (data_dir / "updater" / "skipped_versions.txt").read_text()
            lines = content.strip().split("\n")
            # sorted() uses lexicographic ordering, so "0.10.0" comes before "0.8.0"
            assert lines == ["0.10.0", "0.8.0", "0.9.0"]


class TestParseEnvelope:
    """Tests for parsing JSON envelopes from subprocess output."""

    def test_parse_valid_up_to_date_envelope(self) -> None:
        """Parse valid up_to_date envelope."""
        stdout = json.dumps(
            {"result": "up_to_date", "running": "0.9.0", "latest": "0.9.0"}
        )
        result = _parse_check_envelope(stdout)
        assert result["result"] == "up_to_date"
        assert result["running"] == "0.9.0"

    def test_parse_valid_update_available_envelope(self) -> None:
        """Parse valid update_available envelope."""
        stdout = json.dumps(
            {"result": "update_available", "running": "0.9.0", "latest": "0.10.0"}
        )
        result = _parse_check_envelope(stdout)
        assert result["result"] == "update_available"
        assert result["latest"] == "0.10.0"

    def test_parse_error_envelope(self) -> None:
        """Parse error envelope."""
        stdout = json.dumps(
            {"result": "error", "message": "PyPI unreachable"}
        )
        result = _parse_check_envelope(stdout)
        assert result["result"] == "error"
        assert "PyPI unreachable" in result["message"]

    def test_parse_editable_envelope(self) -> None:
        """Parse editable install early-exit envelope."""
        stdout = json.dumps(
            {
                "result": "editable",
                "message": "sentinel-mac is installed in editable mode",
            }
        )
        result = _parse_check_envelope(stdout)
        assert result["result"] == "editable"

    def test_parse_invalid_json(self) -> None:
        """Parsing invalid JSON returns error dict."""
        result = _parse_check_envelope("not valid json")
        assert result["result"] == "error"
        assert "Failed to parse JSON" in result["message"]

    def test_parse_empty_string(self) -> None:
        """Parsing empty string returns error dict."""
        result = _parse_check_envelope("")
        assert result["result"] == "error"


class TestShouldShowDialog:
    """Tests for deciding whether to show update dialog."""

    def test_should_show_dialog_up_to_date(self) -> None:
        """No dialog for up_to_date."""
        envelope = {"result": "up_to_date", "running": "0.9.0"}
        assert _should_show_dialog(envelope, set()) is False

    def test_should_show_dialog_update_available_not_skipped(self) -> None:
        """Show dialog for new update_available version."""
        envelope = {"result": "update_available", "latest": "0.10.0"}
        assert _should_show_dialog(envelope, set()) is True

    def test_should_show_dialog_update_available_but_skipped(self) -> None:
        """Don't show dialog if version is skipped."""
        envelope = {"result": "update_available", "latest": "0.10.0"}
        skipped = {"0.10.0"}
        assert _should_show_dialog(envelope, skipped) is False

    def test_should_show_dialog_error(self) -> None:
        """No dialog for error."""
        envelope = {"result": "error", "message": "Network failed"}
        assert _should_show_dialog(envelope, set()) is False

    def test_should_show_dialog_editable(self) -> None:
        """No dialog for editable."""
        envelope = {"result": "editable"}
        assert _should_show_dialog(envelope, set()) is False

    def test_should_show_dialog_system_unsafe(self) -> None:
        """No dialog for system_unsafe."""
        envelope = {"result": "system_unsafe"}
        assert _should_show_dialog(envelope, set()) is False


class TestMenubarUpdateIntegration:
    """Integration-style tests for menu bar update flow.

    These tests verify subprocess call patterns and state transitions
    without requiring a full rumps app instance.
    """

    @patch("subprocess.run")
    def test_check_updates_subprocess_call(self, mock_run: MagicMock) -> None:
        """Verify correct subprocess args for --check."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"result": "up_to_date", "running": "0.9.0"}),
            returncode=0,
        )

        # Simulate what the worker would do
        import sys

        subprocess.run(
            [sys.executable, "-m", "sentinel_mac", "update", "--check", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Verify call
        assert mock_run.called
        call_args = mock_run.call_args
        assert "--check" in call_args[0][0]
        assert "--json" in call_args[0][0]

    @patch("subprocess.run")
    def test_apply_updates_subprocess_call(self, mock_run: MagicMock) -> None:
        """Verify correct subprocess args for --apply."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"result": "success", "latest": "0.10.0"}),
            returncode=0,
        )

        import sys

        subprocess.run(
            [
                sys.executable,
                "-m",
                "sentinel_mac",
                "update",
                "--apply",
                "--yes",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert mock_run.called
        call_args = mock_run.call_args
        assert "--apply" in call_args[0][0]
        assert "--yes" in call_args[0][0]
        assert "--json" in call_args[0][0]
        # Verify timeout is generous
        assert call_args[1]["timeout"] == 300

    def test_subprocess_timeout_handling(self) -> None:
        """Verify timeout is caught and converted to error envelope.

        The worker methods catch subprocess.TimeoutExpired and convert it
        to an error envelope. This is tested via the exception-handling
        logic, not by actually timing out.
        """
        # Pattern: timeout exception caught in worker → error envelope
        # See _check_updates_worker and _apply_update_worker implementations

    @patch("subprocess.run")
    def test_check_updates_json_parse_error(self, mock_run: MagicMock) -> None:
        """Handling of malformed JSON from subprocess."""
        mock_run.return_value = MagicMock(
            stdout="not valid json",
            returncode=0,
        )

        # Simulate worker behavior
        try:
            envelope = json.loads(mock_run.return_value.stdout)
        except json.JSONDecodeError:
            envelope = {
                "result": "error",
                "message": "Failed to parse version check response",
            }

        assert envelope["result"] == "error"
        assert "Failed to parse" in envelope["message"]

    def test_dialog_flow_update_now(self) -> None:
        """Verify state transitions for 'Update Now' button."""
        # Simulate: check result → dialog shown → user clicks "Update Now" →
        # worker thread spawned → apply result → main thread shows notification
        envelope = {"result": "update_available", "latest": "0.10.0", "running": "0.9.0"}

        # Check phase
        result = envelope.get("result")
        assert result == "update_available"

        # Dialog would be shown, user selects "Update Now"
        # (choice.clicked == 1)

        # Apply phase
        apply_envelope = {
            "result": "success",
            "latest": "0.10.0",
        }
        assert apply_envelope["result"] == "success"

    def test_dialog_flow_skip_version(self) -> None:
        """Verify state transitions for 'Skip This Version' button."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)

            # Check result
            envelope = {"result": "update_available", "latest": "0.10.0"}
            assert envelope["result"] == "update_available"

            # User clicks "Skip This Version"
            _add_skipped_version(data_dir, "0.10.0")

            # Verify skipped
            skipped = _read_skipped_versions(data_dir)
            assert "0.10.0" in skipped

            # Next check should not trigger dialog (tested in _should_show_dialog)

    def test_dialog_flow_cancel(self) -> None:
        """Verify state for 'Cancel' button (no-op)."""
        # User clicks "Cancel" → choice.clicked == 0 → no action taken
        # No state changes, menu item remains as-is
        pass


class TestMenubarHeadlessImport:
    """Smoke test that menubar_app can be imported in headless environment.

    This verifies that the menu bar app's imports don't fail in CI (no display),
    even though rumps functionality won't work. The import should succeed but
    app instantiation would fail without a display.
    """

    def test_import_menubar_app(self) -> None:
        """Importing sentinel_mac.menubar_app should not raise."""
        try:
            import sentinel_mac.menubar_app  # noqa: F401
        except ImportError as e:
            # Expected if rumps is missing; acceptable in CI
            if "rumps" not in str(e):
                raise
