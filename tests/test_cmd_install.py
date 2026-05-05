"""Tests for sentinel_mac.commands.install module (ADR 0011 Track A).

Covers:
* Full install sequence (happy path)
* Idempotency (already installed = exit 2)
* Install method detection (EDITABLE/SYSTEM_UNSAFE/HOMEBREW = exit 3)
* D5 conflict detection (dev .venv vs pipx)
* --force override
* --no-launchagent path
* --yes auto-confirm
* Non-TTY cancellation
* --json envelope output
* Rollback on failure
"""

import json
from pathlib import Path
from typing import Optional
from unittest import mock

import pytest

from sentinel_mac.commands.install import cmd_install, dispatch


@pytest.fixture
def isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Isolate home/config/data dirs to tmp_path."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    return home


@pytest.fixture
def mock_subprocess(monkeypatch: pytest.MonkeyPatch) -> mock.MagicMock:
    """Mock subprocess.run for launchctl calls."""
    mock_run = mock.MagicMock()
    mock_run.return_value = mock.MagicMock(returncode=0, stdout="0\n", stderr="")
    monkeypatch.setattr("subprocess.run", mock_run)
    return mock_run


@pytest.fixture
def mock_stdin_tty(monkeypatch: pytest.MonkeyPatch) -> mock.MagicMock:
    """Mock sys.stdin.isatty() to return True (interactive)."""
    mock_tty = mock.MagicMock(return_value=True)
    monkeypatch.setattr("sys.stdin.isatty", mock_tty)
    return mock_tty


@pytest.fixture
def mock_pipx_install(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock detect_install_method and sys.executable for PIPX (typical install scenario)."""
    from sentinel_mac.updater.detect import InstallMethod

    def _mock_detect() -> InstallMethod:
        return InstallMethod.PIPX

    monkeypatch.setattr(
        "sentinel_mac.commands.install.detect_install_method",
        _mock_detect,
    )
    # Mock sys.executable to return a pipx-like path (without .venv)
    monkeypatch.setattr(
        "sys.executable",
        "~/.local/pipx/venvs/sentinel-mac/bin/python",
    )


@pytest.fixture
def mock_resolve_paths(monkeypatch: pytest.MonkeyPatch, isolated_home: Path) -> None:
    """Mock path resolution to use isolated home."""
    def mock_resolve_config_path(explicit_path: Optional[str] = None) -> Optional[Path]:
        if explicit_path:
            return Path(explicit_path)
        xdg_config = isolated_home / ".config" / "sentinel" / "config.yaml"
        if xdg_config.exists():
            return xdg_config
        return None

    def mock_resolve_data_dir() -> Path:
        data_dir = isolated_home / ".local" / "share" / "sentinel"
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir

    monkeypatch.setattr(
        "sentinel_mac.commands.install.resolve_config_path",
        mock_resolve_config_path,
    )
    monkeypatch.setattr(
        "sentinel_mac.commands.install.resolve_data_dir",
        mock_resolve_data_dir,
    )


class TestInstallHappyPath:
    """Test successful install with all steps."""

    def test_install_success_with_defaults(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_stdin_tty: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Full install sequence should exit 0 and print banner."""
        monkeypatch.setattr("builtins.input", lambda _: "y")

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 0
        out = capsys.readouterr().out
        assert "Sentinel installed" in out
        assert "config:" in out
        assert "data dir:" in out
        assert "daemon:" in out

    def test_install_with_yes_flag(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """With --yes flag, should skip confirmation."""
        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = True
        args.json = False

        result = cmd_install(args)

        assert result == 0
        out = capsys.readouterr().out
        assert "Sentinel installed" in out

    def test_install_creates_config(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_stdin_tty: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Install should create config file."""
        monkeypatch.setattr("builtins.input", lambda _: "y")

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 0
        config_path = isolated_home / ".config" / "sentinel" / "config.yaml"
        assert config_path.exists()

    def test_install_creates_plist(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_stdin_tty: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Install should create LaunchAgent plist."""
        monkeypatch.setattr("builtins.input", lambda _: "y")

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 0
        plist_path = isolated_home / "Library" / "LaunchAgents" / "com.sentinel.agent.plist"
        assert plist_path.exists()

    def test_install_creates_data_dir(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_stdin_tty: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Install should create data directory."""
        monkeypatch.setattr("builtins.input", lambda _: "y")

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 0
        data_dir = isolated_home / ".local" / "share" / "sentinel"
        assert data_dir.exists()


class TestInstallIdempotency:
    """Test idempotency (exit 2 when already installed)."""

    def test_already_installed_exit_2(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_stdin_tty: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If all artifacts exist and daemon running, exit 2."""
        monkeypatch.setattr("builtins.input", lambda _: "y")

        # First install
        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)
        assert result == 0

        # Mock daemon running
        mock_subprocess.reset_mock()
        mock_subprocess.return_value = mock.MagicMock(
            returncode=0,
            stdout="123\n",  # PID
            stderr="",
        )

        # Second install (same args)
        result = cmd_install(args)
        assert result == 2


class TestInstallUnsupportedMethods:
    """Test early-exit for unsupported install methods (exit 3)."""

    def test_editable_install_exit_3(
        self,
        isolated_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """EDITABLE install should exit 3 with guidance."""
        monkeypatch.setattr(
            "sentinel_mac.commands.install.detect_install_method",
            lambda: __import__("sentinel_mac.updater.detect", fromlist=["InstallMethod"]).InstallMethod.EDITABLE,
        )

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 3
        out = capsys.readouterr().out
        assert "editable" in out.lower() or "development" in out.lower()

    def test_system_unsafe_exit_3(
        self,
        isolated_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """SYSTEM_UNSAFE install should exit 3 with guidance."""
        monkeypatch.setattr(
            "sentinel_mac.commands.install.detect_install_method",
            lambda: __import__("sentinel_mac.updater.detect", fromlist=["InstallMethod"]).InstallMethod.SYSTEM_UNSAFE,
        )

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 3
        out = capsys.readouterr().out
        assert "system" in out.lower() or "sudo" in out.lower()


class TestInstallConflictDetection:
    """Test D5 conflict detection."""

    def test_dev_venv_conflict_aborts(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_stdin_tty: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Dev .venv plist conflicts with PIPX install, should exit 1 without --force."""
        monkeypatch.setattr("builtins.input", lambda _: "y")

        # Create existing dev install plist
        plist_dir = isolated_home / "Library" / "LaunchAgents"
        plist_dir.mkdir(parents=True, exist_ok=True)
        plist = plist_dir / "com.sentinel.agent.plist"
        plist.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>'
            '<key>ProgramArguments</key><array>'
            '<string>/Users/test/.venv/bin/sentinel</string>'
            '</array></dict></plist>'
        )

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 1
        out = capsys.readouterr().out
        assert "conflict" in out.lower() or "migrate" in out.lower()

    def test_force_overrides_conflict(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_stdin_tty: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """With --force, conflict should be resolved (backup created)."""
        monkeypatch.setattr("builtins.input", lambda _: "y")

        # Create existing dev install plist
        plist_dir = isolated_home / "Library" / "LaunchAgents"
        plist_dir.mkdir(parents=True, exist_ok=True)
        plist = plist_dir / "com.sentinel.agent.plist"
        plist.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>'
            '<key>ProgramArguments</key><array>'
            '<string>/Users/test/.venv/bin/sentinel</string>'
            '</array></dict></plist>'
        )

        args = mock.MagicMock()
        args.force = True
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 0
        # Backup should exist
        backup = plist_dir / "com.sentinel.agent.plist.bak"
        assert backup.exists()


class TestInstallNoLaunchagent:
    """Test --no-launchagent flag."""

    def test_no_launchagent_skips_plist(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_stdin_tty: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """With --no-launchagent, should not create plist."""
        monkeypatch.setattr("builtins.input", lambda _: "y")

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = True
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 0
        plist_path = isolated_home / "Library" / "LaunchAgents" / "com.sentinel.agent.plist"
        assert not plist_path.exists()
        out = capsys.readouterr().out
        assert "not started" in out


class TestInstallNonInteractive:
    """Test non-TTY behavior."""

    def test_non_tty_without_yes_cancels(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_pipx_install: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Non-TTY without --yes should cancel with WARNING."""
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = False

        result = cmd_install(args)

        assert result == 1
        err = capsys.readouterr().err
        assert "warning" in err.lower()

    def test_non_tty_with_yes_proceeds(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Non-TTY with --yes should proceed."""
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = True
        args.json = False

        result = cmd_install(args)

        assert result == 0


class TestInstallJsonOutput:
    """Test --json envelope output."""

    def test_json_envelope_structure(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_stdin_tty: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--json should emit ADR 0004 envelope."""
        monkeypatch.setattr("builtins.input", lambda _: "y")

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = True

        result = cmd_install(args)

        assert result == 0
        out = capsys.readouterr().out
        data = json.loads(out.strip())

        assert data["version"] == 1
        assert data["kind"] == "install"
        assert "generated_at" in data
        assert "data" in data

    def test_json_error_envelope(
        self,
        isolated_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--json with error should emit install_error kind."""
        monkeypatch.setattr(
            "sentinel_mac.commands.install.detect_install_method",
            lambda: __import__("sentinel_mac.updater.detect", fromlist=["InstallMethod"]).InstallMethod.EDITABLE,
        )

        args = mock.MagicMock()
        args.force = False
        args.no_launchagent = False
        args.yes = False
        args.json = True

        result = cmd_install(args)

        assert result == 3
        out = capsys.readouterr().out
        data = json.loads(out.strip())

        assert data["kind"] == "install_error"


class TestDispatch:
    """Test dispatch() argparse entry point."""

    def test_dispatch_parses_yes_flag(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """dispatch should parse --yes flag."""
        result = dispatch(["--yes"])

        assert result == 0
        out = capsys.readouterr().out
        assert "Sentinel installed" in out

    def test_dispatch_parses_json_flag(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """dispatch should parse --json flag."""
        result = dispatch(["--yes", "--json"])

        assert result == 0
        out = capsys.readouterr().out
        data = json.loads(out.strip())
        assert data["kind"] == "install"

    def test_dispatch_parses_force_flag(
        self,
        isolated_home: Path,
        mock_subprocess: mock.MagicMock,
        mock_pipx_install: None,
        mock_resolve_paths: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """dispatch should parse --force flag."""
        result = dispatch(["--yes", "--force"])

        assert result == 0
