"""Tests for sentinel_mac.updater.detect (ADR 0010 §D1)."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from sentinel_mac.updater.detect import (
    InstallMethod,
    detect_install_method,
    get_source_root,
)


class TestGetSourceRoot:
    """Test source root detection for editable installs."""

    def test_finds_pyproject_toml_in_parent(self) -> None:
        """Should find pyproject.toml by walking up from sentinel_mac/__file__."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            sentinel_dir = tmp_path / "sentinel_mac"
            sentinel_dir.mkdir()
            (sentinel_dir / "__init__.py").touch()
            (tmp_path / "pyproject.toml").touch()

            with patch("sentinel_mac.__file__", str(sentinel_dir / "__init__.py")):
                root = get_source_root()
                assert root == tmp_path

    def test_returns_none_if_no_pyproject_toml(self) -> None:
        """Should return None if pyproject.toml not found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            sentinel_dir = tmp_path / "sentinel_mac"
            sentinel_dir.mkdir()
            (sentinel_dir / "__init__.py").touch()

            with patch("sentinel_mac.__file__", str(sentinel_dir / "__init__.py")):
                root = get_source_root()
                assert root is None


class TestDetectInstallMethod:
    """Test install method detection heuristics."""

    def test_detects_editable_with_egg_link(self) -> None:
        """Should detect EDITABLE when .egg-link is in path."""
        with patch("sys.executable", "/usr/local/bin/python3"), \
             patch("sentinel_mac.__file__", "/path/to/site-packages/sentinel_mac.egg-link"):
            assert detect_install_method() == InstallMethod.EDITABLE

    def test_detects_editable_with_editable_string(self) -> None:
        """Should detect EDITABLE when __editable__ is in path."""
        with patch("sys.executable", "/usr/local/bin/python3"), \
             patch("sentinel_mac.__file__", "/path/__editable__/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.EDITABLE

    def test_detects_editable_with_pyproject_toml(self) -> None:
        """Should detect EDITABLE when pyproject.toml exists in source tree."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            sentinel_dir = tmp_path / "sentinel_mac"
            sentinel_dir.mkdir()
            (tmp_path / "pyproject.toml").touch()

            with patch("sys.executable", "/usr/local/bin/python3"), \
                 patch("sentinel_mac.__file__", str(sentinel_dir / "__init__.py")):
                assert detect_install_method() == InstallMethod.EDITABLE

    def test_detects_pipx_from_executable_path(self) -> None:
        """Should detect PIPX when executable is under /.local/pipx/venvs/."""
        with patch("sys.executable", "/home/user/.local/pipx/venvs/sentinel-mac/bin/python"), \
             patch("sentinel_mac.__file__", "/tmp/site-packages/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.PIPX

    def test_detects_pipx_from_env_var(self) -> None:
        """Should detect PIPX when PIPX_HOME env var is set and executable is inside."""
        pipx_home = "/custom/pipx/home"
        with patch("sys.executable", "/custom/pipx/home/venvs/sentinel-mac/bin/python"), \
             patch("os.environ.get") as mock_getenv, \
             patch("sentinel_mac.__file__", "/tmp/site-packages/sentinel_mac/__init__.py"):
            mock_getenv.side_effect = lambda key, default="": pipx_home if key == "PIPX_HOME" else default
            assert detect_install_method() == InstallMethod.PIPX

    def test_detects_homebrew_opt_homebrew(self) -> None:
        """Should detect HOMEBREW when executable is under /opt/homebrew/."""
        with patch("sys.executable", "/opt/homebrew/bin/python3"), \
             patch("sentinel_mac.__file__", "/tmp/site-packages/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.HOMEBREW

    def test_detects_homebrew_usr_local_cellar(self) -> None:
        """Should detect HOMEBREW when executable is under /usr/local/Cellar/."""
        with patch("sys.executable", "/usr/local/Cellar/python@3.11/3.11.0/bin/python3"), \
             patch("sentinel_mac.__file__", "/tmp/site-packages/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.HOMEBREW

    def test_detects_pip_venv(self) -> None:
        """Should detect PIP_VENV when executable is under /.venv/ or /venv/."""
        with patch("sys.executable", "/home/user/project/.venv/bin/python"), \
             patch("sentinel_mac.__file__", "/tmp/site-packages/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.PIP_VENV

        with patch("sys.executable", "/home/user/project/venv/bin/python"), \
             patch("sentinel_mac.__file__", "/tmp/site-packages/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.PIP_VENV

    def test_detects_system_unsafe_usr_bin(self) -> None:
        """Should detect SYSTEM_UNSAFE for /usr/bin/python3."""
        with patch("sys.executable", "/usr/bin/python3"), \
             patch("sentinel_mac.__file__", "/tmp/site-packages/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.SYSTEM_UNSAFE

    def test_detects_system_unsafe_usr_local_bin(self) -> None:
        """Should detect SYSTEM_UNSAFE for /usr/local/bin/python3."""
        with patch("sys.executable", "/usr/local/bin/python3"), \
             patch("sentinel_mac.__file__", "/tmp/site-packages/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.SYSTEM_UNSAFE

    def test_editable_priority_over_pipx(self) -> None:
        """EDITABLE should take priority over PIPX."""
        with patch("sys.executable", "/home/user/.local/pipx/venvs/sentinel-mac/bin/python"), \
             patch("sentinel_mac.__file__", "/path/__editable__/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.EDITABLE

    def test_fallback_to_pip_venv(self) -> None:
        """Should fallback to PIP_VENV for unknown executable paths."""
        with patch("sys.executable", "/some/random/path/python"), \
             patch("sentinel_mac.__file__", "/tmp/site-packages/sentinel_mac/__init__.py"):
            assert detect_install_method() == InstallMethod.PIP_VENV
