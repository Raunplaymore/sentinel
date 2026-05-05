"""Tests for sentinel_mac.installer.plist module (ADR 0011 Track A).

Covers:
* Plist XML generation (valid structure, correct fields)
* Write with proper permissions
* Existing plist parsing for conflict detection (D5)
"""

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from sentinel_mac.installer.plist import (
    existing_plist_install_method,
    generate_plist,
    plist_path,
    write_plist,
)


class TestPlistPath:
    """Test plist_path() helper."""

    def test_plist_path_returns_launchagents_dir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Plist path should be ~/Library/LaunchAgents/com.sentinel.agent.plist."""
        fake_home = Path("/fake/home")
        monkeypatch.setattr(Path, "home", lambda: fake_home)
        result = plist_path()
        assert str(result) == "/fake/home/Library/LaunchAgents/com.sentinel.agent.plist"


class TestGeneratePlist:
    """Test generate_plist() pure function."""

    def test_generate_plist_is_valid_xml(self, tmp_path: Path) -> None:
        """Generated plist XML must be parseable."""
        binary = tmp_path / "sentinel"
        data_dir = tmp_path / "data"

        xml_str = generate_plist(binary, data_dir)

        # Should parse without error
        root = ET.fromstring(xml_str)
        assert root.tag == "plist"

    def test_generate_plist_contains_label(self, tmp_path: Path) -> None:
        """Plist must contain Label key with 'com.sentinel.agent'."""
        binary = tmp_path / "sentinel"
        data_dir = tmp_path / "data"

        xml_str = generate_plist(binary, data_dir)
        root = ET.fromstring(xml_str)

        # Find Label in dict
        dict_elem = root.find("dict")
        assert dict_elem is not None

        keys = [elem.text for elem in dict_elem.findall("key")]
        assert "Label" in keys

    def test_generate_plist_has_program_arguments(self, tmp_path: Path) -> None:
        """Plist must contain ProgramArguments array with binary path."""
        binary = tmp_path / "sentinel"
        data_dir = tmp_path / "data"

        xml_str = generate_plist(binary, data_dir)
        root = ET.fromstring(xml_str)

        dict_elem = root.find("dict")
        assert dict_elem is not None

        # Find ProgramArguments
        keys = list(dict_elem.findall("key"))
        values = []
        for _i, key in enumerate(keys):
            if key.text == "ProgramArguments":
                # Next element should be array
                idx = list(dict_elem).index(key)
                if idx + 1 < len(dict_elem):
                    next_elem = list(dict_elem)[idx + 1]
                    if next_elem.tag == "array":
                        strings = next_elem.findall("string")
                        values = [s.text for s in strings]
                        break

        assert str(binary) in values

    def test_generate_plist_has_stdout_stderr(self, tmp_path: Path) -> None:
        """Plist must have StandardOutPath and StandardErrorPath."""
        binary = tmp_path / "sentinel"
        data_dir = tmp_path / "data"

        xml_str = generate_plist(binary, data_dir)
        root = ET.fromstring(xml_str)

        dict_elem = root.find("dict")
        assert dict_elem is not None

        keys = [elem.text for elem in dict_elem.findall("key")]
        assert "StandardOutPath" in keys
        assert "StandardErrorPath" in keys

    def test_generate_plist_has_keep_alive(self, tmp_path: Path) -> None:
        """Plist must have KeepAlive set to true."""
        binary = tmp_path / "sentinel"
        data_dir = tmp_path / "data"

        xml_str = generate_plist(binary, data_dir)
        # Check for <true/> or <true></true> after KeepAlive key
        assert "<key>KeepAlive</key>" in xml_str
        assert "<true" in xml_str or "<true/>" in xml_str

    def test_generate_plist_has_run_at_load(self, tmp_path: Path) -> None:
        """Plist must have RunAtLoad set to true."""
        binary = tmp_path / "sentinel"
        data_dir = tmp_path / "data"

        xml_str = generate_plist(binary, data_dir)
        assert "<key>RunAtLoad</key>" in xml_str


class TestWritePlist:
    """Test write_plist() function."""

    def test_write_plist_creates_file(self, tmp_path: Path) -> None:
        """write_plist should create the file."""
        plist = tmp_path / "test.plist"
        binary = tmp_path / "sentinel"
        data_dir = tmp_path / "data"

        content = generate_plist(binary, data_dir)
        write_plist(content, plist)

        assert plist.exists()

    def test_write_plist_sets_permissions(self, tmp_path: Path) -> None:
        """write_plist should set 0o644 permissions."""
        plist = tmp_path / "test.plist"
        binary = tmp_path / "sentinel"
        data_dir = tmp_path / "data"

        content = generate_plist(binary, data_dir)
        write_plist(content, plist)

        stat_info = plist.stat()
        # Check permissions (mask to relevant bits)
        mode = stat_info.st_mode & 0o777
        assert mode == 0o644

    def test_write_plist_creates_parent_dirs(self, tmp_path: Path) -> None:
        """write_plist should create parent directories."""
        plist = tmp_path / "a" / "b" / "c" / "test.plist"
        binary = tmp_path / "sentinel"
        data_dir = tmp_path / "data"

        content = generate_plist(binary, data_dir)
        write_plist(content, plist)

        assert plist.exists()
        assert plist.parent == tmp_path / "a" / "b" / "c"


class TestExistingPlistInstallMethod:
    """Test existing_plist_install_method() for D5 conflict detection."""

    def test_missing_plist_returns_none(self, tmp_path: Path) -> None:
        """If plist doesn't exist, should return None."""
        plist = tmp_path / "missing.plist"
        result = existing_plist_install_method(plist)
        assert result is None

    def test_pipx_plist_detected(self, tmp_path: Path) -> None:
        """Should detect pipx install from /.local/pipx/ path."""
        plist = tmp_path / "test.plist"
        binary = Path("~/.local/pipx/venvs/sentinel-mac/bin/sentinel").expanduser()
        data_dir = tmp_path / "data"

        content = generate_plist(binary, data_dir)
        write_plist(content, plist)

        result = existing_plist_install_method(plist)
        assert result == "pipx"

    def test_pip_venv_plist_detected(self, tmp_path: Path) -> None:
        """Should detect pip venv install from /.venv/ path."""
        plist = tmp_path / "test.plist"
        binary = tmp_path / "sentinel_project" / ".venv" / "bin" / "sentinel"
        data_dir = tmp_path / "data"

        content = generate_plist(binary, data_dir)
        write_plist(content, plist)

        result = existing_plist_install_method(plist)
        assert result == "pip-venv"

    def test_malformed_plist_returns_unknown(self, tmp_path: Path) -> None:
        """Should return 'unknown' for malformed plist."""
        plist = tmp_path / "test.plist"
        plist.write_text("not valid xml")

        result = existing_plist_install_method(plist)
        assert result == "unknown"

    def test_plist_without_program_arguments_returns_unknown(self, tmp_path: Path) -> None:
        """Should return 'unknown' if no ProgramArguments key."""
        plist = tmp_path / "test.plist"
        plist.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict><key>Label</key><string>test</string></dict></plist>'
        )

        result = existing_plist_install_method(plist)
        assert result == "unknown"
