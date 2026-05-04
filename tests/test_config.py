"""Tests for configuration loading and validation."""
import json
from pathlib import Path

from sentinel_mac import core as core_mod
from sentinel_mac.core import (
    DEFAULT_CONFIG,
    _print_version_snapshot,
    _validate_config,
    _version_config_line,
    _version_daemon_line,
    _version_data_dir_line,
    _version_hook_line,
    load_config,
    resolve_config_path,
)


class TestLoadConfig:
    """Tests for load_config function."""

    def test_defaults_when_no_path(self):
        config = load_config(None)
        assert config["check_interval_seconds"] == 30
        assert config["ntfy_topic"] == "sentinel-default"
        assert config["thresholds"]["battery_warning"] == 20

    def test_load_valid_yaml(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text('ntfy_topic: "my-topic"\ncheck_interval_seconds: 60\n')
        config = load_config(cfg)
        assert config["ntfy_topic"] == "my-topic"
        assert config["check_interval_seconds"] == 60
        # Defaults should still be present
        assert config["cooldown_minutes"] == 10

    def test_merge_thresholds(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("thresholds:\n  battery_warning: 30\n")
        config = load_config(cfg)
        assert config["thresholds"]["battery_warning"] == 30
        # Other thresholds should retain defaults
        assert config["thresholds"]["temp_warning"] == 85

    def test_missing_file_returns_defaults(self, tmp_path):
        config = load_config(tmp_path / "nonexistent.yaml")
        assert config == load_config(None)

    def test_invalid_yaml_returns_defaults(self, tmp_path):
        cfg = tmp_path / "bad.yaml"
        cfg.write_text(":::invalid yaml{{{\n")
        config = load_config(cfg)
        assert config["check_interval_seconds"] == 30

    def test_empty_yaml_returns_defaults(self, tmp_path):
        cfg = tmp_path / "empty.yaml"
        cfg.write_text("")
        config = load_config(cfg)
        assert config["check_interval_seconds"] == 30


class TestValidateConfig:
    """Tests for _validate_config function."""

    def test_valid_config_unchanged(self):
        config = {
            "check_interval_seconds": 30,
            "status_interval_minutes": 60,
            "cooldown_minutes": 10,
            "thresholds": DEFAULT_CONFIG["thresholds"].copy(),
        }
        result = _validate_config(config)
        assert result["check_interval_seconds"] == 30

    def test_negative_interval_uses_default(self):
        config = {
            "check_interval_seconds": -5,
            "status_interval_minutes": 60,
            "cooldown_minutes": 10,
            "thresholds": DEFAULT_CONFIG["thresholds"].copy(),
        }
        result = _validate_config(config)
        assert result["check_interval_seconds"] == DEFAULT_CONFIG["check_interval_seconds"]

    def test_too_large_interval_clamped(self):
        config = {
            "check_interval_seconds": 99999,
            "status_interval_minutes": 60,
            "cooldown_minutes": 10,
            "thresholds": DEFAULT_CONFIG["thresholds"].copy(),
        }
        result = _validate_config(config)
        assert result["check_interval_seconds"] == 3600

    def test_string_value_uses_default(self):
        config = {
            "check_interval_seconds": "not a number",
            "status_interval_minutes": 60,
            "cooldown_minutes": 10,
            "thresholds": DEFAULT_CONFIG["thresholds"].copy(),
        }
        result = _validate_config(config)
        assert result["check_interval_seconds"] == DEFAULT_CONFIG["check_interval_seconds"]

    def test_negative_threshold_uses_default(self):
        config = {
            "check_interval_seconds": 30,
            "status_interval_minutes": 60,
            "cooldown_minutes": 10,
            "thresholds": {
                **DEFAULT_CONFIG["thresholds"],
                "battery_warning": -10,
            },
        }
        result = _validate_config(config)
        assert result["thresholds"]["battery_warning"] == DEFAULT_CONFIG["thresholds"]["battery_warning"]

    def test_invalid_thresholds_type_replaced(self):
        config = {
            "check_interval_seconds": 30,
            "status_interval_minutes": 60,
            "cooldown_minutes": 10,
            "thresholds": "not a dict",
        }
        result = _validate_config(config)
        assert isinstance(result["thresholds"], dict)
        assert result["thresholds"]["battery_warning"] == 20


class TestContextLevelValidation:
    """ADR 0008 D5 — fail-soft validation of notifications.context_level.

    Unknown values fall back to "standard" + WARNING; never raise.
    Missing key is silent (engine treats absence as "standard" by
    default in __init__).
    """

    def _base_config(self):
        return {
            "check_interval_seconds": 30,
            "status_interval_minutes": 60,
            "cooldown_minutes": 10,
            "thresholds": DEFAULT_CONFIG["thresholds"].copy(),
        }

    def test_valid_minimal_unchanged(self):
        cfg = self._base_config()
        cfg["notifications"] = {"context_level": "minimal"}
        result = _validate_config(cfg)
        assert result["notifications"]["context_level"] == "minimal"

    def test_valid_standard_unchanged(self):
        cfg = self._base_config()
        cfg["notifications"] = {"context_level": "standard"}
        result = _validate_config(cfg)
        assert result["notifications"]["context_level"] == "standard"

    def test_valid_full_unchanged(self):
        cfg = self._base_config()
        cfg["notifications"] = {"context_level": "full"}
        result = _validate_config(cfg)
        assert result["notifications"]["context_level"] == "full"

    def test_unknown_value_falls_back_to_standard(self, caplog):
        cfg = self._base_config()
        cfg["notifications"] = {"context_level": "full_disclosure"}
        import logging as _logging
        with caplog.at_level(_logging.WARNING):
            result = _validate_config(cfg)
        # Fail-soft normalization (ADR 0008 D5).
        assert result["notifications"]["context_level"] == "standard"
        # WARNING was logged once.
        warnings = [r for r in caplog.records if r.levelno == _logging.WARNING]
        assert any(
            "context_level" in r.getMessage() for r in warnings
        )

    def test_missing_key_silent_default(self, caplog):
        cfg = self._base_config()
        cfg["notifications"] = {"ntfy_topic": "x"}  # no context_level
        import logging as _logging
        with caplog.at_level(_logging.WARNING):
            result = _validate_config(cfg)
        # Key still missing; the engine __init__ defaults to "standard".
        assert "context_level" not in result["notifications"]
        # No WARNING for the absent key.
        assert not any(
            "context_level" in r.getMessage()
            for r in caplog.records
            if r.levelno == _logging.WARNING
        )

    def test_missing_notifications_section_silent(self):
        cfg = self._base_config()
        result = _validate_config(cfg)
        # No notifications section — validation simply skips the check.
        assert "notifications" not in result or "context_level" not in (
            result.get("notifications") or {}
        )

    def test_reload_validation_does_not_raise_on_invalid_level(self):
        """ADR 0005 §D3 atomic-or-nothing: a bad context_level must NOT
        abort the reload. _validate_reload_config normalizes the value
        in-place rather than raising."""
        # Late import to avoid a top-level dependency on Sentinel class.
        from unittest.mock import MagicMock

        from sentinel_mac import core as _core
        from sentinel_mac.core import Sentinel as _Sentinel  # noqa: F401

        # Borrow the validator off an instance without running __init__
        # (which has heavy side effects). The method only touches its
        # `new_config` argument.
        instance = MagicMock(spec=_Sentinel)
        bad = {"notifications": {"context_level": "totally_not_valid"}}
        # Bind the unbound method explicitly.
        _core.Sentinel._validate_reload_config(instance, bad)
        # Normalized in place; no exception raised.
        assert bad["notifications"]["context_level"] == "standard"


class TestResolveConfigPath:
    """Tests for resolve_config_path function."""

    def test_explicit_path(self, tmp_path):
        p = str(tmp_path / "my.yaml")
        assert resolve_config_path(p) == Path(p)

    def test_none_when_no_config_found(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
        result = resolve_config_path()
        assert result is None


class TestVersionOutput:
    """v0.9 Track 3b — `sentinel --version` snapshot.

    The output:
        sentinel-mac X.Y.Z
        <blank>
          config:    ...
          data dir:  ...
          daemon:    ...
          CC hook:   ...

    First line MUST keep the legacy ``sentinel-mac X.Y.Z`` shape so
    scripts that grep the version out keep working. Each subsequent
    line is best-effort — never raises.
    """

    def _isolate_environment(self, monkeypatch, tmp_path):
        """Point HOME and CWD into tmp_path so the snapshot reads
        a known-empty environment instead of whatever the developer
        machine actually has installed.

        Without this, --version probes ~/.config/sentinel/config.yaml,
        ~/.local/share/sentinel/sentinel.lock, and
        ~/.claude/settings.json on the real filesystem — making the
        test results depend on the contributor's machine state.
        """
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setattr(Path, "home", lambda: fake_home)
        monkeypatch.chdir(tmp_path)
        # CLAUDE_SETTINGS_PATH is computed at import time from
        # Path.home(); override the module-level constant too so the
        # hook check actually inspects the fake home.
        monkeypatch.setattr(
            core_mod, "CLAUDE_SETTINGS_PATH",
            fake_home / ".claude" / "settings.json",
        )
        return fake_home

    def test_version_snapshot_first_line_legacy_shape(
        self, capsys, monkeypatch, tmp_path,
    ):
        """First line must be ``sentinel-mac X.Y.Z`` for grep-out scripts."""
        from sentinel_mac import __version__
        self._isolate_environment(monkeypatch, tmp_path)
        _print_version_snapshot()
        out = capsys.readouterr().out
        first_line = out.splitlines()[0]
        assert first_line == f"sentinel-mac {__version__}"

    def test_version_snapshot_includes_all_four_lines(
        self, capsys, monkeypatch, tmp_path,
    ):
        """Each of the four enrichment lines must be present."""
        self._isolate_environment(monkeypatch, tmp_path)
        _print_version_snapshot()
        out = capsys.readouterr().out
        assert "config:" in out
        assert "data dir:" in out
        assert "daemon:" in out
        assert "CC hook:" in out

    def test_config_line_when_no_config_found(self, monkeypatch, tmp_path):
        """No config file anywhere → 'not configured (...)' message."""
        self._isolate_environment(monkeypatch, tmp_path)
        line = _version_config_line()
        assert "not configured" in line
        assert "sentinel --init-config" in line

    def test_config_line_when_xdg_config_exists(self, monkeypatch, tmp_path):
        """XDG-located config → its path is reported."""
        fake_home = self._isolate_environment(monkeypatch, tmp_path)
        cfg_dir = fake_home / ".config" / "sentinel"
        cfg_dir.mkdir(parents=True)
        cfg_file = cfg_dir / "config.yaml"
        cfg_file.write_text("ntfy_topic: x\n")
        line = _version_config_line()
        assert line == str(cfg_file)

    def test_data_dir_line_returns_a_path(self, monkeypatch, tmp_path):
        """Data dir is always a real path (resolve_data_dir mkdirs it)."""
        self._isolate_environment(monkeypatch, tmp_path)
        line = _version_data_dir_line()
        # Either the in-tree ./logs (cwd-relative) or the XDG dir.
        assert line  # non-empty
        assert "/" in line

    def test_daemon_line_when_no_lock_file(self, monkeypatch, tmp_path):
        """No lock file → 'not running'."""
        self._isolate_environment(monkeypatch, tmp_path)
        line = _version_daemon_line()
        assert line == "not running"

    def test_daemon_line_when_lock_unheld(self, monkeypatch, tmp_path):
        """Lock file exists but no daemon holds it → 'not running'.

        The version snapshot probes the lock with a non-blocking
        flock; if it acquires the lock, the daemon is not running.
        """
        from sentinel_mac.core import daemon_lock_path
        self._isolate_environment(monkeypatch, tmp_path)
        # Touch the lock file so it exists but is unheld.
        lock = daemon_lock_path()
        lock.write_text("")
        line = _version_daemon_line()
        assert line == "not running"

    def test_hook_line_when_settings_missing(self, monkeypatch, tmp_path):
        """No ~/.claude/settings.json → 'not installed (...)'."""
        self._isolate_environment(monkeypatch, tmp_path)
        line = _version_hook_line()
        assert "not installed" in line

    def test_hook_line_when_hook_installed(self, monkeypatch, tmp_path):
        """Sentinel hook present in PreToolUse → 'installed'."""
        fake_home = self._isolate_environment(monkeypatch, tmp_path)
        settings_path = fake_home / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command",
                             "command": "/usr/local/bin/sentinel hook-check"},
                        ],
                    },
                ],
            },
        }))
        line = _version_hook_line()
        assert line == "installed"

    def test_hook_line_when_hook_missing_from_settings(
        self, monkeypatch, tmp_path,
    ):
        """Settings exist but no Sentinel hook → 'not installed (...)'."""
        fake_home = self._isolate_environment(monkeypatch, tmp_path)
        settings_path = fake_home / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps({"hooks": {"PreToolUse": []}}))
        line = _version_hook_line()
        assert "not installed" in line
        assert "sentinel hooks install" in line

    def test_hook_line_when_settings_corrupt(self, monkeypatch, tmp_path):
        """Malformed JSON in settings → 'unknown (...)' (no crash)."""
        fake_home = self._isolate_environment(monkeypatch, tmp_path)
        settings_path = fake_home / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{not json")
        line = _version_hook_line()
        assert "unknown" in line

    def test_version_snapshot_never_raises_on_corrupt_settings(
        self, capsys, monkeypatch, tmp_path,
    ):
        """End-to-end: corrupt hook settings must degrade gracefully."""
        fake_home = self._isolate_environment(monkeypatch, tmp_path)
        settings_path = fake_home / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{invalid")
        # Must not raise.
        _print_version_snapshot()
        out = capsys.readouterr().out
        assert "sentinel-mac" in out
        # Hook line shows "unknown (...)"
        assert "unknown" in out
