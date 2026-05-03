"""Tests for configuration loading and validation."""
import pytest
import tempfile
from pathlib import Path

from sentinel_mac.core import (
    DEFAULT_CONFIG,
    load_config,
    _validate_config,
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
        from sentinel_mac.core import Sentinel as _Sentinel  # noqa: F401
        from unittest.mock import MagicMock
        from sentinel_mac import core as _core

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
