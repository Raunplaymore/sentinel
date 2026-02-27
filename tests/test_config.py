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
