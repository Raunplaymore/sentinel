"""Tests for the `event_log_retention_days` config key (v0.11)."""

import logging
import tempfile

import pytest

from sentinel_mac.core import DEFAULT_CONFIG, _resolve_event_log_retention
from sentinel_mac.event_logger import EventLogger


class TestResolveEventLogRetention:
    """Tests for `_resolve_event_log_retention(config)` validation.

    Returns:
        - positive int if the config value is a valid positive int
        - None on missing/invalid (caller falls back to
          EventLogger.DEFAULT_RETENTION_DAYS)
    """

    def test_default_config_is_90(self) -> None:
        """The default DEFAULT_CONFIG entry resolves to 90."""
        assert _resolve_event_log_retention(DEFAULT_CONFIG) == 90

    def test_missing_key_returns_none(self) -> None:
        """When the key is absent the helper returns None (use logger default)."""
        assert _resolve_event_log_retention({}) is None

    def test_explicit_none_returns_none(self) -> None:
        """Explicit `event_log_retention_days: null` is treated as missing."""
        assert _resolve_event_log_retention({"event_log_retention_days": None}) is None

    def test_valid_positive_int_returned_verbatim(self) -> None:
        """Positive int passes through unchanged."""
        assert _resolve_event_log_retention({"event_log_retention_days": 30}) == 30
        assert _resolve_event_log_retention({"event_log_retention_days": 365}) == 365
        assert _resolve_event_log_retention({"event_log_retention_days": 1}) == 1

    def test_zero_falls_back_with_warning(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Zero is rejected (would prune everything immediately)."""
        with caplog.at_level(logging.WARNING):
            assert _resolve_event_log_retention({"event_log_retention_days": 0}) is None
        assert "positive integer" in caplog.text

    def test_negative_falls_back_with_warning(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Negative values are rejected."""
        with caplog.at_level(logging.WARNING):
            result = _resolve_event_log_retention({"event_log_retention_days": -7})
        assert result is None
        assert "positive integer" in caplog.text

    def test_string_falls_back_with_warning(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Strings (including numeric strings) are rejected — YAML quoting bug."""
        with caplog.at_level(logging.WARNING):
            result = _resolve_event_log_retention(
                {"event_log_retention_days": "30"},
            )
        assert result is None
        assert "positive integer" in caplog.text

    def test_float_falls_back_with_warning(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Floats are rejected — retention is in whole days."""
        with caplog.at_level(logging.WARNING):
            result = _resolve_event_log_retention(
                {"event_log_retention_days": 30.5},
            )
        assert result is None

    def test_bool_true_falls_back_with_warning(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """`True` is `int` in Python (bool subclasses int) — must be rejected
        explicitly so a YAML `true` does not silently become 1 day."""
        with caplog.at_level(logging.WARNING):
            result = _resolve_event_log_retention(
                {"event_log_retention_days": True},
            )
        assert result is None

    def test_bool_false_falls_back_with_warning(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """`False` (== int 0) is also rejected via the bool guard."""
        with caplog.at_level(logging.WARNING):
            result = _resolve_event_log_retention(
                {"event_log_retention_days": False},
            )
        assert result is None


class TestEventLoggerHonorsRetention:
    """Round-trip: resolved value reaches the EventLogger constructor."""

    def test_default_constructor_uses_logger_default(self) -> None:
        """No `retention_days` kwarg → EventLogger.DEFAULT_RETENTION_DAYS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = EventLogger(tmpdir)
            assert logger._retention_days == EventLogger.DEFAULT_RETENTION_DAYS
            logger.close()

    def test_explicit_retention_kwarg(self) -> None:
        """Positive int kwarg overrides the default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = EventLogger(tmpdir, retention_days=7)
            assert logger._retention_days == 7
            logger.close()

    def test_none_kwarg_uses_default(self) -> None:
        """`retention_days=None` falls back to DEFAULT_RETENTION_DAYS — this
        is the path used when the helper rejects a malformed config value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = EventLogger(tmpdir, retention_days=None)
            assert logger._retention_days == EventLogger.DEFAULT_RETENTION_DAYS
            logger.close()
