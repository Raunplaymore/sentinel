"""Tests for NtfyNotifier."""
import pytest
from unittest.mock import patch, MagicMock

from sentinel_mac.core import NtfyNotifier, Alert, DEFAULT_CONFIG


class TestNtfyNotifier:

    def test_disabled_does_not_send(self):
        config = {**DEFAULT_CONFIG, "notifications_enabled": False}
        notifier = NtfyNotifier(config)
        alert = Alert(level="info", category="test", title="Test", message="msg")
        with patch("requests.post") as mock_post:
            notifier.send(alert)
            mock_post.assert_not_called()

    def test_successful_send(self):
        notifier = NtfyNotifier(DEFAULT_CONFIG)
        alert = Alert(level="info", category="test", title="Test", message="msg")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp) as mock_post:
            notifier.send(alert)
            mock_post.assert_called_once()

    def test_failed_send_queued_for_retry(self):
        notifier = NtfyNotifier(DEFAULT_CONFIG)
        alert = Alert(level="info", category="test", title="Test", message="msg")
        with patch("requests.post", side_effect=Exception("network error")):
            notifier.send(alert)
        assert len(notifier._retry_queue) == 1

    def test_retry_succeeds(self):
        notifier = NtfyNotifier(DEFAULT_CONFIG)
        alert = Alert(level="info", category="test", title="Test", message="msg")

        # First send fails
        with patch("requests.post", side_effect=Exception("network error")):
            notifier.send(alert)
        assert len(notifier._retry_queue) == 1

        # Next send triggers flush — retry succeeds
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp):
            notifier.send(alert)
        assert len(notifier._retry_queue) == 0

    def test_retry_exhausted_after_max(self):
        notifier = NtfyNotifier(DEFAULT_CONFIG)
        alert = Alert(level="info", category="test", title="Test", message="msg")

        # Manually add an alert at max retries
        notifier._retry_queue.append((alert, NtfyNotifier.MAX_RETRIES))

        # Flush with failure — should be dropped
        with patch("requests.post", side_effect=Exception("fail")):
            notifier._flush_retries()
        assert len(notifier._retry_queue) == 0

    def test_priority_mapping(self):
        notifier = NtfyNotifier(DEFAULT_CONFIG)
        alert = Alert(level="critical", category="test", title="T", message="m", priority=5)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp) as mock_post:
            notifier.send(alert)
            headers = mock_post.call_args[1]["headers"]
            assert headers["Priority"] == "urgent"
