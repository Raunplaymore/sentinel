"""Tests for notification system: NotificationManager, NtfyNotifier, MacOSNotifier, SlackNotifier, TelegramNotifier."""
from unittest.mock import MagicMock, patch

from sentinel_mac.core import DEFAULT_CONFIG
from sentinel_mac.models import Alert
from sentinel_mac.notifier import (
    MacOSNotifier,
    NotificationManager,
    NtfyNotifier,
    SlackNotifier,
    TelegramNotifier,
)

# ─── NtfyNotifier unit tests ───


class TestNtfyNotifier:

    def test_successful_send(self):
        notifier = NtfyNotifier("test-topic")
        alert = Alert(level="critical", category="test", title="Test", message="msg")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("sentinel_mac.notifier.requests.post", return_value=mock_resp) as mock_post:
            result = notifier.send(alert)
            mock_post.assert_called_once()
            assert result is True

    def test_failed_send_queued_for_retry(self):
        notifier = NtfyNotifier("test-topic")
        alert = Alert(level="critical", category="test", title="Test", message="msg")
        with patch("sentinel_mac.notifier.requests.post", side_effect=Exception("network error")):
            notifier.send(alert)
        assert len(notifier._retry_queue) == 1

    def test_retry_succeeds(self):
        notifier = NtfyNotifier("test-topic")
        alert = Alert(level="critical", category="test", title="Test", message="msg")

        with patch("sentinel_mac.notifier.requests.post", side_effect=Exception("network error")):
            notifier.send(alert)
        assert len(notifier._retry_queue) == 1

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("sentinel_mac.notifier.requests.post", return_value=mock_resp):
            notifier.send(alert)
        assert len(notifier._retry_queue) == 0

    def test_retry_exhausted_after_max(self):
        notifier = NtfyNotifier("test-topic")
        alert = Alert(level="critical", category="test", title="Test", message="msg")

        notifier._retry_queue.append((alert, NtfyNotifier.MAX_RETRIES))

        with patch("sentinel_mac.notifier.requests.post", side_effect=Exception("fail")):
            notifier._flush_retries()
        assert len(notifier._retry_queue) == 0

    def test_priority_mapping(self):
        notifier = NtfyNotifier("test-topic")
        alert = Alert(level="critical", category="test", title="T", message="m", priority=5)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("sentinel_mac.notifier.requests.post", return_value=mock_resp) as mock_post:
            notifier.send(alert)
            headers = mock_post.call_args[1]["headers"]
            assert headers["Priority"] == "urgent"


# ─── MacOSNotifier unit tests ───


class TestMacOSNotifier:

    def test_send_calls_terminal_notifier_when_available(self):
        with patch("sentinel_mac.notifier.shutil.which", return_value="/usr/local/bin/terminal-notifier"):
            notifier = MacOSNotifier()
        alert = Alert(level="critical", category="test", title="Test", message="msg")
        with patch("sentinel_mac.notifier.subprocess.run") as mock_run:
            result = notifier.send(alert)
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args[0] == "terminal-notifier"
            assert result is True

    def test_send_falls_back_to_osascript(self):
        with patch("sentinel_mac.notifier.shutil.which", return_value=None):
            notifier = MacOSNotifier()
        alert = Alert(level="critical", category="test", title="Test", message="msg")
        with patch("sentinel_mac.notifier.subprocess.run") as mock_run:
            result = notifier.send(alert)
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args[0] == "osascript"
            assert result is True

    def test_critical_includes_sound_terminal_notifier(self):
        with patch("sentinel_mac.notifier.shutil.which", return_value="/usr/local/bin/terminal-notifier"):
            notifier = MacOSNotifier()
        alert = Alert(level="critical", category="test", title="Test", message="msg")
        with patch("sentinel_mac.notifier.subprocess.run") as mock_run:
            notifier.send(alert)
            args = mock_run.call_args[0][0]
            assert "-sound" in args
            assert "Funk" in args

    def test_critical_includes_sound_osascript(self):
        with patch("sentinel_mac.notifier.shutil.which", return_value=None):
            notifier = MacOSNotifier()
        alert = Alert(level="critical", category="test", title="Test", message="msg")
        with patch("sentinel_mac.notifier.subprocess.run") as mock_run:
            notifier.send(alert)
            script = mock_run.call_args[0][0][2]
            assert 'sound name' in script

    def test_warning_no_sound(self):
        with patch("sentinel_mac.notifier.shutil.which", return_value="/usr/local/bin/terminal-notifier"):
            notifier = MacOSNotifier()
        alert = Alert(level="warning", category="test", title="Test", message="msg")
        with patch("sentinel_mac.notifier.subprocess.run") as mock_run:
            notifier.send(alert)
            args = mock_run.call_args[0][0]
            assert "-sound" not in args

    def test_name_property(self):
        assert MacOSNotifier().name == "macos"


# ─── SlackNotifier unit tests ───


class TestSlackNotifier:

    def test_send_posts_to_webhook(self):
        notifier = SlackNotifier("https://hooks.slack.com/test")
        alert = Alert(level="critical", category="test", title="Test", message="msg")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("sentinel_mac.notifier.requests.post", return_value=mock_resp) as mock_post:
            result = notifier.send(alert)
            mock_post.assert_called_once()
            assert mock_post.call_args[0][0] == "https://hooks.slack.com/test"
            assert result is True

    def test_name_property(self):
        assert SlackNotifier("url").name == "slack"


# ─── NotificationManager tests ───


class TestNotificationManager:

    def test_macos_enabled_by_default(self):
        config = {**DEFAULT_CONFIG}
        mgr = NotificationManager(config)
        assert "macos" in mgr.channel_names

    def test_macos_disabled(self):
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False}}
        mgr = NotificationManager(config)
        assert "macos" not in mgr.channel_names

    def test_ntfy_enabled_when_topic_set(self):
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False, "ntfy_topic": "my-topic"}}
        mgr = NotificationManager(config)
        assert "ntfy" in mgr.channel_names

    def test_ntfy_disabled_when_topic_empty(self):
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False, "ntfy_topic": ""}}
        mgr = NotificationManager(config)
        assert "ntfy" not in mgr.channel_names

    def test_ntfy_disabled_when_default_topic(self):
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False, "ntfy_topic": "sentinel-CHANGE-ME"}}
        mgr = NotificationManager(config)
        assert "ntfy" not in mgr.channel_names

    def test_slack_enabled_when_webhook_set(self):
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False, "slack_webhook": "https://hooks.slack.com/x"}}
        mgr = NotificationManager(config)
        assert "slack" in mgr.channel_names

    def test_slack_disabled_when_empty(self):
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False, "slack_webhook": ""}}
        mgr = NotificationManager(config)
        assert "slack" not in mgr.channel_names

    def test_critical_alert_sent_to_channels(self):
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False}}
        mgr = NotificationManager(config)
        mock_channel = MagicMock()
        mock_channel.name = "test"
        mgr._channels = [mock_channel]

        alert = Alert(level="critical", category="test", title="T", message="m")
        mgr.send(alert)
        mock_channel.send.assert_called_once_with(alert)

    def test_warning_alert_not_sent(self):
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False}}
        mgr = NotificationManager(config)
        mock_channel = MagicMock()
        mock_channel.name = "test"
        mgr._channels = [mock_channel]

        alert = Alert(level="warning", category="test", title="T", message="m")
        mgr.send(alert)
        mock_channel.send.assert_not_called()

    def test_info_alert_not_sent(self):
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False}}
        mgr = NotificationManager(config)
        mock_channel = MagicMock()
        mock_channel.name = "test"
        mgr._channels = [mock_channel]

        alert = Alert(level="info", category="test", title="T", message="m")
        mgr.send(alert)
        mock_channel.send.assert_not_called()

    def test_status_report_bypasses_level_filter(self):
        """send_status should send to all channels regardless of alert level."""
        from sentinel_mac.models import SystemMetrics
        config = {**DEFAULT_CONFIG, "notifications": {"macos": False}}
        mgr = NotificationManager(config)
        mock_channel = MagicMock()
        mock_channel.name = "test"
        mgr._channels = [mock_channel]

        from datetime import datetime
        metrics = SystemMetrics(timestamp=datetime.now())
        mgr.send_status(metrics)
        mock_channel.send.assert_called_once()

    def test_legacy_ntfy_topic_fallback(self):
        """Top-level ntfy_topic should still work for backward compatibility."""
        config = {**DEFAULT_CONFIG, "ntfy_topic": "legacy-topic", "notifications": {"macos": False}}
        mgr = NotificationManager(config)
        assert "ntfy" in mgr.channel_names

    def test_telegram_enabled_when_both_set(self):
        config = {**DEFAULT_CONFIG, "notifications": {
            "macos": False,
            "telegram_bot_token": "123:ABC",
            "telegram_chat_id": "456",
        }}
        mgr = NotificationManager(config)
        assert "telegram" in mgr.channel_names

    def test_telegram_disabled_when_token_missing(self):
        config = {**DEFAULT_CONFIG, "notifications": {
            "macos": False,
            "telegram_bot_token": "",
            "telegram_chat_id": "456",
        }}
        mgr = NotificationManager(config)
        assert "telegram" not in mgr.channel_names

    def test_telegram_disabled_when_chat_id_missing(self):
        config = {**DEFAULT_CONFIG, "notifications": {
            "macos": False,
            "telegram_bot_token": "123:ABC",
            "telegram_chat_id": "",
        }}
        mgr = NotificationManager(config)
        assert "telegram" not in mgr.channel_names


# ─── TelegramNotifier unit tests ───


class TestTelegramNotifier:

    def test_send_calls_telegram_api(self):
        notifier = TelegramNotifier("123:ABC", "456")
        alert = Alert(level="critical", category="test", title="Test", message="msg")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("sentinel_mac.notifier.requests.post", return_value=mock_resp) as mock_post:
            result = notifier.send(alert)
            mock_post.assert_called_once()
            url = mock_post.call_args[0][0]
            assert "api.telegram.org/bot123:ABC/sendMessage" in url
            payload = mock_post.call_args[1]["json"]
            assert payload["chat_id"] == "456"
            assert "Test" in payload["text"]
            assert result is True

    def test_send_failure(self):
        notifier = TelegramNotifier("123:ABC", "456")
        alert = Alert(level="critical", category="test", title="Test", message="msg")
        with patch("sentinel_mac.notifier.requests.post", side_effect=Exception("network")):
            result = notifier.send(alert)
            assert result is False

    def test_name_property(self):
        assert TelegramNotifier("t", "c").name == "telegram"
