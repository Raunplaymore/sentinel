"""Sentinel — Multi-channel Notification Delivery.

Design principles:
- Install and it works: macOS native notifications enabled by default.
- "Value means enabled": if ntfy_topic has a value, ntfy is active.
  If slack_webhook has a URL, Slack is active. No separate on/off switches.
- Watch everything, notify minimally: only critical alerts push notifications.
  Warning/info are logged but not sent to any notification channel.
"""

import logging
import subprocess
import requests
from collections import deque
from typing import Protocol

from sentinel_mac.models import SystemMetrics, Alert


# ─── Channel Protocol ───

class NotificationChannel(Protocol):
    """Interface for notification channels."""

    def send(self, alert: Alert) -> bool:
        """Send an alert. Returns True on success."""
        ...

    @property
    def name(self) -> str:
        ...


# ─── macOS Native Notifications ───

class MacOSNotifier:
    """macOS native notifications via osascript (no dependencies)."""

    @property
    def name(self) -> str:
        return "macos"

    def send(self, alert: Alert) -> bool:
        title = alert.title.encode("utf-8", errors="replace").decode("utf-8")
        message = alert.message.encode("utf-8", errors="replace").decode("utf-8")
        # Escape double quotes for AppleScript
        title = title.replace('"', '\\"')
        message = message.replace('"', '\\"')

        script = (
            f'display notification "{message}" '
            f'with title "{title}" '
            f'subtitle "Sentinel"'
        )
        if alert.level == "critical":
            script += ' sound name "Funk"'

        try:
            subprocess.run(
                ["osascript", "-e", script],
                capture_output=True, timeout=5,
            )
            logging.info(f"[macos] Alert sent: {alert.title}")
            return True
        except Exception as e:
            logging.error(f"[macos] Send failed: {e}")
            return False


# ─── ntfy.sh Notifications ───

class NtfyNotifier:
    """Sends push notifications via ntfy.sh with retry queue."""

    PRIORITY_MAP = {1: "min", 2: "low", 3: "default", 4: "high", 5: "urgent"}
    MAX_RETRIES = 3
    RETRY_QUEUE_SIZE = 50

    def __init__(self, topic: str, server: str = "https://ntfy.sh"):
        self.topic = topic
        self.server = server
        self._retry_queue: deque = deque(maxlen=self.RETRY_QUEUE_SIZE)

    @property
    def name(self) -> str:
        return "ntfy"

    def send(self, alert: Alert) -> bool:
        self._flush_retries()

        if not self._do_send(alert):
            self._retry_queue.append((alert, 1))
            return False
        return True

    def _do_send(self, alert: Alert) -> bool:
        url = f"{self.server}/{self.topic}"
        headers = {
            "Title": alert.title,
            "Priority": self.PRIORITY_MAP.get(alert.priority, "default"),
            "Tags": f"{alert.emoji},{alert.category}",
        }

        try:
            resp = requests.post(url, data=alert.message.encode("utf-8"),
                                 headers=headers, timeout=10)
            if resp.status_code == 200:
                logging.info(f"[ntfy] Alert sent: {alert.title}")
                return True
            else:
                logging.warning(f"[ntfy] Error: {resp.status_code}")
                return False
        except Exception as e:
            logging.error(f"[ntfy] Send failed: {e}")
            return False

    def _flush_retries(self):
        if not self._retry_queue:
            return

        remaining = deque(maxlen=self.RETRY_QUEUE_SIZE)
        while self._retry_queue:
            alert, attempt = self._retry_queue.popleft()
            if self._do_send(alert):
                logging.info(f"[ntfy] Retry succeeded: {alert.title} (attempt {attempt})")
            elif attempt < self.MAX_RETRIES:
                remaining.append((alert, attempt + 1))
            else:
                logging.error(f"[ntfy] Retry exhausted, dropping: {alert.title}")
        self._retry_queue = remaining


# ─── Slack Webhook Notifications ───

class SlackNotifier:
    """Sends notifications to Slack via incoming webhook."""

    LEVEL_EMOJI = {"critical": ":red_circle:", "warning": ":large_yellow_circle:", "info": ":white_circle:"}

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "slack"

    def send(self, alert: Alert) -> bool:
        emoji = self.LEVEL_EMOJI.get(alert.level, ":white_circle:")
        payload = {
            "text": f"{emoji} *{alert.title}*\n{alert.message}",
        }
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            if resp.status_code == 200:
                logging.info(f"[slack] Alert sent: {alert.title}")
                return True
            else:
                logging.warning(f"[slack] Error: {resp.status_code}")
                return False
        except Exception as e:
            logging.error(f"[slack] Send failed: {e}")
            return False


# ─── Telegram Bot Notifications ───

class TelegramNotifier:
    """Sends notifications via Telegram Bot API."""

    LEVEL_EMOJI = {"critical": "\U0001f534", "warning": "\U0001f7e0", "info": "\u26aa"}

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id

    @property
    def name(self) -> str:
        return "telegram"

    def send(self, alert: Alert) -> bool:
        emoji = self.LEVEL_EMOJI.get(alert.level, "\u26aa")
        text = f"{emoji} *{alert.title}*\n{alert.message}"
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                logging.info(f"[telegram] Alert sent: {alert.title}")
                return True
            else:
                logging.warning(f"[telegram] Error: {resp.status_code}")
                return False
        except Exception as e:
            logging.error(f"[telegram] Send failed: {e}")
            return False


# ─── Notification Manager ───

class NotificationManager:
    """Multi-channel notification manager.

    Core rule: only critical alerts are pushed to notification channels.
    Warning and info alerts are logged but NOT sent.
    """

    def __init__(self, config: dict):
        self._channels: list = []
        self._setup_channels(config)

    def _setup_channels(self, config: dict):
        """Auto-detect enabled channels from config values."""
        notif = config.get("notifications", {})

        # macOS native — enabled by default
        if notif.get("macos", True):
            self._channels.append(MacOSNotifier())

        # ntfy.sh — enabled if topic is set and non-default
        # notifications.ntfy_topic takes precedence; fall back to top-level only if not in notifications block
        ntfy_topic = notif.get("ntfy_topic") if "ntfy_topic" in notif else config.get("ntfy_topic", "")
        ntfy_server = notif.get("ntfy_server") or config.get("ntfy_server", "https://ntfy.sh")
        if ntfy_topic and ntfy_topic != "sentinel-CHANGE-ME":
            self._channels.append(NtfyNotifier(ntfy_topic, ntfy_server))

        # Slack — enabled if webhook URL is set
        slack_url = notif.get("slack_webhook", "")
        if slack_url:
            self._channels.append(SlackNotifier(slack_url))

        # Telegram — enabled if both bot_token and chat_id are set
        tg_token = notif.get("telegram_bot_token", "")
        tg_chat_id = notif.get("telegram_chat_id", "")
        if tg_token and tg_chat_id:
            self._channels.append(TelegramNotifier(tg_token, tg_chat_id))

    @property
    def channel_names(self) -> list[str]:
        return [ch.name for ch in self._channels]

    def send(self, alert: Alert):
        """Send alert to all channels IF it's critical. Otherwise log only."""
        if alert.level != "critical":
            logging.info(f"[{alert.level}] {alert.title} — logged only")
            return

        for channel in self._channels:
            try:
                channel.send(alert)
            except Exception as e:
                logging.error(f"[{channel.name}] Channel error: {e}")

    def send_status(self, m: SystemMetrics):
        """Send periodic status report. Status is always sent (operational heartbeat)."""
        cpu_temp = " | {}°C".format(m.cpu_temp) if m.cpu_temp else ""
        lines = [
            f"CPU: {m.cpu_percent}%{cpu_temp}",
            f"MEM: {m.memory_percent}% ({m.memory_used_gb}GB)",
            f"DISK: {m.disk_percent}% ({m.disk_free_gb}GB free)",
        ]
        if m.battery_percent is not None:
            plug = "\U0001f50c" if m.battery_plugged else "\U0001f50b"
            bat_remaining = " ({} min)".format(m.battery_minutes_left) if m.battery_minutes_left else ""
            lines.append(f"BAT: {plug} {m.battery_percent}%{bat_remaining}")
        if m.fan_speed_rpm:
            lines.append(f"FAN: {m.fan_speed_rpm} RPM")
        security = []
        if m.firewall_enabled is not None:
            security.append(f"FW {'ON' if m.firewall_enabled else 'OFF'}")
        if m.gatekeeper_enabled is not None:
            security.append(f"GK {'ON' if m.gatekeeper_enabled else 'OFF'}")
        if m.filevault_enabled is not None:
            security.append(f"FV {'ON' if m.filevault_enabled else 'OFF'}")
        if security:
            lines.append(f"SEC: {' | '.join(security)}")
        if m.ai_processes:
            lines.append(f"AI: {len(m.ai_processes)} process(es), CPU {m.ai_cpu_total:.0f}%")
            top = m.ai_processes[0]
            lines.append(f"  Top: {top['name']} ({top['cpu']}%)")

        message = "\n".join(lines)
        status_alert = Alert(
            level="info", category="status",
            title="\U0001f4ca Sentinel Status Report",
            message=message,
            priority=1
        )
        # Status reports bypass the critical-only filter
        for channel in self._channels:
            try:
                channel.send(status_alert)
            except Exception as e:
                logging.error(f"[{channel.name}] Status send error: {e}")
