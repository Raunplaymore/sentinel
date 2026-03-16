#!/usr/bin/env python3
"""
Sentinel — AI Session Guardian for macOS
Monitors system resources and sends smart alerts via ntfy.sh
"""

import logging
import queue
import signal
import subprocess
import sys
import os
import fcntl
import time
from datetime import datetime, timedelta
from pathlib import Path
from logging.handlers import RotatingFileHandler

# Re-export from new modules so existing imports (tests, sentinel.py) keep working
from sentinel_mac.models import SystemMetrics, Alert, SecurityEvent  # noqa: F401
from sentinel_mac.collectors.system import MacOSCollector  # noqa: F401
from sentinel_mac.collectors.fs_watcher import FSWatcher  # noqa: F401
from sentinel_mac.collectors.net_tracker import NetTracker  # noqa: F401
from sentinel_mac.collectors.agent_log_parser import AgentLogParser  # noqa: F401
from sentinel_mac.engine import AlertEngine  # noqa: F401
from sentinel_mac.notifier import NtfyNotifier, NotificationManager, MacOSNotifier, SlackNotifier, TelegramNotifier  # noqa: F401
from sentinel_mac.event_logger import EventLogger  # noqa: F401

# ─────────────────────────────────────────────
# Config Resolution
# ─────────────────────────────────────────────

import yaml

DEFAULT_CONFIG = {
    "ntfy_topic": "sentinel-default",
    "ntfy_server": "https://ntfy.sh",
    "notifications_enabled": True,
    "check_interval_seconds": 30,
    "status_interval_minutes": 60,
    "cooldown_minutes": 10,
    "thresholds": {
        "battery_warning": 20,
        "battery_critical": 10,
        "battery_drain_rate": 10,
        "temp_warning": 85,
        "temp_critical": 95,
        "memory_critical": 90,
        "network_spike_mb": 100,
        "session_hours_warning": 3,
        "disk_critical": 90,
    }
}


def resolve_config_path(explicit_path: str = None) -> Path:
    """Find config file in priority order:
    1. Explicit --config path
    2. ./config.yaml (current directory)
    3. ~/.config/sentinel/config.yaml (XDG-style)
    4. None (use defaults)
    """
    if explicit_path:
        return Path(explicit_path)

    # Current directory
    cwd_config = Path.cwd() / "config.yaml"
    if cwd_config.exists():
        return cwd_config

    # XDG config
    xdg_config = Path.home() / ".config" / "sentinel" / "config.yaml"
    if xdg_config.exists():
        return xdg_config

    return None


def resolve_data_dir() -> Path:
    """Resolve data directory for logs and lock files.
    Uses ~/.local/share/sentinel/ for pip installs,
    or ./logs/ if running from repo directory.
    """
    # If running from repo (install.sh style), use local logs/
    local_logs = Path.cwd() / "logs"
    if local_logs.exists():
        return local_logs

    # XDG data dir
    data_dir = Path.home() / ".local" / "share" / "sentinel"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def _validate_config(config: dict) -> dict:
    """Validate and clamp config values to safe ranges."""
    # Top-level numeric fields: (key, min, max, type)
    numeric_fields = [
        ("check_interval_seconds", 5, 3600),
        ("status_interval_minutes", 1, 1440),
        ("cooldown_minutes", 1, 1440),
    ]
    for key, lo, hi in numeric_fields:
        val = config.get(key)
        if not isinstance(val, (int, float)) or val < lo:
            config[key] = DEFAULT_CONFIG[key]
        elif val > hi:
            config[key] = hi

    # Threshold fields: (key, min, max)
    threshold_ranges = {
        "battery_warning": (5, 50),
        "battery_critical": (1, 30),
        "battery_drain_rate": (1, 100),
        "temp_warning": (50, 110),
        "temp_critical": (60, 120),
        "memory_critical": (50, 99),
        "disk_critical": (50, 99),
        "network_spike_mb": (1, 10000),
        "session_hours_warning": (1, 72),
    }
    thresholds = config.get("thresholds", {})
    if not isinstance(thresholds, dict):
        config["thresholds"] = DEFAULT_CONFIG["thresholds"].copy()
        return config

    for key, (lo, hi) in threshold_ranges.items():
        val = thresholds.get(key)
        if not isinstance(val, (int, float)) or val < lo:
            thresholds[key] = DEFAULT_CONFIG["thresholds"][key]
        elif val > hi:
            thresholds[key] = hi
    config["thresholds"] = thresholds
    return config


def _apply_env_overrides(config: dict) -> None:
    """Override notification secrets with environment variables if set."""
    notif = config.setdefault("notifications", {})
    env_map = {
        "SENTINEL_NTFY_TOPIC":        "ntfy_topic",
        "SENTINEL_SLACK_WEBHOOK":     "slack_webhook",
        "SENTINEL_TELEGRAM_TOKEN":    "telegram_bot_token",
        "SENTINEL_TELEGRAM_CHAT_ID":  "telegram_chat_id",
    }
    for env_key, config_key in env_map.items():
        val = os.environ.get(env_key)
        if val:
            notif[config_key] = val


def load_config(config_path: Path = None) -> dict:
    """Load config with error handling and default fallback."""
    defaults = DEFAULT_CONFIG.copy()
    defaults["thresholds"] = DEFAULT_CONFIG["thresholds"].copy()

    if config_path is None:
        return defaults

    try:
        with open(config_path) as f:
            user_config = yaml.safe_load(f) or {}
        if not isinstance(user_config, dict):
            logging.error("Config format error: top-level YAML must be a mapping — using defaults")
            return defaults
        merged = {**defaults, **user_config}
        merged["thresholds"] = {**defaults["thresholds"], **user_config.get("thresholds", {})}
        _apply_env_overrides(merged)
        return _validate_config(merged)
    except FileNotFoundError:
        logging.warning(f"Config not found: {config_path} — using defaults")
        return defaults
    except yaml.YAMLError as e:
        logging.error(f"Config parse error: {e} — using defaults")
        return defaults


# ─────────────────────────────────────────────
# Main Daemon
# ─────────────────────────────────────────────

class Sentinel:
    """Main monitoring daemon."""

    def __init__(self, config_path: str = None):
        # Prevent duplicate instances via PID file lock
        self._pid_file = None
        self._data_dir = resolve_data_dir()
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._acquire_lock()

        resolved = resolve_config_path(config_path)
        self.config = load_config(resolved)

        # Setup logging with rotation (max 5MB x 3 files = 15MB)
        log_dir = self._data_dir
        log_dir.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                RotatingFileHandler(
                    log_dir / "sentinel.log",
                    maxBytes=5 * 1024 * 1024,
                    backupCount=3,
                ),
                logging.StreamHandler()
            ]
        )

        self.collector = MacOSCollector()
        self.engine = AlertEngine(self.config)
        self.notifier = NotificationManager(self.config)
        self._event_logger = EventLogger(self._data_dir)

        # Security layer — event queue shared between collectors and main loop
        self._security_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._fs_watcher: FSWatcher | None = None
        self._net_tracker: NetTracker | None = None
        self._agent_log_parser: AgentLogParser | None = None

        # Start security collectors if enabled
        sec_config = self.config.get("security", {})
        if sec_config.get("enabled", False):
            fs_config = sec_config.get("fs_watcher", {})
            if fs_config.get("enabled", True):
                self._fs_watcher = FSWatcher(self.config, self._security_queue)
            net_config = sec_config.get("net_tracker", {})
            if net_config.get("enabled", True):
                self._net_tracker = NetTracker(self.config, self._security_queue)
            agent_config = sec_config.get("agent_logs", {})
            if agent_config.get("enabled", True):
                self._agent_log_parser = AgentLogParser(self.config, self._security_queue)

        self.interval = self.config.get("check_interval_seconds", 30)
        self.status_interval = self.config.get("status_interval_minutes", 60)
        self._last_status = datetime.min
        self._running = True

        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)

    def _acquire_lock(self):
        """Prevent duplicate daemon instances using a file lock.

        Always uses a fixed path (~/.local/share/sentinel/) regardless of
        working directory, so that two instances started from different
        locations still detect each other.
        """
        global_lock_dir = Path.home() / ".local" / "share" / "sentinel"
        global_lock_dir.mkdir(parents=True, exist_ok=True)
        lock_file = global_lock_dir / "sentinel.lock"
        self._pid_file = open(lock_file, "w")
        try:
            fcntl.flock(self._pid_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._pid_file.write(str(os.getpid()))
            self._pid_file.flush()
        except OSError:
            print(f"ERROR: Sentinel is already running. Lock file: {lock_file}")
            sys.exit(1)

    def _shutdown(self, signum, frame):
        logging.info("\U0001f6d1 Sentinel shutting down...")
        self._running = False
        if self._fs_watcher:
            self._fs_watcher.stop()
        if self._agent_log_parser:
            self._agent_log_parser.stop()
        self._event_logger.close()
        if self._pid_file and not self._pid_file.closed:
            fcntl.flock(self._pid_file, fcntl.LOCK_UN)
            self._pid_file.close()

    def run(self):
        channels = self.notifier.channel_names
        logging.info(f"\U0001f680 Sentinel started — channels: {', '.join(channels)}")
        logging.info(f"   Check interval: {self.interval}s")
        logging.info(f"   Status report every: {self.status_interval}min")

        self.notifier.send(Alert(
            level="info", category="startup",
            title="\U0001f680 Sentinel Started",
            message=f"Check interval: {self.interval}s\n"
                   f"Status report every {self.status_interval} min",
            priority=2
        ))

        # Start security layer collectors
        if self._fs_watcher:
            self._fs_watcher.start()
        if self._agent_log_parser:
            self._agent_log_parser.start()

        while self._running:
            try:
                metrics = self.collector.collect()

                logging.info(
                    "CPU:{}% {}MEM:{}% DISK:{}% BAT:{}{}% AI:{}procs".format(
                        metrics.cpu_percent,
                        "T:{}°C ".format(metrics.cpu_temp) if metrics.cpu_temp else "",
                        metrics.memory_percent,
                        metrics.disk_percent,
                        "\U0001f50c" if metrics.battery_plugged else "\U0001f50b",
                        metrics.battery_percent,
                        len(metrics.ai_processes),
                    )
                )

                alerts = self.engine.evaluate(metrics)
                for alert in alerts:
                    logging.warning(f"\U0001f6a8 {alert.level}: {alert.title}")
                    self.notifier.send(alert)

                # Poll network connections (polling-based, runs in main loop)
                if self._net_tracker:
                    self._net_tracker.poll()

                # Drain security event queue
                self._process_security_events()

                now = datetime.now()
                if (now - self._last_status).total_seconds() > self.status_interval * 60:
                    self.notifier.send_status(metrics)
                    self._last_status = now

            except Exception as e:
                logging.error(f"Monitor error: {e}", exc_info=True)

            time.sleep(self.interval)

        logging.info("Sentinel stopped.")

    def _process_security_events(self):
        """Drain the security event queue, log to JSONL, and generate alerts."""
        processed = 0
        while not self._security_queue.empty() and processed < 100:
            try:
                event = self._security_queue.get_nowait()
                self._event_logger.log(event)
                alerts = self.engine.evaluate_security_event(event)
                for alert in alerts:
                    logging.warning(f"\U0001f6a8 [security] {alert.level}: {alert.title}")
                    self.notifier.send(alert)
                processed += 1
            except queue.Empty:
                break


# ─────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────

def generate_report(days: int = 1) -> None:
    """Read JSONL event logs and print a summary report."""
    import json as _json
    from collections import Counter

    data_dir = resolve_data_dir()
    events_dir = data_dir / "events"

    if not events_dir.exists():
        print("No event logs found.")
        return

    today = datetime.now()
    start_date = today - timedelta(days=days - 1)

    # Collect events from date range
    events = []
    for d in range(days):
        date = start_date + timedelta(days=d)
        filepath = events_dir / "{}.jsonl".format(date.strftime("%Y-%m-%d"))
        if not filepath.exists():
            continue
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(_json.loads(line))
                    except _json.JSONDecodeError:
                        pass

    if not events:
        print("No events recorded in the selected period.")
        return

    # Classify by risk_score
    critical = [e for e in events if e.get("risk_score", 0) >= 0.8]
    warning = [e for e in events if 0.4 <= e.get("risk_score", 0) < 0.8]
    info = [e for e in events if e.get("risk_score", 0) < 0.4]

    # Top sources
    source_counts = Counter(e.get("source", "unknown") for e in events)

    # Notable events (critical, most recent first)
    notable = sorted(critical, key=lambda e: e.get("ts", ""), reverse=True)[:5]

    # Format
    period_start = start_date.strftime("%Y-%m-%d")
    period_end = today.strftime("%Y-%m-%d")
    period_label = period_start if days == 1 else "{} ~ {}".format(period_start, period_end)

    print("")
    print("=" * 50)
    print("  Sentinel Report")
    print("  {}".format(period_label))
    print("=" * 50)
    print("")
    print("  Events: {} total".format(len(events)))
    print("    Critical: {:>4}".format(len(critical)))
    print("    Warning:  {:>4}".format(len(warning)))
    print("    Info:     {:>4}".format(len(info)))
    print("")
    print("  Top Sources:")
    for source, count in source_counts.most_common(5):
        print("    {:<20s} {}".format(source, count))

    if notable:
        print("")
        print("  Notable Events:")
        for e in notable:
            ts = e.get("ts", "?")[:16]
            source = e.get("source", "?")
            target = e.get("target", "?")
            if len(target) > 60:
                target = target[:57] + "..."
            print("    {} | [{}] {}".format(ts, source, target))

    print("")
    print("=" * 50)
    print("")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

PLIST_NAME = "com.sentinel.agent"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{PLIST_NAME}.plist"


def _service_control(command: str):
    """Control the Sentinel launchd service."""
    if command == "status":
        try:
            result = subprocess.run(
                ["launchctl", "list", PLIST_NAME],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                # Extract PID from output
                for line in result.stdout.strip().splitlines():
                    if "PID" in line or line.strip().startswith('"PID"'):
                        continue
                    parts = line.strip().split("\t")
                    if len(parts) >= 1 and parts[0].isdigit():
                        print(f"Sentinel is running (PID {parts[0]})")
                        return
                print("Sentinel is running")
            else:
                print("Sentinel is not running")
        except Exception:
            print("Sentinel is not running")
        return

    if command == "logs":
        data_dir = resolve_data_dir()
        log_file = data_dir / "sentinel.log"
        if not log_file.exists():
            print(f"No log file found: {log_file}")
            return
        print(f"Tailing {log_file} (Ctrl+C to stop)\n")
        try:
            subprocess.run(["tail", "-f", "-n", "50", str(log_file)])
        except KeyboardInterrupt:
            print("\nStopped.")
        return

    if not PLIST_PATH.exists():
        print(f"LaunchAgent not found: {PLIST_PATH}")
        print("Run install.sh first, or start manually: sentinel --config <path>")
        return

    if command == "stop":
        subprocess.run(["launchctl", "unload", str(PLIST_PATH)],
                        capture_output=True)
        print("Sentinel stopped")

    elif command == "start":
        # Check if already running via launchd
        check = subprocess.run(
            ["launchctl", "list", PLIST_NAME],
            capture_output=True, text=True,
        )
        if check.returncode == 0:
            print("Sentinel is already running")
            return
        result = subprocess.run(
            ["launchctl", "load", str(PLIST_PATH)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"Failed to start Sentinel: {result.stderr.strip()}")
        else:
            print("Sentinel started")

    elif command == "restart":
        subprocess.run(["launchctl", "unload", str(PLIST_PATH)],
                        capture_output=True)
        subprocess.run(["launchctl", "load", str(PLIST_PATH)],
                        capture_output=True)
        print("Sentinel restarted")


def main():
    import argparse
    from sentinel_mac import __version__

    parser = argparse.ArgumentParser(
        description="Sentinel — AI Agent Security Guardian for macOS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="service commands:\n"
               "  start       Start background service\n"
               "  stop        Stop background service\n"
               "  restart     Restart background service\n"
               "  status      Check if service is running\n"
               "  logs        Tail live logs (Ctrl+C to stop)",
    )
    parser.add_argument("command", nargs="?", default=None,
                        choices=["start", "stop", "restart", "status", "logs"],
                        metavar="command",
                        help="start | stop | restart | status | logs")
    parser.add_argument("--config", "-c", default=None, help="Config file path")
    parser.add_argument("--once", action="store_true", help="Run once and print metrics")
    parser.add_argument("--test-notify", action="store_true", help="Send test notification")
    parser.add_argument("--version", "-v", action="version", version=f"sentinel-mac {__version__}")
    parser.add_argument("--report", nargs="?", const=1, type=int, metavar="DAYS",
                        help="Show event summary (default: today, or specify number of days)")
    parser.add_argument("--init-config", action="store_true",
                        help="Generate config.yaml in ~/.config/sentinel/")
    args = parser.parse_args()

    if args.command:
        _service_control(args.command)
        return

    if args.report is not None:
        generate_report(args.report)
        return

    if args.init_config:
        config_dir = Path.home() / ".config" / "sentinel"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file = config_dir / "config.yaml"
        if config_file.exists():
            print(f"Config already exists: {config_file}")
        else:
            config_content = """# Sentinel — Configuration
# Generated by: sentinel --init-config

check_interval_seconds: 30
status_interval_minutes: 60
cooldown_minutes: 10

# Notification channels — value means enabled, empty means disabled.
notifications:
  macos: true                  # macOS native (works out of the box)
  ntfy_topic: ""               # ntfy.sh topic (set to enable)
  ntfy_server: "https://ntfy.sh"
  slack_webhook: ""            # Slack webhook URL (set to enable)
  telegram_bot_token: ""       # Telegram Bot token (from @BotFather)
  telegram_chat_id: ""         # Telegram Chat ID

thresholds:
  battery_warning: 20
  battery_critical: 10
  battery_drain_rate: 10
  temp_warning: 85
  temp_critical: 95
  memory_critical: 90
  disk_critical: 90
  network_spike_mb: 100
  session_hours_warning: 3
"""
            config_file.write_text(config_content)
            print(f"Config created: {config_file}")
            print(f"macOS native notifications enabled by default.")
            print(f"Edit {config_file} to add ntfy.sh, Slack, or Telegram.")
        return

    if args.once:
        collector = MacOSCollector()
        m = collector.collect()
        print(f"\n{'='*50}")
        print(f"  Sentinel — System Snapshot")
        print(f"  {m.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*50}")
        cpu_temp = "  |  {}°C".format(m.cpu_temp) if m.cpu_temp else ""
        print(f"  CPU:     {m.cpu_percent}%{cpu_temp}")
        print(f"  Thermal: {m.thermal_pressure}")
        print(f"  Memory:  {m.memory_percent}% ({m.memory_used_gb}GB)")
        if m.battery_percent is not None:
            plug = "charging \U0001f50c" if m.battery_plugged else "on battery \U0001f50b"
            print(f"  Battery: {m.battery_percent}% ({plug})")
            if m.battery_minutes_left:
                print(f"           ~{m.battery_minutes_left} min remaining")
            if m.battery_cycle_count:
                print(f"           Cycles: {m.battery_cycle_count}")
        print(f"  Disk:    {m.disk_percent}% ({m.disk_free_gb}GB free)")
        if m.fan_speed_rpm:
            print(f"  Fan:     {m.fan_speed_rpm} RPM")
        security = []
        if m.firewall_enabled is not None:
            security.append(f"Firewall {'ON' if m.firewall_enabled else 'OFF'}")
        if m.gatekeeper_enabled is not None:
            security.append(f"Gatekeeper {'ON' if m.gatekeeper_enabled else 'OFF'}")
        if m.filevault_enabled is not None:
            security.append(f"FileVault {'ON' if m.filevault_enabled else 'OFF'}")
        if security:
            print(f"  Security: {' | '.join(security)}")
        print(f"  Network: \u2191{m.net_sent_mb}MB \u2193{m.net_recv_mb}MB")
        if m.ai_processes:
            print(f"\n  AI Processes ({len(m.ai_processes)}):")
            for p in m.ai_processes[:5]:
                print(f"    {p['name']:20s} CPU:{p['cpu']:5.1f}%  MEM:{p['mem_mb']:.0f}MB")
        else:
            print(f"\n  AI Processes: none detected")
        print(f"{'='*50}\n")
        return

    if args.test_notify:
        resolved = resolve_config_path(args.config)
        config = load_config(resolved)
        notifier = NotificationManager(config)
        test_alert = Alert(
            level="critical", category="test",
            title="\U0001f9ea Sentinel Test",
            message="Notification delivered successfully! \u2705\n"
                   f"Active channels: {', '.join(notifier.channel_names)}",
            priority=5
        )
        notifier.send(test_alert)
        print(f"\u2705 Test notification sent to: {', '.join(notifier.channel_names)}")
        return

    # If no config found and no --config specified, show quickstart guide
    resolved = resolve_config_path(args.config)
    if resolved is None and args.config is None:
        from sentinel_mac import __version__ as ver
        print("")
        print("=" * 50)
        print("  Sentinel — AI Agent Security Guardian")
        print(f"  v{ver}")
        print("=" * 50)
        print("")
        print("  No config found. Quick start:")
        print("")
        print("  sentinel --init-config        Create config file")
        print("  sentinel --once               System snapshot")
        print("  sentinel --test-notify        Test notifications")
        print("  sentinel --help               All options")
        print("")
        print("  For auto-start background service:")
        print("    git clone https://github.com/raunplaymore/sentinel.git")
        print("    cd sentinel && bash install.sh")
        print("")
        print("=" * 50)
        print("")
        return

    sentinel = Sentinel(config_path=args.config)
    sentinel.run()


if __name__ == "__main__":
    main()
