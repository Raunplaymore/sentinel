"""Sentinel — Menubar App (PoC).

Standalone macOS menubar app that visualizes Sentinel metrics live.

Reuses MacOSCollector + AlertEngine. Does NOT send notifications and does
NOT acquire the daemon PID lock — intentionally so it can run alongside
the LaunchAgent daemon during the PoC. The daemon keeps doing the
"alert delivery" job; the menubar app is a read-only viewer for now.

Settings toggles round-trip the on-disk config.yaml via ruamel.yaml so
hand-written comments and layout survive `Save`.

Run with `sentinel-app` after `pip install -e '.[app]'`.
"""

from __future__ import annotations

import fcntl
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import IO, Any, Optional

import rumps
from ruamel.yaml import YAML

from sentinel_mac.collectors.system import MacOSCollector
from sentinel_mac.core import load_config, resolve_config_path, resolve_data_dir
from sentinel_mac.engine import AlertEngine
from sentinel_mac.models import Alert, SystemMetrics

# Round-trip YAML preserves comments, blank lines, key order, and quoting
# style across load → mutate → dump, so toggling a Settings switch from the
# menubar leaves the user's hand-written config.yaml comments intact.
_yaml_rt = YAML(typ="rt")
_yaml_rt.preserve_quotes = True

POLL_SECONDS = 5
ALERT_HISTORY_LIMIT = 5
LOG_WINDOW_HOURS = 12

_LEVEL_EMOJI = {
    "critical": "🔴",
    "warning": "🟠",
    "info": "🟡",
}

# Logger format is "%(asctime)s [%(levelname)s] %(message)s" — asctime defaults
# to "YYYY-MM-DD HH:MM:SS,sss".
_LOG_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_LOG_LEVEL_RE = re.compile(r"\[(DEBUG|INFO|WARNING|ERROR|CRITICAL)\]")
_LOG_LEVEL_PRIORITY = {
    "DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50,
}

# ── Detection rules surfaced in the Settings menu ─────────────────────────────
# Top-level: each maps to a real config key the daemon honors today.
DETECTION_RULES: list[dict] = [
    {
        "title": "Security layer (master)",
        "description": (
            "Master switch — turns all detection collectors below on/off."
        ),
        "config_path": ("security", "enabled"),
        "default": True,
    },
    {
        "title": "File system watcher",
        "description": (
            "Watches sensitive paths (~/.ssh, ~/.aws, ~/.env, …) for AI "
            "process file access; also flags bulk changes and new executables."
        ),
        "config_path": ("security", "fs_watcher", "enabled"),
        "default": True,
    },
    {
        "title": "Network tracker",
        "description": (
            "Flags AI process outbound connections to non-allowlisted hosts "
            "(potential data exfiltration)."
        ),
        "config_path": ("security", "net_tracker", "enabled"),
        "default": True,
    },
    {
        "title": "Agent log parser",
        "description": (
            "Reads Claude Code / Cursor session logs to flag risky tool "
            "calls, sensitive file access, MCP injection, typosquatting."
        ),
        "config_path": ("security", "agent_logs", "enabled"),
        "default": True,
    },
]

# Sub-rules bundled inside the Agent log parser. Each maps to a config key
# under security.agent_logs.rules.* that AgentLogParser honors per-rule.
AGENT_LOG_SUBRULES: list[dict] = [
    {
        "title": "Risky Bash commands",
        "description": "curl|sh, rm -rf, chmod +x, base64 -d, pip install …",
        "config_path": ("security", "agent_logs", "rules", "bash"),
        "default": True,
    },
    {
        "title": "Sensitive file R/W/Edit",
        "description": ".env*, .ssh/, credentials, *.pem, id_rsa, .netrc",
        "config_path": ("security", "agent_logs", "rules", "sensitive_file"),
        "default": True,
    },
    {
        "title": "WebFetch URLs",
        "description": "Logs URL fetches performed by the agent.",
        "config_path": ("security", "agent_logs", "rules", "web_fetch"),
        "default": True,
    },
    {
        "title": "MCP tool calls",
        "description": "Detects suspicious MCP server tool invocations.",
        "config_path": ("security", "agent_logs", "rules", "mcp"),
        "default": True,
    },
    {
        "title": "Typosquatting (pip/npm)",
        "description": "Flags installs of names similar to top-300 packages.",
        "config_path": ("security", "agent_logs", "rules", "typosquatting"),
        "default": True,
    },
]

# Held for the lifetime of the process — losing this reference would release
# the flock and let a second instance start.
_singleton_lock_handle: Optional[IO] = None


def _parse_log_timestamp(line: str) -> Optional[datetime]:
    m = _LOG_TS_RE.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _recent_log_entries(
    log_path: Path, hours: int, min_level: Optional[str] = None
) -> list[str]:
    """Return log entries within the last N hours, oldest-first.

    Continuation lines (no timestamp prefix, e.g. traceback frames) stay
    grouped with their parent entry so reversal doesn't scramble tracebacks.

    If `min_level` is given (e.g. "WARNING"), entries below that Python
    logging level are dropped. Sentinel's daemon dispatches every alert at
    WARNING level, so min_level="WARNING" effectively yields "alerts only".
    """
    cutoff = datetime.now() - timedelta(hours=hours)
    min_priority = _LOG_LEVEL_PRIORITY.get(min_level or "", 0)

    entries: list[str] = []
    cur_lines: list[str] = []
    cur_in_window = False
    cur_passes_level = False

    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            ts = _parse_log_timestamp(line)
            if ts is not None:
                if cur_in_window and cur_passes_level and cur_lines:
                    entries.append("".join(cur_lines))
                cur_lines = [line]
                cur_in_window = ts >= cutoff
                if min_priority == 0:
                    cur_passes_level = True
                else:
                    m = _LOG_LEVEL_RE.search(line)
                    cur_passes_level = (
                        m is not None
                        and _LOG_LEVEL_PRIORITY.get(m.group(1), 0) >= min_priority
                    )
            else:
                cur_lines.append(line)
        if cur_in_window and cur_passes_level and cur_lines:
            entries.append("".join(cur_lines))

    return entries


def _get_nested(config: dict, path: tuple[str, ...], default: Any) -> Any:
    """Walk a path through nested dicts; return default if any segment is missing."""
    cur: Any = config
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _set_nested(config: dict, path: tuple[str, ...], value: Any) -> None:
    """Walk a path, creating intermediate dicts as needed; set the leaf."""
    cur = config
    for key in path[:-1]:
        if not isinstance(cur.get(key), dict):
            cur[key] = {}
        cur = cur[key]
    cur[path[-1]] = value


def _persist_setting(config_path: Path, path: tuple[str, ...], value: Any) -> None:
    """Round-trip the on-disk config.yaml: load with comments preserved, set
    one nested key, write back atomically. Existing user comments and layout
    are kept intact.

    If the file is missing or unreadable, a fresh minimal mapping is written.
    """
    if config_path.exists():
        with open(config_path) as f:
            doc = _yaml_rt.load(f)
        if doc is None:  # empty file
            doc = {}
    else:
        doc = {}
    _set_nested(doc, path, value)

    tmp = config_path.with_suffix(config_path.suffix + ".tmp")
    with open(tmp, "w") as f:
        _yaml_rt.dump(doc, f)
    tmp.replace(config_path)


def _acquire_singleton_lock() -> bool:
    """Acquire an exclusive flock so only one menubar app runs at a time.

    Uses a separate lock file from the daemon's so the two can coexist.
    """
    global _singleton_lock_handle
    lock_dir = Path.home() / ".local" / "share" / "sentinel"
    lock_dir.mkdir(parents=True, exist_ok=True)
    _singleton_lock_handle = open(lock_dir / "sentinel-app.lock", "w")
    try:
        fcntl.flock(_singleton_lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    _singleton_lock_handle.write(str(os.getpid()))
    _singleton_lock_handle.flush()
    return True


class SentinelApp(rumps.App):
    def __init__(self) -> None:
        super().__init__("Sentinel", title="🛡 …", quit_button=None)

        self._config_path: Optional[Path] = resolve_config_path()
        self._config = load_config(self._config_path)
        self._collector = MacOSCollector()
        self._engine = AlertEngine(self._config)
        self._paused = False
        self._last_metrics: Optional[SystemMetrics] = None
        self._alert_history: list[tuple[datetime, Alert]] = []
        self._rule_items: dict[str, rumps.MenuItem] = {}

        self._cpu_item = rumps.MenuItem("CPU: —")
        self._mem_item = rumps.MenuItem("MEM: —")
        self._disk_item = rumps.MenuItem("DISK: —")
        self._battery_item = rumps.MenuItem("BAT: —")
        self._ai_summary = rumps.MenuItem("AI procs: —")
        self._ai_submenu = rumps.MenuItem("AI Processes")
        self._ai_submenu.add(rumps.MenuItem("(initializing)"))
        self._alert_summary = rumps.MenuItem(
            "No recent alerts", callback=self._on_summary_clicked
        )
        self._alert_submenu = rumps.MenuItem("Recent Alerts")
        self._alert_submenu.add(rumps.MenuItem("(none)"))
        self._scan_item = rumps.MenuItem("Scan Now", callback=self._on_scan_now)
        self._pause_item = rumps.MenuItem(
            "Pause monitoring", callback=self._on_toggle_pause
        )
        self._settings_submenu = self._build_settings_menu()
        self._open_log_item = rumps.MenuItem("Open Log")
        self._open_log_item.add(rumps.MenuItem(
            f"Warnings only · last {LOG_WINDOW_HOURS}h",
            callback=self._on_open_warning_log,
        ))
        self._open_log_item.add(rumps.MenuItem(
            f"All entries · last {LOG_WINDOW_HOURS}h",
            callback=self._on_open_all_log,
        ))
        self._quit_item = rumps.MenuItem("Quit Sentinel", callback=rumps.quit_application)

        self.menu = [
            self._cpu_item,
            self._mem_item,
            self._disk_item,
            self._battery_item,
            None,
            self._ai_summary,
            self._ai_submenu,
            None,
            self._alert_summary,
            self._alert_submenu,
            None,
            self._scan_item,
            self._pause_item,
            None,
            self._settings_submenu,
            None,
            self._open_log_item,
            None,
            self._quit_item,
        ]

        self._refresh()

    def _build_settings_menu(self) -> rumps.MenuItem:
        rules_submenu = rumps.MenuItem("Detection Rules")

        # Master switch first, separated from individual collectors.
        master = self._make_rule_item(DETECTION_RULES[0])
        rules_submenu.add(master)
        rules_submenu.add(None)

        for rule in DETECTION_RULES[1:]:
            rules_submenu.add(self._make_rule_item(rule))

        rules_submenu.add(None)

        bundled = rumps.MenuItem("Agent log: bundled rules")
        for rule in AGENT_LOG_SUBRULES:
            bundled.add(self._make_rule_item(rule))
        rules_submenu.add(bundled)

        rules_submenu.add(None)
        rules_submenu.add(
            rumps.MenuItem("About these rules…", callback=self._on_about_rules)
        )

        settings = rumps.MenuItem("Settings")
        settings.add(rules_submenu)
        if self._config_path:
            settings.add(
                rumps.MenuItem("Open config.yaml", callback=self._on_open_config)
            )
        return settings

    def _make_rule_item(self, rule: dict) -> rumps.MenuItem:
        item = rumps.MenuItem(rule["title"], callback=self._on_toggle_rule)
        item._sentinel_rule = rule  # type: ignore[attr-defined]
        item.state = 1 if _get_nested(
            self._config, rule["config_path"], rule["default"]
        ) else 0
        self._rule_items[rule["title"]] = item
        return item

    @rumps.timer(POLL_SECONDS)
    def _on_tick(self, _sender) -> None:
        if self._paused:
            return
        self._refresh()

    def _on_scan_now(self, _sender) -> None:
        self._refresh()

    def _on_toggle_pause(self, sender) -> None:
        self._paused = not self._paused
        sender.title = "Resume monitoring" if self._paused else "Pause monitoring"
        if self._paused:
            self.title = "🛡 ⏸"

    def _on_open_all_log(self, _sender) -> None:
        self._open_log_view(min_level=None, suffix="all", label="all levels")

    def _on_open_warning_log(self, _sender) -> None:
        self._open_log_view(
            min_level="WARNING", suffix="warnings", label="WARNING+ only (alerts)"
        )

    def _open_log_view(
        self, min_level: Optional[str], suffix: str, label: str
    ) -> None:
        data_dir = resolve_data_dir()
        log_path = data_dir / "sentinel.log"
        if not log_path.exists():
            rumps.alert("Log not found", f"Expected at: {log_path}")
            return

        try:
            entries = _recent_log_entries(log_path, LOG_WINDOW_HOURS, min_level)
        except Exception as exc:
            logging.exception("log read failed")
            rumps.alert("Log read failed", str(exc))
            return

        # Newest first so the default "open at top" behavior of TextEdit/
        # Console.app lands on the most recent entry.
        header = (
            f"# Sentinel log — last {LOG_WINDOW_HOURS} hours, {label}, newest first\n"
            f"# {len(entries)} entries from {log_path}\n"
            f"# Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )
        body = (
            "".join(reversed(entries))
            if entries
            else f"(no matching log entries in the last {LOG_WINDOW_HOURS} hours)\n"
        )

        out = data_dir / f"sentinel-recent-{LOG_WINDOW_HOURS}h-{suffix}.log"
        out.write_text(header + body)
        subprocess.Popen(["open", str(out)])

    def _on_toggle_rule(self, sender) -> None:
        rule = getattr(sender, "_sentinel_rule", None)
        if not rule:
            return

        new_state = 0 if sender.state else 1
        sender.state = new_state
        new_value = bool(new_state)
        _set_nested(self._config, rule["config_path"], new_value)

        if not self._config_path:
            rumps.alert(
                "Saved in memory only",
                "No config.yaml was found, so this toggle won't persist.\n"
                "Copy config.example.yaml → config.yaml to enable persistence.",
            )
            return

        try:
            _persist_setting(self._config_path, rule["config_path"], new_value)
        except Exception as exc:
            logging.exception("persist_setting failed")
            rumps.alert("Could not save config", str(exc))
            return

        try:
            rumps.notification(
                "Setting saved",
                rule["title"],
                "Restart the daemon to apply: launchctl unload/load "
                "~/Library/LaunchAgents/com.sentinel.agent.plist",
            )
        except Exception:
            # Notifications can fail on first run before TCC consent.
            pass

    def _on_about_rules(self, _sender) -> None:
        lines = ["Sentinel watches the following AI behaviors:", ""]
        for r in DETECTION_RULES:
            lines.append(f"• {r['title']}")
            lines.append(f"    {r['description']}")
            lines.append("")
        lines.append("Bundled inside the Agent log parser (each toggleable):")
        for r in AGENT_LOG_SUBRULES:
            lines.append(f"  • {r['title']}: {r['description']}")
        rumps.alert("Sentinel — Detection Rules", "\n".join(lines))

    def _on_open_config(self, _sender) -> None:
        if self._config_path and self._config_path.exists():
            subprocess.Popen(["open", str(self._config_path)])
        else:
            rumps.alert("config.yaml not found", "No user config to open.")

    def _refresh(self) -> None:
        try:
            metrics = self._collector.collect()
        except Exception as exc:
            logging.exception("collect failed")
            self.title = "🛡 ERR"
            self._alert_summary.title = f"Collector error: {exc}"
            return

        self._last_metrics = metrics
        self._render_title(metrics)
        self._render_metrics(metrics)
        self._render_ai_processes(metrics)

        try:
            new_alerts = self._engine.evaluate(metrics)
        except Exception:
            logging.exception("engine.evaluate failed")
            new_alerts = []
        self._render_alerts(new_alerts)

    def _render_title(self, metrics: SystemMetrics) -> None:
        ai_count = len(metrics.ai_processes)
        cpu = int(round(metrics.cpu_percent))
        self.title = f"🛡 {cpu}% · {ai_count}AI"

    def _render_metrics(self, m: SystemMetrics) -> None:
        temp = f" · {m.cpu_temp:.0f}°C" if m.cpu_temp else ""
        self._cpu_item.title = f"CPU: {m.cpu_percent}%{temp} ({m.thermal_pressure})"
        self._mem_item.title = f"MEM: {m.memory_percent}% · {m.memory_used_gb} GB used"
        self._disk_item.title = f"DISK: {m.disk_percent}% · {m.disk_free_gb} GB free"
        if m.battery_percent is not None:
            plug = "🔌" if m.battery_plugged else "🔋"
            self._battery_item.title = f"BAT: {plug} {m.battery_percent}%"
        else:
            self._battery_item.title = "BAT: n/a"

    def _render_ai_processes(self, m: SystemMetrics) -> None:
        n = len(m.ai_processes)
        if n == 0:
            self._ai_summary.title = "AI procs: none detected"
        else:
            top = m.ai_processes[0]
            self._ai_summary.title = (
                f"AI procs: {n} · top {top['name']} ({top['cpu']}%)"
            )

        self._ai_submenu.clear()
        if not m.ai_processes:
            self._ai_submenu.add(rumps.MenuItem("(none)"))
            return
        for p in m.ai_processes:
            label = f"{p['name']} · pid {p['pid']} · {p['cpu']}% · {p['mem_mb']:.0f}MB"
            self._ai_submenu.add(rumps.MenuItem(label))

    def _render_alerts(self, new_alerts: list[Alert]) -> None:
        now = datetime.now()
        for alert in new_alerts:
            self._alert_history.insert(0, (now, alert))
        del self._alert_history[ALERT_HISTORY_LIMIT:]

        if not self._alert_history:
            self._alert_summary.title = "No recent alerts"
        else:
            ts, top = self._alert_history[0]
            emoji = _LEVEL_EMOJI.get(top.level, "•")
            self._alert_summary.title = f"{emoji} {ts.strftime('%H:%M:%S')}  {top.title}"

        self._alert_submenu.clear()
        if not self._alert_history:
            self._alert_submenu.add(rumps.MenuItem("(none)"))
            return
        for ts, alert in self._alert_history:
            self._alert_submenu.add(self._make_alert_item(ts, alert))

    def _make_alert_item(self, ts: datetime, alert: Alert) -> rumps.MenuItem:
        emoji = _LEVEL_EMOJI.get(alert.level, "•")
        label = f"{emoji} {ts.strftime('%H:%M:%S')}  {alert.title}"
        item = rumps.MenuItem(label, callback=self._on_alert_clicked)
        # Stash so the click handler can recover the full alert.
        item._sentinel_alert = (ts, alert)  # type: ignore[attr-defined]
        return item

    def _on_alert_clicked(self, sender) -> None:
        payload = getattr(sender, "_sentinel_alert", None)
        if payload is None:
            return
        ts, alert = payload
        self._show_alert_detail(ts, alert)

    def _on_summary_clicked(self, _sender) -> None:
        if not self._alert_history:
            return
        ts, alert = self._alert_history[0]
        self._show_alert_detail(ts, alert)

    def _show_alert_detail(self, ts: datetime, alert: Alert) -> None:
        emoji = _LEVEL_EMOJI.get(alert.level, "•")
        body = (
            f"When:     {ts.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Severity: {emoji} {alert.level.upper()}  ·  Category: {alert.category}\n"
            f"\n"
            f"{alert.message}"
        )
        rumps.alert(alert.title, body)


def main() -> None:
    if not _acquire_singleton_lock():
        message = (
            "Another Sentinel menubar app is already running.\n"
            "Quit the existing one (menu → Quit Sentinel) before launching a new one."
        )
        print(f"sentinel-app: {message}", file=sys.stderr)
        try:
            rumps.alert("Sentinel already running", message)
        except Exception:
            pass
        sys.exit(1)
    SentinelApp().run()


if __name__ == "__main__":
    main()
