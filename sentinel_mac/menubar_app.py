"""Sentinel — Menubar App (PoC).

Standalone macOS menubar app that visualizes Sentinel metrics live.

Reuses MacOSCollector + AlertEngine. Does NOT send notifications and does
NOT acquire the daemon PID lock — intentionally so it can run alongside
the LaunchAgent daemon during the PoC. The daemon keeps doing the
"alert delivery" job; the menubar app is a read-only viewer for now.

Run with `sentinel-app` after `pip install -e '.[app]'`.
"""

from __future__ import annotations

import fcntl
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import IO, Optional

import rumps

from sentinel_mac.collectors.system import MacOSCollector
from sentinel_mac.core import load_config, resolve_config_path, resolve_data_dir
from sentinel_mac.engine import AlertEngine
from sentinel_mac.models import Alert, SystemMetrics

POLL_SECONDS = 5
ALERT_HISTORY_LIMIT = 5

# Held for the lifetime of the process — losing this reference would release
# the flock and let a second instance start.
_singleton_lock_handle: Optional[IO] = None


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

        config = load_config(resolve_config_path())
        self._collector = MacOSCollector()
        self._engine = AlertEngine(config)
        self._paused = False
        self._last_metrics: Optional[SystemMetrics] = None
        self._alert_history: list[tuple[datetime, Alert]] = []

        self._cpu_item = rumps.MenuItem("CPU: —")
        self._mem_item = rumps.MenuItem("MEM: —")
        self._disk_item = rumps.MenuItem("DISK: —")
        self._battery_item = rumps.MenuItem("BAT: —")
        self._ai_summary = rumps.MenuItem("AI procs: —")
        self._ai_submenu = rumps.MenuItem("AI Processes")
        self._ai_submenu.add(rumps.MenuItem("(initializing)"))
        self._alert_summary = rumps.MenuItem("No recent alerts")
        self._alert_submenu = rumps.MenuItem("Recent Alerts")
        self._alert_submenu.add(rumps.MenuItem("(none)"))
        self._scan_item = rumps.MenuItem("Scan Now", callback=self._on_scan_now)
        self._pause_item = rumps.MenuItem(
            "Pause monitoring", callback=self._on_toggle_pause
        )
        self._open_log_item = rumps.MenuItem("Open Log", callback=self._on_open_log)
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
            self._open_log_item,
            None,
            self._quit_item,
        ]

        self._refresh()

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

    def _on_open_log(self, _sender) -> None:
        log_path = resolve_data_dir() / "sentinel.log"
        if log_path.exists():
            subprocess.Popen(["open", str(log_path)])
        else:
            rumps.alert("Log not found", f"Expected at: {log_path}")

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
            _, top = self._alert_history[0]
            self._alert_summary.title = f"⚠ {top.title}"

        self._alert_submenu.clear()
        if not self._alert_history:
            self._alert_submenu.add(rumps.MenuItem("(none)"))
            return
        for ts, alert in self._alert_history:
            label = f"[{alert.level.upper()}] {ts.strftime('%H:%M:%S')} · {alert.title}"
            self._alert_submenu.add(rumps.MenuItem(label))


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
