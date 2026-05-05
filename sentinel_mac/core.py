#!/usr/bin/env python3
"""
Sentinel — AI Session Guardian for macOS
Monitors system resources and sends smart alerts via ntfy.sh
"""

import argparse as _argparse
import contextlib
import fcntl
import json
import logging
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import IO, Any, Iterator, Optional

# ─────────────────────────────────────────────
# Config Resolution
# ─────────────────────────────────────────────
import yaml

from sentinel_mac.collectors.agent_log_parser import AgentLogParser  # noqa: F401
from sentinel_mac.collectors.context import HostContext  # noqa: F401
from sentinel_mac.collectors.fs_watcher import FSWatcher  # noqa: F401
from sentinel_mac.collectors.net_tracker import NetTracker  # noqa: F401
from sentinel_mac.collectors.project_context import ProjectContext  # noqa: F401
from sentinel_mac.collectors.system import MacOSCollector  # noqa: F401
from sentinel_mac.engine import AlertEngine  # noqa: F401
from sentinel_mac.event_logger import EventLogger  # noqa: F401

# Re-export from new modules so existing imports (tests, sentinel.py) keep working
from sentinel_mac.models import Alert, SecurityEvent, SystemMetrics  # noqa: F401
from sentinel_mac.notifier import (  # noqa: F401
    MacOSNotifier,
    NotificationManager,
    NtfyNotifier,
    SlackNotifier,
    TelegramNotifier,
)

DEFAULT_CONFIG: dict[str, Any] = {
    "ntfy_topic": "sentinel-default",
    "ntfy_server": "https://ntfy.sh",
    "notifications_enabled": True,
    "check_interval_seconds": 30,
    "status_interval_minutes": 60,
    "cooldown_minutes": 10,
    # Days to keep <data_dir>/events/YYYY-MM-DD.jsonl files. Pruned during
    # daily rotation. Must be a positive integer; invalid values fall back
    # to EventLogger.DEFAULT_RETENTION_DAYS with a WARNING.
    "event_log_retention_days": 90,
    "thresholds": {
        "battery_warning": 20,
        "battery_critical": 10,
        "battery_drain_rate": 10,
        "temp_warning": 85,
        "temp_critical": 95,
        "memory_critical": 90,
        "network_spike_mb": 100,
        "disk_critical": 90,
    }
}


def _resolve_event_log_retention(config: dict) -> Optional[int]:
    """Return positive int or None (None → EventLogger uses DEFAULT_RETENTION_DAYS).

    Invalid values (non-int, <=0) log a WARNING and fall back to None so the
    daemon never aborts startup over a typo. Per ADR 0005 §D3 fail-soft.
    """
    raw = config.get("event_log_retention_days")
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        logging.warning(
            "event_log_retention_days must be a positive integer (got %r); "
            "falling back to default", raw,
        )
        return None
    return raw


def resolve_config_path(explicit_path: Optional[str] = None) -> Optional[Path]:
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


# ADR 0008 D1 frozen three-state enum for `notifications.context_level`.
# Kept here (not imported from engine) so `_validate_config` can normalize
# values before the engine is even constructed — the engine reads the
# already-validated value at startup.
_VALID_NOTIFICATION_CONTEXT_LEVELS: frozenset[str] = frozenset(
    {"minimal", "standard", "full"}
)


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
    }
    thresholds = config.get("thresholds", {})
    if not isinstance(thresholds, dict):
        config["thresholds"] = DEFAULT_CONFIG["thresholds"].copy()
    else:
        for key, (lo, hi) in threshold_ranges.items():
            val = thresholds.get(key)
            if not isinstance(val, (int, float)) or val < lo:
                thresholds[key] = DEFAULT_CONFIG["thresholds"][key]
            elif val > hi:
                thresholds[key] = hi
        config["thresholds"] = thresholds

    # ADR 0008 D5 — fail-soft validation of `notifications.context_level`.
    # Unknown / typo'd values fall back to "standard" + WARNING; never
    # crash on a bad value here (the key is convenience plumbing, not a
    # security gate). Missing key is silent — default is "standard".
    notif = config.get("notifications")
    if isinstance(notif, dict):
        level = notif.get("context_level")
        if level is not None and level not in _VALID_NOTIFICATION_CONTEXT_LEVELS:
            logging.warning(
                "Invalid notifications.context_level=%r; "
                "falling back to 'standard'. Valid values: %s",
                level,
                sorted(_VALID_NOTIFICATION_CONTEXT_LEVELS),
            )
            notif["context_level"] = "standard"

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


def load_config(config_path: Optional[Path] = None) -> dict:
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
# Daemon lock helpers (shared with the menubar app)
# ─────────────────────────────────────────────


def daemon_lock_path() -> Path:
    """Fixed path so two daemons started from different cwds find each other."""
    lock_dir = Path.home() / ".local" / "share" / "sentinel"
    lock_dir.mkdir(parents=True, exist_ok=True)
    return lock_dir / "sentinel.lock"


def try_acquire_daemon_lock() -> Optional[IO[str]]:
    """Try to grab the exclusive daemon flock.

    Returns the open file handle on success (caller must keep the reference
    alive — losing it releases the lock) or None if another process holds it.
    """
    fp = open(daemon_lock_path(), "w")  # noqa: SIM115 — daemon-lifetime fd; ownership is handed to the caller.
    try:
        fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fp.close()
        return None
    fp.write(str(os.getpid()))
    fp.flush()
    return fp


# ─────────────────────────────────────────────
# Main Daemon
# ─────────────────────────────────────────────

class Sentinel:
    """Main monitoring daemon."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        *,
        acquire_lock: bool = True,
        install_signal_handlers: bool = True,
    ):
        """Initialize the daemon.

        acquire_lock=False / install_signal_handlers=False let an embedding
        process (the menubar app) own the daemon lock and shutdown lifecycle
        instead of having Sentinel grab them via sys.exit / signal handlers.
        """
        # Prevent duplicate instances via PID file lock
        self._pid_file: Optional[IO[str]] = None
        self._data_dir = resolve_data_dir()
        self._data_dir.mkdir(parents=True, exist_ok=True)
        if acquire_lock:
            self._acquire_lock()

        # ADR 0005 D5/D7 — reload infrastructure must be in place BEFORE the
        # SIGHUP handler is registered (which itself MUST be registered before
        # any collector starts). The `_shutdown_event` is reused by the reload
        # worker loop so a daemon shutdown wakes it cleanly.
        self._reload_lock = threading.RLock()
        self._reload_requested = threading.Event()
        self._shutdown_event = threading.Event()
        self._reload_worker: Optional[threading.Thread] = None

        # Resolve + remember config path so SIGHUP-driven reload reads the
        # same file the daemon started from. None means "use defaults" — the
        # reload worker still re-runs load_config(None) to pick up env-var
        # overrides on each reload.
        resolved = resolve_config_path(config_path)
        self._config_path: Optional[Path] = resolved
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

        # ADR 0005 D7 frozen surface: SIGHUP handler is installed in
        # __init__, immediately after the lock is acquired and before any
        # collector is instantiated. Single registration per process; the
        # reload worker (started below) does the actual reload work.
        if install_signal_handlers:
            # signal.signal is only legal from the main thread of the
            # main interpreter. In embedded mode (menubar app, tests)
            # this can be a no-op — kill -HUP simply will not fire.
            with contextlib.suppress(ValueError, AttributeError):  # pragma: no cover — non-main thread
                signal.signal(signal.SIGHUP, self._on_sighup)

        self.collector = MacOSCollector()
        self.engine = AlertEngine(self.config)
        self.notifier = NotificationManager(self.config)
        self._event_logger = EventLogger(
            self._data_dir,
            retention_days=_resolve_event_log_retention(self.config),
        )

        # Security layer — event queue shared between collectors and main loop
        self._security_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._fs_watcher: Optional[FSWatcher] = None
        self._net_tracker: Optional[NetTracker] = None
        self._agent_log_parser: Optional[AgentLogParser] = None

        # Host context (ADR 0001) — shared across collectors. Disabled by
        # default; load() is idempotent and a no-op when disabled.
        self.host_ctx = HostContext.from_config(self.config)
        self.host_ctx.load()

        # ADR 0007 D4 — single ProjectContext shared across collectors
        # that enrich events with project_meta (agent_log_parser +
        # fs_watcher; net_tracker is excluded per D5). Mirrors the
        # HostContext injection pattern from ADR 0001. No .load() call —
        # ProjectContext is lazy; first lookup populates the cache.
        self.project_ctx = ProjectContext.from_config(self.config)

        # Start security collectors if enabled
        sec_config = self.config.get("security", {})
        # Stash the security rules dict so SIGHUP-driven reload can compare
        # the new vs old shape (e.g., FSWatcher watch_paths) before the swap.
        self._security_rules: dict = sec_config
        if sec_config.get("enabled", False):
            fs_config = sec_config.get("fs_watcher", {})
            if fs_config.get("enabled", True):
                self._fs_watcher = FSWatcher(
                    self.config, self._security_queue,
                    project_ctx=self.project_ctx,
                )
                # ADR 0002 §D3 — wire EventLogger so download joins can
                # rewrite the JSONL line in-place. Cheap no-op when the
                # download_tracking feature is disabled (the rewrite is
                # only reached after a register_download() call).
                self._fs_watcher.attach_event_logger(self._event_logger)
            net_config = sec_config.get("net_tracker", {})
            if net_config.get("enabled", True):
                # ADR 0007 D5 — net_tracker intentionally NOT given a
                # project_ctx (per-connection cwd would require
                # lsof -p <pid> -d cwd per emitted event; perf cost
                # unacceptable for a high-frequency stream).
                self._net_tracker = NetTracker(
                    self.config, self._security_queue,
                    host_ctx=self.host_ctx,
                )
            agent_config = sec_config.get("agent_logs", {})
            if agent_config.get("enabled", True):
                self._agent_log_parser = AgentLogParser(
                    self.config, self._security_queue,
                    host_ctx=self.host_ctx,
                    project_ctx=self.project_ctx,
                )

        # v0.9 Track 3b (PR #28 follow-up) — wire the agent log
        # parser's last-activity getter into the AlertEngine so the
        # stuck_process heuristic can suppress false-positives during
        # active interactive sessions. Done after the collectors block
        # so the parser instance (or None) is final. SIGHUP reload
        # does NOT swap the AgentLogParser instance (ADR 0005 D2
        # explicitly preserves agent log parser state across reload —
        # tail offsets, and by extension the same instance), so this
        # wire-up does not need to be repeated in _do_reload.
        if self._agent_log_parser is not None:
            self.engine.set_agent_activity_callback(
                self._agent_log_parser.last_user_or_assistant_activity_epoch
            )

        self.interval = self.config.get("check_interval_seconds", 30)
        self.status_interval = self.config.get("status_interval_minutes", 60)
        self._last_status = datetime.min
        self._running = True

        if install_signal_handlers:
            signal.signal(signal.SIGTERM, self._shutdown)
            signal.signal(signal.SIGINT, self._shutdown)

        # ADR 0005 D5 — start the reload worker thread last so every
        # `self.*` it might read has been initialized. Daemon thread so it
        # cannot block process exit; the loop also watches `_shutdown_event`
        # for a clean wakeup on stop().
        self._reload_worker = threading.Thread(
            target=self._reload_worker_loop,
            name="sentinel-reload",
            daemon=True,
        )
        self._reload_worker.start()

    def stop(self) -> None:
        """External shutdown trigger for embedded mode (menubar app).

        Idempotent. Releases security collectors, the event log, and the
        PID lock if held — the same cleanup the SIGTERM handler does, minus
        the signal-handler signature.
        """
        self._shutdown(None, None)

    def _acquire_lock(self) -> None:
        """Acquire the global daemon lock; print + sys.exit on contention."""
        fp = try_acquire_daemon_lock()
        if fp is None:
            lock_file = daemon_lock_path()
            print(f"ERROR: Sentinel is already running. Lock file: {lock_file}")
            sys.exit(1)
        self._pid_file = fp

    def adopt_lock(self, fp: IO[str]) -> None:
        """Install a lock handle acquired externally (by the menubar app).

        Used in embedded mode where the menubar tries to grab the daemon lock
        before instantiating Sentinel(acquire_lock=False); on success, the
        same handle is handed off here so _shutdown can release it cleanly.
        """
        self._pid_file = fp

    def _shutdown(self, signum: Optional[int], frame: Any) -> None:
        logging.info("\U0001f6d1 Sentinel shutting down...")
        self._running = False
        # Wake the reload worker so it can observe `_shutdown_event` and
        # exit cleanly instead of blocking another second on Event.wait().
        # Setting `_reload_requested` along with `_shutdown_event` makes the
        # worker fall through its inner branch immediately on wake-up.
        self._shutdown_event.set()
        self._reload_requested.set()
        if self._fs_watcher:
            self._fs_watcher.stop()
        if self._agent_log_parser:
            self._agent_log_parser.stop()
        # ADR 0001 D2: final flush so observations from the current window
        # survive a clean shutdown. No-op when context is disabled.
        try:
            self.host_ctx.flush()
        except Exception as exc:  # pragma: no cover — flush is best-effort
            logging.debug("host_ctx.flush() failed during shutdown: %s", exc)
        self._event_logger.close()
        if self._pid_file and not self._pid_file.closed:
            fcntl.flock(self._pid_file, fcntl.LOCK_UN)
            self._pid_file.close()

    # ── ADR 0005 — daemon reload protocol ───────────────────────────

    def _on_sighup(self, signum: int, frame: Any) -> None:
        """async-signal-safe: just set the flag.

        Heavy lifting (config parse, validation, swap) happens in the
        dedicated reload worker thread per ADR 0005 §D5 — running
        ``yaml.safe_load`` from a real signal handler is unsafe because
        Python's import machinery and most stdlib I/O are not async-signal-safe.
        """
        self._reload_requested.set()

    def _reload_worker_loop(self) -> None:
        """ADR 0005 D5 — wait on `_reload_requested`, run `_do_reload`, repeat.

        Coalescing: the event is `clear()`ed before `_do_reload` runs, so a
        SIGHUP arriving during the reload re-fires the event exactly once
        and the next iteration picks it up. Multiple SIGHUPs queued
        between iterations collapse into a single reload.

        Termination: the loop exits when `_shutdown_event` is set. The
        shutdown handler also sets `_reload_requested` so we never sleep
        the full timeout after stop() is invoked.
        """
        while not self._shutdown_event.is_set():
            # 1.0s timeout means even if no SIGHUP ever fires, the loop
            # still wakes regularly to check the shutdown flag — keeps
            # process exit instant under Ctrl+C.
            if not self._reload_requested.wait(timeout=1.0):
                continue
            self._reload_requested.clear()
            if self._shutdown_event.is_set():
                break
            try:
                self._do_reload()
            except Exception as exc:
                # ADR 0005 D3: outer try keeps the daemon alive even if the
                # reload pipeline raises in an unexpected place. The
                # per-step diagnostics inside _do_reload give finer detail;
                # this is the last-resort safety net.
                logging.warning(
                    "config reload failed at outer scope: %s; keeping previous config",
                    exc,
                )

    def _validate_reload_config(self, new_config: dict) -> None:
        """ADR 0005 D3 step 4 — minimal sanity check before the swap.

        Why a second check exists alongside the module-level
        `_validate_config`: that helper is invoked from `load_config` and
        is *forgiving* — it falls back to defaults when individual fields
        are malformed so a typo never crashes the daemon at startup. At
        reload time we have the opposite priority: a structurally invalid
        new config must abort the reload (D3 atomic-or-nothing) so the
        daemon keeps the old, working config. This guard catches the
        structural cases `load_config` would silently mask (top-level
        non-mapping, `thresholds`/`security` set to a non-dict, etc.) and
        is also useful when a test monkeypatches `load_config`.

        Strictness scope: structural only. Value clamping (already done by
        `_validate_config`) is not repeated here.

        Raises:
            ValueError: when the structure is unusable.
        """
        if not isinstance(new_config, dict):
            raise ValueError("config root is not a mapping")
        thresholds = new_config.get("thresholds")
        if thresholds is not None and not isinstance(thresholds, dict):
            raise ValueError("`thresholds` must be a mapping")
        security = new_config.get("security")
        if security is not None and not isinstance(security, dict):
            raise ValueError("`security` must be a mapping")

        # ADR 0008 D5 — fail-soft for notifications.context_level. ADR
        # 0005 D3 explicitly says config reload is atomic-or-nothing: a
        # bad context_level value must NOT abort the reload (it's a UI
        # convenience, not structural). Mirror the load_config-time
        # behavior — normalize the bad value to "standard" + WARNING
        # instead of raising. Missing notifications dict is silent
        # (engine treats absence as "standard" anyway).
        notif = new_config.get("notifications")
        if isinstance(notif, dict):
            level = notif.get("context_level")
            if level is not None and level not in _VALID_NOTIFICATION_CONTEXT_LEVELS:
                logging.warning(
                    "Invalid notifications.context_level=%r in reloaded "
                    "config; falling back to 'standard'. Valid values: %s",
                    level,
                    sorted(_VALID_NOTIFICATION_CONTEXT_LEVELS),
                )
                notif["context_level"] = "standard"

    def _do_reload(self) -> None:
        """ADR 0005 D3 — atomic-or-nothing reload sequence.

        The new components (host_ctx, thresholds dict, security_rules) are
        built into LOCAL variables. Only after they are all built does the
        method enter the lock and assign them onto `self.*`. A failure
        anywhere in steps 2-5 leaves no observable side effect on the live
        daemon — the worker logs a warning and the daemon keeps running on
        the previous config.

        ADR 0005 D2 explicitly excludes (NEVER reloaded):
          - notifier rate-limit counters
          - AlertEngine cooldown timestamps
          - agent log parser tail offsets
          - typosquatting hardcoded set
          - daemon PID / lock file
        """
        # Step 2 — flush in-memory frequency cache so we cross the reload
        # boundary without losing observations.
        try:
            self.host_ctx.flush()
        except Exception as exc:  # pragma: no cover — best-effort
            logging.debug("host_ctx.flush() during reload failed: %s", exc)

        # Step 3 — load new config (returns defaults on parse error; empty
        # dict for a missing path was the existing semantic).
        try:
            new_config = load_config(self._config_path)
        except Exception as exc:
            logging.warning(
                "config reload failed at load_config: %s; keeping previous config",
                exc,
            )
            return

        # Step 4 — validate. Bail before touching any side state.
        try:
            self._validate_reload_config(new_config)
        except ValueError as exc:
            logging.warning(
                "config reload failed at validate: %s; keeping previous config",
                exc,
            )
            return

        # Step 5 — build new components in side state. If any step raises,
        # `self.*` is unchanged and we abort with the old state intact.
        try:
            new_host_ctx = HostContext.from_config(new_config)
            new_host_ctx.load()
            new_thresholds = new_config.get("thresholds", {}) or {}
            new_security_rules = new_config.get("security", {}) or {}
        except Exception as exc:
            logging.warning(
                "config reload failed at build: %s; keeping previous config",
                exc,
            )
            return

        # Compute the FSWatcher-restart decision against the OLD security
        # rules before the swap so the comparison is meaningful.
        old_fs_paths = (
            (self._security_rules or {}).get("fs_watcher", {}).get("watch_paths")
        )
        new_fs_paths = (
            new_security_rules.get("fs_watcher", {}).get("watch_paths")
        )
        fs_paths_changed = old_fs_paths != new_fs_paths

        # Step 6 — atomic swap under lock. ADR 0005 D2 frozen surface:
        #   - host_ctx: replaced wholesale (new instance, already loaded)
        #   - engine.thresholds: replaced (mutates the existing AlertEngine,
        #     does NOT reset cooldowns — those live in `engine.last_alert_times`
        #     or similar, which is left untouched by design)
        #   - notifier rate-limit counters: NOT touched
        #   - event_logger: close + reopen so log rotation can land cleanly
        #   - FSWatcher: restarted only when watch_paths changed (expensive)
        with self._reload_lock:
            self.config = new_config
            self.host_ctx = new_host_ctx
            self.engine.thresholds = new_thresholds
            # ADR 0008 D4 — refresh the engine's cached context_level so
            # the new value takes effect on the next alert. Mirrors the
            # construction-time logic in AlertEngine.__init__ (defensive
            # default + frozen-enum check). _validate_reload_config
            # already normalized invalid values to "standard".
            new_notif = (
                new_config.get("notifications") or {}
                if isinstance(new_config.get("notifications"), dict)
                else {}
            )
            new_level = new_notif.get("context_level", "standard")
            if new_level not in _VALID_NOTIFICATION_CONTEXT_LEVELS:
                new_level = "standard"
            self.engine._context_level = new_level
            self._security_rules = new_security_rules

            # event_logger swap inside the same lock (D2 row): close the
            # current handle so the next .log() call rotates into a fresh
            # file. ADR 0005 §D5 read-side instrumentation is now in
            # place: the main loop and the security queue drainer call
            # `_snapshot_for_main_loop()` at cycle start to take a
            # consistent reference snapshot under this same lock, so a
            # mid-cycle swap cannot surface partially-replaced state
            # (e.g., new host_ctx paired with old engine.thresholds).
            # The close→reopen window is fully covered: snapshots taken
            # before this block see the old logger; snapshots taken
            # after see the new one; nobody sees a closed handle.
            try:
                self._event_logger.close()
            except Exception as exc:  # pragma: no cover — close is idempotent
                logging.debug("event_logger.close during reload failed: %s", exc)
            self._event_logger = EventLogger(
                self._data_dir,
                retention_days=_resolve_event_log_retention(self.config),
            )

            # FSWatcher restart only if watch_paths actually changed.
            # Restarting the watchdog observer is expensive (~100ms) so we
            # gate on actual change per ADR 0005 D2 row.
            if fs_paths_changed and self._fs_watcher is not None:
                self._restart_fs_watcher(new_security_rules.get("fs_watcher", {}))

            # NOTE — D2 explicitly preserved (do NOT touch):
            #   self.notifier   (rate-limit counters, pending ntfy retries)
            #   self.engine.cooldowns / last_alert_times (active cooldowns)
            #   self._agent_log_parser tail offsets
            #   typosquatting reference set (hardcoded, not config)

        logging.info("reloaded config from %s", self._config_path)

    def _restart_fs_watcher(self, new_fs_config: dict) -> None:
        """Stop and restart the FSWatcher with the new watch_paths.

        Called from `_do_reload` only when `watch_paths` actually changed
        (per ADR 0005 D2 row). Best-effort — a failure to restart logs a
        warning and leaves `self._fs_watcher = None` so the daemon keeps
        running without file-system telemetry rather than crashing.
        """
        old = self._fs_watcher
        try:
            if old is not None:
                old.stop()
        except Exception as exc:  # pragma: no cover — stop should be idempotent
            logging.debug("fs_watcher.stop during reload failed: %s", exc)

        try:
            new_watcher = FSWatcher(self.config, self._security_queue)
            new_watcher.attach_event_logger(self._event_logger)
            new_watcher.start()
            self._fs_watcher = new_watcher
        except Exception as exc:
            logging.warning(
                "FSWatcher restart failed during reload: %s; "
                "fs_watcher disabled until next restart",
                exc,
            )
            self._fs_watcher = None

    def _snapshot_for_main_loop(self) -> tuple:
        """ADR 0005 §D5 — take a consistent reference snapshot under ``_reload_lock``.

        Returns a 4-tuple ``(engine, host_ctx, event_logger, security_rules)``.
        The main loop and the security queue drainer call this once at cycle
        start so a SIGHUP-driven reload landing mid-cycle cannot surface
        partially-swapped state (e.g., new ``host_ctx`` paired with the old
        ``engine.thresholds``, or a logger that was closed mid-write).

        Lock-hold discipline (ADR 0005 §D5): the lock is held only for the
        attribute reads — all downstream processing (collect / evaluate /
        notify / log / queue drain) runs against the local snapshot and so
        does **not** delay an in-flight reload worker waiting for the same
        ``_reload_lock``. This keeps reload latency sub-second per the D5
        contract.
        """
        with self._reload_lock:
            return (
                self.engine,
                self.host_ctx,
                self._event_logger,
                self._security_rules,
            )

    def run(self) -> None:
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
                # ADR 0005 §D5 — take a consistent snapshot of mutable
                # reload-managed refs at the top of every iteration. All
                # downstream calls in this iteration use the snapshot so a
                # mid-cycle SIGHUP reload cannot surface partial state.
                engine, host_ctx, _event_logger, _security_rules = (
                    self._snapshot_for_main_loop()
                )

                metrics = self.collector.collect()

                logging.info(
                    "CPU:{}% {}MEM:{}% DISK:{}% BAT:{}{}% AI:{}procs".format(
                        metrics.cpu_percent,
                        f"T:{metrics.cpu_temp}°C " if metrics.cpu_temp else "",
                        metrics.memory_percent,
                        metrics.disk_percent,
                        "\U0001f50c" if metrics.battery_plugged else "\U0001f50b",
                        metrics.battery_percent,
                        len(metrics.ai_processes),
                    )
                )

                alerts = engine.evaluate(metrics)
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
                    # ADR 0001 D2: piggy-back host context flush on the
                    # status report tick so we do not own a separate timer.
                    # No-op when context is disabled. Uses the snapshot
                    # ref so a reload landing mid-tick does not flush a
                    # stale host_ctx that the swap already replaced.
                    host_ctx.flush()
                    self._last_status = now

            except Exception as e:
                logging.error(f"Monitor error: {e}", exc_info=True)

            time.sleep(self.interval)

        logging.info("Sentinel stopped.")

    def _process_security_events(self) -> None:
        """Drain the security event queue, log to JSONL, and generate alerts.

        ADR 0005 §D5 — the drainer takes its own snapshot of reload-managed
        refs at the top of the cycle so events are routed against a
        consistent (engine, event_logger) pair even if a SIGHUP reload
        lands mid-drain. Within a single cycle every event is processed
        against the same snapshot; the next cycle picks up the new refs.
        """
        # Snapshot once per drain cycle (D5 read-side lock instrumentation).
        # Lock is released immediately; queue / fs_watcher work runs outside.
        engine, _host_ctx, event_logger, _security_rules = (
            self._snapshot_for_main_loop()
        )
        processed = 0
        while not self._security_queue.empty() and processed < 100:
            try:
                event = self._security_queue.get_nowait()
                event_logger.log(event)

                # ADR 0002 §D3 — register agent_download events with the
                # FSWatcher so a matching file_create/modify within the
                # configured window will populate joined_fs_event on the
                # JSONL line we just wrote. Skipped when no fs_watcher,
                # the feature is disabled, or output_path is unknown
                # (e.g., wget no-flag basename case).
                if (
                    event.event_type == "agent_download"
                    and self._fs_watcher is not None
                    and self._fs_watcher.download_tracking_enabled
                ):
                    output_path = event.detail.get("output_path")
                    if isinstance(output_path, str) and os.path.isabs(
                        os.path.expanduser(output_path)
                    ):
                        deadline = (
                            int(time.time())
                            + self._fs_watcher.join_window_seconds
                        )
                        self._fs_watcher.register_download(
                            event_id=event.event_id,
                            output_path=output_path,
                            deadline_epoch=deadline,
                            date=event.timestamp.date(),
                        )

                alerts = engine.evaluate_security_event(event)
                for alert in alerts:
                    logging.warning(f"\U0001f6a8 [security] {alert.level}: {alert.title}")
                    self.notifier.send(alert)
                processed += 1
            except queue.Empty:
                break


# ─────────────────────────────────────────────
# Report — filter helpers (v0.7 Track A)
# ─────────────────────────────────────────────

# Severity classification thresholds. Public constants so consumers (tests,
# future Pro tooling) can reference the same boundaries.
SEVERITY_CRITICAL_THRESHOLD = 0.8
SEVERITY_WARNING_THRESHOLD = 0.4
VALID_SEVERITIES = frozenset({"critical", "warning", "info"})

# parse_since upper bound — protects against typos like "9999d" that would
# load every JSONL on disk. 365d covers retention (90d default) + slack.
_PARSE_SINCE_MAX_SECONDS = 365 * 86400

# `7d` / `24h` / `30m` / `3600s` / bare integer (seconds).
_DURATION_RE = re.compile(r"^\s*(?P<num>\d+)\s*(?P<unit>[smhd]?)\s*$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 1}


def _classify_severity(risk_score: float) -> str:
    """Map a numeric risk_score to a severity label.

    Mapping (matches pre-v0.7 behavior in generate_report):
      >= 0.8        → critical
      0.4 .. 0.8    → warning
      < 0.4         → info
    """
    if risk_score >= SEVERITY_CRITICAL_THRESHOLD:
        return "critical"
    if risk_score >= SEVERITY_WARNING_THRESHOLD:
        return "warning"
    return "info"


def parse_since(value: str) -> int:
    """Parse --since duration into seconds.

    Supported suffixes: s (seconds), m (minutes), h (hours), d (days).
    A bare integer is interpreted as seconds.

    Raises:
        argparse.ArgumentTypeError: on invalid format, non-positive value,
            or value exceeding 365 days.
    """
    if not isinstance(value, str) or not value.strip():
        raise _argparse.ArgumentTypeError(
            "invalid --since value: expected like '7d', '24h', '30m', '3600s', or integer seconds"
        )
    m = _DURATION_RE.match(value)
    if not m:
        raise _argparse.ArgumentTypeError(
            f"invalid --since value: {value!r} (expected '7d' / '24h' / '30m' / '3600s' / integer)"
        )
    try:
        num = int(m.group("num"))
    except ValueError as exc:  # pragma: no cover — regex already constrained
        raise _argparse.ArgumentTypeError(f"invalid --since value: {value!r}") from exc
    unit = m.group("unit") or ""
    seconds = num * _UNIT_SECONDS[unit]
    if seconds <= 0:
        raise _argparse.ArgumentTypeError(
            f"--since must be positive, got {value!r}"
        )
    if seconds > _PARSE_SINCE_MAX_SECONDS:
        raise _argparse.ArgumentTypeError(
            f"--since exceeds 365 days cap (got {value!r})"
        )
    return seconds


def _parse_csv_set(
    value: Optional[str],
    *,
    valid: Optional[set] = None,
    flag: str = "filter",
) -> Optional[set]:
    """Parse a comma-separated argparse value into a set of trimmed tokens.

    None or all-whitespace input returns None (meaning "no filter").
    Optional `valid` argument enforces an enum; violations raise
    argparse.ArgumentTypeError listing the offending tokens.
    """
    if value is None:
        return None
    tokens = {tok.strip() for tok in value.split(",") if tok.strip()}
    if not tokens:
        return None
    if valid is not None:
        invalid = sorted(tokens - set(valid))
        if invalid:
            raise _argparse.ArgumentTypeError(
                f"--{flag}: invalid value(s) {invalid!r}; allowed: {sorted(valid)!r}"
            )
    return tokens


# ─────────────────────────────────────────────
# Report — main entrypoint
# ─────────────────────────────────────────────


def _iter_event_lines(
    events_dir: Path, start_dt: datetime, end_dt: datetime
) -> Iterator[tuple[Path, str]]:
    """Yield (filepath, raw_line) for events in the dated JSONL range.

    Streams line-by-line — never holds the full file in memory. Files outside
    the [start_dt, end_dt] day range are skipped without opening.
    """
    # Iterate inclusive day range (start day .. end day) — JSONL day files are
    # named YYYY-MM-DD.jsonl by event_logger._rotate.
    cur = start_dt.date()
    end = end_dt.date()
    while cur <= end:
        filepath = events_dir / "{}.jsonl".format(cur.strftime("%Y-%m-%d"))
        if filepath.exists():
            with open(filepath, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        yield filepath, line
        cur = cur + timedelta(days=1)


def generate_report(
    *,
    since_seconds: Optional[int] = None,
    severity: Optional[set] = None,
    sources: Optional[set] = None,
    types: Optional[set] = None,
    as_json: bool = False,
    data_dir: Optional[Path] = None,
    days: Optional[int] = None,
) -> None:
    """Read JSONL event logs, apply filters, and emit a summary report.

    Filters:
        since_seconds: only include events where ts >= now - since_seconds.
            If None, the full retention window is scanned.
        severity: subset of {"critical", "warning", "info"}. None → no filter.
        sources: matched against event["source"] (e.g., "agent_log",
            "net_tracker", "fs_watcher"). None → no filter.
        types: matched against event["event_type"] (free-form, e.g.,
            "agent_command", "net_connect", "agent_download"). None → no filter.

    Output:
        as_json=False (default): human-readable summary on stdout.
        as_json=True: ADR 0004 §D2 versioned envelope on stdout —
            {"version", "kind", "generated_at", "data": {filters, summary, events}}.
            The envelope is emitted even when no events match (consumers can
            rely on a stable shape).

    Backward-compat:
        Pre-v0.7 callers used ``generate_report(days=N)`` — that signature is
        preserved via the ``days`` adapter (converted to since_seconds).
    """
    import json as _json
    from collections import Counter

    # Backward-compat adapter: days → since_seconds.
    if since_seconds is None and days is not None:
        since_seconds = days * 86400
    if since_seconds is None:
        # Default: today only (matches pre-v0.7 `--report` no-arg behavior).
        since_seconds = 86400

    if data_dir is None:
        data_dir = resolve_data_dir()
    events_dir = data_dir / "events"

    if not events_dir.exists():
        if as_json:
            _emit_json_envelope(
                kind="report_events",
                payload={
                    "filters": _filters_payload(since_seconds, severity, sources, types),
                    "summary": {
                        "total": 0, "critical": 0, "warning": 0, "info": 0,
                        "by_source": {},
                    },
                    "events": [],
                },
            )
        else:
            print("No event logs found.")
        return

    now = datetime.now()
    cutoff = now - timedelta(seconds=since_seconds)

    matched: list = []
    for _, raw in _iter_event_lines(events_dir, cutoff, now):
        try:
            event = _json.loads(raw)
        except _json.JSONDecodeError:
            continue

        # Time filter — events without parseable ts are dropped (corrupt line).
        ts_raw = event.get("ts")
        if not isinstance(ts_raw, str):
            continue
        try:
            ts_dt = datetime.fromisoformat(ts_raw)
        except ValueError:
            continue
        # event_logger writes naive local-time ISO strings, but be defensive:
        # if a tz-aware ts ever lands (manual edit, future writer), drop the
        # tzinfo to compare against `cutoff` (naive local now()).
        if ts_dt.tzinfo is not None:
            ts_dt = ts_dt.replace(tzinfo=None)
        if ts_dt < cutoff:
            continue

        # Source filter
        if sources is not None and event.get("source") not in sources:
            continue

        # Type filter
        if types is not None and event.get("event_type") not in types:
            continue

        # Severity classification + filter
        risk = event.get("risk_score", 0) or 0
        sev = _classify_severity(float(risk))
        if severity is not None and sev not in severity:
            continue

        # Annotate severity onto the event for consumer convenience
        # (ADR 0004 §D3 — additive only, never reuse existing keys).
        event["severity"] = sev
        matched.append(event)

    if as_json:
        critical = sum(1 for e in matched if e["severity"] == "critical")
        warning = sum(1 for e in matched if e["severity"] == "warning")
        info = sum(1 for e in matched if e["severity"] == "info")
        by_source = dict(Counter(e.get("source", "unknown") for e in matched))
        _emit_json_envelope(
            kind="report_events",
            payload={
                "filters": _filters_payload(since_seconds, severity, sources, types),
                "summary": {
                    "total": len(matched),
                    "critical": critical,
                    "warning": warning,
                    "info": info,
                    "by_source": by_source,
                },
                "events": matched,
            },
        )
        return

    # ─── Text output ──────────────────────────────────────────────────
    _print_text_report(matched, since_seconds, severity, sources, types, now)


def _filters_payload(
    since_seconds: int,
    severity: Optional[set],
    sources: Optional[set],
    types: Optional[set],
) -> dict:
    """Stable JSON-friendly representation of the active filter spec."""
    return {
        "since_seconds": since_seconds,
        "severity": sorted(severity) if severity else None,
        "sources": sorted(sources) if sources else None,
        "types": sorted(types) if types else None,
    }


def _emit_json_envelope(*, kind: str, payload: dict) -> None:
    """Serialize and print an ADR 0004 §D2 versioned envelope to stdout."""
    envelope = {
        "version": 1,
        "kind": kind,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data": payload,
    }
    print(json.dumps(envelope, ensure_ascii=False))


def _format_since_label(since_seconds: int) -> str:
    """Render since_seconds back into a human label for the text header."""
    if since_seconds % 86400 == 0:
        n = since_seconds // 86400
        return f"Last {n} day{'s' if n != 1 else ''}"
    if since_seconds % 3600 == 0:
        n = since_seconds // 3600
        return f"Last {n} hour{'s' if n != 1 else ''}"
    if since_seconds % 60 == 0:
        n = since_seconds // 60
        return f"Last {n} minute{'s' if n != 1 else ''}"
    return f"Last {since_seconds}s"


def _print_text_report(
    events: list,
    since_seconds: int,
    severity: Optional[set],
    sources: Optional[set],
    types: Optional[set],
    now: datetime,
) -> None:
    from collections import Counter

    sev_label = ", ".join(sorted(severity)) if severity else "any"
    src_label = ", ".join(sorted(sources)) if sources else "any"
    type_label = ", ".join(sorted(types)) if types else "any"
    period_label = _format_since_label(since_seconds)

    if not events:
        print("")
        print("=" * 50)
        print("  Sentinel Report")
        print(f"  {period_label}  |  severity: {sev_label}  |  source: {src_label}")
        if types is not None:
            print(f"  type: {type_label}")
        print("=" * 50)
        print("")
        print("  No events matched the selected filters.")
        print("")
        print("=" * 50)
        print("")
        return

    critical = [e for e in events if e["severity"] == "critical"]
    warning = [e for e in events if e["severity"] == "warning"]
    info = [e for e in events if e["severity"] == "info"]
    source_counts = Counter(e.get("source", "unknown") for e in events)
    notable = sorted(critical, key=lambda e: e.get("ts", ""), reverse=True)[:5]

    print("")
    print("=" * 50)
    print("  Sentinel Report")
    print(f"  {period_label}  |  severity: {sev_label}  |  source: {src_label}")
    if types is not None:
        print(f"  type: {type_label}")
    print("=" * 50)
    print("")
    print(f"  Events: {len(events)} total")
    print(f"    Critical: {len(critical):>4}")
    print(f"    Warning:  {len(warning):>4}")
    print(f"    Info:     {len(info):>4}")
    print("")
    print("  Top Sources:")
    for source, count in source_counts.most_common(5):
        print(f"    {source:<20s} {count}")

    if notable:
        print("")
        print("  Notable Events:")
        for e in notable:
            ts = e.get("ts", "?")[:16]
            source = e.get("source", "?")
            target = e.get("target", "?")
            if len(target) > 60:
                target = target[:57] + "..."
            print(f"    {ts} | [{source}] {target}")

    print("")
    print("=" * 50)
    print("")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

PLIST_NAME = "com.sentinel.agent"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{PLIST_NAME}.plist"
CLAUDE_SETTINGS_PATH = Path.home() / ".claude" / "settings.json"
SENTINEL_HOOK_MARKER = "sentinel hook-check"

# Patterns skipped in hook-check (handled separately by typosquatting detector)
_HOOK_SKIP_REASONS: frozenset[str] = frozenset({"arbitrary package install"})


def _load_claude_settings() -> "tuple[dict | None, str | None]":
    """Load ~/.claude/settings.json. Returns (settings, error_message)."""
    if not CLAUDE_SETTINGS_PATH.exists():
        return None, "Claude Code settings not found: ~/.claude/settings.json\nIs Claude Code installed?"
    try:
        return json.loads(CLAUDE_SETTINGS_PATH.read_text()), None
    except json.JSONDecodeError:
        return None, "Error: ~/.claude/settings.json is not valid JSON"


def _hook_has_sentinel(hook_entry: dict) -> bool:
    """Check if a PreToolUse hook entry contains the Sentinel hook-check command."""
    return any(
        SENTINEL_HOOK_MARKER in h.get("command", "")
        for h in hook_entry.get("hooks", [])
        if isinstance(h, dict)
    )


def _hooks_control(subcommand: str) -> None:
    """Manage Claude Code PreToolUse hooks for Sentinel."""
    if subcommand == "status":
        settings, err = _load_claude_settings()
        if settings is None:
            print(err)
            return
        hooks = settings.get("hooks", {}).get("PreToolUse", [])
        if any(_hook_has_sentinel(h) for h in hooks):
            print("✅ Sentinel hook is installed in ~/.claude/settings.json")
        else:
            print("❌ Sentinel hook is NOT installed")
            print("   Run: sentinel hooks install")
        return

    if subcommand == "install":
        sentinel_bin = sys.argv[0]

        if CLAUDE_SETTINGS_PATH.exists():
            settings, err = _load_claude_settings()
            if settings is None:
                print(err)
                return
        else:
            CLAUDE_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            settings = {}

        hooks = settings.setdefault("hooks", {})
        pre_tool_use = hooks.setdefault("PreToolUse", [])

        if any(_hook_has_sentinel(h) for h in pre_tool_use):
            print("Sentinel hook is already installed.")
            return

        pre_tool_use.append({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": f"{sentinel_bin} hook-check"}],
        })

        CLAUDE_SETTINGS_PATH.write_text(json.dumps(settings, indent=2))
        print(f"✅ Sentinel Claude Code hook installed at {CLAUDE_SETTINGS_PATH}")
        print("")
        print("   Pre-tool-use hook now monitors:")
        print("     • Bash commands (pipe-to-shell, rm -rf, ssh, eval, etc.)")
        print("     • Write/Read/Edit on sensitive paths (~/.ssh, .env*, *.pem, ...)")
        print("     • WebFetch URLs")
        print("     • MCP tool calls + injection patterns")
        print("     • Typosquatting (pip/npm install)")
        print("")
        print("   Restart Claude Code for the hook to take effect.")
        print("   To uninstall: sentinel hooks uninstall")
        return

    if subcommand == "uninstall":
        settings, err = _load_claude_settings()
        if settings is None:
            print(err)
            return

        pre_tool_use = settings.get("hooks", {}).get("PreToolUse", [])
        filtered = [h for h in pre_tool_use if not _hook_has_sentinel(h)]

        if len(filtered) == len(pre_tool_use):
            print("Sentinel hook was not installed.")
            return

        settings["hooks"]["PreToolUse"] = filtered
        CLAUDE_SETTINGS_PATH.write_text(json.dumps(settings, indent=2))
        print("✅ Sentinel hook uninstalled.")
        return

    print(f"Unknown hooks subcommand: {subcommand}")
    print("Usage: sentinel hooks install | uninstall | status")


def _hook_check() -> None:
    """Called by Claude Code PreToolUse hook. Reads JSON from stdin, exits 0 (allow) or 2 (block)."""
    from sentinel_mac.collectors.agent_log_parser import HIGH_RISK_PATTERNS
    from sentinel_mac.collectors.typosquatting import (
        check_typosquatting,
        extract_npm_packages,
        extract_pip_packages,
    )

    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, Exception):
        sys.exit(0)  # Don't block on parse error

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    command_lower = command.lower()
    reasons = []

    # High-risk pattern check — skip pip/npm install (handled by typosquatting below)
    for pattern, reason in HIGH_RISK_PATTERNS:
        if reason in _HOOK_SKIP_REASONS:
            continue
        if pattern.search(command_lower):
            reasons.append(f"high-risk command: {reason}")
            break

    # Typosquatting check — block only high-confidence matches
    pip_pkgs = extract_pip_packages(command)
    if pip_pkgs:
        for pkg in pip_pkgs:
            result = check_typosquatting(pkg, "pip")
            if result and result["confidence"] == "high":
                reasons.append(
                    f"typosquatting suspect: '{pkg}' looks like '{result['similar_to']}'"
                )
    else:
        for pkg in extract_npm_packages(command):
            result = check_typosquatting(pkg, "npm")
            if result and result["confidence"] == "high":
                reasons.append(
                    f"typosquatting suspect: '{pkg}' looks like '{result['similar_to']}'"
                )

    if reasons:
        print(f"🚨 Sentinel blocked: {'; '.join(reasons)}")
        print(f"   Command: {command[:200]}")
        print("   To allow, run manually or adjust Sentinel config.")
        sys.exit(2)

    sys.exit(0)


def _print_version_snapshot() -> None:
    """v0.9 Track 3b — print version + fast environment snapshot.

    Output shape::

        sentinel-mac X.Y.Z

          config:    /Users/x/.config/sentinel/config.yaml
          data dir:  /Users/x/.local/share/sentinel/
          daemon:    running (PID 12345)
          CC hook:   installed

    First line matches the legacy ``--version`` output verbatim so
    any user / script that greps the version out keeps working.
    Each subsequent line is best-effort: a missing file / permission
    error degrades to a short status (``not configured`` /
    ``not running`` / ``not installed`` / ``unknown``) instead of
    raising — ``--version`` is meant to be a fast sanity check that
    never crashes. For a full check with remediation hints, use
    ``sentinel doctor``.
    """
    from sentinel_mac import __version__ as _ver

    print(f"sentinel-mac {_ver}")
    print()
    print(f"  config:    {_version_config_line()}")
    print(f"  data dir:  {_version_data_dir_line()}")
    print(f"  daemon:    {_version_daemon_line()}")
    print(f"  CC hook:   {_version_hook_line()}")


def _version_config_line() -> str:
    """Best-effort config path line for ``--version``.

    Mirrors :func:`resolve_config_path`'s priority order but stays
    quiet on any unexpected failure so the snapshot never crashes.
    """
    try:
        resolved = resolve_config_path(None)
    except Exception:  # pragma: no cover — defensive
        return "unknown"
    if resolved is None:
        return "not configured (run: sentinel --init-config)"
    return str(resolved)


def _version_data_dir_line() -> str:
    """Best-effort data dir line for ``--version``."""
    try:
        return str(resolve_data_dir())
    except Exception:  # pragma: no cover — defensive
        return "unknown"


def _version_daemon_line() -> str:
    """Best-effort daemon status line for ``--version``.

    Probes the lock file via a non-blocking flock acquire — if we
    grab it, no daemon is holding it; we release immediately. PID
    is read from the lock file contents (best-effort) when the lock
    is held.
    """
    try:
        lock_path = daemon_lock_path()
    except Exception:  # pragma: no cover — defensive
        return "unknown"
    if not lock_path.exists():
        return "not running"
    try:
        # Try to grab the lock non-blocking. If we get it, no daemon
        # is running; release and report. Open in r+ so we don't
        # truncate the PID written by the actual daemon.
        with open(lock_path, "r+") as fp:
            try:
                fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fp, fcntl.LOCK_UN)
                return "not running"
            except OSError:
                # Held by another process — this is the daemon.
                pid_text = ""
                try:
                    fp.seek(0)
                    pid_text = fp.read().strip()
                except Exception:
                    pass
                if pid_text and pid_text.isdigit():
                    return f"running (PID {pid_text})"
                return "running"
    except OSError:
        return "unknown"


def _version_hook_line() -> str:
    """Best-effort Claude Code hook installation line for ``--version``."""
    if not CLAUDE_SETTINGS_PATH.exists():
        return "not installed (Claude Code settings not found)"
    try:
        settings = json.loads(CLAUDE_SETTINGS_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        # Don't surface the underlying error — the snapshot is a
        # fast check, not a debugger. `sentinel doctor` is the
        # diagnostic surface that explains *why*.
        return "unknown (cannot read ~/.claude/settings.json)"
    hooks = settings.get("hooks", {}).get("PreToolUse", []) if isinstance(settings, dict) else []
    if not isinstance(hooks, list):
        return "not installed"
    if any(_hook_has_sentinel(h) for h in hooks if isinstance(h, dict)):
        return "installed"
    return "not installed (run: sentinel hooks install)"


def _service_control(command: str) -> None:
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


def main() -> None:
    import argparse

    # v0.9 Track 3b — `__version__` is no longer needed at this scope.
    # The bolstered ``--version`` handler imports it inside
    # ``_print_version_snapshot``; the no-config quickstart banner
    # below already does its own local import.

    # Handle subcommands that take their own args before argparse runs
    if len(sys.argv) >= 2 and sys.argv[1] == "hook-check":
        _hook_check()
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "hooks":
        subcommand = sys.argv[2] if len(sys.argv) > 2 else "status"
        _hooks_control(subcommand)
        return
    # ADR 0003 — `sentinel context …` lives in commands/context.py and owns
    # its own argparse subparser. Same dispatch shape as `hooks` above to
    # keep core.main() free of nested subparser plumbing.
    if len(sys.argv) >= 2 and sys.argv[1] == "context":
        from sentinel_mac.commands.context import dispatch as _context_dispatch
        sys.exit(_context_dispatch(sys.argv[2:]))
    # v0.8 Track 1b — `sentinel doctor` health-check command. Same
    # dispatch shape as `context` above; owns its own argparse
    # subparser inside commands/doctor.py.
    if len(sys.argv) >= 2 and sys.argv[1] == "doctor":
        from sentinel_mac.commands.doctor import dispatch as _doctor_dispatch
        sys.exit(_doctor_dispatch(sys.argv[2:]))
    # ADR 0010 — `sentinel update` self-update command. Same dispatch
    # shape; owns its own argparse subparser inside commands/update.py.
    if len(sys.argv) >= 2 and sys.argv[1] == "update":
        from sentinel_mac.commands.update import dispatch as _update_dispatch
        sys.exit(_update_dispatch(sys.argv[2:]))

    parser = argparse.ArgumentParser(
        description="Sentinel — AI Agent Security Guardian for macOS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="service commands:\n"
               "  start         Start background service\n"
               "  stop          Stop background service\n"
               "  restart       Restart background service\n"
               "  status        Check if service is running\n"
               "  logs          Tail live logs (Ctrl+C to stop)\n"
               "\nClaude Code integration:\n"
               "  hooks install    Register Sentinel as Claude Code PreToolUse hook\n"
               "  hooks uninstall  Remove Claude Code hook\n"
               "  hooks status     Check if hook is registered\n"
               "\nHost trust context (ADR 0003):\n"
               "  context status [HOST]   Show snapshot or single-host detail\n"
               "  context forget HOST     Remove from frequency counter\n"
               "  context block   HOST    Add to config blocklist\n"
               "  context unblock HOST    Remove from config blocklist\n"
               "\nHealth check (v0.8 Track 1b):\n"
               "  doctor                  One-shot health check (text)\n"
               "  doctor --json           Health snapshot envelope (kind=health_check)",
    )
    parser.add_argument("command", nargs="?", default=None,
                        choices=["start", "stop", "restart", "status", "logs",
                                 "hooks", "hook-check"],
                        metavar="command",
                        help="start | stop | restart | status | logs | hooks | hook-check")
    parser.add_argument("--config", "-c", default=None, help="Config file path")
    parser.add_argument("--once", action="store_true", help="Run once and print metrics")
    parser.add_argument("--test-notify", action="store_true", help="Send test notification")
    # v0.9 Track 3b — bolstered --version output. Switched from
    # argparse's built-in ``action="version"`` (single line, prints +
    # exits inside argparse) to a plain store_true flag so we can
    # render a multi-line snapshot (config path / data dir / daemon
    # status / hook installed). The first line still matches the
    # legacy ``sentinel-mac X.Y.Z`` shape so any user / script that
    # greps the version out keeps working.
    parser.add_argument("--version", "-v", action="store_true",
                        help="Print version and a fast environment "
                             "snapshot (config path, data dir, daemon "
                             "status, hook installed). For full "
                             "diagnosis with remediation, use "
                             "`sentinel doctor`.")
    parser.add_argument("--report", nargs="?", const=1, type=int, metavar="DAYS",
                        help="Show event summary (default: today, or specify number of days). "
                             "Combine with --since/--severity/--source/--type to filter; "
                             "--json emits an ADR 0004 versioned envelope.")
    parser.add_argument("--since", default=None, metavar="DURATION",
                        help="Filter --report events to the last DURATION "
                             "(e.g., '7d', '24h', '30m', '3600s', or integer seconds). "
                             "Overrides --report DAYS when both supplied. Max 365d.")
    parser.add_argument("--severity", default=None, metavar="LEVELS",
                        help="Comma-separated severity filter for --report "
                             "(critical,warning,info).")
    parser.add_argument("--source", default=None, metavar="SOURCES",
                        help="Comma-separated source filter for --report "
                             "(agent_log,net_tracker,fs_watcher).")
    parser.add_argument("--type", default=None, metavar="EVENT_TYPES",
                        help="Comma-separated event_type filter for --report "
                             "(e.g., agent_command,net_connect,file_modify,agent_download).")
    parser.add_argument("--json", action="store_true",
                        help="Emit --report output as JSON (ADR 0004 §D2 versioned envelope: "
                             "{version, kind, generated_at, data}).")
    parser.add_argument("--init-config", action="store_true",
                        help="Generate config.yaml in ~/.config/sentinel/")
    args = parser.parse_args()

    # v0.9 Track 3b — bolstered --version handler. Runs before any
    # other dispatch so it stays a fast, side-effect-free sanity
    # check. Each line is best-effort; missing files / permission
    # errors degrade to a short "not …" status without raising.
    if args.version:
        _print_version_snapshot()
        return

    if args.command == "hook-check":
        _hook_check()
        return

    if args.command == "hooks":
        subcommand = sys.argv[2] if len(sys.argv) > 2 else "status"
        _hooks_control(subcommand)
        return

    if args.command:
        _service_control(args.command)
        return

    if args.report is not None:
        try:
            since_seconds = (
                parse_since(args.since) if args.since else args.report * 86400
            )
            severity = _parse_csv_set(args.severity, valid=set(VALID_SEVERITIES), flag="severity")
            sources = _parse_csv_set(args.source, flag="source")
            types = _parse_csv_set(args.type, flag="type")
        except _argparse.ArgumentTypeError as exc:
            parser.error(str(exc))
            return  # parser.error raises SystemExit; defensive
        generate_report(
            since_seconds=since_seconds,
            severity=severity,
            sources=sources,
            types=types,
            as_json=args.json,
        )
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
"""
            config_file.write_text(config_content)
            print(f"Config created: {config_file}")
            print("macOS native notifications enabled by default.")
            print(f"Edit {config_file} to add ntfy.sh, Slack, or Telegram.")
        return

    if args.once:
        collector = MacOSCollector()
        m = collector.collect()
        print(f"\n{'='*50}")
        print("  Sentinel — System Snapshot")
        print(f"  {m.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*50}")
        cpu_temp = f"  |  {m.cpu_temp}°C" if m.cpu_temp else ""
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
            print("\n  AI Processes: none detected")
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
