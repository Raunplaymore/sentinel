"""Sentinel — File System Watcher.

Monitors file access/modify/delete events using macOS FSEvents (via watchdog).
Maps file events to AI processes using lsof (best-effort).
"""

import fnmatch
import logging
import os
import queue
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from sentinel_mac.models import SecurityEvent
from sentinel_mac.collectors.system import MacOSCollector

logger = logging.getLogger(__name__)

# Map watchdog event types to our event_type names
_EVENT_TYPE_MAP = {
    "created": "file_create",
    "modified": "file_modify",
    "deleted": "file_delete",
    "moved": "file_move",
}

# File extensions that are considered executable/binary
_EXECUTABLE_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".command",
    ".py", ".rb", ".pl",  # scripts (only flagged if chmod +x)
    ".dylib", ".so", ".bundle",
    "", # no extension — common for compiled binaries
}


class _SentinelEventHandler(FileSystemEventHandler):
    """Watchdog event handler that filters and forwards events."""

    def __init__(self, watcher: "FSWatcher"):
        super().__init__()
        self._watcher = watcher

    def on_any_event(self, event: FileSystemEvent):
        if event.is_directory:
            return
        event_type = _EVENT_TYPE_MAP.get(event.event_type)
        if event_type is None:
            return
        self._watcher._handle_fs_event(event.src_path, event_type)


class FSWatcher:
    """Watches file system events and correlates them with AI processes.

    Runs a watchdog Observer in a background thread. Detected events are
    filtered, enriched with process info (best-effort via lsof), and
    pushed to an event queue as SecurityEvent instances.
    """

    # Reuse AI process detection from system collector
    AI_PROCESS_NAMES = MacOSCollector.AI_PROCESS_NAMES
    AI_CMDLINE_KEYWORDS = MacOSCollector.AI_CMDLINE_KEYWORDS
    GENERIC_PROCESS_NAMES = MacOSCollector.GENERIC_PROCESS_NAMES

    def __init__(self, config: dict, event_queue: queue.Queue):
        sec_config = config.get("security", {}).get("fs_watcher", {})

        self._event_queue = event_queue
        self._observer: Optional[Observer] = None
        self._running = False

        # Paths to watch (expand ~)
        self._watch_paths = [
            os.path.expanduser(p)
            for p in sec_config.get("watch_paths", [os.path.expanduser("~")])
        ]

        # Sensitive paths — access triggers critical alert
        self._sensitive_patterns = [
            os.path.expanduser(p)
            for p in sec_config.get("sensitive_paths", [
                "~/.ssh",
                "~/.env",
                "~/.config",
                "~/.zshrc",
                "~/.bash_profile",
                "~/.gitconfig",
            ])
        ]

        # Ignore patterns (fnmatch style)
        self._ignore_patterns = sec_config.get("ignore_patterns", [
            "*.pyc",
            "__pycache__",
            "node_modules",
            ".git/objects",
            ".git/index",
            "*.swp",
            "*.tmp",
            ".DS_Store",
        ])

        # Bulk change detection
        self._bulk_threshold = sec_config.get("bulk_threshold", 50)
        self._bulk_window = sec_config.get("bulk_window_seconds", 30)
        self._recent_events: list[float] = []
        self._bulk_lock = threading.Lock()
        self._last_bulk_alert_time = 0.0

        # lsof cache to avoid hammering it
        self._lsof_cache: dict[str, tuple[int, str]] = {}
        self._lsof_cache_time = 0.0
        self._lsof_cache_ttl = 2.0  # seconds

    def start(self):
        """Start watching in a background thread."""
        if self._running:
            return

        # Filter to paths that actually exist
        valid_paths = []
        for p in self._watch_paths:
            if os.path.exists(p):
                valid_paths.append(p)
            else:
                logger.warning(f"FSWatcher: watch path does not exist, skipping: {p}")

        if not valid_paths:
            logger.warning("FSWatcher: no valid watch paths — file monitoring disabled")
            return

        self._observer = Observer()
        for path in valid_paths:
            self._observer.schedule(
                _SentinelEventHandler(self),
                path,
                recursive=True,
            )
            logger.info(f"FSWatcher: monitoring {path}")

        self._observer.daemon = True
        self._running = True
        self._observer.start()
        logger.info(f"FSWatcher: started ({len(valid_paths)} paths)")

    def stop(self):
        """Stop the observer."""
        if self._observer and self._running:
            self._running = False
            self._observer.stop()
            self._observer.join(timeout=5)
            logger.info("FSWatcher: stopped")

    def _handle_fs_event(self, path: str, event_type: str):
        """Process a raw file system event."""
        # Ignore filtered patterns
        if self._should_ignore(path):
            return

        # Determine risk level early — skip lsof for non-interesting events
        is_sensitive = self._is_sensitive_path(path)
        is_executable = self._is_executable(path, event_type)

        # Only call lsof (expensive) for sensitive or executable files
        if is_sensitive or is_executable:
            actor_pid, actor_name = self._identify_actor(path)
        else:
            actor_pid, actor_name = 0, "unknown"

        # Check bulk changes
        self._track_bulk(path, event_type)

        # Only emit events that are interesting:
        # 1. Any access to sensitive paths
        # 2. Executable file creation
        # 3. Events attributed to AI processes
        is_ai = self._is_ai_process(actor_name, actor_pid)

        if not (is_sensitive or is_executable or is_ai):
            return

        detail = {}
        if is_sensitive:
            detail["sensitive"] = True
        if is_executable:
            detail["executable"] = True
        if is_ai:
            detail["ai_process"] = True

        event = SecurityEvent(
            timestamp=datetime.now(),
            source="fs_watcher",
            actor_pid=actor_pid,
            actor_name=actor_name,
            event_type=event_type,
            target=path,
            detail=detail,
        )

        try:
            self._event_queue.put_nowait(event)
        except queue.Full:
            logger.warning("FSWatcher: event queue full, dropping event")

    def _should_ignore(self, path: str) -> bool:
        """Check if path matches any ignore pattern."""
        basename = os.path.basename(path)
        for pattern in self._ignore_patterns:
            if fnmatch.fnmatch(basename, pattern):
                return True
            if pattern in path:
                return True
        return False

    def _is_sensitive_path(self, path: str) -> bool:
        """Check if path is under a sensitive directory or matches sensitive patterns."""
        for sensitive in self._sensitive_patterns:
            # Direct match or child path
            if path.startswith(sensitive):
                return True
            # .env file matching (e.g. .env, .env.local, .env.production)
            basename = os.path.basename(path)
            sens_basename = os.path.basename(sensitive)
            if sens_basename.startswith(".env") and basename.startswith(".env"):
                return True
        return False

    def _is_executable(self, path: str, event_type: str) -> bool:
        """Check if a newly created/modified file is executable."""
        if event_type not in ("file_create", "file_modify"):
            return False
        ext = Path(path).suffix.lower()
        if ext in (".sh", ".bash", ".zsh", ".command"):
            return True
        # Check actual execute permission for files without extension
        try:
            if os.path.exists(path) and os.access(path, os.X_OK):
                if ext == "" or ext in _EXECUTABLE_EXTENSIONS:
                    return True
        except OSError:
            pass
        return False

    def _identify_actor(self, path: str) -> tuple[int, str]:
        """Best-effort identification of which process has the file open.

        Uses lsof with a short cache to avoid excessive subprocess calls.
        Returns (pid, process_name) or (0, "unknown") if not identifiable.
        """
        now = time.time()

        # Check cache
        if now - self._lsof_cache_time < self._lsof_cache_ttl:
            cached = self._lsof_cache.get(path)
            if cached:
                return cached

        # Refresh lsof for this file
        try:
            result = subprocess.run(
                ["lsof", "-F", "pcn", "--", path],
                capture_output=True, text=True, timeout=2,
            )
            if result.returncode == 0 and result.stdout.strip():
                pid = 0
                name = "unknown"
                for line in result.stdout.strip().splitlines():
                    if line.startswith("p"):
                        pid = int(line[1:])
                    elif line.startswith("c"):
                        name = line[1:]
                self._lsof_cache[path] = (pid, name)
                self._lsof_cache_time = now
                return pid, name
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass

        return 0, "unknown"

    def _is_ai_process(self, name: str, pid: int) -> bool:
        """Check if a process name/pid belongs to an AI agent."""
        if name == "unknown" or pid == 0:
            return False

        lower_name = name.lower()

        # Tier 1: known AI process names
        if lower_name in self.AI_PROCESS_NAMES:
            return True

        # Tier 2: generic name — check cmdline
        if lower_name in self.GENERIC_PROCESS_NAMES:
            cmdline = self._get_process_cmdline(pid)
            if any(kw in cmdline for kw in self.AI_CMDLINE_KEYWORDS):
                return True

        return False

    def _get_process_cmdline(self, pid: int) -> str:
        """Get command line of a process by PID."""
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                capture_output=True, text=True, timeout=2,
            )
            return result.stdout.strip().lower()
        except (subprocess.TimeoutExpired, OSError):
            return ""

    def _track_bulk(self, path: str, event_type: str):
        """Track recent events for bulk change detection."""
        now = time.time()
        with self._bulk_lock:
            self._recent_events.append(now)
            # Prune old events
            cutoff = now - self._bulk_window
            self._recent_events = [t for t in self._recent_events if t > cutoff]

            if (len(self._recent_events) >= self._bulk_threshold
                    and now - self._last_bulk_alert_time > self._bulk_window):
                self._last_bulk_alert_time = now
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    source="fs_watcher",
                    actor_pid=0,
                    actor_name="unknown",
                    event_type="bulk_change",
                    target=f"{len(self._recent_events)} files in {self._bulk_window}s",
                    detail={"count": len(self._recent_events)},
                )
                try:
                    self._event_queue.put_nowait(event)
                except queue.Full:
                    pass
