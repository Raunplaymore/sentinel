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
from dataclasses import dataclass
from datetime import date as _date_cls, datetime
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from sentinel_mac.models import SecurityEvent
from sentinel_mac.collectors.system import MacOSCollector

if TYPE_CHECKING:  # pragma: no cover
    from sentinel_mac.event_logger import EventLogger

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


@dataclass
class PendingDownload:
    """In-memory record of an ``agent_download`` event awaiting its
    matching file system event (ADR 0002 §D3).

    Attributes:
        event_id: UUID of the original ``agent_download`` SecurityEvent.
            Used to locate the JSONL line for in-place rewrite.
        expected_path: Normalized absolute path that the download will
            land at. We compare incoming fs paths via ``os.path.realpath``
            equality; if the recorded path is a relative basename
            (``wget`` no-flag case) the join cannot fire — we keep the
            entry around for cleanup but never match it.
        deadline_epoch: Unix epoch second after which the entry is
            considered expired and is dropped.
        date: Date of the JSONL file holding the original event.
    """
    event_id: str
    expected_path: str
    deadline_epoch: int
    date: _date_cls


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

        # ADR 0002 — download join state. Populated by register_download()
        # when an agent_download event was just emitted. Cleared on match
        # or when the deadline passes. The event_logger reference is
        # attached lazily via attach_event_logger() so the existing
        # FSWatcher constructor signature is unchanged (back-compat).
        download_cfg = (
            config.get("security", {}).get("download_tracking", {}) or {}
        )
        self.download_tracking_enabled: bool = bool(
            download_cfg.get("enabled", False)
        )
        # Default 5 min; cap at 30 min per ADR 0002 §D3.
        join_window = int(download_cfg.get("join_window_seconds", 300) or 300)
        if join_window < 60:
            join_window = 60
        if join_window > 1800:
            join_window = 1800
        self.join_window_seconds: int = join_window
        self._pending_downloads: dict[str, PendingDownload] = {}
        self._pending_lock = threading.Lock()
        self._event_logger: Optional["EventLogger"] = None

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
        self._recent_events: list[tuple[float, str]] = []  # (timestamp, path)
        self._bulk_lock = threading.Lock()
        self._last_bulk_alert_time = 0.0

        # lsof cache to avoid hammering it
        self._lsof_cache: dict[str, tuple[int, str]] = {}
        self._lsof_cache_time = 0.0
        self._lsof_cache_ttl = 2.0  # seconds

    def attach_event_logger(self, event_logger: "EventLogger") -> None:
        """Wire the EventLogger so download joins can rewrite the JSONL.

        Optional. Without an attached logger, ``register_download`` still
        records the pending entry but no in-place rewrite happens on
        match (the matched fs_event is silently suppressed only when
        suppression is safe — i.e. non-sensitive paths).
        """
        self._event_logger = event_logger

    def register_download(
        self,
        event_id: str,
        output_path: str,
        deadline_epoch: int,
        date: _date_cls,
    ) -> None:
        """Mark an agent_download event as awaiting its file system event.

        Called by the main loop when an ``agent_download`` SecurityEvent
        is drained from the security queue (see core._process_security_events).
        ``output_path`` is normalized via ``os.path.realpath`` for matching;
        callers should pass an absolute path. Relative basenames (the
        ``wget`` no-flag case) are stored as-is and will never match —
        they age out via ``deadline_epoch``.

        ADR 0002 §D3 — single-daemon assumption; lock is in-process only.
        """
        if not event_id or not output_path:
            return
        normalized = os.path.realpath(os.path.expanduser(output_path))
        entry = PendingDownload(
            event_id=event_id,
            expected_path=normalized,
            deadline_epoch=deadline_epoch,
            date=date,
        )
        with self._pending_lock:
            # Index by normalized path so an incoming fs event can do an
            # O(1) lookup. Multiple downloads racing for the same path is
            # rare; the most recent wins (older entry is dropped).
            self._pending_downloads[normalized] = entry

    def _consume_pending_download(
        self, path: str, *, now_epoch: int
    ) -> Optional[PendingDownload]:
        """Pop and return a pending download matching ``path``, or None.

        Cheap GC pass on every call: expired entries are dropped before
        the lookup so the dict cannot grow unboundedly even if no fs
        events ever arrive for the registered paths.
        """
        normalized = os.path.realpath(path)
        with self._pending_lock:
            # Drop expired entries first.
            if self._pending_downloads:
                expired = [
                    p for p, e in self._pending_downloads.items()
                    if e.deadline_epoch < now_epoch
                ]
                for p in expired:
                    self._pending_downloads.pop(p, None)
            entry = self._pending_downloads.pop(normalized, None)
        if entry is None:
            return None
        if entry.deadline_epoch < now_epoch:
            return None
        return entry

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
            # Fallback: if lsof on exact file fails, try parent directory
            if actor_pid == 0 and actor_name == "unknown":
                actor_pid, actor_name = self._identify_actor_by_dir(path)
        else:
            actor_pid, actor_name = 0, "unknown"

        # Check bulk changes
        self._track_bulk(path, event_type)

        # ADR 0002 §D3 — download join: if this fs event matches a
        # previously registered agent_download, populate joined_fs_event
        # on the original JSONL line and suppress this standalone
        # file_create / file_modify event (unless the path is sensitive,
        # in which case the event is preserved for audit).
        joined = False
        if (
            self.download_tracking_enabled
            and event_type in ("file_create", "file_modify")
        ):
            joined = self._try_join_download(
                path, actor_pid=actor_pid, actor_name=actor_name,
            )

        # Only emit events that are interesting:
        # 1. Any access to sensitive paths
        # 2. Executable file creation
        # 3. Events attributed to AI processes
        is_ai = self._is_ai_process(actor_name, actor_pid)

        if not (is_sensitive or is_executable or is_ai):
            return

        # Suppress non-sensitive joined events to reduce noise — the
        # agent_download line now tells the same story (ADR 0002 §D3).
        if joined and not is_sensitive:
            return

        detail = {}
        if is_sensitive:
            detail["sensitive"] = True
        if is_executable:
            detail["executable"] = True
        if is_ai:
            detail["ai_process"] = True
        if joined:
            detail["joined_to_download"] = True

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

    def _try_join_download(
        self, path: str, *, actor_pid: int, actor_name: str,
    ) -> bool:
        """Match an fs event to a pending download and rewrite the JSONL.

        Returns True when a join happened (caller decides whether to
        suppress the standalone fs_event), False otherwise.
        """
        now_epoch = int(time.time())
        entry = self._consume_pending_download(path, now_epoch=now_epoch)
        if entry is None:
            return False

        # Build the joined_fs_event payload (ADR 0002 §D2 sub-keys).
        try:
            size_bytes = os.path.getsize(path)
        except OSError:
            size_bytes = 0

        joined_fs_event = {
            "ts": datetime.now().isoformat(),
            "actor_pid": actor_pid,
            "actor_name": actor_name,
            "size_bytes": size_bytes,
        }

        # Only attempt the JSONL rewrite when an EventLogger is attached.
        # Without it (e.g., unit tests that exercise FSWatcher in
        # isolation) the join is still considered "happened" so the
        # caller can apply the suppression policy uniformly.
        if self._event_logger is not None:
            try:
                # Read+merge the existing detail dict so additive keys
                # already on the line (e.g., other Pro consumers) are
                # preserved — we only set joined_fs_event.
                self._event_logger.update_event_by_id(
                    entry.event_id,
                    {"detail": self._merge_joined_detail(
                        entry, joined_fs_event,
                    )},
                    date=entry.date,
                )
            except Exception as exc:  # pragma: no cover — best-effort
                logger.debug(
                    "FSWatcher: download join rewrite failed for %s: %s",
                    entry.event_id, exc,
                )
        return True

    def _merge_joined_detail(
        self, entry: PendingDownload, joined_fs_event: dict,
    ) -> dict:
        """Re-read the original detail dict from JSONL and overlay
        ``joined_fs_event`` on it. Falls back to a minimal dict if the
        original line cannot be located (caller already holds the lock
        when calling update_event_by_id, so we read the file ourselves).
        """
        # We can't easily get the original detail without scanning, and
        # update_event_by_id replaces top-level "detail" wholesale. The
        # safest pattern: scan the day's file once for our event_id and
        # surface its current detail, then overlay joined_fs_event. This
        # is O(N) but bounded (~100 events/day per ADR 0002 §D3).
        if self._event_logger is None:
            return {"joined_fs_event": joined_fs_event}
        try:
            events_dir = self._event_logger._events_dir  # type: ignore[attr-defined]
            path = events_dir / f"{entry.date.strftime('%Y-%m-%d')}.jsonl"
            if not path.exists():
                return {"joined_fs_event": joined_fs_event}
            import json as _json
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    if obj.get("event_id") == entry.event_id:
                        existing = obj.get("detail", {}) or {}
                        if isinstance(existing, dict):
                            existing = dict(existing)
                            existing["joined_fs_event"] = joined_fs_event
                            return existing
                        break
        except OSError:
            pass
        return {"joined_fs_event": joined_fs_event}

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

    def _identify_actor_by_dir(self, path: str) -> tuple[int, str]:
        """Fallback: find a process with the parent directory open."""
        parent = str(Path(path).parent)
        try:
            result = subprocess.run(
                ["lsof", "+D", parent, "-F", "pc", "-t"],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0 and result.stdout.strip():
                for pid_str in result.stdout.strip().splitlines()[:5]:
                    try:
                        pid = int(pid_str.strip())
                        ps_result = subprocess.run(
                            ["ps", "-p", str(pid), "-o", "comm="],
                            capture_output=True, text=True, timeout=2,
                        )
                        name = ps_result.stdout.strip()
                        if name and name not in ("lsof", "sentinel", "python3", "Python"):
                            return pid, os.path.basename(name)
                    except (ValueError, OSError):
                        continue
        except (subprocess.TimeoutExpired, OSError):
            pass
        return 0, "unknown"

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
            self._recent_events.append((now, path))
            # Prune old events
            cutoff = now - self._bulk_window
            self._recent_events = [(t, p) for t, p in self._recent_events if t > cutoff]

            count = len(self._recent_events)
            if (count >= self._bulk_threshold
                    and now - self._last_bulk_alert_time > self._bulk_window):
                self._last_bulk_alert_time = now

                # Analyze affected paths for forensic context
                paths = [p for _, p in self._recent_events]
                top_dirs = self._analyze_bulk_paths(paths)
                source_project = self._guess_project_name(paths)
                suspect_pid, suspect_name = self._identify_bulk_actor(top_dirs)

                detail = {
                    "count": count,
                    "top_directories": top_dirs[:5],
                }
                if source_project:
                    detail["project"] = source_project
                if suspect_name != "unknown":
                    detail["suspect_process"] = suspect_name
                    detail["suspect_pid"] = suspect_pid

                event = SecurityEvent(
                    timestamp=datetime.now(),
                    source="fs_watcher",
                    actor_pid=suspect_pid,
                    actor_name=suspect_name,
                    event_type="bulk_change",
                    target=f"{count} files in {self._bulk_window}s",
                    detail=detail,
                )
                try:
                    self._event_queue.put_nowait(event)
                except queue.Full:
                    pass

    @staticmethod
    def _analyze_bulk_paths(paths: list[str]) -> list[str]:
        """Find the most common parent directories from a list of paths."""
        dir_counts: dict[str, int] = {}
        for p in paths:
            # Use 2-level parent for meaningful grouping
            parts = Path(p).parts
            if len(parts) >= 4:
                key = str(Path(*parts[:5]))  # e.g. /Users/user/projects/myapp
            else:
                key = str(Path(p).parent)
            dir_counts[key] = dir_counts.get(key, 0) + 1

        return sorted(dir_counts, key=dir_counts.get, reverse=True)

    @staticmethod
    def _guess_project_name(paths: list[str]) -> str:
        """Try to identify the project name from common path prefix."""
        if not paths:
            return ""
        try:
            common = os.path.commonpath(paths)
            # Walk up until we find a likely project root (has .git, package.json, etc.)
            current = Path(common)
            for _ in range(5):
                if any((current / marker).exists()
                       for marker in (".git", "package.json", "pyproject.toml", "Cargo.toml", "go.mod")):
                    return current.name
                if current.parent == current:
                    break
                current = current.parent
        except (ValueError, OSError):
            pass
        return ""

    def _identify_bulk_actor(self, top_dirs: list[str]) -> tuple[int, str]:
        """Try to find the process responsible for bulk changes via lsof on top directories."""
        for d in top_dirs[:2]:
            try:
                result = subprocess.run(
                    ["lsof", "+D", d, "-F", "pcn", "-t"],
                    capture_output=True, text=True, timeout=3,
                )
                if result.returncode == 0 and result.stdout.strip():
                    # Parse first PID from lsof -t output
                    for pid_str in result.stdout.strip().splitlines()[:5]:
                        try:
                            pid = int(pid_str.strip())
                            # Get process name
                            ps_result = subprocess.run(
                                ["ps", "-p", str(pid), "-o", "comm="],
                                capture_output=True, text=True, timeout=2,
                            )
                            name = ps_result.stdout.strip()
                            if name and name not in ("lsof", "sentinel", "python3", "Python"):
                                return pid, os.path.basename(name)
                        except (ValueError, OSError):
                            continue
            except (subprocess.TimeoutExpired, OSError):
                continue
        return 0, "unknown"
