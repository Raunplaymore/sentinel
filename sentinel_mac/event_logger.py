"""Sentinel — JSONL Event Logger.

Writes SecurityEvents to daily JSONL files for audit trail and Phase 2 team dashboard.
Files are stored at: <data_dir>/events/YYYY-MM-DD.jsonl
"""

import json
import logging
import os
import tempfile
import threading
from datetime import date as _date_cls
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional

from sentinel_mac.models import SecurityEvent

logger = logging.getLogger(__name__)


class EventLogger:
    """Append-only JSONL event logger with daily rotation.

    Most operations append a single JSON line per event. ADR 0002 §D3
    introduces one in-place rewrite path — :meth:`update_event_by_id` —
    used by FSWatcher join to populate ``detail["joined_fs_event"]`` on a
    previously written ``agent_download`` line. The rewrite is guarded by
    a single ``threading.Lock`` (the daemon is single-process per ADR 0001
    §D2 / ADR 0002 §D3 mitigation).
    """

    DEFAULT_RETENTION_DAYS = 90

    def __init__(self, data_dir, retention_days=None):
        self._events_dir = Path(data_dir) / "events"
        self._events_dir.mkdir(parents=True, exist_ok=True)
        self._retention_days = retention_days or self.DEFAULT_RETENTION_DAYS
        self._current_date: str = ""
        self._current_file = None
        # Single lock guards both append (rotate + write) and the
        # update_event_by_id rewrite path. ADR 0002 §D3 — small surface,
        # single-daemon assumption.
        self._lock = threading.Lock()

    def log(self, event: SecurityEvent) -> None:
        """Write a SecurityEvent as one JSON line to today's file."""
        today = datetime.now().strftime("%Y-%m-%d")
        line = json.dumps(self._serialize(event), ensure_ascii=False)
        with self._lock:
            # Rotate file on date change
            if today != self._current_date:
                self._rotate(today)
            try:
                self._current_file.write(line + "\n")
                self._current_file.flush()
            except Exception as e:
                logger.error(f"Failed to write event log: {e}")

    def update_event_by_id(
        self,
        event_id: str,
        patch: dict,
        *,
        date: Optional[_date_cls] = None,
    ) -> bool:
        """Find a previously logged event by ``event_id`` and merge ``patch``
        into its dict (top-level keys; ``detail`` is replaced wholesale only
        if ``patch`` includes the ``detail`` key, otherwise nested keys must
        be passed under ``detail`` explicitly by the caller).

        Returns True on successful rewrite, False if no matching ``event_id``
        was found in the day's file (or the file does not exist).

        Atomic: the JSONL is rewritten via temp file + ``os.replace``. The
        rewrite is line-level — every line is parsed, the matched line is
        merged with ``patch`` and re-serialized, all other lines are copied
        verbatim. ADR 0002 §D3 documents this as an acceptable cost at
        v0.7 scale (~100 events/day).

        ⚠ MONITOR (v0.9 Track 1, 2026-05-03 profile pass)
        --------------------------------------------------
        The O(N) per-rewrite scan was a suspected hotspot when PR #12
        landed. The 2026-05-03 cProfile pass against the busy_jsonl /
        fs_bulk / net_burst workloads showed this function did NOT
        appear in the top-20 cumulative entries on any of the three
        scenarios (a hand-shaped trace of one register + one matching
        rewrite of a 1000-line JSONL also stayed sub-millisecond at
        ~1.2ms). Per the measure-first policy in v0.9-plan.md
        Track 1, no in-memory ``event_id → line_offset`` index was
        added. Re-run ``python3 scripts/profile_workload.py`` and
        check ``docs/perf/v0.9-profile-2026-05-03.md`` before
        revisiting; if a future profile shows this call in the top-20
        the index is the right answer (NOT a SQLite migration —
        that's reserved for the dashboard work per v0.9-plan.md
        out-of-scope §).

        Args:
            event_id: UUID string assigned by ``SecurityEvent.event_id``.
            patch: top-level keys to merge. Existing keys are overwritten;
                new keys are added. Caller is responsible for passing the
                full ``detail`` dict if mutating a detail key.
            date: which day's file to scan. Defaults to today.

        Returns:
            True if a line was matched and rewritten, False otherwise.
        """
        if not event_id:
            return False
        target_date = date or datetime.now().date()
        with self._lock:
            return self._rewrite_one_locked(
                event_id, target_date, mutator=lambda obj: obj.update(patch),
            )

    def update_event_detail_by_id(
        self,
        event_id: str,
        detail_patch: dict,
        *,
        date: Optional[_date_cls] = None,
    ) -> bool:
        """Partial-patch the ``detail`` sub-dict of a previously logged event.

        Unlike :meth:`update_event_by_id` (which replaces the top-level
        ``detail`` key wholesale when the caller passes ``{"detail": {...}}``),
        this method merges ``detail_patch`` into the existing ``detail``
        dict on the matched line, preserving any keys the caller did not
        mention. Both the read of the existing detail and the rewrite
        happen under the same ``self._lock`` — no second read-then-replace
        window where a concurrent join on the same ``event_id`` could
        last-write-wins.

        v0.9 Track 1 (2026-05-03): introduced to retire the two-phase
        ``_merge_joined_detail`` pattern in :class:`FSWatcher` (caller
        used to scan the JSONL once OUTSIDE the EventLogger lock to read
        the existing detail, then call :meth:`update_event_by_id` which
        re-acquired the lock to rewrite — leaving a window where another
        thread's rewrite could land between the read and the replace).
        Now the caller hands us the partial patch and we do read+merge+
        rewrite atomically. ADR 0002 §D3's single-daemon assumption is
        unchanged; this is defense-in-depth for the multi-collector
        case (e.g. a hypothetical second consumer enriching the same
        event_id).

        Args:
            event_id: UUID string assigned by ``SecurityEvent.event_id``.
            detail_patch: keys to overlay on the existing ``detail`` dict.
                Existing keys are overwritten by this patch. Keys not
                present in ``detail_patch`` are preserved verbatim.
            date: which day's file to scan. Defaults to today.

        Returns:
            True if the line was matched and rewritten, False otherwise
            (no matching event_id, or the day's file does not exist).
        """
        if not event_id:
            return False
        target_date = date or datetime.now().date()

        def _merge_detail(obj: dict) -> None:
            existing = obj.get("detail")
            if not isinstance(existing, dict):
                # Original detail is missing or non-dict — replace with
                # just our patch so the caller still observes a dict.
                obj["detail"] = dict(detail_patch)
                return
            merged = dict(existing)
            merged.update(detail_patch)
            obj["detail"] = merged

        with self._lock:
            return self._rewrite_one_locked(
                event_id, target_date, mutator=_merge_detail,
            )

    def _rewrite_one_locked(
        self,
        event_id: str,
        target_date: _date_cls,
        *,
        mutator: Callable[[dict], None],
    ) -> bool:
        """Shared implementation for the two update-by-id paths.

        MUST be called with ``self._lock`` already held. ``mutator`` is
        called with the parsed JSON dict for the matched line and is
        expected to mutate it in place; the dict is then re-serialized
        and the file is rewritten atomically (temp file + ``os.replace``).
        Splitting this out lets :meth:`update_event_by_id` and
        :meth:`update_event_detail_by_id` share the file I/O without
        either method's logic leaking into the other.
        """
        path = self._events_dir / f"{target_date.strftime('%Y-%m-%d')}.jsonl"
        if not path.exists():
            return False

        # If we are rewriting today's file and currently hold it open
        # for append, flush first so our pending writes are visible to
        # the rewriter. We do NOT close the handle — _rotate will
        # reopen lazily on next log() if needed.
        if (
            self._current_file is not None
            and self._current_date == target_date.strftime("%Y-%m-%d")
        ):
            try:
                self._current_file.flush()
            except Exception:  # pragma: no cover — best-effort flush
                pass

        matched = False
        try:
            with open(path, "r", encoding="utf-8") as src:
                lines = src.readlines()
        except OSError as exc:
            logger.error(
                f"_rewrite_one_locked: cannot read {path}: {exc}"
            )
            return False

        new_lines: list[str] = []
        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                new_lines.append(raw)
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                new_lines.append(raw)
                continue
            if not matched and obj.get("event_id") == event_id:
                mutator(obj)
                new_lines.append(
                    json.dumps(obj, ensure_ascii=False) + "\n"
                )
                matched = True
            else:
                new_lines.append(raw)

        if not matched:
            return False

        # Atomic rewrite: temp file in same dir + os.replace.
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix=path.stem + ".",
            suffix=".tmp",
            dir=str(self._events_dir),
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as out:
                out.writelines(new_lines)
            os.replace(tmp_path, path)
        except OSError as exc:
            logger.error(
                f"_rewrite_one_locked: rewrite failed for {path}: {exc}"
            )
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return False

        # If the rewritten file is the one we currently have open for
        # append, our existing FD now points at the replaced inode.
        # Reopen so subsequent appends land in the new file.
        if (
            self._current_file is not None
            and self._current_date == target_date.strftime("%Y-%m-%d")
        ):
            try:
                self._current_file.close()
            except Exception:  # pragma: no cover
                pass
            self._current_file = open(path, "a", encoding="utf-8")

        return True

    def _rotate(self, date_str: str) -> None:
        """Open a new daily log file and clean up old ones."""
        if self._current_file:
            self._current_file.close()
        path = self._events_dir / f"{date_str}.jsonl"
        self._current_file = open(path, "a", encoding="utf-8")
        self._current_date = date_str
        self._cleanup()

    def _cleanup(self) -> None:
        """Delete JSONL files older than retention_days."""
        cutoff = datetime.now() - timedelta(days=self._retention_days)
        for f in self._events_dir.glob("*.jsonl"):
            try:
                file_date = datetime.strptime(f.stem, "%Y-%m-%d")
                if file_date < cutoff:
                    f.unlink()
                    logger.info(f"Deleted old event log: {f.name}")
            except ValueError:
                pass

    def close(self) -> None:
        """Close the current file handle."""
        if self._current_file:
            self._current_file.close()
            self._current_file = None

    @staticmethod
    def _serialize(event: SecurityEvent) -> dict:
        """Convert SecurityEvent to a JSON-safe dict."""
        return {
            "ts": event.timestamp.isoformat(),
            "source": event.source,
            "actor_pid": event.actor_pid,
            "actor_name": event.actor_name,
            "event_type": event.event_type,
            "target": event.target,
            "detail": event.detail,
            "risk_score": event.risk_score,
            "event_id": event.event_id,
        }
