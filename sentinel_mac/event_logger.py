"""Sentinel — JSONL Event Logger.

Writes SecurityEvents to daily JSONL files for audit trail and Phase 2 team dashboard.
Files are stored at: <data_dir>/events/YYYY-MM-DD.jsonl
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path

from sentinel_mac.models import SecurityEvent

logger = logging.getLogger(__name__)


class EventLogger:
    """Append-only JSONL event logger with daily rotation."""

    DEFAULT_RETENTION_DAYS = 90

    def __init__(self, data_dir, retention_days=None):
        self._events_dir = Path(data_dir) / "events"
        self._events_dir.mkdir(parents=True, exist_ok=True)
        self._retention_days = retention_days or self.DEFAULT_RETENTION_DAYS
        self._current_date: str = ""
        self._current_file = None

    def log(self, event: SecurityEvent) -> None:
        """Write a SecurityEvent as one JSON line to today's file."""
        today = datetime.now().strftime("%Y-%m-%d")

        # Rotate file on date change
        if today != self._current_date:
            self._rotate(today)

        line = json.dumps(self._serialize(event), ensure_ascii=False)
        try:
            self._current_file.write(line + "\n")
            self._current_file.flush()
        except Exception as e:
            logger.error(f"Failed to write event log: {e}")

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
        }
