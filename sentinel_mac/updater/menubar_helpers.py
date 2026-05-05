"""Pure helpers for the menu bar app's update flow (ADR 0010 §D4 Track C).

Extracted from `menubar_app.py` so they can be unit-tested without importing
rumps (which requires a display). The menu bar app and the test suite both
import these — the production logic and the tested logic are guaranteed to
be the same module.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_SKIPPED_VERSIONS_RELPATH = ("updater", "skipped_versions.txt")


def _skipped_versions_path(data_dir: Path) -> Path:
    return data_dir.joinpath(*_SKIPPED_VERSIONS_RELPATH)


def read_skipped_versions(data_dir: Path) -> set[str]:
    """Read set of skipped versions from <data_dir>/updater/skipped_versions.txt."""
    skipped_path = _skipped_versions_path(data_dir)
    if not skipped_path.exists():
        return set()
    try:
        lines = skipped_path.read_text().strip().split("\n")
        return {line.strip() for line in lines if line.strip()}
    except Exception:
        logger.exception("failed to read skipped_versions")
        return set()


def add_skipped_version(data_dir: Path, version: str) -> None:
    """Append `version` to the skipped list (idempotent — duplicates ignored)."""
    updater_dir = data_dir / "updater"
    updater_dir.mkdir(parents=True, exist_ok=True)
    skipped_path = _skipped_versions_path(data_dir)

    skipped = read_skipped_versions(data_dir)
    if version in skipped:
        return
    skipped.add(version)
    try:
        skipped_path.write_text("\n".join(sorted(skipped)) + "\n")
    except Exception:
        logger.exception("failed to write skipped_versions")


def parse_check_envelope(stdout: str) -> dict:
    """Parse the `--json` envelope emitted by `sentinel update --check`.

    On JSON parse failure returns an `error` envelope so callers can use a
    single dispatch path on the `result` key.
    """
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"result": "error", "message": "Failed to parse JSON"}


def should_show_dialog(envelope: dict, skipped: set[str]) -> bool:
    """Whether the menu bar should pop the modal `Update Now / Skip / Cancel` dialog.

    Returns True only for `update_available` envelopes whose `latest` version
    has not been skipped previously. All other results (up_to_date, error,
    editable, system_unsafe, homebrew) get a notification, never a dialog.
    """
    if envelope.get("result") != "update_available":
        return False
    latest = envelope.get("latest", "unknown")
    return latest not in skipped
