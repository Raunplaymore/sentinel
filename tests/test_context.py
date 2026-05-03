"""Tests for HostContext, TrustLevel, and HostObservation (v0.6)."""
import dataclasses
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pytest

from sentinel_mac.collectors.context import (
    HostContext,
    HostObservation,
    TrustLevel,
)

# ─── helpers ───────────────────────────────────────────────────────


def _make_ctx(
    tmp_path: Path,
    *,
    enabled: bool = True,
    known_hosts: Optional[Path] = None,
    auto_trust_after_seen: int = 5,
    learning_window_days: int = 30,
    dedup_window_seconds: int = 3600,
    max_tracked_hosts: int = 5000,
    blocklist: Optional[list] = None,
    cache_name: str = "host_context.jsonl",
) -> HostContext:
    """Construct a HostContext rooted under tmp_path."""
    return HostContext(
        enabled=enabled,
        cache_path=tmp_path / cache_name,
        known_hosts_path=known_hosts,
        auto_trust_after_seen=auto_trust_after_seen,
        learning_window_days=learning_window_days,
        dedup_window_seconds=dedup_window_seconds,
        max_tracked_hosts=max_tracked_hosts,
        blocklist=blocklist or [],
    )


def _write_known_hosts(tmp_path: Path, lines: list) -> Path:
    """Write a known_hosts file under tmp_path and return the path."""
    p = tmp_path / "known_hosts"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


# ─── TrustLevel ────────────────────────────────────────────────────


class TestTrustLevel:
    """TrustLevel enum semantics."""

    def test_rank_ordering(self):
        assert TrustLevel.rank(TrustLevel.UNKNOWN) == 0
        assert TrustLevel.rank(TrustLevel.LEARNED) == 1
        assert TrustLevel.rank(TrustLevel.KNOWN) == 2
        assert TrustLevel.rank(TrustLevel.BLOCKED) == 3

    def test_str_enum_roundtrip(self):
        assert TrustLevel("known") is TrustLevel.KNOWN
        assert TrustLevel("blocked") is TrustLevel.BLOCKED
        assert TrustLevel.KNOWN.value == "known"

    def test_json_roundtrip(self):
        encoded = json.dumps({"level": TrustLevel.LEARNED.value})
        decoded = json.loads(encoded)
        assert TrustLevel(decoded["level"]) is TrustLevel.LEARNED


# ─── HostObservation ───────────────────────────────────────────────


class TestHostObservation:
    """HostObservation is a frozen dataclass."""

    def test_frozen_cannot_mutate(self):
        obs = HostObservation(host="x.io", count=1, first_seen=0, last_seen=0)
        with pytest.raises(dataclasses.FrozenInstanceError):
            obs.count = 99  # type: ignore[misc]

    def test_basic_fields(self):
        obs = HostObservation(host="x.io", count=3, first_seen=10, last_seen=20)
        assert obs.host == "x.io"
        assert obs.count == 3
        assert obs.first_seen == 10
        assert obs.last_seen == 20


# ─── disabled mode ────────────────────────────────────────────────


class TestHostContextDisabled:
    """Disabled instance is a cheap no-op."""

    def test_classify_returns_unknown(self, tmp_path):
        ctx = _make_ctx(tmp_path, enabled=False)
        assert ctx.classify("api.x.io") is TrustLevel.UNKNOWN

    def test_observe_is_noop(self, tmp_path):
        ctx = _make_ctx(tmp_path, enabled=False)
        ctx.observe("api.x.io")
        assert ctx.seen_count("api.x.io") == 0

    def test_load_flush_no_disk_io(self, tmp_path):
        ctx = _make_ctx(tmp_path, enabled=False)
        ctx.load()
        ctx.observe("api.x.io")
        ctx.flush()
        # No files should have been created.
        assert list(tmp_path.iterdir()) == []

    def test_iter_observations_empty(self, tmp_path):
        ctx = _make_ctx(tmp_path, enabled=False)
        assert list(ctx.iter_observations()) == []

    def test_is_in_known_hosts_false(self, tmp_path):
        ctx = _make_ctx(tmp_path, enabled=False)
        assert ctx.is_in_known_hosts("anything") is False

    def test_forget_returns_false(self, tmp_path):
        ctx = _make_ctx(tmp_path, enabled=False)
        assert ctx.forget("anything") is False


# ─── __init__ validation ──────────────────────────────────────────


class TestHostContextValidation:
    """Construction-time argument validation."""

    def test_auto_trust_below_2_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            HostContext(
                enabled=True,
                cache_path=tmp_path / "c.jsonl",
                auto_trust_after_seen=1,
            )

    def test_learning_window_zero_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            HostContext(
                enabled=True,
                cache_path=tmp_path / "c.jsonl",
                learning_window_days=0,
            )

    def test_dedup_negative_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            HostContext(
                enabled=True,
                cache_path=tmp_path / "c.jsonl",
                dedup_window_seconds=-1,
            )

    def test_max_tracked_zero_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            HostContext(
                enabled=True,
                cache_path=tmp_path / "c.jsonl",
                max_tracked_hosts=0,
            )

    def test_dedup_zero_allowed(self, tmp_path):
        # Zero is allowed (counts every observation immediately).
        ctx = _make_ctx(tmp_path, dedup_window_seconds=0)
        ctx.load()
        ctx.observe("a.io", now_epoch=100)
        ctx.observe("a.io", now_epoch=100)
        assert ctx.seen_count("a.io") == 2


# ─── known_hosts parsing ──────────────────────────────────────────


class TestHostContextKnownHosts:
    """known_hosts loading and matching."""

    def test_literal_match(self, tmp_path):
        kh = _write_known_hosts(tmp_path, [
            "bastion.example.com ssh-rsa AAAA...",
        ])
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        ctx.load()
        assert ctx.is_in_known_hosts("bastion.example.com") is True
        assert ctx.is_in_known_hosts("other.example.com") is False

    def test_comma_joined_patterns(self, tmp_path):
        kh = _write_known_hosts(tmp_path, [
            "host1,host2,*.alt ssh-rsa AAAA...",
        ])
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        ctx.load()
        assert ctx.is_in_known_hosts("host1") is True
        assert ctx.is_in_known_hosts("host2") is True
        assert ctx.is_in_known_hosts("foo.alt") is True
        assert ctx.is_in_known_hosts("bar.alt") is True
        assert ctx.is_in_known_hosts("host3") is False

    def test_wildcard_match(self, tmp_path):
        kh = _write_known_hosts(tmp_path, [
            "*.example.com ssh-rsa AAAA...",
        ])
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        ctx.load()
        assert ctx.is_in_known_hosts("api.example.com") is True
        assert ctx.is_in_known_hosts("foo.bar.example.com") is True
        # OpenSSH '*' typically matches at least one label; we match anything
        # via fnmatch for simplicity. The salient case is that wildcard
        # patterns work.
        assert ctx.is_in_known_hosts("not-example.org") is False

    def test_case_insensitive_lookup(self, tmp_path):
        kh = _write_known_hosts(tmp_path, [
            "Bastion.Example.COM ssh-rsa AAAA...",
        ])
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        ctx.load()
        assert ctx.is_in_known_hosts("bastion.example.com") is True
        assert ctx.is_in_known_hosts("BASTION.EXAMPLE.COM") is True

    def test_hashed_entries_skipped_with_info_log(self, tmp_path, caplog):
        kh = _write_known_hosts(tmp_path, [
            "|1|abc=|def= ssh-rsa AAAA...",
            "|1|ghi=|jkl= ssh-rsa AAAA...",
            "plain.example.com ssh-rsa AAAA...",
        ])
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        with caplog.at_level(logging.INFO, logger="sentinel_mac.collectors.context"):
            ctx.load()
        assert ctx.is_in_known_hosts("plain.example.com") is True
        # Hashed entries are not matchable.
        assert any(
            "hashed known_hosts entries" in record.message
            for record in caplog.records
        )

    def test_missing_known_hosts_file(self, tmp_path):
        ctx = _make_ctx(tmp_path, known_hosts=tmp_path / "nope")
        ctx.load()  # should not raise
        assert ctx.is_in_known_hosts("anything") is False

    def test_empty_known_hosts_file(self, tmp_path):
        kh = tmp_path / "known_hosts"
        kh.write_text("", encoding="utf-8")
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        ctx.load()
        assert ctx.is_in_known_hosts("anything") is False

    def test_comment_and_blank_lines_ignored(self, tmp_path):
        kh = _write_known_hosts(tmp_path, [
            "",
            "# this is a comment",
            "real.host ssh-rsa AAAA...",
        ])
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        ctx.load()
        assert ctx.is_in_known_hosts("real.host") is True

    def test_corrupt_lines_skipped(self, tmp_path):
        kh = _write_known_hosts(tmp_path, [
            "good.host ssh-rsa AAAA...",
            "this-line-has-no-key-field",
            "another.good ssh-ed25519 BBB...",
        ])
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        ctx.load()
        assert ctx.is_in_known_hosts("good.host") is True
        assert ctx.is_in_known_hosts("another.good") is True

    def test_cert_authority_marker_handled(self, tmp_path):
        kh = _write_known_hosts(tmp_path, [
            "@cert-authority *.ca.example ssh-rsa AAAA...",
        ])
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        ctx.load()
        assert ctx.is_in_known_hosts("foo.ca.example") is True

    def test_bracketed_port_form(self, tmp_path):
        kh = _write_known_hosts(tmp_path, [
            "[bastion.internal]:2222 ssh-rsa AAAA...",
        ])
        ctx = _make_ctx(tmp_path, known_hosts=kh)
        ctx.load()
        assert ctx.is_in_known_hosts("bastion.internal") is True


# ─── frequency / observe / dedup ──────────────────────────────────


class TestHostContextFrequency:
    """observe(), dedup, learning window, LRU."""

    def test_below_threshold_is_unknown(self, tmp_path):
        ctx = _make_ctx(tmp_path, auto_trust_after_seen=5)
        ctx.load()
        ctx.observe("api.example.org", now_epoch=1_000_000)
        assert ctx.classify("api.example.org") is TrustLevel.UNKNOWN
        assert ctx.seen_count("api.example.org") == 1

    def test_at_threshold_promotes_to_learned(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            auto_trust_after_seen=5,
            dedup_window_seconds=60,
        )
        ctx.load()
        # Five distinct windows.
        for i in range(5):
            ctx.observe("api.example.org", now_epoch=1_000_000 + i * 120)
        assert ctx.seen_count("api.example.org") == 5
        assert ctx.classify("api.example.org") is TrustLevel.LEARNED

    def test_dedup_within_window(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            auto_trust_after_seen=5,
            dedup_window_seconds=3600,
        )
        ctx.load()
        # Repeat 10 times within 30s — should still count as 1.
        for offset in range(10):
            ctx.observe("api.example.org", now_epoch=1_000_000 + offset * 3)
        assert ctx.seen_count("api.example.org") == 1

    def test_dedup_does_not_bump_last_seen(self, tmp_path):
        # Otherwise dedup would slide forever and never expire.
        ctx = _make_ctx(
            tmp_path,
            auto_trust_after_seen=5,
            dedup_window_seconds=100,
        )
        ctx.load()
        ctx.observe("a.io", now_epoch=1000)
        ctx.observe("a.io", now_epoch=1050)  # within dedup window — ignored
        # Now jump just past 1000 + 100 = 1100 from the *original* last_seen.
        ctx.observe("a.io", now_epoch=1101)
        assert ctx.seen_count("a.io") == 2

    def test_ip_literal_observe_is_noop(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.load()
        ctx.observe("192.168.1.1", now_epoch=1000)
        ctx.observe("::1", now_epoch=1000)
        assert ctx.seen_count("192.168.1.1") == 0
        assert ctx.seen_count("::1") == 0

    def test_ip_literal_classify_unknown(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.load()
        assert ctx.classify("192.168.1.1") is TrustLevel.UNKNOWN
        assert ctx.classify("2001:db8::1") is TrustLevel.UNKNOWN

    def test_empty_host_is_unknown(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.load()
        assert ctx.classify("") is TrustLevel.UNKNOWN
        assert ctx.classify("   ") is TrustLevel.UNKNOWN

    def test_normalization_lowercase(self, tmp_path):
        ctx = _make_ctx(tmp_path, auto_trust_after_seen=2, dedup_window_seconds=10)
        ctx.load()
        ctx.observe("API.Example.org", now_epoch=1000)
        ctx.observe("api.example.org", now_epoch=2000)
        assert ctx.seen_count("API.EXAMPLE.ORG") == 2
        assert ctx.classify("api.example.org") is TrustLevel.LEARNED

    def test_learning_window_prune_on_load(self, tmp_path):
        # Persist an entry well in the past, then reload with a 1-day window.
        ctx = _make_ctx(tmp_path, learning_window_days=1, dedup_window_seconds=10)
        ctx.load()
        old = int(time.time()) - 3 * 86400
        ctx.observe("stale.example.org", now_epoch=old)
        ctx.observe("fresh.example.org", now_epoch=int(time.time()))
        ctx.flush()

        # Reload from disk.
        ctx2 = _make_ctx(tmp_path, learning_window_days=1, dedup_window_seconds=10)
        ctx2.load()
        assert ctx2.seen_count("stale.example.org") == 0
        assert ctx2.seen_count("fresh.example.org") == 1

    def test_max_tracked_hosts_lru_evict(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            max_tracked_hosts=3,
            dedup_window_seconds=0,
        )
        ctx.load()
        ctx.observe("a.io", now_epoch=1000)
        ctx.observe("b.io", now_epoch=2000)
        ctx.observe("c.io", now_epoch=3000)
        ctx.observe("d.io", now_epoch=4000)
        # a.io has the oldest last_seen so it should have been evicted.
        hosts = {o.host for o in ctx.iter_observations()}
        assert "a.io" not in hosts
        assert hosts == {"b.io", "c.io", "d.io"}

    def test_forget_present(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.load()
        ctx.observe("a.io", now_epoch=1000)
        assert ctx.forget("a.io") is True
        assert ctx.seen_count("a.io") == 0

    def test_forget_absent(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.load()
        assert ctx.forget("never-seen.io") is False


# ─── blocklist ────────────────────────────────────────────────────


class TestHostContextBlocklist:
    """Blocklist semantics."""

    def test_literal_blocklist_match(self, tmp_path):
        ctx = _make_ctx(tmp_path, blocklist=["evil.com"])
        ctx.load()
        assert ctx.classify("evil.com") is TrustLevel.BLOCKED

    def test_wildcard_blocklist_match(self, tmp_path):
        ctx = _make_ctx(tmp_path, blocklist=["*.suspicious.tld"])
        ctx.load()
        assert ctx.classify("a.suspicious.tld") is TrustLevel.BLOCKED
        assert ctx.classify("good.tld") is TrustLevel.UNKNOWN

    def test_blocklist_overrides_known_hosts(self, tmp_path):
        kh = _write_known_hosts(tmp_path, [
            "bastion.example.com ssh-rsa AAAA...",
        ])
        ctx = _make_ctx(
            tmp_path,
            known_hosts=kh,
            blocklist=["bastion.example.com"],
        )
        ctx.load()
        assert ctx.classify("bastion.example.com") is TrustLevel.BLOCKED

    def test_blocklist_overrides_learned(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            auto_trust_after_seen=2,
            dedup_window_seconds=10,
            blocklist=["foo.io"],
        )
        ctx.load()
        ctx.observe("foo.io", now_epoch=1000)
        ctx.observe("foo.io", now_epoch=2000)
        # Frequency would say LEARNED, but BLOCKED wins.
        assert ctx.classify("foo.io") is TrustLevel.BLOCKED

    def test_blocklist_ip_literal(self, tmp_path):
        ctx = _make_ctx(tmp_path, blocklist=["10.0.0.5"])
        ctx.load()
        assert ctx.classify("10.0.0.5") is TrustLevel.BLOCKED

    def test_blocklist_normalized(self, tmp_path):
        ctx = _make_ctx(tmp_path, blocklist=["  Evil.COM  "])
        ctx.load()
        assert ctx.classify("evil.com") is TrustLevel.BLOCKED


# ─── persistence / corruption ─────────────────────────────────────


class TestHostContextPersistence:
    """Persistence: round-trip, atomic write, corruption handling."""

    def test_flush_then_load_roundtrip(self, tmp_path):
        # Use timestamps near "now" so the learning-window prune on load
        # does not discard them.
        now = int(time.time())
        ctx = _make_ctx(tmp_path, dedup_window_seconds=10)
        ctx.load()
        ctx.observe("a.io", now_epoch=now - 200)
        ctx.observe("a.io", now_epoch=now - 100)
        ctx.observe("b.io", now_epoch=now - 50)
        ctx.flush()

        ctx2 = _make_ctx(tmp_path, dedup_window_seconds=10)
        ctx2.load()
        assert ctx2.seen_count("a.io") == 2
        assert ctx2.seen_count("b.io") == 1

    def test_flush_uses_atomic_replace(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.load()
        ctx.observe("a.io", now_epoch=1000)

        with patch(
            "sentinel_mac.collectors.context.os.replace",
            wraps=os.replace,
        ) as mock_replace:
            ctx.flush()
            assert mock_replace.called
            args, _ = mock_replace.call_args
            assert str(args[0]).endswith(".tmp")
            assert str(args[1]).endswith("host_context.jsonl")

    def test_flush_skips_when_clean(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.load()
        # No observations — nothing dirty.
        with patch(
            "sentinel_mac.collectors.context.os.replace",
            wraps=os.replace,
        ) as mock_replace:
            ctx.flush()
            assert not mock_replace.called

    def test_corrupt_random_text_quarantined(self, tmp_path, caplog):
        cache = tmp_path / "host_context.jsonl"
        cache.write_text("this is not valid json\nat all\n", encoding="utf-8")

        ctx = _make_ctx(tmp_path)
        with caplog.at_level(logging.WARNING, logger="sentinel_mac.collectors.context"):
            ctx.load()

        # Original cache moved aside.
        assert not cache.exists()
        quarantined = list(tmp_path.glob("host_context.jsonl.corrupted-*"))
        assert len(quarantined) == 1
        # Counter reset.
        assert list(ctx.iter_observations()) == []
        assert any("corrupted" in r.message for r in caplog.records)

    def test_missing_meta_treated_as_corrupt(self, tmp_path):
        cache = tmp_path / "host_context.jsonl"
        # Valid JSON but no _meta header.
        cache.write_text(
            json.dumps({"host": "x.io", "count": 1, "first_seen": 0, "last_seen": 0})
            + "\n",
            encoding="utf-8",
        )
        ctx = _make_ctx(tmp_path)
        ctx.load()
        assert not cache.exists()
        assert list(tmp_path.glob("host_context.jsonl.corrupted-*"))

    def test_unknown_schema_treated_as_corrupt(self, tmp_path):
        cache = tmp_path / "host_context.jsonl"
        cache.write_text(
            json.dumps({"_meta": {"schema": 99}}) + "\n",
            encoding="utf-8",
        )
        ctx = _make_ctx(tmp_path)
        ctx.load()
        assert not cache.exists()
        assert list(tmp_path.glob("host_context.jsonl.corrupted-*"))

    def test_missing_cache_starts_empty_no_warning(self, tmp_path, caplog):
        ctx = _make_ctx(tmp_path)
        with caplog.at_level(logging.WARNING, logger="sentinel_mac.collectors.context"):
            ctx.load()
        assert list(ctx.iter_observations()) == []
        # No warning on first run.
        assert not any("corrupted" in r.message for r in caplog.records)

    def test_flush_writes_meta_header(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.load()
        ctx.observe("a.io", now_epoch=1000)
        ctx.flush()

        cache = tmp_path / "host_context.jsonl"
        first_line = cache.read_text(encoding="utf-8").splitlines()[0]
        meta = json.loads(first_line)
        assert "_meta" in meta
        assert meta["_meta"]["schema"] == 1

    def test_iter_observations_returns_snapshot(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        ctx.load()
        ctx.observe("a.io", now_epoch=1000)
        ctx.observe("b.io", now_epoch=1001)
        hosts = sorted(o.host for o in ctx.iter_observations())
        assert hosts == ["a.io", "b.io"]


# ─── from_config ──────────────────────────────────────────────────


class TestHostContextFromConfig:
    """Config-driven construction."""

    def test_empty_config_disabled(self):
        ctx = HostContext.from_config({})
        assert ctx.classify("anything") is TrustLevel.UNKNOWN
        # observe is a no-op.
        ctx.observe("anything")
        assert ctx.seen_count("anything") == 0

    def test_enabled_false_disabled(self):
        ctx = HostContext.from_config(
            {"security": {"context_aware": {"enabled": False}}}
        )
        assert ctx.classify("anything") is TrustLevel.UNKNOWN

    def test_xdg_default_resolved(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        ctx = HostContext.from_config(
            {
                "security": {
                    "context_aware": {
                        "enabled": True,
                        "cache_path": "",
                        "known_hosts_path": "",
                    }
                }
            }
        )
        assert ctx._cache_path == tmp_path / "xdg" / "sentinel" / "host_context.jsonl"

    def test_xdg_fallback_when_unset(self, monkeypatch):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        ctx = HostContext.from_config(
            {
                "security": {
                    "context_aware": {
                        "enabled": True,
                        "cache_path": "",
                        "known_hosts_path": "",
                    }
                }
            }
        )
        expected = (
            Path("~/.local/share").expanduser()
            / "sentinel"
            / "host_context.jsonl"
        )
        assert ctx._cache_path == expected

    def test_full_config_roundtrip(self, tmp_path):
        ctx = HostContext.from_config(
            {
                "security": {
                    "context_aware": {
                        "enabled": True,
                        "auto_trust_after_seen": 7,
                        "learning_window_days": 14,
                        "dedup_window_seconds": 600,
                        "max_tracked_hosts": 100,
                        "known_hosts_path": str(tmp_path / "kh"),
                        "cache_path": str(tmp_path / "cache.jsonl"),
                        "blocklist": ["evil.com", "*.bad.tld"],
                    }
                }
            }
        )
        assert ctx._auto_trust_after_seen == 7
        assert ctx._learning_window_days == 14
        assert ctx._dedup_window_seconds == 600
        assert ctx._max_tracked_hosts == 100
        assert ctx._cache_path == tmp_path / "cache.jsonl"
        assert ctx._known_hosts_path == tmp_path / "kh"
        # Blocklist split.
        assert "evil.com" in ctx._blocklist_literal
        assert "*.bad.tld" in ctx._blocklist_wildcard

    def test_missing_keys_get_defaults(self):
        ctx = HostContext.from_config(
            {"security": {"context_aware": {"enabled": True}}}
        )
        assert ctx._auto_trust_after_seen == 5
        assert ctx._learning_window_days == 30
        assert ctx._dedup_window_seconds == 3600
        assert ctx._max_tracked_hosts == 5000
