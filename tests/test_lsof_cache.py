"""Tests for FSWatcher._identify_actor's per-path TTL cache (v0.11).

The previous cache (single global timestamp + positive-results-only) is
fixed in v0.11 to:
  - cache per-path with per-entry TTL (was: global TTL across all paths)
  - cache negative results too (was: only positive results)
  - LRU bound at _lsof_cache_max (was: unbounded)
"""

from __future__ import annotations

import queue
import time
from collections import OrderedDict
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel_mac.collectors.fs_watcher import FSWatcher


def _watcher(tmp_path: Path) -> FSWatcher:
    config = {
        "security": {
            "fs_watcher": {
                "watch_paths": [str(tmp_path)],
                "sensitive_paths": [str(tmp_path)],
                "ignore_patterns": [],
                "bulk_threshold": 50,
                "bulk_window_seconds": 30,
            },
            "download_tracking": {"enabled": False},
        }
    }
    q: queue.Queue = queue.Queue(maxsize=100)
    return FSWatcher(config, q)


class TestLsofCacheStructure:
    """Structure invariants — type, defaults."""

    def test_cache_is_ordered_dict(self, tmp_path: Path) -> None:
        w = _watcher(tmp_path)
        assert isinstance(w._lsof_cache, OrderedDict)

    def test_default_ttl_30s(self, tmp_path: Path) -> None:
        """30s — large enough for a 10-path rotation to complete a round
        even at 290ms/uncached call (10*290ms ≈ 3s, well under 30s)."""
        w = _watcher(tmp_path)
        assert w._lsof_cache_ttl == 30.0

    def test_default_lru_cap_512(self, tmp_path: Path) -> None:
        w = _watcher(tmp_path)
        assert w._lsof_cache_max == 512


class TestPositiveResultCaching:
    """A path with a known holder — cache hit avoids subprocess."""

    def test_first_call_invokes_subprocess(self, tmp_path: Path) -> None:
        w = _watcher(tmp_path)
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = "p1234\ncpython\n"
        with patch(
            "sentinel_mac.collectors.fs_watcher.subprocess.run",
            return_value=mock,
        ) as run:
            pid, name = w._identify_actor("/some/path")
            assert (pid, name) == (1234, "python")
            assert run.call_count == 1

    def test_second_call_hits_cache(self, tmp_path: Path) -> None:
        w = _watcher(tmp_path)
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = "p1234\ncpython\n"
        with patch(
            "sentinel_mac.collectors.fs_watcher.subprocess.run",
            return_value=mock,
        ) as run:
            w._identify_actor("/p")
            w._identify_actor("/p")
            w._identify_actor("/p")
            assert run.call_count == 1


class TestNegativeResultCaching:
    """v0.11 fix: paths with no holder must also cache.

    fs_events mostly land on files with no holder (just-created tmp files,
    write-then-close patterns). The prior cache only stored positive
    results, so these paid the subprocess cost on every event.
    """

    def test_empty_lsof_output_is_cached(self, tmp_path: Path) -> None:
        w = _watcher(tmp_path)
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        with patch(
            "sentinel_mac.collectors.fs_watcher.subprocess.run",
            return_value=mock,
        ) as run:
            assert w._identify_actor("/p") == (0, "unknown")
            assert w._identify_actor("/p") == (0, "unknown")
            assert w._identify_actor("/p") == (0, "unknown")
            assert run.call_count == 1
            assert "/p" in w._lsof_cache

    def test_subprocess_error_is_cached(self, tmp_path: Path) -> None:
        """OSError / TimeoutExpired etc. — fall through, still cache the
        negative result so we don't keep retrying the same broken path."""
        w = _watcher(tmp_path)
        with patch(
            "sentinel_mac.collectors.fs_watcher.subprocess.run",
            side_effect=OSError("boom"),
        ) as run:
            assert w._identify_actor("/p") == (0, "unknown")
            assert w._identify_actor("/p") == (0, "unknown")
            assert run.call_count == 1


class TestPerPathTTL:
    """Each entry has its own timestamp (was: global)."""

    def test_stale_entry_is_refreshed(self, tmp_path: Path) -> None:
        w = _watcher(tmp_path)
        w._lsof_cache_ttl = 0.05  # 50ms for fast test
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        with patch(
            "sentinel_mac.collectors.fs_watcher.subprocess.run",
            return_value=mock,
        ) as run:
            w._identify_actor("/p")
            time.sleep(0.07)
            w._identify_actor("/p")
            assert run.call_count == 2

    def test_one_path_cold_does_not_evict_another_hot(
        self, tmp_path: Path,
    ) -> None:
        """Different paths have independent timestamps — looking up a
        cold path does not invalidate the hot path's cache."""
        w = _watcher(tmp_path)
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        with patch(
            "sentinel_mac.collectors.fs_watcher.subprocess.run",
            return_value=mock,
        ) as run:
            w._identify_actor("/hot")
            w._identify_actor("/cold")
            w._identify_actor("/hot")
            w._identify_actor("/cold")
            # 2 unique paths, 2 subprocess calls — repeats are cached.
            assert run.call_count == 2


class TestLruEviction:
    """When the cache exceeds _lsof_cache_max, the oldest entry is evicted."""

    def test_lru_cap_enforced(self, tmp_path: Path) -> None:
        w = _watcher(tmp_path)
        w._lsof_cache_max = 3
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        with patch(
            "sentinel_mac.collectors.fs_watcher.subprocess.run",
            return_value=mock,
        ):
            w._identify_actor("/a")
            w._identify_actor("/b")
            w._identify_actor("/c")
            w._identify_actor("/d")  # evicts /a (oldest)
            assert "/a" not in w._lsof_cache
            assert "/b" in w._lsof_cache
            assert "/c" in w._lsof_cache
            assert "/d" in w._lsof_cache

    def test_lru_touch_on_hit(self, tmp_path: Path) -> None:
        """A cache hit moves the entry to the most-recent position."""
        w = _watcher(tmp_path)
        w._lsof_cache_max = 3
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        with patch(
            "sentinel_mac.collectors.fs_watcher.subprocess.run",
            return_value=mock,
        ):
            w._identify_actor("/a")
            w._identify_actor("/b")
            w._identify_actor("/c")
            w._identify_actor("/a")  # hit — /a moves to most-recent
            w._identify_actor("/d")  # evicts /b (now oldest)
            assert "/a" in w._lsof_cache
            assert "/b" not in w._lsof_cache
            assert "/c" in w._lsof_cache
            assert "/d" in w._lsof_cache


class TestParseCorrectness:
    """The lsof output parser is unchanged but covered for regression."""

    @pytest.mark.parametrize("stdout,expected", [
        ("p1234\ncpython\n", (1234, "python")),
        ("p1234\ncclaude\nf2\n", (1234, "claude")),
        ("p99999\ncnode\n", (99999, "node")),
    ])
    def test_parses_pid_and_name(
        self, tmp_path: Path, stdout: str, expected: tuple[int, str],
    ) -> None:
        w = _watcher(tmp_path)
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = stdout
        with patch(
            "sentinel_mac.collectors.fs_watcher.subprocess.run",
            return_value=mock,
        ):
            assert w._identify_actor("/p") == expected
