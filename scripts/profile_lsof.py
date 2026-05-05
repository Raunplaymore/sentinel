"""Sentinel v0.11 — lsof cache scenario profiler.

Measures the cost of FSWatcher._identify_actor across three burst patterns
to expose cache effectiveness. Unlike scripts/profile_workload.py (which
patches lsof out to measure the watcher logic in isolation), this script
runs the real subprocess.

Run from repo root:

    python3 scripts/profile_lsof.py

Reports per-call timing and cache size for each scenario. Use to validate
perf changes to `_identify_actor`.

Scenarios:

  unique  — 100 different paths (cold cache; bound by subprocess cost)
  repeat  — 1 path × 100 calls (cache should fully absorb the burst)
  mixed   — 10 paths × 10 calls (typical "IDE edit cycle" pattern)
"""

from __future__ import annotations

import queue
import shutil
import sys
import tempfile
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sentinel_mac.collectors.fs_watcher import FSWatcher  # noqa: E402


def _make_watcher(tmp: Path) -> FSWatcher:
    config = {
        "security": {
            "fs_watcher": {
                "watch_paths": [str(tmp)],
                "sensitive_paths": [str(tmp)],
                "ignore_patterns": [],
                "bulk_threshold": 50,
                "bulk_window_seconds": 30,
            },
            "download_tracking": {"enabled": False},
        }
    }
    q: queue.Queue = queue.Queue(maxsize=10_000)
    return FSWatcher(config, q)


def _scenario(label: str, paths: list[str]) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="sentinel-lsof-"))
    try:
        for p in paths:
            full = tmp / Path(p).name
            full.write_text("x")
        watcher = _make_watcher(tmp)
        full_paths = [str(tmp / Path(p).name) for p in paths]

        start = time.perf_counter()
        for fp in full_paths:
            watcher._identify_actor(fp)
        elapsed = time.perf_counter() - start

        unique = len(set(full_paths))
        cache = watcher._lsof_cache
        print(
            f"  {label}: {len(full_paths)} calls, {unique} unique paths, "
            f"elapsed={elapsed * 1000:.1f}ms, "
            f"per-call={elapsed * 1000 / len(full_paths):.2f}ms, "
            f"cache_size={len(cache)}"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    print("[lsof scenarios]")
    _scenario("unique  ", [f"file_{i:03d}.txt" for i in range(100)])
    _scenario("repeat  ", ["file_000.txt"] * 100)
    _scenario("mixed   ", [f"file_{i % 10:03d}.txt" for i in range(100)])
    return 0


if __name__ == "__main__":
    sys.exit(main())
