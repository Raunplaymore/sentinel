"""Tests for ProjectContext (ADR 0007 D3 + D4).

Covers boundary detection, name resolution, git extraction, caching
semantics (LRU + TTL + invalidate), branch_hint override, and
ProjectContext.from_config.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pytest

from sentinel_mac.collectors.project_context import (
    ProjectContext,
    _normalize_github_url,
)


# ─── helpers ───────────────────────────────────────────────────────


def _write_pyproject_pep621(root: Path, name: str) -> None:
    (root / "pyproject.toml").write_text(
        f'[build-system]\nrequires = ["setuptools"]\n\n'
        f'[project]\nname = "{name}"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )


def _write_pyproject_poetry(root: Path, name: str) -> None:
    (root / "pyproject.toml").write_text(
        f'[tool.poetry]\nname = "{name}"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )


def _write_package_json(root: Path, name: str) -> None:
    (root / "package.json").write_text(
        json.dumps({"name": name, "version": "0.0.1"}),
        encoding="utf-8",
    )


def _make_git_dir(
    root: Path,
    *,
    head_ref: Optional[str] = "main",
    head_sha: Optional[str] = "abcdef1234567890abcdef1234567890abcdef12",
    remote_url: Optional[str] = None,
    detached_sha: Optional[str] = None,
    packed_refs: bool = False,
) -> Path:
    """Create a fake .git/ directory under ``root``.

    - ``detached_sha`` (when set) writes a raw 40-hex SHA to .git/HEAD.
    - Otherwise .git/HEAD becomes ``ref: refs/heads/<head_ref>``.
    - ``head_sha`` is written to .git/refs/heads/<head_ref> (loose) unless
      ``packed_refs=True``, in which case it goes to .git/packed-refs.
    - ``remote_url`` (when set) writes a [remote "origin"] block.
    """
    git = root / ".git"
    git.mkdir(parents=True, exist_ok=True)
    if detached_sha is not None:
        (git / "HEAD").write_text(detached_sha + "\n", encoding="utf-8")
    else:
        (git / "HEAD").write_text(
            f"ref: refs/heads/{head_ref}\n", encoding="utf-8",
        )
        if head_sha is not None:
            if packed_refs:
                (git / "packed-refs").write_text(
                    "# pack-refs with: peeled fully-peeled sorted\n"
                    f"{head_sha} refs/heads/{head_ref}\n",
                    encoding="utf-8",
                )
            else:
                refs_dir = git / "refs" / "heads"
                refs_dir.mkdir(parents=True, exist_ok=True)
                (refs_dir / head_ref).write_text(
                    head_sha + "\n", encoding="utf-8",
                )

    if remote_url is not None:
        (git / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n"
            f'[remote "origin"]\n\turl = {remote_url}\n'
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            encoding="utf-8",
        )
    return git


# ─── boundary detection ────────────────────────────────────────────


class TestProjectContextBoundary:
    """Walk-up boundary detection (ADR 0007 D3 — first match wins)."""

    def test_git_only_boundary(self, tmp_path):
        proj = tmp_path / "myproj"
        proj.mkdir()
        _make_git_dir(proj, remote_url=None)
        sub = proj / "src" / "deep"
        sub.mkdir(parents=True)

        ctx = ProjectContext()
        meta = ctx.lookup(str(sub))
        assert meta is not None
        assert meta["root"] == str(proj.resolve())
        # No name file → fallback to basename(root).
        assert meta["name"] == "myproj"

    def test_pyproject_only_boundary(self, tmp_path):
        proj = tmp_path / "pyproj"
        proj.mkdir()
        _write_pyproject_pep621(proj, "demo-py")

        ctx = ProjectContext()
        meta = ctx.lookup(str(proj))
        assert meta is not None
        assert meta["root"] == str(proj.resolve())
        assert meta["name"] == "demo-py"
        # No .git anywhere → git is None.
        assert meta["git"] is None

    def test_package_json_only_boundary(self, tmp_path):
        proj = tmp_path / "node-app"
        proj.mkdir()
        _write_package_json(proj, "my-node-app")

        ctx = ProjectContext()
        meta = ctx.lookup(str(proj / "src"))
        # cwd doesn't exist → realpath still resolves; lookup walks from
        # the resolved path. Actually proj/src doesn't exist so we should
        # get None by the exists() check at the start of _resolve.
        # Test the actual behavior.
        assert meta is None

        # Now from the proj itself which DOES exist.
        meta = ctx.lookup(str(proj))
        assert meta is not None
        assert meta["root"] == str(proj.resolve())
        assert meta["name"] == "my-node-app"

    def test_git_plus_pyproject_same_dir_uses_pyproject_name(self, tmp_path):
        proj = tmp_path / "combined"
        proj.mkdir()
        _make_git_dir(proj, remote_url=None)
        _write_pyproject_pep621(proj, "combined-pkg")

        ctx = ProjectContext()
        meta = ctx.lookup(str(proj))
        assert meta is not None
        assert meta["root"] == str(proj.resolve())
        assert meta["name"] == "combined-pkg"
        assert meta["git"] is not None

    def test_monorepo_first_match_wins(self, tmp_path):
        """ADR 0007 D3: a Node sub-project nested in a Git monorepo finds
        its own package.json first and uses that as `root`. Outer .git is
        still found by the separate git walk.
        """
        outer = tmp_path / "monorepo"
        outer.mkdir()
        _make_git_dir(outer, head_ref="main", remote_url=None)
        sub = outer / "packages" / "ui"
        sub.mkdir(parents=True)
        _write_package_json(sub, "ui-app")

        ctx = ProjectContext()
        meta = ctx.lookup(str(sub))
        assert meta is not None
        # Project root = sub (first marker hit going up).
        assert meta["root"] == str(sub.resolve())
        assert meta["name"] == "ui-app"
        # Git metadata still resolves from the OUTER repo.
        assert meta["git"] is not None
        assert meta["git"]["branch"] == "main"

    def test_max_walk_depth_exceeded_returns_none(self, tmp_path):
        # No markers anywhere — depth cap should bail out.
        deep = tmp_path / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "h"
        deep.mkdir(parents=True)
        ctx = ProjectContext(max_walk_depth=3)
        # The walk stops after 3 parent hops, which is fewer than the
        # depth from `deep` up to tmp_path's parent. No markers → None.
        assert ctx.lookup(str(deep)) is None

    def test_nonexistent_cwd_returns_none(self, tmp_path):
        ctx = ProjectContext()
        assert ctx.lookup(str(tmp_path / "does-not-exist")) is None

    def test_none_or_empty_cwd_returns_none(self, tmp_path):
        ctx = ProjectContext()
        assert ctx.lookup(None) is None
        assert ctx.lookup("") is None


# ─── name resolution ───────────────────────────────────────────────


class TestProjectContextNameResolution:
    """Name priority order (ADR 0007 D3)."""

    def test_pep621_project_name_wins(self, tmp_path):
        proj = tmp_path / "x"
        proj.mkdir()
        _write_pyproject_pep621(proj, "pep621-name")
        ctx = ProjectContext()
        assert ctx.lookup(str(proj))["name"] == "pep621-name"

    def test_poetry_name_when_no_pep621(self, tmp_path):
        proj = tmp_path / "x"
        proj.mkdir()
        _write_pyproject_poetry(proj, "poetry-name")
        ctx = ProjectContext()
        assert ctx.lookup(str(proj))["name"] == "poetry-name"

    def test_pep621_beats_poetry(self, tmp_path):
        proj = tmp_path / "x"
        proj.mkdir()
        # Both sections in one file — PEP 621 wins.
        (proj / "pyproject.toml").write_text(
            '[project]\nname = "pep621-wins"\n\n'
            '[tool.poetry]\nname = "poetry-loses"\n',
            encoding="utf-8",
        )
        ctx = ProjectContext()
        assert ctx.lookup(str(proj))["name"] == "pep621-wins"

    def test_package_json_when_no_pyproject(self, tmp_path):
        proj = tmp_path / "x"
        proj.mkdir()
        _write_package_json(proj, "node-name")
        ctx = ProjectContext()
        assert ctx.lookup(str(proj))["name"] == "node-name"

    def test_pyproject_beats_package_json(self, tmp_path):
        proj = tmp_path / "x"
        proj.mkdir()
        _write_pyproject_pep621(proj, "py-wins")
        _write_package_json(proj, "node-loses")
        ctx = ProjectContext()
        assert ctx.lookup(str(proj))["name"] == "py-wins"

    def test_basename_fallback_when_only_git(self, tmp_path):
        proj = tmp_path / "fallback-name"
        proj.mkdir()
        _make_git_dir(proj)
        ctx = ProjectContext()
        meta = ctx.lookup(str(proj))
        assert meta is not None
        assert meta["name"] == "fallback-name"

    def test_pyproject_parse_failure_falls_back(self, tmp_path):
        """A pyproject without a [project] name section should fall through
        to the next resolver (here: package.json or basename)."""
        proj = tmp_path / "noisy"
        proj.mkdir()
        (proj / "pyproject.toml").write_text(
            "[build-system]\nrequires = []\n",
            encoding="utf-8",
        )
        _write_package_json(proj, "from-package-json")
        ctx = ProjectContext()
        assert ctx.lookup(str(proj))["name"] == "from-package-json"

    def test_corrupt_package_json_falls_through_to_basename(self, tmp_path):
        proj = tmp_path / "weird"
        proj.mkdir()
        (proj / "package.json").write_text("not json {{{", encoding="utf-8")
        ctx = ProjectContext()
        meta = ctx.lookup(str(proj))
        assert meta["name"] == "weird"


# ─── git extraction ────────────────────────────────────────────────


class TestProjectContextGitExtraction:
    """git sub-dict resolution (ADR 0007 D3)."""

    def test_loose_ref_yields_branch_and_short_sha(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _make_git_dir(
            proj, head_ref="main",
            head_sha="abcdef1234567890abcdef1234567890abcdef12",
            remote_url=None,
        )
        ctx = ProjectContext()
        meta = ctx.lookup(str(proj))
        assert meta["git"]["branch"] == "main"
        assert meta["git"]["head"] == "abcdef12"
        assert meta["git"]["remote"] is None

    def test_detached_head_branch_is_none_head_set(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _make_git_dir(
            proj,
            detached_sha="ffeeddccbbaa9988776655443322110099887766",
        )
        ctx = ProjectContext()
        meta = ctx.lookup(str(proj))
        assert meta["git"]["branch"] is None
        assert meta["git"]["head"] == "ffeeddcc"

    def test_packed_refs_fallback(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _make_git_dir(
            proj, head_ref="release",
            head_sha="0123456789abcdef0123456789abcdef01234567",
            packed_refs=True,
        )
        ctx = ProjectContext()
        meta = ctx.lookup(str(proj))
        assert meta["git"]["branch"] == "release"
        assert meta["git"]["head"] == "01234567"

    def test_remote_https_normalized(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _make_git_dir(
            proj, remote_url="https://github.com/owner/repo.git",
        )
        ctx = ProjectContext()
        assert ctx.lookup(str(proj))["git"]["remote"] == "owner/repo"

    def test_remote_https_with_token(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _make_git_dir(
            proj,
            remote_url="https://x-access-token:TOKEN@github.com/owner/repo.git",
        )
        assert (
            ProjectContext().lookup(str(proj))["git"]["remote"] == "owner/repo"
        )

    def test_remote_ssh_normalized(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _make_git_dir(
            proj, remote_url="git@github.com:owner/repo.git",
        )
        ctx = ProjectContext()
        assert ctx.lookup(str(proj))["git"]["remote"] == "owner/repo"

    def test_remote_non_github_yields_null(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _make_git_dir(
            proj, remote_url="https://gitlab.com/owner/repo.git",
        )
        assert ProjectContext().lookup(str(proj))["git"]["remote"] is None

    def test_corrupt_head_branch_and_head_null_remote_still_read(
        self, tmp_path
    ):
        """ADR 0007 D3: a read failure on one git sub-field must not null
        the entire git object — partial metadata is more useful than none.
        """
        proj = tmp_path / "p"
        proj.mkdir()
        git = proj / ".git"
        git.mkdir()
        # Corrupt HEAD — neither a ref nor a SHA.
        (git / "HEAD").write_text("\x00\x01garbage", encoding="utf-8")
        # Valid config.
        (git / "config").write_text(
            '[remote "origin"]\n\turl = git@github.com:foo/bar.git\n',
            encoding="utf-8",
        )
        meta = ProjectContext().lookup(str(proj))
        assert meta["git"] is not None
        assert meta["git"]["branch"] is None
        assert meta["git"]["head"] is None
        assert meta["git"]["remote"] == "foo/bar"

    def test_branch_hint_overrides_cached_branch(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _make_git_dir(
            proj, head_ref="main",
            head_sha="11111111aaaaaaaa22222222bbbbbbbb33333333",
        )
        ctx = ProjectContext()
        # First call — caches branch=main.
        meta1 = ctx.lookup(str(proj))
        assert meta1["git"]["branch"] == "main"
        # Second call with hint — overrides branch but keeps head.
        meta2 = ctx.lookup(str(proj), branch_hint="feature/x")
        assert meta2["git"]["branch"] == "feature/x"
        assert meta2["git"]["head"] == "11111111"
        # Cached entry should NOT have been mutated (deep copy guarantee).
        meta3 = ctx.lookup(str(proj))
        assert meta3["git"]["branch"] == "main"

    def test_branch_hint_synthesizes_git_when_none(self, tmp_path):
        """No .git/ — but the JSONL knew the branch. ProjectContext should
        upgrade `git: null` to a sub-dict carrying the hint."""
        proj = tmp_path / "p"
        proj.mkdir()
        _write_pyproject_pep621(proj, "demo")
        ctx = ProjectContext()
        meta = ctx.lookup(str(proj), branch_hint="from-jsonl")
        assert meta["git"] is not None
        assert meta["git"]["branch"] == "from-jsonl"
        assert meta["git"]["head"] is None
        assert meta["git"]["remote"] is None


# ─── _normalize_github_url unit ─────────────────────────────────────


class TestNormalizeGithubURL:
    @pytest.mark.parametrize("url,expected", [
        ("https://github.com/foo/bar", "foo/bar"),
        ("https://github.com/foo/bar.git", "foo/bar"),
        ("https://github.com/foo/bar/", "foo/bar"),
        ("https://x@github.com/foo/bar.git", "foo/bar"),
        ("git@github.com:foo/bar.git", "foo/bar"),
        ("git@github.com:foo/bar", "foo/bar"),
        ("ssh://git@github.com/foo/bar.git", "foo/bar"),
        ("https://gitlab.com/foo/bar.git", None),
        ("https://bitbucket.org/foo/bar.git", None),
        ("git@gitlab.com:foo/bar.git", None),
        ("/local/path", None),
        ("", None),
    ])
    def test_normalization(self, url, expected):
        assert _normalize_github_url(url) == expected


# ─── caching ───────────────────────────────────────────────────────


class TestProjectContextCaching:
    """Bounded LRU + TTL semantics (ADR 0007 D4)."""

    def test_second_lookup_is_cached(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _write_pyproject_pep621(proj, "cached")

        ctx = ProjectContext()
        first = ctx.lookup(str(proj))
        # Patch the resolver — if cache hits, this should NOT be called.
        with patch.object(
            ProjectContext, "_resolve",
            return_value={"name": "WRONG", "root": "/", "git": None},
        ) as mocked:
            second = ctx.lookup(str(proj))
            assert mocked.call_count == 0
        assert second["name"] == first["name"] == "cached"

    def test_ttl_expiry_triggers_relookup(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _write_pyproject_pep621(proj, "cached")

        ctx = ProjectContext(ttl_seconds=1)
        ctx.lookup(str(proj))

        # Fast-forward via mocking time.monotonic.
        import time as _time
        future = _time.monotonic() + 5.0
        with patch("sentinel_mac.collectors.project_context.time.monotonic",
                   return_value=future):
            with patch.object(
                ProjectContext, "_resolve",
                return_value={"name": "FRESH", "root": "/x", "git": None},
            ) as mocked:
                meta = ctx.lookup(str(proj))
                assert mocked.call_count == 1
        assert meta["name"] == "FRESH"

    def test_max_entries_lru_eviction(self, tmp_path):
        ctx = ProjectContext(max_entries=2)
        # Build 3 distinct projects.
        for i in range(3):
            proj = tmp_path / f"proj{i}"
            proj.mkdir()
            _write_pyproject_pep621(proj, f"proj{i}")
        ctx.lookup(str(tmp_path / "proj0"))
        ctx.lookup(str(tmp_path / "proj1"))
        ctx.lookup(str(tmp_path / "proj2"))
        # Oldest (proj0) should have been evicted.
        with ctx._lock:
            keys = list(ctx._cache.keys())
        assert len(keys) == 2
        assert all("proj0" not in k for k in keys)

    def test_invalidate_specific_cwd(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _write_pyproject_pep621(proj, "x")
        ctx = ProjectContext()
        ctx.lookup(str(proj))
        ctx.invalidate(str(proj))
        with ctx._lock:
            assert str(proj.resolve()) not in ctx._cache

    def test_invalidate_all_clears_cache(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _write_pyproject_pep621(proj, "x")
        ctx = ProjectContext()
        ctx.lookup(str(proj))
        ctx.invalidate()
        with ctx._lock:
            assert len(ctx._cache) == 0

    def test_concurrent_lookup_thread_safe(self, tmp_path):
        proj = tmp_path / "p"
        proj.mkdir()
        _write_pyproject_pep621(proj, "concurrent")

        ctx = ProjectContext()
        results: list[Optional[dict]] = []
        errors: list[BaseException] = []

        def worker():
            try:
                for _ in range(50):
                    results.append(ctx.lookup(str(proj)))
            except BaseException as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert all(r is not None and r["name"] == "concurrent" for r in results)


# ─── from_config ───────────────────────────────────────────────────


class TestProjectContextFromConfig:
    """Config-driven construction (ADR 0007 D4)."""

    def test_empty_config_defaults(self):
        ctx = ProjectContext.from_config({})
        assert ctx._ttl_seconds == 300
        assert ctx._max_entries == 100
        assert ctx._max_walk_depth == 10

    def test_missing_section_defaults(self):
        ctx = ProjectContext.from_config({"security": {}})
        assert ctx._ttl_seconds == 300

    def test_overrides_applied(self):
        ctx = ProjectContext.from_config({
            "security": {
                "project_context": {
                    "ttl_seconds": 60,
                    "max_entries": 25,
                    "max_walk_depth": 4,
                }
            }
        })
        assert ctx._ttl_seconds == 60
        assert ctx._max_entries == 25
        assert ctx._max_walk_depth == 4

    def test_invalid_values_fall_back_to_defaults(self):
        ctx = ProjectContext.from_config({
            "security": {
                "project_context": {
                    "ttl_seconds": "bogus",
                    "max_entries": -5,
                }
            }
        })
        assert ctx._ttl_seconds == 300
        assert ctx._max_entries == 100

    def test_constructor_validates_args(self):
        with pytest.raises(ValueError):
            ProjectContext(ttl_seconds=0)
        with pytest.raises(ValueError):
            ProjectContext(max_entries=0)
        with pytest.raises(ValueError):
            ProjectContext(max_walk_depth=0)
