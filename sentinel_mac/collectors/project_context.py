"""Sentinel — Project Context (ADR 0007 D3 + D4, frozen interface).

Resolves a working directory (``cwd``) to a structured ``project_meta``
dict that carries the forensic context other collectors attach to
SecurityEvent.detail (ADR 0007 §D3):

    {
        "name":   <project name string>,
        "root":   <absolute path to project root>,
        "git": {                                 # or None (not a git repo)
            "branch": <str | None>,
            "head":   <short SHA | None>,
            "remote": <"owner/repo" | None>,    # GitHub-shaped only
        }
    }

Caching:
    Bounded LRU + TTL (default: 100 entries, 5 minutes). The cache is a
    pure optimization; ADR 0005 D2 explicitly excludes ProjectContext
    from SIGHUP reload — TTL picks up filesystem changes lazily.

Out of scope (v0.8):
    - ``git`` binary calls (we read ``.git/HEAD`` / ``.git/refs/...`` /
      ``.git/packed-refs`` / ``.git/config`` directly).
    - ``include`` / ``url.X.insteadOf`` directives in ``.git/config``.
    - Non-GitHub remote URL normalization (gitlab/bitbucket/etc. → None).
    - Trigger-based invalidation on ``.git/HEAD`` mtime advance (v0.9+).

Frozen by ADR 0007 §D3+D4. Adding new sub-fields to ``project_meta`` is
fine without superseding ADR (additive); changing the boundary detection
precedence or repurposing a sub-field requires a superseding ADR.
"""

from __future__ import annotations

import copy
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Maximum directory levels to walk upward when searching for a project
# boundary. ADR 0007 §D3 ("If no marker is found within 10 parents (cap),
# project_meta is null.").
_DEFAULT_MAX_WALK_DEPTH = 10

# Markers that delineate a project root (ADR 0007 §D3 — first-match-wins
# walking upward from cwd).
_PROJECT_MARKERS: tuple[str, ...] = (".git", "pyproject.toml", "package.json")

# Regex helpers — pyproject.toml [project] / [tool.poetry] name extraction
# without a TOML parser dependency (we only need the ``name`` value).
# Conservative: only matches single/double-quoted string literals on the
# first matching line of a section. Multi-line strings or unusual TOML
# constructs fall through to the next resolver.
_TOML_SECTION_RE = re.compile(r"^\[(.+?)\]\s*$")
_TOML_NAME_RE = re.compile(
    r"""^\s*name\s*=\s*(?:"([^"]+)"|'([^']+)')\s*(?:#.*)?$"""
)

# package.json name field — also avoid bringing in a JSON parser dep
# error path. We use stdlib json safely but defensively (any failure
# returns None and the next resolver is consulted).

# .git/HEAD line — either ``ref: refs/heads/<branch>`` or a raw 40-hex SHA.
_GIT_HEAD_REF_RE = re.compile(r"^ref:\s*refs/heads/(.+?)\s*$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}\s*$", re.IGNORECASE)

# .git/config — section + url-line parsing (ConfigParser is unsuitable
# for git's non-standard ``[remote "origin"]`` headers).
_GIT_CONFIG_SECTION_RE = re.compile(
    r"""^\[\s*([A-Za-z0-9._-]+)(?:\s+"([^"]*)")?\s*\]\s*$"""
)
_GIT_CONFIG_URL_RE = re.compile(r"""^\s*url\s*=\s*(.+?)\s*$""")

# GitHub URL normalization patterns. Any non-GitHub-shaped URL → None
# per ADR 0007 §D3 ("Non-GitHub-shaped URLs → null in v0.8").
_GITHUB_HTTPS_RE = re.compile(
    r"^https?://(?:[^@/]+@)?github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$"
)
_GITHUB_SSH_RE = re.compile(
    r"^(?:ssh://)?git@github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$"
)


class ProjectContext:
    """cwd → project_meta resolver with bounded LRU + TTL.

    Thread-safe: a single ``threading.RLock`` guards the cache. Multiple
    readers + writers within one process are supported; cross-process
    sharing is not (Sentinel runs as a single daemon).

    Lifecycle (mirrors HostContext / ADR 0001 D2 pattern):
        ctx = ProjectContext.from_config(config)
        meta = ctx.lookup(cwd)              # hot path; O(1) avg post-cache.
        ctx.invalidate(cwd)                 # rare; defined for tests + v0.9+.

    Disabled mode:
        There is no ``enabled`` flag (ADR 0007 §D4 — always-on, free at
        point of use, cached, no PII risk). Collectors that should not
        emit ``project_meta`` simply skip injection at the call site.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = 300,
        max_entries: int = 100,
        max_walk_depth: int = _DEFAULT_MAX_WALK_DEPTH,
    ) -> None:
        """Construct a ProjectContext.

        Args:
            ttl_seconds: Cache entry lifetime. Stale entries are dropped
                lazily on next access (no proactive sweep). Must be >= 1.
            max_entries: Hard cap on cached entries. Excess entries are
                evicted LRU-style (oldest insertion first). Must be >= 1.
            max_walk_depth: Maximum number of parent directories to scan
                when searching for a project boundary. Cap protects
                pathological cases (cwd deep under ``/tmp`` etc.).
                Must be >= 1.

        Raises:
            ValueError: if any constructor argument is < 1.
        """
        if ttl_seconds < 1:
            raise ValueError(f"ttl_seconds must be >= 1, got {ttl_seconds}")
        if max_entries < 1:
            raise ValueError(f"max_entries must be >= 1, got {max_entries}")
        if max_walk_depth < 1:
            raise ValueError(f"max_walk_depth must be >= 1, got {max_walk_depth}")

        self._ttl_seconds: int = ttl_seconds
        self._max_entries: int = max_entries
        self._max_walk_depth: int = max_walk_depth

        # OrderedDict so we can move-to-end on hit and pop oldest on
        # evict in O(1). Value: (cached_meta_dict_or_none, inserted_epoch).
        self._cache: "OrderedDict[str, tuple[Optional[dict], float]]" = OrderedDict()
        self._lock: threading.RLock = threading.RLock()

    @classmethod
    def from_config(cls, config: dict) -> "ProjectContext":
        """Build a ProjectContext from the parsed sentinel config dict.

        Reads ``config["security"]["project_context"]``. All sub-keys are
        optional; defaults match production targets (5-min TTL, 100 entries).
        Never raises on missing keys.

        Args:
            config: Parsed YAML config (the same dict ``Sentinel`` uses).

        Returns:
            A configured ``ProjectContext``. There is no disabled mode —
            ADR 0007 §D4 specifies always-on caching.
        """
        section = (config or {}).get("security", {}).get("project_context", {}) or {}

        # Defensive int() coercion; bad values fall back to defaults rather
        # than crash the daemon. This mirrors HostContext.from_config.
        try:
            ttl_seconds = int(section.get("ttl_seconds", 300))
        except (TypeError, ValueError):
            ttl_seconds = 300
        try:
            max_entries = int(section.get("max_entries", 100))
        except (TypeError, ValueError):
            max_entries = 100
        try:
            max_walk_depth = int(section.get("max_walk_depth", _DEFAULT_MAX_WALK_DEPTH))
        except (TypeError, ValueError):
            max_walk_depth = _DEFAULT_MAX_WALK_DEPTH

        # Clamp to safe minimums — config typos shouldn't break the daemon.
        if ttl_seconds < 1:
            ttl_seconds = 300
        if max_entries < 1:
            max_entries = 100
        if max_walk_depth < 1:
            max_walk_depth = _DEFAULT_MAX_WALK_DEPTH

        return cls(
            ttl_seconds=ttl_seconds,
            max_entries=max_entries,
            max_walk_depth=max_walk_depth,
        )

    # ── query ────────────────────────────────────────────────────

    def lookup(
        self,
        cwd: Optional[str],
        *,
        branch_hint: Optional[str] = None,
    ) -> Optional[dict]:
        """Resolve ``cwd`` to a frozen ``project_meta`` dict (or None).

        ADR 0007 §D3 schema. Returns None when:
            - ``cwd`` is None or empty.
            - No project boundary found within ``max_walk_depth`` parents.
            - The cwd path doesn't exist or can't be stat'd at root level.

        ``branch_hint`` (when provided — e.g., the JSONL ``gitBranch`` field
        from agent_log_parser) overrides ``project_meta["git"]["branch"]``
        on the returned dict. The cache stores the un-hinted result; the
        hint is applied to a deep copy on every call. This keeps the cache
        size from exploding while still letting per-message branch hints
        always win over the (potentially stale) ``.git/HEAD`` reading.

        Thread-safe.
        """
        if not cwd:
            return None

        # Normalize the cache key — use realpath so symlinked working dirs
        # resolve to a single cache entry.
        try:
            normalized = os.path.realpath(os.path.expanduser(cwd))
        except (OSError, ValueError):
            return self._apply_branch_hint(None, branch_hint)

        if not normalized:
            return self._apply_branch_hint(None, branch_hint)

        now = time.monotonic()

        with self._lock:
            cached = self._cache.get(normalized)
            if cached is not None:
                meta, inserted_at = cached
                if now - inserted_at <= self._ttl_seconds:
                    # LRU bump on hit.
                    self._cache.move_to_end(normalized)
                    return self._apply_branch_hint(meta, branch_hint)
                # Stale — drop and fall through to re-resolve.
                self._cache.pop(normalized, None)

        # Cache miss (or expired) — resolve outside the lock to avoid
        # holding the lock across filesystem reads. We accept the rare
        # double-resolve race; whichever caller stores last wins (the
        # results are identical anyway when there's no concurrent fs change).
        resolved = self._resolve(normalized)

        with self._lock:
            self._cache[normalized] = (resolved, now)
            self._cache.move_to_end(normalized)
            # LRU eviction.
            while len(self._cache) > self._max_entries:
                self._cache.popitem(last=False)

        return self._apply_branch_hint(resolved, branch_hint)

    def invalidate(self, cwd: Optional[str] = None) -> None:
        """Drop one cache entry (when ``cwd`` given) or the whole cache.

        v0.8: not called from production code paths — defined for tests
        and for a future v0.9+ trigger that watches ``.git/HEAD`` mtime
        for branch-switch invalidation. The 5-min TTL is the only
        production invalidation path today.

        Thread-safe.
        """
        with self._lock:
            if cwd is None:
                self._cache.clear()
                return
            try:
                normalized = os.path.realpath(os.path.expanduser(cwd))
            except (OSError, ValueError):
                return
            self._cache.pop(normalized, None)

    # ── internal helpers ─────────────────────────────────────────

    @staticmethod
    def _apply_branch_hint(
        meta: Optional[dict], branch_hint: Optional[str]
    ) -> Optional[dict]:
        """Return a deep copy of ``meta`` with ``git.branch`` overridden.

        - ``meta`` is None → return None (no synthesized project).
        - ``branch_hint`` is None/empty → return a deep copy untouched
          (the cached dict must never escape the cache for callers to
          mutate; ADR 0007 §D2/D3 frozen schemas).
        - ``meta`` has ``git == None`` and a non-empty hint → upgrade
          ``git`` to a full sub-dict with ``branch=hint`` and ``head=None``,
          ``remote=None``. This handles the "no .git/ dir but JSONL knew
          the branch from a parent repo" edge case.
        """
        if meta is None:
            return None
        result = copy.deepcopy(meta)
        if branch_hint:
            git = result.get("git")
            if isinstance(git, dict):
                git["branch"] = branch_hint
            else:
                # No .git/ resolved but we have a hint — synthesize the
                # sub-dict so consumers see a uniform shape.
                result["git"] = {
                    "branch": branch_hint,
                    "head": None,
                    "remote": None,
                }
        return result

    def _resolve(self, normalized_cwd: str) -> Optional[dict]:
        """Walk up from ``normalized_cwd`` and build the project_meta dict.

        Caller passes a realpath-normalized absolute path. Returns None
        when no project boundary is found within ``max_walk_depth``.
        """
        try:
            start = Path(normalized_cwd)
            if not start.exists():
                return None
        except OSError:
            return None

        root = self._find_project_root(start)
        if root is None:
            return None

        name = self._resolve_name(root)
        git = self._resolve_git(root)

        return {
            "name": name,
            "root": str(root),
            "git": git,
        }

    def _find_project_root(self, start: Path) -> Optional[Path]:
        """Walk up from ``start``, returning the first directory containing
        any of ``_PROJECT_MARKERS``. Returns None if none found within
        ``max_walk_depth`` parents.
        """
        current = start
        for _ in range(self._max_walk_depth + 1):
            try:
                for marker in _PROJECT_MARKERS:
                    candidate = current / marker
                    try:
                        if candidate.exists():
                            return current
                    except OSError:
                        continue
            except OSError:
                return None
            parent = current.parent
            if parent == current:
                return None
            current = parent
        return None

    def _resolve_name(self, root: Path) -> str:
        """Resolve project name in priority order (ADR 0007 §D3):
            1. pyproject.toml [project].name (PEP 621)
            2. pyproject.toml [tool.poetry].name (Poetry)
            3. package.json "name"
            4. basename(root) — last-resort
        """
        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            name = self._extract_pyproject_name(pyproject)
            if name:
                return name

        package_json = root / "package.json"
        if package_json.exists():
            name = self._extract_package_json_name(package_json)
            if name:
                return name

        return root.name or str(root)

    @staticmethod
    def _extract_pyproject_name(path: Path) -> Optional[str]:
        """Extract ``name`` from ``[project]`` then ``[tool.poetry]``
        sections of a pyproject.toml. Regex-only — avoids the tomllib
        dependency (Python 3.11+) so 3.8/3.9/3.10 don't need a polyfill.

        Returns None on read failure or when neither section has a
        recognizable string ``name = "..."`` line.
        """
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None

        project_name: Optional[str] = None
        poetry_name: Optional[str] = None
        current_section: Optional[str] = None

        for raw in text.splitlines():
            line = raw.rstrip()
            section_m = _TOML_SECTION_RE.match(line.strip())
            if section_m:
                current_section = section_m.group(1).strip()
                continue
            if current_section in ("project", "tool.poetry"):
                name_m = _TOML_NAME_RE.match(line)
                if name_m:
                    value = name_m.group(1) or name_m.group(2)
                    if current_section == "project" and project_name is None:
                        project_name = value
                    elif current_section == "tool.poetry" and poetry_name is None:
                        poetry_name = value

        # PEP 621 wins over Poetry per ADR 0007 §D3 priority list.
        return project_name or poetry_name

    @staticmethod
    def _extract_package_json_name(path: Path) -> Optional[str]:
        """Extract ``name`` from a package.json file.

        Uses the stdlib ``json`` module defensively — any parse failure or
        non-string ``name`` field returns None.
        """
        import json
        try:
            with open(path, "r", encoding="utf-8") as fh:
                obj = json.load(fh)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(obj, dict):
            return None
        name = obj.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        return None

    def _resolve_git(self, root: Path) -> Optional[dict]:
        """Resolve the ``git`` sub-dict for ``root`` (ADR 0007 §D3).

        Walks up from ``root`` once to find the nearest ``.git/`` (since
        the project root may be a sub-project nested in a monorepo, the
        git directory can sit at an outer parent — D3: "we walk up
        separately for .git/ after the project root is decided").

        Returns None when no ``.git/`` dir is found anywhere up to the
        filesystem root. Otherwise returns a dict with branch/head/remote
        sub-fields, each independently null on partial read failure.
        """
        git_root = self._find_git_root(root)
        if git_root is None:
            return None
        git_dir = git_root / ".git"

        branch, head = self._read_git_head(git_dir)
        remote = self._read_git_remote(git_dir)

        return {
            "branch": branch,
            "head": head,
            "remote": remote,
        }

    @staticmethod
    def _find_git_root(start: Path) -> Optional[Path]:
        """Walk up from ``start`` looking for a directory that contains
        ``.git/``. Returns the parent dir (the git work-tree root) or None.

        No depth cap — git roots can sit far above the project root in
        deeply-nested workspaces, and the walk terminates at the
        filesystem root anyway.
        """
        current = start
        # Hard upper bound on filesystem walk to avoid pathological cases
        # (corrupted symlinks etc.). 64 ancestors is far above any real
        # checkout depth.
        for _ in range(64):
            try:
                if (current / ".git").exists():
                    return current
            except OSError:
                return None
            parent = current.parent
            if parent == current:
                return None
            current = parent
        return None

    @staticmethod
    def _read_git_head(git_dir: Path) -> tuple[Optional[str], Optional[str]]:
        """Return ``(branch, head_short_sha)`` from ``.git/HEAD``.

        - ``ref: refs/heads/<x>`` → branch=<x>, head=first 8 chars of SHA
          read from ``.git/refs/heads/<x>`` (or ``.git/packed-refs``
          fallback when the ref is not loose).
        - Raw 40-hex SHA → branch=None (detached HEAD), head=first 8 chars.
        - Read failure → both None. Per ADR 0007 §D3, partial git read
          failures must not null the entire git object; the ``remote``
          field is read separately.
        """
        head_path = git_dir / "HEAD"
        try:
            content = head_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            return None, None

        if not content:
            return None, None

        ref_m = _GIT_HEAD_REF_RE.match(content)
        if ref_m:
            branch = ref_m.group(1).strip()
            head_sha = ProjectContext._read_ref_sha(git_dir, branch)
            short = head_sha[:8] if head_sha else None
            return branch, short

        if _GIT_SHA_RE.match(content):
            return None, content[:8].lower()

        return None, None

    @staticmethod
    def _read_ref_sha(git_dir: Path, branch: str) -> Optional[str]:
        """Resolve ``refs/heads/<branch>`` to a full SHA.

        Tries the loose ref file first (``.git/refs/heads/<branch>``),
        then falls back to ``.git/packed-refs``. Returns None if neither
        path yields a 40-hex SHA.
        """
        # Loose ref.
        loose = git_dir / "refs" / "heads" / branch
        try:
            if loose.exists():
                value = loose.read_text(encoding="utf-8").strip()
                if _GIT_SHA_RE.match(value):
                    return value.lower()
        except (OSError, UnicodeDecodeError):
            pass

        # packed-refs fallback.
        packed = git_dir / "packed-refs"
        try:
            if not packed.exists():
                return None
            target = f"refs/heads/{branch}"
            with open(packed, "r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#") or line.startswith("^"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    sha, ref = parts[0].strip(), parts[1].strip()
                    if ref == target and _GIT_SHA_RE.match(sha):
                        return sha.lower()
        except (OSError, UnicodeDecodeError):
            return None

        return None

    @staticmethod
    def _read_git_remote(git_dir: Path) -> Optional[str]:
        """Parse ``.git/config`` and return the GitHub-shaped ``owner/repo``
        for ``[remote "origin"]`` (preferred) or the first ``[remote "*"]``
        section. Returns None when no GitHub-shaped URL is found.

        Per ADR 0007 §D3:
            - Non-GitHub URLs → None.
            - ``include`` directives and ``url.X.insteadOf`` rewrites are
              intentionally NOT followed.
        """
        config_path = git_dir / "config"
        try:
            text = config_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

        # Two-pass: first collect URL strings keyed by remote name, then
        # apply the precedence rule (origin first, otherwise the first
        # remote encountered).
        remote_urls: "OrderedDict[str, str]" = OrderedDict()
        current_remote: Optional[str] = None

        for raw in text.splitlines():
            line = raw.split("#", 1)[0].split(";", 1)[0].rstrip()
            stripped = line.strip()
            if not stripped:
                continue

            section_m = _GIT_CONFIG_SECTION_RE.match(stripped)
            if section_m:
                kind = section_m.group(1).strip().lower()
                subname = section_m.group(2)
                if kind == "remote" and subname:
                    current_remote = subname
                else:
                    current_remote = None
                continue

            if current_remote is None:
                continue
            url_m = _GIT_CONFIG_URL_RE.match(line)
            if url_m and current_remote not in remote_urls:
                remote_urls[current_remote] = url_m.group(1).strip()

        # Precedence: origin first, then first inserted.
        chosen_url: Optional[str] = remote_urls.get("origin")
        if chosen_url is None and remote_urls:
            chosen_url = next(iter(remote_urls.values()))

        if not chosen_url:
            return None
        return _normalize_github_url(chosen_url)


# ── module-level helpers (private) ───────────────────────────────


def _normalize_github_url(url: str) -> Optional[str]:
    """Reduce a remote URL to ``owner/repo`` when it is GitHub-shaped.

    Recognized inputs:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        https://x-access-token:TOKEN@github.com/owner/repo.git
        git@github.com:owner/repo.git
        ssh://git@github.com/owner/repo.git

    Returns None for any other shape (gitlab, bitbucket, gitea, custom
    enterprise hosts, local paths, etc.) — ADR 0007 §D3 v0.8 boundary.
    """
    if not url:
        return None
    candidate = url.strip()
    if not candidate:
        return None

    https_m = _GITHUB_HTTPS_RE.match(candidate)
    if https_m:
        owner, repo = https_m.group(1), https_m.group(2)
        return f"{owner}/{repo}"

    ssh_m = _GITHUB_SSH_RE.match(candidate)
    if ssh_m:
        owner, repo = ssh_m.group(1), ssh_m.group(2)
        return f"{owner}/{repo}"

    return None
