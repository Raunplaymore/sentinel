"""Sentinel — Host Context & Trust (v0.6, frozen interface).

Provides per-host trust signals to other collectors so they can downgrade
alert severity for hosts the user has historically interacted with.

Two signals are aggregated:
1. Explicit user trust: matching entries in ``~/.ssh/known_hosts``.
2. Observed frequency: hosts seen >= ``auto_trust_after_seen`` times in
   the learning window.

Plus an explicit negative override (``BLOCKED``) loaded from config.

Disabled by default. A ``HostContext`` constructed with ``enabled=False``
returns ``TrustLevel.UNKNOWN`` for every query and never touches disk.

Out of scope (v0.6):
- ASN / GeoIP / WHOIS / VirusTotal lookups (external data dependencies).
- ``/etc/hosts`` parsing (low signal value).
- Public Suffix List / eTLD+1 normalization (requires external dep).
- WebFetch URL host classification (site diversity too high — see ADR 0001 D4).
- Mutation API for blocklist (config-only in v0.6).

Frozen by ADR 0001. Signature changes require a superseding ADR.

v0.6: API only. CLI subcommands (``sentinel context forget|block|list``)
deferred to v0.7. See ``docs/decisions/0001-host-context.md``.
"""

from __future__ import annotations

import enum
import fnmatch
import ipaddress
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

logger = logging.getLogger(__name__)

# Persistence schema version. Bump on incompatible format changes.
_SCHEMA_VERSION = 1

# How many consecutive JSON parse failures (after _meta) trigger
# corruption handling.
_CORRUPTION_LINE_THRESHOLD = 3


class TrustLevel(str, enum.Enum):
    """Trust classification for a remote host.

    String-valued so the level round-trips cleanly through JSON/YAML
    (``TrustLevel.KNOWN.value == "known"``).

    Ordering by ``rank()``: ``UNKNOWN(0) < LEARNED(1) < KNOWN(2) < BLOCKED(3)``.
    Note that ``BLOCKED`` having the highest rank reflects "strongest
    override", not "most trusted" — callers MUST NOT compare with ``<``/``>``
    directly. Use ``TrustLevel.rank(level)`` and explicit branches.

    AlertEngine downgrade policy (v0.6):
        UNKNOWN → no change (default behavior preserved)
        LEARNED → downgrade severity by 1 step (warning → info, etc.)
        KNOWN   → downgrade severity by 1 step
        BLOCKED → no downgrade (alert preserved at original severity)
    """
    UNKNOWN = "unknown"
    LEARNED = "learned"
    KNOWN = "known"
    BLOCKED = "blocked"

    @classmethod
    def rank(cls, level: "TrustLevel") -> int:
        """Numeric rank for comparison. UNKNOWN=0, LEARNED=1, KNOWN=2, BLOCKED=3."""
        return _TRUST_RANK[level]


_TRUST_RANK: dict[TrustLevel, int] = {
    TrustLevel.UNKNOWN: 0,
    TrustLevel.LEARNED: 1,
    TrustLevel.KNOWN: 2,
    TrustLevel.BLOCKED: 3,
}


@dataclass(frozen=True)
class HostObservation:
    """One row of the persisted frequency counter.

    Attributes:
        host: Lowercased hostname as observed. No eTLD+1 normalization
            in v0.6 — see module docstring.
        count: Number of distinct observation windows in which the host
            was seen (deduplicated within ``dedup_window_seconds``).
        first_seen: Unix epoch seconds of the first observation that
            counted (post-dedup).
        last_seen: Unix epoch seconds of the most recent counted observation.
    """
    host: str
    count: int
    first_seen: int
    last_seen: int


class HostContext:
    """Aggregates trust signals for remote hosts.

    Thread-safety:
        Instance methods are safe for one writer + multiple readers within
        a single process. A single ``threading.Lock`` guards the in-memory
        counter and the disk cache file. Multiple ``HostContext`` instances
        pointing at the same cache file from different processes are NOT
        supported in v0.6 — Sentinel runs as a single daemon.

    Lifecycle:
        ctx = HostContext.from_config(config)
        ctx.load()                          # idempotent; once at startup.
        level = ctx.classify("api.x.io")    # hot path; O(1) avg.
        ctx.observe("api.x.io")             # hot path; O(1) avg, async flush.
        ctx.flush()                         # periodic + at shutdown.

    Disabled mode:
        When constructed with ``enabled=False``, every query returns
        ``TrustLevel.UNKNOWN`` and ``observe()`` is a no-op. ``load()`` /
        ``flush()`` perform no disk I/O.
    """

    DEFAULT_KNOWN_HOSTS_PATH: Path = Path("~/.ssh/known_hosts").expanduser()

    def __init__(
        self,
        *,
        enabled: bool,
        cache_path: Path,
        known_hosts_path: Optional[Path] = None,
        auto_trust_after_seen: int = 5,
        learning_window_days: int = 30,
        dedup_window_seconds: int = 3600,
        max_tracked_hosts: int = 5000,
        blocklist: Optional[Iterable[str]] = None,
    ) -> None:
        """Construct a HostContext.

        All policy values arrive as kwargs so ``from_config`` can centralize
        defaults. A disabled context is a cheap no-op.

        Args:
            enabled: Master switch. False → all queries return UNKNOWN, no
                disk I/O.
            cache_path: Where to persist the frequency counter (JSONL).
            known_hosts_path: OpenSSH known_hosts file. ``None`` or
                non-existent file disables that signal (frequency-only).
            auto_trust_after_seen: Promote to LEARNED after this many
                observations within the learning window. Must be >= 2.
            learning_window_days: Sliding window for frequency counting.
                Observations older than this are pruned at next ``load()``.
                Must be >= 1.
            dedup_window_seconds: Repeated observations of the same host
                within this many seconds count as one.
            max_tracked_hosts: Hard cap on tracked hosts. Excess entries
                are dropped LRU-style on flush.
            blocklist: Iterable of hostnames or fnmatch wildcards (e.g.,
                ``["evil.com", "*.suspicious.tld"]``). Matching hosts
                always classify as BLOCKED, taking precedence over
                known_hosts and frequency.

        Raises:
            ValueError: if ``auto_trust_after_seen < 2``,
                ``learning_window_days < 1``, ``dedup_window_seconds < 0``,
                or ``max_tracked_hosts < 1``.
        """
        if auto_trust_after_seen < 2:
            raise ValueError(
                f"auto_trust_after_seen must be >= 2, got {auto_trust_after_seen}"
            )
        if learning_window_days < 1:
            raise ValueError(
                f"learning_window_days must be >= 1, got {learning_window_days}"
            )
        if dedup_window_seconds < 0:
            raise ValueError(
                f"dedup_window_seconds must be >= 0, got {dedup_window_seconds}"
            )
        if max_tracked_hosts < 1:
            raise ValueError(
                f"max_tracked_hosts must be >= 1, got {max_tracked_hosts}"
            )

        self._enabled: bool = bool(enabled)
        self._cache_path: Path = Path(cache_path)
        self._known_hosts_path: Optional[Path] = (
            Path(known_hosts_path) if known_hosts_path is not None else None
        )
        self._auto_trust_after_seen: int = auto_trust_after_seen
        self._learning_window_days: int = learning_window_days
        self._dedup_window_seconds: int = dedup_window_seconds
        self._max_tracked_hosts: int = max_tracked_hosts

        # Split blocklist into literal set + wildcard list for fast lookup.
        literal, wildcard = _split_blocklist(blocklist or [])
        self._blocklist_literal: set[str] = literal
        self._blocklist_wildcard: list[str] = wildcard

        # known_hosts populated by load().
        self._known_hosts_literal: set[str] = set()
        self._known_hosts_wildcard: list[str] = []

        # Frequency counter; insertion order matters for LRU eviction
        # (oldest last_seen at the front after sorting on flush, but we
        # use a dict and rely on explicit min() for eviction so insertion
        # order is not relied upon for correctness).
        self._observations: dict[str, HostObservation] = {}
        self._dirty: bool = False
        self._loaded: bool = False

        self._lock: threading.Lock = threading.Lock()

    @classmethod
    def from_config(cls, config: dict) -> "HostContext":
        """Build a HostContext from the parsed sentinel config dict.

        Reads ``config["security"]["context_aware"]``. If the section is
        missing or ``enabled`` is false, returns a disabled instance.
        Never raises on missing keys — defaults cover all fields.

        ``cache_path: ""`` resolves to ``$XDG_DATA_HOME/sentinel/host_context.jsonl``
        (or ``~/.local/share/sentinel/host_context.jsonl``).

        Args:
            config: Parsed YAML config (the same dict ``Sentinel`` uses).

        Returns:
            A configured ``HostContext`` (possibly disabled).
        """
        section = (config or {}).get("security", {}).get("context_aware", {}) or {}

        enabled = bool(section.get("enabled", False))
        auto_trust_after_seen = int(section.get("auto_trust_after_seen", 5))
        learning_window_days = int(section.get("learning_window_days", 30))
        dedup_window_seconds = int(section.get("dedup_window_seconds", 3600))
        max_tracked_hosts = int(section.get("max_tracked_hosts", 5000))

        known_hosts_raw = section.get("known_hosts_path", "~/.ssh/known_hosts")
        known_hosts_path: Optional[Path]
        if known_hosts_raw == "" or known_hosts_raw is None:
            known_hosts_path = None
        else:
            known_hosts_path = Path(str(known_hosts_raw)).expanduser()

        cache_raw = section.get("cache_path", "")
        if cache_raw == "" or cache_raw is None:
            cache_path = _resolve_default_cache_path()
        else:
            cache_path = Path(str(cache_raw)).expanduser()

        blocklist = section.get("blocklist", []) or []

        return cls(
            enabled=enabled,
            cache_path=cache_path,
            known_hosts_path=known_hosts_path,
            auto_trust_after_seen=auto_trust_after_seen,
            learning_window_days=learning_window_days,
            dedup_window_seconds=dedup_window_seconds,
            max_tracked_hosts=max_tracked_hosts,
            blocklist=blocklist,
        )

    # ── lifecycle ────────────────────────────────────────────────

    def load(self) -> None:
        """Load known_hosts and the persisted frequency counter into memory.

        Idempotent. On corrupted cache, logs a warning, renames the bad
        file to ``host_context.jsonl.corrupted-<epoch>`` (evidence
        preservation, no auto-delete), and resets the counter to empty.

        No-op if disabled.
        """
        if not self._enabled:
            return

        with self._lock:
            self._load_known_hosts_locked()
            self._load_cache_locked()
            self._loaded = True

    def flush(self) -> None:
        """Persist the in-memory counter to disk atomically.

        Writes to ``<cache_path>.tmp`` then ``os.replace`` to the final
        path — partial writes never corrupt the cache. Cheap if nothing
        changed since the last flush (dirty flag).

        Safe to call from a signal handler. No-op if disabled.
        """
        if not self._enabled:
            return

        with self._lock:
            if not self._dirty:
                return

            cache_path = self._cache_path
            tmp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")

            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            except OSError as exc:
                logger.warning(
                    "HostContext: cannot create cache parent dir %s: %s",
                    cache_path.parent,
                    exc,
                )
                return

            meta = {
                "_meta": {
                    "schema": _SCHEMA_VERSION,
                    "written_at": int(time.time()),
                }
            }

            try:
                with open(tmp_path, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(meta, ensure_ascii=False) + "\n")
                    for obs in self._observations.values():
                        row = {
                            "host": obs.host,
                            "count": obs.count,
                            "first_seen": obs.first_seen,
                            "last_seen": obs.last_seen,
                        }
                        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                # Tighten permissions before replace so the visible file is
                # never world-readable.
                try:
                    os.chmod(tmp_path, 0o600)
                except OSError:
                    pass
                os.replace(tmp_path, cache_path)
                self._dirty = False
            except OSError as exc:
                logger.warning(
                    "HostContext: cache flush failed (%s): %s", cache_path, exc
                )
                # Best-effort cleanup of stale tmp.
                try:
                    if tmp_path.exists():
                        tmp_path.unlink()
                except OSError:
                    pass

    # ── query ────────────────────────────────────────────────────

    def classify(self, host: str) -> TrustLevel:
        """Return the trust level for ``host``.

        Lookup order:
            1. blocklist match → BLOCKED (short-circuit)
            2. known_hosts match → KNOWN
            3. frequency counter >= auto_trust_after_seen → LEARNED
            4. otherwise → UNKNOWN

        Hostname is lowercased and stripped before lookup. IP literals
        (v4 / v6) bypass stages 2-3 and return UNKNOWN unless they match
        blocklist (which supports literal IPs).

        Returns ``TrustLevel.UNKNOWN`` if disabled, ``host`` is empty, or
        no signal matches.
        """
        if not self._enabled:
            return TrustLevel.UNKNOWN

        normalized = _normalize_host(host)
        if not normalized:
            return TrustLevel.UNKNOWN

        is_ip = _is_ip_literal(normalized)

        # IP literals bypass known_hosts/frequency, but blocklist still applies.
        if is_ip:
            if self._matches_blocklist(normalized):
                return TrustLevel.BLOCKED
            return TrustLevel.UNKNOWN

        # 1. Blocklist takes precedence over everything.
        if self._matches_blocklist(normalized):
            return TrustLevel.BLOCKED

        # 2. known_hosts match.
        if self._matches_known_hosts(normalized):
            return TrustLevel.KNOWN

        # 3. Frequency-based LEARNED.
        with self._lock:
            obs = self._observations.get(normalized)
        if obs is not None and obs.count >= self._auto_trust_after_seen:
            return TrustLevel.LEARNED

        return TrustLevel.UNKNOWN

    def is_in_known_hosts(self, host: str) -> bool:
        """True iff ``host`` matches a literal or wildcard entry in known_hosts.

        Supported OpenSSH syntax:
            - Plain hostname / IP literal
            - Comma-joined patterns (``host1,host2,*.alt``)
            - Wildcards (``*.example.com``)

        NOT supported in v0.6:
            - Hashed entries (``|1|salt|hash``) — would require salted SHA1
              per query, too expensive on the hot path. ``load()`` logs a
              single info message reporting the count of hashed entries
              skipped.

        Returns False if disabled or known_hosts file is absent / empty.
        """
        if not self._enabled:
            return False

        normalized = _normalize_host(host)
        if not normalized:
            return False

        return self._matches_known_hosts(normalized)

    def seen_count(self, host: str) -> int:
        """How many times ``host`` has been counted within the learning window.

        Useful for tests, ``--diagnose``, and the future
        ``sentinel context status`` CLI (v0.7). Returns 0 if disabled or
        unseen.
        """
        if not self._enabled:
            return 0

        normalized = _normalize_host(host)
        if not normalized:
            return 0

        with self._lock:
            obs = self._observations.get(normalized)
        return obs.count if obs is not None else 0

    # ── mutation ─────────────────────────────────────────────────

    def observe(self, host: str, *, now_epoch: Optional[int] = None) -> None:
        """Record an observation of ``host``.

        Deduplicated within ``dedup_window_seconds``: rapid repeats for the
        same host inside that window count as one. Prevents a single
        polling burst (net_tracker polls every 30s) from inflating the
        counter and triggering auto-trust faster than the user's intent.

        IP literals are NOT counted (UNKNOWN-only by design).

        Args:
            host: Hostname (lowercased and stripped internally).
            now_epoch: Override current time for tests; defaults to
                ``time.time()``.
        """
        if not self._enabled:
            return

        normalized = _normalize_host(host)
        if not normalized:
            return

        if _is_ip_literal(normalized):
            return

        ts = int(now_epoch if now_epoch is not None else time.time())

        with self._lock:
            existing = self._observations.get(normalized)

            if existing is not None:
                # Dedup: ignore observations within the dedup window —
                # do not bump count or last_seen so dedup remains exact.
                if ts - existing.last_seen < self._dedup_window_seconds:
                    return

                self._observations[normalized] = HostObservation(
                    host=normalized,
                    count=existing.count + 1,
                    first_seen=existing.first_seen,
                    last_seen=ts,
                )
            else:
                self._observations[normalized] = HostObservation(
                    host=normalized,
                    count=1,
                    first_seen=ts,
                    last_seen=ts,
                )

            self._dirty = True

            # LRU evict immediately if over cap. Keep the loop in case the
            # cap was lowered between calls.
            while len(self._observations) > self._max_tracked_hosts:
                victim = min(
                    self._observations.values(),
                    key=lambda o: o.last_seen,
                )
                # Don't evict the entry we just touched.
                if victim.host == normalized:
                    # Find the second-oldest. With max>=1 this is safe
                    # because we only get here when len > max >= 1, so
                    # at least 2 entries exist.
                    candidates = [
                        o for o in self._observations.values()
                        if o.host != normalized
                    ]
                    if not candidates:
                        break
                    victim = min(candidates, key=lambda o: o.last_seen)
                del self._observations[victim.host]

    def forget(self, host: str) -> bool:
        """Remove ``host`` from the frequency counter.

        Used by future ``sentinel context forget HOST`` CLI (v0.7) and by
        tests. Does not affect known_hosts (read-only) or blocklist
        (config-only in v0.6).

        Args:
            host: Hostname to remove.

        Returns:
            True if the host was present and removed, False otherwise.
        """
        if not self._enabled:
            return False

        normalized = _normalize_host(host)
        if not normalized:
            return False

        with self._lock:
            if normalized in self._observations:
                del self._observations[normalized]
                self._dirty = True
                return True
        return False

    def iter_observations(self) -> Iterable[HostObservation]:
        """Yield all tracked observations.

        Order is unspecified in v0.6 (caller must sort). Yields nothing
        if disabled.

        Used by tests and the future ``sentinel context list`` CLI (v0.7).
        """
        if not self._enabled:
            return iter(())

        with self._lock:
            # Snapshot so callers can iterate without holding the lock.
            snapshot = list(self._observations.values())
        return iter(snapshot)

    # ── internal helpers ─────────────────────────────────────────

    def _matches_blocklist(self, host: str) -> bool:
        """True iff ``host`` matches the configured blocklist."""
        if host in self._blocklist_literal:
            return True
        for pattern in self._blocklist_wildcard:
            if fnmatch.fnmatchcase(host, pattern):
                return True
        return False

    def _matches_known_hosts(self, host: str) -> bool:
        """True iff ``host`` matches any loaded known_hosts entry."""
        if host in self._known_hosts_literal:
            return True
        for pattern in self._known_hosts_wildcard:
            if fnmatch.fnmatchcase(host, pattern):
                return True
        return False

    def _load_known_hosts_locked(self) -> None:
        """Parse known_hosts into literal/wildcard sets. Caller holds lock."""
        self._known_hosts_literal = set()
        self._known_hosts_wildcard = []

        path = self._known_hosts_path
        if path is None:
            return

        try:
            if not path.exists():
                return
        except OSError as exc:
            logger.warning("HostContext: cannot stat known_hosts %s: %s", path, exc)
            return

        hashed_count = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for raw_line in fh:
                    parsed = _parse_known_hosts_line(raw_line)
                    if parsed is None:
                        continue
                    is_hashed, patterns = parsed
                    if is_hashed:
                        hashed_count += 1
                        continue
                    for pat in patterns:
                        if "*" in pat or "?" in pat:
                            self._known_hosts_wildcard.append(pat)
                        else:
                            self._known_hosts_literal.add(pat)
        except OSError as exc:
            logger.warning(
                "HostContext: cannot read known_hosts %s: %s", path, exc
            )
            return

        if hashed_count > 0:
            logger.info(
                "HostContext: skipped %d hashed known_hosts entries "
                "(unsupported in v0.6)",
                hashed_count,
            )

    def _load_cache_locked(self) -> None:
        """Load and validate the persisted counter. Caller holds lock."""
        self._observations = {}
        self._dirty = False

        path = self._cache_path
        try:
            if not path.exists():
                return
        except OSError as exc:
            logger.warning("HostContext: cannot stat cache %s: %s", path, exc)
            return

        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.warning("HostContext: cannot read cache %s: %s", path, exc)
            return

        # Empty file is treated as corruption — flush always writes _meta.
        if not lines:
            self._mark_corrupted_locked(path, reason="empty cache file")
            return

        # First line must be a recognized _meta block.
        try:
            meta_obj = json.loads(lines[0])
        except json.JSONDecodeError:
            self._mark_corrupted_locked(path, reason="meta line is not JSON")
            return

        meta = (meta_obj or {}).get("_meta") if isinstance(meta_obj, dict) else None
        if not isinstance(meta, dict):
            self._mark_corrupted_locked(path, reason="missing _meta header")
            return

        schema = meta.get("schema")
        if schema != _SCHEMA_VERSION:
            self._mark_corrupted_locked(
                path,
                reason=f"unknown schema version {schema!r}",
            )
            return

        # Parse observations. Stop early if too many bad lines accumulate
        # (signal of corruption rather than one transient bad row).
        cutoff = int(time.time()) - self._learning_window_days * 86400
        bad_lines = 0
        loaded: dict[str, HostObservation] = {}

        for raw in lines[1:]:
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError:
                bad_lines += 1
                if bad_lines >= _CORRUPTION_LINE_THRESHOLD:
                    self._mark_corrupted_locked(
                        path,
                        reason=f"{bad_lines} consecutive unreadable lines",
                    )
                    return
                continue

            if not isinstance(row, dict):
                bad_lines += 1
                if bad_lines >= _CORRUPTION_LINE_THRESHOLD:
                    self._mark_corrupted_locked(
                        path,
                        reason=f"{bad_lines} non-object rows",
                    )
                    return
                continue

            try:
                host = str(row["host"]).strip().lower()
                count = int(row["count"])
                first_seen = int(row["first_seen"])
                last_seen = int(row["last_seen"])
            except (KeyError, TypeError, ValueError):
                bad_lines += 1
                if bad_lines >= _CORRUPTION_LINE_THRESHOLD:
                    self._mark_corrupted_locked(
                        path,
                        reason=f"{bad_lines} malformed rows",
                    )
                    return
                continue

            if not host:
                continue

            # Prune entries past the learning window on load.
            if last_seen < cutoff:
                continue

            loaded[host] = HostObservation(
                host=host,
                count=count,
                first_seen=first_seen,
                last_seen=last_seen,
            )

        self._observations = loaded
        self._dirty = False

    def _mark_corrupted_locked(self, path: Path, *, reason: str) -> None:
        """Quarantine a corrupt cache file and reset state. Caller holds lock."""
        quarantine = path.with_suffix(path.suffix + f".corrupted-{int(time.time())}")
        try:
            os.replace(path, quarantine)
            logger.warning(
                "HostContext: cache %s appears corrupted (%s); moved to %s",
                path,
                reason,
                quarantine,
            )
        except OSError as exc:
            logger.warning(
                "HostContext: cache %s appears corrupted (%s) and could not "
                "be quarantined: %s",
                path,
                reason,
                exc,
            )
        self._observations = {}
        self._dirty = False


# ── module-level helpers (private) ───────────────────────────────


def _normalize_host(host: str) -> str:
    """Lowercase + strip a hostname; empty/None → ''."""
    if not host:
        return ""
    return host.strip().lower()


def _is_ip_literal(host: str) -> bool:
    """True iff ``host`` parses as an IPv4 or IPv6 literal."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _split_blocklist(items: Iterable[str]) -> tuple[set[str], list[str]]:
    """Partition blocklist into literal set and wildcard list."""
    literal: set[str] = set()
    wildcard: list[str] = []
    for raw in items:
        if raw is None:
            continue
        norm = str(raw).strip().lower()
        if not norm:
            continue
        if "*" in norm or "?" in norm:
            wildcard.append(norm)
        else:
            literal.add(norm)
    return literal, wildcard


def _parse_known_hosts_line(raw_line: str) -> Optional[tuple[bool, list[str]]]:
    """Parse one known_hosts line.

    Returns ``(is_hashed, patterns)`` or ``None`` for blank/comment lines.
    Hashed entries (``|1|salt|hash``) report ``is_hashed=True`` with an
    empty pattern list. Patterns are lowercased and stripped of optional
    OpenSSH ``[host]:port`` brackets and leading ``@cert-authority`` /
    ``@revoked`` markers.
    """
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split()
    # OpenSSH may prefix with @cert-authority or @revoked.
    if parts and parts[0].startswith("@"):
        parts = parts[1:]

    if len(parts) < 2:
        return None

    host_field = parts[0]

    # Hashed entries start with "|1|" (one per line).
    if host_field.startswith("|1|"):
        return True, []

    patterns: list[str] = []
    for piece in host_field.split(","):
        piece = piece.strip().lower()
        if not piece:
            continue
        # Strip negation marker (we treat "!host" as a no-op pattern in v0.6).
        if piece.startswith("!"):
            continue
        # Strip [host]:port brackets — only the hostname is matched.
        if piece.startswith("[") and "]" in piece:
            inner = piece[1:].split("]", 1)[0]
            piece = inner
        patterns.append(piece)

    if not patterns:
        return None
    return False, patterns


def _resolve_default_cache_path() -> Path:
    """Return ``$XDG_DATA_HOME/sentinel/host_context.jsonl`` (or fallback)."""
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        base = Path(xdg)
    else:
        base = Path("~/.local/share").expanduser()
    return base / "sentinel" / "host_context.jsonl"
