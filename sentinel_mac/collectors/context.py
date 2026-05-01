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
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


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
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")

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
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")

    # ── lifecycle ────────────────────────────────────────────────

    def load(self) -> None:
        """Load known_hosts and the persisted frequency counter into memory.

        Idempotent. On corrupted cache, logs a warning, renames the bad
        file to ``host_context.jsonl.corrupted-<epoch>`` (evidence
        preservation, no auto-delete), and resets the counter to empty.

        No-op if disabled.
        """
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")

    def flush(self) -> None:
        """Persist the in-memory counter to disk atomically.

        Writes to ``<cache_path>.tmp`` then ``os.replace`` to the final
        path — partial writes never corrupt the cache. Cheap if nothing
        changed since the last flush (dirty flag).

        Safe to call from a signal handler. No-op if disabled.
        """
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")

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
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")

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
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")

    def seen_count(self, host: str) -> int:
        """How many times ``host`` has been counted within the learning window.

        Useful for tests, ``--diagnose``, and the future
        ``sentinel context status`` CLI (v0.7). Returns 0 if disabled or
        unseen.
        """
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")

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
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")

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
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")

    def iter_observations(self) -> Iterable[HostObservation]:
        """Yield all tracked observations.

        Order is unspecified in v0.6 (caller must sort). Yields nothing
        if disabled.

        Used by tests and the future ``sentinel context list`` CLI (v0.7).
        """
        raise NotImplementedError("Frozen interface — implement in v0.6 PR")
