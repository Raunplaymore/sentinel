"""``sentinel context`` CLI subcommand — host trust inspection / mutation.

Implements ADR 0003 (frozen v0.7 surface) with ADR 0006 fallback:

    sentinel context status [HOST]    # read-only snapshot or single-host detail
    sentinel context forget HOST      # remove from frequency counter
    sentinel context block HOST       # add to config blocklist
    sentinel context unblock HOST     # remove from config blocklist

Universal flags: ``--json``, ``--config PATH``.

Exit codes (ADR 0003 §D6, with ADR 0006 §D4 amendment):
    0 — success
    1 — host not found (e.g., ``forget`` on unknown host, ``unblock`` on
        host not present)
    2 — validation error (bad host syntax)
    3 — config mutation failed (file unwritable, parse error, etc.).
        ADR 0006 §D4 supersedes ADR 0003 §D6 for the ruamel-missing
        case: missing ruamel triggers automatic PyYAML fallback and
        returns exit 0 if the write succeeds.
    4 — cache file read error (corrupted, unreadable)

JSON envelope shape (ADR 0004 §D2):

    {"version": 1, "kind": "...", "generated_at": "<ISO Z>",
     "data": { ... }}

Two ``kind`` values are emitted by this module:

* ``host_context_status``      — ``status`` (snapshot or single-host)
* ``host_context_mutation``    — ``forget`` / ``block`` / ``unblock`` result

Design notes:

* No third-party CLI lib (ADR 0003 §D7) — stdlib ``argparse`` only.
* All four verbs work whether the daemon is running or not (ADR §D3) and
  whether ``security.context_aware.enabled`` is true or not (ADR §D4).
* ``block`` / ``unblock`` mutate ``config.yaml`` in place. The preferred
  loader is ``ruamel.yaml`` (from the ``[app]`` extra) which preserves
  user comments and key order. When ruamel is not installed, the CLI
  falls back automatically to PyYAML (already a hard dependency) per
  ADR 0006 §D1: a single-line stderr warning is emitted, a backup file
  ``config.yaml.bak.<unix_epoch_seconds>`` is written next to the
  original, and the mutation proceeds. Comments are lost on the
  PyYAML path; key order survives via ``sort_keys=False``.
* ``forget`` mutates the runtime cache directly; no config edit.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from sentinel_mac.collectors.context import (
    HostContext,
    TrustLevel,
)
from sentinel_mac.collectors.context import (
    _parse_known_hosts_line as _parse_known_hosts_line,
)
from sentinel_mac.core import (
    daemon_lock_path,
    load_config,
    resolve_config_path,
)

# ── envelope / IO helpers ──────────────────────────────────────────


def _resolve_config(arg_config: Optional[Path]) -> Optional[Path]:
    """Wrap ``core.resolve_config_path`` so we can pass ``Optional[Path]``.

    ``core.resolve_config_path`` was written before strict typing landed
    (its ``explicit_path: str = None`` signature lives under mypy
    ``ignore_errors``). We bridge here so ``commands.*`` stays type-clean.
    """
    if arg_config is None:
        return resolve_config_path()
    return resolve_config_path(str(arg_config))


def _load_config(config_path: Optional[Path]) -> dict:
    """Wrap ``core.load_config`` so callers can pass ``Optional[Path]``.

    ``core.load_config(None)`` already returns the default dict — same
    shim rationale as ``_resolve_config``.
    """
    if config_path is None:
        return load_config()
    return load_config(config_path)


def _emit_json_envelope(*, kind: str, data: dict) -> None:
    """Print an ADR 0004 §D2 versioned envelope to stdout.

    Mirrors ``core._emit_json_envelope`` but lives here so the commands
    package has zero coupling to ``core`` beyond the resolver helpers.
    """
    envelope = {
        "version": 1,
        "kind": kind,
        "generated_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "data": data,
    }
    print(json.dumps(envelope, ensure_ascii=False))


def _err(msg: str) -> None:
    """Print one line to stderr (no trailing newline doubling)."""
    print(msg, file=sys.stderr)


# ── host validation ────────────────────────────────────────────────


def _validate_host(raw: Optional[str]) -> str:
    """Return a normalized host or raise ValueError.

    Normalization: ``strip().lower()``. Accepted shapes:
      * plain hostnames (``example.com``)
      * fnmatch wildcards (``*.evil.tld``, ``foo?.bar``)
      * IPv4/IPv6 literals (``1.2.3.4``, ``::1``)

    Rejected:
      * ``None`` / empty / whitespace-only
      * embedded whitespace (``"foo bar"``)

    The blocklist already passes through ``fnmatch.fnmatchcase`` so we
    intentionally keep the validator permissive — the goal is to catch
    obvious mistakes (typed an extra space, hit Enter on an empty arg),
    not to enforce DNS RFC 1035 strictly.
    """
    if raw is None:
        raise ValueError("host is required")
    norm = raw.strip().lower()
    if not norm:
        raise ValueError("host must not be empty")
    if any(ch.isspace() for ch in norm):
        raise ValueError(f"host must not contain whitespace: {raw!r}")
    return norm


# ── daemon detection ───────────────────────────────────────────────


def _read_daemon_pid() -> Optional[int]:
    """Return the PID recorded in ``sentinel.lock`` if a live daemon owns it.

    Reads the lock file (written by ``try_acquire_daemon_lock`` in
    ``core``), parses the PID, and confirms the process is still alive
    via ``os.kill(pid, 0)``. Returns ``None`` when:

    * the lock file does not exist (no daemon ever started, or it was
      cleared between sessions);
    * the file exists but is empty / unparseable (typically a half-written
      state we should not act on);
    * the recorded PID no longer matches a running process (stale lock).

    Side-effect-free — uses signal 0, which performs the permission
    check without delivering anything. Permission errors on the probe
    are treated as "process exists but not ours" (the daemon ran under
    another user / namespace) and the PID is returned so the caller
    can surface ``failed_unreachable`` accurately.
    """
    lock_path = daemon_lock_path()
    if not lock_path.exists():
        return None
    try:
        raw = lock_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw:
        return None
    try:
        pid = int(raw.split()[0])
    except (ValueError, IndexError):
        return None
    if pid <= 0:
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        # Stale lock — daemon crashed without releasing it.
        return None
    except PermissionError:
        # Process exists but we cannot signal it. Surface the PID so
        # callers can decide (signal_daemon_reload reports "failed_unreachable").
        return pid
    except OSError:
        return None
    return pid


def _is_daemon_running() -> bool:
    """Best-effort check whether the Sentinel daemon currently holds the lock.

    Implemented on top of ``_read_daemon_pid`` so the CLI has a single
    PID-derivation path: if a live PID owns the lock, the daemon is
    running. Falls back to the historical ``flock``-based probe only
    when the PID-based path returns ``None`` *and* the lock file still
    exists, in case a future writer ever skips the PID payload.

    Returns False on any unexpected OSError (best-effort — a stale lock
    file with permission issues should not block CLI mutations).
    """
    pid = _read_daemon_pid()
    if pid is not None:
        return True

    lock_path = daemon_lock_path()
    if not lock_path.exists():
        return False
    try:
        fp = open(lock_path, "a+")
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # Someone (the daemon) holds the lock.
            return True
        except OSError:
            return False
        # We got the lock — nobody else has it. Release and report no daemon.
        try:
            fcntl.flock(fp, fcntl.LOCK_UN)
        except OSError:
            pass
        return False
    finally:
        try:
            fp.close()
        except OSError:
            pass


# ADR 0005 §D7 — frozen enum returned by ``_signal_daemon_reload``.
# Tests reference this constant verbatim to lock the surface.
DAEMON_RELOAD_RESULTS: frozenset[str] = frozenset(
    {"applied", "skipped_not_running", "failed_unreachable"}
)


def _signal_daemon_reload() -> tuple[str, Optional[int]]:
    """ADR 0005 §D7 — signal the running daemon to reload its config.

    Returns ``(status, pid)`` where ``status`` is one of the three
    frozen values:

    * ``"applied"`` — ``os.kill(pid, SIGHUP)`` succeeded; the daemon's
      reload worker will pick the change up sub-second per ADR 0005 §D5.
    * ``"failed_unreachable"`` — a live PID is recorded but signalling
      failed (``ProcessLookupError`` after the read raced with daemon
      exit, or ``PermissionError`` from a cross-user setup).
    * ``"skipped_not_running"`` — no live daemon to signal. The lock
      file is missing or stale; nothing to do.

    Side-effect-free when the daemon is not running. Never raises —
    callers can use the return value directly in the ADR 0004 §D2
    envelope without try/except plumbing.
    """
    pid = _read_daemon_pid()
    if pid is None:
        return "skipped_not_running", None
    try:
        os.kill(pid, signal.SIGHUP)
    except ProcessLookupError:
        # Daemon exited between _read_daemon_pid's probe and our SIGHUP.
        return "failed_unreachable", pid
    except PermissionError:
        return "failed_unreachable", pid
    except OSError:
        return "failed_unreachable", pid
    return "applied", pid


def _daemon_reload_notice(status: str, pid: Optional[int]) -> Optional[str]:
    """Render the human-facing stderr line for a daemon-reload outcome.

    ADR 0005 §D7 message contract:
      * "applied"             → "Applied to running daemon (PID {pid})."
      * "failed_unreachable"  → "Daemon not reachable; restart manually
                                 with `sentinel restart`."
      * "skipped_not_running" → None (no message — the absence of a
                                 daemon is the normal CLI-only path).
    """
    if status == "applied":
        return f"Applied to running daemon (PID {pid})."
    if status == "failed_unreachable":
        return (
            "Daemon not reachable; restart manually with `sentinel restart`."
        )
    return None


def _disabled_notice() -> str:
    """Info line printed when context_aware is currently disabled."""
    return (
        "context_aware is currently disabled; this change takes effect "
        "when you set `security.context_aware.enabled: true`."
    )


# ── config helpers ─────────────────────────────────────────────────


def _is_context_enabled(config: dict) -> bool:
    """True iff ``security.context_aware.enabled`` is truthy in the config."""
    section = (config or {}).get("security", {}).get("context_aware", {}) or {}
    return bool(section.get("enabled", False))


def _config_blocklist(config: dict) -> list:
    """Return the blocklist from config (raw list, may include wildcards)."""
    section = (config or {}).get("security", {}).get("context_aware", {}) or {}
    raw = section.get("blocklist", []) or []
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if item]


def _known_hosts_path_from_config(config: dict) -> Optional[Path]:
    """Resolve the configured known_hosts path (or None when explicitly off)."""
    section = (config or {}).get("security", {}).get("context_aware", {}) or {}
    raw = section.get("known_hosts_path", "~/.ssh/known_hosts")
    if raw == "" or raw is None:
        return None
    return Path(str(raw)).expanduser()


def _read_known_hosts_sample(
    path: Optional[Path], *, sample_size: int = 8
) -> tuple[int, list]:
    """Read known_hosts and return (total_count, sample).

    Counts unique non-hashed pattern entries. Sample preserves insertion
    order, deduped, capped to ``sample_size`` for the snapshot view.
    Failures degrade silently to ``(0, [])`` — this is a read-only
    advisory display, never a fatal error.
    """
    if path is None:
        return 0, []
    try:
        if not path.exists():
            return 0, []
    except OSError:
        return 0, []

    seen: set = set()
    sample: list = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                parsed = _parse_known_hosts_line(raw_line)
                if parsed is None:
                    continue
                is_hashed, patterns = parsed
                if is_hashed:
                    continue
                for pat in patterns:
                    if pat in seen:
                        continue
                    seen.add(pat)
                    if len(sample) < sample_size:
                        sample.append(pat)
    except OSError:
        return 0, []
    return len(seen), sample


# ── status (read-only) ─────────────────────────────────────────────


def cmd_status(args: argparse.Namespace) -> int:
    """Show host context snapshot or single-host detail.

    ADR 0003 §D4: works regardless of ``context_aware.enabled``. ADR §D3:
    no daemon required.
    """
    config_path = _resolve_config(args.config)
    config = _load_config(config_path)
    enabled = _is_context_enabled(config)

    ctx = HostContext.from_config(config)
    # load() is a cheap no-op when disabled. When enabled, it may quarantine
    # a corrupt cache and reset to empty — that is a non-fatal recovery
    # path inside HostContext, not a CLI exit-4 condition.
    try:
        ctx.load()
    except OSError as exc:
        _err(f"Error: failed to read host_context cache: {exc}")
        return 4

    cache_path = _resolve_cache_path_for_display(config)

    if args.host is not None:
        return _status_single_host(
            args.host,
            ctx=ctx,
            config=config,
            config_path=config_path,
            cache_path=cache_path,
            enabled=enabled,
            as_json=bool(args.json),
        )

    return _status_snapshot(
        ctx=ctx,
        config=config,
        config_path=config_path,
        cache_path=cache_path,
        enabled=enabled,
        as_json=bool(args.json),
    )


def _resolve_cache_path_for_display(config: dict) -> Path:
    """Return the cache path that ``HostContext.from_config`` would use."""
    section = (config or {}).get("security", {}).get("context_aware", {}) or {}
    raw = section.get("cache_path", "")
    if raw == "" or raw is None:
        # Mirror context._resolve_default_cache_path without re-importing
        # the private symbol — same XDG fallback rule.
        from sentinel_mac.collectors.context import (
            _resolve_default_cache_path,
        )
        return _resolve_default_cache_path()
    return Path(str(raw)).expanduser()


def _status_snapshot(
    *,
    ctx: HostContext,
    config: dict,
    config_path: Optional[Path],
    cache_path: Path,
    enabled: bool,
    as_json: bool,
) -> int:
    blocklist = _config_blocklist(config)
    known_hosts_path = _known_hosts_path_from_config(config)
    kh_count, kh_sample = _read_known_hosts_sample(known_hosts_path)

    # iter_observations is a no-op when disabled, so this naturally
    # yields [] in that case — no extra branch needed.
    observations = sorted(
        ctx.iter_observations(),
        key=lambda o: (-o.count, o.host),
    )

    frequency_payload: list = []
    for obs in observations:
        # Re-classify each observed host so callers see the live trust
        # decision (e.g., a learned host that was later added to the
        # blocklist surfaces as "blocked", not "learned").
        trust = ctx.classify(obs.host)
        frequency_payload.append(
            {
                "host": obs.host,
                "count": obs.count,
                "first_seen": obs.first_seen,
                "last_seen": obs.last_seen,
                "trust": trust.value,
            }
        )

    if as_json:
        _emit_json_envelope(
            kind="host_context_status",
            data={
                "enabled": enabled,
                "config_path": str(config_path) if config_path else None,
                "cache_path": str(cache_path),
                "frequency": frequency_payload,
                "blocklist": blocklist,
                "known_hosts": {"count": kh_count, "sample": kh_sample},
            },
        )
        return 0

    # ── text output ──
    print("Sentinel — Host Context Status")
    print("=" * 50)
    print(f"  enabled:     {enabled}")
    print(f"  config:      {config_path or '(defaults — no config file)'}")
    print(f"  cache:       {cache_path}")
    print("")

    print("Frequency-learned hosts:")
    if not frequency_payload:
        if enabled:
            print("  (none yet — no observations recorded)")
        else:
            print("  (context_aware is disabled — no observations)")
    else:
        for row in frequency_payload:
            host_label = str(row["host"])
            count_val = row["count"]
            count_int = int(count_val) if isinstance(count_val, int) else 0
            trust_label = str(row["trust"])
            print(
                f"  {host_label:<40s}  count={count_int:<5d} trust={trust_label}"
            )
    print("")

    print("Blocklist (config):")
    if not blocklist:
        print("  (empty)")
    else:
        for entry in blocklist:
            print(f"  {entry}")
    print("")

    print(f"known_hosts: {kh_count} entries")
    for entry in kh_sample:
        print(f"  {entry}")
    if kh_count > len(kh_sample):
        print(f"  ... and {kh_count - len(kh_sample)} more")
    if not enabled:
        print("")
        print(_disabled_notice())
    return 0


def _status_single_host(
    host: str,
    *,
    ctx: HostContext,
    config: dict,
    config_path: Optional[Path],
    cache_path: Path,
    enabled: bool,
    as_json: bool,
) -> int:
    # Single-host status is read-only and forgiving of weird input — even
    # an empty/whitespace host returns UNKNOWN rather than exit 2, because
    # the verb is "show me what you know".
    normalized = (host or "").strip().lower()
    trust = ctx.classify(normalized) if normalized else TrustLevel.UNKNOWN
    count = ctx.seen_count(normalized) if normalized else 0
    in_known_hosts = (
        ctx.is_in_known_hosts(normalized) if normalized else False
    )
    in_blocklist = normalized in {b.strip().lower() for b in _config_blocklist(config)}

    obs = None
    for o in ctx.iter_observations():
        if o.host == normalized:
            obs = o
            break

    first_seen = obs.first_seen if obs is not None else None
    last_seen = obs.last_seen if obs is not None else None

    if as_json:
        _emit_json_envelope(
            kind="host_context_host_detail",
            data={
                "host": normalized,
                "trust": trust.value,
                "count": count,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "in_known_hosts": in_known_hosts,
                "in_blocklist": in_blocklist,
                "enabled": enabled,
                "config_path": str(config_path) if config_path else None,
                "cache_path": str(cache_path),
            },
        )
        return 0

    print(f"Host: {normalized or '(empty)'}")
    print(f"  trust:           {trust.value}")
    print(f"  seen_count:      {count}")
    print(f"  first_seen:      {first_seen if first_seen is not None else '-'}")
    print(f"  last_seen:       {last_seen  if last_seen  is not None else '-'}")
    print(f"  in_known_hosts:  {in_known_hosts}")
    print(f"  in_blocklist:    {in_blocklist}")
    if not enabled:
        print("")
        print(_disabled_notice())
    return 0


# ── forget (mutates cache) ─────────────────────────────────────────


def cmd_forget(args: argparse.Namespace) -> int:
    """Remove ``HOST`` from the in-memory + on-disk frequency counter."""
    try:
        host = _validate_host(args.host)
    except ValueError as exc:
        _err(f"Error: {exc}")
        return 2

    config_path = _resolve_config(args.config)
    config = _load_config(config_path)
    enabled = _is_context_enabled(config)

    if not enabled:
        # ADR §D4 — still allowed; the user is preparing state for when
        # they enable the feature. We can't remove anything from a disabled
        # context (the cache is never loaded), but we should report that
        # cleanly rather than pretending we did something. ADR 0005 §D7
        # — no file write means no SIGHUP, but emit `daemon_reload` for
        # envelope-shape consistency across all forget paths.
        if args.json:
            _emit_json_envelope(
                kind="host_context_mutation",
                data={
                    "action": "forget",
                    "host": host,
                    "result": "not_found",
                    "daemon_reload": "skipped_not_running",
                    "enabled": False,
                },
            )
        else:
            print(f"Host '{host}' not found (context_aware is disabled).")
            print(_disabled_notice())
        return 1

    ctx = HostContext.from_config(config)
    try:
        ctx.load()
    except OSError as exc:
        _err(f"Error: failed to read host_context cache: {exc}")
        return 4

    removed = ctx.forget(host)
    if removed:
        ctx.flush()

    # ADR 0005 §D7 — only signal a reload when the cache actually changed.
    # `forget` on an unknown host is a no-op so there is nothing for the
    # daemon to pick up; skip the SIGHUP to keep the call truly idempotent.
    if removed:
        reload_status, reload_pid = _signal_daemon_reload()
    else:
        reload_status, reload_pid = "skipped_not_running", None

    daemon_running = _is_daemon_running()

    if args.json:
        _emit_json_envelope(
            kind="host_context_mutation",
            data={
                "action": "forget",
                "host": host,
                "result": "removed" if removed else "not_found",
                "daemon_running": daemon_running,
                "daemon_reload": reload_status,
                "enabled": True,
            },
        )
    else:
        if removed:
            print(f"Removed '{host}' from host context cache.")
        else:
            print(f"Host '{host}' not found in host context cache.")

    notice = _daemon_reload_notice(reload_status, reload_pid)
    if notice is not None:
        _err(notice)

    return 0 if removed else 1


# ── block / unblock (mutates config.yaml) ──────────────────────────


def _require_ruamel() -> Any:
    """Import ruamel.yaml or raise ImportError on miss.

    ADR 0006 §D1 — preferred YAML backend. The PyYAML fallback path
    (:func:`_resolve_yaml_backend`) catches the ``ImportError`` and
    proceeds without ruamel. This helper used to raise ``RuntimeError``
    with an install hint; that pre-ADR-0006 behaviour is preserved
    *only* when monkeypatched in the legacy exit-3 test (kept around as
    a safety net for any custom downstream wrapper that called the
    helper directly).
    """
    from ruamel.yaml import YAML  # noqa: F401 — surface ImportError if missing

    yaml_rt = YAML(typ="rt")
    yaml_rt.preserve_quotes = True
    return yaml_rt


def _resolve_yaml_backend() -> tuple[str, Optional[Any]]:
    """ADR 0006 §D1 — pick the YAML backend at mutation time.

    Returns ``(backend_name, ruamel_yaml_instance_or_None)``:

    * ``("ruamel", <YAML(typ="rt") instance>)`` when ruamel is importable.
    * ``("pyyaml", None)`` when ruamel is missing — the caller drives
      the PyYAML path via :func:`_save_config_with_pyyaml`.

    Lazy import: the resolution happens here (not at module load time)
    so monkeypatching ``_require_ruamel`` in tests still flips the
    backend deterministically.
    """
    try:
        return "ruamel", _require_ruamel()
    except ImportError:
        return "pyyaml", None
    except RuntimeError:
        # Legacy monkeypatch in tests/test_context_cli.py raised RuntimeError
        # to simulate a missing extra. ADR 0006 §D4 supersedes that test's
        # original intent (exit 3 → exit 0 via fallback); preserve the same
        # branch behaviour by treating it as a missing import.
        return "pyyaml", None


def _save_config_with_pyyaml(config_path: Path, data: dict) -> str:
    """ADR 0006 §D2 — backup-then-write fallback for the ruamel-less path.

    1. Copy ``config.yaml`` to ``config.yaml.bak.<unix_epoch_seconds>``
       via ``shutil.copy2`` (preserves mtime / permissions; not atomic
       at the FS level, but the original is untouched until the dump
       below succeeds).
    2. Dump the mutated mapping back over the original with
       ``yaml.safe_dump(..., sort_keys=False)`` — comments are lost,
       but key order is preserved per ADR 0006 §D2.
    3. Force both backup and rewritten config to ``0o600`` per ADR 0006
       §D5 (config files may carry webhook secrets).

    Returns the absolute path to the backup file so the caller can
    surface it in the stderr warning + JSON envelope.
    """
    epoch = int(time.time())
    backup_path = config_path.with_suffix(config_path.suffix + f".bak.{epoch}")
    shutil.copy2(config_path, backup_path)  # preserves mtime/perms (best-effort)
    try:
        os.chmod(backup_path, 0o600)  # ADR 0006 §D5 — secrets-grade perms
    except OSError:
        # Permission tightening is advisory; if the FS rejects it (rare),
        # the dump still proceeds — the warning already advises the user.
        pass

    with open(config_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(
            data, fh, default_flow_style=False, sort_keys=False
        )
    try:
        os.chmod(config_path, 0o600)
    except OSError:
        pass

    return str(backup_path)


def _emit_pyyaml_fallback_warning(backup_path: str) -> None:
    """ADR 0006 §D3 — single-line stderr warning when PyYAML path runs.

    Kept under ~120 chars so it does not wrap on a default terminal.
    Includes the absolute backup path so the user can recover from it
    without searching the config directory.
    """
    # ADR 0006 §D3 — keep the message short enough to avoid wrapping on
    # an 80-column terminal. We display the backup path with a leading "~"
    # when it lives under HOME (saves ~30 chars on macOS) and inline the
    # absolute path only when it does not.
    try:
        rel = Path(backup_path).relative_to(Path.home())
        shown = f"~/{rel}"
    except ValueError:
        shown = backup_path
    msg = (
        f"warning: ruamel.yaml missing → PyYAML fallback (comments lost). "
        f"Backup: {shown}. Fix: pip install sentinel-mac[app]."
    )
    print(msg, file=sys.stderr)


def _ensure_blocklist_path(data: Any) -> list:
    """Return the ``security.context_aware.blocklist`` list, creating parents.

    ``data`` is the round-tripped top-level YAML mapping. Missing parents
    (no ``security:``, no ``context_aware:``) get a fresh empty branch so
    ``block`` works on a config that pre-dates v0.6.
    """
    if data is None:
        # Treat empty file as empty mapping; YAML round-trip will dump
        # the new keys at the top level.
        raise RuntimeError(
            "config file is empty — run `sentinel --init-config` first "
            "or write a minimal config.yaml"
        )

    security = data.get("security")
    if security is None:
        data["security"] = {}
        security = data["security"]

    ctx_aware = security.get("context_aware")
    if ctx_aware is None:
        security["context_aware"] = {}
        ctx_aware = security["context_aware"]

    blocklist = ctx_aware.get("blocklist")
    if blocklist is None:
        ctx_aware["blocklist"] = []
        blocklist = ctx_aware["blocklist"]
    if not isinstance(blocklist, list):
        raise RuntimeError(
            "config.yaml: security.context_aware.blocklist is not a list"
        )
    return blocklist


def _mutate_blocklist(
    *, action: str, host: str, args: argparse.Namespace
) -> int:
    """Shared implementation for ``block`` (action='add') and ``unblock``
    (action='remove'). Returns the CLI exit code.

    ADR 0006 §D4 supersedes ADR 0003 §D6 for the ruamel-missing case:
    instead of returning exit 3, we automatically fall back to PyYAML
    and return exit 0 if the write succeeds. The envelope gains four
    additive fields per ADR 0006 §D3 (uniform shape across both
    backends): ``yaml_backend`` ∈ {``"ruamel"``, ``"pyyaml"``},
    ``backup_path`` (PyYAML only — ``null`` on the ruamel path),
    ``comment_preservation`` ∈ {``"preserved"``, ``"lost"``}.
    """
    config_path = _resolve_config(args.config)
    if config_path is None or not Path(config_path).exists():
        _err(
            "Error: no config.yaml found. Run `sentinel --init-config` or "
            "pass --config PATH."
        )
        return 3

    # ADR 0006 §D1 — pick backend lazily. Ruamel preferred (preserves
    # comments / formatting); PyYAML automatic fallback (loses comments
    # but writes a backup).
    backend, ruamel_yaml = _resolve_yaml_backend()

    try:
        if backend == "ruamel":
            assert ruamel_yaml is not None  # narrow for mypy
            with open(config_path, "r", encoding="utf-8") as fh:
                data = ruamel_yaml.load(fh)
        else:  # pyyaml
            with open(config_path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001 — surface any parse error
        _err(f"Error: failed to load {config_path}: {exc}")
        return 3

    try:
        blocklist = _ensure_blocklist_path(data)
    except RuntimeError as exc:
        _err(f"Error: {exc}")
        return 3

    # Normalize all existing entries for comparison without mutating
    # the YAML structure (ruamel preserves quoting/casing on disk;
    # PyYAML normalises strings on load anyway).
    existing_norm = [str(item).strip().lower() for item in blocklist]

    result: str
    if action == "add":
        if host in existing_norm:
            result = "already_present"
        else:
            blocklist.append(host)
            result = "added"
    elif action == "remove":
        if host not in existing_norm:
            # No file write happened, so no SIGHUP is sent (ADR 0005 §D7
            # — additive `daemon_reload` field still emitted with the
            # `skipped_not_running` value so envelope shape stays stable
            # across the success / no-op axes). ADR 0006 §D3 adds the
            # uniform `yaml_backend` / `backup_path` /
            # `comment_preservation` triplet on every emit.
            if args.json:
                _emit_json_envelope(
                    kind="host_context_mutation",
                    data={
                        "action": "unblock",
                        "host": host,
                        "result": "not_found",
                        "daemon_reload": "skipped_not_running",
                        "yaml_backend": backend,
                        "backup_path": None,
                        "comment_preservation": (
                            "preserved" if backend == "ruamel" else "lost"
                        ),
                    },
                )
            else:
                print(f"Host '{host}' is not in the blocklist.")
            return 1
        # Drop every matching entry (covers casing variants too).
        keep = [
            item
            for item in blocklist
            if str(item).strip().lower() != host
        ]
        # ruamel's CommentedSeq is list-like — replace contents in place
        # so anchors / comments attached to the parent survive. PyYAML's
        # plain list also accepts slice assignment.
        blocklist[:] = keep
        result = "removed"
    else:  # pragma: no cover — internal guard
        raise AssertionError(f"unknown action {action!r}")

    # Only flush to disk when something actually changed. A no-op write
    # would still be safe but generates needless mtime churn — and on
    # the PyYAML path it would also create an unnecessary backup.
    backup_path: Optional[str] = None
    if result in {"added", "removed"}:
        try:
            if backend == "ruamel":
                assert ruamel_yaml is not None  # narrow for mypy
                with open(config_path, "w", encoding="utf-8") as fh:
                    ruamel_yaml.dump(data, fh)
            else:  # pyyaml — backup-then-write per ADR 0006 §D2
                backup_path = _save_config_with_pyyaml(config_path, data)
                # Stderr warning surfaces the fallback + backup path
                # immediately after the write so the user sees it next
                # to the (text-mode) confirmation line.
                _emit_pyyaml_fallback_warning(backup_path)
        except OSError as exc:
            _err(f"Error: failed to write {config_path}: {exc}")
            return 3

    enabled = _is_context_enabled(_load_after_mutation(config_path))
    daemon_running = _is_daemon_running()

    # ADR 0005 §D7 — fire SIGHUP only when the file actually changed.
    # An "already_present" block is a no-op on disk; signalling would
    # cause an unnecessary reload (harmless but pointless).
    if result in {"added", "removed"}:
        reload_status, reload_pid = _signal_daemon_reload()
    else:
        reload_status, reload_pid = "skipped_not_running", None

    if args.json:
        _emit_json_envelope(
            kind="host_context_mutation",
            data={
                "action": "block" if action == "add" else "unblock",
                "host": host,
                "result": result,
                "config_path": str(config_path),
                "daemon_running": daemon_running,
                "daemon_reload": reload_status,
                "enabled": enabled,
                "yaml_backend": backend,
                "backup_path": backup_path,
                "comment_preservation": (
                    "preserved" if backend == "ruamel" else "lost"
                ),
            },
        )
    else:
        if action == "add":
            if result == "added":
                print(f"Added '{host}' to blocklist ({config_path}).")
            else:
                print(f"Host '{host}' is already in the blocklist.")
        else:  # remove
            print(f"Removed '{host}' from blocklist ({config_path}).")

        if not enabled and result in {"added", "removed"}:
            print(_disabled_notice())

    notice = _daemon_reload_notice(reload_status, reload_pid)
    if notice is not None:
        _err(notice)

    return 0


def _load_after_mutation(config_path: Path) -> dict:
    """Re-read config to get the post-mutation enabled flag."""
    try:
        return load_config(config_path)
    except Exception:  # noqa: BLE001 — best-effort, never fail the CLI here
        return {}


def cmd_block(args: argparse.Namespace) -> int:
    """Add ``HOST`` to ``security.context_aware.blocklist`` in config.yaml."""
    try:
        host = _validate_host(args.host)
    except ValueError as exc:
        _err(f"Error: {exc}")
        return 2
    return _mutate_blocklist(action="add", host=host, args=args)


def cmd_unblock(args: argparse.Namespace) -> int:
    """Remove ``HOST`` from ``security.context_aware.blocklist`` in config.yaml."""
    try:
        host = _validate_host(args.host)
    except ValueError as exc:
        _err(f"Error: {exc}")
        return 2
    return _mutate_blocklist(action="remove", host=host, args=args)


# ── argparse wiring ────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    """Return the root ``sentinel context …`` argument parser.

    Built standalone so the command can be invoked via either
    ``sentinel context …`` (through ``core.main`` dispatch) or
    ``python -m sentinel_mac.commands.context …`` for ad-hoc debugging.
    """
    parser = argparse.ArgumentParser(
        prog="sentinel context",
        description="Manage host trust context (v0.6+) — see ADR 0003.",
    )
    sub = parser.add_subparsers(dest="context_command", required=True)

    # status [HOST] [--json] [--config PATH]
    p_status = sub.add_parser(
        "status",
        help="Show host context snapshot, or single-host detail when HOST is given.",
    )
    p_status.add_argument(
        "host",
        nargs="?",
        default=None,
        help="Optional host to show in detail. Omit for a full snapshot.",
    )
    _add_common_flags(p_status)
    p_status.set_defaults(func=cmd_status)

    p_forget = sub.add_parser(
        "forget",
        help="Remove HOST from the frequency counter (mutates the cache file).",
    )
    p_forget.add_argument("host", help="Host to forget.")
    _add_common_flags(p_forget)
    p_forget.set_defaults(func=cmd_forget)

    p_block = sub.add_parser(
        "block",
        help="Add HOST to the config blocklist (mutates config.yaml via ruamel).",
    )
    p_block.add_argument("host", help="Host or fnmatch pattern to block.")
    _add_common_flags(p_block)
    p_block.set_defaults(func=cmd_block)

    p_unblock = sub.add_parser(
        "unblock",
        help="Remove HOST from the config blocklist (mutates config.yaml).",
    )
    p_unblock.add_argument("host", help="Host or fnmatch pattern to unblock.")
    _add_common_flags(p_unblock)
    p_unblock.set_defaults(func=cmd_unblock)

    return parser


def _add_common_flags(p: argparse.ArgumentParser) -> None:
    """Attach the universal ``--json`` and ``--config`` flags (ADR §D5)."""
    p.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emit ADR 0004 §D2 versioned envelope on stdout instead of "
            "the human-readable text view."
        ),
    )
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Override config.yaml path. Defaults to ./config.yaml or "
            "~/.config/sentinel/config.yaml."
        ),
    )


def dispatch(argv: Optional[Iterable] = None) -> int:
    """Parse ``argv`` and run the matching subcommand. Returns the exit code.

    ``argv`` is the slice *after* the ``context`` token — i.e., when called
    as ``sentinel context status --json``, pass ``["status", "--json"]``.
    """
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.func(args))


def main() -> None:
    """Entry point for ``python -m sentinel_mac.commands.context``."""
    sys.exit(dispatch(sys.argv[1:]))


if __name__ == "__main__":  # pragma: no cover
    main()
