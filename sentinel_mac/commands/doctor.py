"""``sentinel doctor`` — one-shot health check (v0.8 Track 1b).

Validates the locally-installed Sentinel surface in nine independent
checks:

  1.  daemon            — lock file + alive PID
  2.  config            — config.yaml load + parse
  3.  config_dir_perms  — ``~/.config/sentinel/`` mode (0o700 expected)
  4.  data_dir          — ``~/.local/share/sentinel/`` exists + writable
  5.  event_logs        — JSONL file count + latest date
  6.  hook              — Claude Code PreToolUse hook installed
  7.  host_context_cache— ``host_context.jsonl`` parses + no quarantines
  8.  backup_files      — accumulated ``config.yaml.bak.*`` count
  9.  optional_deps     — ruamel.yaml / rumps / terminal-notifier /
                          osx-cpu-temp install state

Each check is fully isolated: an exception in one does **not** block
the rest (we wrap every callable in ``_run_all_checks``). Exceptions
surface as ``status="fail"`` with the exception class + message.

Output:

* default — text, four-status banner per line plus a summary tail
* ``--json`` — ADR 0004 §D2 versioned envelope with
  ``kind="health_check"`` and a ``data.summary`` count map plus a
  ``data.checks`` list of per-check rows.

Exit codes:

* 0 — every check is OK / WARN / INFO (no FAIL)
* 1 — at least one FAIL row

The ADR 0004 §D2 frozen ``kind`` set is extended by this module to
include ``health_check`` (additive — does not bump ``version``).

ADR 0009 — Backup Cleanup mode (v0.9 Track 3a)
==============================================

``sentinel doctor --cleanup-backups --keep N [--dry-run] [--yes]`` is
mutually exclusive with the standard 9-check pass. When the flag is
present the 9 checks are skipped and only the cleanup runs. See ADR
0009 for the frozen surfaces:

* ``--keep`` is mandatory (no safe default — explicit user intent).
* Selection: parse trailing integer in ``<config>.bak.<epoch>``,
  sort descending, keep N. Filesystem mtime is NOT consulted.
* Interactive ``[y/N]`` by default; ``--yes`` skips it; ``--dry-run``
  reports without deleting.
* Non-TTY stdin without ``--yes`` auto-cancels with a stderr WARNING
  (cron-safe — never hangs).
* JSON envelope ``kind="backup_cleanup"`` (additive, no version bump).
* Exit codes: 0 success / 1 partial failure / 2 argument error.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from sentinel_mac.core import (
    CLAUDE_SETTINGS_PATH,
    _hook_has_sentinel,
    load_config,
    resolve_config_path,
)

# ── result + status enum ───────────────────────────────────────────

# Frozen status set — kept tight so the four banner colours / JSON
# downstream tooling can dispatch on equality without surprise.
STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_INFO = "info"

VALID_STATUSES: frozenset[str] = frozenset(
    {STATUS_OK, STATUS_WARN, STATUS_FAIL, STATUS_INFO}
)


@dataclass
class CheckResult:
    """One row in the doctor report.

    ``remediation`` is meaningful only on WARN / FAIL — for OK / INFO it
    stays ``None`` (no action needed by the user).
    """

    name: str
    status: str  # one of STATUS_OK / STATUS_WARN / STATUS_FAIL / STATUS_INFO
    detail: str
    remediation: str | None = None

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            # Defensive — if a check returns an unknown status, surface it
            # as a fail rather than silently mis-classifying it. Capture the
            # original value BEFORE reassigning so the diagnostic actually
            # reports what the buggy check returned.
            bad = self.status
            self.status = STATUS_FAIL
            self.detail = f"invalid status (was {bad!r}): {self.detail}"


# ── envelope helper ────────────────────────────────────────────────


def _emit_json_envelope(*, kind: str, data: dict) -> None:
    """ADR 0004 §D2 envelope writer (mirrors commands.context shim)."""
    envelope = {
        "version": 1,
        "kind": kind,
        "generated_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "data": data,
    }
    print(json.dumps(envelope, ensure_ascii=False))


# ── path helpers ───────────────────────────────────────────────────


def _config_dir() -> Path:
    """``~/.config/sentinel/`` (the canonical config directory)."""
    return Path.home() / ".config" / "sentinel"


def _data_dir() -> Path:
    """``~/.local/share/sentinel/`` (the canonical data directory).

    Mirrors ``core.resolve_data_dir`` but does not create the directory
    — doctor reports on existence as a check, never as a side effect.
    """
    return Path.home() / ".local" / "share" / "sentinel"


def _events_dir() -> Path:
    """``~/.local/share/sentinel/events/`` — JSONL audit trail location."""
    return _data_dir() / "events"


# ── individual checks ──────────────────────────────────────────────


def _check_daemon() -> CheckResult:
    """Lock file presence + PID liveness probe (signal 0).

    Computes the lock path directly (without ``daemon_lock_path()``)
    because that helper has a ``mkdir(parents=True, exist_ok=True)``
    side effect — calling it from doctor would silently create the
    data directory and mask a legitimate `_check_data_dir` FAIL.
    Doctor must never side-effect; it only reads.
    """
    lock_path = Path.home() / ".local" / "share" / "sentinel" / "sentinel.lock"
    if not lock_path.exists():
        return CheckResult(
            name="daemon",
            status=STATUS_INFO,
            detail="not running (no lock file)",
        )
    try:
        raw = lock_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return CheckResult(
            name="daemon",
            status=STATUS_WARN,
            detail=f"lock file unreadable: {exc}",
            remediation=f"inspect or remove {lock_path}",
        )
    if not raw:
        return CheckResult(
            name="daemon",
            status=STATUS_WARN,
            detail="lock file is empty (likely stale)",
            remediation=f"remove {lock_path} if no daemon is running",
        )
    try:
        pid = int(raw.split()[0])
    except (ValueError, IndexError):
        return CheckResult(
            name="daemon",
            status=STATUS_WARN,
            detail=f"lock file PID unparseable: {raw!r}",
            remediation=f"remove {lock_path} if no daemon is running",
        )
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return CheckResult(
            name="daemon",
            status=STATUS_WARN,
            detail=f"stale lock — PID {pid} no longer alive",
            remediation=(
                f"remove {lock_path} (the previous daemon crashed without "
                "releasing the lock)"
            ),
        )
    except PermissionError:
        # Process exists but we can't signal it — treat as alive.
        return CheckResult(
            name="daemon",
            status=STATUS_OK,
            detail=f"running (PID {pid}, not signal-reachable)",
        )
    except OSError as exc:
        return CheckResult(
            name="daemon",
            status=STATUS_WARN,
            detail=f"liveness probe error: {exc}",
        )
    return CheckResult(
        name="daemon", status=STATUS_OK, detail=f"running (PID {pid})"
    )


def _check_config(config_path: Path | None) -> CheckResult:
    """Resolve + parse ``config.yaml``; report missing/empty/invalid cleanly."""
    resolved = (
        config_path if config_path is not None else resolve_config_path()
    )
    if resolved is None:
        return CheckResult(
            name="config",
            status=STATUS_INFO,
            detail="no config file found; defaults active",
        )
    if not Path(resolved).exists():
        return CheckResult(
            name="config",
            status=STATUS_FAIL,
            detail=f"config path does not exist: {resolved}",
            remediation=(
                "run `sentinel --init-config` or pass an existing --config PATH"
            ),
        )
    try:
        cfg = load_config(Path(resolved))
    except Exception as exc:  # noqa: BLE001 — surface any parse error
        return CheckResult(
            name="config",
            status=STATUS_FAIL,
            detail=f"parse error: {type(exc).__name__}: {exc}",
            remediation=f"fix YAML syntax in {resolved}",
        )
    if not isinstance(cfg, dict) or not cfg:
        # `load_config` returns the defaults dict on most failures, which
        # is non-empty — an empty dict here means a deliberately-blank file.
        return CheckResult(
            name="config",
            status=STATUS_INFO,
            detail=f"empty config: {resolved}",
        )
    return CheckResult(
        name="config", status=STATUS_OK, detail=f"{resolved} — valid"
    )


def _check_config_dir_perms() -> CheckResult:
    """Verify ``~/.config/sentinel/`` is mode ``0o700`` (ADR 0006 §D5)."""
    cfg_dir = _config_dir()
    if not cfg_dir.exists():
        return CheckResult(
            name="config_dir_perms",
            status=STATUS_INFO,
            detail=f"{cfg_dir} does not exist (no config installed)",
        )
    try:
        mode = stat.S_IMODE(cfg_dir.stat().st_mode)
    except OSError as exc:
        return CheckResult(
            name="config_dir_perms",
            status=STATUS_FAIL,
            detail=f"stat failed: {exc}",
        )
    if mode == 0o700:
        return CheckResult(
            name="config_dir_perms",
            status=STATUS_OK,
            detail=f"{cfg_dir} mode is 0o700",
        )
    # Anything more permissive than 0o700 leaks config (which may carry
    # webhook secrets per ADR 0006 §D5) — surface as WARN with the fix.
    return CheckResult(
        name="config_dir_perms",
        status=STATUS_WARN,
        detail=(
            f"{cfg_dir} mode is 0o{mode:o} (group/world readable)"
        ),
        remediation=f"chmod 700 {cfg_dir}",
    )


def _check_data_dir() -> CheckResult:
    """``~/.local/share/sentinel/`` must exist + be writable.

    Missing dir is INFO, not FAIL: that is the legitimate fresh-install
    state (the daemon creates it on first run). Unwritable dir is FAIL
    because that is a real problem the user must fix.
    """
    d = _data_dir()
    if not d.exists():
        return CheckResult(
            name="data_dir",
            status=STATUS_INFO,
            detail=f"{d} does not exist yet (created on first daemon run)",
        )
    if not os.access(d, os.W_OK):
        return CheckResult(
            name="data_dir",
            status=STATUS_FAIL,
            detail=f"{d} is not writable",
            remediation=f"chmod u+w {d}",
        )
    return CheckResult(
        name="data_dir",
        status=STATUS_OK,
        detail=f"{d} — exists, writable",
    )


def _check_event_logs() -> CheckResult:
    """Count daily JSONL files under ``events/`` and report the latest date."""
    ev_dir = _events_dir()
    if not ev_dir.exists():
        return CheckResult(
            name="event_logs",
            status=STATUS_INFO,
            detail="no events recorded yet (events dir absent)",
        )
    try:
        files = sorted(p for p in ev_dir.glob("*.jsonl") if p.is_file())
    except OSError as exc:
        return CheckResult(
            name="event_logs",
            status=STATUS_FAIL,
            detail=f"events dir scan failed: {exc}",
        )
    if not files:
        return CheckResult(
            name="event_logs",
            status=STATUS_INFO,
            detail="no events recorded yet",
        )
    latest = files[-1].stem  # filename is YYYY-MM-DD
    return CheckResult(
        name="event_logs",
        status=STATUS_OK,
        detail=f"{len(files)} files, latest {latest}",
    )


def _check_hook() -> CheckResult:
    """Look for the Sentinel PreToolUse hook in Claude Code settings.

    Reads ``CLAUDE_SETTINGS_PATH`` (this module's binding, so tests can
    monkeypatch it) directly instead of going through
    ``core._load_claude_settings`` — that helper is bound to the
    ``core`` module's own ``CLAUDE_SETTINGS_PATH`` global which would
    bypass the test override. ``_hook_has_sentinel`` is reused as-is
    since it operates on plain dicts.
    """
    settings_path = CLAUDE_SETTINGS_PATH
    if not settings_path.exists():
        return CheckResult(
            name="hook",
            status=STATUS_INFO,
            detail="Claude Code settings.json not found (Claude Code not installed?)",
        )
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return CheckResult(
            name="hook",
            status=STATUS_WARN,
            detail=f"settings.json unreadable: {type(exc).__name__}: {exc}",
            remediation="repair Claude Code settings.json",
        )
    pre_tool_use = settings.get("hooks", {}).get("PreToolUse", [])
    if any(_hook_has_sentinel(h) for h in pre_tool_use):
        return CheckResult(
            name="hook", status=STATUS_OK, detail="installed"
        )
    return CheckResult(
        name="hook",
        status=STATUS_INFO,
        detail="not installed",
        remediation="run `sentinel hooks install`",
    )


def _check_host_context_cache() -> CheckResult:
    """Validate ``host_context.jsonl`` (or report it as not present yet).

    Also flags the presence of any ``host_context.jsonl.corrupted-*``
    quarantine sibling files written by ``HostContext`` on past load
    failures (ADR 0001).
    """
    # Default cache path mirrors `_resolve_default_cache_path` from
    # collectors.context. We deliberately do not import that private
    # helper — duplicating the path keeps doctor's coupling minimal.
    cache_path = _data_dir() / "host_context.jsonl"
    quarantines = list(_data_dir().glob("host_context.jsonl.corrupted-*"))

    if not cache_path.exists():
        if quarantines:
            return CheckResult(
                name="host_context_cache",
                status=STATUS_WARN,
                detail=(
                    f"cache absent but {len(quarantines)} quarantine "
                    "file(s) present"
                ),
                remediation=(
                    f"inspect/remove {quarantines[0].parent}/host_context.jsonl.corrupted-*"
                ),
            )
        return CheckResult(
            name="host_context_cache",
            status=STATUS_INFO,
            detail="cache file not present yet",
        )

    # Walk every line to confirm valid JSON; tolerate the _meta header.
    host_count = 0
    try:
        with open(cache_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if isinstance(obj, dict) and "host" in obj:
                    host_count += 1
    except (OSError, json.JSONDecodeError) as exc:
        return CheckResult(
            name="host_context_cache",
            status=STATUS_FAIL,
            detail=f"cache parse error: {type(exc).__name__}: {exc}",
            remediation=(
                f"remove {cache_path} (HostContext will recreate it on next load)"
            ),
        )

    if quarantines:
        return CheckResult(
            name="host_context_cache",
            status=STATUS_WARN,
            detail=(
                f"{host_count} hosts; {len(quarantines)} quarantine file(s) "
                "from past corruption"
            ),
            remediation=(
                f"clean up {cache_path.parent}/host_context.jsonl.corrupted-*"
            ),
        )
    return CheckResult(
        name="host_context_cache",
        status=STATUS_OK,
        detail=f"{host_count} hosts, no corruption",
    )


def _check_backup_files() -> CheckResult:
    """Count accumulated ``config.yaml.bak.*`` files (ADR 0006 §D5)."""
    cfg_dir = _config_dir()
    if not cfg_dir.exists():
        return CheckResult(
            name="backup_files",
            status=STATUS_OK,
            detail="0 backup files",
        )
    try:
        backups = list(cfg_dir.glob("config.yaml.bak.*"))
    except OSError as exc:
        return CheckResult(
            name="backup_files",
            status=STATUS_FAIL,
            detail=f"glob failed: {exc}",
        )
    n = len(backups)
    if n == 0:
        return CheckResult(
            name="backup_files", status=STATUS_OK, detail="0 backup files"
        )
    if n <= 10:
        return CheckResult(
            name="backup_files",
            status=STATUS_OK,
            detail=f"{n} backup file(s)",
        )
    return CheckResult(
        name="backup_files",
        status=STATUS_WARN,
        detail=f"{n} backup files accumulated",
        remediation=(
            "consider cleanup; future v0.9 `sentinel doctor "
            "--cleanup-backups` will help"
        ),
    )


def _check_optional_deps() -> CheckResult:
    """Report install state of the four optional integrations."""
    deps: list[tuple[str, bool]] = []

    # Python packages — try import.
    try:
        import ruamel.yaml  # noqa: F401
        deps.append(("ruamel.yaml", True))
    except ImportError:
        deps.append(("ruamel.yaml", False))

    try:
        import rumps  # noqa: F401
        deps.append(("rumps", True))
    except ImportError:
        deps.append(("rumps", False))

    # Binaries — `shutil.which` is the right tool here (PATH-aware,
    # cross-shell, no subprocess).
    deps.append(("terminal-notifier", shutil.which("terminal-notifier") is not None))
    deps.append(("osx-cpu-temp", shutil.which("osx-cpu-temp") is not None))

    parts = [f"{name} {'OK' if present else 'missing'}" for name, present in deps]
    return CheckResult(
        name="optional_deps",
        status=STATUS_INFO,
        detail=", ".join(parts),
    )


# ── runner + summary ───────────────────────────────────────────────


def _run_all_checks(config_path: Path | None) -> list[CheckResult]:
    """Execute every check, isolating exceptions into ``CheckResult(fail)``.

    Order is the canonical one used in both text and JSON output. A
    check that raises any ``Exception`` becomes a FAIL row carrying
    ``type(exc).__name__: <msg>`` so the user sees the cause without a
    stack trace flooding the terminal.
    """
    checks: list[tuple[str, Callable[[], CheckResult]]] = [
        ("daemon", _check_daemon),
        ("config", lambda: _check_config(config_path)),
        ("config_dir_perms", _check_config_dir_perms),
        ("data_dir", _check_data_dir),
        ("event_logs", _check_event_logs),
        ("hook", _check_hook),
        ("host_context_cache", _check_host_context_cache),
        ("backup_files", _check_backup_files),
        ("optional_deps", _check_optional_deps),
    ]
    results: list[CheckResult] = []
    for name, fn in checks:
        try:
            res = fn()
        except Exception as exc:  # noqa: BLE001 — isolation is the whole point
            results.append(
                CheckResult(
                    name=name,
                    status=STATUS_FAIL,
                    detail=f"check raised: {type(exc).__name__}: {exc}",
                )
            )
        else:
            # Normalise the name in case a check forgot to set it.
            if not res.name:
                res.name = name
            results.append(res)
    return results


def _summarize(results: Iterable[CheckResult]) -> dict[str, int]:
    counts = {STATUS_OK: 0, STATUS_WARN: 0, STATUS_FAIL: 0, STATUS_INFO: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


# ── output renderers ───────────────────────────────────────────────

# Display labels — one line per status, fixed width so columns align.
_LABEL = {
    STATUS_OK: "[OK]  ",
    STATUS_WARN: "[WARN]",
    STATUS_FAIL: "[FAIL]",
    STATUS_INFO: "[INFO]",
}

# Pretty section names for the text view (snake_case → Title Case).
_PRETTY = {
    "daemon": "Daemon",
    "config": "Config",
    "config_dir_perms": "Config dir",
    "data_dir": "Data dir",
    "event_logs": "Event logs",
    "hook": "Claude Code hook",
    "host_context_cache": "HostContext cache",
    "backup_files": "Backup files",
    "optional_deps": "Optional deps",
}


def _render_text(results: list[CheckResult]) -> str:
    """Render the human-readable doctor view."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines: list[str] = []
    lines.append(f"Sentinel Doctor — {now}")
    lines.append("")
    for r in results:
        label = _LABEL.get(r.status, "[????]")
        title = _PRETTY.get(r.name, r.name)
        lines.append(f"{label} {title}: {r.detail}")
        if r.remediation and r.status in {STATUS_WARN, STATUS_FAIL}:
            lines.append(f"       Remediation: {r.remediation}")
    counts = _summarize(results)
    lines.append("")
    lines.append(
        f"Summary: {counts[STATUS_OK]} OK, {counts[STATUS_WARN]} WARN, "
        f"{counts[STATUS_FAIL]} FAIL, {counts[STATUS_INFO]} INFO"
    )
    return "\n".join(lines)


def _render_json(results: list[CheckResult]) -> None:
    """Emit the ADR 0004 §D2 envelope with ``kind="health_check"``.

    Note: ``health_check`` extends the previously-frozen ADR 0004 §D2
    ``kind`` set additively; no version bump per §D2 ("Additive changes
    do not bump version").
    """
    counts = _summarize(results)
    data = {
        "summary": counts,
        "checks": [
            {
                "name": r.name,
                "status": r.status,
                "detail": r.detail,
                "remediation": r.remediation,
            }
            for r in results
        ],
    }
    _emit_json_envelope(kind="health_check", data=data)


# ── CLI entry ──────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel doctor",
        description=(
            "One-shot health check (ADR 0004 §D2 envelope kind=health_check) "
            "or, with --cleanup-backups, ADR 0009 backup cleanup."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emit ADR 0004 §D2 versioned envelope on stdout instead of the "
            "human-readable text view. In cleanup mode --yes is implied."
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Override config.yaml path. Defaults to ./config.yaml or "
            "~/.config/sentinel/config.yaml."
        ),
    )
    # ADR 0009 cleanup-mode flags. argparse-level mutual exclusion with
    # the 9-check mode happens at dispatch time (cleanup mode = "the
    # --cleanup-backups flag was set"); we don't use add_mutually_exclusive_group
    # because the 9-check mode has no flag of its own (it's the default).
    parser.add_argument(
        "--cleanup-backups",
        action="store_true",
        help=(
            "ADR 0009 — delete old config.yaml.bak.<epoch> files keeping "
            "the N most recent. Mutually exclusive with the standard "
            "9-check health pass; requires --keep N."
        ),
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=None,
        metavar="N",
        help=(
            "ADR 0009 — number of most-recent backups to retain. Mandatory "
            "when --cleanup-backups is present (no safe default — explicit "
            "user intent required)."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "ADR 0009 — report what would be deleted, delete nothing. "
            "Cleanup-mode flag; ignored without --cleanup-backups."
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help=(
            "ADR 0009 — skip the interactive [y/N] confirmation. "
            "Cleanup-mode flag; ignored without --cleanup-backups."
        ),
    )
    return parser


def dispatch(argv: Iterable | None = None) -> int:
    """Parse ``argv``, run every check, render, and return the exit code.

    Exit code is 0 when no FAIL row is present; 1 otherwise — WARN /
    INFO never fail the command.

    ADR 0009 — when ``--cleanup-backups`` is present, the 9-check pass
    is skipped and ``_cmd_cleanup_backups`` runs instead. Exit codes
    follow ADR 0009 D7 in that branch (0 success / 1 partial failure /
    2 argument error).
    """
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    # ADR 0009 D1 — cleanup mode is mutually exclusive with the standard
    # 9-check pass. Branch early so the 9 checks never run when the user
    # asked for cleanup.
    if args.cleanup_backups:
        return _cmd_cleanup_backups(args)

    results = _run_all_checks(args.config)

    if args.json:
        _render_json(results)
    else:
        print(_render_text(results))

    counts = _summarize(results)
    return 1 if counts[STATUS_FAIL] > 0 else 0


# ── ADR 0009 cleanup mode ─────────────────────────────────────────


def _err(msg: str) -> None:
    """Write a single line to stderr — used for cleanup-mode errors and
    the non-TTY auto-cancel WARNING (ADR 0009 D4)."""
    print(msg, file=sys.stderr)


def _resolve_config_for_cleanup(explicit: Path | None) -> Path | None:
    """Resolve the config path for cleanup-mode without requiring it to
    parse — we only need its directory + filename to glob siblings.

    Mirrors the standard ``resolve_config_path`` precedence (explicit
    --config → ./config.yaml → ~/.config/sentinel/config.yaml) but
    returns None when nothing is found instead of falling back to
    defaults — cleanup against an absent config has no meaning.
    """
    if explicit is not None:
        return Path(explicit)
    resolved = resolve_config_path()
    return Path(resolved) if resolved is not None else None


def _list_backups(config_path: Path) -> list[Path]:
    """ADR 0009 D3 selection rule.

    Glob ``<config>.bak.*`` next to the config, parse the trailing
    integer in each filename, sort by epoch descending, return as a
    list of Paths. Files whose suffix after ``.bak.`` does not parse
    to an int are silently skipped (defensive — never delete a file
    that does not match the freeze pattern even if it lives next to it).

    Filesystem mtime is intentionally NOT consulted — the epoch in the
    filename is the canonical timestamp and survives ``cp -p`` / archive
    round-trips.
    """
    parent = config_path.parent
    if not parent.exists():
        return []
    pattern = f"{config_path.name}.bak.*"
    candidates = list(parent.glob(pattern))
    parsed: list[tuple[int, Path]] = []
    for p in candidates:
        # Suffix is everything after the literal ".bak." separator.
        suffix = p.name[len(config_path.name) + len(".bak."):]
        try:
            epoch = int(suffix)
        except ValueError:
            # ADR 0009 D3 — skip non-int suffixes (defensive).
            continue
        parsed.append((epoch, p))
    parsed.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in parsed]


def _format_epoch(epoch: int) -> str:
    """Render a unix epoch as ``YYYY-MM-DD HH:MM:SS`` local time."""
    try:
        return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "?"


def _print_deletion_plan(
    delete: list[Path],
    keep_n: int,
    *,
    dry_run: bool = False,
) -> None:
    """ADR 0009 D4 — render the deletion plan in text mode.

    Shows the first 5 paths inline and elides the rest as
    "... N more ..." so a large cleanup doesn't flood the terminal.
    """
    n = len(delete)
    header = (
        f"Would delete {n} backup file(s)" if dry_run
        else f"Will delete {n} backup file(s)"
    )
    print(f"{header}, keeping the {keep_n} most recent:")
    show = delete[:5]
    for p in show:
        # Suffix after .bak. is the epoch (validated by _list_backups).
        suffix = p.name.rsplit(".bak.", 1)[-1]
        try:
            epoch = int(suffix)
            ts = _format_epoch(epoch)
        except ValueError:  # pragma: no cover — _list_backups guards this
            ts = "?"
        print(f"  {p.name} ({ts})")
    if n > len(show):
        print(f"  ... {n - len(show)} more ...")


def _do_delete(paths: list[Path]) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Attempt to ``unlink`` each path. Returns (deleted, errors).

    A failure on one path does NOT abort the rest — every path is
    attempted independently per ADR 0009 D7 ("partial failure" is a
    real exit-1 outcome distinct from "argument error" exit-2).
    """
    deleted: list[Path] = []
    errors: list[tuple[Path, str]] = []
    for p in paths:
        try:
            p.unlink()
            deleted.append(p)
        except OSError as exc:
            errors.append((p, f"{type(exc).__name__}: {exc}"))
    return deleted, errors


def _emit_cleanup_envelope(
    *,
    config_path: Path,
    found: int,
    keep: int,
    delete_planned: list[Path],
    deleted: list[Path],
    errors: list[tuple[Path, str]],
    dry_run: bool,
) -> None:
    """ADR 0009 D6 — JSON envelope writer.

    For dry-run mode the ``deleted`` field carries the *planned* paths
    (what *would* be deleted) and ``dry_run: true`` flags it. For real
    runs ``deleted`` is the list of paths that actually got unlinked
    and ``errors`` (when present) carries any partial failures.
    """
    data: dict = {
        "config_path": str(config_path),
        "found": found,
        "kept": min(found, keep),
        "deleted": [str(p) for p in (delete_planned if dry_run else deleted)],
        "dry_run": dry_run,
    }
    if errors:
        data["errors"] = [
            {"path": str(p), "error": msg} for p, msg in errors
        ]
    _emit_json_envelope(kind="backup_cleanup", data=data)


def _cmd_cleanup_backups(args) -> int:
    """ADR 0009 — ``sentinel doctor --cleanup-backups``.

    Returns exit code per ADR D7:
        0 = success / nothing to delete / cancelled / dry-run
        1 = partial failure (some files could not be deleted)
        2 = argument validation error
    """
    # ADR 0009 D2 — --keep is mandatory; no safe default. The error
    # message is verbatim per the ADR so users get an actionable hint.
    if args.keep is None:
        _err(
            "error: --cleanup-backups requires --keep N to specify how many "
            "backups to retain. Example: sentinel doctor --cleanup-backups "
            "--keep 3"
        )
        return 2
    if args.keep < 0:
        _err(f"error: --keep must be >= 0, got {args.keep}")
        return 2

    config_path = _resolve_config_for_cleanup(args.config)
    if config_path is None:
        _err(
            "error: no config file found (looked at ./config.yaml and "
            "~/.config/sentinel/config.yaml). Pass --config PATH to point "
            "at the config whose backups you want to clean."
        )
        return 2

    backups = _list_backups(config_path)
    found = len(backups)
    # backups[: args.keep] is the kept slice (computed implicitly via
    # `min(found, args.keep)` in the envelope and text output below);
    # we only need the to-delete slice for the actual unlink.
    delete = backups[args.keep:]

    # JSON mode — D6 envelope, --yes implied (no interactive prompt for
    # tooling consumers). --dry-run still respected; errors populate
    # data.errors and flip the exit code per D7.
    if args.json:
        if not delete:
            _emit_cleanup_envelope(
                config_path=config_path,
                found=found,
                keep=args.keep,
                delete_planned=[],
                deleted=[],
                errors=[],
                dry_run=args.dry_run,
            )
            return 0
        if args.dry_run:
            _emit_cleanup_envelope(
                config_path=config_path,
                found=found,
                keep=args.keep,
                delete_planned=delete,
                deleted=[],
                errors=[],
                dry_run=True,
            )
            return 0
        deleted, errors = _do_delete(delete)
        _emit_cleanup_envelope(
            config_path=config_path,
            found=found,
            keep=args.keep,
            delete_planned=delete,
            deleted=deleted,
            errors=errors,
            dry_run=False,
        )
        return 1 if errors else 0

    # Text mode — D5 idempotency: nothing-to-delete is exit 0 with a
    # friendly message (matches the ADR D5 example).
    if not delete:
        kept_n = min(found, args.keep)
        print(
            f"Nothing to delete ({found} backup file(s), keeping {kept_n})."
        )
        return 0

    if args.dry_run:
        _print_deletion_plan(delete, args.keep, dry_run=True)
        return 0

    # ADR 0009 D4 — interactive prompt (unless --yes). Non-TTY stdin
    # without --yes is the cron / CI case: auto-cancel with a stderr
    # WARNING so the command never hangs waiting for stdin.
    if not args.yes:
        # sys.stdin may not have isatty in unusual harnesses; guard.
        is_tty = False
        try:
            is_tty = sys.stdin.isatty()
        except (AttributeError, ValueError):
            is_tty = False
        if not is_tty:
            _err(
                "warning: --cleanup-backups invoked with non-TTY stdin and "
                "no --yes; skipping deletion"
            )
            return 0
        _print_deletion_plan(delete, args.keep)
        try:
            answer = input("\nProceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled. No files deleted.")
            return 0
        if answer != "y":
            print("Cancelled. No files deleted.")
            return 0

    deleted, errors = _do_delete(delete)
    if errors:
        # D7 — partial failure surfaces on stderr + exit 1.
        for p, msg in errors:
            _err(f"error: failed to delete {p}: {msg}")
        print(
            f"Deleted {len(deleted)} backup file(s); {len(errors)} failed."
        )
        return 1
    print(
        f"Deleted {len(deleted)} backup file(s); kept "
        f"{min(found, args.keep)} most recent."
    )
    return 0


def main() -> None:
    """Entry point for ``python -m sentinel_mac.commands.doctor``."""
    sys.exit(dispatch(sys.argv[1:]))


if __name__ == "__main__":  # pragma: no cover
    main()
