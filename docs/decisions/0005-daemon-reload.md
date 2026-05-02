# ADR 0005 — Daemon Reload Protocol (v0.8)

- **Status**: Accepted
- **Date**: 2026-05-02
- **Scope**: `sentinel_mac/core.py` (signal handler), `sentinel_mac/collectors/context.py`
  (in-place reload helper if needed), `config.example.yaml` (no schema change).
- **Supersedes**: —
- **Referenced by**: ADR 0001 §D2 (deferred to v0.8), ADR 0003 §D3 (deferred to v0.8)

## Context

`sentinel context block evil.com` writes the new entry to `config.yaml`, but
the running daemon already has its `HostContext` initialized from the old
config and only re-reads on startup. Today the user must `sentinel restart`
to see CLI mutations take effect. This is the single biggest UX paper-cut
left from v0.7.

This ADR freezes the SIGHUP-driven reload protocol — **what** is reloaded,
**what is not**, and **how partial failures are handled** — so the v0.8
Track 1 implementation has a fixed contract.

## Decisions

### D1. Trigger — SIGHUP (POSIX standard for "reload your config")

- The daemon registers a `SIGHUP` handler at startup. CLI mutations
  (`sentinel context block` / `unblock` / `forget`) send `SIGHUP` to the
  PID recorded in `~/.local/share/sentinel/sentinel.lock` after their
  filesystem mutation succeeds.
- If the lock file shows no live PID (no daemon running) the CLI skips
  the signal silently — the existing "Restart the daemon for the running
  instance to pick up the change." notice is replaced with an "applied
  to running daemon (PID NNN)." notice on success.
- Non-CLI users can also send `kill -HUP $(cat sentinel.lock)` directly.

`SIGHUP` chosen over `SIGUSR1`/`SIGUSR2` because:
- POSIX convention — operators expect `kill -HUP` to mean "reload".
- launchd preserves it (no special plist flag needed).
- Distinct from `SIGTERM`/`SIGINT` shutdown handlers already in place.

### D2. Reload scope (what gets re-read)

| Source | Reloaded on SIGHUP? | Why |
|---|---|---|
| `config.yaml` (full) | **Yes** | Single source of truth; covers blocklist, thresholds, channels, custom_rules, agent_log per-rule toggles |
| `~/.ssh/known_hosts` | **Yes** | Re-parsed via `HostContext.load()` |
| `host_context.jsonl` (frequency cache) | **Flushed first, then re-read** | Preserves unflushed observations across the reload boundary |
| Notification channel state (rate-limit counters, pending ntfy retries) | **No** | In-memory operational state; reset would lose context |
| AlertEngine cooldown timestamps | **No** | Same reason — would re-flood the user |
| Agent log parser tail offsets (file positions in JSONL session logs) | **No** | Re-reading would replay events |
| Agent log parser hooks-integration watch path | **Conditionally** — same rule as FSWatcher (only if `security.agent_logs.parsers[].log_dir` changed) | Reopening tail reader is mid-cost |
| FSWatcher watchdog observer | **Conditionally** — if `security.fs_watcher.watch_paths` changed | Restarting the observer is expensive; only do it if needed |
| Typosquatting reference list (`collectors/typosquatting.py`) | **No** — hardcoded set, not a config item | Per CLAUDE.md trust model; updated at release time |
| Daemon PID / lock file | **No** | Owned by process lifecycle |
| `event_logger` open file handles | **Yes** (close+reopen, **inside the D3 step-6 swap under `_reload_lock`**) | Lets log rotation work cleanly across reload while preventing concurrent writes during the swap |

### D3. Reload sequence (atomic-ish, fail-safe)

```
1. SIGHUP received.
2. host_ctx.flush()                      # preserve in-memory frequency
3. new_config = load_config(...)         # if this fails → abort, keep old state
4. validate(new_config)                  # threshold sanity, type checks
5. Build new components in a side state:
     new_host_ctx = HostContext.from_config(new_config); new_host_ctx.load()
     new_engine_thresholds = new_config["thresholds"]
     new_notifier_channels = new_config["notifications"]
     new_security_rules = new_config["security"]
6. Atomic swap (under self._reload_lock):
     self.host_ctx = new_host_ctx
     self.engine.thresholds = new_engine_thresholds
     self.notifier.update_channels(new_notifier_channels)
     self.security_rules = new_security_rules
     # FSWatcher: restart only if watch_paths changed
7. log("reloaded config from {path}")
```

If **any of steps 3, 4, or 5** raises, the daemon **keeps running on the
old state** and logs `WARNING: config reload failed at step N: {error};
keeping previous config`. The new objects in step 5 are built into local
variables; the swap (step 6) is the only place existing `self.*`
references change, so a mid-step-5 exception leaves no observable
side effect. Never half-reload. Never crash from SIGHUP.

### D4. What does NOT trigger reload

- File-system change to `config.yaml` (no inotify watch). Reload is
  **explicit user action only** — either via `sentinel context …` CLI
  or manual `kill -HUP`.
- Reason: silently picking up arbitrary edits is surprising and risks
  reload during a half-saved file.

### D5. Concurrency & races

- A single `self._reload_lock` (threading.RLock) guards the swap. The
  main loop's metric collection and the queue drainer take this lock
  briefly before reading `self.host_ctx` / `self.engine.thresholds`.
- SIGHUP delivery is async. The handler sets a `threading.Event`
  (`self._reload_requested`) — async-signal-safe — and a dedicated
  reload worker thread (started in `Sentinel.__init__`) `wait()`s on
  the event and runs the D3 sequence as soon as it fires. **Latency
  is sub-second**, not bound to the main loop's metric tick (which is
  `check_interval_seconds`, default 30s) nor the status report cycle
  (`status_interval_minutes`, default 60min — ADR 0001 §D2). Running
  config parsing in a worker (not the signal handler) avoids the
  unsafe-from-signal-handler restrictions on most operations.
- Multiple SIGHUPs arriving in rapid succession coalesce into one
  reload — the worker `clear()`s the event before running, so any
  SIGHUP arriving during the reload re-fires it exactly once
  afterward (idempotent).
- The dedicated worker thread costs ~0 in steady state (`Event.wait()`
  blocks on a kernel primitive). Trade-off accepted to keep "applied"
  feel instant for the user — v0.8's headline UX value.

### D6. Menubar app — out of scope for v0.8

The `sentinel-app` menubar app is a separate process. Two valid
architectures:
- **Embedded daemon mode** (current code path when no other daemon
  running): the same SIGHUP plumbing applies.
- **Viewer mode** (other daemon owns the lock): menubar reads cached
  state. CLI mutations land in config.yaml; the menubar refreshes its
  view on its existing polling tick. No SIGHUP needed.

A future ADR may add menubar↔daemon IPC. Out of v0.8 scope.

### D7. CLI integration

`sentinel_mac/commands/context.py` adds a `_signal_daemon_reload()` helper
called by `forget` / `block` / `unblock` after their filesystem mutation
succeeds. Behavior:

- Read PID from `sentinel.lock` (existing helper from ADR 0003).
- `os.kill(pid, signal.SIGHUP)`.
- On success: replace the existing "Restart the daemon" notice with
  "Applied to running daemon (PID {pid})."
- On `ProcessLookupError` / `PermissionError`: print "Daemon not
  reachable; restart manually with `sentinel restart`." (don't fail
  the CLI command — the file mutation already succeeded).

JSON envelope for mutation results gains an additive `daemon_reload`
field per ADR 0004 §D3:

```json
{
  "version": 1, "kind": "host_context_mutation",
  "data": {
    "action": "block", "host": "evil.com", "result": "added",
    "daemon_reload": "applied"   // | "skipped_not_running" | "failed_unreachable"
  }
}
```

## Consequences

### Positive
- `sentinel context …` becomes a one-shot operation; no manual restart.
- POSIX-standard reload mechanism; ops engineers can `kill -HUP` directly.
- Atomic-or-nothing reload — no half-state.
- Observability — every reload is logged with timestamp + source.

### Negative / accepted trade-offs
- AlertEngine cooldowns and notifier rate-limits survive reload — by
  design (preserves user UX) but means a config change to a threshold
  doesn't bypass an active cooldown immediately. Documented limitation.
- FSWatcher restart on `watch_paths` change is expensive (~100ms);
  unavoidable given watchdog's design.
- SIGHUP is POSIX — Windows port (if ever) needs an alternative IPC.
  Out of scope (Q4 deferred).

### Follow-ups
- Track 1 of v0.8 — implementation PR. Includes:
  - `Sentinel._handle_sighup` + reload sequence
  - `commands/context.py` `_signal_daemon_reload` integration
  - `tests/test_daemon_reload.py` (new) covering full reload cycle,
    failure isolation, and the SIGHUP flag coalescing
- v0.9+ candidate — file-watch on `config.yaml` for auto-reload (D4
  reversal, only if user demand emerges)
- v0.9+ candidate — menubar↔daemon IPC for live viewer refresh

## Frozen surfaces

- Signal: `SIGHUP`
- Reload scope (D2 table)
- Failure mode: keep old state + log warning (D3)
- Coalescing: multiple SIGHUPs → one reload (D5)
- Handler registration site: `Sentinel.__init__` (after lock acquisition,
  before any collector starts), via `signal.signal(signal.SIGHUP,
  self._on_sighup)`. Single registration per process — no late
  re-registration in main loop, no per-collector handlers (avoids
  fork/spawn race surface).
- Reload worker thread: started in `Sentinel.__init__` after handler
  registration; daemon thread that exits when the process exits.
- CLI envelope addition: `daemon_reload` field with three values
  `{"applied", "skipped_not_running", "failed_unreachable"}`

Adding new reloadable config sections is fine without superseding ADR
(extend the D2 table). Changing the signal, the failure mode, or
removing the coalescing requires a superseding ADR.
