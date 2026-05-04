# Changelog

All notable changes to Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added (v0.10 ADR 0010 freeze + Track A)

- **`sentinel update` command** — check for and apply self-updates without manual `pip` / `launchctl` steps. Detects install method (pipx, pip-venv, Homebrew, editable, system Python) and routes to appropriate upgrade path.
- **`--check` flag** — query PyPI for the latest version and report if an update is available. Exit code 0 (up to date), 2 (update available), 1 (error), or 3 (unsupported install method).
- **Install method detection** — pure-function heuristics on `sys.executable` and `sentinel_mac.__file__` paths (no subprocess calls). Supports editable/pipx/Homebrew/pip-venv/system-Python scenarios.
- **JSON output** — `sentinel update --check --json` emits ADR 0004 §D2 versioned envelope (`kind=update_check`) for scripting.
- **ADR 0010** — freezes self-update interface, version comparison strategy, daemon restart sequence, menu bar UI, and CLI surface. Tracks A (detection + `--check`) and B (apply + daemon restart) separate; C (menu bar) deferred to v0.11 pending B merge.

## [0.9.0] - 2026-05-05

The "polish + performance" release. Two themes — measurable
performance + UX (Tracks 1 & 3) and tooling/type-safety ratchet
(Track 2) — shipped over ~10 PRs since v0.8.0. 680 tests → 779
(+99). Two new ADRs (0008 — Notification Context Level, 0009 —
Backup Retention Policy) and one §D4 amendment (ADR 0007 —
mtime invalidation for ProjectContext) freeze the contracts that
landed this cycle. The mypy/ruff floor is now strict enough that
new untyped code or mutable-default-arg bugs fail CI.

### Highlights for users

- **Real false-positive fix for the `Suspected Stuck Process`
  warning** — the heuristic now consults the agent log parser's
  most-recent user/assistant message timestamp before firing, so
  long interactive sessions (local model thinking, batch
  processing) with high CPU + low network are no longer flagged
  as runaway when there has been activity in the last 5 minutes.
  The alert still fires when the session is truly idle.
- **`sentinel --version` is now a fast sanity check** — first
  line keeps the legacy `sentinel-mac X.Y.Z` shape for grep, but
  three new lines below report config path, data dir, daemon
  status (with PID), and Claude Code hook installation. Each
  enrichment line degrades to a short "not …" status on missing
  files / permission errors instead of crashing — `sentinel
  doctor` is still the right surface for full diagnosis.
- **Three notification context levels** — new
  `notifications.context_level` config key with `minimal` /
  `standard` / `full`. Default `standard` matches v0.8.0 alert
  text exactly (no upgrade-time surprise). `full` adds the git
  `Repo: owner/repo` line under `Project:`; `minimal` strips the
  whole `[ctx]` block for privacy-strict setups. Unknown values
  fall back to `standard` with a `WARNING`.
- **`sentinel doctor --cleanup-backups --keep N`** — user-initiated
  cleanup for `<config>.bak.<epoch>` files. `--keep` is mandatory
  (no safe default), interactive `[y/N]` prompt unless `--yes`,
  non-TTY stdin auto-cancels with a `WARNING` so cron jobs never
  hang. JSON envelope `kind=backup_cleanup` matching ADR 0004 §D2.
- **Faster `git checkout` reaction in alert ctx** — ProjectContext
  now `os.stat()`s `<root>/.git/HEAD` on every `lookup()` and drops
  cached entries when `st_mtime_ns` advances. Branch / head changes
  show up immediately in alerts instead of waiting for the 5-min
  TTL. Non-git projects skip the check.
- **Typosquatting list refreshed** to the 2026-05 PyPI top-300
  snapshot.

### Changed (v0.9 Track 2c)
- mypy ratchet: `disallow_untyped_defs = true`. Every `def` in
  `sentinel_mac/` now carries parameter and return-type
  annotations; future PRs that add an unannotated function will
  fail mypy. 48 missing annotations were added across 9 files
  (`core.py`, `menubar_app.py`, `collectors/agent_log_parser.py`,
  `collectors/fs_watcher.py`, `notifier.py`, `event_logger.py`,
  `commands/doctor.py`, `collectors/system.py`,
  `collectors/net_tracker.py`).
- The Track 2 ratchet sequence (Track 2a ruff `B`/`UP`/`SIM`,
  Track 2b `check_untyped_defs`, Track 2c `disallow_untyped_defs`)
  is now complete.
- `EventLogger.__init__(data_dir)` is now annotated
  `Union[str, Path]` to match the test fixtures that pass
  `tempfile.mkdtemp()` strings — runtime accepted both before, the
  signature was the lie.
- `Sentinel._pid_file` is annotated `Optional[IO[str]]` so the
  flock handle adoption path (`adopt_lock`, `_acquire_lock`) is
  type-safe end-to-end.
- All rumps callbacks (`_on_quit`, `_on_tick`, `_on_toggle_rule`,
  …) take `sender: Any` because rumps ships no type stubs and the
  runtime accepts the same untyped object the caller passes
  through `callback=`.

### Changed (v0.9 Track 2b)
- mypy ratchet: `check_untyped_defs = true` (was `false`). All
  untyped function bodies are now type-checked across the
  codebase. The four modules behind the
  `[[tool.mypy.overrides]] ignore_errors = true` block (`core`,
  `menubar_app`, `agent_log_parser`, `fs_watcher`) all lost the
  override in this PR — the override block itself was removed
  from `pyproject.toml`:
    - `fs_watcher`: override removed; 5 mypy errors fixed
      (`Observer` is a watchdog factory binding, not a class —
      `_observer` re-typed against `BaseObserver`; `detail` dict
      annotated `dict[str, object]` so a project_meta dict can
      coexist with bool flags per ADR 0007 §D3 contract;
      `sorted(..., key=dict.get)` replaced with a lambda since
      `dict.get` returns `Optional[V]` which is not sortable).
    - `menubar_app`: override removed; 3 errors fixed
      (`Sentinel(config_path=...)` signature corrected to
      `Optional[str]` to match its actual call sites; two stale
      `# type: ignore[attr-defined]` comments — left over from
      when rumps had no stubs — dropped because rumps is now
      `Any` and the comments were flagged as unused).
    - `core`: override removed; 13 errors fixed (`DEFAULT_CONFIG`
      annotated `dict[str, Any]` so `.copy()` and `**unpack`
      work; three `Foo | None` instance-var annotations rewritten
      as `Optional[Foo]` because `python_version = "3.9"`
      rejects PEP 604 in mypy even though the runtime tolerates
      it inside method bodies; `resolve_config_path` /
      `load_config` defaults corrected to `Optional[...]` to
      match the documented "None means use defaults" behavior).
    - `agent_log_parser`: override removed; 1 error fixed
      (`events: list[SecurityEvent] = []` annotation in
      `_check_typosquatting`).
- The earlier 3-step pre-mypy fixes (`event_logger._current_file:
  Optional[IO[str]]`, `notifier._retry_queue:
  deque[tuple[Alert, int]]`) are not behavior changes either —
  they only narrow types that were previously inferred as `Any`.
- All 779 pytest tests pass; ruff is clean. No public API or
  on-disk schema changes; the only signature touched is
  `Sentinel.__init__(config_path)` and `resolve_config_path` /
  `load_config`, all three of which always accepted `None` at
  runtime — the annotations were the bug.

### Changed (v0.9 Track 2a)
- Ruff lint ratchet — added rule sets:
  - `B` (bugbear) — surface real bugs (mutable default args,
    unused loop variables, raise-from, etc.).
  - `UP` (pyupgrade) — Python 3.8+ syntax modernization
    (`Optional[X]` → `X | None` under
    `from __future__ import annotations`, `open(..., "r")` →
    `open(...)`, `str.format` → f-string).
  - `SIM` (simplify) — minor cleanup (`try/except/pass` →
    `contextlib.suppress`, ternary collapses, nested-`if` flattening,
    `any(...)` collapses, Yoda-condition swaps).
  - 212 violations across the three rule sets were resolved
    (B: 1, UP: 106, SIM: 33 surface + 72 follow-ups via
    auto-fixers); 4 `# noqa: SIM115` annotations were retained
    with explicit rationale (long-lived daemon / app / log file
    handles whose ownership is intentionally hand-managed).
- Per-file-ignores cleanup — v0.6 Track C's temporary
  `sentinel_mac/{collectors,core,engine,models,notifier,menubar_app}`
  per-file `F401` / `F541` / `F841` / `I001` ignores were dropped:
  the underlying violations are gone after the auto-fix pass.
  `tests/*` keeps `E402` only (path-manipulation-then-import is a
  legitimate test pattern).

### Changed (v0.9 Track 1)
- Profile pass on three representative workloads (busy JSONL with
  1000 mixed Claude Code records, fs_watcher 100-event bulk_change
  spike, NetTracker 50-connection burst). Results captured at
  `docs/perf/v0.9-profile-2026-05-03.md` for future comparison;
  reproducible via `python3 scripts/profile_workload.py`.
- `_merge_joined_detail`: lock layering tightened. `EventLogger`
  gains `update_event_detail_by_id` which performs partial detail
  patches under the same lock as `write_event` (shared
  `_rewrite_one_locked` implementation). FSWatcher's download-join
  path now calls it instead of doing a two-phase
  read-then-wholesale-replace, so concurrent joins on the same
  `event_id` no longer have a last-write-wins window. The legacy
  `update_event_by_id` API is unchanged for back-compat.
- `_pending_downloads`: replaced inline-only GC at register/lookup
  time with a 30-second background sweeper thread owned by
  `FSWatcher.start()`/`stop()`. Memory bound is now deterministic
  regardless of register frequency or whether matching fs events
  ever arrive. `sweeper_interval_seconds` is configurable under
  `security.download_tracking` (default 30s; tests use 50ms).
- `_extract_url` consolidated. A new single-token recognizer
  `_token_as_url(str)` is now shared by `_extract_url`,
  `_extract_curl_download`, and `_extract_wget_download` (each
  previously had its own copy of `tok.startswith(("http://", …))`
  and could drift independently). Drift risk eliminated; the only
  externally observable change is that quote-wrapped URL tokens
  (`'https://x.com/y'` from a logging shell) are now recognized in
  the curl `-o` and wget `-O` flag-loop bodies, matching the
  pre-existing redirect-only-branch behavior.
- `update_event_by_id` O(N) JSONL rewrite kept as-is. The
  2026-05-03 profile pass showed it sub-millisecond on
  representative workloads (top-20 cumulative entries did NOT
  include it on any of the three scenarios; a hand-shaped trace of
  a 1000-line rewrite stayed at ~1.2ms). An inline `MONITOR`
  comment at the function explains the deferral with a back-link
  to the profile report. The in-memory `event_id → line_offset`
  index remains the right answer if a future profile pass shows
  this call in the top-20.

### Added (v0.9 Track 3b)
- stuck_process false-positive fix (PR #28 follow-up): the
  AlertEngine now consults the agent log parser's last
  user/assistant message timestamp before firing the "Suspected
  Stuck Process" warning. Active interactive sessions (local
  models thinking, batch processing) with high CPU + low network
  no longer false-positive when there has been agent activity in
  the last 5 minutes. The heuristic still fires when the session
  is truly idle (no recent messages + sustained high CPU + near-zero
  network). Wired via a new `AlertEngine.set_agent_activity_callback`
  setter; existing callers / tests that build a bare `AlertEngine`
  see no behavior change because the callback defaults to None
  (legacy CPU+net heuristic preserved).
- `sentinel --version` now prints the config path, data dir,
  daemon status (with PID when readable), and Claude Code hook
  installation state in addition to the version string. The first
  line still matches the legacy `sentinel-mac X.Y.Z` shape so
  scripts that grep the version out keep working. Each subsequent
  line is best-effort — missing files / permission errors degrade
  to a short "not …" / "unknown" status instead of crashing the
  command. Use this for fast sanity checks; `sentinel doctor` is
  still the right surface for full diagnosis with remediation.

### Changed (v0.9 Track 3b)
- `install.sh` now opens with a comment recommending `pipx install
  sentinel-mac` for most users while explicitly listing the cases
  where install.sh is still the right choice (launchd auto-setup,
  shell-alias install, source-tree development). The same nudge
  appears as a one-line note under the README Quick Start
  "Option 2" header. Per the Q3 user signal, install.sh remains
  fully supported with no deprecation warning printed at runtime —
  the comment / README note is the only behavior change.

### Added (v0.9 Track 3a)
- ADR 0008 implementation: `notifications.context_level` config key
  with three values (`minimal` / `standard` / `full`). Default
  `standard` matches v0.8.0 behavior; `full` adds a "Repo:
  owner/repo" line under `Project:` in the alert `[ctx]` block;
  `minimal` strips the entire `[ctx]` block from alerts. Unknown
  values fall back to `standard` with a `WARNING` (fail-soft per
  ADR 0005 §D3 — also normalized at SIGHUP reload time, never
  aborts the reload).
- ADR 0009 implementation: `sentinel doctor --cleanup-backups
  --keep N [--dry-run] [--yes]` for user-initiated config-backup
  cleanup. Mandatory `--keep` (no safe default), interactive
  `[y/N]` prompt unless `--yes`, non-TTY stdin auto-cancels with
  stderr `WARNING` (cron-safe — never hangs), JSON envelope
  `kind=backup_cleanup` matching ADR 0004 §D2. Exit codes 0 / 1 / 2
  per ADR 0009 §D7. Mutually exclusive with the standard 9-check
  doctor mode.
- ADR 0007 §D4 amendment implementation: `ProjectContext` now
  `os.stat()`s `<root>/.git/HEAD` on every `lookup()` and drops
  cached entries when `st_mtime_ns` advances — `git checkout`
  shows up immediately instead of waiting for the 5-min TTL.
  Non-git projects skip the check; `os.stat` failures fall back
  silently to TTL behavior with a single DEBUG log line per cwd
  per session. Public API unchanged (additive amendment).

### Added (v0.9 freeze)
- **ADR 0008 — Notification Context Level**. Freezes the new
  `notifications.context_level` setting (`minimal` / `standard` /
  `full`). Default `standard` matches v0.8.0 alert text exactly
  (no upgrade-time surprise). `full` opts in to a `Repo:
  owner/repo` line under `Project:`, narrowing the ADR 0007 §D7
  "git.remote audit-log-only forever" commitment to "audit-log-only
  in `minimal` and `standard` modes only". `minimal` strips the
  entire `[ctx]` block from the alert body for privacy-strict
  setups. Single global key (no per-channel granularity yet).
  Validation is fail-soft (unknown value → `standard` + WARNING).
  Implementation in v0.9 Track 3.
- **ADR 0009 — Backup Retention Policy**. Freezes `sentinel doctor
  --cleanup-backups --keep N`, the user-initiated counterpart to
  ADR 0006 §D5's "backups never auto-deleted by the daemon". `--keep`
  is mandatory (no safe default — explicit user intent required).
  Selection sorts the `<config>.bak.<epoch>` files by the trailing
  integer in the filename (mtime ignored). Interactive `[y/N]`
  prompt by default, `--yes` to skip, `--dry-run` to preview.
  JSON envelope `kind=backup_cleanup` matching ADR 0004 §D2.
  Exit codes 0 / 1 / 2. Implementation in v0.9 Track 3.
- **ADR 0007 §D4 amendment — mtime invalidation**. Adopts the
  "v0.9 candidate" inline note: ProjectContext now stat()s
  `<root>/.git/HEAD` on each `lookup()` and drops cached entries
  when `st_mtime_ns` advances, so `git checkout`-driven
  branch/head changes show up immediately instead of waiting for
  the 5-min TTL. Additive amendment — public API unchanged, no
  supersede required. The 5-min TTL stays as the second-line
  guard for non-git changes.

## [0.8.0] - 2026-05-02

The "polish + performance" release. Three themes — context-aware
detection (v0.6), user-facing power features (v0.7), and operational
correctness + forensic visibility (v0.8) — shipped over 17 PRs since
v0.5.3. 256 tests → 680 (+424). Seven Architecture Decision Records
(ADR 0001–0007) freeze the contracts that future contributors must
not silently break.

### Highlights for users

- **Smart alerts** — `~/.ssh/known_hosts` and frequency learning let
  Sentinel downgrade alerts on hosts you have actually been working
  with. Off by default; opt in via `security.context_aware.enabled`.
- **Forensic context in every alert** — when a typosquat, MCP
  injection, or sensitive write fires, the alert now answers WHO /
  WHERE / WHAT / HOW with project name, git branch + commit, Claude
  Code session id + model, and the cwd at the time of the command.
- **Real-time daemon reload** — `sentinel context block evil.com`
  takes effect sub-second, no `sentinel restart` needed (SIGHUP).
- **`sentinel doctor`** — one-shot health check across daemon,
  config, permissions, hooks, cache integrity, and dependencies.
- **`sentinel context …` CLI** — `status` / `forget` / `block` /
  `unblock` for the host-trust cache, with `--json` output.
- **Filtered audit reports** — `sentinel --report --since 7d
  --severity critical --type agent_command --json` for triage
  (versioned envelope per ADR 0004 §D2).
- **Download tracking** — `curl -o`, `wget`, `git clone` source URL
  is paired with the resulting file via a 5-minute FSWatcher join.
- **`pip install sentinel-mac`** (no extras) is now sufficient for
  the full mutating-CLI surface — `block`/`unblock` automatically
  fall back to PyYAML if `[app]`'s ruamel is missing.
- **Privacy promise unchanged** — nothing leaves your machine
  unless you opt in. Even the alert `[ctx]` block omits the git
  remote URL by design.

### Added (v0.8 Track 2 freeze)
- ADR 0007 — Forensic Context Enrichment. Direct response to a user
  report ("로그에서 알 수 있는 정보들이 너무 한정적이야 … 누가, 어느
  프로젝트에서, 뭐를 어떻게"): freezes the contract for surfacing
  **who / where / what / how** in both the audit log and the
  user-visible Alert message. `detail.session` (Claude Code session
  id / model / version / cwd) and `detail.project_meta` (project
  name / root / git branch / head / remote) added to every relevant
  SecurityEvent. New `[ctx]` block in Alert messages renders
  `Project:` / `Session:` / `Where:` / `What:` lines (with macOS
  truncation guards). Privacy boundary: `git.remote` is
  audit-log-only, never sent to opt-in notification channels
  (ntfy / Slack / Telegram). The legacy `bulk_change.detail.project`
  string field is preserved untouched — the new structured field is
  named `project_meta` per ADR 0004 §D3 (no key repurposing).
  Implementation in v0.8 Track 2.

### Fixed
- Typosquatting detector no longer false-positives on package-like
  tokens that appear inside quoted strings (e.g., `git commit -m "...pip
  install foo..."` was previously treating "foo" as an install
  candidate). Token extraction now uses `shlex.shlex` with
  `punctuation_chars=True` to respect quotes AND correctly tokenize
  shell operators without surrounding whitespace
  (`pip install foo&&pip install bar`, `pip install requets;rm -rf /`).
  Redirect / pipe targets (`pip install foo > out.txt`,
  `... | tee log`) are no longer mistaken for package names. Each
  candidate is validated against PEP 503 / npm naming rules and pure
  numeric tokens are rejected. Resolves a 20-event false-positive
  burst observed during the v0.7/v0.8 release work. The same fix
  applies to the `sentinel hooks install` Claude Code pre-tool-use
  hook (it shares the extractor) — commit messages no longer trigger
  the hook either.
- Typosquatting `risk_score` is now set by the collector before the
  event is written to the JSONL audit log, so `sentinel --report
  --severity critical` correctly surfaces high-confidence typosquatting
  events. Previously the engine mutated `risk_score` post-write so the
  audit log stored 0 (severity "info") while the desktop alert showed
  "critical". Other event types (`agent_command`, `agent_tool_use`,
  `mcp_injection_suspect`, `mcp_tool_call`) still have the same
  collector-vs-engine `risk_score` divergence — tracked as a v0.8
  Track 2 follow-up; only `typosquatting_suspect` is fixed in this
  patch because it is the one currently observed in production.
- Audit log severity now matches user-visible alert severity for the
  remaining 4 event types (`agent_command`, `agent_tool_use`,
  `mcp_injection_suspect`, `mcp_tool_call`) — same defect class as
  PR #18 typosquatting fix, applied to the rest of the agent_log
  pipeline. `sentinel --report --severity critical` now correctly
  surfaces high-risk Bash commands (curl-pipe-to-shell, rm -rf, eval,
  base64 -d, nc -l, inline code exec, arbitrary package installs) and
  MCP injection suspects; `--severity warning` surfaces sensitive
  file writes/reads; `--severity info` correctly buckets MCP tool
  calls and WebFetch events. SSH/SCP commands downgraded by host
  trust persist with `risk_score=0.2` (info) so the audit log mirrors
  the suppressed-alert state. Closes the v0.8 Track 2 follow-up TODO
  from PR #18.

### Added (v0.8 Track 1b)
- `sentinel doctor` — one-shot health check (daemon status, config
  validity, file permissions, hook installation, cache integrity,
  backup file accumulation, optional dependencies). Text output by
  default, `--json` envelope (kind=`health_check`) for tooling.
- ruamel→PyYAML automatic fallback for `sentinel context block /
  unblock` (ADR 0006). `pip install sentinel-mac` (no extras) is now
  sufficient for the full mutating-CLI surface; the `[app]` extra
  remains the preferred path because PyYAML loses comments.

### Changed (v0.8 Track 1b)
- ADR 0003 §D6 exit code 3 for the ruamel-missing case is superseded
  by ADR 0006 §D4: ruamel-missing now triggers automatic PyYAML
  fallback and returns exit 0 if the write succeeds. A single-line
  stderr warning surfaces the fallback + backup path. JSON envelope
  gains uniform additive fields `yaml_backend`, `backup_path`,
  `comment_preservation` on both backends (ADR 0006 §D3).
- README updated to drop the `[app]`-extra requirement note for
  `block`/`unblock` and to document `sentinel doctor`.

### Added (v0.8 Track 1a)
- SIGHUP-driven daemon reload (ADR 0005). The daemon now picks up
  `config.yaml` mutations without a restart. `sentinel context block /
  unblock / forget` automatically signals the running daemon via
  SIGHUP after the file write succeeds; manual `kill -HUP $(cat
  ~/.local/share/sentinel/sentinel.lock)` also works.
- Sub-second reload latency via a dedicated worker thread that
  `wait()`s on a `threading.Event`. Multiple SIGHUPs in rapid
  succession coalesce to one reload (event clear()ed before each
  iteration).
- Atomic-or-nothing reload (ADR 0005 §D3): config parse / validation
  / new-component construction are all done into local variables;
  only the final swap mutates `self.*`. Any failure leaves the
  daemon on the old config and logs a warning.
- `sentinel context` mutation envelopes gain an additive
  `daemon_reload` field per ADR 0005 §D7 with values
  `{"applied", "skipped_not_running", "failed_unreachable"}`.

### Changed (v0.8 Track 1a)
- `sentinel context block / unblock / forget` now print
  `Applied to running daemon (PID NNN).` (or
  `Daemon not reachable; restart manually...`) on stderr after the
  mutation, replacing the previous `Restart the daemon` notice.

### Changed (v0.8 Track 1c)
- Main loop and queue drainer now take `_reload_lock` briefly to
  snapshot live references (engine / host_ctx / event_logger /
  security_rules) at cycle start, ensuring a mid-cycle SIGHUP reload
  cannot surface partially-swapped state. Closes the inline TODO
  from PR #16 (Track 1a). Implements ADR 0005 §D5 verbatim
  (previously deferred to Track 1c). No user-visible behavior
  change — pure correctness reinforcement under concurrent reload.

### Added (v0.8 freeze)
- ADR 0005 — Daemon Reload Protocol. Freezes the SIGHUP-driven reload
  contract: which sources reload (config / known_hosts / host_context),
  which in-memory state survives (cooldowns / rate-limits / log offsets),
  the atomic-or-nothing failure mode, multi-SIGHUP coalescing, and the
  CLI integration that auto-signals the daemon after `sentinel context`
  mutations. Implementation in v0.8 Track 1.
- ADR 0006 — Config Mutation Fallback. Lifts ADR 0003 §D2's hard
  ruamel requirement: `sentinel context block` / `unblock` now falls
  back to PyYAML automatically when ruamel is missing, with a
  backup-then-write safety net, single-line stderr warning, and
  uniform `--json` envelope additions (`yaml_backend`, `backup_path`,
  `comment_preservation`). Supersedes ADR 0003 §D6 exit code 3 for
  the ruamel-missing case. Implementation in v0.8 Track 1.

### Added (v0.7 freeze)
- ADR 0002 — Agent Download Tracking. Freezes the new
  `agent_download` SecurityEvent type, detail schema, FSWatcher join
  logic (5-minute window), extraction patterns (curl / wget / git clone),
  and severity escalation rules. Implementation in v0.7 Track B.
- ADR 0003 — `sentinel context` CLI subcommands. Freezes the four
  verbs (`status` / `forget` / `block` / `unblock`), config-inline
  blocklist persistence via ruamel, daemon-independent operation,
  `--json` envelope, and exit-code map. Implementation in v0.7 Track C.
- ADR 0004 — Pro Branch Optionality. Cross-cutting constraints applied
  during v0.7 (and beyond unless superseded): no license plumbing
  until a Pro feature lands; all `--json` uses a versioned envelope
  (`{version, kind, generated_at, data}`); `SecurityEvent.detail`
  schemas are additive; blocklist / custom_rules / notification
  channels stay layer-able for future Pro extension; audit log
  forwarding wraps the OSS `event_logger`, never modifies it.

### Added
- HostContext API frozen for v0.6 context-aware detection
  (`sentinel_mac/collectors/context.py` skeleton). Opt-in, default OFF.
  4-level `TrustLevel`: UNKNOWN / LEARNED / KNOWN / BLOCKED. Negative
  override via config `blocklist:`. Implementation lands in a follow-up
  PR; signatures are frozen by [ADR 0001](docs/decisions/0001-host-context.md).
- ADR (Architecture Decision Records) directory at `docs/decisions/`.
  ADR 0001 captures v0.6 host-context decisions (Q1–Q5: 4-level enum,
  flush schedule, CLI deferral to v0.7, SSH/SCP-only scope, download
  tracking moved to v0.7).

### Deferred
- `sentinel context forget|block|list|status` CLI — moved to v0.7
  (see ADR 0001 D3).
- Download tracking (`curl -o`, `wget`, `git clone` source-URL ↔ output-path
  pairing) — moved to v0.7 as a side-track of the `--report` filter
  expansion (see ADR 0001 D5).

### Tooling
- Added `ruff` lint (lenient: `E`, `F`, `W`, `I` only; stricter rules
  ratcheted up in v0.8) and `mypy` type check (lenient: ignore_missing_imports,
  check_untyped_defs=false). Both run in CI on Python 3.9–3.13 matrix.

### Documentation
- Added "Privacy & Data" section to README.md and README_KR.md documenting
  exactly what Sentinel watches, what it writes to disk, and what leaves
  the machine (nothing by default — opt-in notification channels only).

### Fixed
- agent_download events were being logged to JSONL with correct risk
  scores but never converted to user-facing Alerts (PR #12 follow-up).
  AlertEngine now dispatches agent_download to critical / warning / info
  per ADR 0002 §D5 severity matrix.

## [0.5.3] - 2026-04-30

### Added
- Agent log parser now flags `Read` and `Edit` tool calls against sensitive files
  (previously only `Write` was checked)
- Sensitive-file detection broadened to filename patterns: `.env*`, `*.pem`,
  `*.key`, `id_rsa/dsa/ecdsa/ed25519`, `.netrc`, `credentials`, `.secret(s)`,
  `*.p12`, `*.pfx` — catches project-level secrets, not just home-directory ones

### Fixed
- AI process scan now detects Claude Code's VS Code extension native binary
  (process name `claude`). The unambiguous-binary CPU floor is also relaxed so
  idle AI processes still appear in `--once` mode

### Changed
- Refreshed PyPI typosquatting reference list to top-300 (2026-04 snapshot,
  +95 packages including `google-genai`, `uv`, `mcp`, opentelemetry exporters)

### Added
- Config validation with safe range clamping
- Security posture monitoring (Firewall, Gatekeeper, FileVault)
- Unit test suite (46 tests covering alerts, config, notifier)
- GitHub Actions CI (Python 3.9–3.13 on macOS)
- GitHub Actions PyPI auto-publish on release
- CHANGELOG.md and CONTRIBUTING.md

### Fixed
- Lock file directory not created before first daemon startup
- Battery drain rate crash when battery_percent is None
- Cooldown timestamps now use metric timestamp for consistent behavior

### Changed
- All alert messages translated from Korean to English
- README translated to English for global audience

## [0.1.0] - 2025-07-15

### Added
- Initial release
- Battery, thermal, memory, disk, network monitoring
- 3-tier AI process detection (process name → cmdline keyword → any cmdline)
- Smart composite alerts (critical, warning, info)
- Night watch mode (12AM–6AM unattended session detection)
- ntfy.sh push notifications with retry queue
- Per-category alert cooldowns (critical alerts get 1/3 shorter cooldown)
- Hourly status reports
- Log rotation (5MB x 3 files)
- Single-instance PID file lock
- Config file with XDG path resolution and default fallback
- `sentinel --once` one-shot system snapshot
- `sentinel --test-notify` notification test
- `sentinel --init-config` auto-generate config with unique topic
- `install.sh` one-command setup with launchd auto-start
- `uninstall.sh` clean removal
- PyPI package: `pip install sentinel-mac`

[Unreleased]: https://github.com/raunplaymore/sentinel/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/raunplaymore/sentinel/compare/v0.5.3...v0.8.0
[0.5.3]: https://github.com/raunplaymore/sentinel/releases/tag/v0.5.3
[0.1.0]: https://github.com/raunplaymore/sentinel/releases/tag/v0.1.0
