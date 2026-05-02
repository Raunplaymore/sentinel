# Changelog

All notable changes to Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/raunplaymore/sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/raunplaymore/sentinel/releases/tag/v0.1.0
