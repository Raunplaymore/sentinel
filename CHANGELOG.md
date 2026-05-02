# Changelog

All notable changes to Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
