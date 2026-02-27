# Changelog

All notable changes to Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
