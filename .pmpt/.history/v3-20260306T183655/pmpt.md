# sentinel

## Product Idea
watch things for safe computing.

## Additional Context
Existing project with established codebase.
- Git history: 2 commits since 2026-02-27, 1 contributor(s)
- Recent work: "Translate README to English + add social preview image", "Initial release v0.1.0 — AI Session Guardian for macOS"

## Features
- [x] Existing project features

## Architecture Decisions
- Keep the existing runtime pipeline: `MacOSCollector -> AlertEngine -> NtfyNotifier -> Sentinel loop`.
- Extend `SystemMetrics` with safe-computing posture signals: `firewall_enabled`, `gatekeeper_enabled`, and `filevault_enabled`.
- Use best-effort command probes on macOS (`socketfilterfw`, `spctl`, `fdesetup`) and treat unknown states as non-alerting to avoid false positives.
- Aggregate disabled controls into a single `security_posture` alert category with cooldown handling.
- **Option 3 — Layered Architecture**: Keep existing system monitor as "system layer", add "AI security layer" on top as separate modules.
- Refactored monolithic `core.py` into modular structure: `models.py`, `collectors/system.py`, `engine.py`, `notifier.py`. core.py re-exports for backward compatibility.
- New `SecurityEvent` data model for all security collectors (FSWatcher, NetTracker, AgentLogParser).
- Phase 2 ready: SecurityEvents will be logged as JSONL for future team dashboard integration.

## Progress
- [x] Project setup
- [x] Core features implementation
- [x] Testing & polish
- [x] AI Security Layer spec design
- [x] Modular refactor (core.py split into models/collectors/engine/notifier)
- [x] FSWatcher — file access monitoring (Priority 1)
- [ ] NetTracker — per-process network tracking (Priority 2)
- [ ] AgentLogParser — Claude Code/Cursor log parsing (Priority 3)

## Snapshot Log
### v1 - Initial Setup
- Project initialized with pmpt

### v2 - Security Posture Watch
- Added security posture monitoring for Firewall, Gatekeeper, and FileVault.
- Added `security_posture` alert generation and surfaced security status in periodic reports and `--once` output.
- Added alert tests for security posture scenarios and fixed two baseline regressions (`load_config` non-mapping YAML handling, cooldown timestamp behavior).
- Test result: `46 passed`.

### v3 - AI Security Layer Foundation
- Decided on Option 3: layered architecture (system layer + AI security layer).
- Created AI Security Layer spec (`ai-security-layer-spec.md`): FSWatcher, NetTracker, AgentLogParser.
- Refactored `core.py` into modular structure: `models.py`, `collectors/system.py`, `engine.py`, `notifier.py`.
- core.py re-exports all symbols for backward compatibility — all 46 tests pass unchanged.
- Added `SecurityEvent` data model for upcoming security collectors.
- New dependency planned: `watchdog>=3.0` for FSEvents file monitoring.

### v4 - FSWatcher Implementation
- Implemented `collectors/fs_watcher.py`: watchdog Observer + lsof-based process attribution.
- Detects sensitive path access (~/.ssh, .env), executable file creation, AI process file activity, bulk changes.
- Added `evaluate_security_event()` to AlertEngine for SecurityEvent -> Alert conversion with cooldown.
- Integrated FSWatcher into Sentinel daemon via shared `queue.Queue` + `_process_security_events()` drain loop.
- Added `security.fs_watcher` config section to config.yaml.
- 27 new tests (filtering, AI detection, event generation, lifecycle, alert conversion).
- Test result: `73 passed` (46 existing + 27 new).
- New dependency: `watchdog>=3.0`.

---
*This document tracks your project progress. Update it as you build.*
*AI instructions are in `pmpt.ai.md` — paste that into your AI tool.*
