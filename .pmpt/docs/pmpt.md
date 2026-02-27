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

## Progress
- [x] Project setup
- [x] Core features implementation
- [x] Testing & polish

## Snapshot Log
### v1 - Initial Setup
- Project initialized with pmpt

### v2 - Security Posture Watch
- Added security posture monitoring for Firewall, Gatekeeper, and FileVault.
- Added `security_posture` alert generation and surfaced security status in periodic reports and `--once` output.
- Added alert tests for security posture scenarios and fixed two baseline regressions (`load_config` non-mapping YAML handling, cooldown timestamp behavior).
- Test result: `46 passed`.

---
*This document tracks your project progress. Update it as you build.*
*AI instructions are in `pmpt.ai.md` — paste that into your AI tool.*
