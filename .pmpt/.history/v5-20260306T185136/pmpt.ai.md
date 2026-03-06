<!-- This file is for AI tools only. Do not edit manually. -->
<!-- Paste this into Claude Code, Codex, Cursor, or any AI coding tool. -->

# Sentinel -- AI Agent Security Guardian for macOS

## What This Project Is

Sentinel is a macOS daemon that monitors system resources AND AI agent behavior, sending smart alerts to your phone via ntfy.sh. It has two layers:

1. **System Layer** -- CPU, battery, thermal, memory, disk, network monitoring with configurable thresholds
2. **AI Security Layer** -- file system watching, network connection tracking, and AI agent log parsing to detect risky behavior

The project is a solo developer tool now, with a clear path to team/enterprise (Phase 2: team dashboard via JSONL event upload).

## Current State (v6 snapshot, 127 tests passing)

All 3 security collectors are implemented and tested:
- **FSWatcher**: watchdog-based file system monitoring with sensitive path detection, AI process attribution via lsof
- **NetTracker**: psutil.net_connections polling with reverse DNS, allowlist matching, duplicate dedup
- **AgentLogParser**: Claude Code JSONL tail-f parser with 14 high-risk command patterns

## Project Structure

```
sentinel_mac/
  core.py                  -- Sentinel daemon, config resolution, CLI entry point
                              Re-exports all symbols from submodules for backward compatibility
  models.py                -- SystemMetrics, Alert, SecurityEvent dataclasses
  engine.py                -- AlertEngine: evaluates metrics + security events, generates Alerts
                              Dispatches by source: _evaluate_fs_event, _evaluate_net_event, _evaluate_agent_log_event
  notifier.py              -- NtfyNotifier: HTTP push to ntfy.sh with retry queue
  collectors/
    system.py              -- MacOSCollector: psutil + macOS native commands (pmset, powermetrics, etc.)
    fs_watcher.py          -- FSWatcher: watchdog Observer in background thread
                              Sensitive paths, AI process detection, executable detection, bulk change detection
    net_tracker.py         -- NetTracker: polling-based, runs in main loop (not threaded)
                              Allowlist with fnmatch wildcards, reverse DNS cache, 5-min dedup TTL
    agent_log_parser.py    -- AgentLogParser: background thread, 3s polling interval
                              Tail-f style reading, HIGH_RISK_PATTERNS regex, tool_use parsing

tests/
  test_alerts.py           -- 26 tests: battery, thermal, memory, disk, network, session, security posture
  test_config.py           -- 11 tests: config loading, validation, path resolution
  test_notifier.py         -- 6 tests: send, retry, priority mapping
  test_fs_watcher.py       -- 27 tests: filtering, AI detection, event handling, lifecycle, alert conversion
  test_net_tracker.py      -- 23 tests: allowlist, AI detection, DNS, polling, alert evaluation
  test_agent_log_parser.py -- 31 tests: high-risk patterns, JSONL processing, lifecycle, tail-f, alerts

config.yaml                -- Full configuration with security section
.pmpt/docs/
  pmpt.md                  -- Human-facing project document (progress, architecture decisions)
  ai-security-layer-spec.md -- Original spec document for the AI security layer
```

## Key Architecture Decisions (reference pmpt.md for full rationale)

1. **Layered Architecture**: System layer (unchanged) + AI Security layer (new modules). Chosen over monolithic integration or separate daemon.
2. **SecurityEvent common model**: All 3 collectors emit the same dataclass. `detail: dict` for source-specific data. JSON-serializable for Phase 2.
3. **queue.Queue event bus**: Thread-safe, stdlib-only. Collectors push, main loop drains up to 100/cycle.
4. **watchdog for FSEvents**: Stable, maintained, cross-platform. Combined with lsof for best-effort process attribution.
5. **Polling for NetTracker**: psutil.net_connections is snapshot-only. Runs in main loop, no extra thread.
6. **Tail-f polling for AgentLogParser**: 3s interval, tracks file positions per session file. Skips pre-existing content on first scan.
7. **Re-export pattern in core.py**: `from sentinel_mac.core import X` still works after refactor. Zero test changes needed.
8. **Pre-compiled regex patterns**: 14 HIGH_RISK_PATTERNS compiled at module load for performance.
9. **Category-based cooldown**: Same-category alerts suppressed for configurable duration. Critical gets 1/3 shorter cooldown.

## Runtime Flow

```
Main loop (30s):
  1. MacOSCollector.collect() -> SystemMetrics
  2. AlertEngine.evaluate(metrics) -> [Alert]
  3. NetTracker.poll() -> SecurityEvent -> queue
  4. _process_security_events(): drain queue -> AlertEngine.evaluate_security_event() -> [Alert]
  5. NtfyNotifier.send(alert) for each alert
  6. Status report if interval elapsed

Background threads:
  - FSWatcher: watchdog Observer -> _handle_fs_event() -> SecurityEvent -> queue
  - AgentLogParser: 3s poll -> _scan_claude_code_logs() -> parse_line() -> SecurityEvent -> queue
```

## Config Structure (config.yaml)

Top-level: ntfy_topic, ntfy_server, notifications_enabled, check_interval_seconds, status_interval_minutes, cooldown_minutes
thresholds: battery_warning/critical/drain_rate, temp_warning/critical, memory_critical, disk_critical, network_spike_mb, session_hours_warning
security:
  enabled, fs_watcher (watch_paths, sensitive_paths, ignore_patterns, bulk_threshold/window),
  net_tracker (alert_on_unknown, allowlist),
  agent_logs (parsers: [{type, log_dir}])

## Dependencies

Runtime: psutil>=5.9, pyyaml>=6.0, requests>=2.28, watchdog>=3.0
Dev: pytest>=7.0

## Conventions

- Tests use `queue.Queue` + direct method calls for unit testing (no threads needed)
- Config passed as dict to all constructors
- SecurityEvent.source determines which AlertEngine._evaluate_*_event() handles it
- Alert.category used for cooldown deduplication
- All security collectors gracefully handle missing paths/permissions (warn, don't crash)

## What's Next (pending tasks)

1. **JSONL event logging** -- Write SecurityEvents to daily JSONL files (`~/.local/share/sentinel/events/YYYY-MM-DD.jsonl`) for Phase 2 team dashboard prep
2. **Integration test** -- End-to-end: config -> collectors -> queue -> engine -> notifier flow
3. **Cursor/VS Code log parser** -- Extend AgentLogParser with additional parser types
4. **MCP injection detection** -- Pattern matching on MCP server calls in agent logs (Phase 3)
5. **pyproject.toml version bump** -- Update to reflect security layer additions
6. **README update** -- Document the AI Security Layer features

---

## Documentation Rule

**Important:** When you make progress, update `.pmpt/docs/pmpt.md` (the human-facing project document) at these moments:
- When architecture or tech decisions are finalized (add to Architecture Decisions with rationale)
- When a feature is implemented (mark as done in Progress)
- When a development phase is completed (add to Snapshot Log)
- When requirements change or new decisions are made

Keep the Progress and Snapshot Log sections in pmpt.md up to date.
After significant milestones, run `pmpt save` to create a snapshot.

### Per-Feature Checklist
After completing each feature:
1. Mark the feature done in `.pmpt/docs/pmpt.md`
2. Add a brief note to the Snapshot Log section
3. Run `pmpt save` in terminal
