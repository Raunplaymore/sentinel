<!-- This file is for AI tools only. Do not edit manually. -->
<!-- Paste this into Claude Code, Codex, Cursor, or any AI coding tool. -->

# Sentinel -- AI Agent Security Guardian for macOS

## What This Project Is

Sentinel is a macOS daemon that monitors system resources AND AI agent behavior, sending smart alerts when something critical happens. It has two layers:

1. **System Layer** -- CPU, battery, thermal, memory, disk, network monitoring with configurable thresholds
2. **AI Security Layer** -- file system watching, network connection tracking, and AI agent log parsing to detect risky behavior

The project is a solo developer tool now, with a clear path to team/enterprise (Phase 2: team dashboard via JSONL event upload).

## Current State (v8 snapshot, 155 tests passing)

All core features implemented:
- **3 security collectors**: FSWatcher, NetTracker, AgentLogParser
- **Multi-channel notifications**: macOS native (default), ntfy.sh (opt-in), Slack (opt-in)
- **Critical-only alerting**: only critical events push notifications; warning/info are JSONL-logged only
- **JSONL event audit log**: all SecurityEvents recorded to daily files for Phase 2 prep
- **Integration tests**: end-to-end event flow verified

## Project Structure

```
sentinel_mac/
  core.py                  -- Sentinel daemon, config resolution, CLI entry point
                              Re-exports all symbols from submodules for backward compatibility
  models.py                -- SystemMetrics, Alert, SecurityEvent dataclasses
  engine.py                -- AlertEngine: evaluates metrics + security events, generates Alerts
                              Dispatches by source: _evaluate_fs_event, _evaluate_net_event, _evaluate_agent_log_event
  notifier.py              -- NotificationManager + channel backends:
                              MacOSNotifier (osascript), NtfyNotifier (HTTP), SlackNotifier (webhook)
                              Core rule: only critical alerts are pushed. Warning/info logged only.
  event_logger.py          -- EventLogger: append-only daily JSONL files for audit trail
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
  test_notifier.py         -- 23 tests: NtfyNotifier (5), MacOSNotifier (4), SlackNotifier (2), NotificationManager (12)
  test_fs_watcher.py       -- 27 tests: filtering, AI detection, event handling, lifecycle, alert conversion
  test_net_tracker.py      -- 23 tests: allowlist, AI detection, DNS, polling, alert evaluation
  test_agent_log_parser.py -- 31 tests: high-risk patterns, JSONL processing, lifecycle, tail-f, alerts
  test_integration.py      -- 11 tests: EventLogger (6), end-to-end security event flow (5)

config.yaml                -- Full configuration with notifications + security sections
.pmpt/docs/
  pmpt.md                  -- Human-facing project document (progress, 12 architecture decisions)
  ai-security-layer-spec.md -- Original spec document for the AI security layer
```

## Key Architecture Decisions (reference pmpt.md AD-1 through AD-12)

1. **Layered Architecture (AD-1)**: System layer (unchanged) + AI Security layer (new modules).
2. **Modular refactor (AD-2)**: core.py split into 5 modules, re-exports for backward compatibility.
3. **SecurityEvent common model (AD-3)**: All 3 collectors emit the same dataclass. `detail: dict` for flexibility.
4. **watchdog for FSEvents (AD-4)**: Combined with lsof for best-effort process attribution.
5. **queue.Queue event bus (AD-5)**: Thread-safe, stdlib-only. maxsize=1000 as safety valve.
6. **Polling for NetTracker (AD-6)**: psutil.net_connections is snapshot-only. No extra thread.
7. **Tail-f polling for AgentLogParser (AD-7)**: 3s interval, skips pre-existing content on first scan.
8. **Pre-compiled regex (AD-8)**: 14 HIGH_RISK_PATTERNS compiled at module load.
9. **Category-based cooldown (AD-9)**: Critical gets 1/3 shorter cooldown.
10. **Re-export pattern (AD-10)**: `from sentinel_mac.core import X` still works after refactor.
11. **JSONL event logging (AD-11)**: Daily rotation, all events logged regardless of alert level.
12. **Multi-channel + Critical-only (AD-12)**: macOS native default, "value means enabled" pattern, critical-only push.

## Runtime Flow

```
Main loop (30s):
  1. MacOSCollector.collect() -> SystemMetrics
  2. AlertEngine.evaluate(metrics) -> [Alert]
  3. NetTracker.poll() -> SecurityEvent -> queue
  4. _process_security_events():
     - drain queue -> EventLogger.log(event)  [JSONL]
     - AlertEngine.evaluate_security_event() -> [Alert]
  5. NotificationManager.send(alert)  [critical only → channels, warning/info → log]
  6. NotificationManager.send_status(metrics) if interval elapsed  [bypasses level filter]

Background threads:
  - FSWatcher: watchdog Observer -> _handle_fs_event() -> SecurityEvent -> queue
  - AgentLogParser: 3s poll -> _scan_claude_code_logs() -> parse_line() -> SecurityEvent -> queue
```

## Config Structure (config.yaml)

```yaml
# Top-level
check_interval_seconds: 30
status_interval_minutes: 60
cooldown_minutes: 10

# Notifications — "value means enabled" pattern
notifications:
  macos: true                    # Default, no setup needed
  ntfy_topic: ""                 # Set value → ntfy enabled
  ntfy_server: "https://ntfy.sh"
  slack_webhook: ""              # Set URL → Slack enabled

# Thresholds
thresholds:
  battery_warning/critical/drain_rate, temp_warning/critical,
  memory_critical, disk_critical, network_spike_mb, session_hours_warning

# Security layer
security:
  enabled: true
  fs_watcher: { watch_paths, sensitive_paths, ignore_patterns, bulk_threshold/window }
  net_tracker: { alert_on_unknown, allowlist }
  agent_logs: { parsers: [{type, log_dir}] }
```

Legacy support: top-level `ntfy_topic` still works if `notifications.ntfy_topic` is not set.

## Dependencies

Runtime: psutil>=5.9, pyyaml>=6.0, requests>=2.28, watchdog>=3.0
Dev: pytest>=7.0

## Conventions

- Tests use `queue.Queue` + direct method calls for unit testing (no threads needed)
- Config passed as dict to all constructors
- SecurityEvent.source determines which AlertEngine._evaluate_*_event() handles it
- Alert.category used for cooldown deduplication
- Alert.level determines notification behavior: critical → push, warning/info → log only
- All security collectors gracefully handle missing paths/permissions (warn, don't crash)
- NotificationManager auto-detects channels from config values (no explicit enable flags)

## What's Next (pending tasks)

1. **Cursor/VS Code log parser** -- Extend AgentLogParser with additional parser types
2. **MCP injection detection** -- Pattern matching on MCP server calls in agent logs (Phase 3)
3. **pyproject.toml version bump** -- Update to reflect security layer additions + watchdog dep
4. **Telegram notification channel** -- Phase 2
5. **Team dashboard** -- JSONL upload + web aggregation (Phase 2)

---

## Documentation Rule

**Important:** When you make progress, update `.pmpt/docs/pmpt.md` at these moments:
- When architecture or tech decisions are finalized (add to Architecture Decisions with rationale)
- When a feature is implemented (mark as done in Progress)
- When a development phase is completed (add to Snapshot Log with test count)
- When requirements change or new decisions are made

Keep the Progress and Snapshot Log sections in pmpt.md up to date.
After significant milestones, run `pmpt save` to create a snapshot.

### Per-Feature Checklist
After completing each feature:
1. Mark the feature done in `.pmpt/docs/pmpt.md`
2. Add a brief note to the Snapshot Log section
3. Run `pmpt save` in terminal
