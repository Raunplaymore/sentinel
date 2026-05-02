# ADR 0002 — Agent Download Tracking (v0.7)

- **Status**: Accepted
- **Date**: 2026-05-02
- **Scope**: `sentinel_mac/collectors/agent_log_parser.py` (new event type),
  `sentinel_mac/collectors/fs_watcher.py` (join logic), `models.py` (no
  schema change — `SecurityEvent.event_type` already free-form string).
- **Supersedes**: —
- **Referenced by**: ADR 0001 §D5 ("Download tracking moved to v0.7")

## Context

Sentinel currently catches:
- `curl ... | sh` / `wget ... | bash` via `HIGH_RISK_PATTERNS` in
  `agent_log_parser` (alert fires).
- `pip install <pkg>` / `npm install <pkg>` via the same path + the
  typosquatting collector (alert fires).
- WebFetch tool calls via the agent log parser (URL logged).
- Any file creation via `FSWatcher` (file event logged, but **without**
  any link to the source URL).

Real gap: an AI agent runs `curl https://x/payload.tar.gz -o /tmp/x.tgz`
or `wget https://x/install.sh` or `git clone https://x/repo /tmp/repo`.
None of the existing patterns flag the *URL→file* relationship. The user
ends up with a suspicious file in `/tmp` and has to manually correlate
the Bash command timestamp with the FSWatcher event to figure out where
it came from.

This ADR freezes the schema + behavior for the new download-tracking
feature so v0.7 Track B and Track A (`--report --type download` filter)
can build against a stable contract.

## Decisions

### D1. New event type `agent_download` — additive, no existing-event mutation

A new `SecurityEvent.event_type` value `"agent_download"` is introduced
for the download case. The existing `agent_command` (Bash command match)
event continues to fire as before — we add a *second* event when the
command is identifiable as a download. Two events for one command is
intentional: keeps existing alert behavior intact (no regression on
`curl … | sh` detection, which is also a download in the technical
sense) and lets `--report --type download` filter cleanly.

Rationale for not mutating `agent_command`: the existing event detail
is consumed by AlertEngine, the menubar app, and JSONL audit log
readers. Mutating it would require coordinated migration; emitting a
new event type is forward-compatible and preserves OSS/Pro decoupling
(ADR 0004 D3).

### D2. Detail schema (additive only, never reuse keys)

`agent_download` event detail shape:

```json
{
  "source_url": "https://example.com/payload.tar.gz",
  "output_path": "/tmp/x.tgz",
  "downloader": "curl",                  // curl | wget | git | unknown
  "command": "curl -L https://...",      // raw matched command
  "high_risk": false,                    // true if host triggers existing rules
  "trust_level": "unknown",              // ADR 0001 host trust on URL host
  "joined_fs_event": null                // populated by D3 join, see below
}
```

Versioning: detail schema is **additive** — new keys may appear in
future releases, existing keys keep their meaning forever. ADR 0004 §D3
formalizes this for the entire project. Consumers (audit log readers,
`--report --json`, future Pro tooling) MUST tolerate unknown keys.

`joined_fs_event` is `null` initially and populated by the FSWatcher
join (D3) within a 5-minute window. Schema:

```json
{
  "ts": "2026-05-02T10:14:23",   // FSWatcher event timestamp
  "actor_pid": 12345,
  "actor_name": "curl",
  "size_bytes": 5242880          // file size at first observation
}
```

If no matching file event arrives within the window, `joined_fs_event`
stays `null` (the download still recorded the URL+output_path pair for
human review).

### D3. FSWatcher → agent_download join (5-minute window)

When `agent_log_parser` emits an `agent_download` event with a known
`output_path`, `FSWatcher` watches for a matching `file_create` (or
first `file_modify` if the file already existed) on that path within
the next 5 minutes. On match:

1. The match metadata (timestamp, PID, name, size) is stored as the
   `joined_fs_event` field on the *original* `agent_download` event
   in the daily JSONL (re-write the line — `event_logger` gains a
   small `update_event_by_id` helper).
2. The standalone `file_create` event is **suppressed** (still logged
   if the file is in a `sensitive_path`, but otherwise dropped to
   reduce noise — the `agent_download` event with `joined_fs_event`
   tells the same story).

The 5-minute window is a default (`security.download_tracking.join_window_seconds`,
configurable). Window cap: 30 minutes. Below 60 seconds the join becomes
flaky (slow downloads).

If the user disables `download_tracking` entirely (default OFF —
opt-in like v0.6 context), `agent_download` events still fire (they
are purely informational), but no JSONL rewrite happens and no
`file_create` suppression occurs.

> **Open question for v0.7 implementation** — how to identify the same
> event for in-place rewrite? Proposal: `event_logger` assigns a
> per-event UUID at write time; the join writes the matched line by
> seeking on UUID. This is implementation detail, not schema; can be
> finalized in the Track B PR.

### D4. Extraction patterns (Track B implementation contract)

Recognized download invocations:

| Tool | Pattern | Example |
|---|---|---|
| `curl` | `-o PATH` / `--output PATH` / `-O` (basename of URL) / `> PATH` redirect | `curl -L https://x/y.tgz -o /tmp/y.tgz` |
| `wget` | `-O PATH` / `--output-document=PATH` / no flag (basename of URL in cwd) | `wget https://x/install.sh` |
| `git clone` | second positional arg = target dir (or basename) | `git clone https://x/repo /tmp/repo` |

Out of scope (v0.7):
- `pip download` — already covered by typosquatting + install patterns
- `brew fetch` / `brew install` — installer manages location, low value
- `aria2c`, `axel`, `httpie`, `xh` — long tail, add per user request
- Shell redirect `> PATH` without `curl/wget` (e.g., `cmd > /tmp/x`) — too noisy

Extraction MUST be conservative — "no detection" is preferred over
"wrong path". Tests must include negative cases (commands that look
download-ish but aren't, e.g., `curl -X POST ...` with no output flag).

### D5. Severity = info by default; escalation rules

`agent_download` events default to `info` (logged, no notification).
Escalation to `warning` when **any** of:

- URL host is **not** in NetTracker `allowlist` AND not in known_hosts
  AND not LEARNED (i.e., NetTracker would have warned on the connection)
- URL host matches `security.context_aware.blocklist` (BLOCKED → warning,
  not critical — the download itself isn't harmful, the source is).

Escalation to `critical` when:
- `output_path` lands in a sensitive path (`~/.ssh`, `.env*`, `*.pem`,
  `*.key`, `id_rsa`, etc. — same `_SENSITIVE_PREFIXES` /
  `_SENSITIVE_FILENAME_RE` from `agent_log_parser`).
- Host is BLOCKED **and** path is sensitive — both at once.

`chmod +x` after a download (within the join window) is already covered
by the existing `make executable` HIGH_RISK pattern; no special
combination rule needed in v0.7.

## Consequences

### Positive
- Closes a real gap; users get URL ↔ file linkage automatically.
- `agent_download` filterable in `--report --type download` (Track A).
- Additive schema preserves OSS/Pro forward-compat (ADR 0004 §D3).

### Negative / accepted trade-offs
- One event becomes potentially two (`agent_command` + `agent_download`
  for the same `curl … -o`). Acceptable — distinct semantics; consumers
  can dedupe by command hash if needed.
- 5-minute join window means slow downloads on a flaky network may
  not get joined. Configurable; documented limitation.
- JSONL line-rewrite for join introduces a small file-locking surface
  in `event_logger`. Mitigated by single-daemon assumption (same as
  ADR 0001 D2 flush model).

### Follow-ups
- Track A — `--report` filter must include `--type download` test case.
- Track B — implementation PR. Includes:
  - extraction helper(s) in `agent_log_parser.py`
  - `event_logger.update_event_by_id` (or equivalent)
  - FSWatcher join logic + suppression
  - `tests/test_download_tracking.py` (new)
  - `config.example.yaml` `security.download_tracking:` section
- v0.8+ candidate — extend extraction to Pro-priority tools (aria2,
  httpie). Tracked separately.

## Frozen schemas

- `SecurityEvent.event_type = "agent_download"`
- Detail keys (initial set): `source_url`, `output_path`, `downloader`,
  `command`, `high_risk`, `trust_level`, `joined_fs_event`
- `joined_fs_event` sub-keys: `ts`, `actor_pid`, `actor_name`, `size_bytes`

Adding new keys is fine without superseding ADR. Removing or repurposing
any key requires a superseding ADR.
