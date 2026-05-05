# Inspecting Event Logs

Sentinel writes one **JSONL** (JSON-per-line) file per day to its data
directory. Each line is one `SecurityEvent`. There is no SQLite, no
binary index, no schema migration — just append-only text.

This document covers three ways to inspect those events:

1. [`sentinel --report`](#1-built-in-report) — the built-in summary CLI (recommended starting point)
2. [Direct JSONL with `jq`](#2-direct-jsonl-with-jq) — for ad-hoc forensics
3. [SQLite import](#3-optional-sqlite-import) — if you really want SQL

The contract for the on-disk format is frozen by **ADR 0002**
(`docs/decisions/0002-download-tracking.md`) and the JSON envelope
shape by **ADR 0004 §D2**.

---

## Where the files live

The path depends on how `sentinel` was launched.

| Install / launch | Events directory |
|---|---|
| `pipx install sentinel-mac` (default) | `~/.local/share/sentinel/events/` |
| `pip install` + `~/.config/sentinel/config.yaml` | `~/.local/share/sentinel/events/` |
| Source / dev (`sentinel --config ./config.yaml`) | `<repo>/logs/events/` |
| `SENTINEL_DATA_DIR` env override | `$SENTINEL_DATA_DIR/events/` |

Confirm the resolved path on your machine:

```bash
sentinel --version | grep "data dir"
#   data dir:  /Users/you/.local/share/sentinel
```

Files are named `YYYY-MM-DD.jsonl` (UTC-naive local date, daily
rotation by `EventLogger`).

---

## Event shape

Every line is a complete JSON object. Example (`fs_watcher.bulk_change`):

```json
{
  "ts": "2026-05-05T00:10:50.624767",
  "source": "fs_watcher",
  "actor_pid": 0,
  "actor_name": "unknown",
  "event_type": "bulk_change",
  "target": "50 files in 30s",
  "detail": {
    "count": 50,
    "top_directories": ["/Users/you/code/repo"],
    "project": "repo",
    "project_meta": {
      "name": "repo",
      "root": "/Users/you/code/repo",
      "git": {"branch": "main", "head": "abc123"}
    }
  },
  "risk_score": 0.0
}
```

Fixed top-level keys: `ts`, `source`, `actor_pid`, `actor_name`,
`event_type`, `target`, `detail`, `risk_score`.

The `detail` object is **additive per ADR 0004 §D3** — keys are
never repurposed across versions, so older inspection scripts keep
working when new keys are added.

`source` enum: `fs_watcher`, `net_tracker`, `agent_log`.

`event_type` values vary by source — common ones: `agent_command`,
`agent_download`, `bulk_change`, `file_modify`, `net_connect`,
`typosquatting`, `mcp_injection`. Run `--report` once to see what
appears in your data.

---

## 1. Built-in `--report`

The fastest path. Reads the JSONL files, groups by type, prints a
summary or a versioned JSON envelope.

```bash
# Today
sentinel --report

# Last 7 days
sentinel --report 7
# or:
sentinel --report --since 7d
```

### Filters

All filters compose. Comma-separate values inside a single flag.

```bash
# Only critical events from the last 24h
sentinel --report --since 24h --severity critical

# Only agent_command + agent_download events from agent_log source
sentinel --report --since 7d --source agent_log --type agent_command,agent_download

# Last 30 days, anything from network watcher
sentinel --report --since 30d --source net_tracker
```

`--since` accepts `30m`, `24h`, `7d`, integer seconds, or a bare
number (treated as days). Cap is 365 days.

### JSON output (script-friendly)

```bash
sentinel --report --since 7d --severity critical --json | jq
```

The envelope follows ADR 0004 §D2:

```json
{
  "version": 1,
  "kind": "report_summary",
  "generated_at": "2026-05-05T08:30:00Z",
  "data": { /* events / counts / etc. */ }
}
```

Pipe to a file for archival or downstream processing:

```bash
sentinel --report --since 30d --json > /tmp/events-$(date +%F).json
```

---

## 2. Direct JSONL with `jq`

When `--report` is not enough — you want to slice by a field that has
no flag, trace one PID across files, or feed events to another tool.
JSONL + `jq` covers most cases.

Quick install: `brew install jq`.

```bash
EVENTS=~/.local/share/sentinel/events
# (or: EVENTS=/path/to/repo/logs/events  if running from source)
```

### Recipes

```bash
# Pretty-print today's events
jq . "$EVENTS/$(date +%F).jsonl"

# Critical events, last day file only, compact one-line each
jq -c 'select(.risk_score >= 0.8)' "$EVENTS/$(date +%F).jsonl"

# Severity is derived from risk_score in the report layer; if you want
# the same buckets here:  >=0.8 critical, >=0.4 warning, else info.
jq -c 'select(.risk_score >= 0.8) | {ts, source, event_type, target}' \
   "$EVENTS"/2026-05-*.jsonl

# Count events by event_type across the whole month
jq -r '.event_type' "$EVENTS"/2026-05-*.jsonl | sort | uniq -c | sort -rn

# All events from a specific actor PID across multiple days
jq -c 'select(.actor_pid == 12345)' "$EVENTS"/2026-05-*.jsonl

# Pull only the forensic context block (project / session / cwd)
jq '{ts, type: .event_type, project: .detail.project_meta, session: .detail.session, cwd: .detail.cwd}' \
   "$EVENTS/$(date +%F).jsonl"

# Typosquatting hits with the suspicious package name and intended target
jq -c 'select(.event_type == "typosquatting")
       | {ts, package: .detail.package, suggested: .detail.suggested, command: .detail.command}' \
   "$EVENTS"/2026-05-*.jsonl

# Network connections to a specific host
jq -c 'select(.event_type == "net_connect" and (.detail.remote_host // "") | endswith("evil.com"))' \
   "$EVENTS"/2026-05-*.jsonl

# Live tail today + parse with jq as events arrive
tail -F "$EVENTS/$(date +%F).jsonl" | jq -c '{ts, event_type, risk_score, target}'

# Convert one day to CSV (ts, type, target, risk)
jq -r '[.ts, .event_type, .target, .risk_score] | @csv' \
   "$EVENTS/$(date +%F).jsonl"
```

### Time-range slicing

JSONL has no index, but the daily rotation already buys you a coarse
filter. Picking a date range is just shell globbing:

```bash
# May 1–5
jq -c '...' "$EVENTS"/2026-05-0[1-5].jsonl

# Everything from April onward
jq -c '...' "$EVENTS"/2026-{04,05}-*.jsonl
```

For sub-day filtering use `jq` on `.ts` (ISO 8601 strings sort
lexicographically):

```bash
jq -c 'select(.ts >= "2026-05-05T08:00:00" and .ts < "2026-05-05T12:00:00")' \
   "$EVENTS/2026-05-05.jsonl"
```

---

## 3. Optional: SQLite import

If you genuinely prefer SQL — for joins, window functions, GUI
browsers like DB Browser for SQLite — convert JSONL to SQLite ad-hoc.
Sentinel itself does not maintain a database.

### Quick one-liner

```bash
# Requires `sqlite-utils` (pipx install sqlite-utils)
sqlite-utils insert events.db events "$EVENTS"/2026-05-*.jsonl --nl

sqlite-utils events.db "
  SELECT event_type, COUNT(*) AS n
  FROM events
  WHERE risk_score >= 0.8
  GROUP BY event_type
  ORDER BY n DESC
"
```

### Without extra tools (Python stdlib only)

```python
import json, sqlite3, glob

con = sqlite3.connect("events.db")
con.execute("""
  CREATE TABLE IF NOT EXISTS events (
    ts TEXT, source TEXT, actor_pid INTEGER, actor_name TEXT,
    event_type TEXT, target TEXT, detail JSON, risk_score REAL
  )
""")
for path in sorted(glob.glob("/Users/you/.local/share/sentinel/events/*.jsonl")):
    with open(path) as f:
        for line in f:
            e = json.loads(line)
            con.execute(
              "INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
              (e["ts"], e["source"], e["actor_pid"], e["actor_name"],
               e["event_type"], e["target"], json.dumps(e["detail"]),
               e["risk_score"]),
            )
con.commit()
```

Then:

```sql
SELECT json_extract(detail, '$.package') AS pkg, COUNT(*)
FROM events
WHERE event_type = 'typosquatting'
GROUP BY pkg
ORDER BY 2 DESC;
```

### Why isn't this the default?

ADR 0001~0007 chose JSONL deliberately:

- **Append-only & crash-safe.** A line is either fully written or not
  written; there is no half-applied transaction state. SQLite's WAL
  is more robust against power loss but adds operational surface.
- **Offline-friendly.** Copy a day's file to another machine and
  every standard Unix tool works. No `.db` lock files, no version
  drift between sqlite3 binaries.
- **Single-writer assumption.** The daemon is a single process per
  ADR 0001 §D2, so file lock + flush is sufficient. SQLite's value
  shows up under multi-writer load that does not exist here.
- **Forensic clarity.** `head` / `tail` / `grep` / `diff` on plain
  text beats `sqlite3 .dump` for after-the-fact incident review.

If your workflow is genuinely SQL-shaped, the conversion above takes
seconds and gives you a fresh `.db` whenever you need it.

---

## Retention

`EventLogger` keeps daily files for **90 days** by default
(`EventLogger.DEFAULT_RETENTION_DAYS`). Older `YYYY-MM-DD.jsonl`
files are pruned during daily rotation. The retention window is
not user-configurable from `config.yaml` as of v0.10.0 — adjust it
in source if you need shorter or longer. (Tracking issue: this is a
v0.11+ candidate.)

To archive before pruning:

```bash
# Tar up older files weekly via cron
tar -czf "/path/to/archive/events-$(date +%Y-%m).tar.gz" \
   "$EVENTS"/$(date -v-30d +%Y-%m)-*.jsonl
```

---

## Privacy

Events stay on the local machine. Nothing in `events/*.jsonl` is sent
anywhere by Sentinel itself; the JSONL is only read by `--report`,
the `sentinel doctor` health check, and any tool you point at it.

Per ADR 0007 §D7, the `git.remote` URL inside `detail.project_meta`
is **audit-log-only** — it appears in JSONL for forensic review but
is never included in opt-in notification channels (ntfy / Slack /
Telegram). The notification context level
(`notifications.context_level`, ADR 0008) further controls how much
of `detail` reaches the alert body.
