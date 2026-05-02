# ADR 0003 — `sentinel context` CLI Subcommands (v0.7)

- **Status**: Accepted
- **Date**: 2026-05-02
- **Scope**: `sentinel_mac/commands/context.py` (new), `sentinel_mac/core.py`
  (argparse subparser wiring), `config.example.yaml` (no schema change —
  blocklist already exists from ADR 0001).
- **Supersedes**: ADR 0001 §D3 (which deferred CLI to v0.7)
- **Referenced by**: —

## Context

ADR 0001 §D3 deferred the `sentinel context …` CLI to v0.7. The
`HostContext` Python API has been in production since v0.6.0 (`forget`,
`iter_observations`, `seen_count`, `is_in_known_hosts` are all on the
class). What's missing is the user-facing CLI to inspect and mutate
host context state without writing Python.

This ADR freezes the subcommand structure, output formats, and config
mutation policy.

## Decisions

### D1. Subcommand surface — 4 verbs

```
sentinel context status [HOST]    # read-only — show full snapshot or single-host detail
sentinel context forget HOST      # mutating — remove from frequency counter
sentinel context block HOST       # mutating — add to config blocklist
sentinel context unblock HOST     # mutating — remove from config blocklist
```

Rejected designs:
- Separate `list` / `blocklist` / `known-hosts` subcommands → too many
  verbs; `status` without args covers all three sections.
- `block --list` style flag → confusing "verb without object".
- `add` / `remove` (generic) → unclear which set (blocklist vs counter).

`status` chosen over `list` as the default read verb because the output
is composite (frequency-learned + blocklist + known_hosts summary), not
a flat list. Single-host invocation (`status HOST`) is the natural
"detail" view.

### D2. Mutating commands persist to `config.yaml` via ruamel round-trip

`block` / `unblock` MUST persist the change. The chosen storage is
**inline edit of `config.yaml`** at the resolved config path
(`--config` flag → `./config.yaml` → `~/.config/sentinel/config.yaml`,
same resolution as the daemon).

Persistence uses `ruamel.yaml` round-trip (already in
`[project.optional-dependencies].app` for the menubar app — same
preserves-comments-and-formatting behavior). If `ruamel.yaml` is not
installed (user did not install the `app` extra), `block`/`unblock`
fails with a clear message: "install with `pip install
sentinel-mac[app]` to use config-mutating subcommands".

`forget` does **not** mutate config — it mutates the runtime cache
(`~/.local/share/sentinel/host_context.jsonl`) directly via
`HostContext.forget(host) + flush()`.

Rationale for config-inline blocklist (vs. separate runtime file):
- Discoverability: user can `git diff` their tracked config to see what
  changed.
- Single source of truth: the daemon already loads blocklist from
  config; CLI reads/writes the same file.
- ADR 0004 §D4 keeps Pro-managed blocklist as a *future* additive layer
  (e.g., loaded from URL) — current schema doesn't conflict.

### D3. Daemon liveness — CLI does NOT require running daemon

All four subcommands work whether the daemon is running or not. They
are pure file operations on the cache + config. The running daemon
will see config changes on next `load()` (currently startup-only —
v0.7+ may add a SIGHUP reload, but that's out of scope here).

For `forget`: if the daemon is running, the in-memory counter and the
disk cache will diverge until the daemon restarts. CLI prints a notice
when it detects a running daemon (via `sentinel.lock`):

```
Removed 'evil.example.com' from cache. Restart the daemon (`sentinel restart`)
for the running instance to pick up the change.
```

A future SIGHUP reload would let the CLI signal the daemon instead;
ADR 0001 §D2 left this open. Not required for v0.7.

### D4. Read-only commands work even when `context_aware: enabled` is false

`status` works regardless of the master switch. Rationale: a user
investigating "should I enable this?" needs to see what data exists
first. Reading `~/.local/share/sentinel/host_context.jsonl` in
disabled mode is a one-shot file read — no daemon side effects.

`forget` / `block` / `unblock` also work when disabled (they prepare
state for when the user enables the feature). CLI prints an info
notice: "context_aware is currently disabled; this change takes
effect when you set `security.context_aware.enabled: true`."

### D5. Output format — text by default, `--json` opt-in

Default human-readable text output. `--json` flag emits the versioned
envelope per ADR 0004 §D2:

```json
{
  "version": 1,
  "kind": "host_context_status",
  "generated_at": "2026-05-02T11:00:00Z",
  "data": {
    "enabled": true,
    "config_path": "~/.config/sentinel/config.yaml",
    "cache_path": "~/.local/share/sentinel/host_context.jsonl",
    "frequency": [
      {
        "host": "api.anthropic.com",
        "count": 42,
        "first_seen": 1714521600,
        "last_seen": 1714694400,
        "trust": "learned"
      }
    ],
    "blocklist": ["evil.example.com", "*.suspicious.tld"],
    "known_hosts": {"count": 8, "sample": ["github.com", "..."]}
  }
}
```

Mutating commands also accept `--json` for machine-friendly result
reporting:

```json
{
  "version": 1,
  "kind": "host_context_mutation",
  "data": {"action": "forget", "host": "evil.com", "result": "removed"}
}
```

`kind` values added by this ADR:
- `host_context_status` — `status` snapshot output (no HOST argument)
- `host_context_host_detail` — `status HOST` single-host detail output
- `host_context_mutation` — `forget` / `block` / `unblock` result

### D6. Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (action completed or read returned data) |
| 1 | Host not found (e.g., `forget` on unknown host) |
| 2 | Validation error (bad host syntax, etc.) |
| 3 | Config mutation failed (ruamel missing, file unwritable, etc.) |
| 4 | Cache file read error (corrupted, unreadable) |

### D7. Argument parsing — argparse subparser, no third-party CLI lib

Stays in stdlib `argparse`. Rationale: existing `sentinel` CLI uses
argparse; consistency. Third-party libs (`click`, `typer`) considered
and rejected — adds a runtime dependency for marginal ergonomics.

## Consequences

### Positive
- Closes the v0.6 deferred CLI work.
- All four subcommands work without daemon — useful for offline
  inspection, dev debugging, and one-shot ops.
- `--json` envelope = same shape as ADR 0002 `--report --json` =
  predictable for tooling.

### Negative / accepted trade-offs
- `block`/`unblock` requires `[app]` extra (ruamel). Documented; clear
  error message. v0.8+ candidate: lazy-import-or-fallback to PyYAML
  with comment loss + warning.
- Config-inline blocklist persistence means user's `config.yaml`
  changes outside their editor — could surprise users editing manually.
  Mitigation: `block` prints the line it added.
- No SIGHUP reload yet; CLI mutations on running daemon need restart.

### Follow-ups
- Track C of v0.7 — implementation PR. Includes:
  - `sentinel_mac/commands/__init__.py` (new package)
  - `sentinel_mac/commands/context.py` (subparser + 4 handlers)
  - `core.py` argparse wiring (one new subparser hook)
  - `tests/test_context_cli.py` (new)
  - README "Commands" section update + Privacy section cross-reference
- v0.8 candidate — SIGHUP reload (live daemon picks up CLI mutations).
- v0.8 candidate — fallback to PyYAML when ruamel absent.

## Frozen surfaces

- Subcommand verbs: `status`, `forget`, `block`, `unblock` (4 total)
- Required positional: `forget HOST`, `block HOST`, `unblock HOST`
- Optional positional: `status [HOST]`
- Universal flags: `--json`, `--config PATH`
- Exit code map (D6 above)
- `--json` envelope `kind` values: `host_context_status`,
  `host_context_host_detail`, `host_context_mutation`

Adding new optional flags is fine without superseding ADR. Adding new
subcommands or repurposing exit codes requires a superseding ADR.
