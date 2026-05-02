# ADR 0006 — Config Mutation Fallback (v0.8)

- **Status**: Accepted
- **Date**: 2026-05-02
- **Scope**: `sentinel_mac/commands/context.py` (`block` / `unblock`
  handlers), no schema change.
- **Supersedes**: ADR 0003 §D2 (ruamel-only persistence) and §D6
  (exit code 3 for the ruamel-missing case)
- **Referenced by**: —

## Context

ADR 0003 §D2 mandated `ruamel.yaml` round-trip for `sentinel context
block` / `unblock` so config.yaml comments and formatting survive
mutation. If `ruamel.yaml` is missing (typical `pipx install
sentinel-mac` user without the `[app]` extra), the CLI exits 3 with
an "install with `pip install sentinel-mac[app]`" message.

This is poor UX — the user wanted to add one host to their blocklist;
they should not need to install a YAML library. v0.8 lifts this
restriction by adding an automatic PyYAML fallback (PyYAML is already
a hard dependency).

This ADR freezes the fallback behavior so it does not silently destroy
user data (comments, anchors, formatting).

## Decisions

### D1. Loader preference — ruamel first, PyYAML automatic fallback

Priority order, evaluated lazily at the moment `block`/`unblock` runs:

1. `ruamel.yaml` available → use it (preserves comments, anchors,
   formatting). No user-visible message.
2. `ruamel.yaml` not available → fall back to `PyYAML` automatically,
   **with a single-line stderr warning** (D3).

No CLI flag is required. Adding a flag (e.g., `--allow-comment-loss`)
was considered and rejected — the warning + backup file (D2) provide
sufficient guard rails without burdening the user with extra flags.

### D2. PyYAML path — backup-then-write

When the PyYAML fallback runs:

1. `shutil.copy2(config.yaml, config.yaml.bak.<epoch>)` — best-effort
   copy preserving permissions and mtime (not atomic at the filesystem
   level, but the original is read-only during the operation; backup
   integrity is the goal, not commit-or-rollback semantics).
2. `data = yaml.safe_load(open(config))`
3. Mutate `data["security"]["context_aware"]["blocklist"]`
4. `yaml.safe_dump(data, open(config, "w"), default_flow_style=False,
   sort_keys=False)`
5. Print confirmation that includes the backup path.

The backup file is **never auto-deleted**. Cleanup is the user's
responsibility (or a future `sentinel doctor --cleanup-backups`
command — out of v0.8 scope).

`sort_keys=False` is critical: PyYAML defaults to alphabetic key sort,
which would silently reorder every section in config.yaml. We accept
that comments are lost but at least the order survives.

### D3. User-visible warning shape (PyYAML fallback only)

Single line on stderr immediately before the mutation (kept under
~120 chars so it doesn't wrap on a default terminal):

```
warning: ruamel.yaml missing; using PyYAML fallback. Comments will be lost. Backup: <path>. Install `sentinel-mac[app]` to preserve.
```

`<path>` is interpolated to the absolute backup path so the user can
recover it without searching.

JSON mode (`--json`) emits the warning as an additional envelope field
under `data` (additive per ADR 0004 §D3):

```json
{
  "version": 1, "kind": "host_context_mutation",
  "data": {
    "action": "block", "host": "evil.com", "result": "added",
    "yaml_backend": "pyyaml",
    "backup_path": "/Users/.../config.yaml.bak.1714694400",
    "comment_preservation": "lost"
  }
}
```

When ruamel is used (D1 path 1), the new fields still appear with
`"yaml_backend": "ruamel"`, `"backup_path": null`,
`"comment_preservation": "preserved"` — uniform shape so consumers
don't need to branch.

### D4. Exit code mapping (revises ADR 0003 §D6)

| Code | Old (ADR 0003) | New (this ADR) |
|---|---|---|
| 3 | "Config mutation failed (ruamel missing, file unwritable, etc.)" | "Config mutation failed (file unwritable, parse error, etc.) — **ruamel-missing no longer returns 3**; it falls back to PyYAML and returns 0 if the write succeeds" |

All other exit codes (0/1/2/4) unchanged. `sentinel_mac/commands/
context.py` ADR 0003 §D6 reference comment is updated to point at
this ADR for the §D6 amendment.

### D5. Backup file naming + retention

- Naming: `config.yaml.bak.<unix_epoch_seconds>` next to the original
  config file. Multiple backups accumulate over time (one per mutation
  that took the PyYAML path).
- File permissions: `0o600` (config may contain webhook secrets).
- Parent directory permissions: inherited from the existing config
  directory (typically `~/.config/sentinel/`). On a shared host, the
  user is responsible for setting that directory to `0o700` —
  `sentinel doctor` (Track 1, separate from this ADR) will surface
  a warning when the directory is group/world-readable.
- Retention: **none** (backups are not auto-deleted in v0.8). User
  may manually clean. A future `sentinel doctor --cleanup-backups
  --keep N` is a v0.9+ candidate.

Rationale for no auto-cleanup: deleting user data without explicit
opt-in is the worst-case sin for a fallback whose entire purpose is
"don't silently destroy data". One stale backup per blocklist edit
is a tiny disk cost.

### D6. PyPI install story unchanged

`pip install sentinel-mac` (no extras) now sufficient for the full
CLI surface. `[app]` extra continues to provide ruamel + rumps for
the menubar app and the comment-preserving config edits. README
install instructions get a one-line note that `block`/`unblock` work
without `[app]` but lose comments.

## Consequences

### Positive
- Removes the install friction for the most common Pro-track-adjacent
  CLI workflow (`sentinel context block`).
- Backup-then-write is robust: even if PyYAML mangles the file
  catastrophically, the user can recover from the backup.
- Uniform `--json` shape (D3 unified envelope) means downstream tooling
  doesn't branch on backend.
- Forward-compatible: the `yaml_backend` field signals which path ran,
  so a future audit / observability layer can track the impact.

### Negative / accepted trade-offs
- Users who don't install `[app]` will silently accumulate
  `config.yaml.bak.*` files until they clean up. Acceptable cost for
  the safety net.
- PyYAML's `safe_dump` reformats the file (no comments, normalized
  spacing). Mitigated by the backup. Documented in the warning message.
- Two YAML libraries in the active code path. Maintenance burden is
  small (the fallback is ~30 LOC).

### Follow-ups
- Track 1 of v0.8 — implementation PR. Includes:
  - `_save_config_with_ruamel` (existing) + new `_save_config_with_pyyaml`
  - `_emit_yaml_backend_warning` helper (single-line stderr + JSON field)
  - `tests/test_context_cli.py` extension: monkeypatch ruamel import
    failure, verify PyYAML path runs + creates backup + warns
  - README "Commands" section updated to drop the `[app]`-extra
    requirement note for `block`/`unblock`
- v0.9+ candidate — `sentinel doctor --cleanup-backups --keep N`
- v0.9+ candidate — opt-in `--no-fallback` flag for users who insist
  on ruamel-or-fail (current default is fail-soft)

## Frozen surfaces

- Loader preference: ruamel preferred, PyYAML fallback automatic
- Backup naming: `config.yaml.bak.<unix_epoch_seconds>`, mode `0o600`,
  no auto-cleanup
- Warning channel: single-line stderr + `--json` envelope additive
  fields (`yaml_backend`, `backup_path`, `comment_preservation`)
- Exit code: ruamel-missing now → exit 0 on successful PyYAML write
  (was exit 3 in ADR 0003)
- Sort policy: `sort_keys=False` to preserve key order in PyYAML path

Changing the backup naming pattern, removing the warning, or
auto-deleting backups requires a superseding ADR. Adding additional
loaders (e.g., omegaconf) is fine without superseding.
