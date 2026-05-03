# ADR 0009 — Backup Retention Policy (v0.9 Track 3)

- **Status**: Accepted
- **Date**: 2026-05-03
- **Scope**: `sentinel_mac/commands/doctor.py` (new
  `--cleanup-backups` flag), no other module touched.
- **Supersedes**: ADR 0006 §D5 ("backups never auto-deleted") —
  narrowed to "**not auto-deleted by the daemon**; user-initiated
  cleanup via `sentinel doctor` is now allowed". See D2.

## Context

ADR 0006 (PyYAML fallback for `sentinel context block`/`unblock`)
shipped a backup-then-write safety net that creates
`config.yaml.bak.<unix_epoch>` on every PyYAML-path mutation. ADR
0006 §D5 explicitly chose **no retention policy** — backups never
auto-deleted because "deleting user data without explicit opt-in is
the worst-case sin for a fallback whose entire purpose is don't
silently destroy data."

That policy is right at write time but accumulates. A user who runs
`sentinel context block` ten times during a debugging session ends
up with ten backup files. `sentinel doctor` already surfaces the
count as a WARN when it crosses 10. The promised v0.9 follow-up
adds the corresponding cleanup tool — explicitly user-initiated, so
the "don't silently destroy" principle is preserved.

## Decisions

### D1. CLI surface — `sentinel doctor --cleanup-backups`

Three flags, all on `sentinel doctor`:

```
sentinel doctor --cleanup-backups            # safety: requires --keep
sentinel doctor --cleanup-backups --keep N   # keep N most-recent backups, delete the rest
sentinel doctor --cleanup-backups --keep N --dry-run    # report what would be deleted, delete nothing
sentinel doctor --cleanup-backups --keep N --yes        # skip the interactive y/n confirmation
```

`sentinel doctor` without these flags continues to run the existing
9-check health pass (ADR 0006 §D5 / Track 1b). The cleanup mode is
**mutually exclusive** with the standard health-check mode — when
`--cleanup-backups` is present, the 9 checks are skipped and only
the cleanup runs.

### D2. `--keep` is mandatory

`sentinel doctor --cleanup-backups` (no `--keep`) **errors out
with exit 2** and prints:

```
error: --cleanup-backups requires --keep N to specify how many backups
to retain. Example: sentinel doctor --cleanup-backups --keep 3
```

Rationale: there is no safe default. `--keep 0` (delete all) is a
plausible intent for a privacy-conscious user; `--keep 3` is
plausible for a "I want a small safety window" user; `--keep 10`
matches the WARN threshold from ADR 0006. Picking any one of these
as default would surprise the other groups. Force the explicit
choice.

### D3. Selection rule — "most recent N by epoch in filename"

Backups are named `<config>.bak.<unix_epoch_seconds>` (ADR 0006 §D5
frozen). Selection:

1. Glob all `<config>.bak.*` next to the active config file.
2. Parse the trailing integer; **skip** files where the suffix is
   not a valid integer (defensive — never delete a file that does
   not match the freeze pattern even if it lives next to the
   pattern).
3. Sort by parsed epoch, descending.
4. Keep the first `N`. Delete the rest.

Filesystem mtime is **not** consulted — the epoch in the filename
is the canonical timestamp and survives `cp -p` / archive
round-trips.

### D4. Interactive confirmation by default

Without `--yes`, the tool prints the deletion plan and prompts:

```
Will delete 7 backup file(s), keeping the 3 most recent:
  config.yaml.bak.1714400001 (2026-04-29 12:33:21)
  config.yaml.bak.1714400000 (2026-04-29 12:33:20)
  ... 5 more ...

Proceed? [y/N]
```

`y` (or `Y`) → delete. Anything else → exit 0 with "Cancelled.
No files deleted." Rationale: this is a destructive operation
explicitly opted into; one more friction step before irreversible
delete is cheap and matches the doctor command's overall
read-mostly posture.

`--yes` skips the prompt for scripting / cron use. `--dry-run`
ignores `--yes` (always reports without deleting; never prompts).

**Non-TTY behavior** (cron, CI, piped stdin): when stdin is not a
TTY and `--yes` is not given, the tool **does not hang** — it
auto-cancels (exit 0) and writes a single-line `WARNING` to stderr
(`warning: --cleanup-backups invoked with non-TTY stdin and no
--yes; skipping deletion`). Cron users should always pass `--yes`.

Recommended cron cadence (when adopted): weekly is plenty. Example:

```cron
0 3 * * 0  /usr/local/bin/sentinel doctor --cleanup-backups --keep 5 --yes
```

(weekly Sunday 3am, keep last 5 backups, no prompt). More frequent
runs are pointless — backups only accumulate when a user actually
invokes `sentinel context block`/`unblock` on the PyYAML fallback
path.

### D5. Idempotency

Running the same command twice in a row is safe:

- First run: deletes excess backups, leaves N most recent.
- Second run: finds exactly N (or fewer) backups, reports
  "Nothing to delete (3 backup file(s), keeping 3)." and exits 0.

The `--dry-run` flag is also idempotent (reads only).

### D6. JSON output mirroring

`sentinel doctor --json --cleanup-backups --keep N` emits an
ADR 0004 §D2 versioned envelope with a new `kind`:

```json
{
  "version": 1,
  "kind": "backup_cleanup",
  "generated_at": "2026-05-03T...",
  "data": {
    "config_path": "/Users/.../config.yaml",
    "found": 10,
    "kept": 3,
    "deleted": ["...bak.1714400001", "...bak.1714400000", ...],
    "dry_run": false
  }
}
```

`--yes` is implied in JSON mode (no interactive prompt — JSON output
is for tooling). `--dry-run` populates `deleted` with what *would*
be deleted and sets `dry_run: true`; the files stay on disk.

### D7. Exit codes (extends ADR 0006 §D6)

| Code | Meaning |
|---|---|
| 0 | Cleanup succeeded (or nothing to delete, or user said N at the prompt, or `--dry-run`) |
| 1 | Cleanup partially failed (some files could not be deleted — permission, disk error). Successful deletes are kept; the failed paths appear in `data.errors` (JSON) or stderr (text). Exit 1 means "human attention recommended". |
| 2 | Argument validation error (`--cleanup-backups` without `--keep`, negative `--keep`, etc.) |

These extend the existing `sentinel doctor` exit-code map (0 OK / 1
any FAIL — ADR 0006 §D5 / Track 1b implementation). When
`--cleanup-backups` is the active mode, the 9-check exit semantics
do not apply.

## Consequences

### Positive
- Closes the ADR 0006 §D5 follow-up that has been documented as
  "v0.9+ candidate" since the original PR.
- Users who hit the `sentinel doctor` >10 backups WARN now have a
  one-line fix that does not require shell glob / `rm` knowledge.
- Idempotent + dry-run + interactive-by-default → safe enough for
  the README to recommend without scary disclaimers.
- JSON envelope `kind=backup_cleanup` matches the ADR 0004
  versioned-envelope pattern, so future `sentinel-mac[pro]` audit
  forwarders can ingest cleanup events the same way they ingest
  health-check events.

### Negative / accepted trade-offs
- Mandatory `--keep` is one more keystroke vs. a default. We
  chose explicitness over convenience; documented in `--help`.
- Cleanup mode hides the 9-check pass — a user who runs
  `sentinel doctor --cleanup-backups --keep 3` and then expects
  to see the daemon-status output will have to run `sentinel
  doctor` again separately. Considered combining (cleanup as a
  side-effect of the standard run) and rejected: side effects
  inside a "doctor" command are surprising.
- Glob walks the config directory; on a host with thousands of
  unrelated `.bak.*` files this is O(N). Acceptable — real-world
  N is dozens at most.

### Follow-ups
- **Track 3 implementation** (this v0.9 cycle): adds the flag
  parsing in `commands/doctor.py`, the cleanup logic, JSON
  envelope branch, and tests covering the §D2 mandatory-keep
  guard, §D3 selection rule, §D4 interactive prompt, §D5
  idempotency, §D6 envelope shape, §D7 exit codes.
- **v0.10+ candidate**: a `--keep-since DURATION` variant
  (`--keep-since 7d` keeps everything newer than 7 days). Not
  implemented in v0.9 — `--keep N` covers the "size cap" use
  case; "time cap" is a separate axis worth its own ADR.
- **v0.10+ candidate**: a daemon-side periodic auto-cleanup with
  a config opt-in (`backups.auto_cleanup_keep: 5`). Not in v0.9
  — preserves the ADR 0006 §D5 spirit ("never silently delete
  user data") for one more release while user-initiated cleanup
  validates the deletion semantics.

## Frozen surfaces

- Flag spelling: `--cleanup-backups` (hyphen) and `--keep N` and
  `--dry-run` and `--yes`. No abbreviations exposed.
- `--keep` is mandatory when `--cleanup-backups` is present.
- Selection rule: parse trailing integer in filename, sort
  descending, keep N. Filesystem mtime not consulted.
- Interactive prompt format: `Proceed? [y/N]` with `y`/`Y`
  acceptance, all other inputs cancel.
- JSON envelope `kind = "backup_cleanup"` with the four `data`
  keys above.
- Exit codes 0 / 1 / 2 as defined in §D7.

Adding new flags is fine without superseding ADR. Changing the
selection rule (e.g., switching to mtime-based), removing the
mandatory-keep guard, or relaxing the interactive prompt requires
a superseding ADR.
