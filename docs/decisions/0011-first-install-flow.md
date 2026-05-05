# ADR 0011 — First-Install Flow (v0.11)

- **Status**: Accepted
- **Accepted**: 2026-05-05
- **Date**: 2026-05-04
- **Scope**: `sentinel_mac/commands/install.py` (new),
  `sentinel_mac/commands/uninstall.py` (new),
  `sentinel_mac/installer/` (new package: `plist.py`, `config_init.py`,
  `verify.py`), `sentinel_mac/core.py` (additive — `PLIST_PATH` reuse,
  `PLIST_NAME` reuse), `sentinel_mac/cli.py` (additive — `install` /
  `uninstall` subcommands), `pyproject.toml` (no version bump — implementation
  PRs carry that), `install.sh` (header comment update), `README.md`
  (Quick Start reorder).
- **Supersedes**: —

## Context

v0.10.0 shipped a smooth `sentinel update` experience (ADR 0010). User feedback:

> "이번 업그레이드 경험은 매우 간단했어. 그런데 첫 설치 경험은 너무 복잡하고 어려웠어."

The current first-install path requires five discrete steps that the user must
discover and execute manually:

```
pipx install sentinel-mac        # package only — daemon not running
sentinel --init-config           # config creation, poorly signposted
# LaunchAgent plist — no automation; user writes XML or runs install.sh
# launchctl load — manual
sentinel doctor                  # verification — user must know to run this
```

The v0.11 goal is to collapse this to one command after `pipx install`:

```bash
sentinel install
```

This ADR freezes the interface contracts and key design decisions before
implementation begins. Status promotes to Accepted after Track A merges.

## Decisions

### D1. CLI surface

**Decision**:

```
sentinel install [--force] [--no-launchagent] [--yes] [--json]
sentinel uninstall [--purge] [--keep-launchagent] [--yes] [--json]
```

Flag semantics for `sentinel install`:

| Flag | Behavior |
|---|---|
| _(no flags)_ | config + plist + load + verify, idempotent (D4) |
| `--force` | regenerate all artifacts even if they already exist |
| `--no-launchagent` | skip plist generation and launchctl load (CLI-only users) |
| `--yes` | skip all interactive prompts (cron / CI friendly) |
| `--json` | emit ADR 0004 §D2 envelope `kind="install"` or `kind="install_error"` |

`--no-config` is intentionally omitted. If `~/.config/sentinel/config.yaml`
already exists, the install step preserves it by default (D4). `--config-path`
is also omitted in v0.11.0; the standard XDG location is the only supported
target. Both may be added in a future ADR without superseding this one.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (I/O failure, launchctl failure, verify failure) |
| 2 | Already fully installed — all artifacts present, daemon running (`--force` to reinstall) |
| 3 | Unsupported install method (EDITABLE or SYSTEM_UNSAFE) |

Non-interactive detection: if the process has no TTY (`not sys.stdin.isatty()`)
and `--yes` is not passed, print a WARNING and cancel — mirroring the ADR 0009
pattern used by `sentinel update --apply`.

**Rationale**: `--force` makes the intent explicit without surprising the user.
Exit code 2 enables scripting (`if sentinel install; then ...; fi` vs already
installed). `--no-launchagent` keeps the command usable by developers who run
the daemon manually.

### D2. Install step sequence

**Decision**: steps execute in strict order. Each step is independently
idempotent (D4). The sequence is:

```
1. detect_install_method()          # reuse ADR 0010 D1 — early-exit if EDITABLE / SYSTEM_UNSAFE
2. config init                      # create ~/.config/sentinel/config.yaml if absent; preserve if present
3. data dir mkdir                   # resolve_data_dir() — creates ~/.local/share/sentinel if absent
4. plist generation                 # write ~/Library/LaunchAgents/com.sentinel.agent.plist
5. launchctl load                   # register the LaunchAgent with the OS
6. daemon liveness check            # 2s sleep + launchctl list | grep com.sentinel.agent; confirm PID
7. post-install banner              # D8
```

Rollback policy per step:

| Step | Failure action |
|---|---|
| 1 | exit 3, no rollback needed (nothing written) |
| 2 | exit 1; if file was partially written, delete the partial file |
| 3 | exit 1; no rollback (mkdir is idempotent) |
| 4 | exit 1; if plist was partially written, delete partial file; restore backup if `--force` replaced an existing plist |
| 5 | exit 1; attempt `launchctl unload` to clean up any half-registered state; delete plist if it was created in this run |
| 6 | exit 1 with "daemon did not start" message + manual recovery instructions; plist remains (user can debug) |
| 7 | informational only — no failure path |

Steps 1–3 are non-destructive. Full rollback (remove all artifacts created in
this run) is attempted only for steps 4–5 on first-run; on `--force` re-run,
the pre-existing backup is restored.

`sentinel doctor` is invoked as a subprocess in step 7 to verify health
(following ADR 0010 §D3 `verify_running_version` subprocess pattern for consistency).
Direct function call was avoided to decouple doctor logic evolution from the install command,
reducing future sync burden between two call sites. The banner data (PID, config path)
is obtained from `installer/verify.py` functions independently.

### D3. Supported install methods

**Decision**:

| Method | Behavior |
|---|---|
| PIPX | Supported. plist `ProgramArguments[0]` = `sys.executable` parent + `sentinel`. Resolved from `detect_install_method()`. |
| PIP_VENV | Supported. plist uses absolute venv binary path derived from `sys.executable`. |
| EDITABLE | Rejected. exit 3 with guidance: "for development, use install.sh; sentinel install is for operational installs." |
| HOMEBREW | Rejected (formula not yet in brew tap). exit 3 with guidance: "Homebrew formula planned for v0.12." |
| SYSTEM_UNSAFE | Rejected. exit 3 with guidance matching ADR 0010 D6 language. |

For PIPX, the binary path is: `Path(sys.executable).parent / "sentinel"`.
For PIP_VENV, the same expression applies. Both are resolved at install time and
written into the plist — not re-detected on every daemon start.

The plist `ProgramArguments` does not include `--config`; the daemon uses XDG
auto-detection (`resolve_config_path()`) as its default. This is consistent with
the current behavior documented in `core.py`.

**Rationale**: committing the exact binary path at install time is safer than
having the daemon re-resolve its own location on launch. If the path changes
(e.g., user reinstalls via a different method), `sentinel install --force` must
be rerun — this is expected and documented.

### D4. Idempotency

**Decision**: option (c) — per-artifact existence check, fill in what is missing.

| Artifact | Already exists | `--force` |
|---|---|---|
| `~/.config/sentinel/config.yaml` | preserve as-is | overwrite with fresh template |
| `~/.local/share/sentinel/` | skip mkdir (already exists) | no-op (mkdir is always idempotent) |
| `~/Library/LaunchAgents/com.sentinel.agent.plist` | preserve (warn if binary path differs) | backup to `.plist.bak` then overwrite |
| LaunchAgent loaded in launchctl | skip load (already running) | unload then load |

If all artifacts exist and the daemon is running: exit 2 with
`"Sentinel is already installed and running. Use --force to reinstall."`.

If some artifacts are missing (e.g., plist absent but config present): create
only the missing ones and print a summary of what was created vs skipped.

**Rationale**: partial installs occur when a user ran `sentinel --init-config`
manually or when install.sh created config but not a pipx-compatible plist.
Option (c) handles these gracefully without requiring `--force`.

### D5. Conflict with existing dev install (install.sh)

**Decision**: option (a) — detect conflict, abort, guide.

Detection: after step 4 plist generation (or when reading an existing plist),
parse `ProgramArguments[0]` from the existing plist. If it points to a `.venv`
path (i.e., contains `/.venv/`) and the current `detect_install_method()` is
`PIPX` or `PIP_VENV`, the paths diverge — print:

```
warning: existing LaunchAgent points to a dev .venv:
  current plist: /path/to/.venv/bin/sentinel
  this install:  ~/.local/pipx/venvs/sentinel-mac/bin/sentinel

To migrate from dev install to operational install, run:
  sentinel install --force
This will back up the existing plist and replace it.
```

Then exit 1 (not 2 — the state is inconsistent, not fully installed).

With `--force`: back up the existing plist to `com.sentinel.agent.plist.bak`,
then proceed with the new plist. No automatic migration without `--force`.

**Rationale**: auto-migration (option b) silently modifies a running dev
environment. Requiring `--force` makes the user's intent explicit. The backup
ensures the dev plist can be restored manually if needed.

### D6. `sentinel uninstall` — symmetric teardown

**Decision**:

Default behavior (no flags):
1. `launchctl unload ~/Library/LaunchAgents/com.sentinel.agent.plist`
2. Delete `~/Library/LaunchAgents/com.sentinel.agent.plist`
3. Print confirmation. **Config and data dir are preserved.**

Flags:

| Flag | Behavior |
|---|---|
| `--purge` | also delete `~/.config/sentinel/config.yaml`, `~/.local/share/sentinel/` (all events JSONL, skipped_versions.txt, logs). Prompts "This will delete all Sentinel data. Continue? [y/N]" unless `--yes`. |
| `--keep-launchagent` | skip plist unload and delete; sentinel-mac package can be separately removed via `pipx uninstall sentinel-mac` |
| `--yes` | skip confirmation prompts |
| `--json` | ADR 0004 §D2 envelope `kind="uninstall"` |

Exit codes: 0 success, 1 error, 2 not installed (plist absent and daemon not
running).

**Rationale**: preserving config and data by default matches user expectations
— uninstalling a tool should not silently destroy monitoring history. `--purge`
makes data destruction explicit and requires confirmation.

### D7. macOS system permissions

**Decision**: `sentinel install` requires no `sudo` at any point.

- LaunchAgent plist lives in `~/Library/LaunchAgents/` — per-user directory,
  no elevated privileges needed.
- `pipx` and pip-venv installs are user-owned — no sudo for the binary.
- `launchctl load` on a per-user plist runs as the current user.

Post-install, the daemon will encounter two permission prompts on first event:

1. **Full Disk Access**: macOS auto-prompts when the daemon first accesses
   `~/Library`, `~/Documents`, or other protected paths. The user must approve
   in System Settings > Privacy & Security > Full Disk Access.
2. **Notifications**: macOS auto-prompts when the first notification is sent.

`sentinel install` prints the following guidance in the post-install banner (D8)
after the success line:

```
macOS may prompt for Full Disk Access on first event. Allow it in:
  System Settings > Privacy & Security > Full Disk Access
```

No automated permission request is issued by `sentinel install` itself. Doing
so would require `tccutil` or private APIs, which are outside scope and policy.

**Rationale**: launchctl permission behavior has been consistent since macOS
Catalina (10.15). The per-user LaunchAgent model is the documented approach for
user-space daemons and requires no sudo.

### D8. Post-install banner

**Decision**: on success, print to stdout:

```
Sentinel installed.

  config:    ~/.config/sentinel/config.yaml
  data dir:  ~/.local/share/sentinel
  daemon:    running (PID NNN)

Next steps:
  - Notification channels are off by default. Edit config.yaml to enable ntfy/Slack/Telegram.
  - Claude Code hook is not installed. Run `sentinel hooks install` to enable.
  - macOS may prompt for Full Disk Access on first event. Allow it in:
      System Settings > Privacy & Security > Full Disk Access
```

Paths are expanded to absolute (not `~`-abbreviated) in the JSON output
(`--json`) but abbreviated with `~` in plain output for readability.

If `--no-launchagent` was passed, the `daemon:` line reads:
`daemon:    not started (--no-launchagent; start manually)`

This exact banner format is frozen. Adding new "Next steps" bullets is allowed
without superseding. Removing or reordering existing bullets requires a
superseding ADR.

**Rationale**: the banner surfaces the three most common post-install friction
points identified from v0.9–v0.10 support requests: notification channel setup,
Claude Code hook, and Full Disk Access. Showing them once at install is more
reliable than expecting users to read the README.

### D9. Relationship with install.sh

**Decision**:

- `install.sh` is preserved as-is for source-tree development workflows.
- The `install.sh` header is updated to:
  `# For source-tree development only. Operational install: pipx install sentinel-mac && sentinel install`
- `README.md` Quick Start is reordered:
  - **Option 1** (default): `pipx install sentinel-mac && sentinel install`
  - Option 2: manual steps (for users who cannot use pipx)
  - Option 3: dev install via `install.sh` (moved to "Contributing" section)

Track C implements this documentation update.

**Rationale**: install.sh fills a real need for contributors working from source.
Removing it would break the dev workflow. Demoting it in README reduces confusion
for operational users who should use `sentinel install`.

### D10. Menu bar wizard — deferred

**Decision**: option A — `sentinel install` CLI only in v0.11.0.

The menu bar first-run wizard (detect no daemon running → offer to run
`sentinel install`) is deferred to v0.11.1 or later as a separate ADR.

**Rationale**: the menu bar wizard involves `rumps` threading, modal dialogs,
and subprocess lifecycle management that are independent from the CLI install
logic. Bundling them would delay Track A/B, increase review surface, and risk
introducing regressions in the menu bar app. The CLI path covers the primary
(pipx) install scenario cleanly on its own.

## Track Split

### Track A — `sentinel install`: config + plist + launchctl + verify

**Scope**: full stateful install sequence. No read-only split is practical here
(unlike ADR 0010 Track A) because every meaningful step in `sentinel install`
writes to disk or calls launchctl. Track A is therefore a single PR covering
the complete `install` command.

Files (new unless noted):

- `sentinel_mac/installer/__init__.py`
- `sentinel_mac/installer/plist.py` — `generate_plist_xml()`, `write_plist()`,
  `read_plist_program_arguments()` (for conflict detection, D5)
- `sentinel_mac/installer/config_init.py` — `init_config()` (wraps existing
  `--init-config` logic from `core.py`, extracted to a callable function)
- `sentinel_mac/installer/verify.py` — `check_daemon_running()` (launchctl list
  + PID parse), `build_install_summary()` (banner data structure)
- `sentinel_mac/commands/install.py` — `cmd_install()` orchestrator, all flag
  handling, rollback logic
- `sentinel_mac/cli.py` — wire `install` subcommand (additive, ~5 lines)
- `sentinel_mac/core.py` — extract `init_config` logic to
  `sentinel_mac/installer/config_init.py` (refactor, not new behavior)
- `tests/test_installer_plist.py` — plist generation, conflict detection
- `tests/test_installer_verify.py` — launchctl mock, PID parse
- `tests/test_cmd_install.py` — full sequence mock; idempotency paths; EDITABLE
  early-exit; conflict abort + `--force` override; `--no-launchagent` path;
  non-interactive cancel

Dependencies: none from Track B or C.

Output: `sentinel install` works end-to-end for PIPX and PIP_VENV installs.
`sentinel uninstall` is not yet implemented.

### Track B — `sentinel uninstall`: teardown

**Scope**: symmetric teardown command. Small PR; depends on Track A for
plist path constants and install method detection.

Files (new or modified):

- `sentinel_mac/commands/uninstall.py` — `cmd_uninstall()`, all flag handling
- `sentinel_mac/cli.py` — wire `uninstall` subcommand (additive, ~5 lines)
- `tests/test_cmd_uninstall.py` — launchctl unload mock; `--purge` data
  deletion; `--keep-launchagent` skip; not-installed exit 2

Dependencies: Track A must merge first (imports `PLIST_PATH`, `PLIST_NAME`
from `core.py`; reuses `installer/verify.py` for not-installed detection).

### Track C — Documentation cleanup

**Scope**: no runtime code changes. Documentation and install.sh header only.

Files modified:

- `README.md` — Quick Start reorder (D9)
- `install.sh` — header comment update (D9)
- `CHANGELOG.md` — v0.11.0 entry summarizing D1–D10

Dependencies: Track B must merge first (changelog entry captures both `install`
and `uninstall`).

### Dependency graph

```
Track A ── Track B ── Track C ── release ceremony (v0.11.0)
```

Sequential. No parallelism — Track B imports Track A artifacts; Track C
documents both commands.

## Consequences

### Positive

- First-install path collapses from five manual steps to one command, matching
  the update experience praised in user feedback.
- Idempotency (D4 option c) handles partial-install states gracefully — no
  `--force` required for most recovery scenarios.
- Conflict detection (D5) prevents the silent "running old .venv binary"
  failure mode that affected early adopters.
- `sentinel uninstall --purge` gives users a clean exit path without leaving
  hidden config and data on disk.
- No sudo at any point — consistent with the existing daemon and update commands.
- Banner (D8) surfaces the three most common post-install friction points at the
  moment they are relevant.

### Negative / accepted trade-offs

- Track A is fully stateful — no clean read-only / write split as in ADR 0010.
  Unit tests require thorough subprocess and filesystem mocking.
- Binary path is written into the plist at install time (D3). If the user
  reinstalls sentinel-mac via a different method, `sentinel install --force`
  must be rerun. This is documented but not automatically detected.
- `--no-launchagent` users must start the daemon manually and cannot use
  `sentinel doctor` daemon-running checks until they load the plist separately.
- Menu bar wizard is deferred (D10) — pipx users with the menu bar app open
  before running `sentinel install` see no in-app guidance. This gap exists
  in v0.11.0 and is accepted.
- `--config-path` not included in v0.11.0 — users who want a non-standard
  config location must create the file manually and pass `--config` at daemon
  start.

### Follow-ups

- v0.11.1 candidate: menu bar first-run wizard (D10 deferred).
- v0.12 candidate: Homebrew formula + `sentinel install` support for HOMEBREW
  method (D3).
- v0.12 candidate: `--config-path PATH` flag for non-XDG installs.
- Future: `sentinel install --hooks` shortcut to run `sentinel hooks install`
  in the same session (reduces Next Steps friction from D8).

## Frozen surfaces

- CLI spelling: `sentinel install [--force] [--no-launchagent] [--yes] [--json]`
  and `sentinel uninstall [--purge] [--keep-launchagent] [--yes] [--json]`.
  No abbreviated flags exposed.
- Exit codes: install 0/1/2/3; uninstall 0/1/2 — as defined in D1 and D6.
- Install step order (D2): detect → config → data dir → plist → load → verify →
  banner. Reordering requires a superseding ADR.
- Plist label: `com.sentinel.agent` (reuse of `PLIST_NAME` from `core.py`).
  Changing the label requires a superseding ADR (affects all existing installs).
- `launchctl load` (not `bootstrap gui/$(id -u)`) is the load command. Rationale:
  `launchctl load` has been consistent across macOS 10.15–15.x for per-user
  LaunchAgents; `bootstrap gui/$(id -u)` is modern but requires the domain to
  already exist and adds complexity for no practical benefit in the per-user
  LaunchAgent case. The existing `updater/apply.py` already uses `load/unload`;
  consistency is preferred. If macOS deprecates `load/unload` in a future OS
  release, a superseding ADR will migrate both update and install.
- Post-install banner structure (D8): the three "Next steps" bullets are frozen.
  Addition is allowed; removal or reorder requires supersede.
- JSON envelope `kind ∈ {"install", "install_error", "uninstall", "uninstall_error"}`
  following ADR 0004 §D2 versioned format.
- `detect_install_method()` (ADR 0010 D1) is reused without modification.
  Changes to detection heuristics are governed by ADR 0010's frozen surfaces.
