# ADR 0010 — Self-Update (v0.10)

- **Status**: Accepted
- **Date**: 2026-05-04
- **Accepted**: 2026-05-05
- **Scope**: `sentinel_mac/commands/update.py` (new),
  `sentinel_mac/updater/` (new package: `detect.py`, `version.py`,
  `apply.py`), `sentinel_mac/menu_bar.py` (additive),
  `sentinel_mac/cli.py` (additive — `sentinel update` subcommand),
  `pyproject.toml` (no version bump — implementation PRs carry that).
- **Supersedes**: —

## Context

v0.9.0 is published on PyPI. Updating to a new version requires 4
terminal commands: `launchctl unload`, `pip install -U`, `launchctl
load`, and a verification step. A user running the menu bar app has
no discoverable path to do this from the GUI.

The chosen solution (user-selected Option 1): a `sentinel update` CLI
that auto-detects the install method and runs the appropriate upgrade
command, followed by a LaunchAgent unload/load cycle. The menu bar
adds a "Check for Updates…" item that drives the same CLI as a
wrapper.

This ADR freezes the interface contracts and key design decisions
before implementation begins. Status promotes to Accepted after Track
B merges.

## Decisions

### D1. Install method detection — path heuristics, no subprocess

**Decision**: detect install method by inspecting `sys.executable`
and `sentinel_mac.__file__` path strings at runtime. No subprocess
calls to `pip show` or `pipx environment` during detection itself.

Detection priority (first match wins):

| Method | Heuristic | Upgrade command |
|---|---|---|
| editable / source | `sentinel_mac.__file__` contains `/site-packages/sentinel_mac.egg-link` OR path contains `/.editable/` OR `pyproject.toml`+`sentinel_mac/` both exist under the same root as `__file__` | early-exit (D7) |
| pipx | `sys.executable` path contains `/.local/pipx/venvs/` OR `PIPX_HOME` env var present and executable path falls inside it | `pipx upgrade sentinel-mac` |
| Homebrew | `sys.executable` path starts with `/opt/homebrew/` or `/usr/local/Cellar/` | deferred (D7) |
| pip / venv | `sys.executable` path contains `/.venv/` or `/venv/` and none of the above match | `pip install --upgrade sentinel-mac` |
| system Python (unsafe) | `sys.executable` is `/usr/bin/python3` or `/usr/local/bin/python3` and is not inside a venv | early-exit with guidance (D7) |

Detection is a pure function `detect_install_method() ->
InstallMethod` (an `Enum`: `EDITABLE | PIPX | HOMEBREW | PIP_VENV |
SYSTEM_UNSAFE`). It reads string paths only; no I/O, no subprocess.
Fast enough to call on every `sentinel update` invocation.

**Rationale**: subprocess calls to `pip show` take ~300ms and add
a failure mode (pip not on PATH when called from the menu bar
process). Path heuristics are O(1) and deterministic. The heuristic
table covers all practical install methods seen in the field; the
editable/system early-exit paths provide safe fallback messaging for
the rest.

### D2. Version source — PyPI JSON API, on-demand only

**Decision**: check for new versions by querying
`https://pypi.org/pypi/sentinel-mac/json`. Parse the `info.version`
field. Compare against the running version from
`importlib.metadata.version("sentinel-mac")` using `packaging.version.Version`
to avoid lexicographic-vs-numeric ordering bugs (`0.10.0 > 0.9.0`).

- **No automatic background polling**. Version checks happen only
  when the user explicitly invokes `sentinel update --check` or
  clicks "Check for Updates…" in the menu bar. The daemon never
  polls autonomously.
- Rationale: Sentinel's core privacy invariant (ADR 0001–0007) is
  "nothing leaves the machine without user action." An automatic
  check-in to PyPI every N hours would be the first outbound network
  call the daemon makes on its own initiative. Even version checks
  carry implicit telemetry value to a passive observer (IP + timing).
  On-demand is the correct default.
- Future opt-in: a `update.auto_check_interval_hours: 0` config key
  (0 = disabled) may be added in v0.11+ with its own ADR. Not
  implemented here.
- Timeout: 5 seconds. On timeout or any HTTP error, `--check` prints
  `warning: could not reach PyPI (timeout)` and exits 0 (not an
  error). `--apply` fails fast with the same message and exit 1.
- The PyPI JSON endpoint is public, unauthenticated, and has no rate
  limit for infrequent on-demand calls (PyPI TOS).

### D3. Daemon restart sequence

**Decision**: the update sequence is strictly ordered:

```
1. launchctl unload <plist-path>   # stop daemon
2. <upgrade command>               # install new version
3. launchctl load <plist-path>     # start daemon
4. verify                          # confirm upgrade succeeded
```

Step 1 (stop) is mandatory before step 2 (install).

Step 4 (verify): run `subprocess.run(["sentinel", "--version"], capture_output=True)`
and confirm the first line starts with `sentinel-mac {expected_new_version}`.
If mismatch, exit 1 and print manual recovery instructions.

**Why stop first**: pip overwrites `.py` files in-place. Python
caches `*.pyc` in `__pycache__`. A running daemon importing live
modules will not crash (already-imported module objects live in
memory), but the process is now running a mix of old bytecode and
newly overwritten source. On next restart it picks up the new code.
Stopping first ensures clean module state and avoids the Heisenbug
window where the daemon appears to be running v0.10.0 but is actually
executing v0.9.0 bytecode.

**Rollback**: pip does not provide atomic installs. Partial upgrade
(network cut mid-install) leaves a broken state. Mitigation:

- Before step 2, record the current version: `old_ver =
  importlib.metadata.version("sentinel-mac")`.
- If step 2 exits non-zero, attempt `pip install sentinel-mac==<old_ver>`
  (or `pipx install sentinel-mac==<old_ver>` for pipx). This is
  best-effort — if the rollback also fails, print the manual recovery
  command and exit 1.
- Rollback is **not guaranteed** (pip cannot uncommit a partial
  download). Document this limitation in `--help` and the README.
- LaunchAgent plist path: resolved from `~/Library/LaunchAgents/com.sentinel.agent.plist`.
  If not found, step 1 and step 3 are skipped with a warning (edge
  case: user installed via pip but never ran `sentinel install`).
- Implementation must import `sentinel_mac.core.PLIST_PATH` constant;
  do not hardcode the filename string in `updater/apply.py`.

**Concurrency**: `--apply` begins by attempting an exclusive lock on
`<data_dir>/updater.lock` using `fcntl.flock(LOCK_EX | LOCK_NB)`. If
another update process already holds the lock, exit 1 with message
`"another sentinel update is in progress (PID N)"`. This prevents
concurrent `--apply` invocations that could corrupt state. Reuse the
ADR 0002 daemon lockfile pattern. `--check` does not acquire the lock
(read-only operation).

### D4. Menu bar UI

**Decision**:

- Menu item label: `"Check for Updates…"`, positioned as the last
  item in the menu before "Quit".
- On click: run `sentinel update --check` in a background thread.
  - If up to date: show a transient native notification
    `"Sentinel is up to date (v0.9.0)"` and do nothing else.
  - If new version available: show a macOS alert dialog (modal)
    with three buttons: `"Update Now"`, `"Skip This Version"`,
    `"Cancel"`.
    - `"Update Now"` → runs `sentinel update --apply --yes` in a
      subprocess, showing a progress window (indeterminate spinner)
      with a streaming text view for stdout. On completion, shows
      success/failure notification.
    - `"Skip This Version"` → records the skipped version in
      `<data_dir>/updater/skipped_versions.txt` (one version
      per line); the "new version" notification will not fire for
      this version again. Future auto-check (if ever enabled per D2)
      also respects this list.
    - `"Cancel"` → dismiss dialog, no action.
- No badge on the menu bar icon for updates. Rationale: the icon is
  a security monitor; a persistent badge for an update would dilute
  the "badge = active alert" semantics established in v0.7.
- No automatic notification on startup. Consistent with D2
  (on-demand only).

**Menu bar app relaunch**: When `--apply` completes successfully, the
daemon process is restarted via the LaunchAgent load cycle (D3 step 3).
However, the menu bar app process itself continues running the old code
until manually quit and relaunched. Starting in v0.10, after a successful
`--apply`, the update command shows a native macOS notification message:
`"Sentinel updated to v{new}. Quit and relaunch the menu bar app to
load the new code."` This message is also shown in the alert dialog's
success branch when the update completes. Auto-relaunch is deferred to
v0.11+ (rumps lifecycle + modal UI state make it complex). The manual
relaunch instruction is the pragmatic v0.10 approach.

### D5. CLI surface

**Decision**:

```
sentinel update [--check | --apply] [--yes] [--json]
```

Subcommand semantics:

| Flag | Behavior |
|---|---|
| `sentinel update` (no flag) | alias for `--check` |
| `--check` | query PyPI, print current vs latest, exit 0 (up to date) or exit 2 (update available — script-friendly) |
| `--apply` | full sequence: stop daemon → upgrade → start daemon → verify |
| `--yes` | skip the "Proceed with update?" interactive confirmation in `--apply` mode |
| `--json` | emit ADR 0004 §D2 versioned envelope `kind = "update_check"` or `"update_apply"` |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success or already up to date |
| 1 | Error (network failure, install failure, rollback attempt) |
| 2 | Update available (only from `--check`; useful for `if sentinel update --check; then ... fi` scripts) |
| 3 | Unsupported install method (editable or system Python; see D7) |

Non-interactive invocation (`--yes` + `--json`) is designed for
future remote management tooling.

### D6. Permissions

**Decision**: no `sudo` required at any point.

- `launchctl unload`/`load` on a per-user LaunchAgent plist
  (`~/Library/LaunchAgents/`) runs as the current user — no elevated
  privileges needed.
- `pipx upgrade` operates on the user-owned pipx venv — no sudo.
- `pip install` inside a user-owned venv — no sudo.
- The `sentinel update` process itself is the menu bar app's child
  process (user context) or the terminal's user shell — no privilege
  escalation is designed or needed.

If the heuristic detects a system Python install (`SYSTEM_UNSAFE`),
the tool prints:

```
sentinel-mac appears to be installed under the system Python
(/usr/bin/python3). Automatic update is not supported for this
configuration because write access requires sudo, which sentinel
will never request.

To update manually:
  sudo pip install --upgrade sentinel-mac
  launchctl unload ~/Library/LaunchAgents/com.sentinel.agent.plist
  launchctl load  ~/Library/LaunchAgents/com.sentinel.agent.plist
```

and exits 3.

### D7. Editable / source install behavior

**Decision**: early-exit with guidance, no upgrade attempt.

When `detect_install_method()` returns `EDITABLE`, `sentinel update`
prints:

```
sentinel-mac is installed in editable/development mode.
Automatic update is disabled for this configuration.

To update your source checkout:
  git -C <source_root> pull
  pip install -e .    # if pyproject.toml dependencies changed
```

and exits 3. The `<source_root>` is derived from
`sentinel_mac.__file__` by walking up to find `pyproject.toml`.

Rationale: an editable install by definition means the developer is
working from source. Running `pip install -U sentinel-mac` would
replace the editable install with the released package — almost
certainly not what the developer wants. Early-exit + guidance is
safer than any automated action.

The current developer environment (`.venv/bin/sentinel`, editable)
will always see this message. This is correct behavior.

### D8. Homebrew (future, not v0.10)

**Decision**: `HOMEBREW` install method detects and exits with
guidance in v0.10:

```
sentinel-mac appears to be managed by Homebrew.
Automatic update via Homebrew is planned for v0.11.

To update now:
  brew upgrade sentinel-mac
```

Exit 3. The upgrade command (`brew upgrade sentinel-mac`) is printed
but not executed — Homebrew formula for sentinel-mac does not yet
exist. This is a placeholder that turns into a real upgrade path in
v0.11+ when the formula lands.

## Track Split

### Track A — Detection + `--check` (net-zero side effects)

**Scope**: pure read path, no filesystem mutations, no daemon restart.

Files (new unless noted):
- `sentinel_mac/updater/__init__.py`
- `sentinel_mac/updater/detect.py` — `InstallMethod` enum +
  `detect_install_method()` pure function
- `sentinel_mac/updater/version.py` — `fetch_latest_pypi_version()`,
  `get_running_version()`, version comparison helpers
- `sentinel_mac/commands/update.py` — `sentinel update` / `--check`
  CLI entry point
- `sentinel_mac/cli.py` — wire `update` subcommand (additive, 3-4
  lines)
- `tests/test_updater_detect.py` (new) — heuristic table coverage
- `tests/test_updater_version.py` (new) — PyPI mock, timeout path,
  version comparison

Dependencies: none from Track B or C.
Output: `sentinel update` and `sentinel update --check` work end-to-
end. `--apply` exits with `NotImplementedError` placeholder.

### Track B — `--apply`: upgrade + daemon restart

**Scope**: stateful path — stops daemon, installs, restarts, verifies.

Files (new or modified):
- `sentinel_mac/updater/apply.py` — `run_upgrade()`, rollback logic,
  `restart_daemon()` (launchctl wrapper)
- `sentinel_mac/commands/update.py` — wire `--apply` branch (additive)
- `tests/test_updater_apply.py` (new) — subprocess mocks for install
  + launchctl; rollback trigger on non-zero exit; plist-not-found path

Dependencies: Track A must merge first (imports `detect.py`,
`version.py`).

### Track C — Menu bar integration

**Scope**: menu item + dialog + progress window in `menu_bar.py`.

Files modified:
- `sentinel_mac/menu_bar.py` — `"Check for Updates…"` item,
  background thread for `--check`, modal dialog, progress window,
  `skipped_versions.txt` read/write
- `tests/test_menu_bar_update.py` (new) — headless / mock subprocess
  path

Dependencies: Track B must merge first (`--apply` must be functional
before wiring the "Update Now" button). Track C is a UI wrapper; it
can be developed against Track A+B stubs but not merged until B is
green.

### Dependency graph

```
Track A ── Track B ── Track C ── release ceremony (v0.10.0)
```

Sequential. No parallelism — each track's output is the next track's
API surface.

## Consequences

### Positive
- Users running pipx or pip-venv get a one-command update path.
- Menu bar UX closes the "4 terminal commands" gap for non-developer
  users.
- Detection is pure-function, testable without any subprocess mocking.
- On-demand-only version check preserves the nothing-leaves-machine
  invariant.
- Rollback best-effort + clear manual recovery instructions mean a
  failed update leaves the user informed, not stranded.

### Negative / accepted trade-offs
- pip's non-atomic install means a network cut during upgrade can
  leave a broken state. Best-effort rollback mitigates; cannot
  fully eliminate.
- Editable installs (current dev environment) always get the early-
  exit message — expected and correct; documented.
- No auto-check means users who never open the menu bar will not
  learn about new versions unless they run `sentinel update --check`
  manually or subscribe to GitHub release notifications. Acceptable
  for v0.10; opt-in auto-check is a v0.11 candidate.
- Homebrew support deferred — users who installed via Homebrew
  (formula does not exist yet) are unaffected in practice.

### Follow-ups
- v0.11 candidate: `update.auto_check_interval_hours` config opt-in
  with its own ADR (extends D2).
- v0.11 candidate: Homebrew formula + real `brew upgrade` path (D8).
- v0.11 candidate: `--keep-since`-style variant for `skipped_versions`
  TTL (auto-expire skipped versions after N days).

## Frozen surfaces

- `InstallMethod` enum values: `EDITABLE | PIPX | HOMEBREW |
  PIP_VENV | SYSTEM_UNSAFE`. Adding values is fine without supersede;
  removing or repurposing requires supersede.
- `detect_install_method()` is a pure function — no I/O, no
  subprocess. Must remain pure.
- CLI spelling: `sentinel update [--check | --apply] [--yes] [--json]`.
  No abbreviated flags exposed.
- Exit codes: 0 / 1 / 2 / 3 as defined in D5.
- Upgrade sequence order (D3): stop → install → start → verify.
  Reordering requires a superseding ADR.
- On-demand-only policy (D2): daemon never polls PyPI autonomously
  without a future ADR introducing the opt-in.
- JSON envelope `kind ∈ {"update_check", "update_apply"}` following
  ADR 0004 §D2 versioned format.

Adding new `--apply` flags or new `kind` values is fine without
superseding ADR. Changing the detection heuristic table (D1),
relaxing the on-demand-only constraint (D2), or reordering the
upgrade sequence (D3) requires a superseding ADR.
