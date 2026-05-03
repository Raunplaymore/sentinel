# ADR 0007 — Forensic Context Enrichment (v0.8 Track 2)

- **Status**: Accepted
- **Date**: 2026-05-02
- **Scope**: `sentinel_mac/collectors/agent_log_parser.py`,
  `sentinel_mac/collectors/fs_watcher.py`, new
  `sentinel_mac/collectors/project_context.py`,
  `sentinel_mac/engine.py` (Alert message formatting), `models.py`
  (no schema change — `SecurityEvent.detail` stays `dict`).
- **Supersedes**: —
- **Referenced by**: ADR 0004 §D3 (additive event detail).

## Context

A user reported on 2026-05-02 that a `critical` typosquatting alert
fired and asked "어디서 누가 뭐하다 실행된건지 알 수가 없네?". The
investigation needed `sentinel --report --since 24h --type
typosquatting_suspect --json` followed by a manual scan of 20 events
to figure out the answer. Even after that scan, the only attribution
the audit log carried was `actor_name="claude_code"` (true for every
agent_log event ever recorded).

This ADR freezes the schema + collector responsibilities for
**forensic context enrichment** so a single alert / single audit-log
row answers the four questions a user obviously wants:

- **Who** ran the command (which AI session, which model, which
  Claude Code version)
- **Where** (which project / repo / branch / cwd)
- **What** (already covered by `command` field — unchanged)
- **How** (cwd + project context closes the gap; deeper "approved by
  user vs auto-permit" is out of scope, see §D7)

Implementation lands in v0.8 Track 2 alongside the perf follow-ups.

## Decisions

### D1. Source of session metadata — scan first user/assistant message

`agent_log_parser` already opens `~/.claude/projects/<project>/<session>.jsonl`
files. The **first lines** of each JSONL are typically
`type=queue-operation` / `type=last-prompt` housekeeping records that
carry only `{type, operation, timestamp, sessionId}` — **no cwd /
gitBranch / version / model**. Real session metadata appears on the
first record whose `type` is `user` or `assistant`.

Verified against real session files (Claude Code 2.1.x) — typical
shape of a `type=user` line:

```
top-level keys: cwd, entrypoint, gitBranch, isSidechain, message,
                parentUuid, permissionMode, promptId, sessionId, slug,
                timestamp, type, userType, uuid, version
message: {content, role}
```

| Field | JSONL location | Notes |
|---|---|---|
| Session ID | top-level `sessionId` (also filename stem) | UUID, stable across the conversation |
| Working directory | top-level `cwd` (per-message — `cd` updates it) | absolute path |
| Git branch | top-level `gitBranch` | string; may be `HEAD` for detached state |
| Claude Code version | top-level `version` | e.g. `2.1.116` |
| Model | **NOT** top-level. Lives on `assistant` records as `message.model`. | First assistant message in the file populates it. |

Parser policy:
1. Open file in tail mode.
2. Skip housekeeping records (`type ∈ {queue-operation, last-prompt,
   summary}`) — they cannot populate `session.*`.
3. On the first record whose `type ∈ {user, assistant}`, capture the
   five fields above into a per-file `SessionMeta` cache. Defensive
   read — missing keys leave the corresponding `session.*` field
   `null`; never raise.
4. On every emitted SecurityEvent, override `session.cwd` with the
   per-message `cwd` of the record that triggered the event (cwd can
   change mid-session via `cd`). Other fields stay as cached.
5. `session.model` is `null` until the first `assistant` record is
   seen; subsequent events get the cached value. This intentionally
   leaves a gap — events triggered by user messages alone will have
   `model: null` and that is honest.

Upstream JSONL key changes: this module is **the** brittle surface.
Wrap each key access in `dict.get(...)`; never assume presence;
never KeyError. If a future Claude Code release renames `gitBranch`
→ `git_branch`, the corresponding `session.*` field goes `null` and
the rest of the daemon keeps running. A single `WARNING` log per
file is emitted on first miss to surface the regression.

### D2. `detail.session` schema (frozen)

Added to **every** `agent_log` SecurityEvent (typosquatting, agent_command,
agent_tool_use, agent_download, mcp_*, etc.). Always present; sub-fields
nullable.

```json
"session": {
  "id": "abc-uuid-...",       // string | null
  "model": "claude-opus-4-7", // string | null
  "version": "1.5.0",         // string | null  (Claude Code CLI version)
  "cwd": "/Users/x/proj"      // string | null  (absolute path at command time)
}
```

Adding new sub-fields is fine without superseding ADR (ADR 0004 §D3
additive). Removing or repurposing requires a superseding ADR.

### D3. `detail.project_meta` schema (frozen)

> **Naming note**: this field is `project_meta`, **not** `project`,
> because `fs_watcher`'s existing `bulk_change` events already use
> `detail["project"] = "<name string>"` and ADR 0004 §D3 forbids
> repurposing existing keys. The legacy string field stays where it
> is for backward compatibility; `project_meta` is the new structured
> field that carries the full forensic context.

Derived from `cwd` (D2) by walking up to find a project boundary.
Added to `agent_log` and `fs_watcher` events. **NOT** added to
`net_tracker` events (D5).

```json
"project_meta": null  // when cwd is unknown or no project boundary found
// OR
"project_meta": {
  "name": "sentinel-mac",          // string  — see "name resolution" below
  "root": "/Users/x/proj",         // string  — absolute path (symlink resolved)
  "git": {                         // object | null  — null if not a git repo
    "branch": "main",              // string | null
    "head": "abc123de",            // string | null  (short SHA, 8 chars)
    "remote": "owner/repo"         // string | null  (github-style; null on local-only)
  }
}
```

**Boundary detection** — walk up from `cwd`; the **first directory
that contains any of the markers** below becomes the project root.
Among co-located markers in the same directory, the priority table
breaks ties for `name` resolution:

1. `.git/` (directory) → git root, also used as project root.
2. `pyproject.toml` (file) → Python project.
3. `package.json` (file) → Node project.

This is the **first match wins** rule, not a global priority sweep:
a Node sub-project nested inside a Git monorepo finds its own
`package.json` first and uses that as `root`. The git metadata in
that case still points at the outer monorepo (we walk up
**separately** for `.git/` after the project root is decided — see
"git extraction" below).

If no marker is found within 10 parents (cap), `project_meta` is
`null`. The depth cap protects pathological cases (cwd deep under
`/tmp` etc.).

**`name` resolution** (in order; first hit wins):

1. `pyproject.toml` `[project].name` (PEP 621).
2. `pyproject.toml` `[tool.poetry].name` (Poetry projects).
3. `package.json` `"name"` field.
4. `basename(root)` (last-resort fallback when only `.git/` is
   present and no metadata file).

**`git` extraction** (no `git` binary dependency — direct file reads):

- **`branch`**: prefer the per-message `gitBranch` from the JSONL
  (already extracted for D1; cheap, always current). Fallback to
  reading `.git/HEAD` and parsing `ref: refs/heads/<branch>`.
  Detached HEAD → `branch` is `null`.
- **`head`**: read `.git/HEAD`. If it is `ref: refs/heads/<x>`,
  follow to `.git/refs/heads/<x>` (or `.git/packed-refs` fallback)
  and take the first 8 chars of the SHA. If it is a raw SHA
  (detached HEAD), use the first 8 chars directly.
- **`remote`**: parse `.git/config` for the **`[remote "origin"]`
  section first** (most projects have one); fall back to the first
  `[remote "*"]` section if no origin. Read its `url = ...` line.
  Normalize to `owner/repo` (strip `https://github.com/`,
  `git@github.com:`, trailing `.git`). Non-GitHub-shaped URLs →
  `null` in v0.8. `include` directives and `url.X.insteadOf`
  rewrites are intentionally **not** followed (rare in practice;
  v0.9+ if a user reports needing them).

If `.git/HEAD` or `.git/config` cannot be read (corrupted, restricted
permissions, not a git repo), the corresponding sub-field is `null`.
A read failure on one sub-field does **not** null the entire `git`
object — partial metadata is more useful than none.

### D4. ProjectContext caching

New module `sentinel_mac/collectors/project_context.py` exposes a
single class:

```python
class ProjectContext:
    """cwd → project_meta resolver with bounded LRU + TTL."""
    def __init__(
        self, *, ttl_seconds: int = 300, max_entries: int = 100
    ) -> None: ...

    def lookup(self, cwd: Optional[str]) -> Optional[dict]:
        """Returns the frozen `project_meta` dict (or None). Thread-safe."""

    def invalidate(self, cwd: Optional[str] = None) -> None:
        """Drop one entry (cwd given) or the whole cache.

        v0.8: not called from production code paths — defined for tests
        and for a future v0.9+ trigger that watches `.git/HEAD` mtime
        for branch-switch invalidation. The 5-min TTL is the only
        production invalidation path today; documented branch-switch
        staleness is an accepted trade-off.
        """
```

Caching is essential: every `agent_log` event would otherwise stat
the filesystem N times per second on a busy session. Eviction is
LRU on `last_accessed`; TTL drops stale entries on next access (not
proactively). Single instance shared across collectors via
`Sentinel.__init__` (mirrors `HostContext` injection from ADR 0001).

Thread safety: single `threading.RLock` guards the dict + LRU list.

**SIGHUP reload (ADR 0005 D2)**: ProjectContext is added to the D2
table as **NOT reloaded** — the cache is a pure optimization; TTL
already picks up filesystem changes lazily and reload would lose
warm entries. The corresponding row should be added to ADR 0005's
D2 table by the implementation PR (cross-ADR documentation
synchronization, not a supersede).

**Known staleness** (original v0.8 behavior): branch switches
(`git checkout`) were not reflected for up to 5 minutes (TTL). For
dev workflows that switch branches often this showed stale
`git.branch` / `git.head` until TTL expired.

#### D4 amendment — mtime invalidation (v0.9 Track 3)

The "v0.9 candidate" trigger-based invalidation noted above is now
adopted. Frozen behavior:

- On every `lookup(cwd)` call, before returning the cached entry,
  `os.stat()` `<root>/.git/HEAD` and compare its `st_mtime_ns` to
  the value captured when the entry was cached.
- If the file does not exist (project is not a git repo) → no
  invalidation check, return cached entry as before.
- If the file exists but `st_mtime_ns` differs from the cached
  value → drop the entry and recompute the full `project_meta`
  fresh, then cache with the new mtime.
- If `os.stat()` raises (file removed mid-call, permission error,
  etc.) → fall back to TTL behavior; do not surface the error to
  the caller. Logged at DEBUG once per cwd per session.

The mtime check is one extra `stat()` per cached `lookup()` —
~µs cost on a warm filesystem cache. The original 5-min TTL stays
in place as the second-line guard for non-git project changes (a
new `pyproject.toml` line, etc.).

`HostObservation`-style cache structures are unaffected — this
amendment is ProjectContext-specific.

This is an **additive** amendment — does not change the cache
shape, the public `lookup` / `invalidate` API, or any other D4
contract. Downstream code that did not opt into mtime invalidation
sees exactly the same return value (just faster freshness for
git-repo cwds). No supersede required.

**Implementation hint** (for the v0.9 Track 3 PR): the new mtime
check belongs in `project_context.py` `lookup()` immediately after
the cache-hit branch finds an entry and before it returns. Add a
private helper `_head_mtime_ns(root: Path) -> Optional[int]` that
wraps `os.stat(root / ".git" / "HEAD").st_mtime_ns` in
try/`OSError`-returns-`None`. Cache entries gain a `head_mtime_ns:
Optional[int]` field captured at insert time; on lookup, recompute
and compare — mismatch → drop and recompute. Tests should cover
(a) non-git project skips the check, (b) `git checkout` between
two lookups returns the new branch/head, (c) `os.stat` failure
falls back to TTL behavior without raising.

### D5. Collector-by-collector enrichment policy

| Collector | session | project | Rationale |
|---|---|---|---|
| `agent_log_parser` | **YES** (from JSONL) | **YES** (from per-message `cwd`) | Native source of all forensic context. |
| `fs_watcher` | NO | **YES** (from event path → walk up) | Project derived from the file's containing dir; session is unknown for non-agent file events. For events that ARE attributed to an AI process (via lsof), session info still unknown today (would need cross-correlation with agent_log timestamps — out of scope). |
| `net_tracker` | NO | NO | Per-connection cwd would require `lsof -p <pid> -d cwd` (or `proc_pidpath`) per emitted event — fork/exec cost is unacceptable for a high-frequency stream (NetTracker polls every 30s and can emit dozens of events per cycle on a busy AI session). Cross-correlation with `agent_log_parser` timestamps would give cheap session attribution but adds inter-collector state — out of scope, v0.9+ candidate. |
| `MacOSCollector` (system metrics) | NO | NO | System metrics are not per-command; no actor context applicable. |

### D6. Alert message format — surface the four answers

`engine._evaluate_*` functions append a `[ctx]` block to the existing
Alert `message`:

```
🚨 Typosquatting Suspect Package
   Package: 'requets' (looks like 'requests')

   Project: sentinel-mac (main @ abc123de)
   Session: claude-opus-4-7 #abc-uuid (CC 1.5.0)
   Where:   /Users/x/Desktop/dir_UK/sentinel
   What:    pip install requets
```

Rules:
- **Always** append the `[ctx]` block when `detail.session` or
  `detail.project` is non-null. Never break Alert when both are null
  (event types without enrichment, e.g., system thermal alerts).
- **`Project:` line** uses `name (branch @ short_sha)`. If `git` is
  null → just `name`. If project is null → omit line.
- **`Session:` line** uses `model #short_id (CC version)`. Falls back
  to `model #short_id` then `model`. Skip if all session fields null.
- **`Where:` line** uses `cwd`. Skip if null.
- **`What:` line** uses the existing `detail.command` (truncated to
  120 chars with `…` suffix if longer). Skip if no command.
- **`Package:` / event-specific first line** unchanged from existing
  alert text.

The `[ctx]` block is a strict **addition** to existing message text.
Existing notification channels accept multi-line messages with
varying truncation behavior:

- **macOS native** (`UserNotifications`): the body is visually
  truncated around ~250 characters in the Notification Center. The
  `[ctx]` block can push a typosquatting alert past that limit.
  Mitigations applied:
  - Render `cwd` with `~/` substitution when under `$HOME` (saves
    ~25 chars on macOS).
  - Truncate the `What:` line to 80 chars with `…` suffix when
    longer (was 120 in an earlier draft; tightened for macOS).
  - The original first line (e.g. `🚨 Typosquatting Suspect …`)
    stays intact so the user can see the alert kind even when the
    body is cut.
  Documented limitation; "Click to expand" reveals the full body.
- **ntfy / Slack / Telegram**: no practical limit at our message
  sizes. Slack's 40,000-char block size is far above our ceiling.

The `[ctx]` block is **best-effort**: when both `session` and
`project_meta` are null (e.g., a `MacOSCollector` system-thermal
alert), the block is omitted entirely and the alert renders as
before. Never break Alert formatting on missing context.

### D7. Privacy — what enters notification channels vs. audit log only

The audit log JSONL (`~/.local/share/sentinel/events/<date>.jsonl`)
records **everything** in detail (full schema D2/D3, including
`git.remote`). Local-only by default per the README "Privacy & Data"
section.

The Alert message that goes to opt-in notification channels (ntfy /
Slack / Telegram) deliberately omits `git.remote` from the `[ctx]`
block. Rationale: remote URL can leak private repo identity to a
third-party channel even when the user only intended to share alert
metadata. `project.name` and `git.branch` are surfaced (already
visible in any chat where the user discusses their work).

A future config toggle `notifications.context_level: "minimal" |
"standard" | "full"` may expose `git.remote` when the user opts in.
**Not** implemented in v0.8.

## Out of scope (v0.8)

- **"Approved by user vs auto-permit"** distinction (Claude Code's
  permission model). Would require parsing additional JSONL fields
  not yet stable upstream.
- **Cross-event correlation** ("this typosquat command followed an
  unknown-host network connection 30s earlier"). Adds correlation
  storage; defer to v0.9+ dashboard work.
- **`/proc/<pid>/cwd` for net_tracker** — macOS-only project; skip.
- **Cursor / VS Code Continue session metadata** — agent_log_parser
  scaffolding exists but no production observations; revisit when a
  Cursor user files an issue.
- **Multi-user attribution** — Sentinel runs as a single-user daemon;
  `actor_name` already captures process name.

## Consequences

### Positive
- A single alert answers "who / where / what / how" without grepping
  JSONL.
- Audit log gains permanent forensic context — `--report --json`
  consumers (and future Pro tooling per ADR 0004) can group events
  by project / session / model trivially.
- Project context shared across collectors via a single
  `ProjectContext` instance — consistent answers across event types.

### Negative / accepted trade-offs
- Detail size grows by ~200–400 bytes per event. Audit log on a
  busy day (~1000 events) goes from ~200KB to ~400KB. Acceptable
  given the 90-day retention auto-cleanup.
- `ProjectContext.lookup` does filesystem reads (cap 10 parents).
  Mitigated by caching (D4).
- `git.remote` extraction reads `.git/config` — small text file, no
  fork/exec. No `git` binary dependency.
- Alert messages are taller. macOS native notifications truncate
  long messages; `[ctx]` block fits in ~5 lines and renders fully on
  all observed channel types.

### Follow-ups
- Track 2 implementation PR — covers D1–D6:
  - `collectors/project_context.py` (new, ~200 LOC + cache)
  - `collectors/agent_log_parser.py` extraction of session metadata
    + project lookup
  - `collectors/fs_watcher.py` project lookup on event emission
  - `engine.py` `[ctx]` block formatting in every `_evaluate_*`
    branch
  - `core.py` `ProjectContext` injection into collectors
  - `tests/test_project_context.py` (new)
  - `tests/test_agent_log_parser.py` extension for session/project
    fields
  - `tests/test_alerts.py` extension for `[ctx]` block

- v0.9+ candidates:
  - `notifications.context_level` config toggle (D7)
  - Cross-event correlation (out-of-scope above)
  - Cursor session metadata once a user requests it

## Frozen surfaces

- `detail.session` keys: `id`, `model`, `version`, `cwd` (all nullable)
- `detail.project_meta` shape: top-level dict OR `null`. Sub-keys:
  `name`, `root`, `git` (object or null). `git` sub-keys: `branch`,
  `head`, `remote`.
- The legacy `detail.project` (string, `bulk_change` events only) is
  preserved unchanged — see D3 naming note. The new structured field
  is a **separate** key, not a replacement.
- `detail.project_meta.git.remote` is GitHub-shaped (`owner/repo`) or null.
- Collector enrichment matrix (D5).
- Alert message `[ctx]` block format and field omission rules (D6),
  including macOS-specific truncation policy (cwd ~/ substitution +
  `What:` 80-char cap).
- Privacy boundary: `git.remote` audit-log-only, never in Alert message
  (D7) — until a future ADR introduces the opt-in.

Adding new `detail.session` or `detail.project_meta` sub-fields is
fine without superseding ADR. Changing the boundary detection
precedence (D3), repurposing the legacy `detail.project` string, or
relaxing the privacy boundary (D7) requires a superseding ADR.
