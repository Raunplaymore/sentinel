# ADR 0008 — Notification Context Level (v0.9 Track 3)

- **Status**: Accepted
- **Date**: 2026-05-03
- **Scope**: `sentinel_mac/engine.py` (`_format_ctx_block` rendering),
  `sentinel_mac/notifier.py` (per-channel pass-through),
  `sentinel_mac/core.py` (config plumbing), `config.example.yaml`
  (new key under `notifications:`).
- **Supersedes**: ADR 0007 §D7 (only the "always omit `git.remote`"
  default — see D2 below)

## Context

ADR 0007 §D7 made `git.remote` audit-log-only — the user-facing
alert message in v0.8.0 deliberately omits the remote URL so opt-in
notification channels (ntfy / Slack / Telegram) cannot accidentally
leak private-repo identity. That default is right for solo developers
on personal projects, but two real cases push back:

1. **Solo developer in a single-org context** (the user's own
   `Raunplaymore/sentinel` repo case). They post the same repo
   identity in commit messages, PR titles, branch names, and the
   GitHub Release notes — `git.remote` in an alert adds zero
   privacy risk and saves a context-switch when triaging.
2. **Privacy-strict user** wants the opposite — even
   `Project: my-app (main @ abc123)` is too much because they treat
   the alert channel as untrusted. Today the only escape is to
   disable the notification channel entirely.

A binary toggle would be enough for case 1 alone, but case 2 needs
a third position. Three-state setting frozen here.

## Decisions

### D1. Three-state setting under `notifications.context_level`

```yaml
notifications:
  context_level: standard   # minimal | standard | full
```

| Value | What appears in the alert message body |
|---|---|
| `minimal` | The original alert text only. **No** `[ctx]` block at all (no Project / Session / Where / What lines). The JSONL audit row is unaffected — full context still recorded. |
| `standard` | Current v0.8.0 behavior. Project name + git branch + git head SHA, session model + id + version, cwd (with `~/` substitution under HOME), command (truncated to 80 chars). **`git.remote` omitted.** This stays the default. |
| `full` | Same as `standard` plus a `Repo: owner/repo` line immediately under `Project:`. Only `git.remote` is added — no other audit-log-only field is opted in by `full`. |

**Default**: `standard`. Same on-screen text as v0.8.0 today; no
upgrade-time surprise. Users who do not set the key see no change.

### D2. Supersede scope of ADR 0007 §D7

ADR 0007 §D7 fixed the `git.remote` user-visibility policy as
"audit-log-only forever". This ADR narrows that to "audit-log-only
**when `notifications.context_level` is `minimal` or `standard`** —
opt-in opt-out via `full`". The other ADR 0007 §D7 commitments
(Project name, branch, head, session, cwd are surface-OK; command is
truncated; macOS `~/` substitution applies) are unchanged.

Adding new opt-in audit-log-only fields to `full` in the future
(e.g., `git.remote_full_url` instead of `owner/repo`) is allowed
without superseding this ADR — must be additive and gated behind
`full`.

### D3. Global, not per-channel

The setting is a single global value, not per-channel
(`notifications.macos_context_level`, `notifications.ntfy_context_level`,
etc.). Rationale:

- The privacy concern is the **content** of the alert message, which
  is constructed once and sent to every active channel. Per-channel
  granularity would require recomputing `_format_ctx_block` per
  channel — cheap but adds branching that is hard to test exhaustively.
- The two real cases (D1 §1 and §2) are user-level postures, not
  channel-level — a user who treats Slack as untrusted would also
  treat ntfy as untrusted in the same setup.
- v0.10+ can introduce per-channel overrides (`notifications.slack:
  {context_level: minimal}`) without superseding this ADR — additive
  layering on top of the global default.

### D4. Engine implementation contract

`_format_ctx_block(detail, *, level: Literal["minimal", "standard", "full"])`
becomes the new signature. The engine reads the global setting once
at evaluation time and threads it through to every Alert formatting
call. No collector changes; no JSONL audit log changes.

Alert object **does not** gain a `context_level` field. The setting
is consumed at format time and not preserved. Rationale: keeping the
Alert dataclass tight; the JSONL row already carries the full context
regardless of how the user-facing string was rendered.

### D5. Validation + fallback

Unknown / typo'd values (e.g., `context_level: full_disclosure`) →
fall back to `standard` + log a single `WARNING` at startup. Never
crash on a bad config value here; this key is convenience plumbing,
not a security gate. Validation lives in `_validate_config`
(extending the existing structural check) so a bad value at SIGHUP
reload also falls back rather than aborting the reload (ADR 0005 D3
atomic-or-nothing — config keeps the old value).

## Consequences

### Positive
- Solo developers on single-org repos get the missing
  `Repo: owner/repo` line without an out-of-band lookup.
- Privacy-strict users get a clean escape hatch (`minimal`) that
  doesn't require disabling channels entirely.
- Default behavior is unchanged — zero upgrade-time surprise.

### Negative / accepted trade-offs
- One more config key to document (small).
- `git.remote` rendering in `full` mode introduces an asymmetry
  with the audit log (which always carries it) — acceptable because
  the JSONL row is the canonical record; alert text is a UI choice.
- Users who set `full` and later change their mind have to know to
  set it back to `standard`. Documented.

### Follow-ups
- **Track 3 implementation** (this v0.9 cycle): `_format_ctx_block`
  signature change + `_validate_config` extension + `config.example.yaml`
  block + 3 tests (one per value) + ADR 0007 D7 cross-reference
  update in the README "Forensic Context in Every Alert" section.
- **v0.10+ candidate**: per-channel overrides (D3 trade-off
  reversed) if a user actually requests it. Per D3, the planned
  shape is **additive layering on top of the global default** —
  `notifications.slack: {context_level: minimal}` falls back to the
  global `notifications.context_level` when omitted. This ADR does
  not need superseding for that addition; the per-channel keys land
  alongside the global key without changing its semantics.
- **v0.10+ candidate**: introduce `confidential` value that also
  redacts `Project:` / `cwd` (currently not on the table — `minimal`
  already drops the entire block, which covers that need).

## Frozen surfaces

- Three-state enum: `minimal` / `standard` / `full` (no other values).
- Default: `standard`.
- Only field opted in by `full` over `standard`: `git.remote`
  (rendered as a `Repo: owner/repo` line directly under `Project:`).
- Global single setting; no per-channel keys in v0.9.
- Validation is fail-soft (unknown value → `standard` + WARNING).
- ADR 0007 §D7's audit-log-only commitment for `git.remote` is
  narrowed to **`minimal` and `standard` modes only**; `full` mode
  surfaces it.

Adding new context-level values, repurposing existing ones, or
making `full` surface additional audit-log-only fields requires a
superseding ADR.
