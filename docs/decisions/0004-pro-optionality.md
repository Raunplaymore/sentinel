# ADR 0004 — Pro Branch Optionality (v0.7 design constraints)

- **Status**: Accepted
- **Date**: 2026-05-02
- **Scope**: Cross-cutting design constraints applied during v0.7 (and
  carried forward unless superseded). No code lives at any single
  location for this ADR.
- **Supersedes**: —
- **Referenced by**: ADR 0002 §D1, §D2; ADR 0003 §D2, §D5

## Context

User confirmed in v0.7 planning that a Pro / paid branch of Sentinel
is a real future option ("Q5 분기 고려"). No specific Pro feature is
decided. The concrete need is: **v0.7 design choices should not lock
out plausible Pro paths** (cloud audit, team dashboards, managed
rules, paid notification channels, longer retention, etc.).

This ADR is unusual — it documents what we are **deliberately not
deciding** plus the constraints that protect optionality. It exists
so future contributors reading "why is this here / why is this
missing?" find the answer in one place instead of git archaeology.

## Decisions (constraint shape, not feature shape)

### D1. No license/Pro plumbing in OSS until a Pro feature lands

No `license_key`, `pro_enabled`, `tier`, or similar field appears in
config schema, CLI flags, or environment variables until a concrete
Pro feature ships. Adding any of those preemptively is dead code +
visible-but-unused surface that confuses OSS users.

When the first Pro feature lands:
- A new ADR (ADR 00XX) freezes the license-check shape.
- The check lives in a single module (`pro.py` or similar) with a
  clean OSS no-op when no license is present.

Until then: zero OSS code paths reference Pro.

### D2. All `--json` outputs use a versioned envelope

Universal envelope shape:

```json
{
  "version": 1,
  "kind": "<noun>",
  "generated_at": "<ISO 8601 UTC>",
  "data": { /* kind-specific payload */ }
}
```

- `version` is an integer. Bumped on **incompatible** schema change.
  Additive changes (new keys in `data`) do **not** bump version.
- `kind` identifies the payload shape (e.g., `host_context_status`,
  `report_events`, `agent_download_summary`).
- `generated_at` is ISO 8601 UTC (`2026-05-02T11:00:00Z`).
- `data` is the kind-specific body. New keys may appear; old keys keep
  meaning forever.

Rationale: Pro tooling (or any third-party consumer) can rely on
`(version, kind)` to dispatch parsing. We get forward-compat for free
on the OSS side.

Affected v0.7 surfaces:
- ADR 0002 — `--report --json` event listing (`kind: report_events`)
- ADR 0003 — `sentinel context status --json` and mutation results

### D3. SecurityEvent detail schemas are additive — never reuse keys

Inside `SecurityEvent.detail`:
- New fields may be added freely (no version bump on the event type).
- Existing keys keep their meaning forever, even if the value becomes
  semantically narrower over time.
- Removing a key or repurposing it for a different meaning requires
  a superseding ADR.
- New `event_type` values are introduced when a new kind of event is
  meaningfully different (cf. ADR 0002 `agent_download` rather than
  mutating `agent_command`).

Rationale: the JSONL audit log at `~/.local/share/sentinel/events/`
is the **most important long-lived data structure** in the project.
Pro features (cloud forwarding, team dashboards, compliance reports)
all consume it. Schema stability is non-negotiable.

### D4. Blocklist / config layering — inline now, additive layers later

`HostContext.blocklist` is loaded from `config.yaml` inline (ADR 0003
§D2). For Pro, a future "managed blocklist" (e.g., loaded from a URL,
or pushed from a team server) plugs in via additive merge:

```
effective_blocklist = local_blocklist ∪ managed_blocklist
```

No replacement, no precedence rule needed. Implementation today:
single source. Implementation tomorrow: union of N sources. The
v0.7 schema (`security.context_aware.blocklist: [strings]`) does not
conflict.

Same principle applies to `custom_rules` — a Pro "shared rule pack"
is an additive loader, not a schema change.

### D5. Notification channels stay plugin-shaped

`notifier.py` already follows the "if value present, channel active"
pattern (each channel reads its own config keys). New Pro channels
(PagerDuty, Datadog, Opsgenie, etc.) plug in the same way:

```yaml
notifications:
  pagerduty_routing_key: "..."   # Pro feature; OSS ignores
```

OSS notifier reads keys it knows about; Pro notifier extends the
registry. No factory rewrite, no plugin-loader hell.

### D6. Audit log forwarding — Pro wraps, OSS unchanged

Cloud forwarding of the JSONL audit log is a plausible Pro feature.
The OSS `event_logger` MUST keep its current shape: write to local
JSONL, daily rotation, 90-day cleanup. Pro adds a forwarder by
subscribing to events at the same emission point — no code changes
in OSS `event_logger.py` to enable Pro forwarding.

Implementation hook (today): `event_logger.write_event` is a single
call site — Pro's forwarder can wrap or call-through. Don't optimize
this now (no observer pattern boilerplate); just preserve the single
call site.

## Things deliberately NOT decided

- **Pro feature list** — no commitment to which features become Pro vs.
  stay in OSS. This ADR only protects optionality.
- **Pricing model** — irrelevant to code structure.
- **OSS license boundary** — current README says MIT. Whether OSS stays
  MIT forever is a separate decision; nothing in this ADR forces a
  change.
- **Pro distribution channel** — separate package on PyPI? Add-on
  installable as `sentinel-mac[pro]`? Separate repo with its own
  release cadence? All deferred.
- **Telemetry/usage metrics** — README "Privacy & Data" (Track C) says
  "Nothing leaves your machine unless you opt in". This ADR does NOT
  weaken that promise. Any future telemetry is opt-in + documented +
  goes through a separate ADR.

## Consequences

### Positive
- Pro work in 6/12 months can begin without ripping up OSS schemas.
- Contributors get clear constraints (additive only, versioned envelope,
  single-source-of-truth registries).

### Negative / accepted trade-offs
- The "additive only" rule means OSS will accumulate some technically-
  unused fields over time (kept for compat). Cleanup is a v1.0+ event.
- "No Pro code in OSS" means we cannot share even small utilities
  between branches today. Acceptable cost.
- Versioned envelope adds one level of indentation to every JSON output.
  Trivial.

### Follow-ups
- Each subsequent ADR that defines a new `--json` output or
  `SecurityEvent.detail` shape should reference this ADR's §D2/§D3.
- When the first Pro feature is concretely planned, open an ADR
  alongside it covering: license check shape, OSS/Pro repo layout,
  install story, telemetry posture (if any).

## Non-frozen — explicitly soft

This ADR is principles, not interfaces. Specific schemas and code
shapes that *implement* these principles are frozen by the per-feature
ADRs (0002, 0003, …). Updating this ADR with additional principles
(e.g., a new optionality concern) does **not** require superseding —
just append a new D-number and re-issue with an updated date.
