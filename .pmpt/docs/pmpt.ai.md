<!-- This file is for AI tools only. Do not edit manually. -->
<!-- Paste this into Claude Code, Codex, Cursor, or any AI coding tool. -->

# sentinel — Product Development Request

## What I Want to Build
watch things for safe computing.

## Additional Context
Existing project with established codebase.
- Git history: 2 commits since 2026-02-27, 1 contributor(s)
- Recent work: "Translate README to English + add social preview image", "Initial release v0.1.0 — AI Session Guardian for macOS"

## Key Features
- Existing project features

## Tech Stack Preferences
Python 3.8+ (requires-python pinned for backward compat); core deps: psutil (system metrics), pyyaml (config), watchdog (FSEvents), requests (ntfy/Slack); optional [app] extra: rumps (menubar), ruamel.yaml (comment-preserving config edit); dev tooling: pytest, ruff (lint), mypy (type-check, lenient — strict ratchet planned for v0.9); CI: GitHub Actions on macos-latest × Python 3.9–3.13 matrix; release: PyPI Trusted Publishing via release-published trigger (no API tokens). macOS-only by design (FSEvents, lsof, launchd); Linux/Windows port deferred to v0.10+.

---

Please help me build this product based on the requirements above.

1. First, review the requirements and ask if anything is unclear.
2. Propose a technical architecture.
3. Outline the implementation steps.
4. Start coding from the first step.

I'll confirm progress at each step before moving to the next.

## Documentation Rule

**Important:** When you make progress, update `.pmpt/docs/pmpt.md` (the human-facing project document) at these moments:
- When architecture or tech decisions are finalized
- When a feature is implemented (mark as done)
- When a development phase is completed
- When requirements change or new decisions are made

Keep the Progress and Snapshot Log sections in pmpt.md up to date.
After significant milestones, save a snapshot using the method below.

### Saving Snapshots

**Always save proactively after milestones — do not wait for the user to ask.**

Try the pmpt MCP tool first:
- Claude Code: call `mcp__pmpt__pmpt_save` with a descriptive `summary`
- Other MCP clients: call `pmpt_save` with a descriptive `summary`

If no MCP tool is available, run `pmpt save` in the terminal.

### Per-Feature Checklist
After completing each feature above:
1. Mark the feature done in `.pmpt/docs/pmpt.md` (change `- [ ]` to `- [x]`)
2. Add a brief note to the Snapshot Log section
3. Call `mcp__pmpt__pmpt_save` (or `pmpt save` in terminal) with a summary

### What to Record in pmpt.md

pmpt.md is the **single source of truth** for this project. AI tools read it to understand context before every session. Keep it accurate.

**## Architecture** — High-level structure. Update when the architecture changes.
- Example: `Next.js (SSG) → Cloudflare Workers API → D1 database`
- Include the WHY if the stack choice was non-obvious

**## Active Work** — What's currently being built. One or two items max.
- Clear this section when done, then move to Snapshot Log
- Example: `- Implementing user auth (started 2025-03-17)`

**## Decisions** — Record WHY, not just WHAT. Include what led to the decision.
- Bad: "Switched to SQLite"
- Good: "Switched SQLite → Postgres: deploy target moved to serverless, needed connection pooling"

**## Constraints** — Platform or library limitations discovered during development.
- Format: `- [Platform/Tool]: what doesn't work → workaround used`
- Example: `- Cloudflare Workers: no native fs access → use KV for file storage`

**## Lessons** — Anti-patterns and "tried X, broke because Y" discoveries.
- Format: `- [What failed] → [Root cause] → [Fix applied]`
- Example: `- JWT refresh on mobile broke → tokens expired before retry → added sliding expiry`
