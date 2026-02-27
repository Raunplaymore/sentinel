# .pmpt — Your Project's Development Journal

This folder is managed by [pmpt](https://pmptwiki.com). It records your product development journey with AI.

## What's Inside

```
.pmpt/
├── config.json     ← Project settings (auto-generated)
├── docs/
│   ├── pmpt.md     ← Human-facing project document (YOU update this)
│   ├── pmpt.ai.md  ← AI-facing prompt (paste into your AI tool)
│   └── plan.md     ← Original plan from pmpt plan
└── .history/       ← Version snapshots (auto-managed)
```

## Quick Reference

| Command | What it does |
|---------|-------------|
| `pmpt plan` | Create or view your AI prompt |
| `pmpt save` | Save a snapshot of current docs |
| `pmpt history` | View version history |
| `pmpt diff` | Compare versions side by side |
| `pmpt publish` | Share your journey on pmptwiki.com |

## How to Get the Most Out of pmpt

1. **Paste `pmpt.ai.md` into your AI tool** to start building
2. **Update `pmpt.md` as you go** — mark features done, log decisions
3. **Run `pmpt save` at milestones** — after setup, after each feature, after big changes
4. **Publish when ready** — others can clone your journey and learn from it

## When Things Go Wrong

| Problem | Solution |
|---------|----------|
| Lost your AI prompt | `pmpt plan` to regenerate or view it |
| Messed up docs | `pmpt history` → `pmpt diff` to find the good version |
| Need to start over | `pmpt recover` rebuilds context from history |
| Accidentally deleted .pmpt | Re-clone from pmptwiki.com if published |

## One Request

Please keep `pmpt.md` updated as you build. It's the human-readable record of your journey — what you tried, what worked, what you decided. When you publish, this is what others will learn from.

Your snapshots tell a story. Make it a good one.

---

*Learn more at [pmptwiki.com](https://pmptwiki.com)*
