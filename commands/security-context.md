---
description: Create or refresh the repo's persistent security context (.boring-security/CONTEXT.md) so every later review and audit starts from what's already known
argument-hint: "[target] [--refresh]"
---

Use the `boring-security` skill and follow `references/project-context.md`. Target: `$ARGUMENTS` (default cwd).

1. Run Scouts A and B (no run directory): write each a brief file outside the repo with the RULES block from `SKILL.md §2` and `briefs/scout-a.md` / `briefs/scout-b.md`, and launch `boring-security:bsec-scout` (or a general-purpose subagent) with its path; with no out path they reply with their findings. If `CONTEXT.md` exists, compare against it and keep the owner's entries.
2. Draft `CONTEXT.md` from the template: fill only what the source shows, with `path:line` where useful. Put everything else (deployment facts, accepted risks, scope) in **Open questions** for the owner. Never invent owner-confirmed facts.
3. Show me the draft (or the diff with `--refresh`) and ask before writing `.boring-security/CONTEXT.md` into the repo.
