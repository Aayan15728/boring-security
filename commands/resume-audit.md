---
description: Resume an audit after a crash, rate limit, closed session or context reset - repairs run state from disk and continues where it stopped
argument-hint: "<run dir>"
---

Use the `boring-security` skill. Run dir: `$ARGUMENTS` (default: the newest `~/boring-security-runs/*/run-*` whose `run.json` status is `in_progress`).

Run `scripts/run-state.cjs recover <run dir>`, then follow the `next:` line it prints. Continue with the phase files from there. Don't redo work that is already on disk.
