---
description: Full security audit of a codebase - exhaustive deep profile, every surface and boundary, critic waves to a clean pass, double independent verification, scored report
argument-hint: "[target] [--profile deep|standard] [--out <run dir>] [--budget <agents>] [--scope <paths>]"
---

Use the `boring-security` skill in **Audit mode**, profile `deep` unless `--profile standard` is given.

`$ARGUMENTS`: target repo root (default: cwd); `--out` run dir; `--budget` max subagent invocations; `--scope` comma-separated paths for a scoped run.

Before hunting, show me the cost estimate from `scripts/run-state.cjs estimate`. Say in one line which execution mode you chose (sandboxed-local-only or source-only) and why. When finished, reply with the run dir, the scorecard's overall line, counts (confirmed by severity, needs_validation, rejected), the fix-plan table, and the coverage summary. Don't paste the whole report.
