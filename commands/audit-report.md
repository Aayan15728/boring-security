---
description: Re-validate an audit run directory and regenerate REPORT.md, DETAILS.md, LEADS.md and findings.sarif
argument-hint: "<run dir>"
---

Use the `boring-security` skill. Run dir: `$ARGUMENTS` (default: the newest `~/boring-security-runs/*/run-*`).

Run both validators with `--target` (`references/audit-run.md` §Phases; the target is `run.json.target`). If either fails, show the errors and stop. Otherwise regenerate the Phase 6 files per `phases/4-6-records-and-report.md` from `findings.json`, `ledger.json`, `run.json` and the run's other records only (`score.cjs` for the scorecard). Don't change `run.json` status. Reply with the paths written and the confirmed-findings table.
