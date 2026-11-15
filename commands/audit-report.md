---
description: Re-validate an audit run directory and regenerate REPORT.md, DETAILS.md, LEADS.md and findings.sarif
argument-hint: "<run dir>"
---

Use the `boring-security` skill. Run dir: `$ARGUMENTS` (default: the newest `~/boring-security-runs/*/run-*`).

Run both validators. If either fails, show the errors and stop. Otherwise regenerate the Phase 6 files per `phases/4-6-records-and-report.md` from `findings.json`, `ledger.json` and `run.json` only. Reply with the paths written and the confirmed-findings table.
