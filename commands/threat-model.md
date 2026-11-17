---
description: Recon-only threat model - architecture, principals, trust boundaries, entry surfaces and a seeded coverage ledger, without hunting
argument-hint: "[target] [--out <run dir>]"
---

Use the `boring-security` skill in **Audit mode**, but run only `phases/1-recon.md` (profile `standard`) on: `$ARGUMENTS`

Include the detector and inventory passes and close the inventory gaps. End with a ledger that passes `check-ledger.cjs --target`, then `run-state.cjs incomplete <run dir> recon_only`. Reply with:
1. A Mermaid `flowchart`: principals → entry surfaces → controls → protected assets.
2. The top 10 units by hunting priority (`phases/2-hunt.md`), one line each.
3. Selected packs and why.
4. The command to continue: `/full-audit <target> --profile standard --out <same run dir>` (the ledger was seeded for `standard`).
