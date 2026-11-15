---
description: Recon-only threat model - architecture, principals, trust boundaries, entry surfaces and a seeded coverage ledger, without hunting
argument-hint: "[target] [--out <run dir>]"
---

Use the `boring-security` skill in **Audit mode**, but run only `phases/1-recon.md` (profile `standard`) on: `$ARGUMENTS`

End with `status: "incomplete"`, `incomplete_reason: "recon_only"`, and a validated ledger. Reply with:
1. A Mermaid `flowchart`: principals → entry surfaces → controls → protected assets.
2. The top 10 units by hunting priority (`phases/2-hunt.md`), one line each.
3. Selected packs and why.
4. The command to continue: `/full-audit <target> --out <same run dir>`.
