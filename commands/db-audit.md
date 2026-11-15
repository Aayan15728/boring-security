---
description: Database integrity and concurrency audit - constraints, races, lost updates, idempotency, transactions, money types, timestamps, migration drift; races proven on a local DB, never on production
argument-hint: "[target] [--profile quick|standard|deep] [--out <run dir>] [--budget <agents>]"
---

Use the `boring-security` skill in **Audit mode** as a scoped run on `packs/data-integrity.md` (profile default `deep`). Other arguments and reply as in `/full-audit`: `$ARGUMENTS`

- Also select `data-lifecycle` (tenant isolation, deletion, restore) and `core-classes.md#Business logic`.
- Seed one unit per invariant × writer path, not per table. Recon must produce the invariant table and constraint inventory described in the pack's Moves.
- Never connect to a deployed database, even read-only. Schema facts come from migrations, models and schema dumps in the repo.
