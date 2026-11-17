---
description: Supply-chain / CI / release security audit - privileged workflows running untrusted input, expression injection, unpinned inputs, signing and update trust
argument-hint: "[target] [--profile quick|standard|deep] [--out <run dir>] [--budget <agents>] [--untrusted] [--advisories]"
---

Use the `boring-security` skill in **Audit mode** as a scoped run on `packs/supply-chain.md` (profile from `--profile`, otherwise `standard` per `references/audit-run.md` §Profiles). Other arguments and reply as in `/full-audit`: `$ARGUMENTS`

Seed one unit per workflow job that holds a secret or write permission, per dependency source, and per release/update channel.
