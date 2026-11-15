---
description: Cloud / IaC / Kubernetes / serverless security audit from source - IAM reach, exposure, workload identity, secrets, storage policies; no cloud API calls
argument-hint: "[target] [--profile quick|standard|deep] [--out <run dir>] [--budget <agents>]"
---

Use the `boring-security` skill in **Audit mode** as a scoped run on `packs/cloud-infra.md` (profile default `deep`). Other arguments and reply as in `/full-audit`: `$ARGUMENTS`

Add `supply-chain` (images, deploy identity) and `data-lifecycle` (buckets, backups) when recon finds them. Seed one unit per workload identity and per exposed entry.
