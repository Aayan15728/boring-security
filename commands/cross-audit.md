---
description: Cross-repository audit - two or more repos that call each other; finds the interfaces between them (HTTP, RPC, GraphQL, queues, webhooks, shared tables, shared packages) and hunts the trust gaps at each one
argument-hint: "<repoA> <repoB> [<repoC>...] [--profile quick|standard] [--out <parent dir>] [--budget <agents>] [--untrusted] [--advisories]"
---

Use the `boring-security` skill in **Audit mode** on several repos at once, following `references/cross-repo.md`. Profile from `--profile`, otherwise `standard` (`references/audit-run.md` §Profiles; show the estimate per repo and ask only above ~150 agents in total). `$ARGUMENTS`: two or more repo roots; `--out` the shared parent directory (default `~/boring-security-runs/cross-<aliases>/`), with one run directory per repo under it; other flags as in `/full-audit`. If any repo is not mine, every run is `untrusted`.

Run `scripts/cross-repo.cjs` over all repos before seeding, copy its JSON to each run directory as `cross-repo.json`, add each repo's interface seeds, then the normal per-repo units. Hunt interface units first, each Hunter with read-only access to the far-side repo. Record each interface finding once, in the run of the repo where the fix belongs, naming both repos.

When finished, reply with: the parent directory; the edge summary (counts by kind and confidence, plus unmatched outbound calls that point at services not included); the interface findings (title, both repos, verdict, severity, where it is recorded); and one scorecard line per repo (status, overall line with coverage). Don't paste the reports.
