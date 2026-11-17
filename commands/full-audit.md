---
description: Full security audit of a codebase - exhaustive deep profile, every surface and boundary, critic waves to a clean pass, recheck sample, double independent verification, coverage-aware scored report
argument-hint: "[target] [--profile deep|standard] [--out <run dir>] [--budget <agents>] [--scope <paths>] [--untrusted] [--advisories]"
---

Use the `boring-security` skill in **Audit mode**, profile `deep` unless `--profile standard` is given.

`$ARGUMENTS`: target repo root (default: cwd); `--out` run dir (an existing `recon_only` or `incomplete` run is continued after `run-state.cjs resume`; with an earlier complete run of the same repo, `run-state.cjs carry --from` it first, `references/audit-run.md` §Prior runs); `--budget` max subagent invocations; `--scope` comma-separated paths for a scoped run; `--untrusted` the code is not mine (trust rules in `references/audit-run.md` §Trust); `--advisories` opt in to the dependency advisory lookup in `references/advisories.md` (disclose what leaves the machine and ask first).

Before hunting, show me the estimate from `scripts/run-state.cjs estimate` for the chosen profile and wait for my yes (commands that borrow this reply format and run `standard` or `quick` show the estimate line and ask only above ~150 agents). Say in one line which execution mode you chose (sandboxed-local-only or source-only) and why, and whether enforcement is the plugin's hooks and restricted agents or advisory. When finished, reply with the run dir, the final status, the scorecard's overall line (with its coverage), counts (confirmed by severity and proof kind, needs_validation, rejected), the fix-plan table, and the coverage summary including the recheck miss-rate estimate. Don't paste the whole report.
