---
description: Turn needs_validation leads blocked on deployed state (RLS, rules, buckets, env vars, webhooks, CI settings) into read-only checks you run yourself, then re-decide each lead from your pasted results
argument-hint: "[run dir | target] [--connected]"
---

Use the `boring-security` skill and follow `references/deployed-checks.md`. Input: `$ARGUMENTS` (default cwd). You never run the checks yourself.

1. **Collect leads.** Run dir: every `needs_validation` record in `findings.json` whose blocker is a deployed fact. Target with no run dir: build leads from `scripts/inventory.cjs` and `packs/app-stack.md` (tables and rules not created by repo migrations, buckets, public env vars, webhook endpoints, CI triggers), each with its source trace.
2. **Give me the checks.** One numbered list: check · the fingerprints/leads it settles · exact read-only command or console location · what a bad result looks like · what not to do. Merge duplicates. Ask me to paste results with the date, never secret values.
3. **Re-decide.** For each lead, one fresh Skeptic with the record and my pasted result, cited as `owner-observed (<date>)`. In a run dir: save my pasted result to a file and run `run-state.cjs brief <run> <fresh-id> --role skeptic --fingerprint <fp> --note-file <file> --note-untrusted`, then `decide`, `assemble`, both validators with `--target`; a changed record needs a Phase 5 `record-check` (standard/deep), then `run-state.cjs complete <run>` again (the new decision set the run back to `in_progress`). Without a run dir: `phases/3-skeptic.md` §Outside a run directory, and validate with `scripts/check-findings.cjs <file> --target <repo>`.
4. Offer to add the observed facts to `.boring-security/CONTEXT.md` (Deployment facts, dated); write only if I agree.

`--connected`: only if I pass it and a first-party read-only connector of mine is in this session, the lead (never a subagent) may read configuration metadata through it after I confirm the project identifier, per the bounded rules in `references/deployed-checks.md`. Without the flag, don't offer it.

Reply with a table: lead · check · observed · new decision (confirmed with severity / still needs_validation with the remaining blocker / rejected with reason).
