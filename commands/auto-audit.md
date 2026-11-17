---
description: Audit with a headless orchestrator - the lead does recon, a deterministic driver runs hunting, critics, recheck and validation in fresh headless sessions, the lead writes the reports
argument-hint: "<run dir | target> [--profile quick|standard|deep] [--max-parallel N]"
---

Use the `boring-security` skill in **Audit mode**: `$ARGUMENTS`. Read `references/audit-run.md` and `references/orchestrator.md`.

1. **Phase 1 (you).** If the argument is a run directory with a seeded ledger (a `/threat-model` `recon_only` run or an interrupted audit), reuse it. Otherwise run `phases/1-recon.md` on the target with the profile given (default `standard`; show `run-state.cjs estimate` first, as `audit-run.md` §Profiles says), including the inventory for standard/deep, and stop once `check-ledger.cjs --target` passes. A sandboxed run is not supported by the orchestrator: keep it `source-only` or use `/full-audit`.
2. **Dry run.** `node "$SKILL_DIR/scripts/orchestrate.cjs" "$RUN_DIR" --dry-run` and show the user the first round and one argv line.
3. **Start it for Phases 2-5.** Tell the user to run it in their own terminal (it outlives this session and uses their login):
   `node "$SKILL_DIR/scripts/orchestrate.cjs" "$RUN_DIR" --max-parallel <N> --retry-wait auto`
   Say how to watch it (`run-state.cjs status "$RUN_DIR"`, `tail -f "$RUN_DIR/usage.jsonl"`, its stdout) and how to resume it after a crash, reboot or usage limit: rerun the same command. Don't run it yourself through a short-lived tool call; if the user insists, start it in the background and only poll `run-state.cjs status`.
4. **When it exits.** Read only its last lines and `run-state.cjs status`. Exit 0: run Phase 6 (`phases/4-6-records-and-report.md`), pasting `orchestrator/score.txt` unchanged; `findings.sarif` is already written. Exit 3: resolve what it printed (waivers, scope decisions, a disputed record) yourself, then rerun the driver. Exit 4: tell the user the reset time. Exit 6: the run is `incomplete`; write the reports as a partial pass. In the run facts, say the run was driven headlessly and give the enforcement line from `references/orchestrator.md` §Prerequisites.
