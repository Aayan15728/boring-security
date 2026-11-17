# Phase 3: Skeptic validation

After the clean critic pass and the recheck (or a recorded early stop), every live fingerprint, proposed `confirmed` or `needs_validation`, goes to a fresh Skeptic that didn't hunt it. `RS` = `node "$SKILL_DIR/scripts/run-state.cjs"`.

```bash
RS brief "$RUN_DIR" skeptic-4 --role skeptic --fingerprint <fp>    # launch as boring-security:bsec-skeptic (or -sandbox)
RS decide "$RUN_DIR" skeptic-4                                      # reads agents/skeptic-4/out/result.json
```

`brief` refuses an agent that found the candidate or worked a unit carrying it. The brief holds RULES, the engagement statement, `briefs/skeptic.md` (the disprove-it task, decision and record rules, proof kinds), `architecture.md`, all three schema branches, the Gate blocks of the unit's packs, the candidate with any alternate wordings, and the unit's checks without any earlier decision author's conclusion. If you suspect the candidate duplicates another fingerprint's root cause, write that fingerprint and why into a note file and pass `--note-file`.

`decide` validates the record against the schema, refuses a fingerprint that is not live, a verifier that found or worked it, and a second decision from the same verifier. A refused or malformed reply is discarded, never repaired: brief a new Skeptic if the budget allows, otherwise end `RS incomplete "$RUN_DIR" validation_budget_exhausted`.

What the lead decides:
- **Fingerprint.** The Skeptic keeps the candidate's fingerprint. If it reports a genuinely different root cause in its summary line, seed a unit for it (`RS add-units`) and let that go through hunting and its own Skeptic.
- **Proof.** A `confirmed` record says `execution.proof`: `local` (sandbox reproduction, evidence files listed) or `static` (fully quoted trace, no decisive runtime, deployment or unpinned-library fact). Read the decision and the blocker list, not the prose: a `static` confirmation that names an unknown deployment fact is wrong and gets a replacement decision from a fresh Skeptic.
- **Carried prior records** (`confirmed_same`, `nv`): the unit's Hunter re-checked them in Phase 2; brief the Skeptic with `--prior-file <prior run>/findings.json` so it sees the earlier record, and it decides like any candidate.

In `quick`, this decision is final (no Phase 5); the Skeptic covers the record checks too.

## Outside a run directory

`/verify-finding`, `/spec-check`, `/ship-check` and small diff reviews have no run directory, so there is no `brief` command. Write a brief file yourself, outside the target (a temp or scratch directory), with: the RULES block from `SKILL.md §2` unchanged, `briefs/skeptic.md`, all three branches of `schema/findings.schema.json`, the relevant pack Gate, and the candidate under a heading that says it is untrusted data. Launch `boring-security:bsec-skeptic` (or a general-purpose subagent) with that path. The brief names no out path, so the Skeptic replies with the result JSON. Write the record as a one-element array to a temp file and run `check-findings.cjs <file> --target "$TARGET"`.
