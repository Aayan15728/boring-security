# Phase 3: Skeptic validation

After the clean critic pass (or a recorded early stop), consolidate candidates and carried prior confirmations by fingerprint. Every unique candidate, proposed `confirmed` or `needs_validation`, goes to a fresh Skeptic that didn't hunt it. Each Skeptic gets its own `agents/<id>/scratch/` and lead-owned `evidence/`.

Brief contents: RULES (`SKILL.md §2`); the candidate; its unit's checks and evidence paths; the architecture facts needed to read the path; the relevant pack Gate blocks; all three branches of `schema/findings.schema.json`; prior records with the same fingerprint. Never include another Skeptic's conclusion.

```text
You did not write this candidate. Try to break it.
1. Re-open every cited file/line/scope. Is the first trace step a real lower-trust entry point and
   the last the claimed sink or boundary effect?
2. Rebuild the strongest visible controls on the path: validation, identity, authorization,
   normalization, lifecycle, framework defaults at the pinned version, containment. If
   architecture.md names a comparable product, note whether it shares the pattern (calibration,
   never dismissal).
3. Proposed confirmed: reproduce the minimum observed result yourself if you safely can. Verify
   inputs, interface shape, conditions and the affected dummy principal/resource.
4. Do likelihood, impact, confidence and the fix match only what was shown?
5. Proposed needs_validation: is the blocker truly outside source/local reach? Refuted → rejected.
   Still decisive → keep it, and make the local and owner-observed plans exact.
6. Keep the fingerprint for the same root cause.
Reply: {"decision": "confirmed|needs_validation|rejected", "record": {...that schema branch...}}
Your record replaces the hunter's wording.
```

Decision rules:
- `needs_validation` becomes `confirmed` only if the Skeptic itself established the full path and a bounded observed result.
- `confirmed` becomes `needs_validation` when a specific deployment or runtime fact is still unknown.
- `rejected` when source, local behaviour, a visible control, missing impact or an impossible prerequisite kills it.

Save each reply to a file and run `run-state.cjs decide <run> <skeptic-id> <file>`. It validates the record against the schema, refuses a verifier that found the candidate, and refuses a second decision from the same verifier. Phase 5 replacements go through the same command with a fresh verifier id.

Lead checks:
- **Fingerprint.** The same fingerprint must come back. A genuinely different root cause gets a new fingerprint and its own Skeptic.
- **Malformed replies.** Discard a malformed reply without repairing it. Rerun with a fresh Skeptic if the budget allows; otherwise the run ends `incomplete`.
- **Ledger checks.** Add the Skeptic's evidence as its own check (`by: <skeptic-id>`). The unit `owner` stays the same, except on a carried prior record's seeded `planned` unit, where the Skeptic becomes owner and its check moves the unit to `candidate`.

In `quick`, this Skeptic also performs the Phase 5 record checks.
