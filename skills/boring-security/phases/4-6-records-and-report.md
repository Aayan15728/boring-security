# Phases 4-6 — Records, fresh-eyes verification, reports

## Phase 4 — `findings.json`

Build `RUN_DIR/findings.json` with `run-state.cjs assemble <run>`, which sorts stored decisions by fingerprint, validates them and cross-checks the ledger. Re-read `schema/findings.schema.json` right before writing — it rejects unknown properties, so strip hunter wrapper fields like `proposed`.

| Field | confirmed | needs_validation | rejected |
|---|---|---|---|
| fingerprint, title, description, trace, evidence | ✔ | ✔ | ✔ |
| root_cause, intended_behavior, conditions, execution, remediation, severity, confidence | ✔ | ✘ | ✘ |
| claimed_root_cause | ✘ | ✔ | ✔ |
| blockers, validation_plan (≥1 of local/deployment) | ✘ | ✔ | ✘ |
| reason | ✘ | ✘ | ✔ |
| category, cwe, packs (optional metadata) | optional | optional | optional |

- `execution` uses the target's **native** interface: HTTP request, CLI call, library call, message, file fixture, intent/deep link, IPC call, rendered policy, test harness. HTTP is not the default.
- `observed_result` is factual and non-empty.
- `severity.overall` must not exceed `severity.impact`.
- Trace: one entry → `entrypoint` or `sink`; several → starts `entrypoint`, ends `sink`, `propagation` between.

Run both validators (`references/audit-run.md`). Passing proves **shape and consistency**, not truth.

## Phase 5 — Fresh-eyes record check

One fresh Scout per `confirmed` and per `needs_validation` record, in parallel. It checks the **record**, not the hunter's story. (In `quick` this was already done by the Phase 3 Skeptic.)

For `confirmed`:
1. Every path/line/scope/operation in trace and evidence is real.
2. The entry interface and exact input shape are real.
3. Every condition, parser/policy step, visible preventing layer, and the observed result hold.
4. The affected principal/resource and impact are what was demonstrated.
5. Likelihood and impact are realistic; overall ≤ impact.
6. The fix (and any `code_changes`) enforces the invariant rather than shifting trust elsewhere.

For `needs_validation`:
1. The path is real and supports only the stated `claimed_root_cause`.
2. Each blocker is decisive and can't already be answered locally.
3. It names a boundary and a concrete possible result, not a generic worry.
4. The plan is exact: `local` = bounded fixture; `deployment` = what an owner should *observe* (config, identity, route, policy, runtime fact). Never "send traffic to prod".
5. Fingerprint matches prior/current records for the same root cause.

Reply: `{"decision":"verified","fingerprint":"..."}` or `{"decision":"replace","why":"...","record":{...}}`. Malformed → discard and rerun fresh.

**Material replacements need yet another independent check.** If a replacement upgrades the verdict (anything → confirmed) or changes root cause, trace, input, observed result, impact or severity, hand the complete replacement to a new verifier who hasn't hunted, skeptic'd, or proposed it. Repeat until `verified`. If budget/independence runs out: remove the disputed record from `findings.json`, keep its unit as an unresolved candidate, end `incomplete` / `verification_unavailable`. Wording-only or line-number fixes can be applied directly.

After every applied replacement: rerun both validators, update linked ledger units. A newly discovered separate root cause gets a new fingerprint and goes back through Phase 3.

## Phase 6 — Reports (derived, never authoritative)

Write only after Phase 5. Prose never changes a verdict, severity, blocker or impact; if prose and JSON disagree, the JSON wins and the prose is wrong.

### `REPORT.md`

1. **Run facts** — profile, scope, budget (spent vs planned), source ref, execution mode statement, prior runs used, carried confirmations, revalidations, deferred and out-of-scope coverage. Quick / scoped / budget-limited / incomplete runs say **"partial pass"** in the first paragraph and list unvalidated fingerprints + units and any critic that didn't run.
2. **Posture** — 3-5 sentences.
3. **Scorecard and fix plan**: the output of `scripts/score.cjs RUN_DIR`, pasted unchanged. Never hand-edit or estimate a score.
4. **Accepted risks** (only if `CONTEXT.md` lists any): confirmed findings matching an unexpired accepted risk, with the owner's reason and review date.
5. **Confirmed findings table** — severity · title · boundary · one-line observed result.
6. **Each confirmed finding** — location, lower-trust principal, native bounded reproduction, conditions, actual result, impact, why this priority, smallest fix.
7. **Needs validation table** — title · trace · exact blocker · local next step · owner-observed check. No severity, never called a vulnerability.
8. **Hardening notes** (from `notes.hardening`) and **positive patterns** worth keeping.
9. **Coverage** — counts of covered / candidate / blocked / deferred / out_of_scope, notable exclusions, final critic result, and "no prior ledger" if applicable.

Rejected records are not findings; mention fingerprints only to explain a disagreement with a prior run.

### `DETAILS.md`

For each confirmed medium/high/critical: ordered trace + evidence; dummy attacker and affected dummy resource; native input and exact bounded steps; observed output and the invariant it disproves; conditions and containment; fix + regression test.

### `LEADS.md`

For each `needs_validation`: trace, verified evidence, exact blocker, boundary at stake, local and/or owner-observed resolution plan. Prioritised, no severity, no live-testing instructions.

### `findings.sarif`

```bash
node "$SKILL_DIR/scripts/to-sarif.cjs" "$RUN_DIR/findings.json" > "$RUN_DIR/findings.sarif"
```

Confirmed → SARIF `error`/`warning`/`note` by severity; needs_validation → `note` with `"kind": "review"`; rejected is omitted. Upload to GitHub code scanning if the owner wants inline annotations.

A clean run can have zero confirmed findings. Say so plainly, along with the coverage and validation limits. Don't invent LOWs.
