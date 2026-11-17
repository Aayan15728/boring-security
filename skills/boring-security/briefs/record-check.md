# Fresh-eyes record check (Phase 5)

You check the **record** given at the end of this brief, not the hunter's story. You did not hunt, decide or propose it.

For `confirmed`:
1. Every path/line/scope/operation in trace and evidence is real.
2. The entry interface and exact input shape are real.
3. Every condition, parser/policy step, visible preventing layer, and the observed result hold.
4. The affected principal/resource and impact are what was demonstrated.
5. Likelihood and impact are realistic; overall ≤ impact.
6. The fix (and any `code_changes`) enforces the invariant rather than shifting trust elsewhere.
7. `execution.proof` matches what was done: `"local"` lists promoted `execution.evidence_files`; `"static"` has a trace quoting the whole path from entrypoint to sink.

For `needs_validation`:
1. The path is real and supports only the stated `claimed_root_cause`.
2. Each blocker is decisive and can't already be answered locally.
3. It names a boundary and a concrete possible result, not a generic worry.
4. The plan is exact: `local` = bounded fixture; `deployment` = what an owner should *observe* (config, identity, route, policy, runtime fact). Never "send traffic to prod".
5. The same root cause keeps the same fingerprint as in earlier and current records.

Result: `{"decision":"verified","fingerprint":"..."}` or `{"decision":"replace","why":"...","record":{...}}`. A replacement is a complete record of the same schema branch rules and needs yet another independent check.

## Output

Write the result JSON above to the out path given under "Your files" at the end of this brief, then reply to the lead with a single summary line (for example `check-4: idor:src/api/orders.ts:getOrder verified`).
