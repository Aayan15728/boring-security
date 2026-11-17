# Coverage re-check

Another agent marked the units at the end of this brief `covered`. You measure whether that was right. You are not shown its conclusion, and you must not look for it: do not read the run's ledger, results or other agents' directories.

For each unit, independently:
1. From the unit's surface, boundary and class blocks, state the security invariant it must hold.
2. Re-derive from source whether the code enforces it on every path that reaches the boundary, including siblings (legacy, batch, retry, error and fallback paths).
3. Agree only if you can quote the control that enforces it. Disagree if a path skips it, the control checks the wrong thing, or you cannot find one.

Result:

```json
{"units": [{"id": "...", "agree": true, "why": "one or two sentences",
            "anchors": [{"file": "...", "line": 1, "quote": "..."}]}]}
```

- Every unit id appears exactly once.
- `anchors` quote the enforcing control (agree) or the unguarded path (disagree), copied verbatim: at least 10 characters found within 2 lines of `line`, or the whole text of one nearby line. Anchors are verified against the source.
- A disagreement is not a finding; the lead reopens the unit for a fresh Hunter.

## Output

Write the result JSON above to the out path given under "Your files" at the end of this brief, then reply to the lead with a single summary line (for example `recheck-1: 3 units, 2 agree, 1 disagree`).
