---
description: Adversarially validate one suspected vulnerability (scanner hit, bug report, hunch) with a fresh skeptic - returns confirmed / needs_validation / rejected
argument-hint: "<description of the issue, or path to a finding JSON>"
---

Use the `boring-security` skill. Candidate: `$ARGUMENTS`

1. Turn the input into a candidate (principal, controlled input, intended control, boundary, affected resource, claimed result, source trace). Find the code yourself if only a description was given.
2. Run one fresh Skeptic per `phases/3-skeptic.md`. Don't pre-judge the candidate in its brief.
3. Write its record as a one-element array to a temp file and validate it with `scripts/check-findings.cjs`.

Reply with the decision and the record as readable markdown; for `confirmed`, add the smallest fix and a regression test.
