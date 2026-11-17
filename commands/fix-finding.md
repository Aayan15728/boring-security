---
description: Fix one verified finding in your own repo - new branch, failing regression test first, smallest root-cause change, existing tests, then a fresh skeptic tries to break the fix; never commits to default, pushes or deploys
argument-hint: "<fingerprint | run dir + fingerprint | description>"
---

Use the `boring-security` skill and follow `references/fixing.md`. Finding: `$ARGUMENTS`

1. Confirm the repo is mine and the working tree is clean. Load the record; if I gave a description or the record isn't `confirmed`, run `/verify-finding` logic first and stop unless it comes back `confirmed`.
2. Work on a new `security/fix-<short-slug>` branch. Write the regression test, see it fail for the right reason, apply the smallest change at the last trusted decision point, list sibling paths with the same root cause, run the existing tests.
3. Send the record and the diff to one fresh Skeptic to break the fix.

Stop and ask before a schema migration or a breaking API change. Never commit to the default branch, push, merge, deploy, or touch secrets or deployed settings; if a secret was exposed, tell me exactly what to rotate.

Reply with the branch, diff summary, test results (new test before/after, existing suite), sibling paths, the Skeptic's answer, and what I still have to do.
