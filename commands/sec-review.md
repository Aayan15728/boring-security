---
description: Security code review of a diff, branch, PR or files with a skeptic pass (named sec-review to avoid clashing with built-in /code-review and /security-review)
argument-hint: "[PR | base..head | branch | paths] [--files] [--comment]"
---

Use the `boring-security` skill in **Diff review mode** (`modes/diff-review.md`) on: `$ARGUMENTS`

`--files` writes `REVIEW.md` and `findings.json`; `--comment` offers to post PR comments after asking me.
