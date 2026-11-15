# Diff review mode (`/sec-review`)

A lighter, PR-sized version of the audit for reviewing a change before it merges. Same evidence bar, same three verdicts, same safety rules — but scoped to what the change touches and with no run directory unless asked.

## 1. Resolve the change

In priority order:
1. Argument is a PR number/URL → `gh pr diff <n>` (if `gh` exists), else ask for the branch.
2. Argument is `A..B` or a branch → `git diff --merge-base <base> <branch>`.
3. Argument is a path → review those files as "new code".
4. Nothing given → staged + unstaged changes (`git diff HEAD`), or the last commit if the tree is clean.

Record the base and head SHAs.

## 2. Mini-recon (you, not a subagent, unless the diff is large)

From the diff and the files it touches, answer briefly:
- Which **entry surfaces** does the change add or alter (routes, handlers, intents, IPC methods, tool definitions, CI triggers, IaC resources)?
- Which **boundaries** does it touch (authn, authz, tenant scope, sandbox, signing, secrets, input validation, rendering)?
- What **controls were removed, loosened, or bypassed**? Deleted lines matter as much as added ones.
- Which **packs** apply (same selection rule as the audit: boundary-driven).

## 3. Hunt

Small diff (≲ 400 changed lines, ≤ 2 boundaries): hunt yourself using `core-classes.md` + selected pack blocks.
Larger: one Hunter per boundary, briefed as in `phases/2-hunt.md` but with units = (changed surface × boundary × class). Run `scripts/detect.cjs <repo> --diff <base>` first and trace each hit. Always include one **Obvious things** pass over the diff (secrets, debug flags, TODO-auth, permissive CORS, new `eval`).

Read beyond the diff wherever the invariant depends on unchanged code (callers, middleware, siblings). A diff that's safe in isolation can break an assumption elsewhere — that's in scope.

Diff-specific questions:
- Does a new route/handler/component get the same middleware, guards, and scoping as its siblings?
- Did a refactor move a check *after* the side effect, or into a path that's skipped on error?
- Did a type/serializer change start accepting fields (mass assignment) or drop validation?
- Did a dependency, workflow, Dockerfile or manifest change widen trust (new permission, `pull_request_target`, `exported=true`, `allowBackup`, broader IAM)?
- Did tests for a security check get deleted or `skip`ped?

## 4. Validate

Each candidate goes to a fresh Skeptic with the `phases/3-skeptic.md` brief (a single Skeptic is enough here; no separate Phase 5). Small reviews may use one Skeptic for all candidates **only if** none of them were found by that Skeptic.

## 5. Output

Default: reply inline in this format, no files.

```
## Security review — <base>..<head>

**Verdict:** block / fix before merge / ok to merge (with notes)

### Confirmed
| Sev | Title | Where | What happens |
...
<per finding: path:line, actor, bounded repro, observed, fix (diff snippet), regression test>

### Needs validation
| Title | Where | Blocker | How to settle |

### Hardening (non-blocking)
- ...

### Checked and fine
- <boundaries/classes that were examined and held, one line each>
```

"Block" only for a confirmed high/critical. If the user asks for files, write `REVIEW.md` and `findings.json` (validated with `scripts/check-findings.cjs`) to `~/boring-security-runs/<repo>/review-<head-sha7>/`. With `--comment` and a PR, offer to post findings as review comments — ask before posting.
