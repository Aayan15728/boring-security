# Fixing a finding (`/fix-finding`)

The audit never edits target code. Fixing is a separate, explicit mode, on the owner's own repository, one finding at a time. RULES (`SKILL.md §2`) still bind every subagent; this mode lets the **lead** edit the target's source on a branch, nothing else.

## Before touching code

1. **Own repo.** Confirm with the user that the repository is theirs to change. A vendored dependency, a fork of someone else's project or a read-only checkout → stop and describe the fix instead.
2. **Tree state.** Run `git status` and `git branch --show-current`. Uncommitted changes → ask the user to commit or stash; don't mix them with the fix.
3. **A verified finding.** Load the record by fingerprint from a run's `findings.json` (or from the run dir the user names). Only `confirmed` records are fixed. Given a description or a `needs_validation` lead, run `/verify-finding` first; never fix an unverified claim. A lead that stays `needs_validation` gets its owner check, not a patch.
4. **Branch.** Create `security/fix-<short-slug>` from the current head. Never work on the default branch.

## Making the fix

1. **Regression test first.** Write a test that performs the record's `execution` with dummy principals (user A against user B's resource, the unsigned webhook, the client-sent price) and asserts it is refused. Run it inside the sandbox if the project's tests can run there; see it **fail for the right reason** (the attack succeeds), not because of a setup error. If tests can't run, write the test anyway and say it is unexecuted.
2. **Smallest change at the last trusted decision point.** Enforce the record's `intended_behavior` where the server decides: the policy, the server action, the webhook handler, the query predicate. Fix the root cause, not the reported path: if three routes share the missing check, the fix goes where they converge or in each, and the test covers one.
3. **Siblings.** Search for the same root cause elsewhere (same helper, same pattern, same table, same missing call). Fix those inside this branch only if they are the same invariant; list every one with `path:line` either way.
4. **Run the project's existing tests** (sandboxed) plus the new test. Report what ran, what passed, and what couldn't run.

## Rules

- One finding per branch and per commit. No drive-by refactors, renames, formatting or dependency bumps.
- Never weaken, skip or delete an existing test to make the suite pass. A test that breaks because it relied on the insecure behaviour is reported to the user, not edited silently.
- Rejected fixes: anything that only hides the symptom. A client-side check, removing the button or route from the UI, renaming the endpoint, obscurity, or a deny-list of the exact reported payload.
- Stop and ask before a schema migration, a data backfill, a breaking API change, or a change to a shared auth/policy module other code depends on. Describe the change and its blast radius instead.
- **Secrets.** Deleting a committed secret does not fix the exposure: it stays in git history, forks, caches and builds. Name exactly what to rotate (which key, in which provider, which environments) and tell the owner to rotate it first. Rotation, history rewriting and redeploys are the owner's job. Never print the secret.
- Never commit to the default branch, push, open or merge a PR, deploy, change hosting/BaaS/CI settings, or touch real secrets. Commit on the fix branch only if the user asks.

## Break the fix

Send one fresh Skeptic (didn't hunt, verify or write the fix) the original record and the diff, with RULES:

```text
You did not write this fix. Try to break it.
1. Replay the record's exact execution against the fixed code. Does it still work?
2. Try the nearest variants: other argument shapes, another route/action/RPC to the same state
   change, the same table through another client type, the same check in sibling files.
3. Did the fix move trust elsewhere (to the client, a header, a new unverified parameter) or open a
   new path (error branch that skips the check, fallback when config is missing)?
4. Does the regression test exercise the attack, and would it fail on the old code?
Reply: {"decision": "fixed|not_fixed|fixed_here_root_cause_open",
        "open_paths": ["path:line", ...], "why": "..."}
```

`not_fixed` → revise and send to a new Skeptic. `fixed_here_root_cause_open` → list the paths; fix them on this branch only if they are the same invariant and the user agrees.

## Reply

Branch name; diff summary (files, lines, what invariant is now enforced and where); regression test and its before/after result; existing test results; sibling paths; the Skeptic's decision verbatim; secrets to rotate, if any; what the owner must still do (review, merge, deploy, rotate, run the owner check from `references/deployed-checks.md` if the fix depends on deployed policy).
