# Pack: Supply chain, CI and release

## When to use

Dependency resolution and lockfiles, code generation, CI/CD workflows, build containers, release, signing and promotion, auto-update and OTA channels (CodePush, EAS Update, Sparkle, Squirrel), plugin and extension ecosystems.

## Discipline

```text
- Name the attacker role: fork-PR author, issue/comment author, package publisher (or squatter),
  pusher to an unprotected branch, plugin author, or holder of a cache/artifact write.
- The crown jewels are CI secrets, OIDC tokens, signing keys, release and registry permissions.
  Trace which attacker-controlled input executes, or is interpreted, in a job that holds them.
- Data is code here: branch names, PR titles, commit messages, artifact contents, cache contents and
  dependency install scripts all execute or get interpolated somewhere.
- Org/repo settings (branch protection, required reviews, environment approvals, fork-PR approval
  policy) live outside the repo. Name the exact setting when it decides the outcome.
- Evidence is the workflow/build file plus static reasoning, or a local render; never a workflow run.
```

## Dependencies and build inputs

**Dependency source and namespace confusion**
Internal package names resolvable from public registries; missing scoped-registry config; `--extra-index-url` mixing; git dependencies on mutable refs.

**Mutable and unbound build inputs**
Actions or images pinned to tags or branches instead of digests/SHAs; `curl | sh`; lockfiles not enforced (`npm install` instead of `npm ci`, missing `--frozen-lockfile`/`--require-hashes`).

**Generated-source provenance**
Code generated from schemas, specs or remote IDLs fetched at build time without review or pinning.

**Build-context inclusion**
Secrets, `.git`, `.env` or credentials copied into images or published artifacts (`COPY . .` without `.dockerignore`, `files` globs).

## CI and automation

**Untrusted code in a privileged workflow**
`pull_request_target`, `workflow_run`, `issue_comment` triggers that check out or execute PR-controlled code (build scripts, `package.json` scripts, Makefiles, test configs) while holding secrets or write tokens.

**Workflow command and expression injection**
`${{ github.event.* }}`, branch names or PR titles interpolated into `run:` scripts or `actions/github-script`; untrusted values written to `GITHUB_ENV`/`GITHUB_OUTPUT`/`GITHUB_PATH`.

**Cache, artifact and workspace trust mixing**
Untrusted jobs writing caches or artifacts that release jobs later restore; shared self-hosted runners that persist workspace between trust levels.

**Automation identity overreach**
`permissions: write-all` or missing `permissions:`; long-lived PATs; cloud OIDC trust policies with wildcard `sub`/`aud` that accept any branch, PR or repo.

## Release and update

**Build-to-promotion substitution**
What's signed or published isn't provably what was built and tested; artifacts rebuilt or re-downloaded between stages.

**Release authorization and signing-policy gaps**
Anyone with push can tag a release; signing keys in env reachable by untrusted steps; no protected environment.

**Update metadata and rollback confusion**
Unsigned manifests, signature checked after extraction, downgrade allowed, update URL or channel taken from user/attacker-controllable config, OTA JS bundles without code signing.

**Plugin and extension trust expansion**
Plugins receive more API than they declare, install from arbitrary URLs, or load without signature or publisher pinning.

## Moves

- For every workflow: triggers, `permissions`, secrets, environments, runner type, and each step that reads event data.
- Trace each attacker-controlled field into `run:`, scripts, env files, or code that executes.
- List each dependency source and whether resolution is locked and verified.

## Gate

1. Name the attacker role and what they control (PR, package, comment, cache).
2. Cite the job/step where that input executes or is interpolated, and the secret or permission reachable there.
3. Missing pinning or broad permissions without such a path is hardening.
