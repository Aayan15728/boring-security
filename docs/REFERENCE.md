# boring-security reference

Everything the [README](../README.md) leaves out: every command and flag, what a run writes, how scoring and completion work, the detector, the layout and the tests. Install: [INSTALL.md](../INSTALL.md). Limits: [README](../README.md#what-it-does-not-do).

## Commands

| Command | What it does |
|---|---|
| `/full-audit [path]` | **Audits everything** (deep profile): every surface × boundary, every pack whose boundary exists, every identity-spec row, every detector hit and inventory surface accounted for, critic waves until clean, a recheck sample of covered units, two independent verifiers per finding, coverage-aware scored report. Shows the cost estimate and waits for your yes before hunting. |
| `/deep-audit [path]` | Alias of `/full-audit`. |
| `/quick-audit [path]` | One hunter wave + one critic, one skeptic per candidate. Fast, honest about being partial. |
| `/sec-review [PR \| a..b \| branch \| paths]` | Security code review of a diff/PR/branch/files with a skeptic pass. Verdict: block / fix before merge / ok. |
| `/ship-check [path] [--advisories]` | Cheap pre-deploy pass for starter-stack apps (Next.js/SvelteKit/Nuxt + Supabase/Firebase + Stripe + model APIs): fixed 12-item checklist, verdict, fixes and owner checks. Partial by design. |
| `/web-audit [path]` | Web app & API: access control, injection, sessions, OAuth/JWT/SAML, CSRF, CORS, caching, SSRF, DOM XSS; adds the app-stack pack when recon finds a BaaS/serverless stack. |
| `/mobile-audit [path] [--with-backend]` | Android / iOS / RN / Flutter / Capacitor: exported components, intents, deep links, WebView bridges, storage, TLS, embedded keys, BaaS rules. |
| `/db-audit [path]` | Database integrity & concurrency: constraints, races, lost updates, idempotency, transactions, money/time types, migration drift. Races proven on a local DB. |
| `/ai-audit [path]` | LLM / agent / MCP: injection → real actions, tool authority, confirmation binding, memory poisoning. |
| `/cloud-audit [path]` | IaC / Kubernetes / IAM / serverless from source — no cloud API calls. |
| `/supply-chain-audit [path]` | CI workflows, dependencies, release signing, OTA/auto-update, plugins. |
| `/cross-audit <repoA> <repoB> [...]` | Two or more of your repos that call each other: finds the interfaces between them (HTTP, RPC, GraphQL, queues, webhooks, shared tables and packages) and hunts the trust gaps at each one. One run per repo. |
| `/auto-audit <run dir | path>` | You do recon; a deterministic driver (`scripts/orchestrate.cjs`) runs hunting, critics, recheck and validation in fresh headless `claude -p` sessions, resuming after crashes and usage limits; you write the reports. Experimental: see below. |
| `/threat-model [path]` | Recon only: architecture, trust boundaries, seeded coverage ledger, Mermaid diagram. Continue later on the same run dir. |
| `/resume-audit <run dir>` | Continue after a crash, rate limit, closed session or context reset — nothing already on disk is redone. |
| `/audit-report <run dir>` | Re-validate a run and regenerate reports + SARIF. |
| `/verify-finding <issue>` | Run one suspected bug (scanner hit, bug report) through an independent skeptic. |
| `/verify-deployed [run dir \| path]` | Turn leads blocked on deployed state (RLS, rules, buckets, env vars, webhooks, CI settings) into read-only checks **you** run, then re-decide each lead from your pasted results. |
| `/fix-finding <fingerprint>` | Fix one verified finding in your own repo: new branch, failing regression test first, smallest root-cause change, then a fresh skeptic tries to break the fix. Never pushes or deploys. |
| `/security-context [path]` | Create/refresh `.boring-security/CONTEXT.md`, the repo's persistent security memory (assets, actors, boundaries, owner-confirmed facts, accepted risks). |
| `/spec-check [jwt\|oauth\|oidc\|saml\|webauthn] [path]` | Row-by-row check against the MUST rules of RFC 7519/8725, RFC 6749/7636/9700, OIDC Core, SAML 2.0 and WebAuthn, with spec citations. |
| `/obvious-scan [path]` | Literal sweep for hardcoded secrets, debug switches, open admin routes, `eval`, permissive CORS — each traced. |

Audit commands accept `--out <dir>`, `--budget <max agents>`, `--untrusted` (the code is not yours: the session is not rooted in it and its own config is ignored), `--advisories` (opt-in dependency advisory lookup; it tells you what leaves the machine and asks first), and most accept `--profile quick|standard|deep` / `--scope <paths>`.

Plain requests work too: *"security audit this repo"* runs the `standard` profile (it prints the estimate first and asks only for very large runs), *"is this endpoint safe?"*, *"review my PR for security"*.

**Cost.** A deep audit is expensive: its estimator predicts on the order of 170 agents for a 60k-line repo. Run `node skills/boring-security/scripts/run-state.cjs estimate <repo> --profile <p>` to see agents and tokens for your repo before choosing. Profiles change breadth, never the evidence bar. Three things cut the bill without lowering the bar: a later run **carries** units whose code is provably unchanged since a complete earlier run instead of re-hunting them; in the `standard` profile, low-risk units go to a cheaper-model hunter and a stratified sample of them is re-checked by strong agents; related units are batched per hunter. The estimate models neither carried nor lite units, so it reads high.

**Repeat runs.** One run finds only part of what repeated independent runs find. For an important target, run it two or more times and merge them with `run-state.cjs merge-runs`: the union of findings, the runs that disagree (each needs a fresh skeptic), possible duplicates, and a rough estimate of how many findings exist in total.

## What a run produces

Default location `~/boring-security-runs/<repo>/run-<N>/` (outside your repo):

```
run.json          run facts: profile, scope, trust, execution mode, status (set only by the completion gate)
architecture.md   ≤1000-word system map
ledger.json       coverage ledger — the actual coverage claim (covered, carried from a prior run, candidate, …)
hashes.json       hashes of the code behind reviewed units, so the next run can carry what didn't change
detector.json     deterministic detector leads, plus everything it excluded, suppressed or skipped
inventory.json    deterministic list of entry surfaces; each must be covered by a unit or waived with a reason
findings.json     confirmed / needs_validation / rejected (schema-validated, every quote checked against source)
REPORT.md         run facts, scorecard + fix plan, findings, coverage (inventory, critics, recheck miss-rate estimate)
DETAILS.md        full repro or static trace for confirmed medium+
LEADS.md          needs_validation handoff for owners, ordered by worst impact if true
findings.sarif    upload to GitHub code scanning
agents/<id>/      per-agent brief, scratch, own result, promoted evidence
```

The **scorecard** (`scripts/score.cjs`) is coverage-aware: only covered, carried or candidate units count as reviewed (carried vs freshly reviewed is stated); an area under 50 % coverage gets no score; overall coverage caps the overall score (under 50 %: no score at all; under 90 %: never an A). The report never shows a score without its coverage. A score describes what this run reviewed and proved, not the absence of bugs.

A run is `complete` only when `run-state.cjs complete` agrees: no open units, every candidate decided, every record independently verified (standard/deep), two distinct clean critics at the current coverage, every inventory surface accounted for, the recheck sample answered (deep, or whenever cheaper-model hunters covered units), and `findings.json` current. Any change after that sets it back to in progress.

## Design rules

- **No boundary, no finding.** A candidate needs a lower-trust actor, a crossed boundary, an affected resource, and a proven result.
- **Two kinds of proof.** `local`: reproduced in a sandbox, with evidence. `static`: a fully quoted source trace, allowed only when no runtime, deployment or library-version fact decides the outcome. Anything with a decisive unknown is `needs_validation`.
- **The finder never validates.** Every candidate goes to a fresh skeptic that tries to break it; the run state refuses a validator that found or worked the candidate.
- **Three verdicts.** `confirmed` (with severity), `needs_validation` (exact blocker, *no* severity), `rejected` (kept so it isn't rediscovered).
- **Severity = demonstrated likelihood × demonstrated impact.** Overall can't exceed impact.
- **Defense-in-depth gaps are hardening notes**, not vulnerabilities.
- **Safe by default.** Source-only unless a real sandbox (no network, clean env, read-only target, resource limits) passes the probe. Never touches deployed systems, real accounts or paid APIs.
- **The repo under review is data.** Its comments, docs, agent configs and suppression files can't instruct the auditor or switch the detector off.
- **Runs add up.** A later run carries unchanged reviewed units from a complete earlier run (by file hash), re-hunts what changed, and re-validates carried findings.

## Deterministic detector

```bash
node skills/boring-security/scripts/detect.cjs <repo> [--json out.json] [--diff <base>] [--history [N]] [--files a,b] \
     [--min-confidence low|medium|high] [--include-tests] [--no-target-config]
node skills/boring-security/scripts/detect.cjs --list-rules
```

116 rules across secrets, injection, XSS, web/auth, crypto/TLS, mobile, CI, containers/IaC, BaaS rules, data integrity, AI, and file-level and aggregate "missing control" rules for the app stack. No network or model calls, and it never runs target code. Each rule ships with must-match and must-not-match examples that the tests enforce. Hits are **leads**: the audit traces each one before anything becomes a finding.

- **Nothing is silent.** Every exclusion, suppression and skip is listed in the output.
- **The target can't switch it off.** Patterns that match every file or every rule are rejected; suppressions need a reason and an expiry at most 365 days ahead; inline ignores name one exact rule id. `--no-target-config` ignores the target's config entirely (use it for code you didn't write).
- `--diff <base>` reads suppression config from the base, so a change can't silence itself, and flags config changes.
- `--history [N]` scans lines added by the last N commits (default 500) with secret rules.
- Secret rules also run in test, fixture and generated paths.

Surface inventory: `node skills/boring-security/scripts/inventory.cjs <repo> [--json out.json]`. It lists routes, handlers, actions and functions it recognises. It misses prefix-mounted and dynamically built routes, and its auth hint only looks in the same file: it is a cross-check, never proof of completeness.

## Expected scanner flags

Skill scanners and secret scanners may flag this repo: its docs describe attacks, its detector rules and tests contain example secrets and vulnerable code (`scripts/detect-rules.cjs`, `scripts/test/`, `hooks/test/`), and `bench/corpus/` holds deliberately vulnerable apps. Those strings are fixtures; every "secret" is fake. `.boring-security/config.json` excludes the rule file and the corpus from the detector. Secret rules still scan test files, so running it on this repo reports the fake Stripe key fixture in `scripts/test/detector.test.cjs`; that one lead is expected.

## Layout

```
.claude-plugin/          plugin + local marketplace manifests
agents/                  8 restricted subagent types (bsec-scout, -hunter, -hunter-lite, -hunter-sandbox, -skeptic, -skeptic-sandbox, -critic, -record-check)
hooks/                   PreToolUse confinement for bsec-* agents, PostToolUse write-time secret guard
commands/                22 slash commands
install.cjs              installer (plugin or copy mode, manifest, uninstall, --check)
bench/                   regression corpus (3 apps), detector benchmark, run scorer
skills/boring-security/
  SKILL.md               always loaded: modes, shared agent RULES, evidence and severity, pack index
  core-classes.md        injection, access control, files/SSRF, crypto, business logic, feature abuse, chains, wildcard, obvious things
  phases/                1-recon, 2-hunt, 3-skeptic, 4-6-records-and-report (what the lead does and decides)
  briefs/                subagent task templates (scouts, hunter, critic, recheck, skeptic, record check)
  modes/diff-review.md   PR / diff review flow
  packs/                 13 domain packs (app-stack, web-and-identity, browser-client, mobile, desktop-and-local-ipc, ai-agents,
                         native-memory, supply-chain, cloud-infra, messaging-rpc, availability, data-lifecycle, data-integrity)
  references/            audit-run (setup, trust, agents, profiles, cost, prior and repeat runs, ending), identity-specs, project-context,
                         sandbox, evidence-promotion, advisories, deployed-checks, fixing, cross-repo, orchestrator
  schema/                findings.schema.json
  scripts/               run-state.cjs (run state, briefs, carry, tiers, completion gate, estimates), brief.cjs, merge-runs.cjs,
                         orchestrate.cjs, cross-repo.cjs, detect.cjs + detect-rules.cjs, inventory.cjs, check-ledger.cjs,
                         check-findings.cjs, score.cjs, to-sarif.cjs, sandbox-probe.cjs, promote.cjs, tests
```

## Requirements

- Claude Code (or another agent with subagents + tool use). The plugin install adds restricted subagents and hooks; other hosts get the same briefs with advisory enforcement.
- Node.js ≥ 18 for the zero-dependency scripts. `git` for install, `--diff` and `--history`.
- Optional: Docker/Podman, bubblewrap, or WSL2 for sandboxed local checks; Android emulator / iOS simulator for `/mobile-audit` validation; an already-installed `osv-scanner` or ecosystem audit tool for `--advisories`.

## Tests

```bash
npm test          # 279 tests: validators, run-state, briefs, detector, inventory, cross-repo, orchestrator (fake CLI), SARIF, probe, hooks, bench, installer
npm run bench     # detector benchmark over bench/corpus; CI fails below 90 % recall
```

Tested on Windows (PowerShell and Git Bash, Node 22). CI runs Linux and Windows on Node 18 and 22. No runtime dependencies. Validators open files with an identity check instead of `O_NOFOLLOW`, so they work on Windows.

## Long audits

The run directory is the memory, not the agent's context. Subagents write their own results, every result is stored before it is applied, every state change is locked and atomic, and `scripts/run-state.cjs status` gives the lead a short summary and the exact next command. If a session crashes, hits a rate limit or loses its context, `/resume-audit` picks up where it stopped. `/auto-audit` hands Phases 2-5 to a headless driver that does the same from disk, with the caveats above.
