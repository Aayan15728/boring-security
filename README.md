# boring-security

Evidence-first security auditing for coding agents (built for Claude Code).
It turns your agent into a patient, skeptical auditor: map the system, plan coverage, hunt with isolated
subagents, try to **disprove** every candidate with a fresh skeptic, and only then write a report.

> **Credit:** the methodology is adapted from Cloudflare's
> [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT). This is an
> independent re-implementation with new commands, a mobile pack, diff review and SARIF export.
> Full attribution in [CREDITS.md](CREDITS.md).

## Commands

| Command | What it does |
|---|---|
| `/full-audit [path]` | **Audits everything** (deep profile): every surface × boundary, every pack whose boundary exists, every identity-spec row, every detector hit traced, critic waves until clean, two independent verifiers per finding, scored report. Shows a cost estimate first. |
| `/deep-audit [path]` | Alias of `/full-audit`. |
| `/quick-audit [path]` | One hunter wave + one critic, one skeptic per candidate. Fast, honest about being partial. |
| `/sec-review [PR \| a..b \| branch \| paths]` | Security code review of a diff/PR/branch/files with a skeptic pass. Verdict: block / fix before merge / ok. |
| `/mobile-audit [path] [--with-backend]` | Android / iOS / RN / Flutter / Capacitor: exported components, intents, deep links, WebView bridges, storage, TLS, embedded keys, BaaS rules. |
| `/db-audit [path]` | Database integrity & concurrency: constraints, races, lost updates, idempotency, transactions, money/time types, migration drift. Races proven on a local DB. |
| `/web-audit [path]` | Web app & API: access control, injection, sessions, OAuth/JWT/SAML, CSRF, CORS, caching, SSRF, DOM XSS. |
| `/ai-audit [path]` | LLM / agent / MCP: injection → real actions, tool authority, confirmation binding, memory poisoning. |
| `/cloud-audit [path]` | IaC / Kubernetes / IAM / serverless from source — no cloud API calls. |
| `/supply-chain-audit [path]` | CI workflows, dependencies, release signing, OTA/auto-update, plugins. |
| `/security-context [path]` | Create/refresh `.boring-security/CONTEXT.md`, the repo's persistent security memory (assets, actors, boundaries, owner-confirmed facts, accepted risks). |
| `/spec-check [jwt|oauth|oidc|saml|webauthn] [path]` | Row-by-row check against the MUST rules of RFC 7519/8725, RFC 6749/7636/9700, OIDC Core, SAML 2.0 and WebAuthn, with spec citations. |
| `/resume-audit <run dir>` | Continue after a crash, rate limit, closed session or context reset — nothing already on disk is redone. |
| `/threat-model [path]` | Recon only: architecture, trust boundaries, seeded coverage ledger, Mermaid diagram. Resume later with `/full-audit --out <same dir>`. |
| `/obvious-scan [path]` | Literal sweep for hardcoded secrets, debug switches, open admin routes, `eval`, permissive CORS — each traced. |
| `/verify-finding <issue>` | Run one suspected bug (scanner hit, bug report) through an independent skeptic. |
| `/audit-report <run dir>` | Re-validate a run and regenerate reports + SARIF. |

All audit commands accept `--out <dir>`, `--budget <max agents>`, and (most) `--profile quick|standard|deep` / `--scope <paths>`.

Plain requests work too: *"security audit this repo"*, *"is this endpoint safe?"*, *"review my PR for security"*.

## Install

### As a Claude Code plugin (recommended)

From inside Claude Code:

```text
/plugin marketplace add C:/Users/<you>/Desktop/boring-security
/plugin install boring-security@boring-security
```

(Or push this folder to a Git repo and use `/plugin marketplace add <owner>/<repo>`.)

Plugin commands can also be called with their namespace, e.g. `/boring-security:sec-review`, if another
command has the same name.

### Skill only (no slash commands)

Copy `skills/boring-security/` into `~/.claude/skills/` (all projects) or `<project>/.claude/skills/` (one project).

### Commands without the plugin

Copy `commands/*.md` into `~/.claude/commands/` together with the skill above.

## What a run produces

Default location `~/boring-security-runs/<repo>/run-<N>/` (always outside your repo):

```
run.json          run facts, profile, scope, budget, status
architecture.md   ≤1000-word system map
ledger.json       coverage ledger — the actual coverage claim
findings.json     confirmed / needs_validation / rejected (schema-validated)
REPORT.md         scorecard (0-100 per area), fix plan (what / where / how / test), findings, coverage
DETAILS.md        full repro for confirmed medium+
LEADS.md          needs_validation handoff for owners
findings.sarif    upload to GitHub code scanning
detector.json     deterministic detector leads
agents/<id>/      per-agent scratch + promoted evidence
```

## Design rules

- **No boundary, no finding.** A candidate needs a lower-trust actor, a crossed boundary, an affected resource, and an observed result.
- **The finder never validates.** Every candidate goes to a fresh skeptic that tries to break it.
- **Three verdicts.** `confirmed` (with severity), `needs_validation` (exact blocker, *no* severity), `rejected` (kept so it isn't rediscovered).
- **Severity = demonstrated likelihood × demonstrated impact.** Overall can't exceed impact.
- **Defense-in-depth gaps are hardening notes**, not vulnerabilities.
- **Safe by default.** Source-only unless a real sandbox (no network, clean env, read-only target, resource limits) is available. Never touches deployed systems, real accounts or paid APIs.
- **Runs add up.** Later runs read earlier ledgers to target gaps and re-verify changed code.

## Layout

```
.claude-plugin/          plugin + local marketplace manifests
commands/                17 slash commands
skills/boring-security/
  SKILL.md               always loaded: modes, shared agent RULES, evidence and severity, pack index
  core-classes.md        injection, access control, files/SSRF, crypto, business logic, feature abuse, chains, wildcard, obvious things
  phases/                1-recon, 2-hunt, 3-skeptic, 4-6-records-and-report
  modes/diff-review.md   PR / diff review flow
  packs/                 12 domain packs (data-integrity, mobile, web-and-identity, browser-client, desktop-and-local-ipc, ai-agents,
                         native-memory, supply-chain, cloud-infra, messaging-rpc, availability, data-lifecycle)
  references/            identity-specs (OAuth/OIDC/JWT/SAML/WebAuthn checklists), project-context (CONTEXT.md template), audit-run (setup, profiles, budget, prior runs, ending), sandbox recipes, evidence promotion
  schema/                findings.schema.json
  scripts/               run-state.cjs (resume, crash-safe state, estimates), sandbox-probe.cjs, detect.cjs + detect-rules.cjs, score.cjs, check-ledger.cjs (+ run.json), check-findings.cjs (schema-driven), to-sarif.cjs, promote.cjs, tests
```

## Requirements

- Claude Code (or another agent with subagents + tool use).
- Node.js ≥ 18 for the zero-dependency validators.
- Optional: Docker/Podman, bubblewrap, or WSL2 for sandboxed local checks; Android emulator / iOS simulator for `/mobile-audit` validation.

## Tests

```bash
npm test
```

Tested on Windows (PowerShell and Git Bash, Node 22) and Linux (Node 18). No runtime dependencies. Validators open files with an identity check instead of `O_NOFOLLOW`, so they work on Windows.

## Long audits

The run directory is the memory, not the agent's context. Every agent result is saved before it is applied, writes are atomic, and `scripts/run-state.cjs` gives the lead a five-line status. If a session crashes, hits a rate limit or loses its context, `/resume-audit` picks up exactly where it stopped. `run-state.cjs estimate <repo>` predicts agents and tokens before you start.

## Expected scanner flags

Skill scanners may flag this repo because its docs describe attacks and its detector rules contain example secrets and vulnerable code (`scripts/detect-rules.cjs`, `scripts/test/`). Those strings are test fixtures. Every "secret" is fake.

## Deterministic detector

```bash
node skills/boring-security/scripts/detect.cjs <repo> [--diff main] [--min-confidence medium] [--json out.json]
node skills/boring-security/scripts/detect.cjs --list-rules
```

90+ rules across secrets, injection, XSS, web/auth, crypto/TLS, mobile, CI, containers/IaC, BaaS rules, data integrity and AI. No network or model calls, and it never runs target code. Each rule ships with must-match and must-not-match examples that the tests enforce. Hits are **leads**: the audit traces each one before anything becomes a finding. Suppressions live in `.boring-security/config.json` and need a reason and an expiry date.

## Use responsibly

Audit code you own or are authorized to test. This skill is defensive: it reviews source and runs only bounded local checks with dummy data. It does not attack live systems.

## License

MIT — see [LICENSE](LICENSE) and [CREDITS.md](CREDITS.md).
