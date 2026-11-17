# Credits

**boring-security** is a concept-level re-implementation of
[**cloudflare/security-audit-skill**](https://github.com/cloudflare/security-audit-skill)
— © 2025-2026 Cloudflare, Inc., released under the MIT License — the skill that seeded Cloudflare's
vulnerability discovery harness, described in their post
[*Build your own vulnerability harness*](https://blog.cloudflare.com/build-your-own-vulnerability-harness).

Thank you to the Cloudflare team for publishing it openly.

## Concepts adapted from the original

| Concept in Cloudflare's skill | Where it lives here |
|---|---|
| Guidance vs full-audit operating modes | `SKILL.md §1` (Advisor / Diff review / Audit) |
| Agent-neutral roles (parent, research, general agents) | `SKILL.md §1` (Lead, Scout, Hunter, Skeptic) |
| OS-enforced sandbox for any target-controlled execution; source-only fallback | `SKILL.md §2` (one RULES block shared by every subagent), `references/sandbox.md` |
| Output directory outside the target, single-writer shared files, per-agent scratch | `references/audit-run.md` |
| Race-safe, parent-only artifact promotion | `references/evidence-promotion.md`, `scripts/promote.cjs` |
| Run metadata file | `run.json`, validated by `scripts/check-ledger.cjs` |
| quick / standard / deep profiles, scoped runs, agent budgets with reserved critics and validation | `references/audit-run.md` |
| Additive multi-run behaviour using prior ledgers and findings | `references/audit-run.md` |
| Boundary-and-result requirement; deployment facts stay unknown; severity anchors; smallest fix | `SKILL.md §3` |
| Six phases: recon → coverage-led hunting → candidate validation → structured output → independent record verification → reporting | `phases/` |
| Four parallel reconnaissance agents and a capped architecture summary | `phases/1-recon.md`, `briefs/scout-*.md` |
| Deterministic coverage ledger with canonical, percent-encoded IDs and a strict state table | `phases/1-recon.md`, `scripts/check-ledger.cjs` |
| Verbatim hunter prompt assembly, structured JSON hunter results, candidate gate | `briefs/` (assembled by `scripts/run-state.cjs brief`), `phases/2-hunt.md` |
| Coverage-critic waves with a separate final-clean critic | `phases/2-hunt.md` |
| Fresh adversarial verifier per candidate | `phases/3-skeptic.md` |
| Three distinct verdicts (`confirmed`, `needs_validation`, `rejected`) with a strict schema | `schema/findings.schema.json`, enforced directly by the schema engine in `scripts/lib.cjs` |
| Material-replacement re-verification | `phases/4-6-records-and-report.md` |
| Target-neutral reports derived from verified records | `phases/4-6-records-and-report.md` |
| Core attack classes incl. Wildcard and Obvious things | `core-classes.md` |
| Domain companion files (memory safety, AI/LLM, web/auth, client-side, supply chain, cloud, protocols/messaging, availability, data isolation, desktop/mobile/IPC) with discipline, classes, universal moves, validation rules | `packs/` |
| Anti-patterns list | `SKILL.md §5` |

## What is different / new here

Prose, file structure and scripts were written independently. A text comparison against the original
(commit `c1c8a8c`) found no copied passages beyond short shared phrases, which have since been reworded.
Some overlap is deliberate: the verdict names and several finding field names follow the original's
vocabulary, and the fingerprint and agent-id formats (`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`,
`^[a-z0-9][a-z0-9_-]{0,63}$`) match the original's so records stay compatible. Additions not present in
the original:

- **Slash commands** (`commands/`): `/deep-audit`, `/full-audit`, `/quick-audit`, `/sec-review`,
  `/mobile-audit`, `/web-audit`, `/ai-audit`, `/cloud-audit`, `/supply-chain-audit`, `/db-audit`, `/threat-model`,
  `/obvious-scan`, `/verify-finding`, `/audit-report`, `/resume-audit`, `/security-context`, `/spec-check`,
  `/ship-check`, `/fix-finding`, `/verify-deployed`, `/cross-audit`, `/auto-audit`.
- **Diff review mode** for PRs/branches (`modes/diff-review.md`).
- A dedicated, expanded **mobile pack** (Android/iOS/React Native/Flutter/Capacitor/MAUI) split out
  from desktop/IPC.
- **SARIF 2.1.0 export** (`scripts/to-sarif.cjs`) for GitHub code scanning.
- Findings ↔ ledger **cross-check** and on-disk evidence checks in the validators; skill-block
  reference checking against the actual pack files.
- **Less repetition, less context:** one shared RULES block instead of safety text restated per prompt and per pack; SKILL.md loads only what every mode needs, and audit-only material loads on demand.
- **Persistent project context** (`.boring-security/CONTEXT.md`): owner-confirmed facts, house rules and accepted risks carried across sessions, treated as data rather than instructions.
- **Deterministic detector** (`scripts/detect.cjs`): 116 example-tested rules, no model calls; hits are leads tied to ledger classes.
- **Data-integrity pack** and `/db-audit`: invariant-first review of constraints, races, idempotency and migrations, with races proven on a local database.
- **Deterministic scorecard and fix plan** (`scripts/score.cjs`) in every report.
- **Identity spec checklists** (`references/identity-specs.md`, `/spec-check`): row-by-row MUST rules for JWT, OAuth 2.0, OIDC, SAML and WebAuthn with spec citations.
- **Crash-safe, context-light runs** (`scripts/run-state.cjs`, `/resume-audit`): agent results persisted before use, atomic writes, journal, recovery, and a cost estimator.
- **Fixes for issues open on the original's tracker:** Windows-safe validators (identity-checked open), verbatim `quote` checked against source (made-up citations fail), a fail-closed `sandbox-probe.cjs`, unit class must be a block its hunter receives, archived verifiers can't reappear, clearer verdict errors, target-controlled agent config treated as data.
- Concrete **sandbox recipes** (Docker/Podman, bubblewrap, WSL2, emulator) and a Node promotion helper.
- **Resume from threat model** (`/threat-model` → `/full-audit` on the same run dir).
- **Generated briefs and agent-written results** (`run-state.cjs brief`, `briefs/`): subagent prompts are assembled from files with target text fenced as untrusted data, and each agent writes its own result file.
- **Restricted plugin subagents and hooks** (`agents/`, `hooks/`): tool allowlists, write confinement to the agent's scratch/out, a fetch/install deny-list, and a write-time secret guard.
- **Completion gate and recorded passes** (`run-state.cjs complete`, `critic`, `verify`, `recheck-result`): a run is complete only when the critic, verification, inventory and recheck records on disk say so.
- **Coverage honesty:** anchor quotes for every `covered` unit, a deterministic surface inventory (`scripts/inventory.cjs`), and an independent recheck sample reported as a miss-rate estimate.
- **Static proof** alongside sandbox reproduction, with a strict rule for when it is allowed.
- **App-stack pack** and `/ship-check`, `/fix-finding`, `/verify-deployed`, opt-in dependency advisories, and owner-run read-only deployed checks.
- **Trust mode** for third-party code, and a detector the audited repo cannot silence.
- **Regression benchmark** (`bench/`) and a one-step installer (`install.cjs`).
- **Incremental re-audits** (`run-state.cjs carry`, `hashes.json`) and **repeat-run merging** (`merge-runs`).
- **Cost tiers** (`tier`, `bsec-hunter-lite`, stratified lite recheck) and assignment batching.
- **Cross-repo interface candidates** (`scripts/cross-repo.cjs`, `/cross-audit`) and a **headless orchestrator** (`scripts/orchestrate.cjs`, `/auto-audit`).

## Original license notice

```
MIT License

Copyright (c) 2025-2026 Cloudflare, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

boring-security is not affiliated with or endorsed by Cloudflare.
