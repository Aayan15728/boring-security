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
| Four parallel reconnaissance agents and a capped architecture summary | `phases/1-recon.md` |
| Deterministic coverage ledger with canonical, percent-encoded IDs and a strict state table | `phases/1-recon.md`, `scripts/check-ledger.cjs` |
| Verbatim hunter prompt assembly, structured JSON hunter results, candidate gate | `phases/2-hunt.md` |
| Coverage-critic waves with a separate final-clean critic | `phases/2-hunt.md` |
| Fresh adversarial verifier per candidate | `phases/3-skeptic.md` |
| Three distinct verdicts (`confirmed`, `needs_validation`, `rejected`) with a strict schema | `schema/findings.schema.json`, enforced directly by the schema engine in `scripts/lib.cjs` |
| Material-replacement re-verification | `phases/4-6-records-and-report.md` |
| Target-neutral reports derived from verified records | `phases/4-6-records-and-report.md` |
| Core attack classes incl. Wildcard and Obvious things | `core-classes.md` |
| Domain companion files (memory safety, AI/LLM, web/auth, client-side, supply chain, cloud, protocols/messaging, availability, data isolation, desktop/mobile/IPC) with discipline, classes, universal moves, validation rules | `packs/` |
| Anti-patterns list | `SKILL.md §5` |

## What is different / new here

All prose, file structure, schema field names and scripts were written from scratch; nothing was
copied verbatim. Additions not present in the original:

- **Slash commands** (`commands/`): `/deep-audit`, `/full-audit`, `/quick-audit`, `/sec-review`,
  `/mobile-audit`, `/web-audit`, `/ai-audit`, `/cloud-audit`, `/supply-chain-audit`, `/threat-model`,
  `/obvious-scan`, `/verify-finding`, `/audit-report`.
- **Diff review mode** for PRs/branches (`modes/diff-review.md`).
- A dedicated, expanded **mobile pack** (Android/iOS/React Native/Flutter/Capacitor/MAUI) split out
  from desktop/IPC.
- **SARIF 2.1.0 export** (`scripts/to-sarif.cjs`) for GitHub code scanning.
- Findings ↔ ledger **cross-check** and on-disk evidence checks in the validators; skill-block
  reference checking against the actual pack files.
- **Less repetition, less context:** one shared RULES block instead of safety text restated per prompt and per pack; SKILL.md loads only what every mode needs, and audit-only material loads on demand.
- **Persistent project context** (`.boring-security/CONTEXT.md`): owner-confirmed facts, house rules and accepted risks carried across sessions, treated as data rather than instructions.
- **Deterministic detector** (`scripts/detect.cjs`): 90+ example-tested rules, no model calls; hits are leads tied to ledger classes.
- **Data-integrity pack** and `/db-audit`: invariant-first review of constraints, races, idempotency and migrations, with races proven on a local database.
- **Deterministic scorecard and fix plan** (`scripts/score.cjs`) in every report.
- **Identity spec checklists** (`references/identity-specs.md`, `/spec-check`): row-by-row MUST rules for JWT, OAuth 2.0, OIDC, SAML and WebAuthn with spec citations.
- **Crash-safe, context-light runs** (`scripts/run-state.cjs`, `/resume-audit`): agent results persisted before use, atomic writes, journal, recovery, and a cost estimator.
- **Fixes for issues open on the original's tracker:** Windows-safe validators (identity-checked open), verbatim `quote` checked against source (made-up citations fail), a fail-closed `sandbox-probe.cjs`, unit class must be a block its hunter receives, archived verifiers can't reappear, clearer verdict errors, target-controlled agent config treated as data.
- Concrete **sandbox recipes** (Docker/Podman, bubblewrap, WSL2, emulator) and a Node promotion helper.
- **Resume from threat model** (`/threat-model` → `/full-audit` on the same run dir).

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
