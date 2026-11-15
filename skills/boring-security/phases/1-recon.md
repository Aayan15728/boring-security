# Phase 1: Recon and coverage plan

Goal: know what the system is, who may do what, where untrusted input enters, and turn that into a deterministic list of work units (the ledger).

## 1.0 Before the Scouts

- Read `.boring-security/CONTEXT.md` if present and give its relevant sections to each Scout as owner-stated context, labelled as data.
- Run the detector into `RUN_DIR/detector.json`. Scouts get only the per-area counts and the high-confidence hits; all hits stay in the file for Hunters.

## 1.1 Four Scouts in parallel

Each brief = the RULES block (`SKILL.md §2`) + one task below. Scouts return facts with `path:line` and write nothing.

**A. What is it**
```text
1. Product purpose, users, operators, and the everyday actions that are trust-sensitive.
2. Languages, frameworks, build systems, runtimes, deployment models visible in the repo.
3. Entry points and subsystem boundaries.
4. Offline build/test commands that would work with what is installed, where they write, and what
   target-controlled input they process. Do not run them.
5. A comparable product/protocol only if the repo's docs or deps ground it; else "none".
6. Missing toolchains or runtime facts that would block local checks.
```

**B. Who is trusted with what**
```text
Read all code that establishes identity, authorization, isolation or privilege. Map:
1. Each lower-trust principal and what it may do by design.
2. How each entry surface authenticates its caller or peer.
3. Per-resource authorization and tenant/owner scoping.
4. Process, browser, workload, CI, plugin, model/tool, device and IPC authority.
5. Privilege changes, confirmations, revocation, recovery and fallback paths.
6. Which controls are visible in source and which depend on deployment facts.
```

**C. Where untrusted data goes**
```text
Inventory every entry of external or lower-trust input: HTTP/browser, RPC/queues/protocols,
files/archives/documents, CLI/env/config, plugins/deps/CI, cloud events/IAM selectors, model
context/tool arguments, mobile intents/deep links/webviews, local IPC. For each, follow major
transformations, stored and derived copies, and security-relevant sinks. Note limits enforced in
source and parallel paths to the same effect.
```

**D. What can safely run, and what can't be seen**
```text
1. Small offline tests/fixtures that could exercise trust boundaries with dummy data.
2. Processes that could run on sandbox loopback with no external dependency.
3. Commands that fetch deps, publish, call paid/provider APIs or touch shared state: mark PROHIBITED.
4. Deployed controls the repo can't establish (proxy, WAF, IAM, MDM, store signing, OS policy).
5. For each deployment mode the repo selects deterministically, the final active code path.
6. Whether this host can enforce every sandbox control in RULES (see references/sandbox.md).
7. Whether this OS supports lead-side evidence promotion (references/evidence-promotion.md).
```

Add focused Scouts for deployment modes or subsystems these four didn't map. If the budget refuses one, seed that area as a `deferred` unit (`budget_reserve`) and disclose it.

Fold in prior runs per `references/audit-run.md`: paths go in `run.json`, only coverage consequences go in `architecture.md`.

## 1.2 `architecture.md` (≈1000 words max)

1. Product, principals, normal authority, protected assets.
2. Comparable baseline, if grounded: the trade-offs it accepts. Use it to calibrate effort and severity, never to dismiss a demonstrated finding; a comparable that shipped the same bug class *strengthens* a finding.
3. Stack, visible deployment paths, offline build/test limits, execution mode.
4. Entry surfaces and the important source→sink and lifecycle paths.
5. Trust boundaries with the strongest visible control on each.
6. Starting paths.
7. Prior-run gaps, revalidation targets, carried exclusions.
8. Selected packs, one line each with the boundary that justified it.

Per-unit block selections live in the ledger, not here.

## 1.3 `ledger.json`

A JSON array of units, one per material combination of the dimensions the profile sets (`references/audit-run.md`).

### Refs and ids

Each dimension has a stable, source-derived ref that survives label renames:

| Dimension | Example ref |
|---|---|
| surface | `src/routes/users.ts#PUT /users/:id` |
| boundary | `src/auth/guards.ts#requireOwner` |
| subsystem | `packages/api` (quick: `profile/quick/all`) |
| class | `core-classes.md#Access control`, `packs/mobile.md#Intent redirection and PendingIntent hijack` |
| lifecycle (deep) | `lifecycle#restore` |

A class ref is `FILE#` plus the class name exactly as written in that file's bold text or heading, without any parenthetical. Don't lowercase or slugify. Refs are NFC, trimmed, with no control or invisible characters.

`id` = each ref UTF-8 percent-encoded (keep only `A-Z a-z 0-9 - . _ ~`, uppercase `%HH`), joined with `::` in the order surface, boundary, subsystem, class[, lifecycle]. No wave, agent, verdict, severity or line numbers in refs. Sort units by `id`. A duplicate id, or one semantic unit (same labels) under two different ref sets, is an error. Never merge them silently.

### Unit

```json
{
  "id": "src%2Froutes%2Fusers.ts%23PUT%20%2Fusers%2F%3Aid::src%2Fauth%2Fguards.ts%23requireOwner::packages%2Fapi::core-classes.md%23Access%20control",
  "refs":   {"surface": "src/routes/users.ts#PUT /users/:id", "boundary": "src/auth/guards.ts#requireOwner", "subsystem": "packages/api", "class": "core-classes.md#Access control"},
  "labels": {"surface": "Update user", "boundary": "Owner check", "subsystem": "API", "class": "Access control"},
  "start_paths": ["src/routes/users.ts"],
  "class_block": "core-classes.md#Access control",
  "pack_blocks": ["packs/web-and-identity.md#Discipline", "packs/web-and-identity.md#JWT verification and claim binding", "packs/web-and-identity.md#Moves", "packs/web-and-identity.md#Gate"],
  "skipped_blocks": [{"block": "packs/web-and-identity.md#SAML assertion binding", "why": "no SAML code in repo"}],
  "prior": "none", "wave": 1, "status": "planned", "owner": null,
  "paths": [], "checks": [], "fingerprints": [], "open": [], "history": [], "notes": {}
}
```

- `class_block` is `null` only if no core class applies. Selecting any pack class also selects that pack's Discipline, Moves and Gate.
- `skipped_blocks` lists every considered block with the source fact that rules it out.
- `notes` is free-form lead bookkeeping (`priority`, `hardening`); validators ignore it.

### States

| status | owner | paths / checks | fingerprints | open |
|---|---|---|---|---|
| planned | null | empty | empty | empty |
| not_applicable, out_of_scope, deferred | null | empty | empty | ≥1 reason |
| in_progress | agent id | empty | empty | empty |
| blocked | agent id | both non-empty | empty | ≥1 blocker |
| covered | agent id | both non-empty | empty | empty |
| candidate | agent id | both non-empty | ≥1 | optional |

A check is `{"by", "paths", "invariant", "method": "source"|"local", "result", "evidence"}`. `source` → `evidence: null`. `local` → a promoted file under `agents/<by>/evidence/`. Unit `paths` = union of its checks' `paths`. Hunter and Skeptic checks coexist; `owner` stays the assignment owner.

`history` is append-only. When a critic reopens a `blocked`/`covered`/`candidate` unit, copy `{wave, status, owner, paths, checks, fingerprints, open}` plus `reopen_reason` into it, bump `wave`, and restart with a **fresh** owner and empty live evidence. Archived waves strictly increase and stay below the live wave. Archived owners and their evidence never reappear in live checks.

Run `check-ledger.cjs` after seeding and fix every error before assigning work. The ledger, not prose or agent count, is the coverage claim.
