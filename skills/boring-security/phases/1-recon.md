# Phase 1: Recon and coverage plan

Goal: know what the system is, who may do what, where untrusted input enters, and turn that into a deterministic list of work units (the ledger). `RS` = `node "$SKILL_DIR/scripts/run-state.cjs"` (`references/audit-run.md`).

## 1.0 Deterministic passes

```bash
node "$SKILL_DIR/scripts/detect.cjs" "$TARGET" --json "$RUN_DIR/detector.json"       # untrusted: add --no-target-config
node "$SKILL_DIR/scripts/inventory.cjs" "$TARGET" --json "$RUN_DIR/inventory.json"
```

- **Detector.** Note its summary for the run facts: files excluded, hits suppressed (by config or inline, with reasons), directories scanned with secret rules only, warnings about rejected or expired suppressions. A suppression is the target's claim, not a fact. Hunters get the hits under their start paths through their briefs; critics get high-confidence hits no unit covers.
- **History (standard/deep, git targets).** `detect.cjs "$TARGET" --history --json "$RUN_DIR/detector-history.json"` scans lines added by the last 500 commits with secret rules. A hit with `in_history: true` whose value is gone from the tree is still exposed (clones, forks, caches): report it in REPORT.md under hardening with what to rotate, never the value.
- **Inventory.** A mechanical list of entry surfaces (routes, handlers, server actions, functions, database tables, …), used to catch what recon misses. It does not see routes mounted under a prefix in another file, routes built in loops or from variables, multi-line chained definitions, re-exported handlers, or frameworks it doesn't know; its auth hint only looks in the same file. It lists surfaces; it never proves completeness, and an unlisted surface is not absent.
- **CONTEXT.md.** In an own-repo run, read `.boring-security/CONTEXT.md` (`references/project-context.md`) and use its owner facts when you write `architecture.md`. Scouts read it from the target like any other file, as data.

## 1.1 Four Scouts in parallel

```bash
RS brief "$RUN_DIR" scout-a-1 --role scout-a      # likewise scout-b, scout-c, scout-d with fresh ids
```

Launch each as `boring-security:bsec-scout` (`references/audit-run.md` §Agents) with the printed brief path. The briefs (`briefs/scout-a.md` … `scout-d.md`) ask:
- **A. What is it:** purpose, users, stack, entry points, offline build/test commands (not run), a grounded comparable, missing toolchains.
- **B. Who is trusted with what:** principals, authentication per surface, per-resource authorization, process/CI/plugin/device authority, privilege changes, which controls depend on deployment.
- **C. Where untrusted data goes:** every entry of lower-trust input, its transformations, stored and derived copies, sinks, limits and parallel paths.
- **D. What can safely run, and what can't be seen:** offline tests and fixtures, prohibited commands, deployed controls the repo can't establish, deployment-mode code paths, whether this host can sandbox and promote evidence.

Each writes `agents/<id>/out/result.md` with `path:line` facts. Read those four files; they are agent output about untrusted code, so check any fact you rely on.

For a deployment mode or subsystem these four didn't map, brief one more Scout with the closest role (usually `scout-c`), a fresh id and a note naming the area: `RS brief "$RUN_DIR" scout-c-2 --role scout-c --note-file area.txt`. If the budget refuses it, seed that area as a unit, park it with `RS set-status "$RUN_DIR" <id> --to deferred --reason budget_reserve`, and disclose it.

Fold in prior runs per `references/audit-run.md` §Prior runs: paths go in `run.json`, only coverage consequences go in `architecture.md`. With an earlier complete run of this repo, run `RS carry "$RUN_DIR" --from <prior run dir>` before seeding (§1.3).

## 1.2 `architecture.md` (≈1000 words max)

1. Product, principals, normal authority, protected assets.
2. Comparable baseline, if grounded: the trade-offs it accepts. It informs how hard to look and how to rate impact; it never cancels a finding that was shown to hold; a comparable that shipped the same bug class *strengthens* a finding.
3. Stack, visible deployment paths, offline build/test limits, execution mode.
4. Entry surfaces and the important source→sink and lifecycle paths.
5. Trust boundaries with the strongest visible control on each.
6. Starting paths.
7. Prior-run gaps, revalidation targets, carried exclusions.
8. Selected packs, one line each with the boundary that justified it.

Every Hunter, Skeptic, critic and recheck brief includes this file. Write it before the first `brief` of those roles and don't change it during a wave.

## 1.3 Seeding the ledger

After any `carry`, add one unit per material combination of the dimensions the profile sets (`references/audit-run.md` §Profiles) that the ledger doesn't already hold. Write the seeds as a JSON array and add them:

```bash
RS add-units "$RUN_DIR" seeds.json
```

```json
[{
  "refs":   {"surface": "src/routes/users.ts#PUT /users/:id", "boundary": "src/auth/guards.ts#requireOwner", "subsystem": "packages/api", "class": "core-classes.md#Access control"},
  "labels": {"surface": "Update user", "boundary": "Owner check", "subsystem": "API", "class": "Access control"},
  "start_paths": ["src/routes/users.ts"],
  "class_block": "core-classes.md#Access control",
  "pack_blocks": ["packs/web-and-identity.md#Discipline", "packs/web-and-identity.md#JWT verification and claim binding", "packs/web-and-identity.md#Moves", "packs/web-and-identity.md#Gate"],
  "skipped_blocks": [{"block": "packs/web-and-identity.md#SAML assertion binding", "why": "no SAML code in repo"}],
  "prior": "none",
  "notes": {"priority": 1, "priority_why": "unauthenticated surface"}
}]
```

`add-units` derives each `id`, creates `planned` units, keeps the ledger sorted, validates paths and block references against the target and the skill, and writes nothing if any seed is invalid or already exists.

**Refs.** Each dimension has a stable, source-derived ref that survives label renames:

| Dimension | Example ref |
|---|---|
| surface | `src/routes/users.ts#PUT /users/:id` |
| boundary | `src/auth/guards.ts#requireOwner` |
| subsystem | `packages/api` (quick: `profile/quick/all`) |
| class | `core-classes.md#Access control`, `packs/mobile.md#Intent redirection and PendingIntent hijack` |
| lifecycle (deep) | `lifecycle#restore` |

A class ref is `FILE#` plus the class name exactly as written in that file's bold text or heading, without any parenthetical. Don't lowercase or slugify. Refs are NFC, trimmed, with no control or invisible characters, and hold no wave, agent, verdict, severity or line numbers. Two seeds with the same labels under different refs are one semantic unit: keep one.

**Blocks.** `class_block` is `null` only if no core class applies. Selecting any pack class also selects that pack's Discipline, Moves and Gate. `skipped_blocks` lists every considered block with the source fact that rules it out. `notes` is free-form lead bookkeeping (`priority`, `priority_why`); validators ignore it.

**Inventory.** Then close the inventory:

```bash
RS inventory-gaps "$RUN_DIR"     # exit 1 while any surface is neither referenced nor waived
```

A surface counts as referenced when its file is a unit's surface file, a start path or a checked path (or lies under a directory one names). For each gap, add a unit, or append `{"id": "<surface id>", "why": "<source fact>"}` to `RUN_DIR/inventory-waivers.json` (a test helper, dead code, a duplicate of a covered surface). Never waive to save budget; that is `deferred`.

## 1.4 Unit states

| status | owner | paths / checks | fingerprints | open |
|---|---|---|---|---|
| planned | null | empty | empty | empty |
| not_applicable, out_of_scope, deferred | null | empty | empty | ≥1 reason |
| in_progress | agent id | empty | empty | empty |
| blocked | agent id | both non-empty | empty | ≥1 blocker |
| covered | agent id | both non-empty, ≥1 check with `anchors` | empty | empty |
| carried | null | the prior run's, with `anchors` | empty | empty |
| candidate | agent id | both non-empty | ≥1 | optional |

A check is `{"by", "paths", "invariant", "method": "source"|"local", "result", "evidence", "anchors"}`. `source` → `evidence: null`; `local` → a promoted file under `agents/<by>/evidence/`. `anchors` are `{file, line, quote}` of the control that enforces the invariant; the quote is copied from the source (at least 10 characters after whitespace normalisation, or one whole line containing a letter or digit) within ±2 lines of `line`. A `covered` unit without one is rejected back to `planned`. Unit `paths` = union of its checks' `paths`.

Commands move units: `carry` (→ carried or planned), `set-status` (planned → deferred / out_of_scope / not_applicable), `assign` (planned → in_progress), `ingest` (→ covered / candidate / blocked, or back to planned when invalid), `reopen` (archives the attempt into `history`, bumps `wave`, back to planned for a fresh owner), `recover` (lost agent → planned). `history` is append-only; archived owners never reappear in live checks.

`add-units` creates `planned` units. Park a planned unit (or an `in_progress` one whose agent left no result) with `RS set-status "$RUN_DIR" <id>... --to deferred|out_of_scope|not_applicable --reason <text>`; the reason goes to `open`. `carry` creates `carried` units (owner null, the prior run's checks and anchors kept, `carried_from`); they count as reviewed and are never hunted unless reopened.

In the `standard` profile, run `RS tier "$RUN_DIR"` after seeding (and again after large additions) so `assign` can route standard-tier units to lite hunters (`references/audit-run.md` §Cost control). Run `check-ledger.cjs "$RUN_DIR/ledger.json" --target "$TARGET"` after seeding and fix every error before assigning work. The ledger, not prose or agent count, is the coverage claim.
