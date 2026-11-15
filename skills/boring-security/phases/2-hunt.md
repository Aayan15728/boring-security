# Phase 2: Hunting waves and critics

## 2.1 Assign

Give `planned` units to Hunters. One Hunter may take closely related units in one subsystem; don't bundle unrelated boundaries. A unit the budget can't reach becomes `deferred`, never silently dropped.

Priority is stored as a number in `notes.priority` (1 = first), with the reason in `notes.priority_why`:
1. Unauthenticated or lowest-trust surfaces.
2. Boundaries guarding credentials, cross-tenant data, code execution, release/signing, money.
3. Prior gaps, revalidations, changed source.
4. Classes that historically pay off for this kind of target.
5. Ties: lexical `id`.

Take units from `run-state.cjs next`, then `run-state.cjs assign <run> <fresh-agent-id> <unit ids…>`. It marks them `in_progress`, creates the agent's directories, and refuses reused agent ids.

## 2.2 Hunter brief, in this order

Items 1-5 are the **shared prefix**: byte-identical for every Hunter in the run, so the prompt cache serves them and each Hunter pays full price only for its own part. Never interleave per-hunter text into it.

1. RULES block (`SKILL.md §2`).
2. "You find source-grounded security invariant failures in the units given at the end of this brief."
3. `architecture.md`.
4. **Method** and **Gate** below.
5. The **Result contract** below, and the `confirmed` and `needs_validation` branches of `schema/findings.schema.json`.
6. The **text** of each selected block: the core class, plus each pack's Discipline, chosen classes, Moves and Gate. Order blocks by pack, so Hunters on the same pack share a longer prefix.
7. Assigned units: ids, labels, start paths, `class_block`, `pack_blocks`, `skipped_blocks` with reasons.
8. Detector hits from `detector.json` under the units' start paths, labelled "leads to verify, not findings".
9. Exclusions: carried prior confirmations (`fingerprint`, `title`, `root_cause` only) and peer-owned unit ids.
10. Agent id, scratch path, promotion allowlist with byte caps.

### Method

```text
METHOD
Read deep. Follow each input through parsing → identity → authorization → normalization → state →
derived copies → final sink. Read the siblings that reach the same effect: legacy, batch, bulk,
retry, cancel, migration, error and fallback paths. Compare sibling controls for equivalence, not
presence. Compare what component A guarantees with what component B assumes.

One invariant at a time:
  1. Lower-trust principal and its starting capability.
  2. The value / action / transition / resource selector it controls.
  3. The control that should reject, bind, scope, limit or revoke it.
  4. The exact path after that decision.
  5. The smallest affected dummy record, wrong return, integrity or local shared-resource effect.
  6. The source change and regression test that would enforce the invariant.

Follow only paths that reach your boundary or that it relies on. Stop when the invariant is settled
either way; record covered / candidate / blocked, or report a new boundary under "uncovered".

Try the sad paths the interface accepts: missing, empty, zero, negative, max, over-max, duplicate,
mixed encoding/case/unicode, stale, revoked, reordered, concurrent, half-migrated, dependency-failed,
rolled-back. Check canonicalization and units at every parser/policy hand-off. In a chain, each step
is a prerequisite you must establish; an unproven step is a blocker.

When a high/critical candidate shows a reusable root cause, search your units for lexical,
structural and logical variants. One root cause = one candidate; prove each variant's conditions.
Variants outside your units go to "uncovered".

Use the narrowest local check that settles it: an existing unit test, a tiny harness, a dummy-tenant
call, a small malformed fixture, a deterministic race schedule, a locally rendered policy.
Before relying on a framework or library default, confirm the version actually pinned in the repo.
```

### Gate

```text
GATE
1. A candidate needs a complete repo-relative trace and evidence for the root cause, including the
   strongest visible control on the path. Every trace/evidence entry carries a verbatim `quote` of
   the cited line; validation rejects quotes that aren't in the source.
2. A proposed "confirmed" also needs a bounded observed result, real impact across a named boundary,
   complete conditions, and no visible layer that prevents it.
3. An unverified critical claim is needs_validation, never a downgraded "confirmed low".
4. A missing best practice with no affected principal/resource is a hardening note. Something source
   disproves is dropped, not needs_validation.
5. One fingerprint per root cause, identical in every state: ^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$, no
   line numbers, wave, agent, severity or verdict. Form: <class>:<path-of-root-cause>:<symbol>,
   e.g. idor:src/api/orders.ts:getOrder
6. Nothing survives → empty candidates array. That is a good result.
```

### Result contract

```json
{
  "units": [{"id": "...", "disposition": "covered|candidate|blocked", "paths": ["..."],
             "checks": [{"by": "<agent-id>", "paths": ["..."], "invariant": "...", "method": "source|local", "result": "...", "evidence": null}],
             "fingerprints": [], "open": []}],
  "candidates": [{"proposed": "confirmed|needs_validation", "...": "that schema branch's fields except verdict"}],
  "hardening": ["concrete non-finding note with path"],
  "uncovered": [{"surface": "...", "boundary": "...", "subsystem": "...", "class": "...", "start_paths": ["..."], "why": "..."}]
}
```

Every assigned id appears exactly once, and dispositions follow the ledger state table. A confirmed candidate's `execution` describes only the check actually done; `observed_result` is real output.

## 2.3 Lead consolidation

Save the Hunter's reply to a file and run `run-state.cjs ingest <run> <agent-id> <file>`. Don't read the reply into your own context beyond its summary line. The script:
- stores the raw result;
- checks each unit (assigned to this agent, valid checks, promoted evidence, ledger state rules);
- applies valid units, and returns invalid or missing ones to `planned`;
- writes candidates to `candidates/`, `uncovered` entries to `queue/uncovered.jsonl` and hardening notes to `notes.hardening`.

Fingerprint duplicates collapse automatically. You still merge candidates that share a root cause under different fingerprints. One root cause reachable many ways = one candidate with the strongest complete trace. Independent missing controls = separate fingerprints. `queue/uncovered.jsonl` entries become new units for the next wave.

## 2.4 Coverage critic (fresh Scout after every wave)

Brief: RULES + `architecture.md` + full ledger + candidate fingerprints and states + prior-gap summary. Task: find unmapped entry points, unchecked parallel paths, missing lifecycle modes, selected pack classes with no unit, unjustified skips, units closed without real paths/checks, high-confidence detector hits no unit's paths include, and prior leads nobody owns. It proposes **coverage**, not findings:

```json
{"missing_units": [{"surface": "...", "boundary": "...", "subsystem": "...", "class": "...", "start_paths": ["..."],
                    "pack_blocks": ["..."], "skipped_blocks": [{"block": "...", "why": "..."}], "why": "source-backed gap"}],
 "reopen_ids": ["..."], "resolved_prior_leads": ["fingerprint"], "stop": false}
```

Lead: reject out-of-scope or unsafe proposals (scoped runs record them `out_of_scope`). Derive ids, dedupe, and fail on collisions. For each valid `reopen_id`, archive into `history` per Phase 1. For each `resolved_prior_leads` entry, record the critic's reason on its unit.

Termination:
- `quick`: one wave → one critic → additions and reopens become `deferred` (`quick_profile`). Stop.
- `standard`/`deep`: repeat wave → critic until it finds nothing and no `planned` units remain, then run a **separate** final-clean critic. Coverage is clean only if that one also finds nothing; otherwise queue its work and loop.
- Early stop: untouched units become `deferred` with the reason. An agent cap is never evidence of coverage.
