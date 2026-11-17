# Phase 2: Hunting waves, critics, recheck

`RS` = `node "$SKILL_DIR/scripts/run-state.cjs"`. Agent types and models: `references/audit-run.md` §Agents. `carried` units are already reviewed and are not assigned.

## 2.1 Assign

Give `planned` units to Hunters in priority order. Priority is a number in the seed's `notes.priority` (1 = first), with the reason in `notes.priority_why`:
1. Unauthenticated or lowest-trust surfaces (cross-repo interface units: 1 for high edges, 2 for medium).
2. Boundaries guarding credentials, cross-tenant data, code execution, release/signing, money.
3. Prior gaps, revalidations, changed source.
4. Classes that historically pay off for this kind of target.
5. Ties: lexical `id`.

```bash
RS next "$RUN_DIR" --batch                       # one line of unit ids per assignment group, priority order
RS assign "$RUN_DIR" hunter-7 <the ids of one line, before its "#">   # in_progress; prints "use agent bsec-hunter-lite" for a lite assignment
RS brief "$RUN_DIR" hunter-7 --role hunter [--exclude-file carried.json] [--note-file sandbox.txt]
```

- A batch shares start paths, one subsystem and one tier (at most 8 units, ~400 KB of source; `--max-units`, `--max-bytes`). Don't bundle unrelated boundaries by hand; `RS next "$RUN_DIR" --n 20` lists single units if you need to.
- **Tier.** In the `standard` profile after `RS tier`, a batch of standard-tier units is a `lite` assignment: launch `boring-security:bsec-hunter-lite`. Add `--strong` to `assign` to give it to a strong hunter instead (always in a sandboxed run). Every other assignment is strong: `bsec-hunter`, or `bsec-hunter-sandbox` in a sandboxed run. Code records the tier but cannot check which model you launched.
- `--exclude-file` is a JSON array of carried prior confirmations (`fingerprint`, `title`, `root_cause` only).
- **Sandboxed runs:** put the exact sandbox wrapper command and the promotion allowlist (relative names, byte caps) in a note file and pass `--note-file`.
- A unit the budget can't reach: `RS set-status "$RUN_DIR" <ids…> --to deferred --reason budget_reserve`, never silently dropped.

## 2.2 The Hunter brief

`brief` assembles it from files; never retype or edit it. Shared prefix (identical for every Hunter in the run, so the prompt cache serves it): RULES, the engagement statement for this run's trust mode, `briefs/hunter.md` (task, METHOD, GATE, result contract, ledger state table, anchor and proof rules), `architecture.md`, the `confirmed` and `needs_validation` schema branches. Per-agent part: your note (if any), the text of every block its units select (core class, pack Discipline, classes, Moves, Gate), the units themselves, detector hits under their start paths ("leads to verify, not findings"), exclusions and peer-owned unit ids, and its own scratch/out paths. Everything from the target is fenced as untrusted data.

Launch a wave's Hunters together with their brief paths. Each writes `agents/<id>/out/result.json` and replies with one line.

## 2.3 Consolidation

```bash
RS ingest "$RUN_DIR" hunter-7          # reads agents/hunter-7/out/result.json
```

`ingest` stores the raw result first, then for each assigned unit checks ownership, checks, promoted evidence, anchors and paths against the target, and the ledger state rules. Valid units are applied (with `notes.covered_tier` and the cited files' hashes in `hashes.json`); invalid or missing ones return to `planned` (the output lists why). Valid candidates go to `candidates/` (a known fingerprint adds the finder), `uncovered` entries to `queue/uncovered.jsonl`, hardening notes to the units' `notes.hardening`. Don't read the result file into your own context; the command's output is the summary.

In a sandboxed run, promote the files a Hunter's `local` checks name (`references/evidence-promotion.md`) before you run `ingest`; a check whose evidence file is missing returns its unit to `planned`.

Turn reported boundaries into units for the next wave:

```bash
RS add-units "$RUN_DIR" --from-queue    # unconvertible lines stay in the queue and are listed
```

Fingerprint duplicates collapse automatically. Candidates that share a root cause under different fingerprints are merged at Phase 3: the weaker one's Skeptic gets a note naming the fingerprint it duplicates and rejects it with that reason. One root cause reachable many ways = one candidate with the strongest complete trace. Independent missing controls = separate fingerprints.

## 2.4 Coverage critic (fresh agent after every wave)

```bash
RS brief "$RUN_DIR" critic-3 --role critic      # launch as boring-security:bsec-critic
RS critic "$RUN_DIR" critic-3                   # stores the reply with the current coverage hash
```

The critic brief carries `architecture.md`, a compact ledger view, candidate fingerprints and states, inventory gaps and high-confidence detector hits no unit's paths include. The critic proposes coverage, not findings: missing units, reopen ids, resolved prior leads, `stop`.

Lead, after every critic:
- `RS add-units "$RUN_DIR" --from-critic critic-3` adds every convertible proposal as `planned`. To accept only some, write the accepted ones as seeds and use `RS add-units "$RUN_DIR" seeds.json` instead. Proposals outside a scoped run's scope: add them, then `RS set-status … --to out_of_scope --reason "<scope>"`.
- For each reopen id the `critic` command prints, run `RS reopen "$RUN_DIR" <unit-id> --reason "..."`: it archives the attempt and plans the unit for a fresh owner.
- `resolved_prior_leads` stay in `critics/<seq>.json`; cite them in the report.

Termination:
- `quick`: one wave → one critic. Add its proposals, then park them: `RS set-status "$RUN_DIR" <new ids> --to deferred --reason quick_profile`. Stop.
- `standard`/`deep`: repeat wave → critic until no `planned` units remain and a critic is clean, then run a **separate** final-clean critic with a fresh id. Coverage is clean when `RS status` says the last two critics are clean, distinct, at the current coverage. Any new, reopened or re-statused unit changes the coverage hash, so both clean critics must come after the last change.
- Early stop: `RS set-status "$RUN_DIR" <untouched ids> --to deferred --reason stopped_early`, then `RS incomplete "$RUN_DIR" stopped_early`. An agent cap is never evidence of coverage.

## 2.5 Recheck sample

Required in `deep` and in any run where lite hunters covered units; in `standard` otherwise, when the budget allows. Draw it once hunting has finished (no `planned` or `in_progress` units):

```bash
RS sample-recheck "$RUN_DIR"                                         # deterministic: 10 % (min 3) of covered + carried units, plus 20 % (min 5) of lite-covered ones
RS brief "$RUN_DIR" recheck-1 --role recheck --units <id> <id> ...   # launch as boring-security:bsec-hunter
RS recheck-result "$RUN_DIR" recheck-1
```

A recheck agent never owned or checked the units it gets and isn't shown the original conclusion; it re-derives each invariant and agrees only if it can quote the enforcing control. Every sampled unit needs an answer.
- For each disagreement, `recheck-result` prints the `reopen` command: run it, hunt the unit again with a fresh Hunter, and run the critics again (the coverage hash changed).
- If the lite stratum fails (two or more disagreements and over 10 % of it), `RS reopen "$RUN_DIR" --lite-tier --reason "..."` sends every lite-covered unit back to strong hunters.
- If units were added or reopened after the sample was drawn, `RS status` asks for `RS sample-recheck "$RUN_DIR" --redraw`; answers already recorded at the same wave are kept.

The report states the sample size and the disagreements (per stratum) as a miss-rate estimate (disagreements ÷ sampled), never as zero misses.
