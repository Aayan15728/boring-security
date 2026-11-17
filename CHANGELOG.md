# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased (0.4.0)

### Added

- Generated subagent briefs (`run-state.cjs brief`, `briefs/`): RULES, role template, architecture, schema and per-agent data assembled from files, with target-derived text fenced as untrusted data. Agents write their own `agents/<id>/out/result.json`; the lead never pastes prompts or results.
- Plugin subagents (`agents/`: scout, hunter, hunter-sandbox, skeptic, skeptic-sandbox, critic, record-check) with restricted tools; a PreToolUse hook that confines them (writes only to their scratch/out, no shell outside sandbox roles, fetch/install deny-list, no web or MCP tools); a PostToolUse write-time secret guard (`BORING_SECURITY_GUARD=off`).
- Run-state commands: `add-units` (seeds, critic proposals, uncovered queue), `critic`, `verify`, `reopen`, `inventory-gaps`, `sample-recheck`, `recheck-result`, `complete`, `incomplete`. Every mutating command takes a lock. Only `complete` can mark a run complete, and only when its conditions hold.
- Coverage honesty: `covered` units need anchor quotes of the enforcing control; a deterministic surface inventory (`inventory.cjs`) that every unit set must reference or waive; a deterministic recheck sample of covered units, reported as a miss-rate estimate.
- Static proof: `confirmed` records carry `execution.proof` (`local` with evidence files, or `static` with a fully quoted trace). `needs_validation` may carry `max_impact_if_true` as a triage hint.
- Detector: 116 rules, including new secret rules and file-level and aggregate "missing control" rules for the app stack; `--history [N]` git-history secret scan; `--no-target-config` for untrusted repos.
- App-stack pack, `/ship-check`, `/fix-finding` (`references/fixing.md`), `/verify-deployed` (`references/deployed-checks.md`), opt-in dependency advisories (`--advisories`, `references/advisories.md`).
- Trust mode (`run.json` `trust: own|untrusted`, `advisories: checked|not_checked`); every brief carries an engagement statement generated from it.
- More run-state commands: `set-status` (park units as deferred / out_of_scope / not_applicable), `resume [--reopen]`, `sample-recheck --redraw`, `brief --note-file [--note-untrusted]` and `--prior-file`. Any change after `complete` sets the run back to `in_progress`.
- Incremental re-audit: `carry --from <prior run>` carries units whose code, anchors and skill blocks are unchanged (status `carried`, `hashes.json`); everything else is re-planned with its prior value.
- Cost tiers: `tier`, `next --batch`, `assign --strong`, agent `bsec-hunter-lite` (cheaper model, standard-tier units in the `standard` profile only), a stratified lite recheck (20 %, min 5) and `reopen --lite-tier`. The tier is recorded, not enforced.
- Repeat-run merging (`merge-runs`, `scripts/merge-runs.cjs`): union of findings, `disagreements.json`, `possible-duplicates.json`, rough total-findings estimate.
- Cross-repo interface candidates (`scripts/cross-repo.cjs`, `/cross-audit`, `references/cross-repo.md`).
- Headless orchestrator for Phases 2-5 (`scripts/orchestrate.cjs`, `/auto-audit`, `references/orchestrator.md`); tested only against a fake CLI.
- Benchmark corpora (`bench/`) with a detector benchmark and a run scorer; CI gates detector recall at 90 %.
- One-step installer (`install.cjs`, `INSTALL.md`), `SECURITY.md`.

### Changed

- A plain or ambiguous audit request runs the `standard` profile (estimate shown first; confirmation only for very large runs). `/full-audit` and `/deep-audit` still mean `deep`, and now always show the estimate and wait for a yes.
- Critics run on the strongest model; scouts and record checks may use a cheaper one.
- Detector: target config can no longer disable it wholesale (catch-all paths and rule patterns rejected, expiry at most 365 days ahead, inline ignores need one exact rule id); `--diff` reads suppression config from the base and flags config changes; it reports everything it excluded, suppressed or skipped; secret rules run in test/fixture/generated paths, multi-line calls and UTF-16 files; hardened git invocations.
- Scorecard is coverage-aware: blocked, deferred and planned units are not reviewed; no score below 50 % coverage; overall score capped by coverage.
- Quote checks require substantive quotes (≥ 10 characters, or a whole line with a letter or digit, within ±2 lines).
- Validators: `check-ledger.cjs --target` and `check-findings.cjs --target` verify paths and quotes against the checkout; schema rejects unknown keys named like object built-ins; ledger size limits match the documented 10,000-unit cap.
- Sandbox recipes rewritten (still unverified end-to-end) and a stricter, testable sandbox probe.
- Phase files describe what the lead does and decides; task text lives only in `briefs/`.

## 0.3.0

- Initial version.
