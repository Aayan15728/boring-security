# Headless orchestrator (Phases 2-5 without a lead session)

`scripts/orchestrate.cjs` drives a seeded run to `complete` without a long-lived lead. It is a plain loop with no model in it: it reads the run directory, picks the next tasks, prepares each with `run-state.cjs` (`assign`, `brief`), runs one fresh headless `claude -p` process per task, and applies the agent's `out/result.json` with the matching command (`ingest`, `decide`, `verify`, `critic`, `recheck-result`). The run directory stays the only source of truth.

**Tested only against a fake `claude` executable** (`scripts/test/orchestrate.test.cjs`). Flags and output shapes come from `claude --help` (v2.1.301) and the Claude Code docs, not from a real audit. Run a small scoped audit first and read `usage.jsonl` and a few `agents/<id>/session.log` files before trusting it with a large one.

## What it automates, and what it does not

| Automated | Not automated (lead or human) |
|---|---|
| Hunting waves: `next --batch` → `assign` → `brief --role hunter` → agent → `ingest`; `recover` for lost agents | Phase 1: scouts, `architecture.md`, detector, inventory, seeding the ledger, `tier` (run `/threat-model` or Phase 1 first) |
| Skeptic per undecided fingerprint → `decide` | Duplicate-root-cause hints to Skeptics, `--prior-file` for carried `confirmed_same`/`nv` units (it warns when such units are planned) |
| Record check per unverified confirmed/needs_validation record → `verify` (a `replace` reply → `decide`, then a new check) | Inventory gaps and waivers, out-of-scope decisions, merge disagreements: anything `complete` lists that needs judgement (exit 3) |
| Critics after each wave until two clean, distinct critics at the current coverage; `add-units --from-critic`, `reopen` its ids; quick: proposals added as `deferred` (`quick_profile`) | Sandboxed runs (`execution: "sandboxed-local-only"`): the wrapper and evidence promotion need the lead; the driver refuses them |
| Recheck: `sample-recheck` (and `--redraw`), `brief --role recheck`, `recheck-result`, `reopen` on disagreement, `reopen --lite-tier` on a lite breach | Phase 6 prose: `REPORT.md`, `DETAILS.md`, `LEADS.md` |
| `assemble`, `complete`, then `score.cjs` → `orchestrator/score.txt` and `to-sarif.cjs` → `findings.sarif` | |

No agent ever gets the ledger or another agent's output in its prompt; briefs carry what each role may see, and the driver never forwards agent prose.

## Prerequisites

- A run directory with `run.json`, a seeded `ledger.json` (and for standard/deep `inventory.json`, gaps closed), e.g. after `/threat-model`. A `recon_only` status is fine; `complete` sets the final value.
- `claude` on `PATH` (or `--claude <path>`, or `BSEC_CLAUDE`), logged in or with an API key.
- The plugin installed, for hook enforcement. Verified from the docs, not observed: `claude -p` without `--bare` loads installed plugins and their hooks; with `--agent`, hook input carries `agent_type`, which `hooks/bsec-pretool.cjs` matches in plain or `boring-security:` form, so the same write/shell/network confinement applies to headless sessions. A copy install has no hooks: use `--agent-mode plain` and treat enforcement as advisory. `--agent-mode none` uses tool flags only (for hosts without the agent types).

## Usage

```bash
node "$SKILL_DIR/scripts/orchestrate.cjs" "$RUN_DIR" [--max-parallel 4] [--max-agents N] [--until hunt|critics|recheck|validate|complete]
     [--dry-run] [--once] [--claude <path>] [--model-strong <m>] [--model-lite <m>] [--retry-wait auto|<seconds>]
     [--task-timeout 3600] [--max-turns N] [--agent-mode plugin|plain|none] [--exclude-file carried.json]
```

- `--dry-run` prints the next round's tasks, the `run-state.cjs` preparation and the exact argv; it writes nothing.
- `--once` runs one round of agents and exits. `--until` stops after that stage is done.
- `--max-agents` caps agents launched by this invocation; `run.json.budget_agents` caps every agent directory in the run (scouts included). Before each wave it reserves critics, the recheck and validation (`audit-run.md` §Budget) and spends only the rest on hunters. When nothing is left for hunters it sets the remaining planned units `deferred` (`budget_reserve`), validates existing candidates while budget lasts, and ends `incomplete` (`stopped_early`, `validation_budget_exhausted` or `critic_budget_exhausted`).
- Models: no `--model` is passed unless given; the agent files decide (hunters, skeptics, critics, recheck inherit the session default; `bsec-hunter-lite` and `bsec-record-check` use sonnet). `--model-strong` applies to strong roles, `--model-lite` to lite hunters and record checks.

### How each task is spawned

One process per task, arguments as an array (no shell; a `.cmd` shim is resolved to its script, else quoted for `cmd.exe`):

```
claude -p "Read <RUN_DIR>/agents/<id>/brief.md completely and follow it." --output-format json
       --agent boring-security:bsec-<role>        (hunter | hunter-lite | skeptic | record-check | critic; recheck uses bsec-hunter)
       --allowedTools Read,Grep,Glob,Write --disallowedTools Bash,PowerShell,WebFetch,WebSearch,NotebookEdit,Monitor
       --permission-mode dontAsk --strict-mcp-config --disable-slash-commands --no-session-persistence
       [--model <m>] [--max-turns N] --add-dir <dir>
```

- `trust: "own"`: working directory = target, `--add-dir` = the agent's directory.
- `trust: "untrusted"`: working directory = the agent's directory (never the target, so its `.claude/`, `CLAUDE.md` and MCP configs never load), `--add-dir` = target. `--disable-slash-commands` keeps skills from the target's `.claude/skills/` out.
- Environment: only what the CLI needs — system variables (`PATH`, `HOME`/`USERPROFILE`, `APPDATA`, `TEMP`, locale, `SystemRoot`, …), Anthropic auth and endpoint variables (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, `CLAUDE_CODE_OAUTH_TOKEN`, `CLAUDE_CONFIG_DIR`), proxy and CA variables, and Bedrock/Vertex/Foundry credentials only when that provider is selected. Anything else must be named in `BSEC_ORCH_PASS_ENV` (comma list).
- Per-task timeout (`--task-timeout`, default 3600 s) kills the process tree. stdout → `agents/<id>/session.json`, stderr → `agents/<id>/session.log`.
- Never two tasks for the same unit or fingerprint in a round; run-state locks still guard every write. Ids are fresh and never reused: `h-<round>-<n>`, `s-…`, `v-…`, `c-…`, `r-…`.

## Failures

- **No valid result or the command rejects it:** recorded in `orchestrator/attempts.jsonl`; `recover` returns a lost hunter's units to `planned`; the work is retried with a fresh id. After 3 failed attempts a hunt unit is set `deferred` with `orchestrator_retries_exhausted`; a Skeptic, record check, critic or recheck stops the driver (exit 3).
- **Usage limit** (`You've hit your … limit · resets …`, `spend limit reached`, `Claude AI usage limit reached|<epoch>`, in the JSON `result` or stderr of a failed session): stops launching, lets running agents finish, runs `recover`, and records nothing as covered that was not. Without `--retry-wait` it exits 4 and prints the reset time; with `--retry-wait auto` it sleeps until the reset plus a minute (15 min if no time was given, at most 6 h) and continues; with a number it sleeps that many seconds. Reset times are read as this machine's local time; a named zone is ignored.
- **Transient API errors** (overloaded, 5xx, throttling 429, network) after the CLI's own retries: not counted as failures; exponential backoff from 30 s, at most 5 rounds in a row, then exit 1.
- **Crash, reboot, Ctrl-C:** rerun the same command. Start-up runs `recover`, applies any written but unapplied output, and continues from disk. The driver keeps only `orchestrator/state.json` (pid, round, counters), `attempts.jsonl` and `driver.lock`.
- **Concurrency:** a second driver on the same run exits 5. A lock whose pid is gone (same host) is taken over.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Run complete (score and SARIF written), or `--until` / `--once` reached |
| 1 | Internal error, or API errors in 5 consecutive rounds |
| 2 | Bad arguments, no `run.json`, missing target, sandboxed run |
| 3 | Needs a human: unmet `complete` conditions (printed), exhausted validation retries, critic proposals that convert to nothing twice, empty ledger |
| 4 | Usage limit; reset time printed; rerun after it |
| 5 | Another orchestrator holds the run |
| 6 | Ended `incomplete` (budget) |
| 130 | Interrupted |

## Where the numbers land

One line per event on stdout (`[12:03:04] hunt h-2-3 units=6 tier=high → ingested: 5 covered, 1 candidate`) and a final summary: agents by role, agent type and model, failed attempts, wall time, token and cost totals. Each session's `--output-format json` result (`total_cost_usd`, `usage`, `modelUsage`, `num_turns`) is appended per agent to `RUN_DIR/usage.jsonl`. Costs are the CLI's client-side estimates. These are the first measured numbers for `run-state.cjs estimate` to be checked against.
