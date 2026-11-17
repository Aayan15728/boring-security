#!/usr/bin/env node
'use strict';
// Headless orchestrator for Phases 2-5 of an audit run. A plain deterministic loop, no model in the driver:
// it reads the run directory, picks the next tasks, prepares each one with run-state.cjs (assign / brief),
// runs one fresh headless `claude -p` process per task, and applies the agent's out/result.json with the
// matching run-state.cjs command (ingest / decide / verify / critic / recheck-result). All run state stays
// in the run directory; the driver itself keeps only RUN_DIR/orchestrator/{state.json,attempts.jsonl,
// driver.lock}, so a crash, rate limit or reboot resumes from disk.
//
//   node orchestrate.cjs <run dir> [--max-parallel 4] [--max-agents N] [--until hunt|critics|recheck|validate|complete]
//        [--dry-run] [--once] [--claude <path>] [--model-strong <m>] [--model-lite <m>] [--retry-wait auto|<seconds>]
//        [--task-timeout <seconds>] [--max-turns N] [--agent-mode plugin|plain|none] [--exclude-file <json>]
//
// Exit codes: 0 done (complete, or --until / --once reached) · 1 internal error or persistent API errors ·
// 2 bad arguments or unsupported run · 3 needs a human (unmet complete conditions, exhausted validation retries,
// unconvertible critic proposals, empty ledger) · 4 usage limit hit (reset time printed) · 5 another driver
// holds the run · 6 run ended incomplete (budget) · 130 interrupted.
// See references/orchestrator.md.

const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const crypto = require('crypto');
const { Reporter, loadJson, LEDGER_LIMITS, isObj, isArr, sha256, canonicalJson } = require('./lib.cjs');
const { coverageHash, EST } = require('./run-state.cjs');

const RS = path.join(__dirname, 'run-state.cjs');
const STAGES = ['hunt', 'critics', 'recheck', 'validate', 'complete'];
const MAX_ATTEMPTS = 3; // first try + 2 retries, each with a fresh agent id
const RECHECK_CHUNK = 6;
const MAX_TRANSIENT_ROUNDS = 5;
const MAX_LIMIT_WAIT_MS = 6 * 3600 * 1000;
const READ_TOOLS = ['Read', 'Grep', 'Glob', 'Write'];
const DENY_TOOLS = ['Bash', 'PowerShell', 'WebFetch', 'WebSearch', 'NotebookEdit', 'Monitor'];
const ROLE_AGENT = { skeptic: 'bsec-skeptic', 'record-check': 'bsec-record-check', critic: 'bsec-critic', recheck: 'bsec-hunter' };

// ---------- small helpers ----------
const now = () => new Date();
const hms = (d = now()) => d.toTimeString().slice(0, 8);
function say(line) { process.stdout.write(`[${hms()}] ${line}\n`); }
function tryJson(file, limits) {
  if (!fs.existsSync(file)) return undefined;
  const rep = new Reporter();
  const v = loadJson(file, rep, limits);
  return rep.errors.length ? undefined : v;
}
function listJson(dir) { return fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort() : []; }
const fpFile = (fp) => encodeURIComponent(fp).replace(/\*/g, '%2A') + '.json';
const fpOfFile = (f) => decodeURIComponent(f.slice(0, -5));
const recordHash = (r) => sha256(canonicalJson(r));
const sleep = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
function writeAtomic(file, text) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, text);
  for (let i = 0; ; i++) {
    try { fs.renameSync(tmp, file); return; } catch (e) {
      if (i >= 8 || !['EPERM', 'EACCES', 'EBUSY'].includes(e.code)) throw e;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50 * (i + 1));
    }
  }
}

class Stop extends Error { constructor(code, msg) { super(msg); this.code = code; } }

// ---------- arguments ----------
const VALUE_FLAGS = new Set(['--max-parallel', '--max-agents', '--until', '--claude', '--model-strong', '--model-lite', '--retry-wait', '--task-timeout', '--max-turns', '--agent-mode', '--exclude-file']);
const BOOL_FLAGS = new Set(['--dry-run', '--once']);
function parseArgs(argv) {
  const o = { maxParallel: 4, maxAgents: null, until: 'complete', dryRun: false, once: false, claude: null, modelStrong: null, modelLite: null,
    retryWait: null, taskTimeout: 3600, maxTurns: null, agentMode: 'plugin', excludeFile: null, run: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (BOOL_FLAGS.has(a)) { o[a === '--dry-run' ? 'dryRun' : 'once'] = true; continue; }
    if (VALUE_FLAGS.has(a)) {
      const v = argv[++i];
      if (v === undefined) throw new Stop(2, `${a} needs a value`);
      const int = (min) => { const n = Number(v); if (!Number.isInteger(n) || n < min) throw new Stop(2, `${a} must be an integer >= ${min}`); return n; };
      switch (a) {
        case '--max-parallel': o.maxParallel = int(1); break;
        case '--max-agents': o.maxAgents = int(0); break;
        case '--until': if (!STAGES.includes(v)) throw new Stop(2, `--until must be one of ${STAGES.join('|')}`); o.until = v; break;
        case '--claude': o.claude = v; break;
        case '--model-strong': o.modelStrong = v; break;
        case '--model-lite': o.modelLite = v; break;
        case '--retry-wait': if (v !== 'auto' && !(Number.isFinite(Number(v)) && Number(v) >= 0)) throw new Stop(2, '--retry-wait must be auto or seconds'); o.retryWait = v === 'auto' ? 'auto' : Number(v); break;
        case '--task-timeout': o.taskTimeout = int(1); break;
        case '--max-turns': o.maxTurns = int(1); break;
        case '--agent-mode': if (!['plugin', 'plain', 'none'].includes(v)) throw new Stop(2, '--agent-mode must be plugin|plain|none'); o.agentMode = v; break;
        case '--exclude-file': o.excludeFile = path.resolve(v); break;
        default: break;
      }
      continue;
    }
    if (a.startsWith('--')) throw new Stop(2, `unknown option ${a}`);
    if (o.run) throw new Stop(2, 'only one run directory');
    o.run = path.resolve(a);
  }
  if (!o.run) throw new Stop(2, 'usage: orchestrate.cjs <run dir> [--max-parallel 4] [--max-agents N] [--until stage] [--dry-run] [--once] [--claude path] [--model-strong m] [--model-lite m] [--retry-wait auto|seconds]');
  return o;
}

// ---------- run-state CLI ----------
function rs(args) {
  const r = cp.spawnSync(process.execPath, [RS, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, windowsHide: true });
  return { ok: r.status === 0, out: (r.stdout || '').trim(), err: (r.stderr || '').trim().replace(/^run-state: /, '') };
}
function rsMust(args) {
  const r = rs(args);
  if (!r.ok) throw new Stop(3, `run-state.cjs ${args[0]} failed: ${r.err || r.out}`);
  return r.out;
}

// ---------- reading run state (read-only) ----------
const SAMPLEABLE = new Set(['covered', 'carried']);
const isLiteCovered = (u) => u.status === 'covered' && isObj(u.notes) && u.notes.covered_tier === 'lite';
const liteRule = (n) => (n ? Math.min(n, Math.max(5, Math.ceil(0.2 * n))) : 0);
const recheckRule = (rate, min, covered) => Math.min(covered, Math.max(min, Math.ceil(rate * covered)));

// Mirrors run-state.cjs recheckState/recheckNeeds (not exported): what the recheck still needs, in order.
function recheckNeeds(run, ledger, profile) {
  const S = ledger.filter((u) => SAMPLEABLE.has(u.status)).length;
  const L = ledger.filter(isLiteCovered).length;
  const plan = tryJson(path.join(run, 'recheck', 'plan.json'));
  if (!isObj(plan) || !isArr(plan.units)) {
    if ((profile === 'deep' && S > 0) || L > 0) return [{ code: 'sample' }];
    return [];
  }
  const planned = plan.units.filter(isObj);
  const planWave = new Map(planned.map((p) => [p.id, p.wave]));
  const recorded = new Map();
  for (const f of listJson(path.join(run, 'recheck', 'results'))) {
    const r = tryJson(path.join(run, 'recheck', 'results', f));
    if (!isObj(r) || !isArr(r.results)) continue;
    for (const e of r.results) {
      if (!isObj(e) || recorded.has(e.id) || !planWave.has(e.id)) continue;
      if (e.wave !== undefined && e.wave !== planWave.get(e.id)) continue;
      recorded.set(e.id, e.agree);
    }
  }
  const byId = new Map(ledger.map((u) => [u.id, u]));
  const still = (p) => { const u = byId.get(p.id); return !!u && SAMPLEABLE.has(u.status) && u.wave === p.wave; };
  const missing = planned.filter((p) => !recorded.has(p.id) && still(p)).map((p) => p.id);
  const unresolved = planned.filter((p) => recorded.get(p.id) === false && still(p)).map((p) => p.id);
  const lite = planned.filter((p) => p.stratum === 'lite');
  const liteDis = lite.filter((p) => recorded.get(p.id) === false).length;
  const out = [];
  if (unresolved.length) out.push({ code: 'reopen', ids: unresolved });
  if (L > 0 && liteDis >= 2 && liteDis * 10 > lite.length) out.push({ code: 'lite' });
  const liteReq = liteRule(L);
  const normReq = Math.min(recheckRule(Number.isFinite(plan.rate) ? plan.rate : 0.1, Number.isInteger(plan.min) ? plan.min : 3, S), Math.max(0, S - liteReq));
  if (planned.length - lite.length < normReq || lite.length < liteReq) out.push({ code: 'redraw' });
  if (missing.length) out.push({ code: 'missing', ids: missing });
  return out;
}

function readState(run) {
  const runJson = tryJson(path.join(run, 'run.json'));
  if (!isObj(runJson)) throw new Stop(2, `${run}: run.json missing or unreadable`);
  const ledger = tryJson(path.join(run, 'ledger.json'), LEDGER_LIMITS);
  if (ledger !== undefined && !isArr(ledger)) throw new Stop(3, 'ledger.json is not a JSON array');
  const L = (ledger || []).filter(isObj);
  const profile = runJson.profile;
  const strict = profile === 'standard' || profile === 'deep';
  const live = new Set(L.flatMap((u) => (isArr(u.fingerprints) ? u.fingerprints : [])));
  const decisions = new Map();
  for (const f of listJson(path.join(run, 'decisions'))) { const d = tryJson(path.join(run, 'decisions', f)); if (isObj(d)) decisions.set(fpOfFile(f), d); }
  const verified = (fp) => {
    const d = decisions.get(fp);
    if (!d || !isObj(d.record)) return false;
    const v = tryJson(path.join(run, 'verifications', fpFile(fp)));
    const h = recordHash(d.record);
    return isObj(v) && isArr(v.verifications) && v.verifications.some((x) => isObj(x) && x.record_sha256 === h);
  };
  const undecided = [...live].filter((fp) => !decisions.has(fp)).sort();
  const unverified = strict ? [...decisions.keys()].filter((fp) => live.has(fp) && decisions.get(fp).decision !== 'rejected' && !verified(fp)).sort() : [];
  const critics = listJson(path.join(run, 'critics')).map((f) => tryJson(path.join(run, 'critics', f))).filter(isObj).sort((a, b) => a.seq - b.seq);
  const hash = coverageHash(L);
  const last2 = critics.slice(-2);
  const criticsOk = profile === 'quick' ? critics.length >= 1
    : last2.length === 2 && last2.every((c) => c.clean === true && c.coverage_hash === hash) && last2[0].critic !== last2[1].critic;
  let findingsCurrent = false;
  const ff = tryJson(path.join(run, 'findings.json'));
  if (ff !== undefined) {
    const exp = [...decisions.values()].map((d) => d.record).sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));
    try { findingsCurrent = canonicalJson(ff) === canonicalJson(exp); } catch { findingsCurrent = false; }
  }
  const agentsDir = path.join(run, 'agents');
  const agentIds = fs.existsSync(agentsDir) ? fs.readdirSync(agentsDir).filter((a) => fs.statSync(path.join(agentsDir, a)).isDirectory()) : [];
  return {
    runJson, profile, strict, ledger: L, hasLedger: ledger !== undefined, live, decisions, undecided, unverified, critics, hash, criticsOk,
    planned: L.filter((u) => u.status === 'planned'), inProgress: L.filter((u) => u.status === 'in_progress'),
    needs: recheckNeeds(run, L, profile), findingsCurrent, agentCount: agentIds.length, agentIds,
  };
}

// Agents whose out/result.json waits for its command (run-state's pendingOutputs is not exported).
function pendingOthers(run, failedAgents) {
  const dir = path.join(run, 'agents');
  const out = [];
  for (const a of fs.existsSync(dir) ? fs.readdirSync(dir).sort() : []) {
    const d = path.join(dir, a);
    if (failedAgents.has(a) || fs.existsSync(path.join(d, 'assignment.json')) || fs.existsSync(path.join(d, 'applied.json'))) continue;
    const meta = tryJson(path.join(d, 'brief.json'));
    if (isObj(meta) && ROLE_AGENT[meta.role] && fs.existsSync(path.join(d, 'out', 'result.json'))) out.push({ agent: a, role: meta.role, fp: meta.fingerprint, units: meta.units });
  }
  return out;
}

// ---------- orchestrator files ----------
class Book {
  constructor(run, dry) {
    this.run = run; this.dry = dry;
    this.dir = path.join(run, 'orchestrator');
    this.attemptsFile = path.join(this.dir, 'attempts.jsonl');
    this.stateFile = path.join(this.dir, 'state.json');
    this.attempts = [];
    if (fs.existsSync(this.attemptsFile)) {
      for (const l of fs.readFileSync(this.attemptsFile, 'utf8').split('\n')) { if (!l.trim()) continue; try { this.attempts.push(JSON.parse(l)); } catch { /* torn line */ } }
    }
    const s = tryJson(this.stateFile);
    this.state = isObj(s) ? s : {};
    this.state.round = Number.isInteger(this.state.round) ? this.state.round : 0;
  }
  attempt(e) {
    const rec = { at: now().toISOString(), round: this.state.round, ...e };
    this.attempts.push(rec);
    if (!this.dry) fs.appendFileSync(this.attemptsFile, JSON.stringify(rec) + '\n');
  }
  save(patch = {}) {
    Object.assign(this.state, patch, { updated: now().toISOString() });
    if (!this.dry) writeAtomic(this.stateFile, JSON.stringify(this.state, null, 2) + '\n');
  }
  failures(key) { return this.attempts.filter((a) => a.keys && a.keys.includes(key) && a.counts !== false && a.outcome !== 'ok').length; }
  failedAgents() { return new Set(this.attempts.filter((a) => a.outcome !== 'ok' && a.agent).map((a) => a.agent)); }
}

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  if (pid === process.pid) return true;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}
let lockFile = null; let lockToken = null;
function acquireDriverLock(run) {
  const dir = path.join(run, 'orchestrator');
  fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, 'driver.lock');
  const token = JSON.stringify({ pid: process.pid, host: os.hostname(), at: now().toISOString(), nonce: crypto.randomBytes(6).toString('hex') });
  for (let i = 0; i < 3; i++) {
    try { fs.writeFileSync(f, token, { flag: 'wx' }); lockFile = f; lockToken = token; return; } catch (e) { if (e.code !== 'EEXIST') throw e; }
    let info = null;
    try { info = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { info = null; }
    if (isObj(info) && info.host && info.host !== os.hostname()) throw new Stop(5, `another orchestrator (pid ${info.pid} on host ${info.host}) holds ${f}; if it is gone, delete the file`);
    if (isObj(info) && pidAlive(info.pid)) throw new Stop(5, `another orchestrator (pid ${info.pid}, since ${info.at}) is driving this run directory (${f})`);
    say(`taking over stale driver lock${isObj(info) ? ` of pid ${info.pid}` : ''}`);
    try { fs.unlinkSync(f); } catch { /* raced */ }
  }
  throw new Stop(5, `could not take the driver lock ${f}`);
}
function releaseDriverLock() {
  if (!lockFile) return;
  try { if (fs.readFileSync(lockFile, 'utf8') === lockToken) fs.unlinkSync(lockFile); } catch { /* ignore */ }
  lockFile = null;
}

// ---------- spawning claude ----------
const ENV_BASE = ['PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'windir', 'ComSpec', 'SystemDrive', 'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
  'APPDATA', 'LOCALAPPDATA', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'CommonProgramFiles', 'TEMP', 'TMP', 'TMPDIR',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM', 'TZ', 'USER', 'USERNAME', 'LOGNAME', 'SHELL', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME',
  'XDG_STATE_HOME', 'XDG_RUNTIME_DIR', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS', 'COMPUTERNAME'];
const ENV_AUTH = /^(ANTHROPIC_(API_KEY|AUTH_TOKEN|BASE_URL|MODEL|SMALL_FAST_MODEL|DEFAULT_[A-Z]+_MODEL|CUSTOM_HEADERS)|CLAUDE_CODE_(OAUTH_TOKEN|USE_BEDROCK|USE_VERTEX|USE_FOUNDRY|MAX_RETRIES|GIT_BASH_PATH)|CLAUDE_CONFIG_DIR|(HTTPS?|NO|ALL)_PROXY|(https?|no|all)_proxy|NODE_EXTRA_CA_CERTS|SSL_CERT_FILE)$/;
const ENV_BEDROCK = /^(AWS_(REGION|DEFAULT_REGION|PROFILE|ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|BEARER_TOKEN_BEDROCK)|ANTHROPIC_BEDROCK_\w+)$/;
const ENV_VERTEX = /^(CLOUD_ML_REGION|ANTHROPIC_VERTEX_\w+|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_CLOUD_PROJECT|VERTEX_REGION_\w+)$/;
const ENV_FOUNDRY = /^ANTHROPIC_FOUNDRY_\w+$/;
// Only what the CLI needs to start and authenticate; never the parent's other variables.
function childEnv(src = process.env) {
  const out = {};
  const extra = new Set(String(src.BSEC_ORCH_PASS_ENV || '').split(',').map((s) => s.trim()).filter(Boolean));
  for (const k of Object.keys(src)) {
    if (ENV_BASE.includes(k) || ENV_AUTH.test(k) || extra.has(k)
      || (src.CLAUDE_CODE_USE_BEDROCK && ENV_BEDROCK.test(k)) || (src.CLAUDE_CODE_USE_VERTEX && ENV_VERTEX.test(k)) || (src.CLAUDE_CODE_USE_FOUNDRY && ENV_FOUNDRY.test(k))) out[k] = src[k];
  }
  return out;
}
function onPath(name) {
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';').map((e) => e.toLowerCase()) : [''];
  for (const dir of String(process.env.PATH || process.env.Path || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const e of process.platform === 'win32' ? ['.exe', ...exts.filter((x) => x !== '.exe')] : ['']) {
      const f = path.join(dir, name + e);
      try { if (fs.statSync(f).isFile()) return f; } catch { /* next */ }
    }
  }
  return null;
}
// cmd.exe quoting for .cmd/.bat shims (arguments are data; metacharacters are caret-escaped twice because the
// shim re-parses its %* through cmd once more).
function cmdQuote(arg) {
  let a = String(arg).replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, '$1$1');
  a = `"${a}"`;
  return a.replace(/([()\][%!^"`<>&|;, *?])/g, '^^^$1');
}
// Returns { file, prefix, verbatim } so that spawn(file, [...prefix, ...args]) runs the CLI without a shell string.
function resolveClaude(opt) {
  const given = opt || process.env.BSEC_CLAUDE || null;
  const file = given ? path.resolve(given) : onPath('claude');
  if (!file) throw new Stop(2, 'claude CLI not found on PATH; pass --claude <path>');
  if (/\.(c|m)?js$/i.test(file)) return { file: process.execPath, prefix: [file], label: file };
  if (process.platform === 'win32' && /\.(cmd|bat)$/i.test(file)) {
    let text = '';
    try { text = fs.readFileSync(file, 'utf8'); } catch { /* fall through */ }
    const m = /"%(?:~)?dp0%?\\?([^"%]+?\.(?:c|m)?js)"/i.exec(text);
    if (m) {
      const js = path.join(path.dirname(file), m[1]);
      if (fs.existsSync(js)) return { file: process.execPath, prefix: [js], label: `${file} -> ${js}` };
    }
    return { file: process.env.ComSpec || 'cmd.exe', prefix: ['/d', '/s', '/c'], cmdShim: file, label: file };
  }
  return { file, prefix: [], label: file };
}

function agentName(base, mode) { return mode === 'plugin' ? `boring-security:${base}` : base; }
// The exact argv (after the executable) for one task.
function buildArgs(task, ctx) {
  const { opts, run, runJson } = ctx;
  const agentDir = path.join(run, 'agents', task.id);
  const brief = path.join(agentDir, 'brief.md');
  const lite = task.kind === 'hunt' && task.tier === 'lite';
  const base = task.kind === 'hunt' ? (lite ? 'bsec-hunter-lite' : 'bsec-hunter') : ROLE_AGENT[task.kind];
  const cheap = lite || task.kind === 'record-check';
  const model = cheap ? opts.modelLite : opts.modelStrong;
  const args = ['-p', `Read ${brief} completely and follow it.`, '--output-format', 'json'];
  if (opts.agentMode !== 'none') args.push('--agent', agentName(base, opts.agentMode));
  else args.push('--tools', READ_TOOLS.join(','));
  args.push('--allowedTools', READ_TOOLS.join(','), '--disallowedTools', DENY_TOOLS.join(','), '--permission-mode', 'dontAsk',
    '--strict-mcp-config', '--disable-slash-commands', '--no-session-persistence');
  if (model) args.push('--model', model);
  if (opts.maxTurns) args.push('--max-turns', String(opts.maxTurns));
  const target = path.resolve(String(runJson.target));
  // untrusted: never rooted in the target (its .claude/, CLAUDE.md, MCP configs never load); target is a read dir.
  const untrusted = runJson.trust === 'untrusted';
  const cwd = untrusted ? agentDir : target;
  args.push('--add-dir', untrusted ? target : agentDir);
  return { args, cwd, agent: opts.agentMode === 'none' ? `(none: ${base} tools)` : agentName(base, opts.agentMode), model: model || 'agent default', brief };
}

function spawnClaude(claude, args, cwd, logDir, timeoutMs) {
  return new Promise((resolve) => {
    fs.mkdirSync(logDir, { recursive: true });
    let file = claude.file; let argv = [...claude.prefix, ...args]; const so = { cwd, env: childEnv(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] };
    if (claude.cmdShim) { argv = ['/d', '/s', '/c', `"${[claude.cmdShim, ...args].map(cmdQuote).join(' ')}"`]; so.windowsVerbatimArguments = true; }
    if (process.platform !== 'win32') so.detached = true; // own process group, so a timeout kills the whole tree
    const t0 = Date.now();
    let child;
    try { child = cp.spawn(file, argv, so); } catch (e) { resolve({ code: null, stdout: '', stderr: String(e.message), timedOut: false, ms: 0 }); return; }
    running.add(child);
    const out = []; const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; killTree(child); }, timeoutMs);
    const done = (code) => {
      clearTimeout(timer); running.delete(child);
      const stdout = Buffer.concat(out).toString('utf8'); const stderr = Buffer.concat(err).toString('utf8');
      try { fs.writeFileSync(path.join(logDir, 'session.json'), stdout); fs.writeFileSync(path.join(logDir, 'session.log'), stderr); } catch { /* agent dir gone */ }
      resolve({ code, stdout, stderr, timedOut, ms: Date.now() - t0 });
    };
    child.on('error', (e) => { err.push(Buffer.from(String(e.message))); });
    child.on('close', (code) => done(code));
  });
}
const running = new Set();
function killTree(child) {
  try {
    if (process.platform === 'win32') cp.spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    else { try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); } setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ } }, 3000).unref(); }
  } catch { /* gone */ }
}

// ---------- reading a session's result ----------
function parseSession(stdout) {
  const t = String(stdout || '').trim();
  if (!t) return null;
  try { const v = JSON.parse(t); if (isObj(v)) return v; if (isArr(v)) return v.filter(isObj).reverse().find((x) => x.type === 'result') || null; } catch { /* lines */ }
  for (const l of t.split('\n').reverse()) { try { const v = JSON.parse(l); if (isObj(v) && v.type === 'result') return v; } catch { /* next */ } }
  return null;
}
const LIMIT_RE = /You(?:'|’)ve hit your [^\n]*?(?:limit|budget)|spend limit reached|Claude AI usage limit reached|usage limit reached/i;
const TRANSIENT_RE = /API Error|overloaded|\b(?:500|502|503|504|529)\b|Request rejected \(429\)|temporarily limiting|ECONNRESET|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket hang up|fetch failed|network error/i;
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
// "resets 3:45pm", "resets Mon 12:00am", "resets Dec 1", "resets 3pm (Europe/London)", or the legacy
// "Claude AI usage limit reached|<epoch>". Times are read as local time of this machine; a named zone is ignored.
function parseReset(text, ref = new Date()) {
  const s = String(text || '');
  const ep = /usage limit reached\|(\d{10,13})/i.exec(s);
  if (ep) { const n = Number(ep[1]); return new Date(n < 1e12 ? n * 1000 : n); }
  const m = /resets\s+(?:at\s+|on\s+)?([^\n·(|"]+)/i.exec(s);
  if (!m) return null;
  const v = m[1].trim().replace(/[.,;]+$/, '').toLowerCase();
  const tm = (str) => { const x = /^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/.exec(str.trim()); if (!x) return null; let h = Number(x[1]); const mi = Number(x[2] || 0); if (x[3] === 'pm' && h < 12) h += 12; if (x[3] === 'am' && h === 12) h = 0; return h < 24 && mi < 60 ? [h, mi] : null; };
  let x = /^(sun|mon|tue|wed|thu|fri|sat)[a-z]*\s+(.+)$/.exec(v);
  if (x) {
    const t = tm(x[2]); if (!t) return null;
    const d = new Date(ref); d.setHours(t[0], t[1], 0, 0);
    let add = (DAYS.indexOf(x[1]) - d.getDay() + 7) % 7;
    if (add === 0 && d <= ref) add = 7;
    d.setDate(d.getDate() + add); return d;
  }
  x = /^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+(\d{1,2})(?:,?\s+(?:at\s+)?(.+))?$/.exec(v);
  if (x) {
    const t = x[3] ? tm(x[3]) : [0, 0]; if (!t) return null;
    const d = new Date(ref.getFullYear(), MONTHS.indexOf(x[1]), Number(x[2]), t[0], t[1], 0, 0);
    if (d <= ref) d.setFullYear(d.getFullYear() + 1);
    return d;
  }
  const t = tm(v);
  if (!t) return null;
  const d = new Date(ref); d.setHours(t[0], t[1], 0, 0);
  if (d <= ref) d.setDate(d.getDate() + 1);
  return d;
}
function usageOf(sess) {
  const u = isObj(sess) && isObj(sess.usage) ? sess.usage : {};
  const n = (k) => (Number.isFinite(u[k]) ? u[k] : 0);
  return {
    cost_usd: isObj(sess) && Number.isFinite(sess.total_cost_usd) ? sess.total_cost_usd : null,
    input_tokens: n('input_tokens'), output_tokens: n('output_tokens'),
    cache_read_input_tokens: n('cache_read_input_tokens'), cache_creation_input_tokens: n('cache_creation_input_tokens'),
    models: isObj(sess) && isObj(sess.modelUsage) ? Object.keys(sess.modelUsage) : [],
    num_turns: isObj(sess) && Number.isFinite(sess.num_turns) ? sess.num_turns : null,
    duration_ms: isObj(sess) && Number.isFinite(sess.duration_ms) ? sess.duration_ms : null,
    session_id: isObj(sess) && typeof sess.session_id === 'string' ? sess.session_id : null,
  };
}

// ---------- the driver ----------
class Driver {
  constructor(opts) {
    this.opts = opts; this.run = opts.run;
    this.book = new Book(this.run, opts.dryRun);
    this.launchedHere = 0;
    this.stats = { byRole: {}, retries: 0, cost: 0, costKnown: 0, tokens: { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 }, models: new Set() };
    this.t0 = Date.now();
    this.transientRounds = 0;
    this.criticNoProgress = 0;
    this.warnedPriors = false;
  }

  freshId(prefix, taken) {
    const r = this.book.state.round;
    for (let n = 1; ; n++) {
      const id = `${prefix}-${r}-${n}`;
      if (!taken.has(id) && !fs.existsSync(path.join(this.run, 'agents', id))) { taken.add(id); return id; }
    }
  }

  remaining(st) {
    const b = st.runJson.budget_agents;
    const a = Number.isInteger(b) ? b - st.agentCount : Infinity;
    const c = this.opts.maxAgents !== null ? this.opts.maxAgents - this.launchedHere : Infinity;
    return Math.min(a, c);
  }
  allowed(stage) { return STAGES.indexOf(stage) <= STAGES.indexOf(this.opts.until); }

  validationTasks(st) {
    const tasks = [];
    if (!this.allowed('validate')) return tasks;
    for (const fp of st.undecided) {
      if (this.book.failures(`skeptic:${fp}`) >= MAX_ATTEMPTS) throw new Stop(3, `Skeptic for ${fp} failed ${MAX_ATTEMPTS} times (see orchestrator/attempts.jsonl): brief one interactively, or end with run-state.cjs incomplete <run> validation_budget_exhausted`);
      tasks.push({ kind: 'skeptic', fp, keys: [`skeptic:${fp}`, `fp:${fp}`] });
    }
    for (const fp of st.unverified) {
      const h = recordHash(st.decisions.get(fp).record).slice(0, 16);
      const key = `record-check:${fp}@${h}`;
      if (this.book.failures(key) >= MAX_ATTEMPTS) throw new Stop(3, `record check for ${fp} failed ${MAX_ATTEMPTS} times: verify it interactively, or end with run-state.cjs incomplete <run> verification_unavailable`);
      const replaced = this.book.attempts.filter((a) => a.outcome === 'ok' && a.replaced === fp).length;
      if (replaced >= MAX_ATTEMPTS) throw new Stop(3, `${fp} was replaced ${replaced} times by record checkers without converging: needs judgement (verification_unavailable)`);
      tasks.push({ kind: 'record-check', fp, keys: [key, `fp:${fp}`] });
    }
    return tasks;
  }

  // Decide the next step from disk. Returns {type:'cmd'|'tasks'|'done'|'stop', ...}.
  nextStep() {
    const st = readState(this.run);
    const { runJson } = st;
    if (runJson.status === 'complete') return { type: 'done', msg: 'run is complete', st, final: true };
    if (runJson.execution === 'sandboxed-local-only') throw new Stop(2, 'sandboxed runs need the lead to pass the sandbox wrapper and promote evidence; the orchestrator drives source-only runs only');
    if (!st.hasLedger || !st.ledger.length) throw new Stop(3, 'no ledger: run Phase 1 (or /threat-model) to seed ledger.json first');
    if (typeof runJson.target !== 'string' || !fs.existsSync(runJson.target)) throw new Stop(2, 'run.json.target must be an existing directory');
    if (st.inProgress.length) return { type: 'cmd', label: 'recover', args: ['recover', this.run], st, why: `${st.inProgress.length} unit(s) in progress from an earlier session` };
    const pend = pendingOthers(this.run, this.book.failedAgents());
    if (pend.length) return { type: 'pending', pend, st };
    const remaining = this.remaining(st);
    const val = () => this.validationTasks(st);
    const budgetMode = this.book.state.budget_mode === true;

    // ---- hunting ----
    if (st.planned.length && !budgetMode) {
      const exhausted = st.planned.filter((u) => this.book.failures(`unit:${u.id}@${u.wave}`) >= MAX_ATTEMPTS).map((u) => u.id);
      if (exhausted.length) return { type: 'cmd', label: 'defer exhausted units', args: ['set-status', this.run, ...exhausted, '--to', 'deferred', '--reason', 'orchestrator_retries_exhausted'], st };
      if (!this.warnedPriors && st.planned.some((u) => u.prior === 'confirmed_same' || u.prior === 'nv')) {
        this.warnedPriors = true;
        say('warning: planned units carry prior confirmed_same/nv records; their hunters get no prior findings path (not automated, see references/orchestrator.md)');
      }
      const out = rsMust(['next', this.run, '--batch']);
      const groups = out.split('\n').filter((l) => l.trim()).map((l) => {
        const [ids, meta = ''] = l.split('  #');
        return { units: ids.trim().split(/\s+/), tier: /tier=standard/.test(meta) ? 'lite' : 'strong' };
      });
      let hunters = groups.length;
      let validation = val();
      if (remaining !== Infinity) {
        const perCand = st.profile === 'quick' ? 1 : 2;
        const criticRes = st.profile === 'quick' ? (st.critics.length ? 0 : 1) : 2;
        const S = st.ledger.filter((u) => SAMPLEABLE.has(u.status)).length + st.planned.length;
        const recheckRes = st.profile === 'deep' || st.ledger.some((u) => isObj(u.notes) && u.notes.tier === 'standard') ? Math.ceil(Math.max(3, Math.ceil(0.1 * S)) / RECHECK_CHUNK) : 0;
        const valRes = st.undecided.length * perCand + st.unverified.length + Math.ceil(st.planned.length * EST.candidateRate) * perCand;
        hunters = Math.min(groups.length, remaining - criticRes - recheckRes - valRes);
        if (hunters <= 0) {
          this.book.save({ budget_mode: true });
          return { type: 'cmd', label: 'defer for budget', args: ['set-status', this.run, ...st.planned.map((u) => u.id), '--to', 'deferred', '--reason', 'budget_reserve'], st,
            why: `agent budget: ${remaining} left, ${criticRes + recheckRes + valRes} reserved for critics, recheck and validation` };
        }
        validation = validation.slice(0, Math.max(0, remaining - hunters));
      }
      const tasks = groups.slice(0, hunters).map((g) => ({ kind: 'hunt', units: g.units, tier: g.tier, keys: g.units.map((id) => { const u = st.ledger.find((x) => x.id === id); return `unit:${id}@${u ? u.wave : 1}`; }) }));
      return { type: 'tasks', stage: 'hunt', tasks: [...tasks, ...validation], st };
    }
    if (st.planned.length && budgetMode) return { type: 'cmd', label: 'defer for budget', args: ['set-status', this.run, ...st.planned.map((u) => u.id), '--to', 'deferred', '--reason', 'budget_reserve'], st };
    if (!this.allowed('critics')) return { type: 'done', msg: 'hunting finished (--until hunt)', st };

    // ---- budget mode: validate what exists, then end incomplete ----
    if (budgetMode) {
      const v = val();
      if (v.length && remaining > 0) return { type: 'tasks', stage: 'validate', tasks: v.slice(0, remaining), st };
      return { type: 'end-incomplete', reason: v.length ? 'validation_budget_exhausted' : 'stopped_early', st };
    }

    // ---- critics ----
    if (!st.criticsOk) {
      if (remaining <= 0) return { type: 'end-incomplete', reason: 'critic_budget_exhausted', st };
      const key = `critic@${st.hash.slice(0, 16)}#${st.critics.length}`;
      if (this.book.failures(key) >= MAX_ATTEMPTS) throw new Stop(3, `the coverage critic failed ${MAX_ATTEMPTS} times at this coverage (see orchestrator/attempts.jsonl)`);
      const v = val().slice(0, Math.max(0, remaining - 1));
      return { type: 'tasks', stage: 'critics', tasks: [{ kind: 'critic', keys: [key] }, ...v], st };
    }
    if (!this.allowed('recheck')) return { type: 'done', msg: 'critics clean (--until critics)', st };

    // ---- recheck ----
    if (st.needs.length) {
      const n = st.needs[0];
      if (n.code === 'reopen') return { type: 'cmd', label: 'reopen disagreeing units', multi: n.ids.map((id) => ['reopen', this.run, id, '--reason', 'recheck disagreement (orchestrator, recheck/results)']), st };
      if (n.code === 'lite') return { type: 'cmd', label: 'reopen lite-tier units', args: ['reopen', this.run, '--lite-tier', '--reason', 'lite-tier recheck failed (orchestrator)'], st };
      if (n.code === 'sample') return { type: 'cmd', label: 'draw recheck sample', args: ['sample-recheck', this.run], st };
      if (n.code === 'redraw') return { type: 'cmd', label: 'redraw recheck sample', args: ['sample-recheck', this.run, '--redraw'], st };
      if (remaining <= 0) return { type: 'end-incomplete', reason: 'stopped_early', st };
      const tasks = [];
      for (let i = 0; i < n.ids.length; i += RECHECK_CHUNK) {
        const ids = n.ids.slice(i, i + RECHECK_CHUNK);
        const keys = ids.map((id) => { const u = st.ledger.find((x) => x.id === id); return `recheck:${id}@${u ? u.wave : 1}`; });
        if (keys.some((k) => this.book.failures(k) >= MAX_ATTEMPTS)) throw new Stop(3, `recheck of ${ids.join(' ')} failed ${MAX_ATTEMPTS} times (see orchestrator/attempts.jsonl)`);
        tasks.push({ kind: 'recheck', units: ids, keys });
      }
      const v = val();
      const all = [...tasks, ...v];
      return { type: 'tasks', stage: 'recheck', tasks: all.slice(0, remaining), st };
    }
    if (!this.allowed('validate')) return { type: 'done', msg: 'recheck finished (--until recheck)', st };

    // ---- validation ----
    const v = val();
    if (v.length) {
      if (remaining <= 0) return { type: 'end-incomplete', reason: 'validation_budget_exhausted', st };
      return { type: 'tasks', stage: 'validate', tasks: v.slice(0, remaining), st };
    }
    if (!this.allowed('complete')) return { type: 'done', msg: 'validation finished (--until validate)', st };

    // ---- records and status ----
    if (!st.findingsCurrent) return { type: 'cmd', label: 'assemble', args: ['assemble', this.run], st };
    return { type: 'complete', st };
  }

  // ---------- task preparation and application ----------
  prepare(task, ctx) {
    const R = this.run;
    if (task.kind === 'hunt') {
      const a = rs(['assign', R, task.id, ...task.units]);
      if (!a.ok) return `assign refused: ${a.err}`;
      const asg = tryJson(path.join(R, 'agents', task.id, 'assignment.json'));
      task.tier = isObj(asg) && asg.tier === 'lite' ? 'lite' : 'strong';
      const b = rs(['brief', R, task.id, '--role', 'hunter', ...(this.opts.excludeFile ? ['--exclude-file', this.opts.excludeFile] : [])]);
      return b.ok ? null : `brief refused: ${b.err}`;
    }
    const args = ['brief', R, task.id, '--role', task.kind];
    if (task.fp) args.push('--fingerprint', task.fp);
    if (task.units) args.push('--units', ...task.units);
    const b = rs(args);
    void ctx;
    return b.ok ? null : `brief refused: ${b.err}`;
  }

  // Apply an agent's out/result.json. Returns {ok, msg, unitFails?, replaced?}.
  apply(task) {
    const R = this.run;
    const out = path.join(R, 'agents', task.id, 'out', 'result.json');
    if (task.kind === 'hunt') {
      const r = rs(['ingest', R, task.id]);
      if (!r.ok) return { ok: false, msg: `ingest failed: ${r.err}`, unitFails: task.units };
      const ledger = tryJson(path.join(R, 'ledger.json'), LEDGER_LIMITS) || [];
      const by = new Map(ledger.filter(isObj).map((u) => [u.id, u]));
      const c = {};
      const fails = [];
      for (const id of task.units) { const s = by.get(id) ? by.get(id).status : 'missing'; c[s] = (c[s] || 0) + 1; if (s === 'planned' || s === 'missing') fails.push(id); }
      const msg = `ingested: ${Object.entries(c).map(([k, n]) => `${n} ${k === 'planned' ? 'rejected (back to planned)' : k}`).join(', ')}`;
      return { ok: fails.length < task.units.length, msg, unitFails: fails };
    }
    if (task.kind === 'skeptic') {
      const r = rs(['decide', R, task.id]);
      return r.ok ? { ok: true, msg: r.out.split('\n')[0] } : { ok: false, msg: `decide refused: ${r.err.split('\n')[0]}` };
    }
    if (task.kind === 'record-check') {
      const reply = tryJson(out);
      if (isObj(reply) && reply.decision === 'replace') {
        const r = rs(['decide', R, task.id]);
        return r.ok ? { ok: true, msg: `replaced: ${r.out.split('\n')[0]}`, replaced: task.fp } : { ok: false, msg: `replacement refused: ${r.err.split('\n')[0]}` };
      }
      const r = rs(['verify', R, task.id]);
      return r.ok ? { ok: true, msg: r.out.split('\n')[0] } : { ok: false, msg: `verify refused: ${r.err.split('\n')[0]}` };
    }
    if (task.kind === 'critic') {
      const before = coverageHash(readState(R).ledger);
      const r = rs(['critic', R, task.id]);
      if (!r.ok) return { ok: false, msg: `critic refused: ${r.err.split('\n')[0]}` };
      const first = r.out.split('\n')[0];
      if (/: clean at coverage/.test(first)) { this.criticNoProgress = 0; return { ok: true, msg: 'clean' }; }
      const profile = readState(R).profile;
      const added = rs(['add-units', R, '--from-critic', task.id]);
      const newIds = added.ok ? added.out.split('\n').map((l) => /^\s+\+ (\S+)/.exec(l)).filter(Boolean).map((m) => m[1]) : [];
      let reopened = 0;
      if (profile === 'quick') {
        if (newIds.length) rsMust(['set-status', R, ...newIds, '--to', 'deferred', '--reason', 'quick_profile']);
      } else {
        for (const m of r.out.split('\n').map((l) => /^\s+run-state\.cjs reopen <run> (\S+) --reason/.exec(l)).filter(Boolean)) {
          if (rs(['reopen', R, m[1], '--reason', `critic ${task.id}: see critics/`]).ok) reopened++;
        }
      }
      const after = coverageHash(readState(R).ledger);
      if (profile !== 'quick' && after === before) {
        this.criticNoProgress++;
        if (this.criticNoProgress >= 2) throw new Stop(3, `critic proposals could not be converted into ledger changes twice in a row (last: ${task.id}); a human must add, scope out or waive them (critics/)`);
      } else this.criticNoProgress = 0;
      return { ok: true, msg: `not clean: ${newIds.length} unit(s) added${profile === 'quick' ? ' as deferred (quick)' : ''}, ${reopened} reopened` };
    }
    if (task.kind === 'recheck') {
      const r = rs(['recheck-result', R, task.id]);
      if (!r.ok) return { ok: false, msg: `recheck-result refused: ${r.err.split('\n')[0]}` };
      const dis = r.out.split('\n').map((l) => /^DISAGREE (\S+):/.exec(l)).filter(Boolean).map((m) => m[1]);
      for (const id of dis) rs(['reopen', R, id, '--reason', `recheck by ${task.id} disagrees (recheck/results/${task.id}.json)`]);
      const recorded = /(\d+) recorded/.exec(r.out);
      return { ok: true, msg: `${recorded ? recorded[1] : '?'} recorded, ${dis.length} disagreement(s)${dis.length ? ' (reopened)' : ''}` };
    }
    return { ok: false, msg: 'unknown task kind' };
  }

  describe(task) {
    if (task.kind === 'hunt') return `hunt ${task.id} units=${task.units.length} tier=${task.tier === 'lite' ? 'standard (lite)' : 'high'}`;
    if (task.fp) return `${task.kind} ${task.id} fp=${task.fp}`;
    if (task.units) return `${task.kind} ${task.id} units=${task.units.length}`;
    return `${task.kind} ${task.id}`;
  }

  async runTask(task, ctx, claude) {
    const R = this.run;
    const why = this.prepare(task, ctx);
    if (why) {
      if (task.kind === 'hunt' && /assign refused/.test(why)) { say(`${task.kind} skipped: ${why}`); return { outcome: 'skipped' }; }
      say(`${this.describe(task)} → not launched: ${why}`);
      this.book.attempt({ agent: task.id, kind: task.kind, keys: task.keys, outcome: 'prepare_failed', detail: why.slice(0, 300) });
      return { outcome: 'failed' };
    }
    const b = buildArgs(task, ctx);
    this.launchedHere++;
    const roleKey = `${task.kind}${task.tier === 'lite' ? ' (lite)' : ''}`;
    const rk = `${roleKey} · ${b.agent} · ${b.model}`;
    this.stats.byRole[rk] = (this.stats.byRole[rk] || 0) + 1;
    this.book.save({ launched: (this.book.state.launched || 0) + 1 });
    say(`${this.describe(task)} → launched (${b.agent}, model ${b.model})`);
    const res = await spawnClaude(claude, b.args, b.cwd, path.join(R, 'agents', task.id), this.opts.taskTimeout * 1000);
    const sess = parseSession(res.stdout);
    const usage = usageOf(sess);
    const rec = { at: now().toISOString(), agent: task.id, role: task.kind, tier: task.tier || null, agent_type: b.agent, model_flag: b.model, exit_code: res.code, timed_out: res.timedOut, wall_ms: res.ms, is_error: isObj(sess) ? !!sess.is_error : null, ...usage };
    fs.appendFileSync(path.join(R, 'usage.jsonl'), JSON.stringify(rec) + '\n');
    if (usage.cost_usd !== null) { this.stats.cost += usage.cost_usd; this.stats.costKnown++; }
    for (const k of Object.keys(this.stats.tokens)) this.stats.tokens[k] += usage[k];
    for (const m of usage.models) this.stats.models.add(m);

    const text = `${isObj(sess) && typeof sess.result === 'string' ? sess.result : ''}\n${res.stdout.slice(-4000)}\n${res.stderr.slice(-4000)}`;
    const failedRun = res.code !== 0 || res.timedOut || (isObj(sess) && sess.is_error === true);
    if (failedRun && LIMIT_RE.test(text)) {
      const reset = parseReset(text);
      const line = (LIMIT_RE.exec(text) || [''])[0];
      say(`${this.describe(task)} → usage limit: "${line.slice(0, 120)}"${reset ? `, resets ${reset.toLocaleString()}` : ''}`);
      this.book.attempt({ agent: task.id, kind: task.kind, keys: task.keys, outcome: 'limited', counts: false, detail: line.slice(0, 200), reset: reset ? reset.toISOString() : null });
      return { outcome: 'limited', reset };
    }
    const outFile = path.join(R, 'agents', task.id, 'out', 'result.json');
    const hasOut = fs.existsSync(outFile);
    if (!hasOut) {
      const transient = !res.timedOut && failedRun && TRANSIENT_RE.test(text);
      const detail = res.timedOut ? `timed out after ${this.opts.taskTimeout}s` : `no out/result.json (exit ${res.code}${isObj(sess) && sess.subtype ? `, ${sess.subtype}` : ''})`;
      say(`${this.describe(task)} → ${transient ? 'transient API error' : 'failed'}: ${detail}`);
      this.book.attempt({ agent: task.id, kind: task.kind, keys: task.keys, outcome: transient ? 'transient' : res.timedOut ? 'timeout' : 'failed', counts: !transient, detail });
      return { outcome: transient ? 'transient' : 'failed', needsRecover: task.kind === 'hunt' };
    }
    let a;
    try { a = this.apply(task); } catch (e) { if (e instanceof Stop) throw e; a = { ok: false, msg: String(e.message) }; }
    say(`${this.describe(task)} → ${a.msg}`);
    if (task.kind === 'hunt') {
      const fails = new Set(a.unitFails || []);
      const keys = task.keys.filter((k) => fails.has(k.slice(5, k.lastIndexOf('@'))));
      this.book.attempt({ agent: task.id, kind: task.kind, keys, outcome: keys.length ? 'rejected' : 'ok', detail: a.msg.slice(0, 300) });
      if (!a.ok) return { outcome: 'failed' };
      return { outcome: 'ok' };
    }
    this.book.attempt({ agent: task.id, kind: task.kind, keys: task.keys, outcome: a.ok ? 'ok' : 'rejected', detail: a.msg.slice(0, 300), ...(a.replaced ? { replaced: a.replaced } : {}) });
    return { outcome: a.ok ? 'ok' : 'failed' };
  }

  async runRound(step, claude) {
    const ctx = { opts: this.opts, run: this.run, runJson: step.st.runJson };
    this.book.save({ round: this.book.state.round + 1 });
    const taken = new Set();
    const prefix = { hunt: 'h', skeptic: 's', 'record-check': 'v', critic: 'c', recheck: 'r' };
    // Never two tasks for the same unit or fingerprint in one round.
    const seen = new Set();
    const tasks = step.tasks.filter((t) => { const ks = [...(t.units || []).map((u) => `u:${u}`), ...(t.fp ? [`f:${t.fp}`] : [])]; if (ks.some((k) => seen.has(k))) return false; ks.forEach((k) => seen.add(k)); return true; });
    for (const t of tasks) t.id = this.freshId(prefix[t.kind], taken);
    say(`round ${this.book.state.round} (${step.stage}): ${tasks.length} task(s): ${Object.entries(tasks.reduce((m, t) => ({ ...m, [t.kind]: (m[t.kind] || 0) + 1 }), {})).map(([k, n]) => `${n} ${k}`).join(', ')}`);
    const results = [];
    let next = 0; let limited = null;
    const worker = async () => {
      while (next < tasks.length) {
        if (limited || stopping) return;
        const t = tasks[next++];
        const r = await this.runTask(t, ctx, claude);
        results.push(r);
        if (r.outcome === 'limited') limited = r;
      }
    };
    let fatal = null;
    await Promise.all(Array.from({ length: Math.min(this.opts.maxParallel, tasks.length) }, () => worker().catch((e) => { fatal = fatal || e; })));
    if (results.some((r) => r.needsRecover || r.outcome === 'limited')) { const r = rs(['recover', this.run]); if (!r.ok) say(`recover: ${r.err}`); }
    if (fatal) throw fatal;
    const ok = results.filter((r) => r.outcome === 'ok').length;
    this.stats.retries += results.filter((r) => r.outcome === 'failed').length;
    if (limited) return { limited };
    if (!ok && results.some((r) => r.outcome === 'transient')) {
      this.transientRounds++;
      if (this.transientRounds > MAX_TRANSIENT_ROUNDS) throw new Stop(1, `API errors in ${MAX_TRANSIENT_ROUNDS} consecutive rounds; giving up (state is on disk; rerun to continue)`);
      const base = Number(process.env.BSEC_ORCH_BACKOFF_MS) >= 0 && process.env.BSEC_ORCH_BACKOFF_MS !== undefined ? Number(process.env.BSEC_ORCH_BACKOFF_MS) : 30000;
      const wait = base * 2 ** (this.transientRounds - 1);
      say(`transient API errors; backing off ${Math.round(wait / 1000)} s (${this.transientRounds}/${MAX_TRANSIENT_ROUNDS})`);
      await sleep(wait);
    } else if (ok) this.transientRounds = 0;
    return {};
  }

  finishOutputs() {
    const R = this.run;
    if (fs.existsSync(path.join(R, 'findings.json'))) {
      const sc = cp.spawnSync(process.execPath, [path.join(__dirname, 'score.cjs'), R], { encoding: 'utf8', windowsHide: true });
      if (sc.status === 0) { fs.writeFileSync(path.join(this.book.dir, 'score.txt'), sc.stdout); say('score.cjs → orchestrator/score.txt'); } else say(`score.cjs failed: ${(sc.stderr || sc.stdout).trim().split('\n')[0]}`);
      const sa = cp.spawnSync(process.execPath, [path.join(__dirname, 'to-sarif.cjs'), path.join(R, 'findings.json')], { encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
      if (sa.status === 0) { writeAtomic(path.join(R, 'findings.sarif'), sa.stdout); say('to-sarif.cjs → findings.sarif'); } else say(`to-sarif.cjs failed: ${(sa.stderr || sa.stdout).trim().split('\n')[0]}`);
    }
  }

  summary(code, why) {
    const s = this.stats;
    const wall = Math.round((Date.now() - this.t0) / 1000);
    const lines = [`summary: exit ${code}${why ? ` (${why})` : ''}; wall time ${Math.floor(wall / 60)}m${wall % 60}s; ${this.launchedHere} agent(s) launched, ${s.retries} failed attempt(s) retried or parked`];
    for (const [k, n] of Object.entries(s.byRole).sort()) lines.push(`  ${n} × ${k}`);
    const t = s.tokens;
    if (this.launchedHere) {
      lines.push(`  tokens: ${t.input_tokens} input, ${t.cache_read_input_tokens} cache read, ${t.cache_creation_input_tokens} cache write, ${t.output_tokens} output${s.models.size ? `; models reported: ${[...s.models].join(', ')}` : ''}`);
      lines.push(`  cost: ${s.costKnown ? `$${s.cost.toFixed(4)} (CLI estimate, ${s.costKnown} of ${this.launchedHere} sessions reported it)` : 'not reported by the CLI'}; per-agent lines in usage.jsonl`);
    }
    process.stdout.write(lines.join('\n') + '\n');
  }

  async main() {
    const o = this.opts;
    if (!fs.existsSync(path.join(o.run, 'run.json'))) throw new Stop(2, `${o.run} has no run.json`);
    const claude = o.dryRun ? (() => { try { return resolveClaude(o.claude); } catch { return { file: o.claude || 'claude', prefix: [], label: o.claude || 'claude (not found on PATH)' }; } })() : resolveClaude(o.claude);
    if (o.dryRun) return this.dryRun(claude);
    acquireDriverLock(o.run);
    this.book.save({ pid: process.pid, host: os.hostname(), started: now().toISOString(), claude: claude.label });
    say(`orchestrating ${o.run} (claude: ${claude.label}; max-parallel ${o.maxParallel}; until ${o.until})`);
    const rec = rs(['recover', o.run]);
    if (!rec.ok) throw new Stop(3, `recover failed: ${rec.err}`);
    for (;;) {
      if (stopping) throw new Stop(130, 'interrupted');
      const step = this.nextStep();
      if (step.type === 'done') { if (step.final) this.finishOutputs(); say(step.msg); return 0; }
      if (step.type === 'cmd') {
        if (step.label === 'recover') {
          if (this.lastWasRecover) throw new Stop(3, `units stay in_progress after recover (${step.st.inProgress.map((u) => `${u.id}:${u.owner}`).slice(0, 5).join(', ')}); see run-state.cjs status`);
          this.lastWasRecover = true;
        } else this.lastWasRecover = false;
        for (const args of step.multi || [step.args]) {
          const r = rs(args);
          if (!r.ok) throw new Stop(3, `${step.label}: run-state.cjs ${args[0]} failed: ${r.err}`);
          say(`${step.label}${step.why ? ` (${step.why})` : ''}: ${r.out.split('\n')[0]}`);
        }
        continue;
      }
      if (step.type === 'pending') {
        for (const p of step.pend) {
          const task = { kind: p.role, id: p.agent, fp: p.fp, units: p.units, keys: p.fp ? [`${p.role}:${p.fp}`] : [] };
          const a = this.apply(task);
          say(`${this.describe(task)} (waiting output) → ${a.msg}`);
          this.book.attempt({ agent: p.agent, kind: p.role, keys: task.keys, outcome: a.ok ? 'ok' : 'rejected', detail: a.msg.slice(0, 300) });
        }
        continue;
      }
      if (step.type === 'end-incomplete') {
        rs(['assemble', o.run]);
        const r = rs(['incomplete', o.run, step.reason]);
        if (!r.ok) throw new Stop(3, `incomplete failed: ${r.err}`);
        say(`${r.out}`);
        this.finishOutputs();
        return 6;
      }
      if (step.type === 'complete') {
        const r = rs(['complete', o.run]);
        if (!r.ok) throw new Stop(3, `complete refused; a human or the interactive lead must resolve:\n${r.err.replace(/^not complete; unmet conditions:\n?/, '')}`);
        say(r.out.split('\n')[0]);
        this.finishOutputs();
        return 0;
      }
      if (!step.tasks.length) throw new Stop(3, 'nothing to launch and nothing left to apply; see run-state.cjs status');
      this.lastWasRecover = false;
      const res = await this.runRound(step, claude);
      if (res.limited) {
        const reset = res.limited.reset;
        if (o.retryWait === null) throw new Stop(4, `usage limit reached; nothing was recorded as covered that was not.${reset ? ` Resets ${reset.toLocaleString()} (${reset.toISOString()}).` : ' Reset time not reported.'} Rerun the same command after the reset (or pass --retry-wait auto).`);
        let wait = o.retryWait === 'auto' ? (reset ? reset - Date.now() + 60000 : 15 * 60000) : o.retryWait * 1000;
        wait = Math.min(Math.max(wait, 0), MAX_LIMIT_WAIT_MS);
        say(`usage limit: waiting ${Math.round(wait / 60000)} min${reset ? ` until ${reset.toLocaleString()}` : ''}, then continuing`);
        this.book.save({ waiting_until: new Date(Date.now() + wait).toISOString() });
        await sleep(wait);
        this.book.save({ waiting_until: null });
      }
      if (o.once) { say('one round done (--once)'); return 0; }
    }
  }

  dryRun(claude) {
    const o = this.opts;
    say(`dry run of ${o.run} (nothing is changed; claude: ${claude.label})`);
    let step;
    try { step = this.nextStep(); } catch (e) { if (e instanceof Stop) { say(`would stop with exit ${e.code}: ${e.message}`); return e.code; } throw e; }
    if (step.type === 'cmd' && step.label === 'recover') { say(`would run: run-state.cjs recover <run> (${step.why}), then plan again`); return 0; }
    if (step.type === 'done' || step.type === 'complete') { say(step.type === 'complete' ? 'would run: run-state.cjs complete <run>, then score.cjs and to-sarif.cjs' : step.msg); return 0; }
    if (step.type === 'cmd') { for (const a of step.multi || [step.args]) say(`would run: run-state.cjs ${a.map((x) => (x === o.run ? '<run>' : x)).join(' ')}`); return 0; }
    if (step.type === 'pending') { for (const p of step.pend) say(`would apply the waiting ${p.role} output of ${p.agent}`); return 0; }
    if (step.type === 'end-incomplete') { say(`would run: run-state.cjs incomplete <run> ${step.reason}`); return 0; }
    const taken = new Set();
    const prefix = { hunt: 'h', skeptic: 's', 'record-check': 'v', critic: 'c', recheck: 'r' };
    const saved = this.book.state.round;
    this.book.state.round = saved + 1;
    say(`round ${saved + 1} (${step.stage}): ${step.tasks.length} task(s), at most ${o.maxParallel} at once`);
    for (const t of step.tasks) {
      t.id = this.freshId(prefix[t.kind], taken);
      const b = buildArgs(t, { opts: o, run: this.run, runJson: step.st.runJson });
      const pre = t.kind === 'hunt' ? `assign <run> ${t.id} ${t.units.join(' ')}; brief <run> ${t.id} --role hunter` : `brief <run> ${t.id} --role ${t.kind}${t.fp ? ` --fingerprint ${t.fp}` : ''}${t.units ? ` --units ${t.units.join(' ')}` : ''}`;
      process.stdout.write(`  ${this.describe(t)}\n    prepare: run-state.cjs ${pre}\n    cwd: ${b.cwd}\n    argv: ${JSON.stringify([claude.file, ...claude.prefix, ...b.args])}\n`);
    }
    this.book.state.round = saved;
    return 0;
  }
}

let stopping = false;
async function cli(argv) {
  let driver = null;
  let code;
  try {
    const opts = parseArgs(argv);
    driver = new Driver(opts);
    const onSig = () => { if (stopping) return; stopping = true; say('interrupt: stopping launches and killing running agents'); for (const c of running) killTree(c); };
    process.on('SIGINT', onSig); process.on('SIGTERM', onSig);
    code = await driver.main();
    if (stopping) code = 130;
    if (!opts.dryRun) driver.summary(code);
  } catch (e) {
    if (e instanceof Stop) {
      process.stderr.write(`orchestrate: ${e.message}\n`);
      code = e.code;
      if (driver && !driver.opts.dryRun && lockFile) driver.summary(code, e.message.split('\n')[0].slice(0, 160));
    } else { process.stderr.write(`orchestrate: internal error: ${e && e.stack ? e.stack : e}\n`); code = 1; }
  } finally {
    for (const c of running) killTree(c);
    if (driver && lockFile) { try { driver.book.save({ pid: null, ended: now().toISOString(), exit: code }); } catch { /* ignore */ } }
    releaseDriverLock();
  }
  return code;
}

if (require.main === module) cli(process.argv.slice(2)).then((c) => { process.exitCode = c; });
module.exports = { parseArgs, parseReset, buildArgs, childEnv, cmdQuote, resolveClaude, parseSession, usageOf, LIMIT_RE, recheckNeeds, cli };
