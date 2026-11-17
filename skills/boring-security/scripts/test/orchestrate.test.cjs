'use strict';
// orchestrate.cjs against a fake `claude` executable only: no model calls, no quota.
const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');
const orch = require('../orchestrate.cjs');

const ORCH = path.resolve(__dirname, '..', 'orchestrate.cjs');
const RS = path.resolve(__dirname, '..', 'run-state.cjs');
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), `bsec orch ${p}-`));
const readJson = (...p) => JSON.parse(fs.readFileSync(path.join(...p), 'utf8'));
const rs = (...a) => execFileSync(process.execPath, [RS, ...a], { encoding: 'utf8', stdio: 'pipe' });

// ---------- the fake CLI ----------
// Reads the brief path from the prompt, works out the role from brief.json and writes a canned valid
// out/result.json derived from the ledger and the fixture target, so anchors and quotes verify.
const FAKE = String.raw`'use strict';
const fs = require('fs'); const path = require('path');
const env = process.env;
const argv = process.argv.slice(2);
const prompt = argv.find((a) => /^Read .+ completely and follow it\.$/.test(a));
const flag = (n) => { const i = argv.indexOf(n); return i === -1 ? null : argv[i + 1]; };
const brief = prompt ? /^Read (.+) completely and follow it\.$/.exec(prompt)[1] : null;
const agentDir = path.dirname(brief); const id = path.basename(agentDir); const run = path.dirname(path.dirname(agentDir));
const meta = JSON.parse(fs.readFileSync(path.join(agentDir, 'brief.json'), 'utf8'));
const role = meta.role;
const read = (...p) => JSON.parse(fs.readFileSync(path.join(...p), 'utf8'));
const ledger = read(run, 'ledger.json'); const runJson = read(run, 'run.json');
const unitOf = (uid) => ledger.find((u) => u.id === uid);
const lines = (f) => fs.readFileSync(path.join(runJson.target, f), 'utf8').split(/\r?\n/);
if (env.BSEC_FAKE_LOG) fs.appendFileSync(env.BSEC_FAKE_LOG, JSON.stringify({ id, role, fp: meta.fingerprint || null, argv, cwd: process.cwd(), envKeys: Object.keys(env) }) + '\n');
const units = role === 'hunter' ? read(agentDir, 'assignment.json').units : (meta.units || []);
const surfaces = units.map((u) => unitOf(u).refs.surface).join('|');
const finish = (summary, code = 0, isErr = false) => {
  process.stdout.write(JSON.stringify({ type: 'result', subtype: 'success', is_error: isErr, result: summary, session_id: 'fake-' + id, num_turns: 3, duration_ms: 7,
    total_cost_usd: 0.0125, usage: { input_tokens: 1000, output_tokens: 200, cache_read_input_tokens: 800, cache_creation_input_tokens: 100 },
    modelUsage: { [flag('--model') || 'fake-default']: { inputTokens: 1000, outputTokens: 200, costUSD: 0.0125 } } }));
  process.exit(code);
};
function counter(name) { fs.mkdirSync(env.BSEC_FAKE_STATE, { recursive: true }); for (let n = 1; ; n++) { try { fs.writeFileSync(path.join(env.BSEC_FAKE_STATE, name + '-' + n), '', { flag: 'wx' }); return n; } catch { /* taken */ } } }
function main() {
  if (env.BSEC_FAKE_LIMIT_AFTER && counter('call') > Number(env.BSEC_FAKE_LIMIT_AFTER)) finish("You've hit your session limit · resets 3:45pm", 1, true);
  if (env.BSEC_FAKE_FAIL_UNITS && role === 'hunter' && surfaces.includes(env.BSEC_FAKE_FAIL_UNITS)) { process.stderr.write('fake failure\n'); process.exit(1); }
  if (env.BSEC_FAKE_TIMEOUT_ONCE_UNITS && role === 'hunter' && surfaces.includes(env.BSEC_FAKE_TIMEOUT_ONCE_UNITS) && counter('timeout') === 1) { setTimeout(() => {}, 120000); return; }
  const out = path.join(agentDir, 'out', 'result.json');
  if (env.BSEC_FAKE_INVALID_ROLE === role) { fs.writeFileSync(out, '{not json'); finish('wrote garbage'); }
  const write = (v, s) => { fs.writeFileSync(out, JSON.stringify(v, null, 2)); finish(s); };
  if (role === 'hunter') {
    const res = { units: [], candidates: [], hardening: [], uncovered: [] };
    const seen = new Set();
    for (const uid of units) {
      const u = unitOf(uid); const file = u.start_paths[0]; const ls = lines(file);
      const check = { by: id, paths: [file], invariant: 'caller may only read own items', method: 'source', result: 'checked', evidence: null, anchors: [{ file, line: 1, quote: ls[0] }] };
      const m = /#VULN\S*?(?:@(\S+))? (\w+)/.exec(u.refs.surface);
      if (!m) { res.units.push({ id: uid, disposition: 'covered', paths: [file], checks: [check], fingerprints: [], open: [] }); continue; }
      const cf = m[1] || file; const cl = lines(cf); const fp = 'idor:' + cf + ':' + m[2];
      res.units.push({ id: uid, disposition: 'candidate', paths: [file], checks: [check], fingerprints: [fp], open: [] });
      if (seen.has(fp)) continue; seen.add(fp);
      res.candidates.push({ proposed: 'needs_validation', fingerprint: fp, title: 'Item lookup may be unscoped', description: 'findById without owner filter',
        claimed_root_cause: 'findById without owner', trace: [{ step: 'sink', file: cf, line: 2, quote: cl[1].trim(), scope: m[2], note: 'n' }],
        evidence: [{ file: cf, line: 2, quote: cl[1].trim(), note: 'n' }], blockers: ['route middleware not visible'], validation_plan: { local: 'two-tenant unit test' } });
    }
    write(res, id + ': ' + units.length + ' units');
  }
  if (role === 'skeptic') {
    const c = read(run, 'candidates', encodeURIComponent(meta.fingerprint).replace(/\*/g, '%2A') + '.json');
    const { proposed, found_by, carried_by, alternates, ...rest } = c;
    write({ decision: 'needs_validation', record: { verdict: 'needs_validation', ...rest } }, id + ': needs_validation');
  }
  if (role === 'record-check') write({ decision: 'verified', fingerprint: meta.fingerprint }, id + ': verified');
  if (role === 'critic') {
    const prior = fs.existsSync(path.join(run, 'critics')) ? fs.readdirSync(path.join(run, 'critics')).length : 0;
    const missing = env.BSEC_FAKE_CRITIC_PROPOSE && prior === 0 ? [JSON.parse(env.BSEC_FAKE_CRITIC_PROPOSE)] : [];
    write({ missing_units: missing, reopen_ids: [], resolved_prior_leads: [], stop: !missing.length }, id + ': ' + missing.length + ' missing');
  }
  if (role === 'recheck') {
    const prior = fs.existsSync(path.join(run, 'recheck', 'results')) ? fs.readdirSync(path.join(run, 'recheck', 'results')).length : 0;
    write({ units: units.map((uid, i) => { const f = unitOf(uid).start_paths[0];
      const agree = !(env.BSEC_FAKE_RECHECK_DISAGREE && prior === 0 && i === 0);
      return { id: uid, agree, why: agree ? 'guard enforced' : 'no guard found', anchors: [{ file: f, line: 1, quote: lines(f)[0] }] }; }) }, id + ': rechecked');
  }
  finish('unknown role', 1, true);
}
const delay = Number(env.BSEC_FAKE_SLEEP_MS || 0);
if (delay) setTimeout(main, delay); else main();
`;
const fakeDir = tmp('fake');
const FAKE_PATH = path.join(fakeDir, 'fake-claude.cjs');
fs.writeFileSync(FAKE_PATH, FAKE);
const PASS = 'BSEC_FAKE_LOG,BSEC_FAKE_STATE,BSEC_FAKE_FAIL_UNITS,BSEC_FAKE_LIMIT_AFTER,BSEC_FAKE_TIMEOUT_ONCE_UNITS,BSEC_FAKE_INVALID_ROLE,BSEC_FAKE_SLEEP_MS,BSEC_FAKE_CRITIC_PROPOSE,BSEC_FAKE_RECHECK_DISAGREE';

// ---------- fixture ----------
const FILES = { 'src/a.js': 'getA', 'src/b.js': 'getB', 'lib/c.js': 'getC', 'pkg/d.js': 'getD' };
function seed(surface, file, { cls = 'core-classes.md#Access control', subsystem = 'profile/quick/all', priority = 1 } = {}) {
  const fn = FILES[file];
  return { refs: { surface, boundary: `${file}#${fn}`, subsystem, class: cls }, labels: { surface, boundary: fn, subsystem, class: cls.split('#')[1] },
    start_paths: [file], class_block: cls, pack_blocks: [], skipped_blocks: [], prior: 'none', notes: { priority, priority_why: 'test' } };
}
function setup({ profile = 'quick', seeds, budget = null, trust = 'own', inventory = false }) {
  const target = tmp('target');
  for (const [f, fn] of Object.entries(FILES)) {
    fs.mkdirSync(path.join(target, path.dirname(f)), { recursive: true });
    fs.writeFileSync(path.join(target, f), `export function ${fn}(req) {\n  return db.items.findById(req.params.id);\n}\n`);
  }
  const run = tmp('run');
  fs.writeFileSync(path.join(run, 'run.json'), JSON.stringify({ run_id: 'run-1', repo: 'fixture', target, source_ref: { commit: 'x', dirty: false }, profile,
    scope: { kind: 'full', paths: [], pack: null, diff: null }, budget_agents: budget, execution: 'source-only', trust, advisories: 'not_checked',
    packs: [], prior_runs: [], status: 'in_progress', incomplete_reason: null }, null, 2));
  const sf = path.join(run, 'seeds.json');
  fs.writeFileSync(sf, JSON.stringify(seeds));
  rs('add-units', run, sf);
  fs.unlinkSync(sf);
  if (inventory) fs.writeFileSync(path.join(run, 'inventory.json'), JSON.stringify({ surfaces: Object.keys(FILES).map((f, i) => ({ id: `s${i}`, kind: 'route', file: f, line: 1, label: f })) }));
  const state = tmp('state');
  return { run, target, log: path.join(state, 'log.jsonl'), state };
}
function envFor(fx, extra = {}) {
  return { ...process.env, BSEC_ORCH_PASS_ENV: PASS, BSEC_TEST_SECRET: 'do-not-leak', BSEC_FAKE_LOG: fx.log, BSEC_FAKE_STATE: fx.state, BSEC_ORCH_BACKOFF_MS: '0', ...extra };
}
async function drive(fx, args = [], extra = {}) {
  const r = await runNode([ORCH, fx.run, '--claude', FAKE_PATH, ...args], envFor(fx, extra));
  return { code: r.status, out: r.stdout, err: r.stderr, all: `${r.stdout}\n${r.stderr}` };
}
const logOf = (fx) => (fs.existsSync(fx.log) ? fs.readFileSync(fx.log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const ledgerById = (fx) => Object.fromEntries(readJson(fx.run, 'ledger.json').map((u) => [u.surface || u.refs.surface, u]));
const attempts = (fx) => fs.readFileSync(path.join(fx.run, 'orchestrator', 'attempts.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

function runNode(args, env) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stderr += d; });
    const t = setTimeout(() => c.kill(), 90000);
    c.on('close', (status) => { clearTimeout(t); resolve({ status, stdout, stderr }); });
  });
}

// ---------- tests (independent fixtures, run concurrently) ----------
describe('orchestrate.cjs with a fake claude CLI', { concurrency: 4 }, () => {
it('quick profile: seeded run driven to complete; one Skeptic per fingerprint; no secrets passed', async () => {
  const fx = setup({ seeds: [seed('src/a.js#VULN getA', 'src/a.js'), seed('src/b.js#GET /b', 'src/b.js'), seed('lib/c.js#VULN@src/a.js getA', 'lib/c.js')] });
  const r = await drive(fx, ['--model-strong', 'fake-strong']);
  assert.strictEqual(r.code, 0, r.all);
  assert.strictEqual(readJson(fx.run, 'run.json').status, 'complete');
  const f = readJson(fx.run, 'findings.json');
  assert.deepStrictEqual(f.map((x) => x.fingerprint), ['idor:src/a.js:getA']);
  assert.ok(fs.existsSync(path.join(fx.run, 'findings.sarif')));
  assert.ok(fs.existsSync(path.join(fx.run, 'orchestrator', 'score.txt')));
  const log = logOf(fx);
  assert.strictEqual(log.filter((l) => l.role === 'hunter').length, 2, 'two hunter groups (src, lib)');
  assert.strictEqual(log.filter((l) => l.role === 'skeptic').length, 1, 'one skeptic for the shared fingerprint');
  assert.strictEqual(log.filter((l) => l.role === 'critic').length, 1);
  const h = log.find((l) => l.role === 'hunter');
  assert.deepStrictEqual(h.argv.slice(0, 2), ['-p', `Read ${path.join(fx.run, 'agents', h.id, 'brief.md')} completely and follow it.`]);
  assert.strictEqual(h.argv[h.argv.indexOf('--agent') + 1], 'boring-security:bsec-hunter');
  assert.strictEqual(h.argv[h.argv.indexOf('--model') + 1], 'fake-strong');
  assert.strictEqual(h.argv[h.argv.indexOf('--permission-mode') + 1], 'dontAsk');
  assert.strictEqual(h.argv[h.argv.indexOf('--add-dir') + 1], path.join(fx.run, 'agents', h.id));
  assert.strictEqual(fs.realpathSync(h.cwd), fs.realpathSync(fx.target), 'own trust: rooted in the target');
  assert.ok(!h.envKeys.includes('BSEC_TEST_SECRET'), 'parent secrets are not passed');
  assert.ok(fs.existsSync(path.join(fx.run, 'agents', h.id, 'session.json')));
  const usage = fs.readFileSync(path.join(fx.run, 'usage.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.strictEqual(usage.length, log.length);
  assert.ok(usage.every((u) => u.cost_usd === 0.0125 && u.input_tokens === 1000));
  assert.match(r.out, /hunt h-\d+-\d+ units=\d+ tier=high → ingested: /);
  assert.match(r.out, /cost: \$0\.0500/);
  // A second run on a complete directory is a no-op.
  const again = await drive(fx);
  assert.strictEqual(again.code, 0, again.all);
  assert.strictEqual(logOf(fx).length, log.length);
});

it('standard profile: critic loop, lite tier, recheck with a disagreement, verifications, complete', async () => {
  const fx = setup({ profile: 'standard', inventory: true, seeds: [
    seed('src/a.js#VULN getA', 'src/a.js', { subsystem: 'api' }),
    seed('src/b.js#GET /b', 'src/b.js', { subsystem: 'api', cls: 'core-classes.md#Files, fetches and parsing', priority: 5 }),
    seed('lib/c.js#GET /c', 'lib/c.js', { subsystem: 'lib' }),
    seed('pkg/d.js#GET /d', 'pkg/d.js', { subsystem: 'pkg' }),
  ] });
  assert.match(rs('tier', fx.run), /1 standard/);
  const propose = JSON.stringify({ surface: 'src/b.js#POST /b', boundary: 'src/b.js#getB', subsystem: 'api', class: 'core-classes.md#Access control', start_paths: ['src/b.js'], why: 'POST handler in src/b.js has no unit' });
  const r = await drive(fx, ['--model-lite', 'fake-lite', '--max-parallel', '3'], { BSEC_FAKE_CRITIC_PROPOSE: propose, BSEC_FAKE_RECHECK_DISAGREE: '1' });
  assert.strictEqual(r.code, 0, r.all);
  assert.strictEqual(readJson(fx.run, 'run.json').status, 'complete');
  const critics = fs.readdirSync(path.join(fx.run, 'critics')).map((f) => readJson(fx.run, 'critics', f)).sort((a, b) => a.seq - b.seq);
  assert.ok(critics.length >= 3, 'not-clean critic, then two clean ones');
  assert.strictEqual(critics[0].clean, false);
  assert.ok(critics.slice(-2).every((c) => c.clean) && critics.at(-1).critic !== critics.at(-2).critic);
  assert.ok(Object.keys(ledgerById(fx)).includes('src/b.js#POST /b'), 'critic proposal hunted');
  const log = logOf(fx);
  const lite = log.filter((l) => l.role === 'hunter' && l.argv.includes('boring-security:bsec-hunter-lite'));
  assert.ok(lite.length >= 1 && lite.every((l) => l.argv[l.argv.indexOf('--model') + 1] === 'fake-lite'));
  assert.ok(log.filter((l) => l.role === 'record-check').every((l) => l.argv.includes('boring-security:bsec-record-check')));
  assert.ok(log.some((l) => l.role === 'recheck'));
  assert.ok(fs.existsSync(path.join(fx.run, 'verifications', `${encodeURIComponent('idor:src/a.js:getA')}.json`)));
  assert.ok(Object.values(ledgerById(fx)).some((u) => u.history.some((h) => /recheck/.test(h.reopen_reason || ''))), 'disagreement reopened a unit');
  const skeptics = log.filter((l) => l.role === 'skeptic').map((l) => l.fp);
  assert.strictEqual(new Set(skeptics).size, skeptics.length, 'never two skeptics for one fingerprint');
});

it('retries a failing hunter with fresh ids, then defers its units; a hung agent is killed and retried', async () => {
  const fx = setup({ seeds: [seed('src/a.js#GET /a', 'src/a.js'), seed('lib/c.js#FLAKY c', 'lib/c.js')] });
  const r = await drive(fx, ['--task-timeout', '4'], { BSEC_FAKE_FAIL_UNITS: 'FLAKY', BSEC_FAKE_TIMEOUT_ONCE_UNITS: 'GET /a' });
  assert.strictEqual(r.code, 0, r.all);
  const led = ledgerById(fx);
  assert.strictEqual(led['lib/c.js#FLAKY c'].status, 'deferred');
  assert.deepStrictEqual(led['lib/c.js#FLAKY c'].open, ['orchestrator_retries_exhausted']);
  assert.strictEqual(led['src/a.js#GET /a'].status, 'covered');
  const a = attempts(fx);
  const flaky = a.filter((x) => x.kind === 'hunt' && x.outcome !== 'ok' && x.counts !== false && x.keys.some((k) => k.startsWith(`unit:${led['lib/c.js#FLAKY c'].id}@`)));
  assert.strictEqual(flaky.length, 3, JSON.stringify(a, null, 1) + r.out);
  assert.strictEqual(new Set(flaky.map((x) => x.agent)).size, 3, 'fresh agent id per attempt');
  assert.ok(a.some((x) => x.outcome === 'timeout'));
  assert.match(r.out, /timed out after 4s/);
  assert.strictEqual(readJson(fx.run, 'run.json').status, 'complete');
});

it('usage limit: stops with exit 4 and the reset time, records nothing false, second invocation completes', async () => {
  const fx = setup({ seeds: [seed('src/a.js#GET /a', 'src/a.js'), seed('lib/c.js#GET /c', 'lib/c.js')] });
  const r = await drive(fx, ['--max-parallel', '1'], { BSEC_FAKE_LIMIT_AFTER: '1' });
  assert.strictEqual(r.code, 4, r.all);
  assert.match(r.err, /usage limit reached/);
  assert.match(r.all, /resets/);
  const led = Object.values(ledgerById(fx));
  assert.deepStrictEqual(led.map((u) => u.status).sort(), ['covered', 'planned'], 'limited unit back to planned, not covered');
  assert.ok(attempts(fx).some((x) => x.outcome === 'limited' && x.counts === false));
  assert.ok(!fs.existsSync(path.join(fx.run, 'orchestrator', 'driver.lock')), 'lock released');
  const r2 = await drive(fx);
  assert.strictEqual(r2.code, 0, r2.all);
  assert.strictEqual(readJson(fx.run, 'run.json').status, 'complete');
});

it('a second driver on the same run is refused; a stale lock is taken over', async () => {
  const fx = setup({ seeds: [seed('src/a.js#GET /a', 'src/a.js')] });
  const child = spawn(process.execPath, [ORCH, fx.run, '--claude', FAKE_PATH], { env: envFor(fx, { BSEC_FAKE_SLEEP_MS: '2500' }), stdio: 'ignore' });
  const exited = new Promise((res) => child.on('exit', res));
  const lock = path.join(fx.run, 'orchestrator', 'driver.lock');
  for (let i = 0; i < 200 && !fs.existsSync(lock); i++) await new Promise((res) => setTimeout(res, 25));
  assert.ok(fs.existsSync(lock));
  const second = await drive(fx);
  assert.strictEqual(second.code, 5, second.all);
  assert.match(second.err, /another orchestrator/);
  assert.strictEqual(await exited, 0);
  fs.writeFileSync(lock, JSON.stringify({ pid: 2147483000, host: os.hostname(), at: new Date().toISOString() }));
  const third = await drive(fx);
  assert.strictEqual(third.code, 0, third.all);
  assert.match(third.out, /taking over stale driver lock/);
});

it('--dry-run prints the plan and exact argv and changes nothing', async () => {
  const fx = setup({ trust: 'untrusted', seeds: [seed('src/a.js#GET /a', 'src/a.js'), seed('lib/c.js#GET /c', 'lib/c.js')] });
  const snap = () => {
    const out = [];
    (function walk(d, rel) { for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const p = path.join(d, e.name); const r = `${rel}/${e.name}`;
      if (e.isDirectory()) { out.push(r + '/'); walk(p, r); } else out.push(`${r}:${crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')}`);
    } })(fx.run, '');
    return out.join('\n');
  };
  const before = snap();
  const r = await drive(fx, ['--dry-run']);
  assert.strictEqual(r.code, 0, r.all);
  assert.strictEqual(snap(), before);
  assert.match(r.out, /round 1 \(hunt\): 2 task\(s\)/);
  const argvLines = r.out.split('\n').filter((l) => l.trim().startsWith('argv: ')).map((l) => JSON.parse(l.trim().slice(6)));
  assert.strictEqual(argvLines.length, 2);
  assert.ok(argvLines[0].includes('--agent') && argvLines[0].includes('boring-security:bsec-hunter'));
  assert.ok(argvLines[0].includes(fx.target), 'untrusted: target added as a read directory');
  assert.match(r.out, new RegExp(`cwd: ${path.join(fx.run, 'agents', 'h-1-1').replace(/[\\.]/g, '\\$&')}`), 'untrusted: rooted in the agent dir');
  assert.strictEqual(logOf(fx).length, 0, 'nothing spawned');
});

it('budget cap: reserves critics and validation, defers the rest with budget_reserve, ends incomplete', async () => {
  const fx = setup({ budget: 3, seeds: [seed('src/a.js#VULN getA', 'src/a.js'), seed('lib/c.js#GET /c', 'lib/c.js', { priority: 2 }), seed('pkg/d.js#GET /d', 'pkg/d.js', { priority: 2 })] });
  const r = await drive(fx);
  assert.strictEqual(r.code, 6, r.all);
  const rj = readJson(fx.run, 'run.json');
  assert.strictEqual(rj.status, 'incomplete');
  assert.strictEqual(rj.incomplete_reason, 'stopped_early');
  assert.ok(fs.readdirSync(path.join(fx.run, 'agents')).length <= 3, 'never more agents than the budget');
  const deferred = Object.values(ledgerById(fx)).filter((u) => u.status === 'deferred');
  assert.ok(deferred.length >= 1 && deferred.every((u) => u.open[0] === 'budget_reserve'));
  assert.strictEqual(logOf(fx).filter((l) => l.role === 'skeptic').length, 1, `existing candidate validated\n${r.out}`);
});

it('invalid Skeptic output: three fresh attempts, then stop with exit 3 for a human', async () => {
  const fx = setup({ seeds: [seed('src/a.js#VULN getA', 'src/a.js')] });
  const r = await drive(fx, [], { BSEC_FAKE_INVALID_ROLE: 'skeptic' });
  assert.strictEqual(r.code, 3, r.all);
  assert.match(r.err, /Skeptic for idor:src\/a\.js:getA failed 3 times/);
  assert.strictEqual(logOf(fx).filter((l) => l.role === 'skeptic').length, 3);
  assert.strictEqual(readJson(fx.run, 'run.json').status, 'in_progress');
});

it('unit: reset-time parsing, env filtering, argv, cmd quoting', async () => {
  const ref = new Date(2026, 10, 16, 14, 0, 0); // Mon 16 Nov 2026 14:00 local
  assert.strictEqual(orch.parseReset("You've hit your session limit · resets 3:45pm", ref).getTime(), new Date(2026, 10, 16, 15, 45).getTime());
  assert.strictEqual(orch.parseReset('resets 9am (Europe/London)', ref).getTime(), new Date(2026, 10, 17, 9, 0).getTime());
  assert.strictEqual(orch.parseReset("You've hit your weekly limit · resets Mon 12:00am", ref).getTime(), new Date(2026, 10, 23, 0, 0).getTime());
  assert.strictEqual(orch.parseReset('spend limit reached · resets Dec 1', ref).getTime(), new Date(2026, 11, 1).getTime());
  assert.strictEqual(orch.parseReset('Claude AI usage limit reached|1800000000', ref).getTime(), 1800000000000);
  assert.strictEqual(orch.parseReset('API Error: overloaded', ref), null);
  assert.ok(orch.LIMIT_RE.test("You've hit your Opus limit · resets 3:45pm"));
  assert.ok(!orch.LIMIT_RE.test('API Error: Server is temporarily limiting requests (not your usage limit)'));
  const e = orch.childEnv({ PATH: '/bin', GITHUB_TOKEN: 'x', ANTHROPIC_API_KEY: 'k', AWS_SECRET_ACCESS_KEY: 'a', NPM_TOKEN: 'n', BSEC_ORCH_PASS_ENV: 'EXTRA', EXTRA: '1' });
  assert.deepStrictEqual(Object.keys(e).sort(), ['ANTHROPIC_API_KEY', 'EXTRA', 'PATH']);
  assert.ok('AWS_SECRET_ACCESS_KEY' in orch.childEnv({ CLAUDE_CODE_USE_BEDROCK: '1', AWS_SECRET_ACCESS_KEY: 'a' }), 'Bedrock credentials only when Bedrock is selected');
  const ctx = { opts: orch.parseArgs(['/r', '--agent-mode', 'none']), run: path.resolve('/r'), runJson: { target: '/t', trust: 'untrusted' } };
  const b = orch.buildArgs({ kind: 'skeptic', id: 's-1-1', fp: 'x' }, ctx);
  assert.ok(b.args.includes('--tools') && !b.args.includes('--agent'));
  assert.strictEqual(b.cwd, path.join(path.resolve('/r'), 'agents', 's-1-1'));
  assert.strictEqual(orch.cmdQuote('a b&c'), '^^^"a^^^ b^^^&c^^^"');
  assert.throws(() => orch.parseArgs(['/r', '--until', 'nope']));
});
});
