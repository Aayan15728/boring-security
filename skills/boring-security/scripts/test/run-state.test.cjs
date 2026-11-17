'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync, spawn } = require('child_process');
const { deriveId, validateLedger } = require('../check-ledger.cjs');
const { Reporter, sha256, canonicalJson } = require('../lib.cjs');
const { verifyQuotes } = require('../check-findings.cjs');

const RS = path.resolve(__dirname, '..', 'run-state.cjs');
// Directory names with spaces on purpose: Windows paths like "C:\Users\First Last\..." must work.
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), `bsec rs ${p}-`));
const rs = (...a) => execFileSync(process.execPath, [RS, ...a], { encoding: 'utf8', stdio: 'pipe' });
const rsFail = (...a) => assert.throws(() => rs(...a));
// Run expecting failure; returns stderr+stdout for message assertions.
const rsErr = (...a) => { const r = spawnSync(process.execPath, [RS, ...a], { encoding: 'utf8' }); assert.notStrictEqual(r.status, 0, `expected failure: ${a.join(' ')}\n${r.stdout}`); return r.stderr + r.stdout; };
const readJson = (...p) => JSON.parse(fs.readFileSync(path.join(...p), 'utf8'));
const writeJson = (file, v) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(v)); return file; };

function unit(surface, start = 'src/orders.ts') {
  const refs = { surface, boundary: 'src/auth.ts#requireUser', subsystem: 'api', class: 'core-classes.md#Access control' };
  return { id: deriveId(refs), refs, labels: { surface, boundary: 'guard', subsystem: 'API', class: 'Access control' },
    start_paths: [start], class_block: 'core-classes.md#Access control', pack_blocks: [], skipped_blocks: [],
    prior: 'none', wave: 1, status: 'planned', owner: null, paths: [], checks: [], fingerprints: [], open: [], history: [] };
}

function setup({ profile = 'deep', surfaces = ['src/orders.ts#GET /orders/:id', 'src/orders.ts#GET /orders'] } = {}) {
  const target = tmp('target');
  fs.mkdirSync(path.join(target, 'src'));
  fs.writeFileSync(path.join(target, 'src', 'orders.ts'), 'export async function getOrder(id) {\r\n  return db.orders.findById(id);\r\n}\r\n');
  fs.writeFileSync(path.join(target, 'src', 'auth.ts'), 'export function requireUser(req) {\n  if (!req.user) throw new Error("401");\n}\n');
  const run = tmp('run');
  const ledger = surfaces.map((s) => unit(s)).sort((a, b) => (a.id < b.id ? -1 : 1));
  fs.writeFileSync(path.join(run, 'run.json'), JSON.stringify({ run_id: 'run-1', repo: 'x', target, source_ref: {}, profile, scope: { kind: 'full' }, execution: 'source-only', status: 'in_progress', incomplete_reason: null }));
  fs.writeFileSync(path.join(run, 'ledger.json'), JSON.stringify(ledger, null, 2).replace(/\n/g, '\r\n')); // CRLF on purpose
  return { target, run, ids: ledger.map((u) => u.id) };
}
const anchor = { file: 'src/orders.ts', line: 2, quote: 'return db.orders.findById(id);' };
const chk = (by = 'hunter-1', extra = {}) => ({ by, paths: ['src/orders.ts'], invariant: 'owner scope', method: 'source', result: 'no owner filter', evidence: null, anchors: [anchor], ...extra });
const check = chk();
const fp = 'idor:src/orders.ts:getOrder';
const record = (fingerprint = fp) => ({
  verdict: 'needs_validation', fingerprint, title: 'Order lookup may be unscoped', description: 'd', claimed_root_cause: 'findById without owner',
  trace: [{ step: 'sink', file: 'src/orders.ts', line: 2, quote: 'return db.orders.findById(id);', scope: 'getOrder', note: 'n' }],
  evidence: [{ file: 'src/orders.ts', line: 2, quote: 'db.orders.findById(id)', note: 'n' }],
  blockers: ['route middleware not visible'], validation_plan: { local: 'two-tenant test' },
});
const cand = (fingerprint = fp) => { const { verdict, ...r } = record(fingerprint); return { proposed: verdict, ...r }; };
const candUnit = (id, by = 'hunter-1') => ({ id, disposition: 'candidate', paths: ['src/orders.ts'], checks: [chk(by)], fingerprints: [fp], open: [] });
const coveredUnit = (id, by = 'hunter-1', a = [anchor]) => ({ id, disposition: 'covered', paths: ['src/orders.ts'], checks: [chk(by, { anchors: a })], fingerprints: [], open: [] });
const outFile = (run, agent) => path.join(run, 'agents', agent, 'out', 'result.json');

test('estimate reports agents and token range', () => {
  const { target } = setup();
  const out = rs('estimate', target, '--profile', 'deep');
  assert.match(out, /agents/); assert.match(out, /tokens processed: ~\S+-\S+/);
});

test('assign → ingest → decide → assemble, with independence enforced', () => {
  const { run, ids } = setup();
  assert.match(rs('assign', run, 'hunter-1', ...ids), /assigned 2/);
  for (const d of ['scratch', 'evidence', 'out']) assert.ok(fs.existsSync(path.join(run, 'agents', 'hunter-1', d)), d);
  rsFail('assign', run, 'hunter-1', ids[0]); // reused agent id
  const result = { units: [candUnit(ids[0]), coveredUnit(ids[1])],
    candidates: [cand()], hardening: ['add an index'], uncovered: [{ surface: 'x', boundary: 'y', subsystem: 'z', class: 'c', start_paths: ['src/x.ts'], why: 'w' }] };
  const resFile = path.join(tmp('res'), 'result.json');
  fs.writeFileSync(resFile, JSON.stringify(result));
  assert.match(rs('ingest', run, 'hunter-1', resFile), /2 unit\(s\), 1 new candidate/);
  const ledger = readJson(run, 'ledger.json');
  assert.deepStrictEqual(ledger.map((u) => u.status).sort(), ['candidate', 'covered']);
  assert.ok(fs.existsSync(path.join(run, 'queue', 'uncovered.jsonl')));
  assert.deepStrictEqual(readJson(run, 'candidates', `${encodeURIComponent(fp)}.json`).found_by, ['hunter-1']);
  assert.match(rs('status', run), /awaiting skeptic 1/);

  const dec = path.join(tmp('dec'), 'd.json');
  fs.writeFileSync(dec, JSON.stringify({ decision: 'needs_validation', record: record() }));
  rsFail('decide', run, 'hunter-1', dec); // the finder can't validate its own candidate
  assert.match(rs('decide', run, 'skeptic-1', dec), /stored needs_validation/);
  rsFail('decide', run, 'skeptic-1', dec); // same verifier twice
  assert.match(rs('assemble', run), /1 record/);
  assert.strictEqual(readJson(run, 'findings.json')[0].fingerprint, fp);
});

test('assemble rejects a made-up quote', () => {
  const { run, ids } = setup();
  rs('assign', run, 'hunter-1', ids[0]);
  const f = path.join(tmp('r'), 'r.json');
  fs.writeFileSync(f, JSON.stringify({ units: [candUnit(ids[0])], candidates: [cand()] }));
  rs('ingest', run, 'hunter-1', f);
  const bad = record(); bad.trace[0].quote = 'return everything_without_checks();';
  const dec = path.join(tmp('d'), 'd.json');
  fs.writeFileSync(dec, JSON.stringify({ decision: 'needs_validation', record: bad }));
  rs('decide', run, 'skeptic-1', dec);
  rsFail('assemble', run);
  assert.ok(!fs.existsSync(path.join(run, 'findings.json')), 'nothing written on failure');
});

test('malformed result returns units to planned and keeps the ledger valid', () => {
  const { run, ids } = setup();
  rs('assign', run, 'hunter-1', ...ids);
  const f = path.join(tmp('m'), 'r.json');
  fs.writeFileSync(f, '{"units": [{"id": "' + ids[0] + '", "disposition": "covered", "checks": [{"by": "COM1"}]}]}');
  const out = rs('ingest', run, 'hunter-1', f);
  assert.match(out, /invalid check/); assert.match(out, /missing from result/);
  const ledger = readJson(run, 'ledger.json');
  assert.ok(ledger.every((u) => u.status === 'planned' && u.owner === null));
  const r = new Reporter(); validateLedger(ledger, r, { runDir: run, checkFiles: true, checkBlocks: true }); assert.deepStrictEqual(r.errors, []);
});

test('recover: ingests saved results and out/ results, frees lost agents, removes nested partial writes', () => {
  const { run, ids } = setup({ surfaces: ['src/orders.ts#A', 'src/orders.ts#B', 'src/orders.ts#C'] });
  rs('assign', run, 'hunter-1', ids[0]);
  rs('assign', run, 'hunter-2', ids[1]);
  rs('assign', run, 'hunter-4', ids[2]);
  // hunter-1 finished but the session crashed before ingest; hunter-4 wrote out/result.json; hunter-2 never returned.
  fs.writeFileSync(path.join(run, 'agents', 'hunter-1', 'result.json'), JSON.stringify({ units: [coveredUnit(ids[0])], candidates: [] }));
  writeJson(outFile(run, 'hunter-4'), { units: [coveredUnit(ids[2], 'hunter-4')], candidates: [] });
  fs.writeFileSync(path.join(run, 'ledger.json.tmp-999'), 'partial');
  fs.mkdirSync(path.join(run, 'decisions'));
  fs.writeFileSync(path.join(run, 'decisions', 'x.json.tmp-12'), 'partial');
  fs.writeFileSync(path.join(run, 'agents', 'hunter-2', 'scratch', 'keep.tmp-5'), 'agent-owned');
  const out = rs('recover', run);
  assert.match(out, /removed partial write ledger\.json\.tmp-999/); assert.match(out, /removed partial write decisions\/x\.json\.tmp-12/);
  assert.ok(fs.existsSync(path.join(run, 'agents', 'hunter-2', 'scratch', 'keep.tmp-5')), 'scratch is agent-owned and left alone');
  assert.match(out, /ingested hunter-1/); assert.match(out, /ingested hunter-4/); assert.match(out, /1 unit\(s\) from lost agents/);
  const by = Object.fromEntries(readJson(run, 'ledger.json').map((u) => [u.id, u]));
  assert.strictEqual(by[ids[0]].status, 'covered');
  assert.strictEqual(by[ids[2]].status, 'covered');
  assert.strictEqual(by[ids[1]].status, 'planned');
  rsFail('assign', run, 'hunter-2', ids[1]); // lost agent id is never reused
  assert.match(rs('assign', run, 'hunter-3', ids[1]), /assigned 1/);
  assert.ok(fs.readFileSync(path.join(run, 'journal.jsonl'), 'utf8').includes('"cmd":"recover"'));
});

test('verifyQuotes refuses files outside the target', () => {
  const { target } = setup();
  const r = new Reporter();
  const rec = record(); rec.trace[0].file = '../outside.txt';
  verifyQuotes([rec], target, r);
  assert.match(r.errors.join(), /not found as a regular file inside the target/);
});

test('dollar estimate: caching lowers input cost, output is unchanged', () => {
  const { dollars } = require('../run-state.cjs');
  const d = dollars(10e6, 1e6, 4, 20, 0.85);
  assert.strictEqual(Math.round(d.uncached), 60);                    // 10M x $4 + 1M x $20
  assert.strictEqual(Math.round(d.cached), Math.round(10 * 4 * (0.85 * 0.1 + 0.15 * 1.25) + 20)); // = $30.9
  const { target } = setup();
  assert.match(rs('estimate', target, '--price-in', '4', '--price-out', '20'), /cost at \$4\/M in, \$20\/M out: ~\$\d+-\$\d+ with 85% cache hits/);
});

// ---------- lock ----------
function runAsync(args) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [RS, ...args]);
    let out = ''; p.stdout.on('data', (d) => { out += d; }); p.stderr.on('data', (d) => { out += d; });
    p.on('close', (code) => resolve({ code, out }));
  });
}

test('lock: two concurrent ingests of different agents both apply', async () => {
  const surfaces = Array.from({ length: 8 }, (_, i) => `src/orders.ts#R${i}`);
  const { run, ids } = setup({ surfaces });
  const half = ids.length / 2;
  rs('assign', run, 'hunter-a', ...ids.slice(0, half));
  rs('assign', run, 'hunter-b', ...ids.slice(half));
  writeJson(outFile(run, 'hunter-a'), { units: ids.slice(0, half).map((id) => coveredUnit(id, 'hunter-a')), candidates: [] });
  writeJson(outFile(run, 'hunter-b'), { units: ids.slice(half).map((id) => coveredUnit(id, 'hunter-b')), candidates: [] });
  const [a, b] = await Promise.all([runAsync(['ingest', run, 'hunter-a']), runAsync(['ingest', run, 'hunter-b'])]);
  assert.strictEqual(a.code, 0, a.out); assert.strictEqual(b.code, 0, b.out);
  const ledger = readJson(run, 'ledger.json');
  assert.ok(ledger.every((u) => u.status === 'covered'), JSON.stringify(ledger.map((u) => u.status)));
  assert.ok(!fs.existsSync(path.join(run, '.lock')), 'lock released');
});

test('lock: a live lock blocks, a stale lock of a dead pid is stolen, die() releases', () => {
  const { run, ids } = setup();
  rs('assign', run, 'hunter-1', ids[0]);
  writeJson(outFile(run, 'hunter-1'), { units: [coveredUnit(ids[0])], candidates: [] });
  const lock = path.join(run, '.lock');
  fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
  const r = spawnSync(process.execPath, [RS, 'ingest', run, 'hunter-1'], { encoding: 'utf8', env: { ...process.env, BSEC_LOCK_WAIT_MS: '300' } });
  assert.notStrictEqual(r.status, 0); assert.match(r.stderr, /locked by pid/);
  const dead = spawnSync(process.execPath, ['-e', '']).pid;
  fs.writeFileSync(lock, JSON.stringify({ pid: dead, at: new Date(Date.now() - 10 * 60e3).toISOString() }));
  assert.match(rs('ingest', run, 'hunter-1'), /ingested hunter-1: 1 unit/);
  assert.ok(!fs.existsSync(lock));
  rsErr('assign', run, 'hunter-1', ids[1]); // dies inside the lock
  assert.ok(!fs.existsSync(lock), 'lock released on die()');
});

// ---------- ingest hardening ----------
test('ingest: validates the agent id and defaults to out/result.json', () => {
  const { run, ids } = setup();
  assert.match(rsErr('ingest', run, '../evil'), /bad agent id/);
  assert.match(rsErr('ingest', run, 'nul'), /bad agent id/);
  rs('assign', run, 'hunter-1', ids[0]);
  assert.match(rsErr('ingest', run, 'hunter-1'), /missing/);
  writeJson(outFile(run, 'hunter-1'), { units: [coveredUnit(ids[0])], candidates: [] });
  assert.match(rs('ingest', run, 'hunter-1'), /1 unit\(s\)/);
  assert.ok(fs.existsSync(path.join(run, 'agents', 'hunter-1', 'result.json')), 'raw result stored');
});

test('ingest: anchors are verified against the target; unanchored or wrong coverage returns to planned', () => {
  const { run, ids } = setup({ surfaces: ['src/orders.ts#A', 'src/orders.ts#B', 'src/orders.ts#C'] });
  rs('assign', run, 'hunter-1', ...ids);
  const noAnchor = coveredUnit(ids[0]); delete noAnchor.checks[0].anchors;
  const wrong = coveredUnit(ids[1], 'hunter-1', [{ file: 'src/orders.ts', line: 2, quote: 'if (user.isOwner(order)) return order;' }]);
  const foreign = coveredUnit(ids[2], 'other-agent');
  const out = rs('ingest', run, 'hunter-1', writeJson(path.join(tmp('a'), 'r.json'), { units: [noAnchor, wrong, foreign], candidates: [] }));
  assert.match(out, /anchors/); assert.match(out, /anchor quote not found/); assert.match(out, /is not hunter-1/);
  assert.ok(readJson(run, 'ledger.json').every((u) => u.status === 'planned'));
});

test('candidates: every finder is recorded, alternates kept, finders cannot validate, orphan candidate units reset', () => {
  const { run, ids } = setup({ surfaces: ['src/orders.ts#A', 'src/orders.ts#B', 'src/orders.ts#C'] });
  rs('assign', run, 'hunter-1', ids[0]);
  rs('assign', run, 'hunter-2', ids[1]);
  rs('assign', run, 'hunter-3', ids[2]);
  rs('ingest', run, 'hunter-1', writeJson(path.join(tmp('c'), 'r.json'), { units: [candUnit(ids[0])], candidates: [cand()] }));
  const second = cand(); second.title = 'Second wording';
  assert.match(rs('ingest', run, 'hunter-2', writeJson(path.join(tmp('c'), 'r.json'), { units: [candUnit(ids[1], 'hunter-2')], candidates: [second] })), /1 already known/);
  const c = readJson(run, 'candidates', `${encodeURIComponent(fp)}.json`);
  assert.deepStrictEqual(c.found_by, ['hunter-1', 'hunter-2']);
  assert.strictEqual(c.title, 'Order lookup may be unscoped');
  assert.strictEqual(c.alternates[0].candidate.title, 'Second wording');
  // a candidate unit whose fingerprint has no candidate object is reset
  const orphan = { ...candUnit(ids[2], 'hunter-3'), fingerprints: ['idor:src/orders.ts:other'] };
  assert.match(rs('ingest', run, 'hunter-3', writeJson(path.join(tmp('c'), 'r.json'), { units: [orphan], candidates: [] })), /has no valid candidate object/);
  const dec = writeJson(path.join(tmp('d'), 'd.json'), { decision: 'needs_validation', record: record() });
  assert.match(rsErr('decide', run, 'hunter-2', dec), /found/); // the second finder is not independent
  assert.match(rsErr('decide', run, 'hunter-3', writeJson(path.join(tmp('d'), 'd.json'), { decision: 'needs_validation', record: record('idor:src/orders.ts:other') })), /not a live fingerprint/);
  // backward compatibility: found_by as a string
  const cf = path.join(run, 'candidates', `${encodeURIComponent(fp)}.json`);
  fs.writeFileSync(cf, JSON.stringify({ ...cand(), found_by: 'old-hunter' }));
  assert.match(rsErr('decide', run, 'old-hunter', dec), /found/);
  assert.match(rsErr('decide', run, 'hunter-2', dec), /owns or has a check/); // still a ledger worker
  assert.match(rs('decide', run, 'skeptic-1', dec), /stored/);
});

// ---------- decide / verify ----------
test('verify: hashes the current record; replacements keep history and invalidate verifications', () => {
  const { run, ids } = setup({ profile: 'standard' });
  rs('assign', run, 'hunter-1', ids[0]);
  rs('ingest', run, 'hunter-1', writeJson(path.join(tmp('v'), 'r.json'), { units: [candUnit(ids[0])], candidates: [cand()] }));
  writeJson(outFile(run, 'skeptic-1'), { decision: 'needs_validation', record: record() });
  assert.match(rs('decide', run, 'skeptic-1'), /stored needs_validation/); // default path
  const ok = writeJson(path.join(tmp('v'), 'v.json'), { decision: 'verified', fingerprint: fp });
  assert.match(rsErr('verify', run, 'skeptic-1', ok), /authored a decision/);
  assert.match(rsErr('verify', run, 'hunter-1', ok), /found/);
  assert.match(rs('verify', run, 'check-1', ok), /verified/);
  assert.match(rsErr('verify', run, 'check-1', ok), /already verified/);
  const v = readJson(run, 'verifications', `${encodeURIComponent(fp)}.json`);
  assert.strictEqual(v.verifications[0].record_sha256, sha256(canonicalJson(record())));
  assert.match(rs('status', run), /awaiting verification 0/);
  // a replace reply is refused by verify and goes through decide
  const rep = record(); rep.title = 'Order lookup is unscoped for guests';
  const repFile = writeJson(path.join(tmp('v'), 'rep.json'), { decision: 'replace', why: 'title', record: rep });
  assert.match(rsErr('verify', run, 'check-2', repFile), /decide <run> check-2/);
  assert.match(rs('decide', run, 'check-2', repFile), /replaces skeptic-1/);
  const d = readJson(run, 'decisions', `${encodeURIComponent(fp)}.json`);
  assert.strictEqual(d.by, 'check-2'); assert.strictEqual(d.history[0].by, 'skeptic-1'); assert.strictEqual(d.history[0].decision, 'needs_validation');
  assert.match(rs('status', run), /awaiting verification 1/);
  assert.match(rsErr('verify', run, 'skeptic-1', ok), /authored/);
  assert.match(rs('verify', run, 'check-3', ok), /by check-2/);
  assert.match(rs('status', run), /awaiting verification 0/);
});

// ---------- critic / complete / incomplete ----------
function cleanCritic(run, id) { return rs('critic', run, id, writeJson(path.join(tmp('cr'), 'c.json'), { missing_units: [], reopen_ids: [], resolved_prior_leads: [], stop: true })); }

test('critic: stores replies with clean flag and coverage hash; ids are single-use', () => {
  const { run, ids } = setup({ profile: 'standard' });
  const { coverageHash } = require('../run-state.cjs');
  assert.match(rsErr('critic', run, 'critic-1', writeJson(path.join(tmp('cr'), 'bad.json'), { missing_units: 'x' })), /missing_units/);
  const dirty = writeJson(path.join(tmp('cr'), 'd.json'), { missing_units: [{ surface: 's' }], reopen_ids: [ids[0]], resolved_prior_leads: [], stop: false });
  assert.match(rs('critic', run, 'critic-1', dirty), /not clean \(1 missing unit\(s\), 1 reopen id/);
  assert.match(rsErr('critic', run, 'critic-1', dirty), /already used/);
  assert.match(cleanCritic(run, 'critic-2'), /#2: clean/);
  const recs = fs.readdirSync(path.join(run, 'critics')).sort();
  assert.deepStrictEqual(recs, ['000001.json', '000002.json']);
  const c2 = readJson(run, 'critics', recs[1]);
  assert.strictEqual(c2.clean, true); assert.strictEqual(c2.critic, 'critic-2');
  assert.strictEqual(c2.coverage_hash, coverageHash(readJson(run, 'ledger.json')));
});

test('complete: lists every unmet condition, then succeeds once all hold; incomplete validates reasons', () => {
  const { run, ids, target } = setup({ profile: 'standard' });
  let err = rsErr('complete', run);
  for (const tag of ['(a)', '(d)', '(e)', '(g)']) assert.ok(err.includes(tag), `${tag} in ${err}`);
  rs('assign', run, 'hunter-1', ...ids);
  rs('ingest', run, 'hunter-1', writeJson(path.join(tmp('x'), 'r.json'), { units: [candUnit(ids[0]), coveredUnit(ids[1])], candidates: [cand()] }));
  err = rsErr('complete', run);
  assert.match(err, /\(b\) 1 live fingerprint/);
  rs('decide', run, 'skeptic-1', writeJson(path.join(tmp('x'), 'd.json'), { decision: 'needs_validation', record: record() }));
  assert.match(rsErr('complete', run), /\(c\) 1 confirmed\/needs_validation/);
  rs('verify', run, 'check-1', writeJson(path.join(tmp('x'), 'v.json'), { decision: 'verified', fingerprint: fp }));
  cleanCritic(run, 'critic-1');
  assert.match(rsErr('complete', run), /\(d\) the two most recent/);
  cleanCritic(run, 'critic-2');
  // inventory: one surface in an unreferenced file, then waived
  const { inventory } = require('../inventory.cjs');
  fs.writeFileSync(path.join(target, 'src', 'admin.ts'), "app.get('/admin', handler);\n");
  const inv = inventory(target);
  writeJson(path.join(run, 'inventory.json'), inv);
  const gapsOut = spawnSync(process.execPath, [RS, 'inventory-gaps', run], { encoding: 'utf8' });
  assert.strictEqual(gapsOut.status, 1); assert.match(gapsOut.stdout, /1 gap/); assert.match(gapsOut.stdout, /src\/admin\.ts/);
  writeJson(path.join(run, 'inventory-waivers.json'), [{ id: 'nope', why: 'x' }]);
  assert.match(spawnSync(process.execPath, [RS, 'inventory-gaps', run], { encoding: 'utf8' }).stdout, /unknown surface id/);
  writeJson(path.join(run, 'inventory-waivers.json'), inv.surfaces.filter((s) => s.file === 'src/admin.ts').map((s) => ({ id: s.id, why: 'admin is test-only' })));
  assert.match(rs('inventory-gaps', run), /0 gap\(s\), 1 waived/);
  assert.match(rsErr('complete', run), /\(g\) findings\.json does not exist/);
  rs('assemble', run);
  assert.match(rs('complete', run), /status complete/);
  assert.strictEqual(readJson(run, 'run.json').status, 'complete');
  assert.match(rs('status', run), /next: Phase 6: run score\.cjs/);
  fs.writeFileSync(path.join(run, 'REPORT.md'), '# r\n');
  assert.match(rs('status', run), /next: done/);
  assert.match(rsErr('incomplete', run, 'tired'), /incomplete_reason must be one of/);
  assert.match(rs('incomplete', run, 'stopped_early'), /incomplete \(stopped_early\)/);
  assert.strictEqual(readJson(run, 'run.json').incomplete_reason, 'stopped_early');
});

test('critic currency: a reopened unit invalidates earlier clean critics', () => {
  const { run, ids } = setup({ profile: 'standard' });
  rs('assign', run, 'hunter-1', ...ids);
  rs('ingest', run, 'hunter-1', writeJson(path.join(tmp('x'), 'r.json'), { units: ids.map((id) => coveredUnit(id)), candidates: [] }));
  cleanCritic(run, 'critic-1'); cleanCritic(run, 'critic-2');
  assert.match(rs('status', run), /at current coverage: yes/);
  assert.match(rs('reopen', run, ids[0], '--reason', 'critic-2 found a sibling path'), /now planned at wave 2/);
  assert.match(rs('status', run), /at current coverage: no/);
  const u = readJson(run, 'ledger.json').find((x) => x.id === ids[0]);
  assert.strictEqual(u.history[0].status, 'covered'); assert.strictEqual(u.history[0].owner, 'hunter-1');
});

// ---------- recheck ----------
test('recheck: deterministic sample, independence, disagreement blocks complete until reopened', () => {
  const surfaces = Array.from({ length: 12 }, (_, i) => `src/orders.ts#R${String(i).padStart(2, '0')}`);
  const { run, ids } = setup({ surfaces });
  rs('assign', run, 'hunter-1', ...ids);
  rs('ingest', run, 'hunter-1', writeJson(path.join(tmp('x'), 'r.json'), { units: ids.map((id) => coveredUnit(id)), candidates: [] }));
  assert.match(rs('status', run), /recheck: not sampled \(required for deep\)/);
  rs('sample-recheck', run, '--rate', '0.1', '--min', '3');
  const plan = readJson(run, 'recheck', 'plan.json');
  const expect = [...ids].sort((a, b) => { const x = sha256('run-1' + a); const y = sha256('run-1' + b); return x < y ? -1 : x > y ? 1 : 0; }).slice(0, 3);
  assert.deepStrictEqual(plan.units.map((p) => p.id), expect);
  assert.match(rsErr('sample-recheck', run), /already exists/);
  const [u1, u2, u3] = expect;
  const reply = writeJson(path.join(tmp('x'), 'rc.json'), { units: [
    { id: u1, agree: true, why: 'owner filter present', anchors: [anchor] },
    { id: u2, agree: false, why: 'batch path skips the check' },
  ] });
  assert.match(rsErr('recheck-result', run, 'hunter-1', reply), /owns or has a check/);
  const out = rs('recheck-result', run, 'recheck-1', reply);
  assert.match(out, /2 recorded, 1 disagreement/);
  assert.ok(out.includes(`reopen <run> ${u2} --reason`));
  assert.strictEqual(readJson(run, 'ledger.json').find((u) => u.id === u2).status, 'covered', 'ledger unchanged by a disagreement');
  assert.match(rs('status', run), /recheck: 3 sampled, 2 recorded, 1 disagreements \(1 unresolved\)/);
  assert.match(rsErr('recheck-result', run, 'recheck-1', reply), /already recorded/);
  const badAnchor = writeJson(path.join(tmp('x'), 'rc2.json'), { units: [{ id: u3, agree: true, why: 'w', anchors: [{ file: 'src/orders.ts', line: 1, quote: 'nothing like this line' }] }] });
  assert.match(rsErr('recheck-result', run, 'recheck-2', badAnchor), /quote/);
  rs('recheck-result', run, 'recheck-3', writeJson(path.join(tmp('x'), 'rc3.json'), { units: [{ id: u3, agree: true, why: 'fine' }] }));
  assert.match(rsErr('complete', run), /\(f\) 1 disagreeing unit/);
  rs('reopen', run, u2, '--reason', 'recheck by recheck-1 disagrees');
  assert.match(rs('status', run), /0 unresolved/);
  assert.doesNotMatch(rsErr('complete', run), /\(f\)/);
});

test('status stays compact and names the next step', () => {
  const { run, ids } = setup();
  let s = rs('status', run);
  assert.ok(s.trim().split('\n').length <= 10, s);
  assert.match(s, /next: assign 2 planned/);
  rs('assign', run, 'hunter-1', ...ids);
  writeJson(outFile(run, 'hunter-1'), { units: ids.map((id) => coveredUnit(id)), candidates: [] });
  s = rs('status', run);
  assert.match(s, /next: ingest results: ingest <run> hunter-1/);
  rs('ingest', run, 'hunter-1');
  s = rs('status', run);
  assert.match(s, /next: Phase 4: assemble/);
  rs('assemble', run);
  s = rs('status', run);
  assert.match(s, /next: run a coverage critic/);
  assert.match(s, /add-units <run> --from-critic/);
  assert.ok(s.trim().split('\n').length <= 10, s);
});

// ---------- inventory directory coverage / add-units ----------
test('inventory-gaps: a directory path covers files under it, by whole path segments', () => {
  const { run, target } = setup({ surfaces: [] });
  writeJson(path.join(run, 'inventory.json'), { surfaces: [
    { id: 'http-route:src/api/orders/route.ts#GET /orders', kind: 'http-route', file: 'src/api/orders/route.ts', line: 1, label: 'GET /orders' },
    { id: 'http-route:src/api-old/x.ts#GET /x', kind: 'http-route', file: 'src/api-old/x.ts', line: 1, label: 'GET /x' },
  ] });
  fs.mkdirSync(path.join(target, 'src', 'api'), { recursive: true });
  const seed = { refs: { surface: 'src/api#all routes', boundary: 'src/auth.ts#requireUser', subsystem: 'api', class: 'core-classes.md#Access control' },
    labels: { surface: 'API routes', boundary: 'guard', subsystem: 'API', class: 'Access control' }, start_paths: ['src/api'],
    class_block: 'core-classes.md#Access control', pack_blocks: [], skipped_blocks: [] };
  rs('add-units', run, writeJson(path.join(tmp('s'), 's.json'), [seed]));
  const r = spawnSync(process.execPath, [RS, 'inventory-gaps', run], { encoding: 'utf8' });
  assert.strictEqual(r.status, 1);
  assert.match(r.stdout, /1 gap/); assert.match(r.stdout, /src\/api-old\/x\.ts/); assert.doesNotMatch(r.stdout, /orders\/route\.ts/);
});

test('add-units: seeds from a file or stdin, sorted ids, duplicates refused with nothing written, journaled', () => {
  const { run } = setup({ surfaces: [] });
  fs.unlinkSync(path.join(run, 'ledger.json')); // created by add-units
  const seed = (s) => ({ refs: { surface: s, boundary: 'src/auth.ts#requireUser', subsystem: 'api', class: 'core-classes.md#Access control' },
    labels: { surface: s, boundary: 'guard', subsystem: 'API', class: 'Access control' }, start_paths: ['src/orders.ts'],
    class_block: 'core-classes.md#Access control', pack_blocks: [], skipped_blocks: [], notes: { priority: 1 } });
  assert.match(rs('add-units', run, writeJson(path.join(tmp('s'), 's.json'), [seed('src/orders.ts#Z'), seed('src/orders.ts#A')])), /2 unit\(s\) added/);
  let ledger = readJson(run, 'ledger.json');
  assert.deepStrictEqual(ledger.map((u) => u.id), [deriveId(seed('src/orders.ts#A').refs), deriveId(seed('src/orders.ts#Z').refs)]);
  assert.deepStrictEqual([ledger[0].status, ledger[0].wave, ledger[0].owner, ledger[0].prior, ledger[0].notes.priority], ['planned', 1, null, 'none', 1]);
  const stdin = execFileSync(process.execPath, [RS, 'add-units', run], { input: JSON.stringify([seed('src/orders.ts#M')]), encoding: 'utf8' });
  assert.match(stdin, /from stdin: 1 unit/);
  const before = fs.readFileSync(path.join(run, 'ledger.json'), 'utf8');
  const err = rsErr('add-units', run, writeJson(path.join(tmp('s'), 's.json'), [seed('src/orders.ts#N'), seed('src/orders.ts#A')]));
  assert.match(err, /nothing written/); assert.match(err, /already in the ledger/);
  assert.match(rsErr('add-units', run, writeJson(path.join(tmp('s'), 's.json'), [{ ...seed('src/orders.ts#Q'), start_paths: ['src/missing.ts'] }])), /does not exist/);
  assert.strictEqual(fs.readFileSync(path.join(run, 'ledger.json'), 'utf8'), before);
  assert.ok(fs.readFileSync(path.join(run, 'journal.jsonl'), 'utf8').includes('"cmd":"add-units"'));
});

test('add-units --from-critic and --from-queue convert usable entries and report the rest', () => {
  const { run, ids } = setup({ profile: 'standard' });
  const good = { surface: 'src/orders.ts#DELETE /orders/:id', boundary: 'src/auth.ts#requireUser', subsystem: 'api', class: 'core-classes.md#Access control', start_paths: ['src/orders.ts'], why: 'w' };
  const noClass = { surface: 'src/orders.ts#PUT /x', boundary: 'b', subsystem: 'api', start_paths: ['src/orders.ts'], why: 'w' };
  const pack = { surface: 'src/orders.ts#deep link', boundary: 'src/auth.ts#requireUser', subsystem: 'api', class: 'packs/mobile.md#Deep link and App Link abuse',
    pack_blocks: ['packs/mobile.md#Discipline', 'packs/mobile.md#Moves', 'packs/mobile.md#Gate'], start_paths: ['src/orders.ts'], why: 'w' };
  rs('critic', run, 'critic-1', writeJson(path.join(tmp('c'), 'c.json'), { missing_units: [good, noClass, pack], reopen_ids: [], resolved_prior_leads: [], stop: false }));
  const out = rs('add-units', run, '--from-critic', 'critic-1');
  assert.match(out, /from critic critic-1: 2 unit\(s\) added as planned, 1 not converted/);
  assert.match(out, /refs needs string/);
  let ledger = readJson(run, 'ledger.json');
  assert.strictEqual(ledger.length, ids.length + 2);
  const p = ledger.find((u) => u.refs.class.startsWith('packs/'));
  assert.ok(p.pack_blocks.includes('packs/mobile.md#Deep link and App Link abuse')); assert.strictEqual(p.labels.surface, 'deep link');
  assert.match(rs('add-units', run, '--from-critic', 'critic-1'), /0 unit\(s\) added.*\n(.*\n)*.*already in the ledger/);
  assert.match(rsErr('add-units', run, '--from-critic', 'nobody'), /no stored critic/);
  // queue
  const q = path.join(run, 'queue', 'uncovered.jsonl');
  fs.mkdirSync(path.dirname(q), { recursive: true });
  const qGood = { ...good, surface: 'src/orders.ts#PATCH /orders/:id', from: 'hunter-1' };
  fs.writeFileSync(q, [JSON.stringify(qGood), JSON.stringify(noClass), 'not json'].join('\n') + '\n');
  assert.match(rs('add-units', run, '--from-queue'), /from queue\/uncovered\.jsonl: 1 unit\(s\) added as planned, 2 not converted/);
  const left = fs.readFileSync(q, 'utf8').trim().split('\n');
  assert.strictEqual(left.length, 2, 'unconverted entries stay in the queue');
  ledger = readJson(run, 'ledger.json');
  assert.strictEqual(ledger.length, ids.length + 3);
  const r = new Reporter(); validateLedger(ledger, r, { runDir: run, checkFiles: true, checkBlocks: true, profile: 'standard' }); assert.deepStrictEqual(r.errors, []);
});

// ---------- gap fixes: recheck guards, set-status, resume, stale completion ----------
function relabel(run, ids, status) {
  const l = readJson(run, 'ledger.json');
  for (const u of l) if (ids.includes(u.id)) Object.assign(u, { status, open: [] });
  fs.writeFileSync(path.join(run, 'ledger.json'), JSON.stringify(l, null, 2));
}

test('sample-recheck: refused while hunting or with nothing covered; complete rejects a too-small plan; --redraw keeps results', () => {
  const surfaces = Array.from({ length: 6 }, (_, i) => `src/orders.ts#S${i}`);
  const { run, ids } = setup({ surfaces });
  assert.match(rsErr('sample-recheck', run), /still planned or in_progress/);
  const first = ids.slice(0, 3); const rest = ids.slice(3);
  rs('assign', run, 'hunter-1', ...first);
  rs('set-status', run, ...rest, '--to', 'deferred', '--reason', 'budget_reserve');
  rs('ingest', run, 'hunter-1', writeJson(path.join(tmp('x'), 'r.json'), { units: first.map((id) => ({ ...coveredUnit(id), disposition: 'blocked', open: ['needs prod config'] })), candidates: [] }));
  assert.match(rsErr('sample-recheck', run), /no covered or carried units/);
  assert.doesNotMatch(rsErr('complete', run), /\(f\)/, 'no plan needed while nothing is covered');
  relabel(run, rest, 'planned');
  rs('assign', run, 'hunter-2', rest[0]);
  rs('ingest', run, 'hunter-2', writeJson(path.join(tmp('x'), 'r.json'), { units: [coveredUnit(rest[0], 'hunter-2')], candidates: [] }));
  rs('set-status', run, ...rest.slice(1), '--to', 'out_of_scope', '--reason', 'scoped run');
  rs('sample-recheck', run, '--rate', '0.5', '--min', '1');
  assert.strictEqual(readJson(run, 'recheck', 'plan.json').units.length, 1);
  assert.match(rsErr('sample-recheck', run, '--redraw'), /has not changed/);
  rs('recheck-result', run, 'recheck-1', writeJson(path.join(tmp('x'), 'rc.json'), { units: [{ id: rest[0], agree: true, why: 'fine' }] }));
  relabel(run, rest.slice(1), 'planned');
  rs('assign', run, 'hunter-3', ...rest.slice(1));
  rs('ingest', run, 'hunter-3', writeJson(path.join(tmp('x'), 'r.json'), { units: rest.slice(1).map((id) => coveredUnit(id, 'hunter-3')), candidates: [] }));
  assert.match(rsErr('complete', run), /\(f\) the recheck sample \(1 normal, 0 lite\) is smaller than 3 reviewed unit\(s\) now need \(2 normal, 0 lite\)/);
  assert.match(rs('sample-recheck', run, '--redraw'), /redrawn\): 2 of 3 reviewed unit\(s\)/);
  const plan = readJson(run, 'recheck', 'plan.json');
  assert.strictEqual(plan.units.length, 2);
  const kept = plan.units.some((p) => p.id === rest[0]) ? 1 : 0;
  assert.match(rs('status', run), new RegExp(`recheck: 2 sampled, ${kept} recorded`));
});

test('set-status: parks planned units and lost in_progress units only, with the reason in open', () => {
  const { run, ids } = setup({ surfaces: ['src/orders.ts#A', 'src/orders.ts#B', 'src/orders.ts#C'] });
  assert.match(rsErr('set-status', run, ids[0], '--to', 'covered', '--reason', 'x'), /--to must be one of/);
  assert.match(rsErr('set-status', run, ids[0], '--to', 'deferred'), /--reason/);
  assert.match(rs('set-status', run, ids[0], '--to', 'deferred', '--reason', 'budget_reserve'), /set 1 unit\(s\) to deferred/);
  let u = readJson(run, 'ledger.json').find((x) => x.id === ids[0]);
  assert.deepStrictEqual([u.status, u.owner, u.open], ['deferred', null, ['budget_reserve']]);
  assert.match(rsErr('set-status', run, ids[0], '--to', 'out_of_scope', '--reason', 'x'), /only planned units/);
  rs('assign', run, 'hunter-1', ids[1]);
  rs('assign', run, 'hunter-2', ids[2]);
  writeJson(outFile(run, 'hunter-2'), { units: [coveredUnit(ids[2], 'hunter-2')], candidates: [] });
  assert.match(rsErr('set-status', run, ids[2], '--to', 'deferred', '--reason', 'x'), /result waiting/);
  assert.match(rs('set-status', run, ids[1], '--to', 'not_applicable', '--reason', 'no such route in this build'), /set 1/);
  u = readJson(run, 'ledger.json').find((x) => x.id === ids[1]);
  assert.deepStrictEqual([u.status, u.owner], ['not_applicable', null]);
  assert.ok(fs.readFileSync(path.join(run, 'journal.jsonl'), 'utf8').includes('"cmd":"set-status"'));
});

test('resume: incomplete → in_progress; complete needs --reopen', () => {
  const { run } = setup();
  assert.match(rs('resume', run), /already in_progress/);
  rs('incomplete', run, 'recon_only');
  assert.match(rs('resume', run), /incomplete \(recon_only\) → in_progress/);
  const r = readJson(run, 'run.json');
  assert.deepStrictEqual([r.status, r.incomplete_reason], ['in_progress', null]);
  fs.writeFileSync(path.join(run, 'run.json'), JSON.stringify({ ...r, status: 'complete' }));
  assert.match(rsErr('resume', run), /--reopen/);
  assert.match(rs('resume', run, '--reopen'), /complete → in_progress/);
});

test('stale completion: changing state after complete sets the run back to in_progress', () => {
  const { run } = setup({ profile: 'quick', surfaces: [] });
  const qs = (s) => { const u0 = unit(s); u0.refs.subsystem = 'profile/quick/all'; u0.id = deriveId(u0.refs); return u0; };
  const units = [qs('src/orders.ts#A'), qs('src/orders.ts#B')].sort((a, b) => (a.id < b.id ? -1 : 1));
  fs.writeFileSync(path.join(run, 'ledger.json'), JSON.stringify(units));
  const qids = units.map((u) => u.id);
  rs('assign', run, 'hunter-1', ...qids);
  rs('ingest', run, 'hunter-1', writeJson(path.join(tmp('x'), 'r.json'), { units: qids.map((id) => coveredUnit(id)), candidates: [] }));
  cleanCritic(run, 'critic-1');
  rs('assemble', run);
  assert.match(rs('complete', run), /status complete/);
  assert.match(cleanCritic(run, 'critic-2'), /was "complete" and is now "in_progress"/);
  assert.strictEqual(readJson(run, 'run.json').status, 'in_progress');
  rs('complete', run);
  assert.match(rs('reopen', run, qids[0], '--reason', 'owner asked'), /now "in_progress"/);
  assert.strictEqual(readJson(run, 'run.json').status, 'in_progress');
});

// ---------- cost features: carry, tiers, batching ----------
function classUnit(surface, cls = 'core-classes.md#Files, fetches and parsing', start = 'src/orders.ts', subsystem = 'api') {
  const refs = { surface, boundary: 'src/auth.ts#requireUser', subsystem, class: cls };
  return { id: deriveId(refs), refs, labels: { surface, boundary: 'guard', subsystem, class: cls.split('#')[1] },
    start_paths: [start], class_block: cls, pack_blocks: [], skipped_blocks: [],
    prior: 'none', wave: 1, status: 'planned', owner: null, paths: [], checks: [], fingerprints: [], open: [], history: [] };
}
function seedLedger(run, units) { fs.writeFileSync(path.join(run, 'ledger.json'), JSON.stringify(units.sort((a, b) => (a.id < b.id ? -1 : 1)), null, 2)); return units.map((u) => u.id); }
function newRunFor(target, runId, extra = {}) {
  const run = tmp('run');
  fs.writeFileSync(path.join(run, 'run.json'), JSON.stringify({ run_id: runId, repo: 'x', target, source_ref: {}, profile: 'deep', scope: { kind: 'full' }, execution: 'source-only', status: 'in_progress', incomplete_reason: null, ...extra }));
  return run;
}
const markComplete = (run) => { const r = readJson(run, 'run.json'); fs.writeFileSync(path.join(run, 'run.json'), JSON.stringify({ ...r, status: 'complete' })); };

test('carry: unchanged covered units are carried; changes, siblings, boundary and chain limits force re-hunting', () => {
  const { run: prior, target, ids } = setup({ surfaces: ['src/orders.ts#A', 'src/orders.ts#B', 'src/orders.ts#C'] });
  rs('assign', prior, 'hunter-1', ...ids);
  rs('ingest', prior, 'hunter-1', writeJson(path.join(tmp('x'), 'r.json'), { units: [candUnit(ids[0]), coveredUnit(ids[1]), coveredUnit(ids[2])], candidates: [cand()] }));
  const h = readJson(prior, 'hashes.json');
  assert.ok(h.files['src/orders.ts'] && h.files['src/auth.ts'] && h.dirs.src && h.blocks['core-classes.md#Access control'] && h.skill_version);
  writeJson(path.join(prior, 'findings.json'), [record()]);
  // refused while the prior run is not complete
  const run2 = newRunFor(target, 'run-2');
  assert.match(rsErr('carry', run2, '--from', prior), /only a complete run/);
  markComplete(prior);
  const out = rs('carry', run2, '--from', prior);
  assert.match(out, /2 unit\(s\) carried unchanged, 1 planned for hunting/);
  assert.match(out, /1\tprior candidate/);
  const l2 = Object.fromEntries(readJson(run2, 'ledger.json').map((u) => [u.id, u]));
  assert.strictEqual(l2[ids[1]].status, 'carried');
  assert.deepStrictEqual(l2[ids[1]].carried_from, { run_id: 'run-1', wave: 1, chain: 1 });
  assert.strictEqual(l2[ids[1]].owner, null);
  assert.deepStrictEqual([l2[ids[0]].status, l2[ids[0]].prior], ['planned', 'nv']);
  assert.ok(fs.existsSync(path.join(run2, 'hashes.json')));
  const r = new Reporter(); validateLedger(readJson(run2, 'ledger.json'), r, { runDir: run2, checkFiles: true, checkBlocks: true, target }); assert.deepStrictEqual(r.errors, []);
  // carried units count as reviewed; score says how many were carried
  const { score, toMarkdown } = require('../score.cjs');
  const md = toMarkdown(score(readJson(run2, 'run.json'), readJson(run2, 'ledger.json'), []), readJson(run2, 'run.json'));
  assert.match(md, /2 carried unchanged from a prior run, 0 freshly reviewed/);
  // chain: run-2 (carried, chain 1) → run-3 (chain 2) → run-4 refuses (re-hunt)
  rs('set-status', run2, ids[0], '--to', 'deferred', '--reason', 'test');
  markComplete(run2);
  const run3 = newRunFor(target, 'run-3');
  assert.match(rs('carry', run3, '--from', run2), /2 unit\(s\) carried/);
  assert.strictEqual(readJson(run3, 'ledger.json').find((u) => u.id === ids[1]).carried_from.chain, 2);
  markComplete(run3);
  const run4 = newRunFor(target, 'run-4');
  const o4 = rs('carry', run4, '--from', run3);
  assert.match(o4, /0 unit\(s\) carried/); assert.match(o4, /2\talready carried 2 runs in a row/);
  // a sibling file in the start_path directory changes → not carried, prior covered_same is not claimed for changed code
  fs.writeFileSync(path.join(target, 'src', 'new-sibling.ts'), 'export const x = 1;\n');
  const run5 = newRunFor(target, 'run-5');
  const o5 = rs('carry', run5, '--from', prior);
  assert.match(o5, /0 unit\(s\) carried/); assert.match(o5, /2\tfile changed in a start_path directory/);
  assert.strictEqual(readJson(run5, 'ledger.json').find((u) => u.id === ids[1]).prior, 'covered_changed');
  // the boundary file changes
  fs.unlinkSync(path.join(target, 'src', 'new-sibling.ts'));
  fs.appendFileSync(path.join(target, 'src', 'auth.ts'), '// changed\n');
  const o6 = rs('carry', newRunFor(target, 'run-6'), '--from', prior);
  assert.match(o6, /2\tboundary file changed/);
  // quick or other-repo priors are refused
  const q = newRunFor(target, 'run-q', { profile: 'quick', status: 'complete' });
  fs.writeFileSync(path.join(q, 'ledger.json'), '[]');
  assert.match(rsErr('carry', newRunFor(target, 'run-7'), '--from', q), /quick prior run/);
  assert.match(rsErr('carry', newRunFor(target, 'run-8', { repo: 'other' }), '--from', prior), /prior run is for repo/);
});

test('check-ledger: carried units are validated (owner null, anchors, source checks, carried_from)', () => {
  const { run, ids } = setup();
  const l = readJson(run, 'ledger.json');
  Object.assign(l[0], { status: 'carried', paths: ['src/orders.ts'], checks: [chk()], carried_from: { run_id: 'run-0', wave: 1, chain: 1 } });
  let r = new Reporter(); validateLedger(l, r, { runDir: run, checkFiles: false, checkBlocks: true }); assert.deepStrictEqual(r.errors, []);
  for (const [mut, msg] of [
    [(u) => { u.owner = 'hunter-1'; }, /carried: owner must be null/],
    [(u) => { delete u.carried_from; }, /needs carried_from/],
    [(u) => { u.carried_from.chain = 3; }, /chain must be an integer 1\.\.2/],
    [(u) => { u.checks = [chk('hunter-1', { anchors: [] })]; }, /anchors/],
    [(u) => { u.checks = [chk('hunter-1', { method: 'local', evidence: 'agents/hunter-1/evidence/x.txt' })]; }, /only source checks/],
  ]) {
    const c = JSON.parse(JSON.stringify(l)); mut(c[0]);
    r = new Reporter(); validateLedger(c, r, { runDir: run, checkFiles: false, checkBlocks: true });
    assert.match(r.errors.join('\n'), msg);
  }
  const c = JSON.parse(JSON.stringify(l)); c[1].carried_from = { run_id: 'x', wave: 1, chain: 1 };
  r = new Reporter(); validateLedger(c, r, { runDir: run, checkFiles: false, checkBlocks: true });
  assert.match(r.errors.join('\n'), /only allowed on a carried unit/);
  assert.ok(ids.length);
});

test('tier: standard profile only; assign never mixes tiers; lite coverage is recorded, stratified and gated', () => {
  const { run, target } = setup({ profile: 'standard', surfaces: [] });
  fs.mkdirSync(path.join(target, 'lib'));
  fs.writeFileSync(path.join(target, 'lib', 'x.ts'), 'export const y = 2;\n');
  const lite = Array.from({ length: 6 }, (_, i) => classUnit(`src/orders.ts#F${i}`));
  const high = classUnit('src/orders.ts#AC', 'core-classes.md#Access control');
  const ids = seedLedger(run, [...lite, high]);
  const liteIds = lite.map((u) => u.id);
  // before `tier` runs everything is high: one strong assignment is fine
  assert.match(rs('tier', run), /1 high, 6 standard/);
  const l = Object.fromEntries(readJson(run, 'ledger.json').map((u) => [u.id, u]));
  assert.strictEqual(l[high.id].notes.tier, 'high'); assert.match(l[high.id].notes.tier_why, /class Access control/);
  assert.strictEqual(l[liteIds[0]].notes.tier, 'standard');
  assert.match(rsErr('assign', run, 'hunter-x', high.id, liteIds[0]), /mixes high and standard/);
  assert.match(rs('assign', run, 'lite-1', ...liteIds), /use agent bsec-hunter-lite/);
  assert.strictEqual(readJson(run, 'agents', 'lite-1', 'assignment.json').tier, 'lite');
  rs('assign', run, 'strong-1', high.id);
  rs('ingest', run, 'lite-1', writeJson(path.join(tmp('x'), 'r.json'), { units: liteIds.map((id) => coveredUnit(id, 'lite-1')), candidates: [] }));
  rs('ingest', run, 'strong-1', writeJson(path.join(tmp('x'), 'r.json'), { units: [coveredUnit(high.id, 'strong-1')], candidates: [] }));
  assert.ok(readJson(run, 'ledger.json').filter((u) => liteIds.includes(u.id)).every((u) => u.notes.covered_tier === 'lite'));
  assert.match(rs('status', run), /covered by tier: 1 strong, 6 lite/);
  assert.match(rsErr('complete', run), /6 unit\(s\) covered by lite hunters need the stratified recheck sample/);
  assert.match(rs('sample-recheck', run), /5 in the lite stratum/);
  const plan = readJson(run, 'recheck', 'plan.json');
  const litePlan = plan.units.filter((p) => p.stratum === 'lite').map((p) => p.id);
  assert.strictEqual(litePlan.length, 5);
  assert.ok(litePlan.every((id) => liteIds.includes(id)));
  // two of five lite re-hunts disagree (>= 2 and > 10 %): complete is blocked until every lite unit is reopened
  rs('recheck-result', run, 'strong-rc', writeJson(path.join(tmp('x'), 'rc.json'), { units: litePlan.map((id, i) => ({ id, agree: i >= 2, why: 'w' })) }));
  assert.match(rsErr('complete', run), /lite-tier recheck failed \(2 of 5 disagree\)/);
  assert.match(rs('status', run), /recheck: 7 sampled \(5 lite\), 5 recorded, 2 disagreements/);
  assert.match(rs('reopen', run, '--lite-tier', '--reason', 'lite sample disagreed'), /reopened 6 lite-covered unit\(s\)/);
  const after = readJson(run, 'ledger.json').filter((u) => liteIds.includes(u.id));
  assert.ok(after.every((u) => u.status === 'planned' && u.notes.tier === 'high' && u.notes.tier_lock === true && u.notes.covered_tier === undefined));
  assert.match(rs('tier', run), /6 locked high/);
  assert.doesNotMatch(rsErr('complete', run), /lite-tier recheck failed/);
  // deep: every unit is high
  const d = setup({ profile: 'deep', surfaces: [] });
  seedLedger(d.run, [classUnit('src/orders.ts#F0')]);
  assert.match(rs('tier', d.run), /1 high, 0 standard \(tiering applies only to the standard profile\)/);
  assert.ok(ids.length);
});

test('next --batch: groups share files or directories, one subsystem and one tier, within caps', () => {
  const { run, target } = setup({ profile: 'standard', surfaces: [] });
  fs.mkdirSync(path.join(target, 'lib'));
  fs.writeFileSync(path.join(target, 'lib', 'x.ts'), 'export const y = 2;\n');
  const a = classUnit('src/orders.ts#A1'); const b = classUnit('src/orders.ts#A2');
  const c = classUnit('src/auth.ts#A3', undefined, 'src/auth.ts');
  const d = classUnit('lib/x.ts#B1', undefined, 'lib/x.ts');
  const e = classUnit('src/orders.ts#W1', undefined, 'src/orders.ts', 'web');
  const f = classUnit('src/orders.ts#H1', 'core-classes.md#Injection');
  seedLedger(run, [a, b, c, d, e, f]);
  rs('tier', run);
  const lines = rs('next', run, '--batch').trim().split('\n');
  const groups = lines.map((l) => l.split('  #')[0].split(' '));
  const groupOf = (u) => groups.findIndex((g) => g.includes(u.id));
  assert.strictEqual(groupOf(a), groupOf(b)); assert.strictEqual(groupOf(a), groupOf(c), 'same directory');
  assert.notStrictEqual(groupOf(a), groupOf(d), 'different directory');
  assert.notStrictEqual(groupOf(a), groupOf(e), 'different subsystem');
  assert.notStrictEqual(groupOf(a), groupOf(f), 'different tier');
  assert.match(lines[groupOf(f)], /tier=high \(strong hunter\)/); assert.match(lines[groupOf(a)], /tier=standard \(bsec-hunter-lite\)/);
  assert.strictEqual(groups.flat().length, 6);
  const capped = rs('next', run, '--batch', '--max-units', '2').trim().split('\n').map((l) => l.split('  #')[0].split(' '));
  assert.ok(capped.every((g) => g.length <= 2));
  const tiny = rs('next', run, '--batch', '--max-bytes', '10').trim().split('\n');
  assert.strictEqual(tiny.length, 6, 'byte cap keeps oversized units alone');
  // a batch line pastes straight into assign
  assert.match(rs('assign', run, 'lite-1', ...groups[groupOf(a)]), /assigned 3/);
});

// ---------- merge-runs ----------
test('merge-runs: union by fingerprint, disagreements held for a fresh Skeptic, estimate, near-duplicates, union coverage', () => {
  const { target, ids } = setup();
  const fp2 = 'sqli:src/orders.ts:listOrders'; const dupFp = 'idor:src/orders.ts:getOrderById';
  const rejected = (f) => { const { blockers, validation_plan, ...r } = record(f); return { ...r, verdict: 'rejected', reason: 'owner check upstream' }; };
  const mk = (runId, findings, statuses, extra = {}) => {
    const run = newRunFor(target, runId, { status: 'complete', source_ref: { commit: 'abc', dirty: false }, ...extra });
    const led = readJson(setup().run, 'ledger.json').map((u, i) => ({ ...u, ...(statuses[i] === 'covered'
      ? { status: 'covered', owner: 'hunter-1', paths: ['src/orders.ts'], checks: [chk()] } : {}) }));
    led[0] = { ...led[0], status: 'candidate', owner: 'hunter-1', paths: ['src/orders.ts'], checks: [chk()], fingerprints: findings.map((x) => x.fingerprint) };
    fs.writeFileSync(path.join(run, 'ledger.json'), JSON.stringify(led));
    fs.writeFileSync(path.join(run, 'findings.json'), JSON.stringify(findings.sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1))));
    return run;
  };
  const A = mk('run-a', [record(fp), record(fp2)], ['candidate', 'planned']);
  const Bdir = mk('run-b', [record(fp), record(dupFp), rejected(fp2)], ['candidate', 'covered']);
  const out = path.join(tmp('merge'), 'out');
  const o = rs('merge-runs', out, A, Bdir);
  assert.match(o, /merged 2 runs/); assert.match(o, /1 unresolved disagreement/); assert.match(o, /1 possible duplicate pair/);
  const merged = readJson(out, 'findings.json');
  assert.deepStrictEqual(merged.map((x) => x.fingerprint), [fp, dupFp].sort());
  const dis = readJson(out, 'disagreements.json');
  assert.strictEqual(dis[0].fingerprint, fp2); assert.deepStrictEqual(dis[0].records.map((r) => r.verdict), ['needs_validation', 'rejected']);
  const m = readJson(out, 'merge.json');
  assert.deepStrictEqual(m.overlap.matrix, [[2, 1], [1, 2]]);
  assert.deepStrictEqual(m.runs.map((r) => r.unique), [[fp2], [dupFp]]);
  assert.strictEqual(m.estimate.estimated_total, 3.5); assert.match(m.estimate.label, /ROUGH ESTIMATE/); assert.ok(m.estimate.assumptions.length >= 2);
  assert.deepStrictEqual(readJson(out, 'possible-duplicates.json').map((d) => [d.a.fingerprint, d.b.fingerprint].sort()), [[dupFp, fp].sort()]);
  assert.strictEqual(readJson(out, 'run.json').status, 'in_progress');
  assert.strictEqual(readJson(out, 'ledger.json').find((u) => u.id === ids[1]).status, 'covered', 'union coverage');
  // a resolution by someone who worked the fingerprint is refused; a fresh Skeptic's is used
  writeJson(path.join(out, 'resolutions', `${encodeURIComponent(fp2)}.json`), { by: 'hunter-1', decision: 'rejected', record: rejected(fp2) });
  assert.match(rs('merge-runs', out, A, Bdir), /resolution refused: .*hunter-1 found, decided, verified or worked/);
  writeJson(path.join(out, 'resolutions', `${encodeURIComponent(fp2)}.json`), { by: 'skeptic-merge', decision: 'needs_validation', record: record(fp2) });
  assert.match(rs('merge-runs', out, A, Bdir), /0 unresolved disagreement\(s\), 1 resolved/);
  assert.ok(readJson(out, 'findings.json').some((x) => x.fingerprint === fp2));
  assert.strictEqual(readJson(out, 'run.json').status, 'complete');
  // score.cjs scores the merged directory on union coverage and says so
  const S = path.resolve(__dirname, '..', 'score.cjs');
  assert.match(execFileSync(process.execPath, [S, out], { encoding: 'utf8' }), /merged from 2 runs \(run-a, run-b\): a unit counts as reviewed if any run reviewed it/);
  // refusals
  const C = mk('run-c', [record(fp)], ['candidate', 'planned'], { source_ref: { commit: 'def', dirty: false } });
  assert.match(rsErr('merge-runs', path.join(tmp('m2'), 'o'), A, C), /different source refs/);
  assert.match(rsErr('merge-runs', path.join(tmp('m2'), 'o'), A, C, '--allow-ref-drift'), /run-a has no hashes\.json/);
  const D = mk('run-d', [record(fp)], ['candidate', 'planned'], { status: 'in_progress' });
  assert.match(rsErr('merge-runs', path.join(tmp('m3'), 'o'), A, D), /only complete runs/);
  const E = mk('run-e', [record(fp)], ['candidate', 'planned'], { repo: 'other' });
  assert.match(rsErr('merge-runs', path.join(tmp('m4'), 'o'), A, E), /different repos/);
  assert.match(rsErr('merge-runs', path.join(tmp('m5'), 'o'), A), /usage/);
});

test('merge-runs estimate: Chao2 lower bound for three runs, omitted without overlap', () => {
  const { estimate } = require('../merge-runs.cjs');
  assert.match(estimate([new Set(['a', 'b']), new Set(['c', 'd'])]).omitted, /overlap is zero/);
  assert.match(estimate([new Set(['a']), new Set(['a'])]).omitted, /fewer than 3/);
  const e = estimate([new Set(['a', 'b', 'c']), new Set(['a', 'd']), new Set(['a', 'b', 'e'])]);
  // observed 5; f1 = 3 (c, d, e), f2 = 1 (b); 5 + (2/3) * 9 / 2 = 8
  assert.strictEqual(e.estimated_total_lower_bound, 8); assert.match(e.method, /Chao2/);
});
