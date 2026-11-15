'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { deriveId, validateLedger } = require('../check-ledger.cjs');
const { Reporter } = require('../lib.cjs');
const { verifyQuotes } = require('../check-findings.cjs');

const RS = path.resolve(__dirname, '..', 'run-state.cjs');
// Directory names with spaces on purpose: Windows paths like "C:\Users\First Last\..." must work.
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), `bsec rs ${p}-`));
const rs = (...a) => execFileSync(process.execPath, [RS, ...a], { encoding: 'utf8', stdio: 'pipe' });
const rsFail = (...a) => assert.throws(() => rs(...a));
const readJson = (...p) => JSON.parse(fs.readFileSync(path.join(...p), 'utf8'));

function unit(surface) {
  const refs = { surface, boundary: 'src/auth.ts#requireUser', subsystem: 'api', class: 'core-classes.md#Access control' };
  return { id: deriveId(refs), refs, labels: { surface, boundary: 'guard', subsystem: 'API', class: 'Access control' },
    start_paths: ['src/orders.ts'], class_block: 'core-classes.md#Access control', pack_blocks: [], skipped_blocks: [],
    prior: 'none', wave: 1, status: 'planned', owner: null, paths: [], checks: [], fingerprints: [], open: [], history: [] };
}

function setup() {
  const target = tmp('target');
  fs.mkdirSync(path.join(target, 'src'));
  fs.writeFileSync(path.join(target, 'src', 'orders.ts'), 'export async function getOrder(id) {\r\n  return db.orders.findById(id);\r\n}\r\n');
  const run = tmp('run');
  const ledger = [unit('src/orders.ts#GET /orders/:id'), unit('src/orders.ts#GET /orders')].sort((a, b) => (a.id < b.id ? -1 : 1));
  fs.writeFileSync(path.join(run, 'run.json'), JSON.stringify({ run_id: 'run-1', repo: 'x', target, source_ref: {}, profile: 'deep', scope: { kind: 'full' }, execution: 'source-only', status: 'in_progress', incomplete_reason: null }));
  fs.writeFileSync(path.join(run, 'ledger.json'), JSON.stringify(ledger, null, 2).replace(/\n/g, '\r\n')); // CRLF on purpose
  return { target, run, ids: ledger.map((u) => u.id) };
}
const check = { by: 'hunter-1', paths: ['src/orders.ts'], invariant: 'owner scope', method: 'source', result: 'no owner filter', evidence: null };
const fp = 'idor:src/orders.ts:getOrder';
const record = (fingerprint = fp) => ({
  verdict: 'needs_validation', fingerprint, title: 'Order lookup may be unscoped', description: 'd', claimed_root_cause: 'findById without owner',
  trace: [{ step: 'sink', file: 'src/orders.ts', line: 2, quote: 'return db.orders.findById(id);', scope: 'getOrder', note: 'n' }],
  evidence: [{ file: 'src/orders.ts', line: 2, quote: 'db.orders.findById(id)', note: 'n' }],
  blockers: ['route middleware not visible'], validation_plan: { local: 'two-tenant test' },
});

test('estimate reports agents and token range', () => {
  const { target } = setup();
  const out = rs('estimate', target, '--profile', 'deep');
  assert.match(out, /agents/); assert.match(out, /tokens processed: ~\S+-\S+/);
});

test('assign → ingest → decide → assemble, with independence enforced', () => {
  const { run, ids } = setup();
  assert.match(rs('assign', run, 'hunter-1', ...ids), /assigned 2/);
  rsFail('assign', run, 'hunter-1', ids[0]); // reused agent id
  const result = { units: [
    { id: ids[0], disposition: 'candidate', paths: ['src/orders.ts'], checks: [check], fingerprints: [fp], open: [] },
    { id: ids[1], disposition: 'covered', paths: ['src/orders.ts'], checks: [check], fingerprints: [], open: [] },
  ], candidates: [{ proposed: 'needs_validation', ...record() }], hardening: ['add an index'], uncovered: [{ surface: 'x', boundary: 'y', subsystem: 'z', class: 'c', start_paths: ['src/x.ts'], why: 'w' }] };
  const resFile = path.join(tmp('res'), 'result.json');
  fs.writeFileSync(resFile, JSON.stringify(result));
  assert.match(rs('ingest', run, 'hunter-1', resFile), /2 unit\(s\), 1 new candidate/);
  const ledger = readJson(run, 'ledger.json');
  assert.deepStrictEqual(ledger.map((u) => u.status).sort(), ['candidate', 'covered']);
  assert.ok(fs.existsSync(path.join(run, 'queue', 'uncovered.jsonl')));
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
  fs.writeFileSync(f, JSON.stringify({ units: [{ id: ids[0], disposition: 'candidate', paths: ['src/orders.ts'], checks: [check], fingerprints: [fp], open: [] }], candidates: [] }));
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

test('recover: ingests saved results, frees lost agents, removes partial writes', () => {
  const { run, ids } = setup();
  rs('assign', run, 'hunter-1', ids[0]);
  rs('assign', run, 'hunter-2', ids[1]);
  // hunter-1 finished but the session crashed before ingest; hunter-2 never returned.
  fs.writeFileSync(path.join(run, 'agents', 'hunter-1', 'result.json'), JSON.stringify({ units: [{ id: ids[0], disposition: 'covered', paths: ['src/orders.ts'], checks: [check], fingerprints: [], open: [] }], candidates: [] }));
  fs.writeFileSync(path.join(run, 'ledger.json.tmp-999'), 'partial');
  const out = rs('recover', run);
  assert.match(out, /removed partial write/); assert.match(out, /ingested hunter-1/); assert.match(out, /1 unit\(s\) from lost agents/);
  const by = Object.fromEntries(readJson(run, 'ledger.json').map((u) => [u.id, u]));
  assert.strictEqual(by[ids[0]].status, 'covered');
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
