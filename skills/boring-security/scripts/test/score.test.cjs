'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { score, toMarkdown, grade } = require('../score.cjs');
const { deriveId } = require('../check-ledger.cjs');

const run = { run_id: 'r1', repo: 'x', target: '/t', source_ref: {}, profile: 'standard', scope: { kind: 'full' }, execution: 'source-only', status: 'complete', incomplete_reason: null };
const check = { by: 'h1', paths: ['src/a.ts'], invariant: 'i', method: 'source', result: 'r', evidence: null };
function unit(cls, status, fps = []) {
  const refs = { surface: `s#${cls}`, boundary: 'b', subsystem: 'api', class: cls };
  const reviewed = ['covered', 'candidate', 'blocked'].includes(status);
  return { id: deriveId(refs), refs, status, owner: reviewed ? 'h1' : null, paths: reviewed ? ['src/a.ts'] : [], checks: reviewed ? [check] : [],
    fingerprints: fps, open: status === 'blocked' ? ['no sandbox'] : [], history: [] };
}
const tr = [{ step: 'entrypoint', file: 'src/r.ts', line: 3, quote: 'q', scope: 'GET /o/:id', note: 'n' }, { step: 'sink', file: 'src/db.ts', line: 9, quote: 'q', scope: 'findOrder', note: 'n' }];
const ev = [{ file: 'src/db.ts', line: 9, quote: 'q', note: 'n' }];
const high = { verdict: 'confirmed', fingerprint: 'idor:src/db.ts:findOrder', title: 'Any user reads any order', description: 'd', root_cause: 'r', intended_behavior: 'i',
  trace: tr, evidence: ev, conditions: [], execution: { attacker: 'a', payloads: ['p'], steps: 's', observed_result: 'o', proof: 'static' },
  remediation: { strategy: 'Scope the query by owner. Then add tests.', code_changes: [{ file: 'src/db.ts', change: 'c' }], regression_test: 'B cannot read A order' },
  severity: { likelihood: { level: 'high', why: 'w' }, impact: { level: 'high', why: 'w' }, overall: 'high' }, confidence: { level: 'high', why: 'w' } };
const nv = { verdict: 'needs_validation', fingerprint: 'race:src/w.ts:debit', title: 'Wallet debit may race', description: 'd', claimed_root_cause: 'c',
  trace: [tr[0]], evidence: ev, blockers: ['isolation level unknown'], validation_plan: { local: 'two-connection harness' }, max_impact_if_true: 'high' };
const ledger = [
  unit('core-classes.md#Access control', 'candidate', [high.fingerprint]),
  unit('core-classes.md#Access control', 'covered'),
  unit('packs/data-integrity.md#Lost updates on counters and balances', 'candidate', [nv.fingerprint]),
  unit('packs/mobile.md#Exported component overreach', 'planned'),
];

test('grades', () => assert.deepStrictEqual([95, 85, 70, 55, 10].map(grade), ['A', 'B', 'C', 'D', 'F']));

test('area scores, caps, not-assessed and weakest point', () => {
  const s = score(run, ledger, [high, nv]);
  const by = Object.fromEntries(s.rows.map((r) => [r.area, r]));
  assert.strictEqual(by['Access control'].score, 59, 'one confirmed high caps the area at 59');
  assert.strictEqual(by['Access control'].grade, 'D');
  assert.match(by['Access control'].weakest, /Any user reads any order \(high\)/);
  assert.strictEqual(by['Data integrity'].score, 97);
  assert.match(by['Data integrity'].weakest, /^Unverified/);
  assert.strictEqual(by.Mobile.score, null, 'unreviewed area is not assessed, never 100');
  assert.ok(s.overall <= 59, 'overall capped by a confirmed high');
  assert.strictEqual(s.partial, true, 'a planned unit is unreviewed, so the pass is partial');
  assert.strictEqual(s.coverage.percent, 75);
  assert.strictEqual(s.coverage.planned, 1);
});

test('partial runs are labelled and critical caps at 29', () => {
  const crit = JSON.parse(JSON.stringify(high));
  crit.severity = { likelihood: { level: 'high', why: 'w' }, impact: { level: 'critical', why: 'w' }, overall: 'critical' };
  const s = score({ ...run, profile: 'quick' }, ledger, [crit]);
  assert.ok(s.overall <= 29 && s.partial);
});

test('markdown has scorecard, fix plan with where/how/test, and verify-next', () => {
  const md = toMarkdown(score(run, ledger, [high, nv]), run);
  assert.match(md, /## Scorecard/);
  assert.ok(md.includes('| 1 | high | static | Any user reads any order | `src/db.ts:9` (findOrder); change `src/db.ts` | Scope the query by owner. | B cannot read A order |'));
  assert.match(md, /## Verify next/);
  assert.match(md, /isolation level unknown/);
});

function ledgerOf(spec) {
  // spec: [[class, status, count], ...] -> units with distinct surfaces
  const out = [];
  for (const [cls, status, n] of spec) for (let i = 0; i < n; i++) {
    const u = unit(cls, status);
    u.refs = { ...u.refs, surface: `s#${cls}#${i}` };
    u.id = deriveId(u.refs);
    out.push(u);
  }
  return out;
}
const ACC = 'core-classes.md#Access control';

test('1 covered + 9 deferred and no findings is not assessed, never 100/A', () => {
  const l = ledgerOf([[ACC, 'covered', 1], [ACC, 'deferred', 9]]);
  const s = score(run, l, []);
  assert.strictEqual(s.overall, null);
  assert.strictEqual(s.partial, true);
  assert.strictEqual(s.coverage.percent, 10);
  assert.strictEqual(s.coverage.deferred, 9);
  assert.strictEqual(s.rows[0].score, null);
  const md = toMarkdown(s, run);
  assert.ok(md.includes('Overall: not assessed** · coverage 10% (1 of 10 in-scope units reviewed; 9 deferred, 0 planned, 0 blocked) · partial pass'));
  assert.ok(md.includes('not assessed (coverage 10%)'));
  assert.ok(!md.includes('100/100'));
});

test('overall coverage caps: <70 -> 79, <90 -> 89, >=90 uncapped, 50% boundary', () => {
  const ov = (rev, def) => score(run, ledgerOf([[ACC, 'covered', rev], [ACC, 'deferred', def]]), []).overall;
  assert.strictEqual(ov(4, 6), null, '40% is not assessed');
  assert.strictEqual(ov(5, 5), 79, '50% assessed but capped at 79');
  assert.strictEqual(ov(69, 31), 79);
  assert.strictEqual(ov(7, 3), 89, '70% capped at 89, never an A');
  assert.strictEqual(ov(89, 11), 89);
  assert.strictEqual(ov(9, 1), 100, '90% is uncapped');
  assert.ok(toMarkdown(score(run, ledgerOf([[ACC, 'covered', 7], [ACC, 'deferred', 3]]), []), run).includes('Overall: 89/100 (B)** (capped at 89 by coverage 70%)'));
});

test('area coverage: <50 not assessed, 50-79 provisional, >=80 plain', () => {
  const l = ledgerOf([[ACC, 'covered', 2], [ACC, 'deferred', 8], ['packs/data-integrity.md#Lost updates on counters and balances', 'covered', 6], ['packs/data-integrity.md#Lost updates on counters and balances', 'deferred', 4], ['packs/mobile.md#Exported component overreach', 'covered', 9], ['packs/mobile.md#Exported component overreach', 'deferred', 1]]);
  const by = Object.fromEntries(score(run, l, []).rows.map((r) => [r.area, r]));
  assert.strictEqual(by['Access control'].score, null);
  assert.strictEqual(by['Data integrity'].score, 100);
  assert.strictEqual(by['Data integrity'].provisional, true);
  assert.strictEqual(by.Mobile.provisional, false);
  assert.ok(toMarkdown(score(run, l, []), run).includes('| 100 (provisional) |'));
});

test('partial pass is stated for incomplete, quick and scoped runs even at full coverage', () => {
  const l = ledgerOf([[ACC, 'covered', 10]]);
  const full = toMarkdown(score(run, l, []), run);
  assert.ok(full.includes('Overall: 100/100 (A)** · coverage 100% (10 of 10'));
  assert.ok(!full.includes('partial pass'));
  assert.ok(toMarkdown(score({ ...run, status: 'incomplete' }, l, []), run).includes('partial pass (status incomplete)'));
  assert.ok(toMarkdown(score({ ...run, profile: 'quick' }, l, []), run).includes('partial pass (quick profile)'));
  assert.ok(toMarkdown(score({ ...run, scope: { kind: 'diff' } }, l, []), run).includes('partial pass (diff scope)'));
});

test('blocked units count as not reviewed and are reported', () => {
  const s = score(run, ledgerOf([[ACC, 'covered', 3], [ACC, 'blocked', 1]]), []);
  assert.strictEqual(s.coverage.blocked, 1);
  assert.strictEqual(s.coverage.percent, 75);
  assert.strictEqual(s.partial, true);
});

test('verify-next sorts by max_impact_if_true then fingerprint and shows the column only when present', () => {
  const mk = (fp, impact) => { const r = { ...nv, fingerprint: fp, title: fp }; if (impact) r.max_impact_if_true = impact; else delete r.max_impact_if_true; return r; };
  const l = ledgerOf([[ACC, 'covered', 3]]);
  const s = score(run, l, [mk('a:x:1', 'low'), mk('b:x:2', 'critical'), mk('c:x:3'), mk('a:x:0', 'low')]);
  assert.deepStrictEqual(s.verifyNext.map((f) => f.fingerprint), ['b:x:2', 'a:x:0', 'a:x:1', 'c:x:3']);
  const md = toMarkdown(s, run);
  assert.ok(md.includes('| Lead | Where | If true, up to | Blocked on | How to settle |'));
  assert.ok(new RegExp('b:x:2 '+String.fromCharCode(92)+'|.*'+String.fromCharCode(92)+'| critical '+String.fromCharCode(92)+'|').test(md));
  assert.ok(md.includes('not a severity'));
  const plain = toMarkdown(score(run, l, [mk('a:x:1'), mk('b:x:2')]), run);
  assert.ok(plain.includes('| Lead | Where | Blocked on | How to settle |'));
  assert.ok(!plain.includes('If true, up to'));
});

test('fix plan shows proof column, em dash when absent, local when local', () => {
  const noProof = JSON.parse(JSON.stringify(high)); delete noProof.execution.proof; noProof.fingerprint = 'idor:src/db.ts:other';
  const local = JSON.parse(JSON.stringify(high)); local.execution.proof = 'local'; local.fingerprint = 'idor:src/db.ts:third';
  const md = toMarkdown(score(run, ledgerOf([[ACC, 'covered', 3]]), [high, noProof, local]), run);
  assert.ok(md.includes('| # | Severity | Proof | What is weak |'));
  assert.ok(md.includes('| high | static |'));
  assert.ok(md.includes('| high | local |'));
  assert.ok(md.includes('| high | — |'));
});

// The findings validator is being extended (execution.proof, max_impact_if_true); drop the new fields if this checkout still rejects them.
function diskRecords(recs) {
  const { Reporter } = require('../lib.cjs');
  const { validateFindings } = require('../check-findings.cjs');
  const copy = JSON.parse(JSON.stringify(recs));
  const rep = new Reporter();
  validateFindings(copy, rep);
  if (rep.errors.some((e) => /unexpected property "(proof|max_impact_if_true)"/.test(e))) for (const r of copy) { delete r.max_impact_if_true; if (r.execution) delete r.execution.proof; }
  return copy;
}

test('CLI refuses invalid findings', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-score-'));
  fs.writeFileSync(path.join(dir, 'run.json'), JSON.stringify(run));
  fs.writeFileSync(path.join(dir, 'ledger.json'), JSON.stringify(ledger));
  fs.writeFileSync(path.join(dir, 'findings.json'), JSON.stringify(diskRecords([nv, high].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1)))));
  const S = path.resolve(__dirname, '..', 'score.cjs');
  assert.match(execFileSync(process.execPath, [S, dir]).toString(), /Overall: \d+\/100/);
  fs.writeFileSync(path.join(dir, 'findings.json'), JSON.stringify([{ verdict: 'nope' }]));
  assert.throws(() => execFileSync(process.execPath, [S, dir], { stdio: 'pipe' }));
});
