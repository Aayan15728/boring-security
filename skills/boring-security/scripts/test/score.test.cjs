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
  trace: tr, evidence: ev, conditions: [], execution: { attacker: 'a', payloads: ['p'], steps: 's', observed_result: 'o' },
  remediation: { strategy: 'Scope the query by owner. Then add tests.', code_changes: [{ file: 'src/db.ts', change: 'c' }], regression_test: 'B cannot read A order' },
  severity: { likelihood: { level: 'high', why: 'w' }, impact: { level: 'high', why: 'w' }, overall: 'high' }, confidence: { level: 'high', why: 'w' } };
const nv = { verdict: 'needs_validation', fingerprint: 'race:src/w.ts:debit', title: 'Wallet debit may race', description: 'd', claimed_root_cause: 'c',
  trace: [tr[0]], evidence: ev, blockers: ['isolation level unknown'], validation_plan: { local: 'two-connection harness' } };
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
  assert.strictEqual(s.partial, false);
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
  assert.match(md, /\| 1 \| high \| Any user reads any order \| `src\/db\.ts:9` \(findOrder\); change `src\/db\.ts` \| Scope the query by owner\. \| B cannot read A order \|/);
  assert.match(md, /## Verify next/);
  assert.match(md, /isolation level unknown/);
});

test('CLI refuses invalid findings', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-score-'));
  fs.writeFileSync(path.join(dir, 'run.json'), JSON.stringify(run));
  fs.writeFileSync(path.join(dir, 'ledger.json'), JSON.stringify(ledger));
  fs.writeFileSync(path.join(dir, 'findings.json'), JSON.stringify([nv, high].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1))));
  const S = path.resolve(__dirname, '..', 'score.cjs');
  assert.match(execFileSync(process.execPath, [S, dir]).toString(), /Overall: \d+\/100/);
  fs.writeFileSync(path.join(dir, 'findings.json'), JSON.stringify([{ verdict: 'nope' }]));
  assert.throws(() => execFileSync(process.execPath, [S, dir], { stdio: 'pipe' }));
});
