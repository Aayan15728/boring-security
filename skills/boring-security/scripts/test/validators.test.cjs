'use strict';
// Run: node --test skills/boring-security/scripts/test/
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { Reporter, lintSchema, loadJson } = require('../lib.cjs');
const { validateFindings, crossCheckLedger } = require('../check-findings.cjs');
const { validateLedger, checkRun, deriveId } = require('../check-ledger.cjs');
const { toSarif } = require('../to-sarif.cjs');

const clone = (o) => JSON.parse(JSON.stringify(o));
const OPTS = { runDir: os.tmpdir(), checkFiles: false, checkBlocks: true };

function runF(data) { const r = new Reporter(); validateFindings(data, r); return r.errors; }
function runL(data, opts = OPTS) { const r = new Reporter(); validateLedger(data, r, opts); return r.errors; }

// ---------- fixtures ----------
const trace = [
  { step: 'entrypoint', file: 'src/routes/orders.ts', line: 12, quote: 'q', scope: 'GET /orders/:id', note: 'id from path' },
  { step: 'propagation', file: 'src/services/orders.ts', line: 40, quote: 'q', scope: 'getOrder', note: 'no owner filter' },
  { step: 'sink', file: 'src/db/orders.ts', line: 8, quote: 'q', scope: 'findById', note: 'returns any tenant row' },
];
const evidence = [{ file: 'src/services/orders.ts', line: 40, quote: 'q', note: 'query lacks tenant_id' }];

const confirmed = {
  verdict: 'confirmed',
  fingerprint: 'idor:src/services/orders.ts:getOrder',
  title: 'Any user can read any order',
  description: 'Order lookup is not scoped to the caller.',
  root_cause: 'getOrder queries by id only.',
  intended_behavior: 'Users read only their own orders.',
  trace, evidence,
  conditions: [{ kind: 'authentication', note: 'any logged-in user' }],
  execution: { attacker: 'dummy user A', payloads: ['GET /orders/2 as A'], steps: 'framework test client, two dummy tenants', observed_result: 'order 2 of tenant B returned' },
  remediation: { strategy: 'filter by caller tenant in getOrder', code_changes: [{ file: 'src/services/orders.ts', change: 'add where tenant_id = ctx.tenant' }], regression_test: 'A cannot read B order' },
  severity: { likelihood: { level: 'high', why: 'trivial' }, impact: { level: 'high', why: 'cross-tenant read' }, overall: 'high' },
  confidence: { level: 'high', why: 'reproduced locally' },
  category: 'access-control', cwe: ['CWE-639'],
};
const nv = {
  verdict: 'needs_validation',
  fingerprint: 'mobile-exported:android/app/src/main/AndroidManifest.xml:DeepLinkActivity',
  title: 'Deep link may be exported',
  description: 'Source manifest exports it; merged manifest unavailable.',
  claimed_root_cause: 'Activity exported with intent filter accepting token param.',
  trace: [trace[0]], evidence,
  blockers: ['final merged manifest not available'],
  validation_plan: { local: 'build debug variant in sandbox and read merged manifest' },
};
const rejected = {
  verdict: 'rejected',
  fingerprint: 'xss:src/views/profile.tsx:Bio',
  title: 'Bio XSS', description: 'Suspected raw HTML.',
  claimed_root_cause: 'bio rendered raw', trace: [trace[2]], evidence,
  reason: 'React escapes; no dangerouslySetInnerHTML on path.',
};
const findings = [confirmed, nv, rejected].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1));

function unit(over = {}) {
  const refs = { surface: 'src/routes/orders.ts#GET /orders/:id', boundary: 'src/auth/guard.ts#requireUser', subsystem: 'packages/api', class: 'core-classes.md#Access control', ...(over.refs || {}) };
  const u = {
    id: deriveId(refs), refs,
    labels: { surface: 'Get order', boundary: 'User guard', subsystem: 'API', class: 'Access control', ...(over.labels || {}) },
    start_paths: ['src/routes/orders.ts'],
    class_block: 'core-classes.md#Access control',
    pack_blocks: ['packs/web-and-identity.md#Discipline', 'packs/web-and-identity.md#JWT verification and claim binding', 'packs/web-and-identity.md#Moves', 'packs/web-and-identity.md#Gate'],
    skipped_blocks: [{ block: 'packs/web-and-identity.md#SAML assertion binding', why: 'no SAML' }],
    prior: 'none', wave: 1, status: 'planned', owner: null, paths: [], checks: [], fingerprints: [], open: [], history: [],
  };
  const { refs: _r, labels: _l, ...rest } = over;
  return Object.assign(u, rest);
}
const srcCheck = { by: 'hunter-1', paths: ['src/services/orders.ts'], invariant: 'tenant scope', method: 'source', result: 'missing', evidence: null };

// ---------- findings ----------
test('valid findings pass', () => assert.deepStrictEqual(runF(findings), []));
test('unsorted findings fail', () => assert.match(runF([...findings].reverse()).join('\n'), /sorted/));
test('duplicate fingerprint fails', () => assert.match(runF([confirmed, confirmed]).join('\n'), /duplicate/));
test('overall above impact fails', () => {
  const c = clone(confirmed); c.severity.overall = 'critical';
  assert.match(runF([c]).join('\n'), /exceeds demonstrated impact/);
});
test('needs_validation with severity fails', () => {
  const n = clone(nv); n.severity = confirmed.severity;
  assert.match(runF([n]).join('\n'), /unexpected property "severity"/);
});
test('needs_validation without plan fails', () => {
  const n = clone(nv); n.validation_plan = {};
  assert.match(runF([n]).join('\n'), /at least 1 propert/);
});
test('confirmed using claimed_root_cause fails', () => {
  const c = clone(confirmed); c.claimed_root_cause = 'x';
  assert.match(runF([c]).join('\n'), /unexpected property/);
});
test('trace order enforced', () => {
  const c = clone(confirmed); c.trace = [trace[1], trace[2]];
  assert.match(runF([c]).join('\n'), /start with entrypoint/);
});
test('absolute and traversal paths rejected', () => {
  for (const bad of ['/etc/passwd', 'C:/x.ts', '../x.ts', 'a\\b.ts', 'a//b.ts']) {
    const c = clone(confirmed); c.evidence = [{ file: bad, line: 1, quote: 'q', note: 'x' }];
    assert.match(runF([c]).join('\n'), /repo-relative/, bad);
  }
});
test('bad fingerprint rejected', () => {
  const c = clone(confirmed); c.fingerprint = '-bad fp';
  assert.match(runF([c]).join('\n'), /fingerprint/);
});

// ---------- ledger ----------
test('planned unit passes', () => assert.deepStrictEqual(runL([unit()]), []));
test('id must match derivation', () => {
  const u = unit(); u.id = 'nope';
  assert.match(runL([u]).join('\n'), /canonical derivation/);
});
test('percent encoding is uppercase and keeps unreserved', () => {
  assert.strictEqual(deriveId({ surface: 'a b', boundary: 'é', subsystem: 'x-y_z.~', class: 'f.md#C' }), 'a%20b::%C3%A9::x-y_z.~::f.md%23C');
});
test('lifecycle appended', () => {
  const u = unit({ refs: { lifecycle: 'lifecycle#restore' }, labels: { lifecycle: 'Restore' } });
  assert.ok(u.id.endsWith('::lifecycle%23restore'));
  assert.deepStrictEqual(runL([u]), []);
});
test('non-NFC ref rejected', () => {
  const u = unit({ refs: { subsystem: 'cafe\u0301' } });
  assert.match(runL([u]).join('\n'), /NFC/);
});
test('duplicate ids rejected', () => assert.match(runL([unit(), unit()]).join('\n'), /duplicate id/));
test('unknown block rejected', () => {
  const u = unit({ class_block: 'core-classes.md#Nonexistent' });
  assert.match(runL([u]).join('\n'), /not found/);
});
test('pack selection requires Discipline/Moves/Gate', () => {
  const u = unit({ pack_blocks: ['packs/mobile.md#Exported component overreach'] });
  const e = runL([u]).join('\n');
  assert.match(e, /packs\/mobile.md#Discipline/); assert.match(e, /packs\/mobile.md#Gate/);
});
test('covered unit with checks passes', () => {
  const u = unit({ status: 'covered', owner: 'hunter-1', paths: ['src/services/orders.ts'], checks: [srcCheck] });
  assert.deepStrictEqual(runL([u]), []);
});
test('covered without checks fails', () => {
  const u = unit({ status: 'covered', owner: 'hunter-1' });
  assert.match(runL([u]).join('\n'), /covered: needs paths and checks/);
});
test('paths must equal union of check paths', () => {
  const u = unit({ status: 'covered', owner: 'hunter-1', paths: ['src/other.ts'], checks: [srcCheck] });
  assert.match(runL([u]).join('\n'), /union/);
});
test('candidate needs fingerprint', () => {
  const u = unit({ status: 'candidate', owner: 'hunter-1', paths: ['src/services/orders.ts'], checks: [srcCheck] });
  assert.match(runL([u]).join('\n'), /at least one fingerprint/);
});
test('deferred needs reason', () => assert.match(runL([unit({ status: 'deferred' })]).join('\n'), /reason/));
test('windows device agent id rejected', () => {
  const u = unit({ status: 'in_progress', owner: 'com1' });
  assert.match(runL([u]).join('\n'), /canonical agent id/);
});
test('local evidence must be under the check author dir', () => {
  const c = { ...srcCheck, method: 'local', evidence: 'agents/someone-else/evidence/out.txt' };
  const u = unit({ status: 'covered', owner: 'hunter-1', paths: ['src/services/orders.ts'], checks: [c] });
  assert.match(runL([u]).join('\n'), /agents\/hunter-1\/evidence/);
});
test('local evidence file checked on disk', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-'));
  fs.mkdirSync(path.join(dir, 'agents', 'hunter-1', 'evidence'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'agents', 'hunter-1', 'evidence', 'out.txt'), 'ok');
  const c = { ...srcCheck, method: 'local', evidence: 'agents/hunter-1/evidence/out.txt' };
  const u = unit({ status: 'covered', owner: 'hunter-1', paths: ['src/services/orders.ts'], checks: [c] });
  assert.deepStrictEqual(runL([u], { ...OPTS, runDir: dir, checkFiles: true }), []);
  const c2 = { ...c, evidence: 'agents/hunter-1/evidence/missing.txt' };
  assert.match(runL([unit({ status: 'covered', owner: 'hunter-1', paths: ['src/services/orders.ts'], checks: [c2] })], { ...OPTS, runDir: dir, checkFiles: true }).join('\n'), /does not exist/);
});
test('history requires fresh owner and lower waves', () => {
  const archived = { wave: 1, status: 'covered', owner: 'hunter-1', paths: ['src/services/orders.ts'], checks: [srcCheck], fingerprints: [], open: [], reopen_reason: 'missed batch path' };
  const ok = unit({ wave: 2, status: 'in_progress', owner: 'hunter-2', history: [archived] });
  assert.deepStrictEqual(runL([ok]), []);
  const sameOwner = unit({ wave: 2, status: 'in_progress', owner: 'hunter-1', history: [archived] });
  assert.match(runL([sameOwner]).join('\n'), /fresh owner/);
  const badWave = unit({ wave: 1, status: 'in_progress', owner: 'hunter-2', history: [archived] });
  assert.match(runL([badWave]).join('\n'), /below the live wave/);
});

// ---------- cross-check + sarif ----------
test('findings must link to ledger fingerprints', () => {
  const r = new Reporter();
  crossCheckLedger(findings, [unit()], r);
  assert.ok(r.errors.length === 3);
});
test('sarif skips rejected and maps severity', () => {
  const s = toSarif(findings);
  const res = s.runs[0].results;
  assert.strictEqual(res.length, 2);
  const c = res.find((x) => x.properties.verdict === 'confirmed');
  assert.strictEqual(c.level, 'error');
  assert.strictEqual(c.locations[0].physicalLocation.artifactLocation.uri, 'src/db/orders.ts');
  assert.strictEqual(res.find((x) => x.properties.verdict === 'needs_validation').kind, 'review');
});

// ---------- CLI smoke ----------
test('CLIs exit 0 on valid input and 1 on invalid', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-cli-'));
  const f = path.join(dir, 'findings.json');
  const l = path.join(dir, 'ledger.json');
  fs.writeFileSync(f, JSON.stringify(findings));
  fs.writeFileSync(l, JSON.stringify([unit()]));
  const node = process.execPath;
  const S = path.resolve(__dirname, '..');
  execFileSync(node, [path.join(S, 'check-findings.cjs'), f], { stdio: 'pipe' });
  execFileSync(node, [path.join(S, 'check-ledger.cjs'), l], { stdio: 'pipe' });
  const sarif = execFileSync(node, [path.join(S, 'to-sarif.cjs'), f], { stdio: 'pipe' }).toString();
  assert.strictEqual(JSON.parse(sarif).version, '2.1.0');
  fs.writeFileSync(f, JSON.stringify([{ verdict: 'nope' }]));
  assert.throws(() => execFileSync(node, [path.join(S, 'check-findings.cjs'), f], { stdio: 'pipe' }));
});

test('promote copies a regular file and refuses traversal', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-prom-'));
  const scratch = path.join(dir, 'scratch'); const ev = path.join(dir, 'evidence');
  fs.mkdirSync(path.join(scratch, 'out'), { recursive: true }); fs.mkdirSync(ev);
  fs.writeFileSync(path.join(scratch, 'out', 'r.txt'), 'result');
  const P = path.resolve(__dirname, '..', 'promote.cjs');
  execFileSync(process.execPath, [P, scratch, ev, 'out/r.txt', '100'], { stdio: 'pipe' });
  assert.strictEqual(fs.readFileSync(path.join(ev, 'out', 'r.txt'), 'utf8'), 'result');
  assert.throws(() => execFileSync(process.execPath, [P, scratch, ev, '../x', '100'], { stdio: 'pipe' }));
  assert.throws(() => execFileSync(process.execPath, [P, scratch, ev, 'out/r.txt', '100'], { stdio: 'pipe' }), 'second promotion must not overwrite');
  fs.writeFileSync(path.join(scratch, 'big.txt'), 'x'.repeat(200));
  assert.throws(() => execFileSync(process.execPath, [P, scratch, ev, 'big.txt', '100'], { stdio: 'pipe' }));
});

// ---------- schema-driven checks and input hardening ----------
const NL = '\n';
test('schema engine rejects unknown keywords', () => {
  const errs = []; lintSchema({ type: 'string', format: 'email' }, 's', errs);
  assert.match(errs.join(), /unsupported keyword "format"/);
});
test('invisible-only text rejected', () => {
  const c = clone(confirmed); c.title = '​ ​';
  assert.match(runF([c]).join(NL), /visible text/);
});
test('duplicate blockers rejected', () => {
  const n = clone(nv); n.blockers = ['x', 'x'];
  assert.match(runF([n]).join(NL), /unique/);
});
test('unknown verdict reports no matching variant', () => assert.match(runF([{ verdict: 'maybe' }]).join(NL), /no allowed variant/));
test('invalid UTF-8 input rejected', () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-utf-')), 'f.json');
  fs.writeFileSync(f, Buffer.from([0x5b, 0x22, 0xff, 0x22, 0x5d]));
  const r = new Reporter(); loadJson(f, r);
  assert.match(r.errors.join(), /UTF-8/);
});
test('symlinked input rejected', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-ln-'));
  fs.writeFileSync(path.join(dir, 'real.json'), '[]');
  try { fs.symlinkSync(path.join(dir, 'real.json'), path.join(dir, 'link.json')); } catch { t.skip('symlinks not permitted here'); return; }
  const r = new Reporter(); loadJson(path.join(dir, 'link.json'), r);
  assert.match(r.errors.join(), /symlink/);
});

// ---------- ledger: duplicates, collisions, archived evidence, run.json ----------
test('duplicate start_paths and pack_blocks rejected', () => {
  const u = unit({ start_paths: ['a.ts', 'a.ts'] }); u.pack_blocks.push(u.pack_blocks[0]);
  const e = runL([u]).join(NL); assert.match(e, /start_paths contains duplicates/); assert.match(e, /pack_blocks: contains duplicates/);
});
test('same labels under different refs rejected', () => {
  const a = unit(); const b = unit({ refs: { boundary: 'src/auth/other.ts#requireUser' } });
  const units = [a, b].sort((x, y) => (x.id < y.id ? -1 : 1));
  assert.match(runL(units).join(NL), /different refs/);
});
test('archived owner checks and evidence stay archived', () => {
  const localOld = { ...srcCheck, method: 'local', evidence: 'agents/hunter-1/evidence/o.txt' };
  const archived = { wave: 1, status: 'covered', owner: 'hunter-1', paths: ['src/services/orders.ts'], checks: [localOld], fingerprints: [], open: [], reopen_reason: 'missed path' };
  const u = unit({ wave: 2, status: 'covered', owner: 'hunter-2', paths: ['src/services/orders.ts'], checks: [srcCheck], history: [archived] });
  assert.match(runL([u]).join(NL), /archived owner "hunter-1"/);
  const reused = { ...localOld, by: 'hunter-2' };
  const u2 = unit({ wave: 2, status: 'covered', owner: 'hunter-2', paths: ['src/services/orders.ts'], checks: [reused], history: [archived] });
  assert.match(runL([u2]).join(NL), /agents\/hunter-2\/evidence/);
});
test('quick profile pins the subsystem; other profiles forbid it', () => {
  assert.match(runL([unit()], { ...OPTS, profile: 'quick' }).join(NL), /quick profile requires/);
  const q = unit({ refs: { subsystem: 'profile/quick/all' } });
  assert.deepStrictEqual(runL([q], { ...OPTS, profile: 'quick' }), []);
  assert.match(runL([q], { ...OPTS, profile: 'standard' }).join(NL), /only valid in the quick profile/);
});
test('complete run cannot have planned units', () => assert.match(runL([unit()], { ...OPTS, status: 'complete' }).join(NL), /says complete/));
test('run.json enums enforced', () => {
  const base = { run_id: 'r', repo: 'x', target: '/t', source_ref: {}, profile: 'standard', scope: { kind: 'full' }, execution: 'source-only', status: 'in_progress', incomplete_reason: null };
  const ok = new Reporter(); checkRun(base, ok); assert.deepStrictEqual(ok.errors, []);
  const bad = new Reporter(); checkRun({ ...base, status: 'incomplete', incomplete_reason: 'tired' }, bad);
  assert.match(bad.errors.join(), /incomplete_reason/);
});
test('unlinked ledger candidate is fatal when run is complete', () => {
  const u = unit({ status: 'candidate', owner: 'hunter-1', paths: ['src/services/orders.ts'], checks: [srcCheck], fingerprints: ['idor:x:y'] });
  const r = new Reporter(); crossCheckLedger([], [u], r, 'complete'); assert.match(r.errors.join(), /says complete/);
  const r2 = new Reporter(); crossCheckLedger([], [u], r2, 'in_progress'); assert.strictEqual(r2.errors.length, 0);
});

// ---------- Cloudflare tracker regressions (#126, #143, #150) and spec checklists ----------
test('unit class must be a block its hunter receives', () => {
  const u = unit({ class_block: 'core-classes.md#Injection' });
  assert.match(runL([u]).join(NL), /neither class_block nor in pack_blocks/);
});
test('archived verifier cannot reappear in the live attempt', () => {
  const verifierCheck = { ...srcCheck, by: 'skeptic-9' };
  const archived = { wave: 1, status: 'covered', owner: 'hunter-1', paths: ['src/services/orders.ts'], checks: [srcCheck, verifierCheck], fingerprints: [], open: [], reopen_reason: 'r' };
  const u = unit({ wave: 2, status: 'covered', owner: 'hunter-2', paths: ['src/services/orders.ts'], checks: [{ ...srcCheck, by: 'skeptic-9' }], history: [archived] });
  assert.match(runL([u]).join(NL), /archived owner "skeptic-9"/);
});
test('identity spec sections are valid blocks and need no Discipline/Moves/Gate', () => {
  const u = unit({ pack_blocks: [...unit().pack_blocks, 'references/identity-specs.md#JWT and JWS'] });
  assert.deepStrictEqual(runL([u]), []);
});
test('unknown verdict is named in the error', () => assert.match(runF([{ verdict: 'maybe' }]).join(NL), /verdict "maybe" is not one of/));
