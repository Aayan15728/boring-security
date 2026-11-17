'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { toSarif, skillVersion, readSkillVersion, relUri } = require('../to-sarif.cjs');
const { Reporter } = require('../lib.cjs');
const { validateFindings } = require('../check-findings.cjs');

const SCRIPT = path.resolve(__dirname, '..', 'to-sarif.cjs');
const tr = [
  { step: 'entrypoint', file: 'src/routes/orders.ts', line: 3, quote: 'q', scope: 'GET /o/:id', note: 'n' },
  { step: 'sink', file: 'src/db.ts', line: 9, quote: 'q', scope: 'findOrder', note: 'n' },
];
const ev = [{ file: 'src/db.ts', line: 9, quote: 'q', note: 'n' }];
const confirmed = {
  verdict: 'confirmed', fingerprint: 'idor:src/db.ts:findOrder', title: 'Any user reads any order', description: 'd',
  root_cause: 'The query is not scoped by owner.', intended_behavior: 'i', trace: tr, evidence: ev, conditions: [],
  execution: { attacker: 'a', payloads: ['p'], steps: 's', observed_result: 'o', proof: 'static' },
  remediation: { strategy: 'Scope the query by owner.', code_changes: [{ file: 'src/db.ts', change: 'c' }], regression_test: 'B cannot read A order' },
  severity: { likelihood: { level: 'high', why: 'w' }, impact: { level: 'high', why: 'w' }, overall: 'high' },
  confidence: { level: 'high', why: 'w' }, category: 'idor', cwe: ['CWE-639'],
};
const needs = {
  verdict: 'needs_validation', fingerprint: 'race:src/w.ts:debit', title: 'Wallet debit may race', description: 'd',
  claimed_root_cause: 'No row lock.', trace: [tr[0]], evidence: ev, blockers: ['isolation level unknown'],
  validation_plan: { local: 'two-connection harness' }, max_impact_if_true: 'high',
};
const rejected = { verdict: 'rejected', fingerprint: 'xss:src/v.ts:render', title: 't', description: 'd', claimed_root_cause: 'c', trace: [tr[0]], evidence: ev, reason: 'sanitised upstream' };

// If this checkout's validator has not learned the new optional fields yet, drop them for the CLI test.
function diskRecords(recs) {
  const copy = JSON.parse(JSON.stringify(recs));
  const rep = new Reporter();
  validateFindings(copy, rep);
  if (rep.errors.some((e) => /unexpected property "(proof|max_impact_if_true)"/.test(e))) {
    for (const r of copy) { delete r.max_impact_if_true; if (r.execution) delete r.execution.proof; }
  }
  return copy;
}

// Structural checks for what GitHub code scanning requires of a SARIF 2.1.0 log.
function assertSarifShape(log, expectedResults) {
  assert.strictEqual(log.version, '2.1.0');
  assert.match(log.$schema, /sarif-2\.1\.0/);
  assert.strictEqual(log.runs.length, 1);
  const run = log.runs[0];
  assert.ok(!('originalUriBaseIds' in run), 'no bogus base: artifact URIs are repo-relative');
  assert.strictEqual(run.tool.driver.name, 'boring-security');
  assert.ok(Array.isArray(run.tool.driver.rules));
  assert.strictEqual(run.results.length, expectedResults);
  const ruleIds = run.tool.driver.rules.map((r) => r.id);
  assert.strictEqual(new Set(ruleIds).size, ruleIds.length, 'rule ids unique');
  const checkLoc = (l) => {
    const al = l.physicalLocation.artifactLocation;
    assert.strictEqual(al.uriBaseId, '%SRCROOT%');
    assert.ok(!/^[a-z][a-z0-9+.-]*:/i.test(al.uri), `uri has no scheme: ${al.uri}`);
    assert.ok(!al.uri.startsWith('/') && !al.uri.includes('\\'), `uri is repo-relative: ${al.uri}`);
    assert.ok(Number.isInteger(l.physicalLocation.region.startLine) && l.physicalLocation.region.startLine >= 1);
    assert.ok(l.message && typeof l.message.text === 'string' && l.message.text.length > 0);
  };
  for (const r of run.results) {
    assert.strictEqual(ruleIds[r.ruleIndex], r.ruleId, 'ruleIndex points at ruleId');
    assert.ok(['error', 'warning', 'note', 'none'].includes(r.level));
    assert.ok(['fail', 'review', 'pass', 'open', 'notApplicable', 'informational'].includes(r.kind));
    assert.ok(r.message.text.length > 0);
    assert.strictEqual(r.locations.length, 1);
    r.locations.forEach(checkLoc);
    assert.ok(r.partialFingerprints['boringSecurity/v1']);
    for (const f of r.codeFlows) for (const tf of f.threadFlows) tf.locations.forEach((tl) => checkLoc(tl.location));
  }
  return run;
}

test('confirmed record: error level, fail kind, severity score, proof, repo-relative sink location', () => {
  const run = assertSarifShape(toSarif([confirmed], '9.9.9'), 1);
  const r = run.results[0];
  assert.strictEqual(run.tool.driver.version, '9.9.9');
  assert.strictEqual(r.ruleId, 'idor');
  assert.strictEqual(r.level, 'error');
  assert.strictEqual(r.kind, 'fail');
  assert.deepStrictEqual(r.locations[0].physicalLocation.artifactLocation, { uri: 'src/db.ts', uriBaseId: '%SRCROOT%' });
  assert.strictEqual(r.locations[0].physicalLocation.region.startLine, 9);
  assert.strictEqual(r.codeFlows[0].threadFlows[0].locations.length, 2);
  assert.strictEqual(r.properties.proof, 'static');
  assert.strictEqual(r.properties['security-severity'], '8.0');
  assert.strictEqual(r.properties.severity, 'high');
  assert.ok(!('max_impact_if_true' in r.properties));
  assert.deepStrictEqual(run.tool.driver.rules[0].properties.tags, ['security', 'external/cwe/cwe-639']);
});

test('needs_validation record: note level, review kind, no severity, max_impact_if_true as hint', () => {
  const run = assertSarifShape(toSarif([needs], '1.0.0'), 1);
  const r = run.results[0];
  assert.strictEqual(r.level, 'note');
  assert.strictEqual(r.kind, 'review');
  assert.match(r.message.text, /^\[needs validation\]/);
  assert.strictEqual(r.properties.max_impact_if_true, 'high');
  assert.ok(!('security-severity' in r.properties) && !('severity' in r.properties) && !('proof' in r.properties));
});

test('new optional fields may be absent; rejected records are skipped; one rule per category', () => {
  const noProof = JSON.parse(JSON.stringify(confirmed)); delete noProof.execution.proof;
  const noHint = JSON.parse(JSON.stringify(needs)); delete noHint.max_impact_if_true;
  const run = assertSarifShape(toSarif([noProof, noHint, rejected], null), 2);
  assert.ok(!('proof' in run.results[0].properties));
  assert.ok(!('max_impact_if_true' in run.results[1].properties));
  assert.ok(!('version' in run.tool.driver), 'unknown version is omitted, not invented');
});

test('proof and hint are not mixed across verdicts', () => {
  const wrong = JSON.parse(JSON.stringify(confirmed)); wrong.max_impact_if_true = 'critical';
  assert.ok(!('max_impact_if_true' in toSarif([wrong], null).runs[0].results[0].properties));
});

test('relUri normalises to repo-relative forward-slash URIs', () => {
  assert.strictEqual(relUri('src/a b/c.ts'), 'src/a%20b/c.ts');
  assert.strictEqual(relUri('.\\src\\a.ts'), 'src/a.ts');
  assert.strictEqual(relUri('/src/a.ts'), 'src/a.ts');
});

test('version is read from SKILL.md metadata and matches the shipped file', () => {
  assert.strictEqual(skillVersion('---\nname: x\nmetadata:\n  version: "1.2.3"\n  credits: "c"\n---\n# b\nversion: "9"'), '1.2.3');
  assert.strictEqual(skillVersion('---\r\nmetadata:\r\n  credits: c\r\n  version: 0.4.0 # note\r\n---\r\n'), '0.4.0');
  assert.strictEqual(skillVersion('---\nname: x\nversion: "7.7.7"\n---\n'), null, 'only metadata.version counts');
  assert.strictEqual(skillVersion('no front matter'), null);
  assert.strictEqual(readSkillVersion(path.join(os.tmpdir(), 'does-not-exist-bsec', 'SKILL.md')), null);
  const text = fs.readFileSync(path.resolve(__dirname, '..', '..', 'SKILL.md'), 'utf8');
  assert.strictEqual(readSkillVersion(), skillVersion(text));
  assert.match(readSkillVersion(), /^\d+\.\d+\.\d+/);
  assert.ok(!/0\.3\.0/.test(fs.readFileSync(SCRIPT, 'utf8')), 'no hardcoded version');
});

test('CLI converts valid findings and refuses invalid input', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-sarif-'));
  const file = path.join(dir, 'findings.json');
  const recs = [needs, confirmed].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1));
  fs.writeFileSync(file, JSON.stringify(diskRecords(recs)));
  const ok = spawnSync(process.execPath, [SCRIPT, file], { encoding: 'utf8' });
  assert.strictEqual(ok.status, 0, ok.stderr);
  const run = assertSarifShape(JSON.parse(ok.stdout), 2);
  assert.strictEqual(run.tool.driver.version, readSkillVersion());

  fs.writeFileSync(file, JSON.stringify([{ verdict: 'nope' }]));
  const bad = spawnSync(process.execPath, [SCRIPT, file], { encoding: 'utf8' });
  assert.strictEqual(bad.status, 1);
  assert.strictEqual(bad.stdout, '', 'nothing is written for invalid input');
  assert.strictEqual(spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8' }).status, 2);
});
