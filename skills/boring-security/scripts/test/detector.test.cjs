'use strict';
// Run: node --test skills/boring-security/scripts/test/
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RULES = require('../detect-rules.cjs');
const { detect } = require('../detect.cjs');
const { blockProblem } = require('../check-ledger.cjs');

test('at least 60 rules, unique ids, required fields', () => {
  assert.ok(RULES.length >= 60, `only ${RULES.length} rules`);
  assert.strictEqual(new Set(RULES.map((r) => r.id)).size, RULES.length);
  for (const r of RULES) {
    for (const k of ['id', 'cls', 'conf', 'files', 'verify', 'bad', 'good']) assert.ok(r[k] !== undefined, `${r.id} missing ${k}`);
    assert.ok(['low', 'medium', 'high'].includes(r.conf), r.id);
    assert.ok(r.nameOnly || r.pattern instanceof RegExp, `${r.id} needs a pattern`);
    assert.ok(r.bad.length && r.good.length, `${r.id} needs bad and good examples`);
  }
});

test('every rule links to a real ledger class block', () => {
  for (const r of RULES) assert.strictEqual(blockProblem(r.cls, true), null, `${r.id}: ${r.cls}`);
});

test('bad examples match and good examples do not', () => {
  for (const r of RULES) {
    const hit = (s) => (r.nameOnly ? r.files.test(s) : r.pattern.test(s) && !(r.unless && r.unless.test(s)));
    for (const b of r.bad) assert.ok(hit(b), `${r.id} should match: ${b}`);
    for (const g of r.good) assert.ok(!hit(g), `${r.id} should not match: ${g}`);
  }
});

function repo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-det-'));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}
const ids = (out) => out.hits.map((h) => `${h.rule}@${h.file}`);

test('scans real files with file filters, requires, and redaction', () => {
  const dir = repo({
    'src/api.js': "const { exec } = require('child_process');\nexec(`convert ${f} o.png`);\nconst k = 'sk_live_abcdefghijklmnop1234';\n",
    'src/api.py': 'exec(`not js`)\n',
    'android/app/src/main/AndroidManifest.xml': '<application android:debuggable="true">',
    'node_modules/x/index.js': 'eval(userCode)',
    'build/intermediates/merged_manifests/release/AndroidManifest.xml': '<activity android:exported="true">',
    'keys/release.jks': Buffer.from([0, 1, 2, 3]),
  });
  const out = detect(dir);
  const got = ids(out);
  assert.ok(got.includes('inj.cmd-exec-js@src/api.js'));
  assert.ok(got.includes('mobile.android-debuggable@android/app/src/main/AndroidManifest.xml'));
  assert.ok(got.includes('mobile.android-exported@build/intermediates/merged_manifests/release/AndroidManifest.xml'), 'merged manifest kept');
  assert.ok(got.includes('secret.credential-file@keys/release.jks'), 'binary file still gets name rules');
  assert.ok(!got.some((g) => g.endsWith('node_modules/x/index.js')), 'node_modules skipped');
  assert.ok(!got.some((g) => g.startsWith('inj.cmd-exec-js@src/api.py')), 'file filter respected');
  const stripe = out.hits.find((h) => h.rule === 'secret.stripe-live-key');
  assert.ok(stripe && !stripe.snippet.includes('abcdefghijklmnop1234') && stripe.snippet.includes('redacted'));
});

test('tests are skipped by default and downgraded when included', () => {
  const dir = repo({ 'src/__tests__/a.test.js': 'eval(userCode)' });
  assert.strictEqual(detect(dir).hits.length, 0);
  const h = detect(dir, { includeTests: true }).hits[0];
  assert.strictEqual(h.confidence, 'low');
  assert.strictEqual(h.in_test, true);
});

test('suppressions need a reason and an unexpired date; inline ignores need a reason', () => {
  const dir = repo({
    'a.js': 'eval(userCode)\n// boring-security-ignore inj.eval-js -- sandboxed worker, reviewed\neval(other)\n// boring-security-ignore inj.eval-js\neval(third)\n',
    'b.js': 'eval(x)',
    'c.js': 'eval(y)',
    '.boring-security/config.json': JSON.stringify({ detector: {
      exclude_paths: ['c.js'],
      ignore: [
        { rule: 'inj.eval-js', path: 'b.js', reason: 'ok', expires: '2999-01-01' },
        { rule: 'inj.eval-js', path: 'a.js', reason: 'old', expires: '2000-01-01' },
        { rule: 'inj.*', path: 'a.js' },
      ] } }),
  });
  const out = detect(dir);
  const lines = out.hits.filter((h) => h.rule === 'inj.eval-js').map((h) => `${h.file}:${h.line}`);
  assert.deepStrictEqual(lines.sort(), ['a.js:1', 'a.js:5']);
  assert.strictEqual(out.suppressed, 1);
  assert.ok(out.warnings.some((w) => /expired/.test(w)) && out.warnings.some((w) => /without rule\/reason\/expires/.test(w)));
});

test('min confidence filters', () => {
  const dir = repo({ 'a.js': '// TODO: add auth check\nconst k = "sk_live_abcdefghijklmnop1234"' });
  const rules = detect(dir, { minConfidence: 'high' }).hits.map((h) => h.rule);
  assert.deepStrictEqual(rules, ['secret.stripe-live-key']);
});
