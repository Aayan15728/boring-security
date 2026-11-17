'use strict';
// Run: node --test skills/boring-security/scripts/test/
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

const RULES = require('../detect-rules.cjs');
const { detect, scanFile, listFiles, TEST_PATH, decode, validateRef, MAX_LINE } = require('../detect.cjs');
const { blockProblem } = require('../check-ledger.cjs');

const DETECT = path.join(__dirname, '..', 'detect.cjs');
const SKILL = path.join(__dirname, '..', '..');
const kindOf = (r) => r.kind || 'line';
const lineRules = RULES.filter((r) => kindOf(r) === 'line');
const isSecret = (r) => !!r.secret || r.id.startsWith('secret.');
const asCases = (list) => list.map((c) => (Array.isArray(c) ? c : [c]));

const made = [];
function repo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-det-'));
  made.push(dir);
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}
test.after(() => { for (const d of made) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } } });
const ids = (out) => out.hits.map((h) => `${h.rule}@${h.file}`);
const day = (n) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);
const FAKE_GHP = `ghp_${'FAKEfake'.repeat(4)}FAKE`;
const FAKE_STRIPE = 'sk_live_abcdefghijklmnop1234';

// ---------------------------------------------------------------- rule table
test('at least 60 rules, unique ids, required fields per kind', () => {
  assert.ok(RULES.length >= 60, `only ${RULES.length} rules`);
  assert.strictEqual(new Set(RULES.map((r) => r.id)).size, RULES.length);
  for (const r of RULES) {
    for (const k of ['id', 'cls', 'conf', 'files', 'verify']) assert.ok(r[k] !== undefined, `${r.id} missing ${k}`);
    assert.ok(['low', 'medium', 'high'].includes(r.conf), r.id);
    assert.ok(r.files instanceof RegExp, `${r.id} files must be a RegExp`);
    const kind = kindOf(r);
    assert.ok(['line', 'file', 'aggregate'].includes(kind), `${r.id} unknown kind ${kind}`);
    if (kind === 'line') {
      assert.ok(r.nameOnly || r.pattern instanceof RegExp, `${r.id} needs a pattern`);
      assert.ok(Array.isArray(r.bad) && r.bad.length && Array.isArray(r.good) && r.good.length, `${r.id} needs bad and good examples`);
      if (r.pattern) assert.ok(!/[gy]/.test(r.pattern.flags), `${r.id} pattern must not be global/sticky`);
    } else {
      assert.ok(Array.isArray(r.badFiles) && r.badFiles.length && Array.isArray(r.goodFiles) && r.goodFiles.length, `${r.id} needs badFiles and goodFiles`);
      for (const c of asCases([...r.badFiles, ...r.goodFiles])) for (const f of c) assert.ok(typeof f.path === 'string' && typeof f.text === 'string', `${r.id} example needs {path, text}`);
      if (kind === 'file') assert.ok(r.match instanceof RegExp && r.unlessFile instanceof RegExp, `${r.id} file rule needs match and unlessFile`);
      else assert.strictEqual(typeof r.run, 'function', `${r.id} aggregate rule needs run()`);
    }
  }
});

test('every rule links to a real ledger class block', (t) => {
  const appStack = fs.existsSync(path.join(SKILL, 'packs', 'app-stack.md'));
  for (const r of RULES) {
    if (!appStack && r.cls.startsWith('packs/app-stack.md#')) { t.diagnostic(`packs/app-stack.md missing; not checking ${r.id}`); continue; }
    assert.strictEqual(blockProblem(r.cls, true), null, `${r.id}: ${r.cls}`);
  }
});

const hitRe = (r, s) => (r.nameOnly ? r.files.test(s) : r.pattern.test(s) && !(r.unless && r.unless.test(s)));
test('line rules: bad examples match and good examples do not', () => {
  for (const r of lineRules) {
    for (const b of r.bad) assert.ok(hitRe(r, b), `${r.id} should match: ${b}`);
    for (const g of r.good) assert.ok(!hitRe(r, g), `${r.id} should not match: ${g}`);
  }
});

// A copy of the rule that applies to any path and ignores file-level gates.
const loose = (r) => ({ ...r, files: /./, requires: undefined, unlessFile: undefined });
const prettierSplit = (s) => s.replace(/([(,])[ \t]*/g, '$1\n  ');

test('line rules through the engine: bad hits, good stays quiet even when split across lines', () => {
  for (const r of lineRules.filter((x) => !x.nameOnly)) {
    for (const b of r.bad) assert.ok(scanFile('x.any', `${b}\n`, [loose(r)]).length, `${r.id} engine should hit: ${b}`);
    for (const g of r.good) {
      assert.strictEqual(scanFile('x.any', `${g}\n`, [loose(r)]).length, 0, `${r.id} engine should not hit: ${g}`);
      const split = prettierSplit(g);
      const win = scanFile('x.any', split, [loose(r)]).filter((h) => h.window);
      assert.strictEqual(win.length, 0, `${r.id} multi-line window should not hit split good example:\n${split}`);
    }
  }
});

test('file and aggregate rules: badFiles hit, goodFiles do not', () => {
  for (const r of RULES.filter((x) => kindOf(x) !== 'line')) {
    for (const c of asCases(r.badFiles)) {
      const out = detect(repo(Object.fromEntries(c.map((f) => [f.path, f.text]))), { useGit: false });
      assert.ok(out.hits.some((h) => h.rule === r.id), `${r.id} should hit on ${c.map((f) => f.path).join(', ')}`);
    }
    for (const c of asCases(r.goodFiles)) {
      const out = detect(repo(Object.fromEntries(c.map((f) => [f.path, f.text]))), { useGit: false });
      assert.ok(!out.hits.some((h) => h.rule === r.id), `${r.id} should not hit on ${c.map((f) => f.path).join(', ')}: ${JSON.stringify(out.hits.filter((h) => h.rule === r.id))}`);
    }
  }
});

test('no rule pattern backtracks catastrophically on hostile lines', () => {
  const base = ['a', ' ', '(', 'req.query.', '"', '`${', '{', 'eyJ', 'A', 'password = "', 'postgres://a', ':', 'x ', 'TODO ', 'a.', '=', 'Token',
    'service_role', '\\', '[', '-', 'SELECT ', 'allow read, ', 'uses: a/b@', '${{ github.event.issue.', 'Math.random() ', '0', 'createBucket(', 'AC'];
  const inputs = [];
  for (const b of base) { inputs.push(b.repeat(Math.ceil(MAX_LINE / b.length)).slice(0, MAX_LINE)); inputs.push(b.repeat(Math.ceil(4000 / b.length)).slice(0, 4000) + '!'); }
  inputs.push('eyJ' + 'a'.repeat(900) + '.' + 'b'.repeat(900) + '.', 'postgres://' + 'a'.repeat(900) + ':' + 'b'.repeat(900), '{' + ' role,'.repeat(300));
  for (const r of lineRules.filter((x) => x.pattern)) {
    for (const s of inputs) {
      const t0 = process.hrtime.bigint();
      r.pattern.exec(s);
      if (r.unless) r.unless.exec(s);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      assert.ok(ms < 250, `${r.id} took ${ms.toFixed(1)}ms on ${JSON.stringify(s.slice(0, 30))}...`);
    }
  }
});

// ---------------------------------------------------------------- engine
test('scans real files with file filters, requires, and redaction', () => {
  const dir = repo({
    'src/api.js': `const { exec } = require('child_process');\nexec(\`convert \${f} o.png\`);\nconst k = '${FAKE_STRIPE}';\n`,
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
  assert.strictEqual(out.mode, 'walk');
  assert.ok(out.skipped_dirs.some((d) => d.path === 'node_modules' && d.reason === 'always-skipped'));
  assert.ok(out.secret_only_dirs.some((d) => d.path === 'build' && /secret rules only/.test(d.reason)));
  assert.ok(out.skipped_files.some((f) => f.path === 'keys/release.jks' && /binary/.test(f.reason)));
  assert.match(out.note, /untrusted/);
});

test('test paths: secret rules always run at full confidence, other rules only with --include-tests', () => {
  assert.ok(TEST_PATH.test('src/__tests__/a.test.js'));
  const dir = repo({ 'src/__tests__/a.test.js': `eval(userCode)\nconst k = "${FAKE_STRIPE}"\n`, 'fixtures/creds.pem': 'x' });
  const def = detect(dir);
  assert.deepStrictEqual(def.hits.map((h) => h.rule).sort(), ['secret.credential-file', 'secret.stripe-live-key']);
  for (const h of def.hits) { assert.strictEqual(h.in_test, true); assert.notStrictEqual(h.confidence, 'low'); }
  assert.strictEqual(def.hits.find((h) => h.rule === 'secret.stripe-live-key').confidence, 'high');
  assert.strictEqual(def.files_secrets_only, 2);
  const inc = detect(dir, { includeTests: true });
  const ev = inc.hits.find((h) => h.rule === 'inj.eval-js');
  assert.strictEqual(ev.confidence, 'low');
  assert.strictEqual(ev.in_test, true);
  assert.strictEqual(inc.hits.find((h) => h.rule === 'secret.stripe-live-key').confidence, 'high');
});

test('walk mode: skip-list build/vendor dirs get secret rules only; dependency stores stay skipped', () => {
  const sec = `const k = "${FAKE_STRIPE}";\neval(userCode);\n`;
  const dir = repo({
    'build/deploy.js': sec, 'env/config.js': sec, 'dist/nested/out.js': sec,
    'venv/lib/x.py': `k = "${FAKE_STRIPE}"\n`, '.venv/y.py': `k = "${FAKE_STRIPE}"\n`,
    'pyenv/env/pyvenv.cfg': 'home = /usr/bin\n', 'pyenv/env/lib/z.py': `k = "${FAKE_STRIPE}"\n`,
    'build/big.js': `// ${'x'.repeat(1024 * 1024)}\nconst k = "${FAKE_STRIPE}";\n`, 'build/blob.bin': Buffer.from([0, 1, 2, 0, 0, 0, 9]),
  });
  const out = detect(dir, { useGit: false });
  const stripe = out.hits.filter((h) => h.rule === 'secret.stripe-live-key').map((h) => h.file).sort();
  assert.deepStrictEqual(stripe, ['build/deploy.js', 'dist/nested/out.js', 'env/config.js']);
  for (const h of out.hits.filter((x) => x.rule === 'secret.stripe-live-key')) { assert.strictEqual(h.confidence, 'high'); assert.strictEqual(h.in_test, false); }
  assert.ok(!out.hits.some((h) => h.rule === 'inj.eval-js'), 'non-secret rules do not run there');
  assert.deepStrictEqual(out.secret_only_dirs.map((d) => d.path).sort(), ['build', 'dist', 'env']);
  for (const p of ['venv', '.venv', 'pyenv/env']) assert.ok(out.skipped_dirs.some((d) => d.path === p && /dependency store/.test(d.reason)), p);
  assert.ok(out.skipped_files.some((f) => f.path === 'build/big.js' && /too large/.test(f.reason)));
  assert.ok(out.skipped_files.some((f) => f.path === 'build/blob.bin' && /binary/.test(f.reason)));
  assert.strictEqual(out.files_secrets_only, 5);
});

test('min confidence filters', () => {
  const dir = repo({ 'a.js': `// TODO: add auth check\nconst k = "${FAKE_STRIPE}"` });
  const rules = detect(dir, { minConfidence: 'high' }).hits.map((h) => h.rule);
  assert.deepStrictEqual(rules, ['secret.stripe-live-key']);
});

test('multi-line (prettier) calls hit, reported at the first line, without duplicates', () => {
  const dir = repo({
    'src/users.js': [
      'async function h(req, res) {',
      '  const rows = await db.query(',
      '    `SELECT * FROM users WHERE id = ${req.params.id}`',
      '  );',
      '  const r = await fetch(',
      '    req.query.url',
      '  );',
      '  const one = await fetch(req.query.other);',
      '  const q = db',
      '    .query(`SELECT * FROM t WHERE n = ${req.query.n}`);',
      '}',
    ].join('\n'),
  });
  const out = detect(dir);
  const at = (rule) => out.hits.filter((h) => h.rule === rule).map((h) => h.line).sort((a, b) => a - b);
  assert.deepStrictEqual(at('inj.sql-concat-js'), [2, 10]); // line 10 matches on its own; the window at 9 is deduplicated
  assert.deepStrictEqual(at('web.ssrf-fetch-input'), [5, 8]);
});

test('UTF-16 files are decoded, not treated as binary', () => {
  const body = `const k = "${FAKE_STRIPE}";\neval(userCode);\n`;
  const le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(body, 'utf16le')]);
  const be = Buffer.from(le); be.swap16();
  const noBom = Buffer.from(body, 'utf16le');
  assert.strictEqual(decode(noBom).encoding, 'utf16le');
  assert.ok(decode(Buffer.from([0, 1, 2, 3, 0, 0, 7])).binary);
  const dir = repo({ 'le.js': le, 'be.js': be, 'nobom.js': noBom });
  const out = detect(dir);
  for (const f of ['le.js', 'be.js', 'nobom.js']) {
    assert.ok(ids(out).includes(`secret.stripe-live-key@${f}`), `${f} secret`);
    assert.ok(ids(out).includes(`inj.eval-js@${f}`), `${f} eval`);
  }
  assert.strictEqual(out.skipped_counts.binary, 0);
});

test('long lines: secret rules still run (chunked, redacted); others skip and are reported', () => {
  const long = `var a="${'x'.repeat(3000)}";eval(userCode);var k="${FAKE_STRIPE}";${'y'.repeat(3000)}`;
  const dir = repo({ 'dist-bundle.js': `${long}\n` });
  const out = detect(dir);
  const s = out.hits.find((h) => h.rule === 'secret.stripe-live-key');
  assert.ok(s && s.line === 1 && !s.snippet.includes('abcdefghijklmnop') && s.snippet.length <= 200);
  assert.ok(!out.hits.some((h) => h.rule === 'inj.eval-js'));
  assert.deepStrictEqual(out.skipped_long_lines, [{ file: 'dist-bundle.js', line: 1, length: long.length }]);
  assert.strictEqual(out.skipped_counts.long_lines, 1);
});

test('redaction leaves no part of the secret value and snippets carry no control/invisible characters', () => {
  const dir = repo({
    '.env': 'APP_PASSPHRASE=correcthorse battery staple\n',
    'app.js': `// note‮​\x07: ${'p'.repeat(5)}\nconsole.log("token", "${FAKE_GHP}")\nconst t = "${FAKE_GHP}" // trailing ${FAKE_GHP.slice(4, 20)}\n`,
    'evil.js': 'eval(userCode) /* ‮reversed⁦ ​zw \x1b[31m */\n',
  });
  const out = detect(dir);
  const env = out.hits.find((h) => h.rule === 'secret.dotenv-committed');
  assert.ok(env, 'dotenv hit');
  for (const part of ['correcthorse', 'battery', 'staple']) assert.ok(!env.snippet.includes(part), `dotenv snippet leaks ${part}: ${env.snippet}`);
  assert.ok(env.snippet.startsWith('APP_PASSPHRASE='));
  for (const h of out.hits) {
    assert.ok(!h.snippet.includes('FAKEfakeFAKE'), `${h.rule} leaks token: ${h.snippet}`);
    assert.ok(!/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/.test(h.snippet), `${h.rule} snippet has invisible/control chars`);
    assert.ok(h.snippet.length <= 200);
  }
  assert.ok(out.hits.some((h) => h.rule === 'hygiene.sensitive-log'), 'non-secret rule on a secret-bearing line still reports, redacted');
  assert.ok(out.hits.find((h) => h.file === 'evil.js').snippet.includes('reversed'));
});

// ---------------------------------------------------------------- suppression
test('config suppressions and inline ignores are validated, applied, and reported', () => {
  const dir = repo({
    'a.js': 'eval(userCode)\n// boring-security-ignore inj.eval-js -- sandboxed worker, reviewed\neval(other)\n// boring-security-ignore inj.eval-js\neval(third)\n// boring-security-ignore * -- everything\neval(fourth)\neval(fifth) // boring-security-ignore inj.eval-* -- glob\n',
    'b.js': 'eval(x)',
    'c.js': 'eval(y)',
    'd.js': '// TODO: add auth check\n',
    '.boring-security/config.json': JSON.stringify({ detector: {
      exclude_paths: ['c.js', '**', '*', '**/*', './**/**'],
      ignore: [
        { rule: 'inj.eval-js', path: 'b.js', reason: 'ok', expires: day(30) },
        { rule: 'inj.eval-js', path: 'a.js', reason: 'old', expires: '2000-01-01' },
        { rule: 'inj.*', path: 'a.js' },
        { rule: '*', reason: 'all', expires: day(30) },
        { rule: '**', reason: 'all', expires: day(30) },
        { rule: 'inj.eval-js', path: 'a.js', reason: 'forever', expires: day(400) },
        { rule: 'inj.eval-js', path: 'a.js', reason: 'bad date', expires: '2026-02-30' },
        { rule: 'hygiene.*', path: 'd.js', reason: 'tracked in issue 12', expires: day(10) },
      ] } }),
  });
  const out = detect(dir);
  const lines = out.hits.filter((h) => h.rule === 'inj.eval-js').map((h) => `${h.file}:${h.line}`);
  assert.deepStrictEqual(lines.sort(), ['a.js:1', 'a.js:5', 'a.js:7', 'a.js:8']);
  assert.strictEqual(out.suppressed, 3);
  const sup = out.suppressed_hits.map((s) => `${s.source}:${s.rule}@${s.file}:${s.line}`).sort();
  assert.deepStrictEqual(sup, ['config:hygiene.security-todo@d.js:1', 'config:inj.eval-js@b.js:1', 'inline:inj.eval-js@a.js:3']);
  assert.strictEqual(out.suppressed_hits.find((s) => s.source === 'inline').reason, 'sandboxed worker, reviewed');
  assert.strictEqual(out.suppressed_hits.find((s) => s.file === 'd.js').pattern, 'hygiene.*');
  assert.deepStrictEqual(out.excluded_by_config, { count: 1, by_pattern: { 'c.js': 1 }, files: ['c.js'] });
  const w = out.warnings.join('\n');
  for (const re of [/expired/, /without rule\/reason\/expires/, /"\*\*" matches every file/, /"\*" matches every file/, /"\*\*\/\*" matches every file/,
    /"\.\/\*\*\/\*\*" matches every file/, /"\*" matches every rule/, /"\*\*" matches every rule/, /more than 365 days/, /malformed expires/, /malformed inline ignore at a\.js:4/,
    /malformed inline ignore at a\.js:6/, /malformed inline ignore at a\.js:8/]) assert.match(w, re);
});

test('--no-target-config ignores config and inline ignores', () => {
  const dir = repo({
    'a.js': 'eval(one) // boring-security-ignore inj.eval-js -- reviewed\n',
    'b.js': 'eval(two)\n',
    '.boring-security/config.json': JSON.stringify({ detector: { exclude_paths: ['b.js'], ignore: [{ rule: 'inj.eval-js', reason: 'x', expires: day(5) }] } }),
  });
  assert.strictEqual(detect(dir).hits.filter((h) => h.rule === 'inj.eval-js').length, 0);
  const out = detect(dir, { noTargetConfig: true });
  assert.deepStrictEqual(out.hits.filter((h) => h.rule === 'inj.eval-js').map((h) => h.file).sort(), ['a.js', 'b.js']);
  assert.strictEqual(out.suppressed, 0);
  assert.match(out.config.source, /disabled/);
});

test('validateRef rejects option-looking and odd revisions', () => {
  for (const bad of ['--output=/tmp/x', '-p', 'HEAD --output=x', 'a:b', '', 'HEAD\n', '../x;rm', '$(id)']) assert.throws(() => validateRef(bad), /invalid git base/, bad);
  for (const ok of ['main', 'origin/main', 'HEAD~3', 'v1.2.3', 'HEAD@{1}', 'abc123^', 'a..b']) assert.strictEqual(validateRef(ok), ok);
});

// ---------------------------------------------------------------- git
const NULL_DEV = process.platform === 'win32' ? 'NUL' : '/dev/null';
const HAS_GIT = (() => { try { execFileSync('git', ['--version'], { stdio: 'ignore' }); return true; } catch { return false; } })();
const gitOpts = { skip: HAS_GIT ? false : 'git not available' };
function g(dir, ...args) {
  return execFileSync('git', ['-c', `core.hooksPath=${NULL_DEV}`, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', '-c', 'core.fsmonitor=false', ...args], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}
function gitRepo(files) {
  const dir = repo(files);
  g(dir, 'init', '-q');
  g(dir, 'add', '-A');
  g(dir, 'commit', '-q', '-m', 'init');
  return dir;
}
const cli = (...args) => spawnSync(process.execPath, [DETECT, ...args], { encoding: 'utf8' });
const posix = (p) => p.split(path.sep).join('/');
function plantScript(dir, name, marker) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, `#!/bin/sh\necho ran > "${posix(marker)}"\ncat\n`);
  fs.chmodSync(p, 0o755);
  return posix(p);
}

test('git work tree: .gitignore decides what is generated; skips are reported', gitOpts, () => {
  const dir = gitRepo({
    '.gitignore': 'generated/\n*.log\n',
    'build/app.js': 'eval(userCode)\n',
    'generated/x.js': 'eval(userCode)\n',
    'debug.log': 'x',
    'node_modules/m/index.js': 'eval(userCode)\n',
  });
  fs.writeFileSync(path.join(dir, 'untracked.js'), 'eval(userCode)\n');
  const out = detect(dir);
  assert.strictEqual(out.mode, 'git');
  const files = out.hits.filter((h) => h.rule === 'inj.eval-js').map((h) => h.file).sort();
  assert.deepStrictEqual(files, ['build/app.js', 'untracked.js']);
  assert.ok(out.skipped_dirs.some((d) => d.path === 'generated' && d.reason === 'gitignored'), JSON.stringify(out.skipped_dirs));
  assert.ok(out.skipped_dirs.some((d) => d.path === 'node_modules' && d.reason === 'always-skipped'), JSON.stringify(out.skipped_dirs));
  assert.ok(out.skipped_files.some((f) => f.path === 'debug.log' && f.reason === 'gitignored'));
  const listed = listFiles(dir, {});
  assert.ok(Array.isArray(listed) && listed.includes('build/app.js') && !listed.some((f) => f.startsWith('node_modules/')));
});

test('--diff rejects argument injection and git never writes the file', gitOpts, () => {
  const dir = gitRepo({ 'a.js': 'x\n' });
  const outFile = path.join(os.tmpdir(), `bsec-pwned-${process.pid}-${Date.now()}.txt`);
  for (const ref of [`--output=${outFile}`, `HEAD --output=${outFile}`]) {
    const r = cli(dir, '--diff', ref);
    assert.notStrictEqual(r.status, 0, r.stdout);
    assert.match(r.stderr, /invalid git base/);
    assert.ok(!fs.existsSync(outFile), 'injected --output file was written');
  }
  const r = cli(dir, '--diff', 'no-such-branch');
  assert.notStrictEqual(r.status, 0);
  assert.match(r.stderr, /unknown git revision/);
});

test('a planted core.fsmonitor or filter driver does not run during --diff or listing', gitOpts, (t) => {
  const dir = gitRepo({ 'a.js': 'eval(userCode)\n', '.gitattributes': '*.js filter=evil\n' });
  const scripts = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-hook-'));
  made.push(scripts);
  const marker = path.join(scripts, 'ran.txt');
  const script = plantScript(scripts, 'payload.sh', marker);
  g(dir, 'config', 'core.fsmonitor', script);
  g(dir, 'config', 'filter.evil.clean', `sh "${script}"`);
  g(dir, 'config', 'filter.evil.process', `sh "${script}"`);
  fs.writeFileSync(path.join(dir, 'a.js'), 'eval(userCode)\neval(more)\n');
  // Control: an unhardened git command in this repo does run the payload.
  spawnSync('git', ['-C', dir, 'diff', '--name-only', 'HEAD'], { stdio: 'ignore' });
  if (fs.existsSync(marker)) fs.rmSync(marker); else t.diagnostic('control did not trigger the payload on this git; assertions still hold');
  const r = cli(dir, '--diff', 'HEAD');
  assert.strictEqual(r.status, 0, r.stderr);
  assert.match(r.stdout, /lead/);
  const r2 = cli(dir);
  assert.strictEqual(r2.status, 0, r2.stderr);
  const r3 = cli(dir, '--history', '5');
  assert.strictEqual(r3.status, 0, r3.stderr);
  assert.ok(!fs.existsSync(marker), 'planted payload executed');
});

test('--diff reads suppressions from the base ref and flags config changes', gitOpts, () => {
  const dir = gitRepo({ 'a.js': 'const x = 1\n', 'old.js': 'eval(kept)\n',
    '.boring-security/config.json': JSON.stringify({ detector: { ignore: [{ rule: 'inj.eval-js', path: 'old.js', reason: 'reviewed', expires: day(30) }] } }) });
  fs.writeFileSync(path.join(dir, 'a.js'), 'eval(userCode)\neval(more) // boring-security-ignore inj.eval-js -- added by this change\n');
  fs.writeFileSync(path.join(dir, 'old.js'), 'eval(kept)\neval(newer)\n');
  fs.writeFileSync(path.join(dir, '.boring-security/config.json'), JSON.stringify({ detector: { exclude_paths: ['a.js'], ignore: [{ rule: 'inj.eval-js', reason: 'all', expires: day(30) }] } }));
  const out = detect(dir, { diff: 'HEAD' });
  assert.strictEqual(out.mode, 'diff');
  assert.match(out.config.source, /^base:HEAD/);
  const evals = out.hits.filter((h) => h.rule === 'inj.eval-js').map((h) => `${h.file}:${h.line}`).sort();
  assert.deepStrictEqual(evals, ['a.js:1', 'a.js:2'], 'worktree exclude/ignore and a new inline ignore must not apply');
  assert.deepStrictEqual(out.suppressed_hits.map((s) => `${s.source}:${s.file}:${s.line}`).sort(), ['config:old.js:1', 'config:old.js:2']);
  const meta = out.hits.find((h) => h.rule === 'meta.suppression-config-changed');
  assert.ok(meta && meta.confidence === 'high');
  assert.match(out.warnings.join('\n'), /new in this change/);
});

test('--history finds secrets that only exist in deleted history', gitOpts, () => {
  const dir = gitRepo({ 'src/config.js': `const t = "${FAKE_GHP}";\n`, 'README.md': 'hi\n' });
  const first = g(dir, 'rev-parse', '--short', 'HEAD');
  fs.writeFileSync(path.join(dir, 'src/config.js'), 'const t = process.env.GH_TOKEN;\n');
  g(dir, 'commit', '-q', '-am', 'remove token');
  const now = detect(dir);
  assert.ok(!now.hits.some((h) => h.rule === 'secret.github-token'));
  assert.ok(!now.history);
  const out = detect(dir, { history: 10 });
  const h = out.hits.find((x) => x.rule === 'secret.github-token');
  assert.ok(h, JSON.stringify(out.history));
  assert.strictEqual(h.in_history, true);
  assert.strictEqual(h.commit, first);
  assert.strictEqual(h.file, 'src/config.js');
  assert.strictEqual(h.line, 1);
  assert.strictEqual(h.in_working_tree, false);
  assert.ok(!h.snippet.includes('FAKEfake'));
  assert.strictEqual(out.history.commits_scanned, 2);
  const r = cli(dir, '--history');
  assert.strictEqual(r.status, 0, r.stderr);
  assert.match(r.stdout, new RegExp(`@${first}`));
});
