'use strict';
// Tests for install.cjs. Everything runs against temp directories. The real `claude` CLI is never
// invoked: BORING_SECURITY_CLAUDE_BIN always points at a fake script or a missing file, and HOME /
// CLAUDE_CONFIG_DIR point into a temp directory.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const INSTALLER = path.join(ROOT, 'install.cjs');
const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'bs-install-test-'));
const HOME = path.join(SANDBOX, 'home');
fs.mkdirSync(HOME, { recursive: true });
const MISSING_CLAUDE = path.join(SANDBOX, 'no-such-claude');
const FAKE_CLAUDE = path.join(SANDBOX, 'fake-claude.cjs');
const FAKE_LOG = path.join(SANDBOX, 'fake-claude.log');

fs.writeFileSync(FAKE_CLAUDE, `
const fs = require('fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FAKE_CLAUDE_LOG, JSON.stringify(args) + '\\n');
const j = args.join(' ');
const failOn = process.env.FAKE_CLAUDE_FAIL;
if (failOn && j.includes(failOn)) { console.error(process.env.FAKE_CLAUDE_MSG || 'simulated failure'); process.exit(1); }
if (j === 'plugin list') console.log(process.env.FAKE_CLAUDE_LIST || '');
else console.log('ok');
`);

test.after(() => { fs.rmSync(SANDBOX, { recursive: true, force: true }); });

function run(args, env) {
  const r = cp.spawnSync(process.execPath, [INSTALLER].concat(args), {
    encoding: 'utf8',
    timeout: 60000,
    env: Object.assign({}, process.env, {
      HOME, USERPROFILE: HOME, CLAUDE_CONFIG_DIR: path.join(HOME, '.claude'),
      BORING_SECURITY_CLAUDE_BIN: MISSING_CLAUDE, FAKE_CLAUDE_LOG: FAKE_LOG,
    }, env || {}),
  });
  return { status: r.status, out: r.stdout || '', err: r.stderr || '' };
}

function tmp(name) {
  const d = path.join(SANDBOX, name + '-' + Math.random().toString(36).slice(2, 8));
  fs.mkdirSync(d, { recursive: true });
  return d;
}

function listFiles(dir) {
  const res = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else res.push(path.relative(dir, p).split(path.sep).join('/'));
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return res.sort();
}

const MANIFEST = 'skills/boring-security/.install-manifest.json';
const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;

test('fresh copy install creates skill, commands and a manifest', () => {
  const dest = tmp('fresh');
  const r = run(['--copy', '--dest', dest]);
  assert.equal(r.status, 0, r.out + r.err);
  const files = listFiles(dest);
  assert.ok(files.includes('skills/boring-security/SKILL.md'));
  assert.ok(files.includes('skills/boring-security/scripts/detect.cjs'));
  assert.ok(files.includes(MANIFEST));
  for (const c of fs.readdirSync(path.join(ROOT, 'commands')).filter((n) => n.endsWith('.md'))) {
    assert.ok(files.includes('commands/' + c), 'missing command ' + c);
  }
  if (fs.existsSync(path.join(ROOT, 'agents'))) {
    for (const a of fs.readdirSync(path.join(ROOT, 'agents')).filter((n) => n.endsWith('.md'))) {
      assert.ok(files.includes('agents/' + a), 'missing agent ' + a);
    }
  }
  assert.ok(!files.some((f) => f.includes('scripts/test/')), 'test directory must not be copied');
  assert.ok(!files.some((f) => f.includes('node_modules') || f.includes('.git/')));
  assert.ok(!files.some((f) => f.startsWith('hooks/')), 'hooks must not be installed in copy mode');
  const m = JSON.parse(fs.readFileSync(path.join(dest, ...MANIFEST.split('/')), 'utf8'));
  assert.equal(m.version, version);
  assert.equal(m.name, 'boring-security');
  const listed = m.files.map((f) => f.path).sort();
  assert.deepEqual(listed, files.filter((f) => f !== MANIFEST));
  assert.match(r.out, /Hooks are NOT installed/);
});

test('re-running is idempotent', () => {
  const dest = tmp('idem');
  assert.equal(run(['--copy', '--dest', dest]).status, 0);
  const before = listFiles(dest);
  const content = fs.readFileSync(path.join(dest, 'skills', 'boring-security', 'SKILL.md'), 'utf8');
  const r = run(['--copy', '--dest', dest]);
  assert.equal(r.status, 0, r.out + r.err);
  assert.deepEqual(listFiles(dest), before);
  assert.equal(fs.readFileSync(path.join(dest, 'skills', 'boring-security', 'SKILL.md'), 'utf8'), content);
  assert.match(r.out, /0 new, 0 updated/);
});

test('upgrade overwrites installed files and removes stale listed files only', () => {
  const dest = tmp('upgrade');
  assert.equal(run(['--copy', '--dest', dest]).status, 0);
  const skill = path.join(dest, 'skills', 'boring-security', 'SKILL.md');
  fs.writeFileSync(skill, 'locally edited');
  // pretend an older release shipped an extra command
  const mpath = path.join(dest, ...MANIFEST.split('/'));
  const m = JSON.parse(fs.readFileSync(mpath, 'utf8'));
  fs.writeFileSync(path.join(dest, 'commands', 'old-removed.md'), 'old');
  m.files.push({ path: 'commands/old-removed.md', sha256: 'x' });
  fs.writeFileSync(mpath, JSON.stringify(m));
  const r = run(['--copy', '--dest', dest]);
  assert.equal(r.status, 0, r.out + r.err);
  assert.notEqual(fs.readFileSync(skill, 'utf8'), 'locally edited');
  assert.ok(!fs.existsSync(path.join(dest, 'commands', 'old-removed.md')));
});

test('--dry-run changes nothing', () => {
  const dest = tmp('dry');
  const r = run(['--copy', '--dry-run', '--dest', dest]);
  assert.equal(r.status, 0, r.out + r.err);
  assert.deepEqual(listFiles(dest), []);
  assert.match(r.out, /dry run/i);
  assert.match(r.out, /\+ create skills\/boring-security\/SKILL\.md/);
  // dry-run on top of an existing install also leaves it untouched
  assert.equal(run(['--copy', '--dest', dest]).status, 0);
  const before = listFiles(dest);
  fs.writeFileSync(path.join(dest, 'skills', 'boring-security', 'SKILL.md'), 'edited');
  assert.equal(run(['--copy', '--dry-run', '--dest', dest]).status, 0);
  assert.equal(fs.readFileSync(path.join(dest, 'skills', 'boring-security', 'SKILL.md'), 'utf8'), 'edited');
  assert.deepEqual(listFiles(dest), before);
  const u = run(['--uninstall', '--dry-run', '--dest', dest]);
  assert.equal(u.status, 0, u.out + u.err);
  assert.deepEqual(listFiles(dest), before);
});

test('a pre-existing foreign command file is a conflict without --force', () => {
  const dest = tmp('conflict');
  const foreign = path.join(dest, 'commands', 'quick-audit.md');
  fs.mkdirSync(path.dirname(foreign), { recursive: true });
  fs.writeFileSync(foreign, 'my own command');
  const r = run(['--copy', '--dest', dest]);
  assert.equal(r.status, 3, r.out + r.err);
  assert.match(r.out, /quick-audit\.md/);
  assert.equal(fs.readFileSync(foreign, 'utf8'), 'my own command');
  assert.deepEqual(listFiles(dest), ['commands/quick-audit.md'], 'nothing else may be written');
  const f = run(['--copy', '--force', '--dest', dest]);
  assert.equal(f.status, 0, f.out + f.err);
  assert.notEqual(fs.readFileSync(foreign, 'utf8'), 'my own command');
});

test('--uninstall removes only manifest-listed files and leaves foreign files intact', () => {
  const dest = tmp('uninstall');
  assert.equal(run(['--copy', '--dest', dest]).status, 0);
  const mine = [path.join(dest, 'commands', 'my-own.md'), path.join(dest, 'skills', 'boring-security', 'my-notes.txt'), path.join(dest, 'skills', 'other-skill', 'SKILL.md')];
  for (const f of mine) { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, 'keep'); }
  const r = run(['--uninstall', '--dest', dest]);
  assert.equal(r.status, 0, r.out + r.err);
  assert.deepEqual(listFiles(dest), ['commands/my-own.md', 'skills/boring-security/my-notes.txt', 'skills/other-skill/SKILL.md']);
  const again = run(['--uninstall', '--dest', dest]);
  assert.equal(again.status, 0);
  assert.match(again.out, /No copy-mode install|Nothing to uninstall/);
});

test('a tampered manifest listing a path outside the allowed directories is rejected', () => {
  const dest = tmp('tamper');
  assert.equal(run(['--copy', '--dest', dest]).status, 0);
  const victim = path.join(dest, 'settings.json');
  fs.writeFileSync(victim, '{}');
  const mpath = path.join(dest, ...MANIFEST.split('/'));
  const m = JSON.parse(fs.readFileSync(mpath, 'utf8'));
  m.files.push({ path: '../settings.json', sha256: 'x' }, { path: 'settings.json', sha256: 'x' });
  fs.writeFileSync(mpath, JSON.stringify(m));
  const r = run(['--uninstall', '--dest', dest]);
  assert.notEqual(r.status, 0);
  assert.ok(fs.existsSync(victim));
});

test('--check passes on a fresh install and fails when a file is removed', () => {
  const dest = tmp('check');
  assert.equal(run(['--copy', '--dest', dest]).status, 0);
  const ok = run(['--check', '--dest', dest]);
  assert.equal(ok.status, 0, ok.out + ok.err);
  assert.match(ok.out, /Check passed/);
  assert.match(ok.out, /detector lists \d+ rules/);
  fs.unlinkSync(path.join(dest, 'commands', 'quick-audit.md'));
  const bad = run(['--check', '--dest', dest]);
  assert.equal(bad.status, 4, bad.out + bad.err);
  assert.match(bad.out, /missing: commands\/quick-audit\.md/);
});

test('--check fails when nothing is installed', () => {
  const dest = tmp('check-empty');
  const r = run(['--check', '--dest', dest]);
  assert.equal(r.status, 4);
});

test('symlinks in the destination are never followed', (t) => {
  const dest = tmp('symlink');
  const elsewhere = tmp('elsewhere');
  try { fs.symlinkSync(elsewhere, path.join(dest, 'commands'), 'junction'); } catch (e) { return t.skip('cannot create symlinks here'); }
  const r = run(['--copy', '--dest', dest]);
  assert.notEqual(r.status, 0);
  assert.deepEqual(listFiles(elsewhere), [], 'nothing may be written through the symlink');
});

test('CLAUDE_CONFIG_DIR is honoured when no destination flag is given', () => {
  const cfg = tmp('cfgdir');
  const r = run(['--copy'], { CLAUDE_CONFIG_DIR: cfg });
  assert.equal(r.status, 0, r.out + r.err);
  assert.ok(fs.existsSync(path.join(cfg, 'skills', 'boring-security', 'SKILL.md')));
  assert.ok(!fs.existsSync(path.join(HOME, '.claude', 'skills')), 'must not touch the default config dir');
});

test('--project installs into <dir>/.claude', () => {
  const proj = tmp('proj');
  const r = run(['--project', proj]);
  assert.equal(r.status, 0, r.out + r.err);
  assert.ok(fs.existsSync(path.join(proj, '.claude', 'skills', 'boring-security', 'SKILL.md')));
});

test('usage errors exit 2', () => {
  assert.equal(run(['--bogus']).status, 2);
  assert.equal(run(['--plugin', '--copy']).status, 2);
  assert.equal(run(['--uninstall', '--check']).status, 2);
  assert.equal(run(['--dest']).status, 2);
  assert.equal(run(['--help']).status, 0);
});

test('auto mode without a claude CLI falls back to copy', () => {
  const cfg = tmp('auto-nocli');
  const r = run([], { CLAUDE_CONFIG_DIR: cfg });
  assert.equal(r.status, 0, r.out + r.err);
  assert.match(r.out, /Plugin route unavailable/);
  assert.ok(fs.existsSync(path.join(cfg, 'skills', 'boring-security', 'SKILL.md')));
});

test('--plugin without a claude CLI fails and writes nothing', () => {
  const cfg = tmp('plugin-nocli');
  const r = run(['--plugin'], { CLAUDE_CONFIG_DIR: cfg });
  assert.equal(r.status, 1);
  assert.deepEqual(listFiles(cfg), []);
});

test('plugin route (fake CLI): dry-run prints the planned commands and runs none', () => {
  fs.rmSync(FAKE_LOG, { force: true });
  const r = run(['--dry-run'], { BORING_SECURITY_CLAUDE_BIN: FAKE_CLAUDE });
  assert.equal(r.status, 0, r.out + r.err);
  assert.match(r.out, /would run: claude plugin marketplace add .* --scope user/);
  assert.match(r.out, /would run: claude plugin install boring-security@boring-security --scope user/);
  const calls = fs.readFileSync(FAKE_LOG, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(calls, [['plugin', 'install', '--help']], 'only the capability probe may run');
});

test('plugin route (fake CLI): runs marketplace add then install with array arguments', () => {
  fs.rmSync(FAKE_LOG, { force: true });
  const cfg = tmp('plugin-ok');
  const r = run([], { BORING_SECURITY_CLAUDE_BIN: FAKE_CLAUDE, CLAUDE_CONFIG_DIR: cfg });
  assert.equal(r.status, 0, r.out + r.err);
  const calls = fs.readFileSync(FAKE_LOG, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(calls, [
    ['plugin', 'install', '--help'],
    ['plugin', 'marketplace', 'add', ROOT, '--scope', 'user'],
    ['plugin', 'install', 'boring-security@boring-security', '--scope', 'user'],
  ]);
  assert.deepEqual(listFiles(cfg), [], 'plugin route must not copy files');
  assert.match(r.out, /new session/);
});

test('plugin route: "already installed" turns into an update', () => {
  fs.rmSync(FAKE_LOG, { force: true });
  const r = run(['--plugin'], { BORING_SECURITY_CLAUDE_BIN: FAKE_CLAUDE, FAKE_CLAUDE_FAIL: 'plugin install boring', FAKE_CLAUDE_MSG: 'Plugin is already installed' });
  assert.equal(r.status, 0, r.out + r.err);
  const calls = fs.readFileSync(FAKE_LOG, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(calls[calls.length - 1], ['plugin', 'update', 'boring-security@boring-security', '--scope', 'user']);
});

test('plugin route failure falls back to copy in auto mode, but fails with --plugin', () => {
  const cfg = tmp('plugin-fail');
  const env = { BORING_SECURITY_CLAUDE_BIN: FAKE_CLAUDE, FAKE_CLAUDE_FAIL: 'marketplace add', CLAUDE_CONFIG_DIR: cfg };
  const auto = run([], env);
  assert.equal(auto.status, 0, auto.out + auto.err);
  assert.match(auto.out, /Plugin install failed/);
  assert.match(auto.out, /Falling back to copy mode/);
  assert.ok(fs.existsSync(path.join(cfg, 'skills', 'boring-security', 'SKILL.md')));
  const cfg2 = tmp('plugin-fail2');
  const forced = run(['--plugin'], Object.assign({}, env, { CLAUDE_CONFIG_DIR: cfg2 }));
  assert.equal(forced.status, 1);
  assert.deepEqual(listFiles(cfg2), []);
});

test('uninstall (fake CLI) removes the plugin when it is listed', () => {
  fs.rmSync(FAKE_LOG, { force: true });
  const cfg = tmp('plugin-un');
  const r = run(['--uninstall'], { BORING_SECURITY_CLAUDE_BIN: FAKE_CLAUDE, FAKE_CLAUDE_LIST: 'boring-security@boring-security  enabled', CLAUDE_CONFIG_DIR: cfg });
  assert.equal(r.status, 0, r.out + r.err);
  const calls = fs.readFileSync(FAKE_LOG, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(calls[calls.length - 1], ['plugin', 'uninstall', 'boring-security@boring-security', '--scope', 'user']);
});
