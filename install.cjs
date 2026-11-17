#!/usr/bin/env node
'use strict';
/*
 * boring-security installer. Zero dependencies, Node >= 18, Windows/macOS/Linux.
 *
 *   node install.cjs                 install (plugin route if the claude CLI supports it, else copy)
 *   node install.cjs --check         verify an existing install
 *   node install.cjs --uninstall     remove what this installer installed
 *   node install.cjs --help
 *
 * Plugin mode shells out to the `claude` CLI with an argument array (never a shell string).
 * Copy mode only ever writes inside <config>/skills/boring-security/, <config>/commands/ and
 * <config>/agents/, records every file in a manifest, and never follows symlinks in the destination.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const cp = require('node:child_process');

const NAME = 'boring-security';
const PLUGIN_ID = 'boring-security@boring-security';
const SKILL_REL = 'skills/boring-security';
const MANIFEST_REL = SKILL_REL + '/.install-manifest.json';
const ALLOWED_PREFIXES = [SKILL_REL + '/', 'commands/', 'agents/'];
const SKIP_NAMES = new Set(['node_modules', '.git', '.DS_Store', 'Thumbs.db']);
const SKIP_REL_DIRS = new Set(['scripts/test']); // relative to the skill directory
const TRANSIENT = /(\.bs-tmp-|\.tmp(\.|$)|\.(bak|orig|swp|rej)$|~$)/; // editor/atomic-write leftovers
const SELF_TEST_MODULES = ['lib.cjs', 'detect-rules.cjs', 'check-findings.cjs', 'check-ledger.cjs'];
const ROOT = __dirname;
// A git checkout is registered in place; an npm/npx copy lives in a package cache that can be cleaned,
// so the plugin is registered from GitHub instead and Claude Code keeps its own copy.
const GITHUB_SOURCE = 'Aayan15728/boring-security';
const FROM_CHECKOUT = fs.existsSync(path.join(ROOT, '.git'));
const MARKETPLACE_SOURCE = FROM_CHECKOUT ? ROOT : GITHUB_SOURCE;

const EXIT = { OK: 0, ERROR: 1, USAGE: 2, CONFLICT: 3, CHECK_FAILED: 4 };

class Fail extends Error {
  constructor(message, code) { super(message); this.code = code || EXIT.ERROR; }
}

const HELP = `boring-security installer

Usage: node install.cjs [options]

Modes (default: auto)
  (none)            auto: install as a Claude Code plugin when the claude CLI supports it
                    (enables bundled subagents and hooks), otherwise copy files.
  --plugin          force the plugin route; fail instead of falling back.
  --copy            force copy mode (skill + commands + agents; no hooks).

Where (copy mode)
  (default)         $CLAUDE_CONFIG_DIR if set, else ~/.claude
  --project <dir>   install into <dir>/.claude/ (implies copy unless --plugin is given)
  --dest <dir>      use <dir> as the config directory (implies copy; used by tests)

Actions
  --uninstall       remove only what a previous install recorded (and the plugin, if present)
  --check           verify an existing install (version, files, Node >= 18, detector self-test)
  --dry-run         print what would happen; change nothing
  --force           overwrite files that were not installed by this installer
  --help, -h        show this help
  --version         print the version

Exit codes
  0 success   1 error   2 usage error   3 conflict (nothing written)   4 --check failed

Environment
  CLAUDE_CONFIG_DIR            relocates the user config directory (same as Claude Code)
  BORING_SECURITY_CLAUDE_BIN   path of the claude executable to use instead of searching PATH
`;

// ---------------------------------------------------------------- output

const out = (s) => process.stdout.write(s + '\n');
const warn = (s) => process.stderr.write('warning: ' + s + '\n');

// ---------------------------------------------------------------- args

function parseArgs(argv) {
  const o = { mode: 'auto', dryRun: false, uninstall: false, check: false, force: false, help: false, version: false, project: null, dest: null };
  let forced = null;
  const need = (i, flag) => {
    if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) throw new Fail(flag + ' needs a directory argument', EXIT.USAGE);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    let a = argv[i];
    let inline = null;
    const eq = a.indexOf('=');
    if (a.startsWith('--') && eq > 0) { inline = a.slice(eq + 1); a = a.slice(0, eq); }
    switch (a) {
      case '--plugin': case '--copy':
        if (forced && forced !== a) throw new Fail('--plugin and --copy are mutually exclusive', EXIT.USAGE);
        forced = a; o.mode = a.slice(2); break;
      case '--dry-run': o.dryRun = true; break;
      case '--uninstall': o.uninstall = true; break;
      case '--check': o.check = true; break;
      case '--force': o.force = true; break;
      case '--help': case '-h': o.help = true; break;
      case '--version': o.version = true; break;
      case '--project': o.project = inline !== null ? inline : need(i++, a); break;
      case '--dest': o.dest = inline !== null ? inline : need(i++, a); break;
      default: throw new Fail('unknown option: ' + argv[i] + ' (try --help)', EXIT.USAGE);
    }
  }
  if (o.uninstall && o.check) throw new Fail('--uninstall and --check are mutually exclusive', EXIT.USAGE);
  if (o.project && o.dest) throw new Fail('--project and --dest are mutually exclusive', EXIT.USAGE);
  if (o.dest && o.mode === 'plugin') throw new Fail('--dest only applies to copy mode (the plugin route is managed by Claude Code)', EXIT.USAGE);
  return o;
}

// ---------------------------------------------------------------- versions

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return null; }
}

function sourceVersion() {
  const pkg = readJson(path.join(ROOT, 'package.json'));
  const plug = readJson(path.join(ROOT, '.claude-plugin', 'plugin.json'));
  const v = (pkg && pkg.version) || (plug && plug.version) || 'unknown';
  if (pkg && plug && pkg.version && plug.version && pkg.version !== plug.version) {
    warn('package.json version (' + pkg.version + ') differs from .claude-plugin/plugin.json (' + plug.version + ')');
  }
  return v;
}

function nodeOk() {
  return parseInt(process.versions.node.split('.')[0], 10) >= 18;
}

// ---------------------------------------------------------------- destination

function resolveConfigDir(o) {
  if (o.dest) return path.resolve(o.dest);
  if (o.project) return path.join(path.resolve(o.project), '.claude');
  const env = process.env.CLAUDE_CONFIG_DIR;
  if (env && env.trim()) return path.resolve(env);
  return path.join(os.homedir(), '.claude');
}

function toNative(root, rel) { return path.join(root, ...rel.split('/')); }

// Refuse symlinks anywhere below the destination root along the path we are about to touch.
function assertNoSymlinks(root, rel) {
  const parts = rel.split('/');
  let cur = root;
  for (let i = 0; i < parts.length; i++) {
    cur = path.join(cur, parts[i]);
    let st;
    try { st = fs.lstatSync(cur); } catch (e) { if (e.code === 'ENOENT') return; throw e; }
    if (st.isSymbolicLink()) throw new Fail('refusing to touch ' + cur + ': it is a symlink (this installer never follows symlinks in the destination)', EXIT.CONFLICT);
    if (i < parts.length - 1 && !st.isDirectory()) throw new Fail('refusing to touch ' + cur + ': expected a directory', EXIT.CONFLICT);
  }
}

function validRel(rel) {
  if (typeof rel !== 'string' || !rel || rel.includes('\\') || rel.includes('\0') || path.isAbsolute(rel) || /^[A-Za-z]:/.test(rel)) return false;
  const segs = rel.split('/');
  if (segs.some((s) => s === '' || s === '.' || s === '..')) return false;
  return ALLOWED_PREFIXES.some((p) => rel.startsWith(p)) && rel !== MANIFEST_REL;
}

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

// ---------------------------------------------------------------- manifest

function readManifest(dest) {
  const file = toNative(dest, MANIFEST_REL);
  let st;
  try { st = fs.lstatSync(file); } catch (e) { return { manifest: null }; }
  if (!st.isFile()) return { manifest: null, problem: 'manifest path is not a regular file' };
  let m;
  try { m = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return { manifest: null, problem: 'manifest is not valid JSON' }; }
  if (!m || m.name !== NAME || !Array.isArray(m.files)) return { manifest: null, problem: 'manifest has an unexpected shape' };
  const files = [];
  for (const f of m.files) {
    const p = f && typeof f === 'object' ? f.path : null;
    if (!validRel(p)) return { manifest: null, problem: 'manifest lists a path outside the allowed directories: ' + JSON.stringify(p) };
    files.push({ path: p, sha256: f.sha256 || null });
  }
  return { manifest: { version: String(m.version || 'unknown'), installedAt: m.installedAt || null, source: m.source || null, files } };
}

function writeAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.bs-tmp-' + process.pid;
  fs.writeFileSync(tmp, data);
  try { fs.renameSync(tmp, file); } catch (e) { try { fs.unlinkSync(tmp); } catch (_) { /* ignore */ } throw e; }
}

function writeManifest(dest, version, files) {
  const m = { schema: 1, name: NAME, version, installedAt: new Date().toISOString(), source: ROOT, mode: 'copy', files };
  writeAtomic(toNative(dest, MANIFEST_REL), JSON.stringify(m, null, 2) + '\n');
}

// ---------------------------------------------------------------- source collection

function collectSource() {
  const skillSrc = path.join(ROOT, 'skills', NAME);
  if (!fs.existsSync(path.join(skillSrc, 'SKILL.md'))) throw new Fail('skills/boring-security/SKILL.md not found next to install.cjs; run this from a complete checkout');
  const files = [];
  const skipped = [];
  const walk = (absDir, relDir) => {
    for (const ent of fs.readdirSync(absDir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const rel = relDir ? relDir + '/' + ent.name : ent.name;
      if (SKIP_NAMES.has(ent.name)) continue;
      if (ent.isSymbolicLink()) { skipped.push(rel + ' (symlink)'); continue; }
      if (ent.isDirectory()) {
        if (SKIP_REL_DIRS.has(rel)) continue;
        walk(path.join(absDir, ent.name), rel);
      } else if (ent.isFile()) {
        if (TRANSIENT.test(ent.name) || ent.name === '.install-manifest.json') continue;
        files.push({ rel: SKILL_REL + '/' + rel, src: path.join(absDir, ent.name) });
      }
    }
  };
  walk(skillSrc, '');
  for (const [dir, label] of [['commands', 'commands'], ['agents', 'agents']]) {
    const d = path.join(ROOT, dir);
    if (!fs.existsSync(d)) continue;
    for (const ent of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (ent.isSymbolicLink()) { skipped.push(label + '/' + ent.name + ' (symlink)'); continue; }
      if (ent.isFile() && ent.name.endsWith('.md')) files.push({ rel: label + '/' + ent.name, src: path.join(d, ent.name) });
    }
  }
  for (const f of files) f.data = fs.readFileSync(f.src), f.hash = sha256(f.data);
  return { files, skipped };
}

// ---------------------------------------------------------------- claude CLI

function isFile(p) { try { return fs.statSync(p).isFile(); } catch (e) { return false; } }

function findClaude() {
  const override = process.env.BORING_SECURITY_CLAUDE_BIN;
  if (override) return isFile(override) ? path.resolve(override) : null;
  const dirs = (process.env.PATH || '').split(path.delimiter).map((d) => d.replace(/^"|"$/g, '')).filter(Boolean);
  const win = process.platform === 'win32';
  const exts = win ? ['.exe', '.cmd', '.bat'] : [''];
  for (const d of dirs) {
    for (const e of exts) {
      const p = path.join(d, 'claude' + e);
      if (!isFile(p)) continue;
      if (!win) { try { fs.accessSync(p, fs.constants.X_OK); } catch (err) { continue; } }
      return p;
    }
  }
  return null;
}

function quoteForCmd(a) {
  if (/["%!\r\n]/.test(a)) throw new Error('argument contains a character that cannot be passed safely through cmd.exe: ' + a);
  return '"' + a + '"';
}

function fmtCmd(bin, args) {
  return [bin].concat(args).map((a) => (/[\s"]/.test(a) ? '"' + a + '"' : a)).join(' ');
}

function runClaude(bin, args, opts) {
  opts = opts || {};
  let cmd = bin;
  let argv = args;
  const spawnOpts = { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: opts.timeout || 120000, windowsHide: true, maxBuffer: 8 * 1024 * 1024, cwd: opts.cwd, env: process.env };
  if (/\.(c|m)?js$/i.test(bin)) {
    cmd = process.execPath; argv = [bin].concat(args);
  } else if (process.platform === 'win32' && /\.(cmd|bat)$/i.test(bin)) {
    cmd = process.env.ComSpec || 'cmd.exe';
    argv = ['/d', '/s', '/c', '"' + [bin].concat(args).map(quoteForCmd).join(' ') + '"'];
    spawnOpts.windowsVerbatimArguments = true;
  }
  const r = cp.spawnSync(cmd, argv, spawnOpts);
  const text = ((r.stdout || '') + (r.stderr || '')).trim();
  if (r.error) return { ok: false, status: null, text, reason: r.error.code === 'ETIMEDOUT' ? 'timed out' : r.error.message };
  if (r.signal) return { ok: false, status: null, text, reason: 'killed by ' + r.signal };
  return { ok: r.status === 0, status: r.status, text, reason: r.status === 0 ? '' : 'exit status ' + r.status };
}

function claudeSupportsPlugins(bin) {
  const r = runClaude(bin, ['plugin', 'install', '--help'], { timeout: 20000 });
  return r.ok && r.text.length > 0;
}

function lastLines(text, n) { return text.split(/\r?\n/).slice(-n).join('\n    '); }

// ---------------------------------------------------------------- plugin route

function pluginSteps(o) {
  const scope = o.project ? 'project' : 'user';
  const steps = [
    { label: 'add marketplace', args: ['plugin', 'marketplace', 'add', MARKETPLACE_SOURCE, '--scope', 'user'], tolerate: /already/i },
    { label: 'install plugin', args: ['plugin', 'install', PLUGIN_ID, '--scope', scope], tolerate: null, onAlready: ['plugin', 'update', PLUGIN_ID, '--scope', scope] },
  ];
  return { steps, scope, cwd: o.project ? path.resolve(o.project) : undefined };
}

function warnIfCopyInstallExists(o) {
  if (o.dest || o.project) return;
  const { manifest } = readManifest(resolveConfigDir(o));
  if (manifest) warn('a copy-mode install already exists in ' + resolveConfigDir(o) + '; the plugin and the copy would both load. Remove the copy with: node install.cjs --uninstall --copy');
}

function installPlugin(o, bin, version) {
  const { steps, scope, cwd } = pluginSteps(o);
  out('boring-security ' + version + ': installing as a Claude Code plugin (scope: ' + scope + ')');
  out('  claude: ' + bin);
  for (const s of steps) {
    const r = runClaude(bin, s.args, { cwd });
    if (r.ok) { out('  ok   ' + s.label + (r.text ? ': ' + lastLines(r.text, 1) : '')); continue; }
    if (s.tolerate && s.tolerate.test(r.text)) { out('  ok   ' + s.label + ': already present'); continue; }
    if (s.onAlready && /already/i.test(r.text)) {
      const u = runClaude(bin, s.onAlready, { cwd });
      if (u.ok) { out('  ok   plugin already installed; updated: ' + lastLines(u.text, 1)); continue; }
      throw new Fail('plugin update failed (' + u.reason + '): ' + fmtCmd('claude', s.onAlready) + '\n    ' + lastLines(u.text, 6));
    }
    throw new Fail(s.label + ' failed (' + r.reason + '): ' + fmtCmd('claude', s.args) + '\n    ' + lastLines(r.text, 6));
  }
  warnIfCopyInstallExists(o);
  out('');
  out('Installed as the plugin ' + PLUGIN_ID + ' (slash commands, skill, subagents and hooks).');
  if (FROM_CHECKOUT) out('The plugin loads in place from this checkout, so keep it at: ' + ROOT);
  else out('Registered from GitHub (' + GITHUB_SOURCE + '); Claude Code keeps its own copy.');
  out('Next: restart Claude Code or start a new session (or run /reload-plugins), then try /quick-audit');
  out('or ask: "security audit this repo".');
  if (FROM_CHECKOUT) out('Update: git pull in this folder, then node install.cjs again. Remove: node install.cjs --uninstall');
  else out('Update: npx boring-security-skill@latest. Remove: npx boring-security-skill --uninstall');
}

// ---------------------------------------------------------------- copy route

function planCopy(dest, src, prev) {
  const prevSet = new Map(prev ? prev.files.map((f) => [f.path, f]) : []);
  const plan = [];
  const conflicts = [];
  for (const f of src.files) {
    assertNoSymlinks(dest, f.rel);
    const target = toNative(dest, f.rel);
    let st = null;
    try { st = fs.lstatSync(target); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (!st) { plan.push({ action: 'create', f }); continue; }
    if (!st.isFile()) { conflicts.push({ rel: f.rel, why: 'exists and is not a regular file' }); continue; }
    const same = sha256(fs.readFileSync(target)) === f.hash;
    if (same) { plan.push({ action: 'unchanged', f }); continue; }
    if (prevSet.has(f.rel)) plan.push({ action: 'update', f });
    else conflicts.push({ rel: f.rel, why: 'exists and was not installed by boring-security' });
  }
  const want = new Set(src.files.map((f) => f.rel));
  const stale = prev ? prev.files.filter((f) => !want.has(f.path)).map((f) => f.path) : [];
  return { plan, conflicts, stale };
}

function legacyWarn(dest) {
  const rec = path.join(dest, 'plugins', 'installed_plugins.json');
  try {
    if (fs.readFileSync(rec, 'utf8').includes(PLUGIN_ID)) warn('the plugin ' + PLUGIN_ID + ' is also installed; the plugin and the copy would both load. Uninstall one of them.');
  } catch (e) { /* not present */ }
}

function installCopy(o, version, reason) {
  const dest = resolveConfigDir(o);
  const src = collectSource();
  const { manifest: prev, problem } = readManifest(dest);
  if (problem) warn('previous manifest ignored: ' + problem);
  const { plan, conflicts, stale } = planCopy(dest, src, prev);
  const counts = { create: 0, update: 0, unchanged: 0 };
  for (const p of plan) counts[p.action]++;

  out('boring-security ' + version + ': ' + (o.dryRun ? 'dry run, ' : '') + 'copy install' + (reason ? ' (' + reason + ')' : ''));
  out('  from: ' + ROOT);
  out('  to:   ' + dest);
  if (prev) out('  previous install: ' + prev.version + ' (upgrading in place)');
  for (const s of src.skipped) warn('skipped ' + s);

  if (conflicts.length && !o.force) {
    out('');
    out('Refusing to overwrite files that boring-security did not install:');
    for (const c of conflicts) out('  ! ' + c.rel + '  (' + c.why + ')');
    out('Nothing was written. Rename or move those files, or re-run with --force to overwrite them.');
    throw new Fail('conflicts found', EXIT.CONFLICT);
  }
  const forced = conflicts.map((c) => c.rel);

  if (o.dryRun) {
    out('');
    for (const p of plan) if (p.action !== 'unchanged') out('  ' + (p.action === 'create' ? '+ create ' : '~ update ') + p.f.rel);
    for (const c of forced) out('  ~ overwrite (--force) ' + c);
    for (const s of stale) out('  - remove (no longer shipped) ' + s);
    out('  = ' + counts.unchanged + ' unchanged');
    out('Dry run: nothing was changed. Hooks are not installed in copy mode.');
    return;
  }

  const all = src.files.map((f) => ({ path: f.rel, sha256: f.hash }));
  // Manifest first (union of old and new) so an interrupted run can still be uninstalled cleanly.
  const union = all.concat((prev ? prev.files : []).filter((f) => !all.some((a) => a.path === f.path)));
  writeManifest(dest, version, union);
  for (const f of src.files) {
    const target = toNative(dest, f.rel);
    const p = plan.find((x) => x.f === f);
    if (p && p.action === 'unchanged') continue;
    assertNoSymlinks(dest, f.rel);
    writeAtomic(target, f.data);
  }
  let removed = 0;
  for (const rel of stale) {
    assertNoSymlinks(dest, rel);
    try { fs.unlinkSync(toNative(dest, rel)); removed++; } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  writeManifest(dest, version, all);
  removeEmptyDirs(dest, stale);

  const nCmd = src.files.filter((f) => f.rel.startsWith('commands/')).length;
  const nAgents = src.files.filter((f) => f.rel.startsWith('agents/')).length;
  out('');
  out('Installed ' + src.files.length + ' files: ' + counts.create + ' new, ' + counts.update + ' updated, ' + counts.unchanged + ' unchanged' + (removed ? ', ' + removed + ' stale removed' : '') + '.');
  out('  skill: ' + path.join(dest, 'skills', NAME) + '   commands: ' + nCmd + '   subagents: ' + nAgents);
  if (forced.length) warn('overwrote ' + forced.length + ' file(s) not installed by boring-security (--force): ' + forced.join(', '));
  out('Hooks are NOT installed in copy mode (they need the plugin route), so the enforcement hooks and the');
  out('write-time secret guard are inactive. Re-run with --plugin to get them.');
  legacyWarn(dest);
  out('Next: restart Claude Code or start a new session, then try /quick-audit or ask: "security audit this repo".');
  out('Check: node install.cjs --check' + (o.dest ? ' --dest ' + o.dest : '') + (o.project ? ' --project ' + o.project : '') + '   Remove: node install.cjs --uninstall' + (o.dest ? ' --dest ' + o.dest : '') + (o.project ? ' --project ' + o.project : ''));
}

function removeEmptyDirs(dest, rels) {
  const dirs = new Set();
  for (const rel of rels) {
    const parts = rel.split('/');
    for (let i = parts.length - 1; i >= 2; i--) {
      const d = parts.slice(0, i).join('/');
      if (d.startsWith(SKILL_REL + '/')) dirs.add(d);
    }
  }
  for (const d of [...dirs].sort((a, b) => b.length - a.length)) {
    try { fs.rmdirSync(toNative(dest, d)); } catch (e) { /* not empty or gone */ }
  }
}

// ---------------------------------------------------------------- uninstall

function uninstallCopy(o) {
  const dest = resolveConfigDir(o);
  const { manifest, problem } = readManifest(dest);
  if (problem) throw new Fail('cannot uninstall safely: ' + problem + ' (' + toNative(dest, MANIFEST_REL) + '); remove files by hand', EXIT.ERROR);
  if (!manifest) { out('No copy-mode install found in ' + dest + '.'); return false; }
  out('boring-security ' + manifest.version + ': ' + (o.dryRun ? 'dry run, ' : '') + 'removing copy install from ' + dest);
  let n = 0;
  const gone = [];
  for (const f of manifest.files) {
    const target = toNative(dest, f.path);
    try { assertNoSymlinks(dest, f.path); } catch (e) { warn('skipped ' + f.path + ': ' + e.message); continue; }
    let st = null;
    try { st = fs.lstatSync(target); } catch (e) { continue; }
    if (!st.isFile()) { warn('skipped ' + f.path + ': not a regular file'); continue; }
    if (o.dryRun) { out('  - ' + f.path); n++; continue; }
    fs.unlinkSync(target); n++; gone.push(f.path);
  }
  if (o.dryRun) { out('Dry run: ' + n + ' file(s) would be removed, nothing was changed.'); return true; }
  try { fs.unlinkSync(toNative(dest, MANIFEST_REL)); } catch (e) { /* ignore */ }
  removeEmptyDirs(dest, gone);
  try { fs.rmdirSync(toNative(dest, SKILL_REL)); } catch (e) { /* not empty (user files) or gone */ }
  out('Removed ' + n + ' file(s) and the manifest. Files you added yourself were left alone.');
  return true;
}

function pluginInstalled(bin) {
  const r = runClaude(bin, ['plugin', 'list'], { timeout: 30000 });
  return r.ok && r.text.includes(PLUGIN_ID) ? r : null;
}

function uninstallPlugin(o, bin) {
  const scope = o.project ? 'project' : 'user';
  const args = ['plugin', 'uninstall', PLUGIN_ID, '--scope', scope];
  if (o.dryRun) { out('Would run: ' + fmtCmd('claude', args)); return; }
  const r = runClaude(bin, args, { cwd: o.project ? path.resolve(o.project) : undefined });
  if (!r.ok) throw new Fail('plugin uninstall failed (' + r.reason + '): ' + fmtCmd('claude', args) + '\n    ' + lastLines(r.text, 6));
  out('Uninstalled the plugin ' + PLUGIN_ID + '. (The local marketplace entry stays; remove it with: claude plugin marketplace remove boring-security)');
}

function doUninstall(o) {
  let did = false;
  if (o.mode !== 'plugin') did = uninstallCopy(o) || did;
  if (o.mode !== 'copy' && !o.dest) {
    const bin = findClaude();
    if (bin && claudeSupportsPlugins(bin) && (o.mode === 'plugin' || pluginInstalled(bin))) { uninstallPlugin(o, bin); did = true; }
    else if (o.mode === 'plugin') throw new Fail('claude CLI with plugin support not found; cannot uninstall the plugin');
  }
  if (!did) out('Nothing to uninstall.');
}

// ---------------------------------------------------------------- check

function selfTest(skillDir) {
  const scripts = path.join(skillDir, 'scripts');
  const mods = SELF_TEST_MODULES.map((m) => path.join(scripts, m));
  for (const m of mods) if (!isFile(m)) return { ok: false, msg: 'missing ' + m };
  let r = cp.spawnSync(process.execPath, ['-e', 'for (const f of process.argv.slice(1)) require(f);'].concat(mods), { encoding: 'utf8', timeout: 30000, windowsHide: true });
  if (r.error || r.status !== 0) return { ok: false, msg: 'validators failed to load: ' + lastLines(((r.stderr || '') + (r.error ? r.error.message : '')).trim(), 4) };
  r = cp.spawnSync(process.execPath, [path.join(scripts, 'detect.cjs'), '--list-rules'], { encoding: 'utf8', timeout: 30000, windowsHide: true });
  if (r.error || r.status !== 0) return { ok: false, msg: 'detect.cjs --list-rules failed: ' + lastLines(((r.stderr || '') + (r.error ? r.error.message : '')).trim(), 4) };
  const rules = (r.stdout || '').split(/\r?\n/).filter((l) => l.trim()).length;
  if (rules < 1) return { ok: false, msg: 'detect.cjs --list-rules printed nothing' };
  return { ok: true, msg: 'validators load; detector lists ' + rules + ' rules' };
}

function doCheck(o, version) {
  const dest = resolveConfigDir(o);
  let failed = false;
  const line = (ok, s) => { out('  ' + (ok ? 'ok   ' : 'FAIL ') + s); if (!ok) failed = true; };
  out('boring-security check (source version ' + version + ')');
  line(nodeOk(), 'Node ' + process.versions.node + (nodeOk() ? '' : ' (need >= 18)'));

  const { manifest, problem } = readManifest(dest);
  let skillDir = null;
  if (problem) line(false, 'manifest problem: ' + problem);
  if (manifest) {
    out('  copy install: ' + dest);
    line(true, 'manifest found, installed version ' + manifest.version);
    if (manifest.version !== version) out('  warn outdated: installed ' + manifest.version + ', source ' + version + ' (re-run node install.cjs)');
    const missing = [];
    const modified = [];
    for (const f of manifest.files) {
      try { assertNoSymlinks(dest, f.path); } catch (e) { missing.push(f.path + ' (symlink)'); continue; }
      let st = null;
      try { st = fs.lstatSync(toNative(dest, f.path)); } catch (e) { /* missing */ }
      if (!st || !st.isFile()) { missing.push(f.path); continue; }
      if (f.sha256 && sha256(fs.readFileSync(toNative(dest, f.path))) !== f.sha256) modified.push(f.path);
    }
    line(missing.length === 0, manifest.files.length - missing.length + '/' + manifest.files.length + ' files present' + (missing.length ? '; missing: ' + missing.slice(0, 5).join(', ') + (missing.length > 5 ? ', ...' : '') : ''));
    if (modified.length) out('  warn ' + modified.length + ' file(s) differ from what was installed (edited locally?): ' + modified.slice(0, 3).join(', '));
    skillDir = toNative(dest, SKILL_REL);
  }

  let plugin = false;
  if (!o.dest && !o.project && o.mode !== 'copy') {
    const bin = findClaude();
    if (bin && claudeSupportsPlugins(bin)) {
      const r = pluginInstalled(bin);
      if (r) {
        plugin = true;
        out('  plugin install: ' + PLUGIN_ID);
        line(true, 'plugin is listed (hooks and subagents are only active this way; confirm it is enabled with: claude plugin list)');
        if (!skillDir) skillDir = path.join(ROOT, 'skills', NAME);
        if (manifest) out('  warn both a plugin and a copy are installed; they will both load. Uninstall one.');
      }
    }
  }

  if (!manifest && !plugin && !problem) line(false, 'no installation found (copy manifest absent' + (o.dest || o.project ? '' : ', plugin not listed') + ') in ' + dest);
  if (skillDir) {
    const t = selfTest(skillDir);
    line(t.ok, 'self-test from ' + skillDir + ': ' + t.msg);
  }
  out(failed ? 'Check FAILED.' : 'Check passed.');
  if (failed) throw new Fail('check failed', EXIT.CHECK_FAILED);
}

// ---------------------------------------------------------------- install (mode selection)

function doInstall(o, version) {
  if (!nodeOk()) throw new Fail('Node >= 18 is required (found ' + process.versions.node + ')');
  let mode = o.mode;
  if (mode === 'auto' && (o.dest || o.project)) mode = 'copy';
  if (mode === 'copy') return installCopy(o, version, '');

  const bin = findClaude();
  let why = null;
  if (!bin) why = 'the claude CLI was not found on PATH';
  else if (!claudeSupportsPlugins(bin)) why = 'the claude CLI at ' + bin + ' does not support "claude plugin install"';

  if (why) {
    if (mode === 'plugin') throw new Fail(why + '; cannot use --plugin');
    out('Plugin route unavailable: ' + why + '. Using copy mode.');
    return installCopy(o, version, 'fallback');
  }
  if (o.dryRun) {
    const { steps, cwd } = pluginSteps(o);
    out('boring-security ' + version + ': dry run, plugin install via ' + bin);
    for (const s of steps) out('  would run: ' + fmtCmd('claude', s.args) + (cwd ? '   (cwd ' + cwd + ')' : ''));
    out('Dry run: nothing was changed.');
    return;
  }
  try {
    installPlugin(o, bin, version);
  } catch (e) {
    if (!(e instanceof Fail) || mode === 'plugin') throw e;
    out('');
    out('Plugin install failed: ' + e.message);
    out('Falling back to copy mode.');
    installCopy(o, version, 'fallback after plugin failure');
  }
}

// ---------------------------------------------------------------- main

function main(argv) {
  let o;
  try {
    o = parseArgs(argv);
    if (o.help) { out(HELP); return EXIT.OK; }
    const version = sourceVersion();
    if (o.version) { out(version); return EXIT.OK; }
    if (o.check) doCheck(o, version);
    else if (o.uninstall) doUninstall(o);
    else doInstall(o, version);
    return EXIT.OK;
  } catch (e) {
    if (e instanceof Fail) {
      if (e.code === EXIT.USAGE) process.stderr.write('error: ' + e.message + '\n');
      else if (e.message !== 'conflicts found' && e.message !== 'check failed') process.stderr.write('error: ' + e.message + '\n');
      return e.code;
    }
    process.stderr.write('error: ' + (e && e.stack ? e.stack : e) + '\n');
    return EXIT.ERROR;
  }
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { main, parseArgs, EXIT };
