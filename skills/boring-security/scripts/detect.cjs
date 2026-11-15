#!/usr/bin/env node
'use strict';
// Deterministic, zero-dependency security detector. No network, no LLM calls, never executes target code.
// Hits are LEADS for Hunters (verify each one), never findings.
//
// Usage: node detect.cjs <target> [--json <out.json>] [--diff <git-base>] [--files <a,b>]
//                        [--min-confidence low|medium|high] [--include-tests] [--list-rules]
// Reads <target>/.boring-security/config.json for exclusions and dated suppressions.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const RULES = require('./detect-rules.cjs');
const { areaOf } = require('./lib.cjs');

const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'dist', 'build', 'out', 'target', '.next', '.nuxt', '.svelte-kit',
  'coverage', '__pycache__', '.venv', 'venv', 'env', 'Pods', '.gradle', '.idea', '.vscode', 'bower_components', '.terraform', '.dart_tool', 'DerivedData', '.boring-security']);
const KEEP_IN_SKIPPED = /(?:^|\/)AndroidManifest\.xml$/; // merged manifests live under build/
const MAX_FILE = 1024 * 1024;
const MAX_LINE = 2000;
const CONF = { low: 0, medium: 1, high: 2 };
const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|examples?|samples?|testdata|mocks?)(?:\/|$)|\.(?:test|spec)\.[^/]+$|_test\.(?:go|py)$|(?:^|\/)test_[^/]+\.py$/i;
const INLINE_IGNORE = /boring-security-ignore\s+([\w.*-]+)\s+--\s+\S/;

function globToRe(g) {
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*' && g[i + 1] === '*') { re += '.*'; i++; if (g[i + 1] === '/') i++; }
    else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

function loadConfig(target, warnings) {
  const p = path.join(target, '.boring-security', 'config.json');
  const cfg = { exclude: [], ignore: [] };
  if (!fs.existsSync(p)) return cfg;
  let raw;
  try { raw = JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { warnings.push(`config.json unreadable: ${e.message}`); return cfg; }
  const d = (raw && raw.detector) || {};
  cfg.exclude = (Array.isArray(d.exclude_paths) ? d.exclude_paths : []).filter((g) => typeof g === 'string').map(globToRe);
  const today = new Date().toISOString().slice(0, 10);
  for (const e of Array.isArray(d.ignore) ? d.ignore : []) {
    if (!e || typeof e.rule !== 'string' || typeof e.reason !== 'string' || !e.reason.trim() || typeof e.expires !== 'string') {
      warnings.push(`ignored suppression without rule/reason/expires: ${JSON.stringify(e)}`); continue;
    }
    if (e.expires < today) { warnings.push(`expired suppression no longer applied: ${e.rule} (${e.expires})`); continue; }
    cfg.ignore.push({ rule: globToRe(e.rule), path: globToRe(e.path || '**'), reason: e.reason, id: e.rule });
  }
  return cfg;
}

function listFiles(target, opts) {
  if (opts.files) return opts.files;
  if (opts.diff) {
    const out = execFileSync('git', ['-C', target, 'diff', '--name-only', '--diff-filter=ACMR', opts.diff], { encoding: 'utf8' });
    return out.split('\n').filter(Boolean);
  }
  const files = [];
  (function walk(dir, rel, skipped) {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) walk(path.join(dir, e.name), r, skipped || SKIP_DIRS.has(e.name));
      else if (e.isFile() && (!skipped || KEEP_IN_SKIPPED.test(r))) files.push(r);
    }
  })(target, '', false);
  return files;
}

const redact = (line, m) => line.replace(m, (s) => `${s.slice(0, 4)}…[redacted ${s.length} chars]`);

function scanFile(rel, text, rules) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  for (const rule of rules) {
    if (!rule.files.test(rel)) continue;
    if (rule.nameOnly) { hits.push({ rule, line: 1, snippet: rel }); continue; }
    if (rule.requires && !rule.requires.test(text)) continue;
    if (rule.unlessFile && rule.unlessFile.test(text)) continue;
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i];
      if (ln.length > MAX_LINE) continue; // minified or generated
      const m = rule.pattern.exec(ln);
      if (!m || (rule.unless && rule.unless.test(ln))) continue;
      const ig = INLINE_IGNORE.exec(ln) || (i > 0 && INLINE_IGNORE.exec(lines[i - 1]));
      if (ig && globToRe(ig[1]).test(rule.id)) continue;
      const snippet = (rule.secret ? redact(ln, m[0]) : ln).trim().slice(0, 200);
      hits.push({ rule, line: i + 1, snippet });
      if (rule.once) break;
    }
  }
  return hits;
}

function detect(target, opts = {}) {
  const warnings = [];
  const cfg = loadConfig(target, warnings);
  const min = CONF[opts.minConfidence || 'low'];
  const rules = RULES.filter((r) => CONF[r.conf] >= min - 1); // tests downgrade one level later
  const results = [];
  let scanned = 0;
  let suppressed = 0;
  for (const rel of listFiles(target, opts)) {
    const posix = rel.split(path.sep).join('/');
    if (cfg.exclude.some((re) => re.test(posix))) continue;
    const full = path.join(target, rel);
    let st;
    try { st = fs.lstatSync(full); } catch { continue; }
    if (!st.isFile() || st.size > MAX_FILE) continue;
    const inTest = TEST_PATH.test(posix);
    if (inTest && !opts.includeTests) continue;
    scanned++;
    const buf = fs.readFileSync(full);
    const binary = buf.includes(0); // binary files still get file-name rules (e.g. .p12, .jks)
    const fileRules = binary ? rules.filter((r) => r.nameOnly) : rules;
    for (const h of scanFile(posix, binary ? '' : buf.toString('utf8'), fileRules)) {
      let conf = CONF[h.rule.conf] - (inTest ? 1 : 0);
      if (conf < min) continue;
      const sup = cfg.ignore.find((s) => s.rule.test(h.rule.id) && s.path.test(posix));
      if (sup) { suppressed++; continue; }
      conf = Math.max(conf, 0);
      results.push({
        rule: h.rule.id, area: areaOf(h.rule.cls), class: h.rule.cls,
        confidence: Object.keys(CONF)[conf], file: posix, line: h.line, in_test: inTest,
        snippet: h.snippet, verify: h.rule.verify,
      });
    }
  }
  results.sort((a, b) => CONF[b.confidence] - CONF[a.confidence] || a.file.localeCompare(b.file) || a.line - b.line);
  return { tool: 'boring-security-detect', rules: RULES.length, files_scanned: scanned, suppressed, warnings, hits: results };
}

function main(argv) {
  const args = argv.slice(2);
  const val = (f) => { const i = args.indexOf(f); return i !== -1 ? args[i + 1] : undefined; };
  if (args.includes('--list-rules')) {
    for (const r of RULES) console.log(`${r.id.padEnd(36)} ${r.conf.padEnd(7)} ${areaOf(r.cls)}`);
    console.log(`${RULES.length} rules`);
    return 0;
  }
  const target = args[0];
  if (!target || target.startsWith('--')) { console.error('usage: node detect.cjs <target> [--json out] [--diff base] [--files a,b] [--min-confidence low|medium|high] [--include-tests] [--list-rules]'); return 2; }
  const min = val('--min-confidence') || 'low';
  if (!(min in CONF)) { console.error('--min-confidence must be low|medium|high'); return 2; }
  const out = detect(path.resolve(target), {
    diff: val('--diff'), files: val('--files') ? val('--files').split(',') : undefined,
    minConfidence: min, includeTests: args.includes('--include-tests'),
  });
  if (val('--json')) fs.writeFileSync(val('--json'), JSON.stringify(out, null, 2) + '\n');
  for (const w of out.warnings) console.error(`warning  ${w}`);
  const byArea = {};
  for (const h of out.hits) byArea[h.area] = (byArea[h.area] || 0) + 1;
  console.log(`detector: ${out.hits.length} lead(s) in ${out.files_scanned} file(s), ${out.rules} rules, ${out.suppressed} suppressed`);
  for (const [a, n] of Object.entries(byArea).sort((x, y) => y[1] - x[1])) console.log(`  ${String(n).padStart(4)}  ${a}`);
  if (!val('--json')) for (const h of out.hits) console.log(`${h.confidence.padEnd(6)} ${h.rule.padEnd(34)} ${h.file}:${h.line}  ${h.snippet}`);
  return 0;
}

if (require.main === module) process.exitCode = main(process.argv);
module.exports = { detect, scanFile, globToRe, listFiles, TEST_PATH };
