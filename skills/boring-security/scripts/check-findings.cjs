#!/usr/bin/env node
'use strict';
// Validate findings.json against schema/findings.schema.json (the single source of truth for shape),
// then the cross-record rules a schema can't express.
// Usage: node check-findings.cjs <findings.json> [--ledger <ledger.json>]
//   With --ledger, run.json next to the ledger (if present) decides whether unlinked candidates are fatal.

const fs = require('fs');
const path = require('path');
const { Reporter, loadJson, isObj, isArr, lintSchema, validateSchema } = require('./lib.cjs');

const SCHEMA_PATH = path.resolve(__dirname, '..', 'schema', 'findings.schema.json');
const LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];

function loadSchema() {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  const problems = [];
  lintSchema(schema, 'schema', problems);
  if (problems.length) throw new Error(`unsupported or invalid schema:\n${problems.join('\n')}`);
  return schema;
}

function validateFindings(data, rep, schema = loadSchema()) {
  for (const e of validateSchema(data, schema, schema, 'findings')) rep.err('schema', e);
  if (!isArr(data)) return [];
  const seen = new Map();
  let prev = null;
  data.forEach((r, i) => {
    if (!isObj(r)) return;
    const w = `findings[${i}](${typeof r.fingerprint === 'string' ? r.fingerprint : '?'})`;
    if (typeof r.fingerprint === 'string') {
      if (seen.has(r.fingerprint)) rep.err(w, `duplicate fingerprint (also index ${seen.get(r.fingerprint)})`);
      seen.set(r.fingerprint, i);
      if (prev !== null && r.fingerprint < prev) rep.err(w, 'records must be sorted by fingerprint');
      prev = r.fingerprint;
      if (/:L?\d+$/.test(r.fingerprint)) rep.warn(w, 'fingerprint ends with a number: make sure it is not a line number');
    }
    if (isArr(r.trace) && r.trace.every(isObj)) {
      const steps = r.trace.map((t) => t.step);
      if (steps.length === 1 && steps[0] === 'propagation') rep.err(w, 'a one-step trace must be entrypoint or sink');
      if (steps.length > 1) {
        if (steps[0] !== 'entrypoint') rep.err(w, 'trace must start with entrypoint');
        if (steps[steps.length - 1] !== 'sink') rep.err(w, 'trace must end with sink');
        if (steps.slice(1, -1).some((s) => s !== 'propagation')) rep.err(w, 'middle trace steps must be propagation');
      }
    }
    const sev = r.severity;
    if (isObj(sev) && isObj(sev.impact)) {
      const o = LEVELS.indexOf(sev.overall); const im = LEVELS.indexOf(sev.impact.level);
      if (o >= 0 && im >= 0 && o > im) rep.err(w, `severity.overall "${sev.overall}" exceeds demonstrated impact "${sev.impact.level}"`);
    }
  });
  return data;
}

function crossCheckLedger(findings, ledger, rep, runStatus) {
  if (!isArr(ledger)) { rep.err('ledger', 'top level must be an array'); return; }
  const live = new Map();
  const known = new Set();
  for (const u of ledger) {
    if (!isObj(u)) continue;
    for (const fp of isArr(u.fingerprints) ? u.fingerprints : []) { known.add(fp); if (!live.has(fp)) live.set(fp, []); live.get(fp).push(u.id); }
    for (const h of isArr(u.history) ? u.history : []) for (const fp of isObj(h) && isArr(h.fingerprints) ? h.fingerprints : []) known.add(fp);
  }
  const have = new Set();
  for (const r of findings) {
    if (!isObj(r) || typeof r.fingerprint !== 'string') continue;
    have.add(r.fingerprint);
    if (!known.has(r.fingerprint)) rep.err(`findings(${r.fingerprint})`, 'fingerprint is not linked to any ledger unit');
  }
  for (const [fp, ids] of live) {
    if (have.has(fp)) continue;
    const msg = `ledger candidate in ${ids.slice(0, 3).join(', ')} has no final record`;
    if (runStatus === 'complete') rep.err(`ledger(${fp})`, `${msg}, but run.json says complete`);
    else rep.warn(`ledger(${fp})`, `${msg} (allowed only while the run is incomplete)`);
  }
}

// Every trace/evidence quote must appear (whitespace-normalized) within ±2 lines of its cited line in the
// target checkout, so a made-up location or excerpt fails. Files are read inside the target only.
const norm = (s) => s.replace(/\s+/g, ' ').trim();
function verifyQuotes(findings, target, rep) {
  const root = path.resolve(target);
  const cache = new Map();
  const lines = (rel) => {
    if (cache.has(rel)) return cache.get(rel);
    let v = null;
    try {
      const realRoot = fs.realpathSync(root);
      const full = fs.realpathSync(path.resolve(root, ...rel.split('/'))); // resolves symlinked dirs too
      const inside = path.relative(realRoot, full);
      const st = fs.statSync(full);
      if (!inside.startsWith('..') && !path.isAbsolute(inside) && st.isFile() && st.size <= 5 * 1024 * 1024) v = fs.readFileSync(full, 'utf8').split(/\r?\n/);
    } catch { /* missing */ }
    cache.set(rel, v); return v;
  };
  findings.forEach((r, i) => {
    if (!isObj(r)) return;
    for (const key of ['trace', 'evidence']) for (const [j, e] of (isArr(r[key]) ? r[key] : []).entries()) {
      if (!isObj(e) || typeof e.file !== 'string' || typeof e.quote !== 'string' || !Number.isInteger(e.line)) continue;
      const w = `findings[${i}](${r.fingerprint}).${key}[${j}]`;
      const ls = lines(e.file);
      if (!ls) { rep.err(w, `${e.file} not found as a regular file inside the target`); continue; }
      const window = norm(ls.slice(Math.max(0, e.line - 3), e.line + 2).join(' '));
      if (!window.includes(norm(e.quote))) rep.err(w, `quote not found near ${e.file}:${e.line}`);
    }
  });
}

function main(argv) {
  const args = argv.slice(2);
  if (!args.length || args.includes('-h') || args.includes('--help')) {
    console.log('usage: node check-findings.cjs <findings.json> [--ledger <ledger.json>] [--target <repo>]');
    return args.length ? 0 : 2;
  }
  const rep = new Reporter();
  const data = loadJson(args[0], rep);
  let findings = [];
  if (data !== undefined) findings = validateFindings(data, rep);
  const li = args.indexOf('--ledger');
  if (li !== -1) {
    if (!args[li + 1]) rep.err('args', '--ledger needs a path');
    else {
      const ledger = loadJson(args[li + 1], rep);
      const runPath = path.join(path.dirname(path.resolve(args[li + 1])), 'run.json');
      const run = fs.existsSync(runPath) ? loadJson(runPath, rep) : undefined;
      if (ledger !== undefined && data !== undefined) crossCheckLedger(findings, ledger, rep, isObj(run) ? run.status : undefined);
    }
  }
  const ti = args.indexOf('--target');
  if (ti !== -1) {
    if (!args[ti + 1]) rep.err('args', '--target needs a path');
    else if (data !== undefined) verifyQuotes(findings, args[ti + 1], rep);
  }
  const counts = { confirmed: 0, needs_validation: 0, rejected: 0 };
  for (const r of findings) if (isObj(r) && r.verdict in counts) counts[r.verdict]++;
  return rep.finish('findings', `${counts.confirmed} confirmed, ${counts.needs_validation} needs_validation, ${counts.rejected} rejected`);
}

if (require.main === module) process.exitCode = main(process.argv);
module.exports = { validateFindings, crossCheckLedger, verifyQuotes, loadSchema, main };
