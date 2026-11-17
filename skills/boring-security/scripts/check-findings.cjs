#!/usr/bin/env node
'use strict';
// Validate findings.json against schema/findings.schema.json (the single source of truth for shape),
// then the cross-record rules a schema can't express:
//   - records sorted by fingerprint, no duplicates; trace order entrypoint -> propagation* -> sink
//   - severity.overall <= severity.impact.level
//   - confirmed execution.proof = "local": execution.evidence_files has >= 1 entry
//   - confirmed execution.proof = "static": trace has >= 2 steps, entrypoint first, sink last
// Usage: node check-findings.cjs <findings.json> [--ledger <ledger.json>] [--target <repo>]
//   --ledger  cross-check fingerprints against the ledger; run.json next to the ledger (if present)
//             decides whether unlinked candidates are fatal.
//   --target  verify every trace/evidence quote against the target checkout (lib.quoteMatches rule:
//             >= 10 chars and within 2 lines of `line`, or exactly the whole text of a nearby line).

const fs = require('fs');
const path = require('path');
const { Reporter, loadJson, LEDGER_LIMITS, hasOwn, isObj, isArr, isRelPath, lintSchema, validateSchema, quoteMatches, makeTargetReader, normWs, QUOTE_MIN_CHARS } = require('./lib.cjs');

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
    if (r.verdict === 'confirmed' && isObj(r.execution)) {
      const ex = r.execution;
      if (ex.proof === 'local') {
        if (!isArr(ex.evidence_files) || !ex.evidence_files.length) rep.err(w, 'execution.proof "local" needs at least one execution.evidence_files entry');
      } else if (ex.proof === 'static') {
        const steps = isArr(r.trace) ? r.trace.map((t) => (isObj(t) ? t.step : undefined)) : [];
        if (steps.length < 2 || steps[0] !== 'entrypoint' || steps[steps.length - 1] !== 'sink') {
          rep.err(w, 'execution.proof "static" needs the whole path quoted: a trace of two or more steps from entrypoint to sink');
        }
      }
    }
    // Short quotes are only valid when they are a whole source line; that needs --target to verify.
    for (const key of ['trace', 'evidence']) for (const [j, e] of (isArr(r[key]) ? r[key] : []).entries()) {
      if (isObj(e) && typeof e.quote === 'string' && normWs(e.quote) && [...normWs(e.quote)].length < QUOTE_MIN_CHARS) {
        rep.warn(`${w}.${key}[${j}]`, `quote shorter than ${QUOTE_MIN_CHARS} characters: valid only if it is the whole text of a nearby line (checked with --target)`);
      }
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

// Every trace/evidence quote must pass lib.quoteMatches against the target checkout, so a made-up
// location or a trivially satisfiable excerpt (")", "e") fails. Files are read inside the target only
// (symlinks resolving outside it are refused). `reader` is an optional lib.makeTargetReader(target) to share.
function verifyQuotes(findings, target, rep, reader = makeTargetReader(target)) {
  if (!reader.root) { rep.err('target', `${target} is not a readable directory`); return; }
  (isArr(findings) ? findings : []).forEach((r, i) => {
    if (!isObj(r)) return;
    for (const key of ['trace', 'evidence']) for (const [j, e] of (isArr(r[key]) ? r[key] : []).entries()) {
      if (!isObj(e) || typeof e.file !== 'string' || typeof e.quote !== 'string' || !Number.isInteger(e.line)) continue;
      const w = `findings[${i}](${r.fingerprint}).${key}[${j}]`;
      if (!isRelPath(e.file)) { rep.err(w, `${JSON.stringify(e.file)} not found as a regular file inside the target (not a safe repo-relative path)`); continue; }
      const ls = reader.lines(e.file);
      if (!ls) { rep.err(w, `${e.file} not found as a regular file inside the target`); continue; }
      const m = quoteMatches(ls, e.line, e.quote);
      if (!m.ok) rep.err(w, `quote not found near ${e.file}:${e.line} (${m.why})`);
    }
  });
}

function main(argv) {
  const args = argv.slice(2);
  if (!args.length || args.includes('-h') || args.includes('--help')) {
    console.log([
      'usage: node check-findings.cjs <findings.json> [--ledger <ledger.json>] [--target <repo>]',
      '  --ledger <ledger.json>  cross-check fingerprints against the ledger (run.json next to it decides',
      '                          whether unlinked ledger candidates are fatal)',
      '  --target <repo>         verify every trace/evidence quote in the target checkout: after whitespace',
      '                          normalisation it must be >= 10 characters and appear within 2 lines of',
      '                          `line`, or equal the whole text of one line within 2 lines',
      'Confirmed records need execution.proof: "local" (>= 1 execution.evidence_files) or "static"',
      '(trace of >= 2 steps from entrypoint to sink).',
    ].join('\n'));
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
      const ledger = loadJson(args[li + 1], rep, LEDGER_LIMITS);
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
  for (const r of findings) if (isObj(r) && hasOwn(counts, r.verdict)) counts[r.verdict]++;
  return rep.finish('findings', `${counts.confirmed} confirmed, ${counts.needs_validation} needs_validation, ${counts.rejected} rejected`);
}

if (require.main === module) process.exitCode = main(process.argv);
module.exports = { validateFindings, crossCheckLedger, verifyQuotes, loadSchema, main };
