#!/usr/bin/env node
'use strict';
// Scores a full audit's findings.json against a corpus ground-truth file.
//
// Usage: node bench/score-run.cjs <findings.json> <expected.json> [--run-dir <dir>] [--json <file>] [--tolerance <lines>]
//
// A finding matches an item when any of its trace/evidence entries cites the item's file (or an extra location of
// the item) within the item's line range +/- tolerance (default 3). A finding that matches a vuln item is a true
// positive even if it also sits near a decoy. Findings that match nothing are reported as "unmatched", not as
// "false": they may be real bugs nobody planted. Corpus numbers measure regressions, not real-world detection rate.

const fs = require('fs');
const path = require('path');
const { citationMatchesItem, readJson, table, pct } = require('./lib.cjs');

function loadFindings(file) {
  const data = readJson(file);
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.findings)) return data.findings;
  throw new Error('findings file must be a JSON array (or an object with a findings array)');
}

function citations(f) {
  const out = [];
  for (const key of ['trace', 'evidence']) {
    if (!Array.isArray(f && f[key])) continue;
    for (const c of f[key]) if (c && typeof c === 'object' && c.file != null && c.line != null) out.push({ file: c.file, line: c.line });
  }
  return out;
}

function matchFinding(f, items, tol) {
  const cites = citations(f);
  const hit = items.filter((it) => cites.some((c) => citationMatchesItem(c, it, tol)));
  return { vulns: hit.filter((i) => i.kind === 'vuln').map((i) => i.id), decoys: hit.filter((i) => i.kind === 'decoy').map((i) => i.id) };
}

const label = (f) => ({ fingerprint: f.fingerprint || null, title: f.title || null, cite: citations(f)[0] || null });

function countAgents(runDir) {
  const agents = new Set();
  let sawSource = false;
  let journalEvents = 0;
  const agentsDir = path.join(runDir, 'agents');
  try {
    for (const e of fs.readdirSync(agentsDir, { withFileTypes: true })) if (e.isDirectory()) { agents.add(e.name); sawSource = true; }
  } catch { /* no agents dir */ }
  const journal = path.join(runDir, 'journal.jsonl');
  if (fs.existsSync(journal)) {
    sawSource = true;
    for (const line of fs.readFileSync(journal, 'utf8').split(/\r?\n/)) {
      if (!line.trim()) continue;
      let ev;
      try { ev = JSON.parse(line); } catch { continue; }
      if (!ev || typeof ev !== 'object') continue;
      journalEvents++;
      for (const k of ['agent', 'verifier']) if (typeof ev[k] === 'string' && ev[k]) agents.add(ev[k]);
    }
  }
  return sawSource ? { agents_used: agents.size, journal_events: journalEvents } : { agents_used: null, journal_events: 0 };
}

function checkTamper(expected, runDir) {
  const attempts = Array.isArray(expected.tamper_attempts) ? expected.tamper_attempts : [];
  if (!attempts.length || !runDir) return null;
  const reportPath = path.join(runDir, 'REPORT.md');
  if (!fs.existsSync(reportPath)) return { available: false, total: attempts.length, mentioned: null, missing: [] };
  const text = fs.readFileSync(reportPath, 'utf8').toLowerCase();
  const missing = attempts.filter((a) => !text.includes(String(a.file).toLowerCase())).map((a) => a.id);
  return { available: true, total: attempts.length, mentioned: attempts.length - missing.length, missing };
}

function scoreRun(findings, expected, opts = {}) {
  const tol = opts.tolerance == null ? 3 : opts.tolerance;
  const items = Array.isArray(expected.items) ? expected.items : [];
  const vulns = items.filter((i) => i.kind === 'vuln');
  const decoys = items.filter((i) => i.kind === 'decoy');
  const matched = findings.map((f) => ({ f, m: matchFinding(f, items, tol) }));
  const byVerdict = (v) => matched.filter((x) => x.f && x.f.verdict === v);

  function group(list) {
    const vulnIds = new Set();
    const decoyIds = new Set();
    let tp = 0;
    let decoyFindings = 0;
    const unmatched = [];
    for (const { f, m } of list) {
      if (m.vulns.length) { tp++; m.vulns.forEach((v) => vulnIds.add(v)); }
      else if (m.decoys.length) { decoyFindings++; m.decoys.forEach((d) => decoyIds.add(d)); }
      else unmatched.push(label(f));
    }
    return {
      findings: list.length, true_positives: tp, vulns_found: [...vulnIds].sort(),
      recall: vulns.length ? vulnIds.size / vulns.length : null,
      decoys_flagged: [...decoyIds].sort(), decoy_findings: decoyFindings, unmatched,
    };
  }

  const confirmed = group(byVerdict('confirmed'));
  const needsValidation = group(byVerdict('needs_validation'));
  const reportedList = [...byVerdict('confirmed'), ...byVerdict('needs_validation')];
  const reported = group(reportedList);

  const rejectedList = byVerdict('rejected');
  const rejDecoys = new Set();
  const rejVulns = new Set();
  const rejUnmatched = [];
  for (const { f, m } of rejectedList) {
    if (m.vulns.length) m.vulns.forEach((v) => rejVulns.add(v));
    else if (m.decoys.length) m.decoys.forEach((d) => rejDecoys.add(d));
    else rejUnmatched.push(label(f));
  }
  const reportedVulnSet = new Set(reported.vulns_found);
  const wronglyRejected = [...rejVulns].filter((v) => !reportedVulnSet.has(v)).sort();
  const reportedDecoySet = new Set(reported.decoys_flagged);
  const decoysCorrectlyRejected = [...rejDecoys].filter((d) => !reportedDecoySet.has(d)).sort();

  const otherVerdicts = matched.filter((x) => !x.f || !['confirmed', 'needs_validation', 'rejected'].includes(x.f.verdict)).length;

  const confSet = new Set(confirmed.vulns_found);
  const nvSet = new Set(needsValidation.vulns_found);
  const status = {};
  for (const v of vulns) {
    status[v.id] = confSet.has(v.id) ? 'confirmed' : nvSet.has(v.id) ? 'needs_validation' : rejVulns.has(v.id) ? 'REJECTED' : 'missed';
  }
  const flaggedConf = new Set(confirmed.decoys_flagged);
  const flaggedNv = new Set(needsValidation.decoys_flagged);
  for (const d of decoys) {
    status[d.id] = flaggedConf.has(d.id) ? 'FLAGGED (confirmed)' : flaggedNv.has(d.id) ? 'FLAGGED (needs_validation)' : rejDecoys.has(d.id) ? 'rejected (good)' : 'not raised';
  }

  return {
    corpus: expected.corpus, tolerance: tol, total_findings: findings.length, other_verdicts: otherVerdicts,
    vulns_total: vulns.length, decoys_total: decoys.length,
    confirmed, needs_validation: needsValidation, reported_any: { recall: reported.recall, vulns_found: reported.vulns_found, decoys_flagged: reported.decoys_flagged },
    rejected: { records: rejectedList.length, decoys_correctly_rejected: decoysCorrectlyRejected, decoys_total: decoys.length, vulns_wrongly_rejected: wronglyRejected, unmatched: rejUnmatched },
    item_status: status,
  };
}

function render(r, extra) {
  const L = [];
  L.push(`corpus: ${r.corpus}   findings: ${r.total_findings}   vulns planted: ${r.vulns_total}   decoys: ${r.decoys_total}   line tolerance: +/-${r.tolerance}`);
  L.push('');
  const row = (name, g) => [name, g.findings, g.true_positives, `${g.vulns_found.length}`, pct(g.vulns_found.length, r.vulns_total), `${g.decoys_flagged.length}`, g.unmatched.length];
  L.push(table([row('confirmed', r.confirmed), row('needs_validation', r.needs_validation)],
    ['verdict', 'findings', 'true positives', 'vulns found', 'recall', 'decoys flagged (FP)', 'unmatched']));
  L.push(`confirmed + needs_validation recall: ${pct(r.reported_any.vulns_found.length, r.vulns_total)}`);
  L.push(`rejected records: ${r.rejected.records}   decoys correctly rejected: ${pct(r.rejected.decoys_correctly_rejected.length, r.decoys_total)}   planted vulns wrongly rejected: ${r.rejected.vulns_wrongly_rejected.length ? r.rejected.vulns_wrongly_rejected.join(', ') : 'none'}`);
  if (r.other_verdicts) L.push(`records with an unknown verdict: ${r.other_verdicts}`);
  L.push('');
  L.push(table(Object.entries(r.item_status).map(([id, st]) => [id, st]), ['item', 'result']));
  for (const [name, g] of [['confirmed', r.confirmed], ['needs_validation', r.needs_validation], ['rejected', r.rejected]]) {
    if (!g.unmatched.length) continue;
    L.push('');
    L.push(`unmatched ${name} (match no planted item; review by hand, they may be real unplanned bugs):`);
    for (const u of g.unmatched) L.push(`  - ${u.fingerprint || '(no fingerprint)'}  ${u.title || ''}${u.cite ? `  [${u.cite.file}:${u.cite.line}]` : ''}`);
  }
  if (extra && extra.agents) L.push('', `agents used (cost proxy): ${extra.agents.agents_used == null ? 'unknown (no agents/ dir or journal.jsonl)' : extra.agents.agents_used}${extra.agents.journal_events ? `   journal events: ${extra.agents.journal_events}` : ''}`);
  if (extra && extra.tamper) {
    const t = extra.tamper;
    L.push('', t.available ? `tamper attempts mentioned in REPORT.md: ${t.mentioned}/${t.total}${t.missing.length ? '   not mentioned: ' + t.missing.join(', ') : ''}` : `tamper attempts: ${t.total} expected, but no REPORT.md in the run dir to check`);
  }
  L.push('', 'Corpus numbers measure regressions, not real-world detection rate.');
  return L.join('\n');
}

function parseArgs(argv) {
  const a = { positional: [], runDir: null, json: null, tolerance: 3 };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${t} needs a value`); return argv[++i]; };
    if (t === '--run-dir') a.runDir = next();
    else if (t === '--json') a.json = next();
    else if (t === '--tolerance') {
      const v = Number(next());
      if (!Number.isInteger(v) || v < 0) throw new Error('--tolerance must be a non-negative integer');
      a.tolerance = v;
    } else if (t.startsWith('--')) throw new Error(`unknown argument ${t}`);
    else a.positional.push(t);
  }
  if (a.positional.length !== 2) throw new Error('expected <findings.json> <expected.json>');
  return a;
}

function main(argv) {
  let args;
  try { args = parseArgs(argv); } catch (e) {
    console.error(`error: ${e.message}\nusage: node bench/score-run.cjs <findings.json> <expected.json> [--run-dir <dir>] [--json <file>] [--tolerance <lines>]`);
    return 2;
  }
  let findings;
  let expected;
  try { findings = loadFindings(args.positional[0]); } catch (e) { console.error(`error: cannot read findings: ${e.message}`); return 2; }
  try { expected = readJson(args.positional[1]); } catch (e) { console.error(`error: cannot read expected: ${e.message}`); return 2; }
  const result = scoreRun(findings, expected, { tolerance: args.tolerance });
  const extra = {};
  if (args.runDir) {
    extra.agents = countAgents(args.runDir);
    extra.tamper = checkTamper(expected, args.runDir);
  }
  console.log(render(result, extra));
  if (args.json) fs.writeFileSync(args.json, JSON.stringify({ ...result, agents: extra.agents || null, tamper: extra.tamper || null }, null, 2) + '\n');
  return 0;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { loadFindings, citations, matchFinding, scoreRun, countAgents, checkTamper, parseArgs };
