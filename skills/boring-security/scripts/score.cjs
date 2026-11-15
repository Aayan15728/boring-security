#!/usr/bin/env node
'use strict';
// Deterministic scorecard + fix plan from a run directory. Paste the markdown into REPORT.md unchanged.
// Usage: node score.cjs <run-dir> [--json]
// Inputs: run.json, ledger.json, findings.json (validated first), optional detector.json.
//
// Scoring (per area = the ledger class a unit/finding belongs to):
//   penalty = confirmed: critical 50, high 30, medium 12, low 4, informational 0
//           + needs_validation 3 each (max 15) + blocked units 2 each (max 10)
//   score = 100 - penalty, then capped: any confirmed critical → ≤ 29, any confirmed high → ≤ 59
//   grade: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50
//   An area with no reviewed unit is "not assessed" (never 100 by default).
//   Coverage < 50 % marks the area "provisional".
//   Overall = unit-weighted mean of assessed areas, with the same caps over all findings.
// A score describes what this run reviewed and proved. It is not a guarantee of absence.

const fs = require('fs');
const path = require('path');
const { Reporter, loadJson, isObj, isArr, areaOf } = require('./lib.cjs');
const { validateFindings } = require('./check-findings.cjs');

const SEV = ['informational', 'low', 'medium', 'high', 'critical'];
const PENALTY = { critical: 50, high: 30, medium: 12, low: 4, informational: 0 };
const grade = (s) => (s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 65 ? 'C' : s >= 50 ? 'D' : 'F');
const cell = (s) => String(s ?? '—').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim() || '—';
const firstSentence = (s) => (String(s).match(/^.*?[.!?](?:\s|$)/) || [String(s)])[0].trim();

function capFor(findings) {
  if (findings.some((f) => f.verdict === 'confirmed' && f.severity.overall === 'critical')) return 29;
  if (findings.some((f) => f.verdict === 'confirmed' && f.severity.overall === 'high')) return 59;
  return 100;
}

function score(run, ledger, findings, detector) {
  // area membership for units and findings
  const fpArea = new Map();
  const areas = new Map();
  const area = (name) => {
    if (!areas.has(name)) areas.set(name, { name, units: 0, reviewed: 0, blocked: [], findings: [] });
    return areas.get(name);
  };
  const sortedUnits = [...ledger].filter(isObj).sort((a, b) => String(a.id).localeCompare(String(b.id)));
  for (const u of sortedUnits) {
    const a = area(areaOf(u.refs && u.refs.class));
    if (u.status === 'out_of_scope' || u.status === 'not_applicable') continue;
    a.units++;
    if (['covered', 'candidate', 'blocked'].includes(u.status)) a.reviewed++;
    if (u.status === 'blocked') a.blocked.push(u);
    const fps = [...(u.fingerprints || []), ...(u.history || []).flatMap((h) => h.fingerprints || [])];
    for (const fp of fps) if (!fpArea.has(fp)) fpArea.set(fp, a.name);
  }
  const live = findings.filter((f) => f.verdict !== 'rejected');
  for (const f of live) area(fpArea.get(f.fingerprint) || 'Basics & other').findings.push(f);

  const rows = [];
  for (const a of [...areas.values()].sort((x, y) => x.name.localeCompare(y.name))) {
    if (!a.units && !a.findings.length) continue;
    const conf = a.findings.filter((f) => f.verdict === 'confirmed');
    const nv = a.findings.filter((f) => f.verdict === 'needs_validation');
    const counts = Object.fromEntries(SEV.map((s) => [s, conf.filter((f) => f.severity.overall === s).length]));
    const coverage = a.units ? Math.round((100 * a.reviewed) / a.units) : 0;
    let value = null;
    if (a.reviewed > 0 || conf.length) {
      const penalty = conf.reduce((p, f) => p + PENALTY[f.severity.overall], 0) + Math.min(15, 3 * nv.length) + Math.min(10, 2 * a.blocked.length);
      value = Math.min(Math.max(0, 100 - penalty), capFor(a.findings));
    }
    const worst = [...conf].sort((x, y) => SEV.indexOf(y.severity.overall) - SEV.indexOf(x.severity.overall) || x.fingerprint.localeCompare(y.fingerprint))[0];
    const weakest = worst ? `${worst.title} (${worst.severity.overall})`
      : nv[0] ? `Unverified: ${nv[0].title}`
        : a.blocked[0] ? `Blocked: ${(a.blocked[0].open || [])[0]}` : '—';
    rows.push({ area: a.name, score: value, grade: value === null ? '—' : grade(value), coverage, units: a.units,
      provisional: value !== null && coverage < 50, counts, needs_validation: nv.length, weakest });
  }

  const assessed = rows.filter((r) => r.score !== null);
  let overall = null;
  if (assessed.length) {
    const w = assessed.reduce((s, r) => s + Math.max(1, r.units), 0);
    overall = Math.min(Math.round(assessed.reduce((s, r) => s + r.score * Math.max(1, r.units), 0) / w), capFor(live));
  }
  const partial = run.profile === 'quick' || (run.scope && run.scope.kind !== 'full') || run.status !== 'complete';

  const fixes = live.filter((f) => f.verdict === 'confirmed').sort((x, y) =>
    SEV.indexOf(y.severity.overall) - SEV.indexOf(x.severity.overall)
    || ['low', 'medium', 'high'].indexOf(y.confidence.level) - ['low', 'medium', 'high'].indexOf(x.confidence.level)
    || x.fingerprint.localeCompare(y.fingerprint));
  const verifyNext = live.filter((f) => f.verdict === 'needs_validation').sort((x, y) => x.fingerprint.localeCompare(y.fingerprint));
  const det = isObj(detector) && isArr(detector.hits) ? { total: detector.hits.length, high: detector.hits.filter((h) => h.confidence === 'high').length } : null;
  return { overall, overallGrade: overall === null ? '—' : grade(overall), partial, rows, fixes, verifyNext, detector: det };
}

function toMarkdown(s, run) {
  const out = [];
  out.push('## Scorecard', '');
  if (s.overall === null) out.push('**Overall: not assessed.** No coverage unit was reviewed in this run.', '');
  else out.push(`**Overall: ${s.overall}/100 (${s.overallGrade})**${s.partial ? ` · partial pass (${run.profile}, ${run.scope ? run.scope.kind : 'full'} scope, status ${run.status})` : ''}`, '');
  out.push('Scores come from `scripts/score.cjs` using verified records and ledger coverage only. They measure what this run reviewed and proved, not the absence of bugs.', '');
  out.push('| Area | Score | Grade | Coverage | Confirmed C/H/M/L | Unverified | Weakest point |', '|---|---|---|---|---|---|---|');
  for (const r of s.rows) {
    const sc = r.score === null ? 'not assessed' : `${r.score}${r.provisional ? ' (provisional)' : ''}`;
    out.push(`| ${cell(r.area)} | ${sc} | ${r.grade} | ${r.coverage}% of ${r.units} | ${r.counts.critical}/${r.counts.high}/${r.counts.medium}/${r.counts.low} | ${r.needs_validation} | ${cell(r.weakest)} |`);
  }
  out.push('', '## Fix plan', '');
  if (!s.fixes.length) out.push('No confirmed findings.');
  else {
    out.push('| # | Severity | What is weak | Where | How to fix | Regression test |', '|---|---|---|---|---|---|');
    s.fixes.forEach((f, i) => {
      const sink = f.trace[f.trace.length - 1];
      const files = (f.remediation.code_changes || []).map((c) => c.file);
      const where = `\`${sink.file}:${sink.line}\` (${sink.scope})${files.length ? `; change ${files.map((x) => `\`${x}\``).join(', ')}` : ''}`;
      out.push(`| ${i + 1} | ${f.severity.overall} | ${cell(f.title)} | ${cell(where)} | ${cell(firstSentence(f.remediation.strategy))} | ${cell(f.remediation.regression_test)} |`);
    });
  }
  if (s.verifyNext.length) {
    out.push('', '## Verify next (unconfirmed, no severity)', '', '| Lead | Where | Blocked on | How to settle |', '|---|---|---|---|');
    for (const f of s.verifyNext) {
      const e = f.trace[0];
      out.push(`| ${cell(f.title)} | \`${cell(`${e.file}:${e.line}`)}\` | ${cell(f.blockers[0])} | ${cell(f.validation_plan.local || f.validation_plan.deployment)} |`);
    }
  }
  if (s.detector) out.push('', `Detector: ${s.detector.total} lead(s), ${s.detector.high} high-confidence, in \`detector.json\`. Leads are not findings; reviewed ones appear above.`);
  return out.join('\n') + '\n';
}

function main(argv) {
  const dir = argv[2];
  if (!dir) { console.error('usage: node score.cjs <run-dir> [--json]'); return 2; }
  const rep = new Reporter();
  const run = loadJson(path.join(dir, 'run.json'), rep);
  const ledger = loadJson(path.join(dir, 'ledger.json'), rep);
  const findings = loadJson(path.join(dir, 'findings.json'), rep);
  if (findings !== undefined) validateFindings(findings, rep);
  const detPath = path.join(dir, 'detector.json');
  const detector = fs.existsSync(detPath) ? loadJson(detPath, rep) : undefined;
  if (rep.errors.length || !isObj(run) || !isArr(ledger)) { rep.finish('score'); console.error('refusing to score invalid inputs'); return 1; }
  const s = score(run, ledger, findings, detector);
  process.stdout.write(argv.includes('--json') ? JSON.stringify(s, null, 2) + '\n' : toMarkdown(s, run));
  return 0;
}

if (require.main === module) process.exitCode = main(process.argv);
module.exports = { score, toMarkdown, grade };
