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
//   Coverage = reviewed units / in-scope units. Reviewed = covered, candidate or carried (carried = unchanged
//   since a complete prior run, run-state.cjs carry; the overall line says how many were carried vs freshly
//   reviewed, and how many covered units each hunter tier (strong / lite) reviewed when lite hunters were used). Planned, in_progress,
//   deferred and blocked units are NOT reviewed (out_of_scope and not_applicable are not counted at all).
//   Area: coverage < 50 % → "not assessed" (no score, no grade); 50–79 % → score shown, marked provisional.
//   Overall = unit-weighted mean of assessed areas, then capped by the findings caps above and by overall
//   coverage (reviewed / all in-scope units across every area):
//     coverage < 50 % → "not assessed" (no number); < 70 % → at most 79; < 90 % → at most 89 (never an A).
//   The overall line always states coverage and the deferred/planned/blocked counts, and says
//   "partial pass" when any in-scope unit is not reviewed, status is not complete, profile is quick,
//   or scope is not full.
//   A merged directory (run-state.cjs merge-runs; run.json.merged_from) is scored on its union ledger: a unit
//   counts as reviewed if any merged run reviewed it, and the overall line says so.
//   Fix plan lists confirmed findings with their proof kind (execution.proof: static|local, "—" if absent).
//   "Verify next" lists needs_validation records; when max_impact_if_true is present it is shown as
//   "If true, up to" (a triage hint, not a severity) and used to sort, highest first.
// A score describes what this run reviewed and proved. It is not a guarantee of absence.

const fs = require('fs');
const path = require('path');
const { Reporter, loadJson, LEDGER_LIMITS, isObj, isArr, areaOf } = require('./lib.cjs');
const { validateFindings } = require('./check-findings.cjs');

const SEV = ['informational', 'low', 'medium', 'high', 'critical'];
const PENALTY = { critical: 50, high: 30, medium: 12, low: 4, informational: 0 };
const REVIEWED = new Set(['covered', 'candidate', 'carried']);
const grade = (s) => (s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 65 ? 'C' : s >= 50 ? 'D' : 'F');
const cell = (s) => String(s ?? '—').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim() || '—';
const firstSentence = (s) => (String(s).match(/^.*?[.!?](?:\s|$)/) || [String(s)])[0].trim();
const pct = (num, den) => (den ? Math.floor((100 * num) / den) : 0);
const sevRank = (s) => SEV.indexOf(s); // -1 when absent or unknown

function capFor(findings) {
  if (findings.some((f) => f.verdict === 'confirmed' && f.severity.overall === 'critical')) return 29;
  if (findings.some((f) => f.verdict === 'confirmed' && f.severity.overall === 'high')) return 59;
  return 100;
}

// Cap on the overall score from overall coverage (fraction compared exactly, never rounded up).
function coverageCap(reviewed, total) {
  if (!total || reviewed * 2 < total) return null; // not assessed
  if (reviewed * 10 < total * 7) return 79;
  if (reviewed * 10 < total * 9) return 89;
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
  const totals = { units: 0, reviewed: 0, deferred: 0, planned: 0, blocked: 0, in_progress: 0, carried: 0, lite: 0, strong: 0 };
  const sortedUnits = [...ledger].filter(isObj).sort((a, b) => String(a.id).localeCompare(String(b.id)));
  for (const u of sortedUnits) {
    const a = area(areaOf(u.refs && u.refs.class));
    if (u.status === 'out_of_scope' || u.status === 'not_applicable') continue;
    a.units++;
    totals.units++;
    if (REVIEWED.has(u.status)) {
      a.reviewed++; totals.reviewed++;
      if (u.status === 'carried') totals.carried++;
      else if (u.status === 'covered') { if (isObj(u.notes) && u.notes.covered_tier === 'lite') totals.lite++; else totals.strong++; }
    }
    else if (u.status in totals) totals[u.status]++;
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
    const coverage = pct(a.reviewed, a.units);
    const assessed = a.units > 0 && a.reviewed * 2 >= a.units; // coverage >= 50 %
    let value = null;
    if (assessed) {
      const penalty = conf.reduce((p, f) => p + PENALTY[f.severity.overall], 0) + Math.min(15, 3 * nv.length) + Math.min(10, 2 * a.blocked.length);
      value = Math.min(Math.max(0, 100 - penalty), capFor(a.findings));
    }
    const worst = [...conf].sort((x, y) => SEV.indexOf(y.severity.overall) - SEV.indexOf(x.severity.overall) || x.fingerprint.localeCompare(y.fingerprint))[0];
    const weakest = worst ? `${worst.title} (${worst.severity.overall})`
      : nv[0] ? `Unverified: ${nv[0].title}`
        : a.blocked[0] ? `Blocked: ${(a.blocked[0].open || [])[0]}` : '—';
    rows.push({ area: a.name, score: value, grade: value === null ? '—' : grade(value), coverage, units: a.units,
      provisional: value !== null && a.reviewed * 10 < a.units * 8, counts, needs_validation: nv.length, weakest });
  }

  const assessed = rows.filter((r) => r.score !== null);
  const covCap = coverageCap(totals.reviewed, totals.units);
  const coverage = pct(totals.reviewed, totals.units);
  let overall = null;
  let capNote = null;
  if (assessed.length && covCap !== null) {
    const w = assessed.reduce((s, r) => s + Math.max(1, r.units), 0);
    const mean = Math.round(assessed.reduce((s, r) => s + r.score * Math.max(1, r.units), 0) / w);
    const fCap = capFor(live);
    overall = Math.min(mean, fCap, covCap);
    if (overall < mean) {
      capNote = overall === fCap && fCap < covCap ? `capped at ${fCap} by confirmed findings` : `capped at ${overall} by coverage ${coverage}%`;
    }
  }

  const notReviewed = totals.units - totals.reviewed;
  const partialReasons = [];
  if (notReviewed > 0) partialReasons.push(`${notReviewed} in-scope unit(s) not reviewed`);
  if (run.status !== 'complete') partialReasons.push(`status ${run.status}`);
  if (run.profile === 'quick') partialReasons.push('quick profile');
  if (run.scope && run.scope.kind !== 'full') partialReasons.push(`${run.scope.kind} scope`);
  const partial = partialReasons.length > 0;

  const fixes = live.filter((f) => f.verdict === 'confirmed').sort((x, y) =>
    SEV.indexOf(y.severity.overall) - SEV.indexOf(x.severity.overall)
    || ['low', 'medium', 'high'].indexOf(y.confidence.level) - ['low', 'medium', 'high'].indexOf(x.confidence.level)
    || x.fingerprint.localeCompare(y.fingerprint));
  const verifyNext = live.filter((f) => f.verdict === 'needs_validation').sort((x, y) =>
    sevRank(y.max_impact_if_true) - sevRank(x.max_impact_if_true) || x.fingerprint.localeCompare(y.fingerprint));
  const det = isObj(detector) && isArr(detector.hits) ? { total: detector.hits.length, high: detector.hits.filter((h) => h.confidence === 'high').length } : null;
  return {
    overall, overallGrade: overall === null ? '—' : grade(overall), capNote, partial, partialReasons,
    coverage: { percent: coverage, reviewed: totals.reviewed, units: totals.units, deferred: totals.deferred, planned: totals.planned, blocked: totals.blocked, in_progress: totals.in_progress,
      carried: totals.carried, fresh: totals.reviewed - totals.carried, covered_strong: totals.strong, covered_lite: totals.lite },
    rows, fixes, verifyNext, detector: det,
  };
}

function toMarkdown(s, run) {
  const c = s.coverage;
  const facts = `coverage ${c.percent}% (${c.reviewed} of ${c.units} in-scope units reviewed; ${c.deferred} deferred, ${c.planned} planned, ${c.blocked} blocked${c.in_progress ? `, ${c.in_progress} in progress` : ''})${c.carried ? `; ${c.carried} carried unchanged from a prior run, ${c.fresh} freshly reviewed` : ''}${c.covered_lite ? `; covered by tier: ${c.covered_strong} strong, ${c.covered_lite} lite` : ''}`;
  const partial = s.partial ? ` · partial pass (${s.partialReasons.join('; ')})` : '';
  const merged = isArr(run.merged_from) && run.merged_from.length ? ` · merged from ${run.merged_from.length} runs (${run.merged_from.join(', ')}): a unit counts as reviewed if any run reviewed it` : '';
  const out = [];
  out.push('## Scorecard', '');
  if (s.overall === null) out.push(`**Overall: not assessed** · ${facts}${merged}${partial}. Fewer than half of the in-scope units were reviewed, so no overall score is given.`, '');
  else out.push(`**Overall: ${s.overall}/100 (${s.overallGrade})**${s.capNote ? ` (${s.capNote})` : ''} · ${facts}${merged}${partial}`, '');
  out.push('Scores come from `scripts/score.cjs` using verified records and ledger coverage only. They measure what this run reviewed and proved, not the absence of bugs.', '');
  out.push('| Area | Score | Grade | Coverage | Confirmed C/H/M/L | Unverified | Weakest point |', '|---|---|---|---|---|---|---|');
  for (const r of s.rows) {
    const sc = r.score === null ? `not assessed (coverage ${r.coverage}%)` : `${r.score}${r.provisional ? ' (provisional)' : ''}`;
    out.push(`| ${cell(r.area)} | ${sc} | ${r.grade} | ${r.coverage}% of ${r.units} | ${r.counts.critical}/${r.counts.high}/${r.counts.medium}/${r.counts.low} | ${r.needs_validation} | ${cell(r.weakest)} |`);
  }
  out.push('', '## Fix plan', '');
  if (!s.fixes.length) out.push('No confirmed findings.');
  else {
    out.push('| # | Severity | Proof | What is weak | Where | How to fix | Regression test |', '|---|---|---|---|---|---|---|');
    s.fixes.forEach((f, i) => {
      const sink = f.trace[f.trace.length - 1];
      const files = (f.remediation.code_changes || []).map((c) => c.file);
      const where = `\`${sink.file}:${sink.line}\` (${sink.scope})${files.length ? `; change ${files.map((x) => `\`${x}\``).join(', ')}` : ''}`;
      const proof = f.execution && f.execution.proof;
      out.push(`| ${i + 1} | ${f.severity.overall} | ${cell(proof)} | ${cell(f.title)} | ${cell(where)} | ${cell(firstSentence(f.remediation.strategy))} | ${cell(f.remediation.regression_test)} |`);
    });
  }
  if (s.verifyNext.length) {
    const hint = s.verifyNext.some((f) => f.max_impact_if_true);
    out.push('', '## Verify next (unconfirmed, no severity)', '');
    out.push(`| Lead | Where |${hint ? ' If true, up to |' : ''} Blocked on | How to settle |`, `|---|---|${hint ? '---|' : ''}---|---|`);
    for (const f of s.verifyNext) {
      const e = f.trace[0];
      out.push(`| ${cell(f.title)} | \`${cell(`${e.file}:${e.line}`)}\` |${hint ? ` ${cell(f.max_impact_if_true)} |` : ''} ${cell(f.blockers[0])} | ${cell(f.validation_plan.local || f.validation_plan.deployment)} |`);
    }
    if (hint) out.push('', '"If true, up to" is a triage hint about the largest impact if the lead holds. It is not a severity and does not count toward any score.');
  }
  if (s.detector) out.push('', `Detector: ${s.detector.total} lead(s), ${s.detector.high} high-confidence, in \`detector.json\`. Leads are not findings; reviewed ones appear above.`);
  return out.join('\n') + '\n';
}

function main(argv) {
  const dir = argv[2];
  if (!dir) { console.error('usage: node score.cjs <run-dir> [--json]'); return 2; }
  const rep = new Reporter();
  const run = loadJson(path.join(dir, 'run.json'), rep);
  const ledger = loadJson(path.join(dir, 'ledger.json'), rep, LEDGER_LIMITS);
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
