'use strict';
// Merge two or more complete runs of the same repo at the same source ref (run-state.cjs merge-runs).
// Zero dependencies, Node >= 18.
//
//   merge-runs <out dir> <run dir> <run dir>... [--allow-ref-drift]
//
// Independent repeated runs find different bugs, so their union is worth more than any one run. This never
// invents or rewrites a record:
//   - findings.json  union by fingerprint. A fingerprint every deciding run calls non-rejected keeps the record
//                    with the strongest verdict (confirmed > needs_validation), ties broken by run order. All
//                    rejected -> the rejected record. Rejected in one run and not in another -> NOT merged: it
//                    goes to disagreements.json with every run's record, until a fresh Skeptic's decision is
//                    stored in OUT/resolutions/<fingerprint>.json ({"by", "decision", "record"}; the Skeptic must
//                    not have found, decided, verified or worked that fingerprint in any run) and merge-runs is
//                    run again. The merged set is re-validated (schema, cross-record rules, quotes vs target).
//   - ledger.json    union coverage for score.cjs: per unit id the most-reviewed state any run reached.
//   - run.json       merged_from lists the runs; status complete only when no disagreement is unresolved.
//   - merge.json     per run: profile, units, reviewed, verdict counts, findings unique to it; the overlap
//                    matrix; a rough capture-recapture estimate of the total (omitted when overlap is zero or
//                    counts are too small); resolved and unresolved disagreements.
//   - disagreements.json, possible-duplicates.json (different fingerprints, same sink file, sink lines
//                    within 3, same class: listed for the lead, never merged).
// Same source ref = identical run.json.source_ref. --allow-ref-drift accepts different refs only when every
// file hash in any run's hashes.json equals the same file in every other run that hashed it and in the target.

const fs = require('fs');
const path = require('path');
const { Reporter, loadJson, LEDGER_LIMITS, isObj, isArr, isAgentId, canonicalJson, sha256 } = require('./lib.cjs');
const { validateFindings, verifyQuotes } = require('./check-findings.cjs');

const RANK = { confirmed: 3, needs_validation: 2, rejected: 1 };
const STATE_RANK = { carried: 9, covered: 9, candidate: 8, blocked: 7, in_progress: 3, planned: 2, deferred: 1, out_of_scope: 1, not_applicable: 0 };
const fpFile = (fp) => encodeURIComponent(fp).replace(/\*/g, '%2A') + '.json';
const byCode = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const asList = (v) => (typeof v === 'string' ? [v] : isArr(v) ? v.filter((x) => typeof x === 'string') : []);

class MergeError extends Error {}
const fail = (msg) => { throw new MergeError(msg); };
function read(file, required, limits) {
  if (!fs.existsSync(file)) { if (required) fail(`missing ${file}`); return undefined; }
  const rep = new Reporter();
  const v = loadJson(file, rep, limits);
  if (rep.errors.length) fail(rep.errors.join('; '));
  return v;
}
function writeAtomic(file, text) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, text);
  fs.renameSync(tmp, file);
}
const writeJson = (file, v) => writeAtomic(file, JSON.stringify(v, null, 2) + '\n');

function loadRun(dir) {
  const run = read(path.join(dir, 'run.json'), true);
  if (!isObj(run)) fail(`${dir}: run.json must be an object`);
  if (run.status !== 'complete') fail(`${dir}: status is ${run.status}; only complete runs can be merged`);
  const ledger = read(path.join(dir, 'ledger.json'), true, LEDGER_LIMITS);
  const findings = read(path.join(dir, 'findings.json'), true);
  const rep = new Reporter();
  validateFindings(findings, rep);
  if (rep.errors.length) fail(`${dir}: findings.json invalid: ${rep.errors.slice(0, 3).join('; ')}`);
  const hashes = read(path.join(dir, 'hashes.json'), false, LEDGER_LIMITS);
  // independence data for resolutions
  const people = new Map(); // fp -> Set(agent ids)
  const add = (fp, id) => { if (typeof id !== 'string') return; if (!people.has(fp)) people.set(fp, new Set()); people.get(fp).add(id); };
  const cdir = path.join(dir, 'candidates');
  for (const f of fs.existsSync(cdir) ? fs.readdirSync(cdir).filter((x) => x.endsWith('.json')) : []) {
    const c = read(path.join(cdir, f), false);
    if (isObj(c)) for (const id of [...asList(c.found_by), ...asList(c.carried_by)]) add(c.fingerprint, id);
  }
  for (const [sub, key] of [['decisions', 'by'], ['verifications', null]]) {
    const d = path.join(dir, sub);
    for (const f of fs.existsSync(d) ? fs.readdirSync(d).filter((x) => x.endsWith('.json')) : []) {
      const x = read(path.join(d, f), false);
      const fp = decodeURIComponent(f.slice(0, -5));
      if (!isObj(x)) continue;
      if (key) { add(fp, x.by); for (const h of isArr(x.history) ? x.history : []) if (isObj(h)) add(fp, h.by); }
      else for (const v of isArr(x.verifications) ? x.verifications : []) if (isObj(v)) add(fp, v.by);
    }
  }
  for (const u of isArr(ledger) ? ledger : []) {
    if (!isObj(u)) continue;
    const states = [u, ...(isArr(u.history) ? u.history : [])].filter(isObj);
    const fps = new Set(states.flatMap((s) => (isArr(s.fingerprints) ? s.fingerprints : [])));
    for (const fp of fps) for (const s of states) { add(fp, s.owner); for (const c of isArr(s.checks) ? s.checks : []) if (isObj(c)) add(fp, c.by); }
  }
  return { dir, run, ledger: isArr(ledger) ? ledger : [], findings, hashes: isObj(hashes) ? hashes : null, people };
}

function checkDrift(runs, target) {
  const problems = [];
  for (const r of runs) if (!r.hashes || !isObj(r.hashes.files)) problems.push(`${r.run.run_id} has no hashes.json`);
  if (problems.length) return problems;
  const files = new Set(runs.flatMap((r) => Object.keys(r.hashes.files)));
  for (const f of [...files].sort(byCode)) {
    const vals = new Set(runs.filter((r) => Object.prototype.hasOwnProperty.call(r.hashes.files, f)).map((r) => r.hashes.files[f]));
    let now = null;
    try { now = sha256(fs.readFileSync(path.join(target, ...f.split('/')))); } catch { now = null; }
    vals.add(now);
    if (vals.size !== 1 || now === null) problems.push(`${f} differs between runs or from the target`);
    if (problems.length >= 20) break;
  }
  return problems;
}

const sinkOf = (rec) => (isArr(rec.trace) && rec.trace.length ? rec.trace[rec.trace.length - 1] : null);
const classOf = (rec) => (typeof rec.category === 'string' ? `category:${rec.category}` : `fp:${String(rec.fingerprint).split(':')[0]}`);

// Rough total-findings estimate from capture overlap. `sets` = non-rejected fingerprints per run.
function estimate(sets) {
  const k = sets.length;
  const union = new Set(sets.flatMap((s) => [...s]));
  const assumptions = [
    'runs are independent samples of the same fixed set of findings (same code, same skill)',
    'every finding is equally likely to be found by a run (in practice some are much harder, so the true total is likely higher)',
    'fingerprints identify findings consistently across runs (near-duplicates with different fingerprints inflate the estimate)',
  ];
  if (union.size < 3) return { omitted: 'fewer than 3 distinct non-rejected findings across runs' };
  if (k === 2) {
    const [a, b] = sets;
    const m = [...a].filter((x) => b.has(x)).length;
    if (m === 0) return { omitted: 'no finding was found by both runs (overlap is zero)' };
    if (a.size < 2 || b.size < 2) return { omitted: 'a run found fewer than 2 findings' };
    const chapman = ((a.size + 1) * (b.size + 1)) / (m + 1) - 1;
    return { method: 'Lincoln-Petersen (Chapman bias-corrected)', label: 'ROUGH ESTIMATE, not a count', observed: union.size, n1: a.size, n2: b.size, overlap: m,
      estimated_total: Math.round(chapman * 10) / 10, assumptions };
  }
  const freq = new Map();
  for (const s of sets) for (const x of s) freq.set(x, (freq.get(x) || 0) + 1);
  const f1 = [...freq.values()].filter((v) => v === 1).length;
  const f2 = [...freq.values()].filter((v) => v === 2).length;
  if (![...freq.values()].some((v) => v >= 2)) return { omitted: 'no finding was found by more than one run (overlap is zero)' };
  const c = (k - 1) / k;
  const extra = f2 > 0 ? c * (f1 * f1) / (2 * f2) : c * (f1 * (f1 - 1)) / 2;
  return { method: 'Chao2 incidence lower bound', label: 'ROUGH ESTIMATE (lower bound), not a count', observed: union.size, runs: k, found_by_one_run: f1, found_by_two_runs: f2,
    estimated_total_lower_bound: Math.round((union.size + extra) * 10) / 10, assumptions };
}

function mergeRuns(outDir, runDirs, opts = {}) {
  if (!outDir || runDirs.length < 2) fail('usage: merge-runs <out dir> <run dir> <run dir>... [--allow-ref-drift]');
  const out = path.resolve(outDir);
  const dirs = runDirs.map((d) => path.resolve(d));
  if (new Set(dirs).size !== dirs.length) fail('the same run directory is listed twice');
  if (dirs.includes(out)) fail('the output directory must not be one of the runs');
  if (fs.existsSync(out)) {
    const ents = fs.readdirSync(out);
    if (ents.length && !ents.includes('merge.json')) fail(`${out} exists and is not empty (and holds no earlier merge.json)`);
  }
  const runs = dirs.map(loadRun);
  const repo = runs[0].run.repo;
  for (const r of runs) if (r.run.repo !== repo) fail(`runs are for different repos (${JSON.stringify(repo)} vs ${JSON.stringify(r.run.repo)})`);
  const ids = runs.map((r) => String(r.run.run_id));
  if (new Set(ids).size !== ids.length) fail('two runs share a run_id');
  const target = runs[0].run.target;
  let st = null;
  try { st = fs.statSync(target); } catch { st = null; }
  if (!st || !st.isDirectory()) fail(`target ${target} is not an existing directory (needed to re-check quotes)`);
  const refs = new Set(runs.map((r) => canonicalJson(isObj(r.run.source_ref) ? r.run.source_ref : null)));
  let drift = false;
  if (refs.size > 1) {
    if (!opts.allowRefDrift) fail('runs are at different source refs; pass --allow-ref-drift only if every cited file is identical (checked with hashes.json)');
    const p = checkDrift(runs, target);
    if (p.length) fail(`--allow-ref-drift refused:\n  ${p.join('\n  ')}`);
    drift = true;
  }

  // ---- findings ----
  const byFp = new Map();
  runs.forEach((r, i) => { for (const rec of r.findings) { if (!byFp.has(rec.fingerprint)) byFp.set(rec.fingerprint, []); byFp.get(rec.fingerprint).push({ i, run_id: ids[i], rec }); } });
  const resDir = path.join(out, 'resolutions');
  const merged = []; const disagreements = []; const resolved = []; const resolutionProblems = [];
  for (const fp of [...byFp.keys()].sort(byCode)) {
    const all = byFp.get(fp);
    const verdicts = new Set(all.map((x) => x.rec.verdict));
    if (verdicts.has('rejected') && verdicts.size > 1) {
      const rf = path.join(resDir, fpFile(fp));
      const res = fs.existsSync(rf) ? read(rf, false) : undefined;
      let why = null;
      if (res !== undefined) {
        const rep = new Reporter();
        if (!isObj(res) || !isObj(res.record) || res.decision !== res.record.verdict || res.record.fingerprint !== fp) why = 'must be {"by", "decision", "record"} with record.verdict = decision and the same fingerprint';
        else if (!isAgentId(res.by)) why = 'by must be an agent id';
        else if (runs.some((r) => r.people.has(fp) && r.people.get(fp).has(res.by))) why = `${res.by} found, decided, verified or worked ${fp} in one of the runs`;
        else { validateFindings([res.record], rep); if (rep.errors.length) why = rep.errors[0]; }
        if (why) resolutionProblems.push(`resolutions/${fpFile(fp)}: ${why}`);
        else { merged.push(res.record); resolved.push({ fingerprint: fp, by: res.by, decision: res.decision }); continue; }
      }
      disagreements.push({ fingerprint: fp, needs: 'a fresh Skeptic decision in resolutions/<fingerprint>.json, then run merge-runs again', records: all.map((x) => ({ run_id: x.run_id, verdict: x.rec.verdict, record: x.rec })) });
      continue;
    }
    const best = [...all].sort((a, b) => RANK[b.rec.verdict] - RANK[a.rec.verdict] || a.i - b.i)[0];
    merged.push(best.rec);
  }
  merged.sort((a, b) => byCode(a.fingerprint, b.fingerprint));
  const rep = new Reporter();
  validateFindings(merged, rep);
  verifyQuotes(merged, target, rep);
  if (rep.errors.length) fail(`merged findings invalid, nothing written:\n  ${rep.errors.slice(0, 20).join('\n  ')}`);

  // ---- union ledger ----
  const units = new Map();
  for (const r of runs) for (const u of r.ledger) {
    if (!isObj(u) || typeof u.id !== 'string') continue;
    const cur = units.get(u.id);
    if (!cur || (STATE_RANK[u.status] || 0) > (STATE_RANK[cur.status] || 0)) units.set(u.id, u);
  }
  const ledger = [...units.values()].sort((a, b) => byCode(a.id, b.id));

  // ---- statistics ----
  const live = runs.map((r) => new Set(r.findings.filter((x) => x.verdict !== 'rejected').map((x) => x.fingerprint)));
  const matrix = live.map((a) => live.map((b) => [...a].filter((x) => b.has(x)).length));
  const perRun = runs.map((r, i) => {
    const count = (v) => r.findings.filter((x) => x.verdict === v).length;
    const others = new Set(live.filter((_, j) => j !== i).flatMap((s) => [...s]));
    return { run_id: ids[i], dir: r.dir, profile: r.run.profile, units: r.ledger.length,
      reviewed: r.ledger.filter((u) => isObj(u) && ['covered', 'candidate', 'carried'].includes(u.status)).length,
      confirmed: count('confirmed'), needs_validation: count('needs_validation'), rejected: count('rejected'),
      unique: [...live[i]].filter((x) => !others.has(x)).sort(byCode) };
  });
  const recs = [...byFp.entries()].flatMap(([fp, all]) => all.filter((x) => x.rec.verdict !== 'rejected').map((x) => ({ fp, run: x.run_id, rec: x.rec })));
  const dupes = [];
  const seenPair = new Set();
  for (let a = 0; a < recs.length; a++) for (let b = a + 1; b < recs.length; b++) {
    const x = recs[a]; const y = recs[b];
    if (x.fp === y.fp || x.run === y.run) continue;
    const sx = sinkOf(x.rec); const sy = sinkOf(y.rec);
    if (!sx || !sy || sx.file !== sy.file || Math.abs(sx.line - sy.line) > 3 || classOf(x.rec) !== classOf(y.rec)) continue;
    const key = [x.fp, y.fp].sort(byCode).join('\u0000');
    if (seenPair.has(key)) continue;
    seenPair.add(key);
    dupes.push({ a: { fingerprint: x.fp, run_id: x.run, sink: `${sx.file}:${sx.line}` }, b: { fingerprint: y.fp, run_id: y.run, sink: `${sy.file}:${sy.line}` }, class: classOf(x.rec) });
  }
  const profiles = ['quick', 'standard', 'deep'];
  const weakest = runs.map((r) => r.run.profile).sort((a, b) => profiles.indexOf(a) - profiles.indexOf(b))[0];
  const first = runs[0].run;
  const runJson = { run_id: `merged-${ids.join('+')}`, repo, target, source_ref: first.source_ref, profile: weakest, scope: first.scope, execution: first.execution,
    status: disagreements.length ? 'in_progress' : 'complete', incomplete_reason: null, merged_from: ids };
  const mergeJson = {
    runs: perRun, overlap: { run_ids: ids, matrix, note: 'number of non-rejected fingerprints each pair of runs shares (diagonal = found by that run)' },
    estimate: estimate(live), ref_drift_allowed: drift,
    disagreements: { unresolved: disagreements.map((d) => d.fingerprint), resolved, problems: resolutionProblems },
    possible_duplicates: dupes.length, findings: merged.length,
  };
  fs.mkdirSync(out, { recursive: true });
  writeJson(path.join(out, 'findings.json'), merged);
  writeJson(path.join(out, 'ledger.json'), ledger);
  writeJson(path.join(out, 'run.json'), runJson);
  writeJson(path.join(out, 'merge.json'), mergeJson);
  writeJson(path.join(out, 'disagreements.json'), disagreements);
  writeJson(path.join(out, 'possible-duplicates.json'), dupes);
  const est = mergeJson.estimate;
  return [
    `merged ${runs.length} runs → ${out}: ${merged.length} finding(s); ${disagreements.length} unresolved disagreement(s)${resolved.length ? `, ${resolved.length} resolved` : ''}; ${dupes.length} possible duplicate pair(s)`,
    ...perRun.map((p) => `  ${p.run_id}: ${p.confirmed} confirmed, ${p.needs_validation} needs_validation, ${p.rejected} rejected, ${p.unique.length} unique`),
    est.omitted ? `  estimate omitted: ${est.omitted}` : `  ${est.label}: ${est.estimated_total ?? est.estimated_total_lower_bound} total (observed ${est.observed}; ${est.method}; see merge.json for assumptions)`,
    ...resolutionProblems.map((p) => `  resolution refused: ${p}`),
  ].join('\n');
}

module.exports = { mergeRuns, estimate, MergeError };
