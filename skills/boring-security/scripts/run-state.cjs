#!/usr/bin/env node
'use strict';
// Crash-safe run state for long audits. The run directory on disk is the source of truth, so the lead
// never has to hold the ledger or agent results in its context, and any crash, rate limit or context
// reset resumes from files.
//
//   estimate <target> [--profile p] [--price-in N --price-out N] [--cache-hit 0.85]   rough agents, tokens, dollars
//   status   <run>                                       compact progress summary + the next action
//   next     <run> [--n 10]                              planned units to assign, in priority order
//   assign   <run> <agent-id> <unit-id>...               mark units in_progress for a fresh agent
//   ingest   <run> <agent-id> <result.json>              apply a Hunter result to the ledger
//   decide   <run> <verifier-id> <decision.json>         store a Skeptic / record-check decision
//   assemble <run>                                       build findings.json from stored decisions
//   recover  <run>                                       repair state after a crash or rate limit
//
// Every write is atomic (temp file + rename) and appended to journal.jsonl. A step that fails
// validation changes nothing.

const fs = require('fs');
const path = require('path');
const { Reporter, loadJson, isObj, isArr, isAgentId, isRelPath, FINGERPRINT } = require('./lib.cjs');
const { validateLedger } = require('./check-ledger.cjs');
const { validateFindings, crossCheckLedger, verifyQuotes } = require('./check-findings.cjs');

// ---------- files ----------
function sleepMs(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function writeAtomic(file, text) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, text);
  for (let i = 0; ; i++) {
    try { fs.renameSync(tmp, file); return; } catch (e) {
      // Windows: antivirus/indexers can briefly hold the target open.
      if (i >= 8 || !['EPERM', 'EACCES', 'EBUSY'].includes(e.code)) { try { fs.unlinkSync(tmp); } catch { /* ignore */ } throw e; }
      sleepMs(50 * (i + 1));
    }
  }
}
const writeJson = (file, v) => writeAtomic(file, JSON.stringify(v, null, 2) + '\n');
function journal(run, event) { fs.appendFileSync(path.join(run, 'journal.jsonl'), JSON.stringify({ t: new Date().toISOString(), ...event }) + '\n'); }
const fpFile = (fp) => encodeURIComponent(fp).replace(/\*/g, '%2A') + '.json';

function die(msg) { console.error(`run-state: ${msg}`); process.exit(1); }
function load(file, required = true) {
  if (!fs.existsSync(file)) { if (required) die(`missing ${file}`); return undefined; }
  const rep = new Reporter();
  const v = loadJson(file, rep);
  if (rep.errors.length) die(rep.errors.join('; '));
  return v;
}
function saveLedger(run, ledger) {
  const rep = new Reporter();
  validateLedger(ledger, rep, { runDir: run, checkFiles: true, checkBlocks: true, ...runOpts(run) });
  if (rep.errors.length) die(`ledger update rejected, nothing written:\n  ${rep.errors.slice(0, 20).join('\n  ')}`);
  writeJson(path.join(run, 'ledger.json'), ledger);
}
function runOpts(run) { const r = load(path.join(run, 'run.json'), false); return isObj(r) ? { profile: r.profile, status: r.status } : {}; }
function listJson(dir) { return fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort() : []; }

// ---------- estimate ----------
const EST = {
  unitsPerKloc: { quick: 1.5, standard: 4, deep: 7 },
  unitsPerHunter: 4, candidateRate: 0.06, verifiersPerCandidate: { quick: 1, standard: 2, deep: 2 },
  criticCalls: { quick: 1, standard: 6, deep: 10 },
  tokensPerAgent: { scout: 250e3, hunter: 400e3, verifier: 250e3, critic: 300e3 }, // processed input, incl. cached re-reads
  leadOverhead: 0.2, range: [0.5, 1.6], maxUnitsPerRun: 10000,
  outputPerAgent: 12e3,
  // Prompt-cache pricing relative to the base input price (typical: reads 0.1x, writes 1.25x).
  cacheReadFactor: 0.1, cacheWriteFactor: 1.25,
};
// Dollar cost for a token estimate. cacheHit = share of processed input served from cache.
function dollars(tokensIn, tokensOut, priceIn, priceOut, cacheHit) {
  const cached = tokensIn * (cacheHit * EST.cacheReadFactor + (1 - cacheHit) * EST.cacheWriteFactor) * priceIn / 1e6;
  const uncached = tokensIn * priceIn / 1e6;
  const out = tokensOut * priceOut / 1e6;
  return { cached: cached + out, uncached: uncached + out };
}
function estimate(target, profile) {
  const { listFiles, TEST_PATH } = require('./detect.cjs');
  const code = /\.(?:[cm]?[jt]sx?|vue|svelte|py|go|java|kt|kts|php|rb|cs|swift|m|mm|dart|rs|scala|c|cc|cpp|h|hpp|sql|prisma|tf|ya?ml|xml|plist|rules|sh)$/i;
  let loc = 0; let files = 0;
  for (const rel of listFiles(target, {})) {
    const posix = rel.split(path.sep).join('/');
    if (!code.test(posix) || TEST_PATH.test(posix)) continue;
    const full = path.join(target, rel);
    const st = fs.statSync(full);
    if (st.size > 1024 * 1024) continue;
    const text = fs.readFileSync(full, 'utf8');
    loc += text.split('\n').filter((l) => l.trim()).length; files++;
  }
  const kloc = loc / 1000;
  const units = Math.max(20, Math.round(kloc * EST.unitsPerKloc[profile]));
  const hunters = Math.ceil(units / EST.unitsPerHunter);
  const verifiers = Math.ceil(units * EST.candidateRate) * EST.verifiersPerCandidate[profile];
  const scouts = 4 + Math.ceil(kloc / 100);
  const critics = EST.criticCalls[profile] * (profile === 'quick' ? 1 : Math.max(1, Math.ceil(kloc / 200)));
  const t = EST.tokensPerAgent;
  const base = (scouts * t.scout + hunters * t.hunter + verifiers * t.verifier + critics * t.critic) * (1 + EST.leadOverhead);
  const runs = Math.ceil(units / EST.maxUnitsPerRun);
  const agents = scouts + hunters + verifiers + critics;
  return { profile, files, loc, units, scouts, hunters, verifiers, critics, agents,
    tokens_low: Math.round(base * EST.range[0]), tokens_high: Math.round(base * EST.range[1]),
    output_low: Math.round(agents * EST.outputPerAgent * EST.range[0]), output_high: Math.round(agents * EST.outputPerAgent * EST.range[1]),
    scoped_runs_needed: runs };
}
const human = (n) => (n >= 1e9 ? `${(n / 1e9).toFixed(1)}B` : n >= 1e6 ? `${(n / 1e6).toFixed(0)}M` : `${Math.round(n / 1e3)}k`);

// ---------- status / next ----------
function status(run) {
  const runJson = load(path.join(run, 'run.json'));
  const ledger = load(path.join(run, 'ledger.json'), false) || [];
  const counts = {};
  for (const u of ledger) counts[u.status] = (counts[u.status] || 0) + 1;
  const inProgress = ledger.filter((u) => u.status === 'in_progress');
  const agentsDir = path.join(run, 'agents');
  const pendingResults = fs.existsSync(agentsDir) ? fs.readdirSync(agentsDir).filter((a) =>
    fs.existsSync(path.join(agentsDir, a, 'result.json')) && !fs.existsSync(path.join(agentsDir, a, 'ingested.json'))) : [];
  const liveFps = [...new Set(ledger.flatMap((u) => u.fingerprints || []))];
  const decided = new Set(listJson(path.join(run, 'decisions')).map((f) => decodeURIComponent(f.slice(0, -5))));
  const undecided = liveFps.filter((fp) => !decided.has(fp));
  const hasFindings = fs.existsSync(path.join(run, 'findings.json'));
  let next;
  if (!ledger.length) next = 'Phase 1: seed ledger.json';
  else if (pendingResults.length) next = `ingest results from: ${pendingResults.join(', ')}`;
  else if (inProgress.length) next = `wait for or recover agents: ${[...new Set(inProgress.map((u) => u.owner))].join(', ')}`;
  else if (counts.planned) next = `assign ${counts.planned} planned unit(s) (run-state next)`;
  else if (undecided.length) next = `send ${undecided.length} candidate(s) to Skeptics`;
  else if (!hasFindings && decided.size) next = 'assemble findings.json';
  else next = 'critic / Phase 5 / Phase 6 per the phase files';
  const lines = [
    `run ${runJson.run_id} · ${runJson.profile} · ${runJson.status}${runJson.incomplete_reason ? ` (${runJson.incomplete_reason})` : ''}`,
    `units ${ledger.length}: ${Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ') || 'none'}`,
    `candidates ${liveFps.length}, decided ${decided.size}, awaiting skeptic ${undecided.length}`,
    `findings.json ${hasFindings ? 'present' : 'not yet'}`,
    `next: ${next}`,
  ];
  return lines.join('\n');
}
function next(run, n) {
  const ledger = load(path.join(run, 'ledger.json'));
  const rank = (u) => (isObj(u.notes) && Number.isFinite(u.notes.priority) ? u.notes.priority : 99);
  return ledger.filter((u) => u.status === 'planned').sort((a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id)).slice(0, n)
    .map((u) => `${u.id}\t${u.refs.class}\t${u.start_paths.join(',')}`).join('\n');
}

// ---------- assign / ingest ----------
function assign(run, agent, ids) {
  if (!isAgentId(agent)) die(`bad agent id ${agent}`);
  if (fs.existsSync(path.join(run, 'agents', agent))) die(`agent ${agent} already exists; use a fresh id`);
  const ledger = load(path.join(run, 'ledger.json'));
  const byId = new Map(ledger.map((u) => [u.id, u]));
  for (const id of ids) {
    const u = byId.get(id);
    if (!u) die(`unknown unit ${id}`);
    if (u.status !== 'planned') die(`unit ${id} is ${u.status}, not planned`);
    if ((u.history || []).some((h) => h.owner === agent || (h.checks || []).some((c) => c.by === agent))) die(`${agent} worked an archived attempt of ${id}`);
    u.status = 'in_progress'; u.owner = agent;
  }
  for (const d of ['scratch', 'evidence']) fs.mkdirSync(path.join(run, 'agents', agent, d), { recursive: true });
  writeJson(path.join(run, 'agents', agent, 'assignment.json'), { units: ids, at: new Date().toISOString() });
  saveLedger(run, ledger);
  journal(run, { cmd: 'assign', agent, units: ids.length });
  return `assigned ${ids.length} unit(s) to ${agent}`;
}

function ingest(run, agent, resultPath) {
  const dir = path.join(run, 'agents', agent);
  if (!fs.existsSync(path.join(dir, 'assignment.json'))) die(`no assignment for ${agent}`);
  if (fs.existsSync(path.join(dir, 'ingested.json'))) return `${agent} already ingested`;
  const stored = path.join(dir, 'result.json');
  if (path.resolve(resultPath) !== path.resolve(stored)) {
    // Persist the raw result first so a crash after this point never loses agent work.
    writeAtomic(stored, fs.readFileSync(resultPath, 'utf8'));
  }
  const assigned = new Set(load(path.join(dir, 'assignment.json')).units);
  const ledger = load(path.join(run, 'ledger.json'));
  const byId = new Map(ledger.map((u) => [u.id, u]));
  let result;
  try { result = JSON.parse(fs.readFileSync(stored, 'utf8')); } catch { result = null; }
  const problems = [];
  const reset = (u, why) => { problems.push(`${u.id}: ${why}`); Object.assign(u, { status: 'planned', owner: null, paths: [], checks: [], fingerprints: [], open: [] }); };
  const seen = new Set();
  const results = isObj(result) && isArr(result.units) ? result.units : [];
  if (!isObj(result)) problems.push('result is not a JSON object; all units returned to planned');
  for (const r of results) {
    const u = isObj(r) && byId.get(r.id);
    if (!u || !assigned.has(r.id) || seen.has(r.id)) { problems.push(`ignored unit entry ${isObj(r) ? r.id : '?'} (not assigned or duplicate)`); continue; }
    seen.add(r.id);
    if (u.owner !== agent || u.status !== 'in_progress') { problems.push(`${r.id}: not in progress for ${agent}`); continue; }
    if (!['covered', 'candidate', 'blocked'].includes(r.disposition)) { reset(u, 'bad disposition'); continue; }
    const checks = isArr(r.checks) ? r.checks : [];
    const badCheck = checks.find((c) => !isObj(c) || !isAgentId(c.by) || !isArr(c.paths) || !c.paths.every(isRelPath)
      || (c.method === 'local' && !(typeof c.evidence === 'string' && fs.existsSync(path.join(run, ...c.evidence.split('/'))))));
    if (badCheck) { reset(u, 'invalid check or unpromoted evidence'); continue; }
    Object.assign(u, {
      status: r.disposition, paths: [...new Set(checks.flatMap((c) => c.paths))], checks,
      fingerprints: r.disposition === 'candidate' ? (r.fingerprints || []) : [], open: isArr(r.open) ? r.open : [],
    });
    const one = new Reporter();
    validateLedger([u], one, { runDir: run, checkFiles: true, checkBlocks: true, ...runOpts(run) });
    if (one.errors.length) reset(u, `rejected: ${one.errors[0]}`);
  }
  for (const id of assigned) if (!seen.has(id)) { const u = byId.get(id); if (u && u.status === 'in_progress' && u.owner === agent) reset(u, 'missing from result'); }
  if (isObj(result) && isArr(result.hardening) && result.hardening.length) {
    for (const id of seen) { const u = byId.get(id); u.notes = { ...(isObj(u.notes) ? u.notes : {}), hardening: [...new Set([...((u.notes && u.notes.hardening) || []), ...result.hardening.filter((h) => typeof h === 'string')])] }; }
  }
  saveLedger(run, ledger); // validates; aborts with nothing written if invalid
  let cands = 0;
  for (const c of isObj(result) && isArr(result.candidates) ? result.candidates : []) {
    if (!isObj(c) || typeof c.fingerprint !== 'string' || !FINGERPRINT.test(c.fingerprint)) { problems.push('candidate without valid fingerprint skipped'); continue; }
    fs.mkdirSync(path.join(run, 'candidates'), { recursive: true });
    const f = path.join(run, 'candidates', fpFile(c.fingerprint));
    if (!fs.existsSync(f)) { writeJson(f, { ...c, found_by: agent }); cands++; }
  }
  const unc = isObj(result) && isArr(result.uncovered) ? result.uncovered.filter(isObj) : [];
  if (unc.length) {
    fs.mkdirSync(path.join(run, 'queue'), { recursive: true });
    fs.appendFileSync(path.join(run, 'queue', 'uncovered.jsonl'), unc.map((x) => JSON.stringify({ ...x, from: agent })).join('\n') + '\n');
  }
  writeJson(path.join(dir, 'ingested.json'), { at: new Date().toISOString(), problems });
  journal(run, { cmd: 'ingest', agent, units: seen.size, candidates: cands, uncovered: unc.length, problems: problems.length });
  return `ingested ${agent}: ${seen.size} unit(s), ${cands} new candidate(s), ${unc.length} uncovered${problems.length ? `\n  ${problems.join('\n  ')}` : ''}`;
}

// ---------- decide / assemble ----------
function decide(run, verifier, decisionPath) {
  if (!isAgentId(verifier)) die(`bad verifier id ${verifier}`);
  const d = load(decisionPath);
  const record = isObj(d) && isObj(d.record) ? d.record : undefined;
  if (!record || !['confirmed', 'needs_validation', 'rejected'].includes(d.decision) || record.verdict !== d.decision) die('decision must be {"decision": verdict, "record": {...same verdict...}}');
  const rep = new Reporter();
  validateFindings([record], rep);
  if (rep.errors.length) die(`record invalid, not stored:\n  ${rep.errors.slice(0, 20).join('\n  ')}`);
  const candidates = path.join(run, 'candidates', fpFile(record.fingerprint));
  const prior = load(candidates, false);
  if (prior && prior.found_by === verifier) die(`${verifier} found this candidate and cannot validate it`);
  fs.mkdirSync(path.join(run, 'decisions'), { recursive: true });
  const file = path.join(run, 'decisions', fpFile(record.fingerprint));
  const old = load(file, false);
  if (old && old.by === verifier) die(`${verifier} already decided ${record.fingerprint}; a replacement needs a fresh verifier`);
  writeJson(file, { by: verifier, at: new Date().toISOString(), decision: d.decision, record, replaces: old ? old.by : null });
  journal(run, { cmd: 'decide', verifier, fingerprint: record.fingerprint, decision: d.decision });
  return `stored ${d.decision} for ${record.fingerprint}`;
}
function assemble(run) {
  const records = listJson(path.join(run, 'decisions')).map((f) => load(path.join(run, 'decisions', f)).record)
    .sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));
  const rep = new Reporter();
  validateFindings(records, rep);
  const ledger = load(path.join(run, 'ledger.json'));
  crossCheckLedger(records, ledger, rep, runOpts(run).status);
  const runJson = load(path.join(run, 'run.json'), false);
  if (isObj(runJson) && typeof runJson.target === 'string' && fs.existsSync(runJson.target)) verifyQuotes(records, runJson.target, rep);
  if (rep.errors.length) die(`findings invalid, not written:\n  ${rep.errors.slice(0, 20).join('\n  ')}`);
  writeJson(path.join(run, 'findings.json'), records);
  journal(run, { cmd: 'assemble', records: records.length });
  return `findings.json: ${records.length} record(s)${rep.warnings.length ? `\n  ${rep.warnings.join('\n  ')}` : ''}`;
}

// ---------- recover ----------
function recover(run) {
  const out = [];
  for (const f of fs.readdirSync(run)) if (/\.tmp-\d+$/.test(f)) { fs.unlinkSync(path.join(run, f)); out.push(`removed partial write ${f}`); }
  const agentsDir = path.join(run, 'agents');
  for (const a of fs.existsSync(agentsDir) ? fs.readdirSync(agentsDir).sort() : []) {
    if (fs.existsSync(path.join(agentsDir, a, 'result.json')) && !fs.existsSync(path.join(agentsDir, a, 'ingested.json'))) {
      out.push(ingest(run, a, path.join(agentsDir, a, 'result.json')));
    }
  }
  const ledger = load(path.join(run, 'ledger.json'));
  let lost = 0;
  for (const u of ledger) {
    if (u.status !== 'in_progress') continue;
    if (fs.existsSync(path.join(agentsDir, u.owner, 'result.json'))) continue;
    Object.assign(u, { status: 'planned', owner: null }); lost++; // the lost agent id is never reused (assign refuses existing dirs)
  }
  if (lost) { saveLedger(run, ledger); out.push(`${lost} unit(s) from lost agents returned to planned`); }
  journal(run, { cmd: 'recover', lost });
  out.push(status(run));
  return out.join('\n');
}

function main(argv) {
  const [cmd, ...a] = argv.slice(2);
  const flag = (f, d) => { const i = a.indexOf(f); return i !== -1 ? a[i + 1] : d; };
  switch (cmd) {
    case 'estimate': {
      const profile = flag('--profile', 'deep');
      if (!a[0] || !EST.unitsPerKloc[profile]) die('usage: estimate <target> [--profile deep|standard|quick] [--price-in $/M --price-out $/M] [--cache-hit 0.85]');
      const e = estimate(path.resolve(a[0]), profile);
      console.log(`${e.files} files, ${e.loc.toLocaleString('en-US')} non-blank lines (tests and vendored code excluded)`);
      console.log(`${e.profile}: ~${e.units} units → ${e.agents} agents (${e.scouts} scouts, ${e.hunters} hunters, ${e.verifiers} verifiers, ${e.critics} critic calls)`);
      console.log(`tokens processed: ~${human(e.tokens_low)}-${human(e.tokens_high)} input, ~${human(e.output_low)}-${human(e.output_high)} output (rough, ±60%)`);
      const pin = Number(flag('--price-in', NaN)); const pout = Number(flag('--price-out', NaN)); const hit = Number(flag('--cache-hit', 0.85));
      if (Number.isFinite(pin) && Number.isFinite(pout)) {
        const lo = dollars(e.tokens_low, e.output_low, pin, pout, hit); const hi = dollars(e.tokens_high, e.output_high, pin, pout, hit);
        console.log(`cost at $${pin}/M in, $${pout}/M out: ~$${lo.cached.toFixed(0)}-$${hi.cached.toFixed(0)} with ${Math.round(hit * 100)}% cache hits; ~$${lo.uncached.toFixed(0)}-$${hi.uncached.toFixed(0)} with no caching`);
      }
      if (e.scoped_runs_needed > 1) console.log(`split into ≥ ${e.scoped_runs_needed} scoped runs (10,000-unit ledger cap)`);
      return 0;
    }
    case 'status': console.log(status(a[0])); return 0;
    case 'next': console.log(next(a[0], Number(flag('--n', 10)))); return 0;
    case 'assign': console.log(assign(a[0], a[1], a.slice(2))); return 0;
    case 'ingest': console.log(ingest(a[0], a[1], a[2])); return 0;
    case 'decide': console.log(decide(a[0], a[1], a[2])); return 0;
    case 'assemble': console.log(assemble(a[0])); return 0;
    case 'recover': console.log(recover(a[0])); return 0;
    default:
      console.error('usage: run-state.cjs estimate|status|next|assign|ingest|decide|assemble|recover ... (see header)');
      return 2;
  }
}

if (require.main === module) process.exitCode = main(process.argv);
module.exports = { estimate, dollars, status, next, assign, ingest, decide, assemble, recover, writeAtomic, EST };
