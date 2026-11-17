#!/usr/bin/env node
'use strict';
// Crash-safe run state for long audits. The run directory on disk is the source of truth, so the lead
// never has to hold the ledger or agent results in its context, and any crash, rate limit or context
// reset resumes from files.
//
//   estimate <target> [--profile p] [--price-in N --price-out N] [--cache-hit 0.85]   rough agents, tokens, dollars
//   status   <run>                                       compact progress summary + the next action
//   next     <run> [--n 10]                              planned units to assign, in priority order
//   next     <run> --batch [--max-units 8] [--max-bytes 400000]
//            assignment groups: one line of unit ids per group (paste after assign <run> <fresh-id>); a group shares
//            start_path files or directories, one subsystem and one tier, within the unit and start_path byte caps
//   carry    <run> --from <prior run dir>                carry unchanged covered units of a complete prior run
//            (status carried); every other prior unit becomes planned with its prior value; prints grouped reasons
//   merge-runs <out dir> <run dir> <run dir>... [--allow-ref-drift]
//            union of complete runs of one repo at one source ref (see merge-runs.cjs): findings.json, union
//            ledger.json, run.json (merged_from), merge.json, disagreements.json, possible-duplicates.json
//   tier     <run>                                       set notes.tier high|standard (profile standard only; deep and
//            quick: all high; before tier runs every unit counts as high)
//   add-units <run> [seeds.json]                         add planned units from a JSON array of seeds
//            {refs, labels, start_paths, class_block, pack_blocks, skipped_blocks, prior?, notes?} (stdin when no
//            file); ids are derived, the ledger is created if absent and kept sorted; any invalid seed or existing
//            id aborts with nothing written
//   add-units <run> --from-critic <critic-id> | --from-queue
//            convert a stored critic's missing_units, or drain queue/uncovered.jsonl; entries that can't form a
//            valid unit (or already exist) are reported and skipped (unconverted queue lines stay in the queue)
//   assign   <run> <agent-id> <unit-id>... [--strong]    mark units in_progress for a fresh agent; never mixes tiers;
//            standard-tier units get tier "lite" (agent bsec-hunter-lite) unless --strong
//   brief    <run> <agent-id> --role <role> [--fingerprint <fp>] [--units <id>...] [--exclude-file <json>]
//            [--note-file <path> [--note-untrusted]] [--prior-file <json>]
//            write agents/<id>/brief.md from files (roles: scout-a|scout-b|scout-c|scout-d|hunter|skeptic|
//            critic|record-check|recheck) and print its path
//   ingest   <run> <agent-id> [result.json]              apply a Hunter result (default agents/<id>/out/result.json);
//            records notes.covered_tier and the cited files' hashes in hashes.json
//   decide   <run> <verifier-id> [decision.json]         store a Skeptic decision or a Phase 5 replacement
//   verify   <run> <verifier-id> [reply.json]            store a Phase 5 {"decision":"verified","fingerprint"} reply
//   critic   <run> <critic-id> [reply.json]              store a coverage critic reply with the coverage hash
//   reopen   <run> <unit-id> --reason <text>             archive a blocked/covered/candidate/carried unit, bump its wave, plan it
//   reopen   <run> --lite-tier --reason <text>           reopen every lite-covered unit for strong hunters (tier locked high)
//   set-status <run> <unit-id>... --to deferred|out_of_scope|not_applicable --reason <text>
//            park planned units (or in_progress units whose owner's result is lost); reason goes to open
//   resume   <run> [--reopen]                             incomplete → in_progress (complete only with --reopen)
//   inventory-gaps <run>                                 inventory.json surfaces no unit references (exit 1 if any)
//   sample-recheck <run> [--rate 0.1] [--min 3] [--redraw]  draw the deterministic recheck sample of covered units
//            (refused while units are planned/in_progress or none is covered; --redraw only after the covered set
//            changed; results recorded at the same wave are kept)
//   recheck-result <run> <agent-id> [reply.json]         store a re-check agent's agree/disagree per sampled unit
//   assemble <run>                                       build findings.json from stored decisions
//   complete <run>                                       set status "complete" if every completion condition holds
//   incomplete <run> <reason>                            set status "incomplete" with a valid reason
//   recover  <run>                                       repair state after a crash or rate limit
//
// [reply.json] defaults to RUN_DIR/agents/<id>/out/result.json, where the agent writes its own result.
// A change to the ledger, a decision, verification, critic record or recheck after status "complete" sets the
// run back to in_progress (the command says so). Every mutating command holds an exclusive lock on RUN_DIR/.lock. Every write is atomic (temp file +
// rename) and appended to journal.jsonl. A step that fails validation changes nothing.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  Reporter, loadJson, LEDGER_LIMITS, isObj, isArr, isAgentId, isRelPath, isVisible, FINGERPRINT, sha256, canonicalJson,
  quoteMatches, makeTargetReader,
} = require('./lib.cjs');
const { validateLedger, checkAnchors, checkRun } = require('./check-ledger.cjs');
const { validateFindings, crossCheckLedger, verifyQuotes } = require('./check-findings.cjs');
const briefLib = require('./brief.cjs');

const VERDICTS = ['confirmed', 'needs_validation', 'rejected'];
const CARRIED_PRIORS = new Set(['confirmed_same', 'nv']);
const ROLE_CMD = { skeptic: 'decide', critic: 'critic', 'record-check': 'verify', recheck: 'recheck-result' };
const now = () => new Date().toISOString();

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
function journal(run, event) { fs.appendFileSync(path.join(run, 'journal.jsonl'), JSON.stringify({ t: now(), ...event }) + '\n'); }
const fpFile = (fp) => encodeURIComponent(fp).replace(/\*/g, '%2A') + '.json';
const fpOfFile = (f) => decodeURIComponent(f.slice(0, -5));

function die(msg) { console.error(`run-state: ${msg}`); process.exit(1); }
function load(file, required = true, limits) {
  if (!fs.existsSync(file)) { if (required) die(`missing ${file}`); return undefined; }
  const rep = new Reporter();
  const v = loadJson(file, rep, limits);
  if (rep.errors.length) die(rep.errors.join('; '));
  return v;
}
// Like load, but never dies: undefined when missing or unreadable (status must work on a damaged run).
function tryLoad(file, limits) {
  if (!fs.existsSync(file)) return undefined;
  const rep = new Reporter();
  const v = loadJson(file, rep, limits);
  return rep.errors.length ? undefined : v;
}
// Raw text of an agent-written file: regular file only (never a symlink), size-capped.
function readRegular(file, maxBytes) {
  let st;
  try { st = fs.lstatSync(file); } catch { die(`missing ${file}`); }
  if (!st.isFile()) die(`${file} must be a regular file (not a symlink or directory)`);
  if (st.size > maxBytes) die(`${file} is larger than ${maxBytes} bytes`);
  return fs.readFileSync(file, 'utf8');
}
const loadLedger = (run, required = true) => load(path.join(run, 'ledger.json'), required, LEDGER_LIMITS);
const runInfo = (run) => { const r = tryLoad(path.join(run, 'run.json')); return isObj(r) ? r : {}; };
function targetOf(run) {
  const t = runInfo(run).target;
  try { return typeof t === 'string' && t && fs.statSync(t).isDirectory() ? t : null; } catch { return null; }
}
function ledgerOpts(run) {
  const r = runInfo(run);
  const o = { runDir: run, checkFiles: true, checkBlocks: true };
  if (r.profile !== undefined) o.profile = r.profile;
  if (r.status !== undefined) o.status = r.status;
  const t = targetOf(run);
  if (t) o.target = t;
  return o;
}
// Any change to the ledger, a decision, a verification, a critic record or the recheck after
// status "complete" sets the run back to in_progress, so `complete` must run again.
let unsealNote = null;
function unseal(run) {
  const f = path.join(run, 'run.json');
  const r = tryLoad(f);
  if (!isObj(r) || r.status !== 'complete') return;
  writeJson(f, { ...r, status: 'in_progress', incomplete_reason: null });
  journal(run, { cmd: 'unseal', reason: 'state changed after complete' });
  unsealNote = 'run.json: status was "complete" and is now "in_progress" because run state changed; run `complete <run>` again';
}
function saveLedger(run, ledger) {
  const opts = ledgerOpts(run);
  const sealed = opts.status === 'complete';
  if (sealed) opts.status = 'in_progress';
  const rep = new Reporter();
  validateLedger(ledger, rep, opts);
  if (rep.errors.length) die(`ledger update rejected, nothing written:\n  ${rep.errors.slice(0, 20).join('\n  ')}`);
  if (sealed) unseal(run);
  writeJson(path.join(run, 'ledger.json'), ledger);
}
function listJson(dir) { return fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort() : []; }
const agentDir = (run, a) => path.join(run, 'agents', a);
const outResult = (run, a) => path.join(agentDir(run, a), 'out', 'result.json');
function ensureAgentDirs(run, a) { for (const d of ['scratch', 'evidence', 'out']) fs.mkdirSync(path.join(agentDir(run, a), d), { recursive: true }); }
function markApplied(run, a, cmd) { const d = agentDir(run, a); if (fs.existsSync(d)) writeJson(path.join(d, 'applied.json'), { cmd, at: now() }); }
const candFile = (run, fp) => path.join(run, 'candidates', fpFile(fp));
const decFile = (run, fp) => path.join(run, 'decisions', fpFile(fp));
const verFile = (run, fp) => path.join(run, 'verifications', fpFile(fp));
const asList = (v) => (typeof v === 'string' ? [v] : isArr(v) ? v.filter((x) => typeof x === 'string') : []);
const byFp = (a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0);
const recordHash = (record) => sha256(canonicalJson(record));
const under = (file, paths) => typeof file === 'string' && paths.some((p) => file === p || file.startsWith(p + '/'));

// ---------- lock ----------
// RUN_DIR/.lock is created with the `wx` flag and holds {pid, at, nonce}. Waiters retry with backoff for
// up to LOCK.waitMs. A lock older than LOCK.staleMs whose pid is not alive may be stolen. The lock is
// released on normal return and on exit (die() calls process.exit, which runs the exit handler).
const LOCK = {
  waitMs: Number(process.env.BSEC_LOCK_WAIT_MS) > 0 ? Number(process.env.BSEC_LOCK_WAIT_MS) : 15000,
  staleMs: Number(process.env.BSEC_LOCK_STALE_MS) > 0 ? Number(process.env.BSEC_LOCK_STALE_MS) : 120000,
};
let lockFile = null;
let lockToken = null;
let lockDepth = 0;
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  if (pid === process.pid) return true;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}
function readLock(f) {
  let text; let st;
  try { st = fs.statSync(f); text = fs.readFileSync(f, 'utf8'); } catch { return null; }
  let info = null;
  try { info = JSON.parse(text); } catch { info = null; }
  return { text, info: isObj(info) ? info : null, mtime: st.mtimeMs };
}
function lockIsStale(h) {
  const t = h.info && typeof h.info.at === 'string' ? Date.parse(h.info.at) : NaN;
  const age = Date.now() - (Number.isFinite(t) ? t : h.mtime);
  return age > LOCK.staleMs && !(h.info && pidAlive(h.info.pid));
}
function stealLock(f, h) {
  const stale = `${f}.stale-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  try { fs.renameSync(f, stale); } catch { return; } // someone else moved it first
  let moved = null;
  try { moved = fs.readFileSync(stale, 'utf8'); } catch { moved = null; }
  if (moved !== h.text) { try { fs.linkSync(stale, f); } catch { /* a newer lock exists; leave it */ } } // took a fresh lock by mistake: put it back
  try { fs.unlinkSync(stale); } catch { /* ignore */ }
}
function acquireLock(run) {
  let st;
  try { st = fs.statSync(run); } catch { st = null; }
  if (!st || !st.isDirectory()) die(`run directory ${run} not found`);
  const f = path.join(run, '.lock');
  const token = JSON.stringify({ pid: process.pid, at: now(), nonce: crypto.randomBytes(8).toString('hex') });
  const deadline = Date.now() + LOCK.waitMs;
  let delay = 20;
  for (;;) {
    try { fs.writeFileSync(f, token, { flag: 'wx' }); lockFile = f; lockToken = token; return; } catch (e) {
      if (!['EEXIST', 'EPERM', 'EACCES', 'EBUSY'].includes(e.code)) die(`cannot create lock ${f}: ${e.code || e.message}`);
    }
    const h = readLock(f);
    if (h && lockIsStale(h)) { stealLock(f, h); continue; }
    if (Date.now() > deadline) {
      const who = h && h.info ? ` by pid ${h.info.pid} since ${h.info.at}` : '';
      die(`run directory is locked${who} (${f}); another run-state command is running. Retry later; if that process is gone, the lock is stolen automatically after ${Math.round(LOCK.staleMs / 1000)} s`);
    }
    sleepMs(delay + Math.floor(Math.random() * delay));
    delay = Math.min(delay * 2, 400);
  }
}
function releaseLock() {
  if (!lockFile) return;
  try { if (fs.readFileSync(lockFile, 'utf8') === lockToken) fs.unlinkSync(lockFile); } catch { /* ignore */ }
  lockFile = null; lockToken = null; lockDepth = 0;
}
process.on('exit', releaseLock);
function withLock(run, fn) {
  if (lockDepth > 0) { lockDepth++; try { return fn(); } finally { lockDepth--; } }
  acquireLock(run);
  lockDepth = 1;
  try { return fn(); } finally { releaseLock(); }
}

// ---------- ledger helpers ----------
const liveFps = (ledger) => new Set(ledger.flatMap((u) => (isObj(u) && isArr(u.fingerprints) ? u.fingerprints : [])));
// sha256 over the sorted "id:status:wave" of every unit: checks added later (Skeptic) don't change it;
// any new, reopened or re-statused unit does.
const coverageHash = (ledger) => sha256(ledger.filter(isObj).map((u) => `${u.id}:${u.status}:${u.wave}`).sort().join('\n'));
const states = (u) => [u, ...(isArr(u.history) ? u.history : [])].filter(isObj);
function unitPeople(u) {
  const s = new Set();
  for (const st of states(u)) {
    if (typeof st.owner === 'string') s.add(st.owner);
    for (const c of isArr(st.checks) ? st.checks : []) if (isObj(c) && typeof c.by === 'string') s.add(c.by);
  }
  return s;
}
const carriesFp = (u, fp) => states(u).some((s) => isArr(s.fingerprints) && s.fingerprints.includes(fp));

// Who touched a fingerprint: finders (candidate found_by), carriers of a prior record (carried_by: the
// owner of a carried prior unit, who re-validates it), ledger workers (owners and check authors of any unit
// carrying the fingerprint, live or history, minus carriers), decision authors and verifiers.
function provenance(run, ledger, fp) {
  const cand = tryLoad(candFile(run, fp));
  const finders = new Set(asList(isObj(cand) && cand.found_by));
  const carriers = new Set(asList(isObj(cand) && cand.carried_by));
  const workers = new Set();
  for (const u of ledger) if (isObj(u) && carriesFp(u, fp)) for (const p of unitPeople(u)) workers.add(p);
  for (const c of carriers) workers.delete(c);
  const decision = tryLoad(decFile(run, fp));
  const dec = isObj(decision) ? decision : null;
  const authors = new Set(dec ? [dec.by, ...(isArr(dec.history) ? dec.history.map((h) => isObj(h) && h.by) : [])].filter((x) => typeof x === 'string') : []);
  const ver = tryLoad(verFile(run, fp));
  const verifications = isObj(ver) && isArr(ver.verifications) ? ver.verifications.filter(isObj) : [];
  return { cand: isObj(cand) ? cand : null, finders, carriers, workers, decision: dec, authors, verifications, verifiers: new Set(verifications.map((v) => v.by)) };
}
function independenceProblem(p, id, fp) {
  if (p.finders.has(id)) return `${id} found ${fp} and cannot validate it`;
  if (p.workers.has(id)) return `${id} owns or has a check on a ledger unit carrying ${fp} and cannot validate it`;
  return null;
}
const isVerified = (p) => !!p.decision && isObj(p.decision.record) && p.verifications.some((v) => v.record_sha256 === recordHash(p.decision.record));
function decisionsMap(run) {
  const m = new Map();
  for (const f of listJson(path.join(run, 'decisions'))) { const d = tryLoad(path.join(run, 'decisions', f)); if (isObj(d)) m.set(fpOfFile(f), d); }
  return m;
}

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

// ---------- critics / inventory / recheck state ----------
function criticRecords(run) {
  return listJson(path.join(run, 'critics')).map((f) => tryLoad(path.join(run, 'critics', f))).filter(isObj).sort((a, b) => a.seq - b.seq);
}
function criticState(run, ledger, profile) {
  const recs = criticRecords(run);
  const hash = coverageHash(ledger);
  const current = (c) => c.clean === true && c.coverage_hash === hash;
  const last2 = recs.slice(-2);
  const ok = profile === 'quick' ? recs.length >= 1
    : last2.length === 2 && last2.every(current) && last2[0].critic !== last2[1].critic;
  const last = recs[recs.length - 1];
  return { count: recs.length, ok, lastCleanCurrent: !!last && current(last), hash, recs };
}

function inventoryGaps(run, ledger) {
  const invFile = path.join(run, 'inventory.json');
  const res = { present: fs.existsSync(invFile), total: 0, gaps: [], waived: 0, errors: [] };
  if (!res.present) return res;
  const rep = new Reporter();
  const inv = loadJson(invFile, rep, LEDGER_LIMITS);
  if (rep.errors.length) { res.errors.push(...rep.errors); return res; }
  const surfaces = isObj(inv) && isArr(inv.surfaces) ? inv.surfaces.filter((s) => isObj(s) && typeof s.id === 'string' && typeof s.file === 'string') : null;
  if (!surfaces) { res.errors.push('inventory.json: no surfaces array'); return res; }
  res.total = surfaces.length;
  const ids = new Set(surfaces.map((s) => s.id));
  const waived = new Set();
  const wFile = path.join(run, 'inventory-waivers.json');
  if (fs.existsSync(wFile)) {
    const wrep = new Reporter();
    const w = loadJson(wFile, wrep);
    if (wrep.errors.length) res.errors.push(...wrep.errors);
    else if (!isArr(w)) res.errors.push('inventory-waivers.json: must be an array of {"id", "why"}');
    else w.forEach((x, i) => {
      const where = `inventory-waivers.json[${i}]`;
      if (!isObj(x) || typeof x.id !== 'string') { res.errors.push(`${where}: needs a string id`); return; }
      if (!ids.has(x.id)) { res.errors.push(`${where}: unknown surface id ${JSON.stringify(briefLib.sanitize(x.id).slice(0, 160))}`); return; }
      if (!isVisible(x.why)) { res.errors.push(`${where}: "why" must be visible text`); return; }
      if (waived.has(x.id)) { res.errors.push(`${where}: duplicate waiver`); return; }
      waived.add(x.id);
    });
  }
  const referenced = new Set();
  for (const u of ledger) {
    if (!isObj(u)) continue;
    for (const p of [...(isArr(u.start_paths) ? u.start_paths : []), ...(isArr(u.paths) ? u.paths : [])]) if (typeof p === 'string') referenced.add(p);
    if (isObj(u.refs) && typeof u.refs.surface === 'string') referenced.add(u.refs.surface.split('#')[0]);
  }
  // A referenced path covers itself and, when it is a directory, every file under it (whole path
  // segments: `src/api` covers `src/api/x.ts`, not `src/api-old/x.ts`).
  const coveredFile = (file) => {
    const parts = file.split('/');
    for (let i = 1; i <= parts.length; i++) if (referenced.has(parts.slice(0, i).join('/'))) return true;
    return false;
  };
  for (const s of surfaces) {
    if (coveredFile(s.file)) continue;
    if (waived.has(s.id)) { res.waived++; continue; }
    res.gaps.push(s);
  }
  return res;
}

const planFile = (run) => path.join(run, 'recheck', 'plan.json');
const SAMPLEABLE = new Set(['covered', 'carried']);
const isLiteCovered = (u) => u.status === 'covered' && isObj(u.notes) && u.notes.covered_tier === 'lite';
// Lite stratum: at least 20 % of lite-covered units, minimum 5, all if fewer.
const liteRule = (n) => (n ? Math.min(n, Math.max(5, Math.ceil(0.2 * n))) : 0);
// Everything the recheck still needs before complete, in next-step order: [{code, text}].
function recheckNeeds(ledger, rc, profile) {
  const S = ledger.filter((u) => SAMPLEABLE.has(u.status)).length;
  const L = ledger.filter(isLiteCovered).length;
  const out = [];
  if (!rc) {
    if (profile === 'deep' && S > 0) out.push({ code: 'sample', text: 'deep: no recheck sample (sample-recheck <run>)' });
    else if (L > 0) out.push({ code: 'sample', text: `${L} unit(s) covered by lite hunters need the stratified recheck sample (sample-recheck <run>)` });
    return out;
  }
  if (rc.unresolved.length) out.push({ code: 'reopen', text: `${rc.unresolved.length} disagreeing unit(s) still covered at their sampled wave: ${rc.unresolved.slice(0, 3).join(', ')} (reopen <run> <unit-id> --reason ...)` });
  if (L > 0 && rc.liteDisagreements >= 2 && rc.liteDisagreements * 10 > rc.liteSampled) {
    out.push({ code: 'lite', text: `lite-tier recheck failed (${rc.liteDisagreements} of ${rc.liteSampled} disagree): reopen <run> --lite-tier --reason "..." so strong hunters redo every lite-covered unit` });
  }
  const liteReq = liteRule(L);
  const normReq = Math.min(recheckRule(Number.isFinite(rc.plan.rate) ? rc.plan.rate : 0.1, Number.isInteger(rc.plan.min) ? rc.plan.min : 3, S), Math.max(0, S - liteReq));
  if (rc.normalSampled < normReq || rc.liteSampled < liteReq) {
    out.push({ code: 'redraw', text: `the recheck sample (${rc.normalSampled} normal, ${rc.liteSampled} lite) is smaller than ${S} reviewed unit(s) now need (${normReq} normal, ${liteReq} lite); plan drawn too early: sample-recheck <run> --redraw` });
  }
  if (rc.missing.length) out.push({ code: 'missing', text: `${rc.missing.length} sampled unit(s) not re-checked yet` });
  return out;
}
function recheckState(run, ledger) {
  const plan = tryLoad(planFile(run));
  if (!isObj(plan) || !isArr(plan.units)) return null;
  const planned = plan.units.filter(isObj);
  const planWave = new Map(planned.map((p) => [p.id, p.wave]));
  // A result counts for a plan entry only when it was recorded at the sampled wave (results kept across a
  // redraw stay valid for units still in the sample at the same wave).
  const recorded = new Map();
  for (const f of listJson(path.join(run, 'recheck', 'results'))) {
    const r = tryLoad(path.join(run, 'recheck', 'results', f));
    if (isObj(r) && isArr(r.results)) {
      for (const e of r.results) {
        if (!isObj(e) || recorded.has(e.id) || !planWave.has(e.id)) continue;
        if (e.wave !== undefined && e.wave !== planWave.get(e.id)) continue;
        recorded.set(e.id, { agent: r.agent, agree: e.agree });
      }
    }
  }
  const byId = new Map(ledger.filter(isObj).map((u) => [u.id, u]));
  const stillSampled = (p) => { const u = byId.get(p.id); return !!u && SAMPLEABLE.has(u.status) && u.wave === p.wave; };
  const missing = planned.filter((p) => !recorded.has(p.id) && stillSampled(p)).map((p) => p.id);
  const disagreements = planned.filter((p) => recorded.has(p.id) && recorded.get(p.id).agree === false);
  const unresolved = disagreements.filter(stillSampled).map((p) => p.id);
  const lite = planned.filter((p) => p.stratum === 'lite');
  const liteDis = lite.filter((p) => recorded.has(p.id) && recorded.get(p.id).agree === false).length;
  return { plan, sampled: planned.length, normalSampled: planned.length - lite.length, liteSampled: lite.length, liteDisagreements: liteDis,
    recorded: planned.filter((p) => recorded.has(p.id)).length, missing, disagreements: disagreements.map((p) => p.id), unresolved, recordedMap: recorded };
}

// Agents whose out/result.json (or stored result) waits to be applied.
function pendingOutputs(run) {
  const dir = path.join(run, 'agents');
  const hunters = []; const others = [];
  for (const a of fs.existsSync(dir) ? fs.readdirSync(dir).sort() : []) {
    if (!isAgentId(a)) continue;
    const d = path.join(dir, a);
    const has = (...p) => fs.existsSync(path.join(d, ...p));
    if (has('assignment.json')) { if (!has('ingested.json') && (has('result.json') || has('out', 'result.json'))) hunters.push(a); continue; }
    const meta = tryLoad(path.join(d, 'brief.json'));
    if (isObj(meta) && ROLE_CMD[meta.role] && has('out', 'result.json') && !has('applied.json')) others.push({ agent: a, role: meta.role });
  }
  return { hunters, others };
}

function expectedRecords(run) {
  return listJson(path.join(run, 'decisions')).map((f) => load(path.join(run, 'decisions', f)).record).sort(byFp);
}
function findingsState(run) {
  const f = path.join(run, 'findings.json');
  if (!fs.existsSync(f)) return 'not yet';
  const cur = tryLoad(f);
  let exp;
  try { exp = listJson(path.join(run, 'decisions')).map((x) => (tryLoad(path.join(run, 'decisions', x)) || {}).record).sort(byFp); } catch { return 'stale'; }
  try { return cur !== undefined && canonicalJson(cur) === canonicalJson(exp) ? 'current' : 'stale (run assemble)'; } catch { return 'stale (run assemble)'; }
}

// ---------- status / next ----------
function status(run) {
  const runJson = load(path.join(run, 'run.json'));
  const profile = runJson.profile;
  const ledger = loadLedger(run, false) || [];
  const counts = {};
  for (const u of ledger) counts[u.status] = (counts[u.status] || 0) + 1;
  const inProgress = ledger.filter((u) => u.status === 'in_progress');
  const live = [...liveFps(ledger)].sort();
  const decisions = decisionsMap(run);
  const undecided = live.filter((fp) => !decisions.has(fp));
  const needVer = profile === 'quick' ? [] : [...decisions.keys()].filter((fp) => decisions.get(fp).decision !== 'rejected' && !isVerified(provenance(run, ledger, fp)));
  const cs = criticState(run, ledger, profile);
  const inv = inventoryGaps(run, ledger);
  const rc = recheckState(run, ledger);
  const fstate = findingsState(run);
  const pend = pendingOutputs(run);
  const R = '<run>';
  const needs = recheckNeeds(ledger, rc, profile);
  const tiers = { strong: ledger.filter((u) => u.status === 'covered' && !isLiteCovered(u)).length, lite: ledger.filter(isLiteCovered).length };
  let next;
  if (!ledger.length) next = 'Phase 1: brief scout-a..d, write architecture.md, seed ledger.json (check-ledger.cjs)';
  else if (pend.hunters.length) next = `ingest results: ${pend.hunters.map((a) => `ingest ${R} ${a}`).join('; ')}`;
  else if (pend.others.length) next = `apply outputs: ${pend.others.map((o) => `${ROLE_CMD[o.role]} ${R} ${o.agent}`).join('; ')}`;
  else if (inProgress.length) next = `wait for or recover agents: ${[...new Set(inProgress.map((u) => u.owner))].join(', ')}`;
  else if (counts.planned) next = `assign ${counts.planned} planned unit(s): next ${R}, assign ${R} <fresh-id> <ids...>, brief ${R} <id> --role hunter`;
  else if (undecided.length) next = `send ${undecided.length} candidate(s) to Skeptics: brief ${R} <fresh-id> --role skeptic --fingerprint <fp>, then decide ${R} <id>`;
  else if (fstate !== 'current') next = `Phase 4: assemble ${R}`;
  else if (needVer.length) next = `Phase 5: ${needVer.length} record(s) need a fresh check: brief ${R} <fresh-id> --role record-check --fingerprint <fp>, then verify ${R} <id>`;
  else if (!cs.ok) {
    next = profile !== 'quick' && cs.lastCleanCurrent
      ? `run a separate final-clean critic: brief ${R} <fresh-id> --role critic, then critic ${R} <id>`
      : `run a coverage critic: brief ${R} <fresh-id> --role critic, then critic ${R} <id>, then add-units ${R} --from-critic <id> and reopen`;
  } else if (needs.length) {
    const x = needs[0];
    next = x.code === 'missing'
      ? `re-check ${rc.missing.length} sampled unit(s): brief ${R} <fresh-id> --role recheck --units <ids...> (lite-stratum units to a strong agent), then recheck-result ${R} <id>`
      : x.text.replace(/<run>/g, R);
  }
  else if (!inv.present && profile !== 'quick') next = `write the inventory: node inventory.cjs <target> --json ${R}/inventory.json, then inventory-gaps ${R}`;
  else if (inv.present && (inv.gaps.length || inv.errors.length)) next = `close ${inv.gaps.length} inventory gap(s) (${inv.errors.length} waiver error(s)): add-units or waive them (inventory-gaps ${R})`;
  else if (runJson.status !== 'complete') next = `complete ${R} (then Phase 6: score.cjs, REPORT.md, DETAILS.md, LEADS.md, findings.sarif)`;
  else if (!fs.existsSync(path.join(run, 'REPORT.md'))) next = 'Phase 6: run score.cjs, write REPORT.md, DETAILS.md, LEADS.md, findings.sarif (to-sarif.cjs)';
  else next = 'done: run is complete';
  const lines = [
    `run ${runJson.run_id} · ${profile} · ${runJson.status}${runJson.incomplete_reason ? ` (${runJson.incomplete_reason})` : ''}`,
    `units ${ledger.length}: ${Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ') || 'none'}${tiers.lite ? `; covered by tier: ${tiers.strong} strong, ${tiers.lite} lite` : ''}`,
    `candidates ${live.length}, decided ${decisions.size}, awaiting skeptic ${undecided.length}, awaiting verification ${needVer.length}`,
    `critics ${cs.count}; ${profile === 'quick' ? `quick needs 1: ${cs.ok ? 'yes' : 'no'}` : `last two clean, distinct, at current coverage: ${cs.ok ? 'yes' : 'no'}`}`,
    `inventory: ${inv.present ? `${inv.total} surfaces, ${inv.gaps.length} gap(s), ${inv.waived} waived${inv.errors.length ? `, ${inv.errors.length} error(s)` : ''}` : 'inventory.json not present'}`,
    `recheck: ${rc ? `${rc.sampled} sampled${rc.liteSampled ? ` (${rc.liteSampled} lite)` : ''}, ${rc.recorded} recorded, ${rc.disagreements.length} disagreements (${rc.unresolved.length} unresolved)` : `not sampled${profile === 'deep' ? ' (required for deep)' : ''}`}`,
    `findings.json ${fstate}`,
  ];
  if (pend.hunters.length || pend.others.length) lines.push(`pending outputs: ${[...pend.hunters, ...pend.others.map((o) => o.agent)].join(', ')}`);
  lines.push(`next: ${next}`);
  return lines.join('\n');
}
function next(run, n) {
  const ledger = loadLedger(run);
  const rank = (u) => (isObj(u.notes) && Number.isFinite(u.notes.priority) ? u.notes.priority : 99);
  return ledger.filter((u) => u.status === 'planned').sort((a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id)).slice(0, n)
    .map((u) => `${u.id}\t${u.refs.class}\t${u.start_paths.join(',')}`).join('\n');
}

// ---------- assign / ingest ----------
function assign(run, agent, ids, forceStrong = false) {
  if (!isAgentId(agent)) die(`bad agent id ${agent}`);
  // A pasted `next --batch` line ends in "# tier=…"; everything from the first "#" token on is a comment.
  const hash = ids.findIndex((x) => typeof x === 'string' && x.startsWith('#'));
  if (hash !== -1) ids = ids.slice(0, hash);
  return withLock(run, () => {
    if (fs.existsSync(agentDir(run, agent))) die(`agent ${agent} already exists; use a fresh id`);
    if (!ids.length) die('assign needs at least one unit id');
    const ledger = loadLedger(run);
    const byId = new Map(ledger.map((u) => [u.id, u]));
    for (const id of ids) {
      const u = byId.get(id);
      if (!u) die(`unknown unit ${id}`);
      if (u.status !== 'planned') die(`unit ${id} is ${u.status}, not planned`);
      if ((u.history || []).some((h) => h.owner === agent || (h.checks || []).some((c) => c.by === agent))) die(`${agent} worked an archived attempt of ${id}`);
      u.status = 'in_progress'; u.owner = agent;
    }
    const profile = runInfo(run).profile;
    const tiers = new Set(ids.map((id) => tierOf(byId.get(id), profile)));
    if (tiers.size > 1) die('assignment mixes high and standard tier units; give them to separate agents (next <run> --batch never mixes them)');
    const hunterTier = tiers.has('standard') && !forceStrong ? 'lite' : 'strong';
    ensureAgentDirs(run, agent);
    writeJson(path.join(agentDir(run, agent), 'assignment.json'), { units: ids, at: now(), tier: hunterTier });
    saveLedger(run, ledger);
    journal(run, { cmd: 'assign', agent, units: ids.length, tier: hunterTier });
    return `assigned ${ids.length} unit(s) to ${agent}${hunterTier === 'lite' ? ' (standard tier: use agent bsec-hunter-lite)' : ''}`;
  });
}

// A hunter candidate is valid when it is that schema branch's record (verdict = proposed).
function candidateProblem(c) {
  if (!['confirmed', 'needs_validation'].includes(c.proposed)) return 'proposed must be confirmed|needs_validation';
  if (c.verdict !== undefined && c.verdict !== c.proposed) return 'verdict differs from proposed';
  const { proposed, ...rest } = c;
  const rep = new Reporter();
  validateFindings([{ ...rest, verdict: proposed }], rep);
  return rep.errors.length ? rep.errors.slice(0, 3).join('; ') : null;
}

function ingest(run, agent, resultPath) {
  if (!isAgentId(agent)) die(`bad agent id ${JSON.stringify(String(agent))}`);
  return withLock(run, () => {
    const dir = agentDir(run, agent);
    if (!fs.existsSync(path.join(dir, 'assignment.json'))) die(`no assignment for ${agent}`);
    if (fs.existsSync(path.join(dir, 'ingested.json'))) return `${agent} already ingested`;
    const stored = path.join(dir, 'result.json');
    let src = resultPath ? path.resolve(resultPath) : outResult(run, agent);
    if (!resultPath && !fs.existsSync(src) && fs.existsSync(stored)) src = stored;
    // Persist the raw result first so a crash after this point never loses agent work.
    if (path.resolve(src) !== path.resolve(stored)) writeAtomic(stored, readRegular(src, LEDGER_LIMITS.maxBytes));
    const assigned = new Set(load(path.join(dir, 'assignment.json')).units);
    const ledger = loadLedger(run);
    const opts = ledgerOpts(run);
    const byId = new Map(ledger.map((u) => [u.id, u]));
    const rep0 = new Reporter();
    let result = loadJson(stored, rep0, LEDGER_LIMITS);
    if (rep0.errors.length) result = null;
    const problems = [];
    const reset = (u, why) => { problems.push(`${u.id}: ${why}`); Object.assign(u, { status: 'planned', owner: null, paths: [], checks: [], fingerprints: [], open: [] }); };
    if (!isObj(result)) problems.push('result is not a JSON object; all units returned to planned');
    // Candidates first: a candidate unit needs a valid candidate object (or an existing candidate file).
    const validCands = new Map();
    for (const c of isObj(result) && isArr(result.candidates) ? result.candidates : []) {
      if (!isObj(c) || typeof c.fingerprint !== 'string' || !FINGERPRINT.test(c.fingerprint)) { problems.push('candidate without valid fingerprint skipped'); continue; }
      if (validCands.has(c.fingerprint)) { problems.push(`duplicate candidate ${c.fingerprint} skipped`); continue; }
      const why = candidateProblem(c);
      if (why) { problems.push(`candidate ${c.fingerprint} invalid, not stored: ${why}`); continue; }
      validCands.set(c.fingerprint, c);
    }
    const seen = new Set();
    const results = isObj(result) && isArr(result.units) ? result.units : [];
    for (const r of results) {
      const u = isObj(r) && byId.get(r.id);
      if (!u || !assigned.has(r.id) || seen.has(r.id)) { problems.push(`ignored unit entry ${isObj(r) ? r.id : '?'} (not assigned or duplicate)`); continue; }
      seen.add(r.id);
      if (u.owner !== agent || u.status !== 'in_progress') { problems.push(`${r.id}: not in progress for ${agent}`); continue; }
      if (!['covered', 'candidate', 'blocked'].includes(r.disposition)) { reset(u, 'bad disposition'); continue; }
      const checks = isArr(r.checks) ? r.checks : [];
      const badCheck = checks.find((c) => !isObj(c) || !isAgentId(c.by) || !isArr(c.paths) || !c.paths.every((p) => typeof p === 'string')
        || (c.method === 'local' && !(typeof c.evidence === 'string' && fs.existsSync(path.join(run, ...c.evidence.split('/'))))));
      if (badCheck) { reset(u, 'invalid check or unpromoted evidence'); continue; }
      const foreign = checks.find((c) => c.by !== agent);
      if (foreign) { reset(u, `invalid check: by "${foreign.by}" is not ${agent}`); continue; }
      const fps = r.disposition === 'candidate' ? (isArr(r.fingerprints) ? r.fingerprints : []) : [];
      const orphan = fps.find((fp) => typeof fp !== 'string' || !FINGERPRINT.test(fp) || !(validCands.has(fp) || fs.existsSync(candFile(run, fp))));
      if (orphan !== undefined) { reset(u, `candidate fingerprint ${JSON.stringify(orphan)} has no valid candidate object in this result`); continue; }
      Object.assign(u, { status: r.disposition, paths: [...new Set(checks.flatMap((c) => c.paths))], checks, fingerprints: fps, open: isArr(r.open) ? r.open : [] });
      const one = new Reporter();
      validateLedger([u], one, opts); // includes anchor quotes and path existence when run.json.target exists
      if (one.errors.length) reset(u, `rejected: ${one.errors[0]}`);
    }
    for (const id of assigned) if (!seen.has(id)) { const u = byId.get(id); if (u && u.status === 'in_progress' && u.owner === agent) reset(u, 'missing from result'); }
    if (isObj(result) && isArr(result.hardening) && result.hardening.length) {
      for (const id of seen) { const u = byId.get(id); u.notes = { ...(isObj(u.notes) ? u.notes : {}), hardening: [...new Set([...((u.notes && u.notes.hardening) || []), ...result.hardening.filter((h) => typeof h === 'string')])] }; }
    }
    const asg = load(path.join(dir, 'assignment.json'));
    const coveredTier = isObj(asg) && asg.tier === 'lite' ? 'lite' : 'strong';
    for (const id of seen) {
      const u = byId.get(id);
      const notes = isObj(u.notes) ? { ...u.notes } : {};
      if (u.status === 'covered') notes.covered_tier = coveredTier; else delete notes.covered_tier;
      u.notes = notes;
    }
    saveLedger(run, ledger); // validates; aborts with nothing written if invalid
    recordHashes(run, targetOf(run), [...seen].map((id) => byId.get(id)).filter((u) => ['covered', 'candidate', 'blocked'].includes(u.status)));
    const live = liveFps(ledger);
    let newC = 0; let knownC = 0;
    for (const [fp, c] of validCands) {
      if (!live.has(fp)) problems.push(`candidate ${fp} is not linked to any live unit (stored anyway)`);
      const carried = ledger.some((u) => u.owner === agent && CARRIED_PRIORS.has(u.prior) && isArr(u.fingerprints) && u.fingerprints.includes(fp));
      const key = carried ? 'carried_by' : 'found_by';
      fs.mkdirSync(path.join(run, 'candidates'), { recursive: true });
      const f = candFile(run, fp);
      const old = tryLoad(f);
      if (!isObj(old)) { writeJson(f, { ...c, [key]: [agent] }); newC++; continue; }
      const fb = asList(old.found_by); const cb = asList(old.carried_by);
      if (fb.includes(agent) || cb.includes(agent)) continue; // re-ingest after a crash
      const upd = { ...old, found_by: carried ? fb : [...fb, agent] };
      if (carried || cb.length) upd.carried_by = carried ? [...cb, agent] : cb;
      upd.alternates = [...(isArr(old.alternates) ? old.alternates : []), { by: agent, at: now(), candidate: c }];
      writeJson(f, upd); knownC++;
    }
    const unc = isObj(result) && isArr(result.uncovered) ? result.uncovered.filter(isObj) : [];
    if (unc.length) {
      fs.mkdirSync(path.join(run, 'queue'), { recursive: true });
      fs.appendFileSync(path.join(run, 'queue', 'uncovered.jsonl'), unc.map((x) => JSON.stringify({ ...x, from: agent })).join('\n') + '\n');
    }
    writeJson(path.join(dir, 'ingested.json'), { at: now(), problems });
    journal(run, { cmd: 'ingest', agent, units: seen.size, candidates: newC, known_candidates: knownC, uncovered: unc.length, problems: problems.length });
    return `ingested ${agent}: ${seen.size} unit(s), ${newC} new candidate(s)${knownC ? `, ${knownC} already known (finder added)` : ''}, ${unc.length} uncovered${problems.length ? `\n  ${problems.join('\n  ')}` : ''}`;
  });
}

// ---------- decide / verify / assemble ----------
function decide(run, verifier, decisionPath) {
  if (!isAgentId(verifier)) die(`bad verifier id ${JSON.stringify(String(verifier))}`);
  return withLock(run, () => {
    const d = load(decisionPath ? path.resolve(decisionPath) : outResult(run, verifier));
    const record = isObj(d) && isObj(d.record) ? d.record : undefined;
    // A Phase 5 {"decision":"replace","why","record"} reply is stored as a decision with the record's verdict.
    const decision = isObj(d) && d.decision === 'replace' && record ? record.verdict : isObj(d) ? d.decision : undefined;
    if (!record || !VERDICTS.includes(decision) || record.verdict !== decision) die('decision must be {"decision": verdict, "record": {...same verdict...}} or {"decision":"replace","why":"...","record":{...}}');
    const rep = new Reporter();
    validateFindings([record], rep);
    if (rep.errors.length) die(`record invalid, not stored:\n  ${rep.errors.slice(0, 20).join('\n  ')}`);
    const fp = record.fingerprint;
    const ledger = loadLedger(run);
    if (!liveFps(ledger).has(fp)) die(`${fp} is not a live fingerprint of any ledger unit; only a live candidate can be decided`);
    const p = provenance(run, ledger, fp);
    const why = independenceProblem(p, verifier, fp);
    if (why) die(why);
    if (p.authors.has(verifier)) die(`${verifier} already decided ${fp}; a replacement needs a fresh verifier`);
    const old = p.decision;
    const history = old ? [...(isArr(old.history) ? old.history : []), { by: old.by, at: old.at, decision: old.decision, record: old.record, ...(old.why ? { why: old.why } : {}) }] : [];
    const entry = { by: verifier, at: now(), decision, record, replaces: old ? old.by : null, history };
    if (d.decision === 'replace' && typeof d.why === 'string') entry.why = d.why;
    fs.mkdirSync(path.join(run, 'decisions'), { recursive: true });
    unseal(run);
    writeJson(decFile(run, fp), entry);
    markApplied(run, verifier, 'decide');
    journal(run, { cmd: 'decide', verifier, fingerprint: fp, decision, replaces: entry.replaces });
    return `stored ${decision} for ${fp}${old ? ` (replaces ${old.by}'s ${old.decision}; needs a new verification)` : ''}`;
  });
}

function verify(run, verifier, replyPath) {
  if (!isAgentId(verifier)) die(`bad verifier id ${JSON.stringify(String(verifier))}`);
  return withLock(run, () => {
    const d = load(replyPath ? path.resolve(replyPath) : outResult(run, verifier));
    if (isObj(d) && d.decision === 'replace') {
      die(`a "replace" reply is a new decision, not a verification: run \`run-state.cjs decide <run> ${verifier} <file>\` with this reply (the verifier id must be fresh for that fingerprint); the replacement then needs a new verification by another fresh agent`);
    }
    if (!isObj(d) || d.decision !== 'verified' || typeof d.fingerprint !== 'string' || !FINGERPRINT.test(d.fingerprint)) die('verification must be {"decision":"verified","fingerprint":"..."}');
    const fp = d.fingerprint;
    const ledger = loadLedger(run);
    if (!liveFps(ledger).has(fp)) die(`${fp} is not a live fingerprint of any ledger unit`);
    const p = provenance(run, ledger, fp);
    if (!p.decision || !isObj(p.decision.record)) die(`no decision stored for ${fp}; run decide first`);
    const why = independenceProblem(p, verifier, fp);
    if (why) die(why);
    if (p.authors.has(verifier)) die(`${verifier} authored a decision for ${fp} and cannot verify it`);
    if (p.verifiers.has(verifier)) die(`${verifier} already verified ${fp}; a further check needs a fresh agent`);
    fs.mkdirSync(path.join(run, 'verifications'), { recursive: true });
    const entry = { by: verifier, at: now(), record_sha256: recordHash(p.decision.record), decision_by: p.decision.by, verdict: p.decision.decision };
    unseal(run);
    writeJson(verFile(run, fp), { fingerprint: fp, verifications: [...p.verifications, entry] });
    markApplied(run, verifier, 'verify');
    journal(run, { cmd: 'verify', verifier, fingerprint: fp, record_sha256: entry.record_sha256 });
    return `verified ${fp} (current ${p.decision.decision} record by ${p.decision.by})`;
  });
}

function buildFindings(run) {
  const records = expectedRecords(run);
  const rep = new Reporter();
  validateFindings(records, rep);
  const ledger = loadLedger(run);
  crossCheckLedger(records, ledger, rep, runInfo(run).status);
  const t = targetOf(run);
  if (t) verifyQuotes(records, t, rep);
  return { records, rep };
}
function assemble(run) {
  return withLock(run, () => {
    const { records, rep } = buildFindings(run);
    if (rep.errors.length) die(`findings invalid, not written:\n  ${rep.errors.slice(0, 20).join('\n  ')}`);
    writeJson(path.join(run, 'findings.json'), records);
    journal(run, { cmd: 'assemble', records: records.length });
    return `findings.json: ${records.length} record(s)${rep.warnings.length ? `\n  ${rep.warnings.join('\n  ')}` : ''}`;
  });
}

// ---------- critic / reopen ----------
function critic(run, id, replyPath) {
  if (!isAgentId(id)) die(`bad critic id ${JSON.stringify(String(id))}`);
  return withLock(run, () => {
    const d = load(replyPath ? path.resolve(replyPath) : outResult(run, id));
    const bad = [];
    if (!isObj(d)) bad.push('reply must be an object');
    else {
      if (!isArr(d.missing_units) || !d.missing_units.every(isObj)) bad.push('missing_units must be an array of objects');
      if (!isArr(d.reopen_ids) || !d.reopen_ids.every((x) => typeof x === 'string')) bad.push('reopen_ids must be an array of strings');
      if (!isArr(d.resolved_prior_leads) || !d.resolved_prior_leads.every((x) => typeof x === 'string')) bad.push('resolved_prior_leads must be an array of strings');
      if (typeof d.stop !== 'boolean') bad.push('stop must be a boolean');
    }
    if (bad.length) die(`critic reply rejected, nothing stored: ${bad.join('; ')} (shape: {"missing_units": [...], "reopen_ids": [...], "resolved_prior_leads": [...], "stop": bool})`);
    const recs = criticRecords(run);
    if (recs.some((r) => r.critic === id)) die(`critic id ${id} was already used; every critic run needs a fresh id`);
    if (fs.existsSync(path.join(agentDir(run, id), 'assignment.json'))) die(`${id} is a hunter; a critic must be a fresh agent`);
    const ledger = loadLedger(run);
    const byId = new Map(ledger.map((u) => [u.id, u]));
    const profile = runInfo(run).profile;
    const seq = recs.length ? Math.max(...recs.map((r) => r.seq)) + 1 : 1;
    const clean = d.missing_units.length === 0 && d.reopen_ids.length === 0;
    const hash = coverageHash(ledger);
    fs.mkdirSync(path.join(run, 'critics'), { recursive: true });
    unseal(run);
    writeJson(path.join(run, 'critics', `${String(seq).padStart(6, '0')}.json`), { seq, critic: id, at: now(), clean, coverage_hash: hash, profile, reply: d });
    markApplied(run, id, 'critic');
    journal(run, { cmd: 'critic', critic: id, seq, clean, coverage_hash: hash });
    const out = [`critic ${id} recorded as #${seq}: ${clean ? 'clean' : `not clean (${d.missing_units.length} missing unit(s), ${d.reopen_ids.length} reopen id(s))`} at coverage ${hash.slice(0, 12)}`];
    if (!clean) {
      const known = d.reopen_ids.filter((x) => byId.has(x));
      const unknown = d.reopen_ids.length - known.length;
      if (profile === 'quick') out.push(`quick profile: run-state.cjs add-units <run> --from-critic ${id}, then set-status <run> <new ids...> --to deferred --reason quick_profile (reopens are recorded as deferred the same way, not reopened)`);
      else {
        out.push(`lead: run-state.cjs add-units <run> --from-critic ${id} adds the ${d.missing_units.length} missing unit(s) as planned (then set-status --to out_of_scope for out-of-scope or unsafe ones); reopen each unit below:`);
        for (const x of known.slice(0, 20)) {
          const u = byId.get(x);
          out.push(['blocked', 'covered', 'candidate'].includes(u.status) ? `  run-state.cjs reopen <run> ${x} --reason "critic ${id}: see critics/${String(seq).padStart(6, '0')}.json"` : `  ${x} is ${u.status}; nothing to reopen`);
        }
        if (known.length > 20) out.push(`  ... ${known.length - 20} more reopen id(s) in critics/${String(seq).padStart(6, '0')}.json`);
      }
      if (unknown) out.push(`${unknown} reopen id(s) are not ledger units (ignored)`);
    }
    return out.join('\n');
  });
}

function archiveAndPlan(u, reason) {
  u.history = [...(isArr(u.history) ? u.history : []), { wave: u.wave, status: u.status, owner: u.owner, paths: u.paths, checks: u.checks, fingerprints: u.fingerprints, open: u.open, reopen_reason: reason }];
  Object.assign(u, { wave: u.wave + 1, status: 'planned', owner: null, paths: [], checks: [], fingerprints: [], open: [] });
  delete u.carried_from;
  if (isObj(u.notes)) { u.notes = { ...u.notes }; delete u.notes.covered_tier; }
}
const REOPENABLE = ['blocked', 'covered', 'candidate', 'carried'];
// reopen <run> <unit-id> --reason r            one unit
// reopen <run> --lite-tier --reason r          every covered unit a lite hunter covered; they become tier high
//                                              (notes.tier_lock) so only strong hunters take them again
function reopen(run, id, reason, liteTier = false) {
  return withLock(run, () => {
    if (!isVisible(reason)) die('reopen needs --reason <visible text>');
    const ledger = loadLedger(run);
    if (liteTier) {
      if (id) die('reopen --lite-tier takes no unit id');
      const lite = ledger.filter((u) => u.status === 'covered' && isObj(u.notes) && u.notes.covered_tier === 'lite');
      if (!lite.length) die('no covered unit was covered by a lite hunter');
      for (const u of lite) {
        archiveAndPlan(u, `lite-tier recheck failed: ${reason}`);
        u.notes = { ...u.notes, tier: 'high', tier_lock: true, tier_why: `lite-tier recheck failed: ${reason}` };
      }
      saveLedger(run, ledger);
      journal(run, { cmd: 'reopen', lite_tier: true, units: lite.length });
      return `reopened ${lite.length} lite-covered unit(s) for strong hunters (tier high, locked)`;
    }
    const u = ledger.find((x) => x.id === id);
    if (!u) die(`unknown unit ${id}`);
    if (!REOPENABLE.includes(u.status)) die(`unit is ${u.status}; only ${REOPENABLE.join('|')} units can be reopened`);
    archiveAndPlan(u, reason);
    saveLedger(run, ledger);
    journal(run, { cmd: 'reopen', unit: id, wave: u.wave });
    return `reopened ${id}: wave ${u.wave - 1} archived to history, now planned at wave ${u.wave} (needs a fresh owner)`;
  });
}

// ---------- set-status / resume ----------
const PARKED = ['deferred', 'out_of_scope', 'not_applicable'];
// Move units from planned (or from in_progress when the owner's result is lost: neither result.json nor
// out/result.json exists) to deferred|out_of_scope|not_applicable, with the reason in open.
function setStatus(run, ids, to, reason) {
  return withLock(run, () => {
    if (!PARKED.includes(to)) die(`--to must be one of ${PARKED.join('|')}`);
    if (!isVisible(reason)) die('set-status needs --reason <visible text>');
    if (!ids.length) die('set-status needs at least one unit id');
    const ledger = loadLedger(run);
    const byId = new Map(ledger.map((u) => [u.id, u]));
    for (const id of new Set(ids)) {
      const u = byId.get(id);
      if (!u) die(`unknown unit ${id}`);
      if (u.status === 'in_progress') {
        if (fs.existsSync(path.join(agentDir(run, u.owner), 'result.json')) || fs.existsSync(outResult(run, u.owner))) die(`${id}: owner ${u.owner} has a result waiting; ingest it first`);
      } else if (u.status !== 'planned') die(`${id} is ${u.status}; only planned units (or in_progress units whose result is lost) can be set to ${to}`);
      Object.assign(u, { status: to, owner: null, paths: [], checks: [], fingerprints: [], open: [reason] });
    }
    saveLedger(run, ledger);
    journal(run, { cmd: 'set-status', to, units: new Set(ids).size, reason });
    return `set ${new Set(ids).size} unit(s) to ${to}`;
  });
}
function resume(run, reopenComplete) {
  return withLock(run, () => {
    const f = path.join(run, 'run.json');
    const r = load(f);
    if (!isObj(r)) die('run.json must be an object');
    if (r.status === 'in_progress') return 'run.json: already in_progress';
    if (r.status === 'complete' && !reopenComplete) die('run is complete; pass --reopen to set it back to in_progress (complete must then run again)');
    writeJson(f, { ...r, status: 'in_progress', incomplete_reason: null });
    journal(run, { cmd: 'resume', from: r.status, reason: r.incomplete_reason || null });
    return `run.json: status ${r.status}${r.incomplete_reason ? ` (${r.incomplete_reason})` : ''} → in_progress`;
  });
}

// ---------- add-units ----------
// Seed shape: {refs, labels, start_paths, class_block, pack_blocks, skipped_blocks, prior?, notes?}.
// Critic missing_units / queue/uncovered.jsonl entries use flat refs {surface, boundary, subsystem, class,
// lifecycle?, start_paths, pack_blocks?, skipped_blocks?}; their labels default to the text after the last
// '#' of each ref, class_block to the class when it is a core-classes.md block, and a pack class is added
// to pack_blocks when missing.
const DIMS = ['surface', 'boundary', 'subsystem', 'class', 'lifecycle'];
function seedFromFlat(e) {
  if (!isObj(e)) return null;
  const refs = {};
  for (const k of DIMS) if (typeof e[k] === 'string') refs[k] = e[k];
  const label = (r) => { const t = r.slice(r.lastIndexOf('#') + 1).trim(); return t || r; };
  const labels = isObj(e.labels) ? e.labels : Object.fromEntries(Object.entries(refs).map(([k, v]) => [k, label(v)]));
  const cls = refs.class;
  const packBlocks = isArr(e.pack_blocks) ? [...e.pack_blocks] : [];
  if (typeof cls === 'string' && cls.startsWith('packs/') && !packBlocks.includes(cls)) packBlocks.push(cls);
  return {
    refs, labels, start_paths: e.start_paths,
    class_block: e.class_block !== undefined ? e.class_block : typeof cls === 'string' && cls.startsWith('core-classes.md#') ? cls : null,
    pack_blocks: packBlocks, skipped_blocks: isArr(e.skipped_blocks) ? e.skipped_blocks : [],
  };
}
function unitFromSeed(s) {
  const { deriveId } = require('./check-ledger.cjs');
  if (!isObj(s) || !isObj(s.refs) || !['surface', 'boundary', 'subsystem', 'class'].every((k) => typeof s.refs[k] === 'string')) return { error: 'refs needs string surface, boundary, subsystem and class' };
  const u = {
    id: deriveId(s.refs), refs: s.refs, labels: s.labels, start_paths: s.start_paths, class_block: s.class_block === undefined ? null : s.class_block,
    pack_blocks: s.pack_blocks === undefined ? [] : s.pack_blocks, skipped_blocks: s.skipped_blocks === undefined ? [] : s.skipped_blocks,
    prior: s.prior === undefined ? 'none' : s.prior, wave: 1, status: 'planned', owner: null,
    paths: [], checks: [], fingerprints: [], open: [], history: [],
  };
  if (s.notes !== undefined) u.notes = s.notes;
  return { unit: u };
}
function addUnits(run, opts = {}) {
  return withLock(run, () => {
    load(path.join(run, 'run.json'));
    const ledger = loadLedger(run, false) || [];
    if (!isArr(ledger)) die('ledger.json must be a JSON array');
    const existing = new Set(ledger.map((u) => u.id));
    const lopts = ledgerOpts(run);
    const strict = !opts.fromCritic && !opts.fromQueue; // explicit seeds: any problem aborts the whole call
    let entries; let source; let queueLines = null;
    if (opts.fromCritic) {
      const rec = criticRecords(run).find((c) => c.critic === opts.fromCritic);
      if (!rec) die(`no stored critic record for ${opts.fromCritic}`);
      entries = (isObj(rec.reply) && isArr(rec.reply.missing_units) ? rec.reply.missing_units : []).map(seedFromFlat);
      source = `critic ${opts.fromCritic}`;
    } else if (opts.fromQueue) {
      const qf = path.join(run, 'queue', 'uncovered.jsonl');
      queueLines = fs.existsSync(qf) ? readRegular(qf, LEDGER_LIMITS.maxBytes).split('\n').filter((l) => l.trim()) : [];
      entries = queueLines.map((l) => { try { return seedFromFlat(JSON.parse(l)); } catch { return null; } });
      source = 'queue/uncovered.jsonl';
    } else {
      let text;
      if (opts.file) text = readRegular(path.resolve(opts.file), LEDGER_LIMITS.maxBytes);
      else { try { text = fs.readFileSync(0, 'utf8'); } catch { die('add-units: no file given and stdin is not readable'); } }
      let data;
      try { data = JSON.parse(text.replace(/^﻿/, '')); } catch (e) { die(`add-units: invalid JSON: ${e.message}`); }
      if (!isArr(data)) die('add-units: input must be a JSON array of unit seeds');
      entries = data;
      source = opts.file ? path.basename(opts.file) : 'stdin';
    }
    const added = []; const failed = []; const takenIdx = new Set();
    const ids = new Set(existing);
    entries.forEach((e, i) => {
      const { unit: u, error } = e ? unitFromSeed(e) : { error: 'not a usable entry' };
      if (error) { failed.push(`[${i}] ${error}`); return; }
      if (ids.has(u.id)) { failed.push(`[${i}] ${u.id}: ${existing.has(u.id) ? 'already in the ledger' : 'duplicate in this input'}`); return; }
      const rep = new Reporter();
      validateLedger([u], rep, lopts);
      if (rep.errors.length) { failed.push(`[${i}] ${u.id}: ${rep.errors.slice(0, 2).join('; ')}`); return; }
      ids.add(u.id); added.push(u); takenIdx.add(i);
    });
    if (strict && failed.length) die(`add-units: nothing written; ${failed.length} problem(s):\n  ${failed.join('\n  ')}`);
    if (added.length) {
      const all = [...ledger, ...added].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      saveLedger(run, all); // whole-ledger validation; aborts with nothing written
      if (queueLines) writeAtomic(path.join(run, 'queue', 'uncovered.jsonl'), queueLines.filter((_, i) => !takenIdx.has(i)).map((l) => l + '\n').join(''));
    }
    journal(run, { cmd: 'add-units', source, added: added.length, not_converted: failed.length });
    return [`add-units from ${source}: ${added.length} unit(s) added as planned, ${failed.length} not converted`,
      ...added.slice(0, 50).map((u) => `  + ${u.id}`), ...(added.length > 50 ? [`  ... ${added.length - 50} more`] : []),
      ...failed.slice(0, 50).map((f) => `  - ${f}`)].join('\n');
  });
}

// ---------- file hashes (hashes.json) ----------
// RUN_DIR/hashes.json records, for every file a worked unit cites, the state of the target when the unit was
// ingested (or carried), so a later run can tell whether the unit's code changed:
//   { "skill_version": "0.4.0",
//     "files":  { "<rel file>": "<sha256 of bytes>" | null },     anchors, paths, start_paths, boundary file
//     "trees":  { "<rel dir>": "<digest>" | null },                 directories cited in paths/start_paths (recursive)
//     "dirs":   { "<rel dir or .>": "<digest>" | null },            parent directory of each file start_path (direct files)
//     "blocks": { "<FILE#Block>": "<sha256 of block text>" | null } class_block, refs.class, pack_blocks }
// A digest is sha256 over sorted "relpath<TAB>sha256" lines of regular files; symlinks are never followed;
// dependency/VCS/build directories are skipped; null = unreadable or more than HASH_TREE_MAX files.
const HASH_TREE_MAX = 5000;
const HASH_SKIP = new Set(['node_modules', '.git', '.hg', '.svn', 'vendor', 'dist', 'build', '.next', '.venv', 'venv', '__pycache__', 'target', 'coverage', '.boring-security']);
function skillVersion() {
  try { const m = /^\s*version:\s*"?([^"\n]+?)"?\s*$/m.exec(fs.readFileSync(path.join(briefLib.SKILL_DIR, 'SKILL.md'), 'utf8')); return m ? m[1] : null; } catch { return null; }
}
function makeHasher(target) {
  let root = null;
  try { root = fs.realpathSync(path.resolve(target)); } catch { root = null; }
  const cache = new Map();
  const resolve = (rel) => {
    if (!root) return null;
    if (rel === '.') return root;
    if (!isRelPath(rel)) return null;
    const full = path.join(root, ...rel.split('/'));
    try {
      const real = fs.realpathSync(full);
      const inside = path.relative(root, real);
      if (inside.startsWith('..') || path.isAbsolute(inside)) return null;
      return full;
    } catch { return null; }
  };
  const memo = (k, fn) => { if (!cache.has(k)) cache.set(k, fn()); return cache.get(k); };
  const kind = (rel) => memo(`k:${rel}`, () => { const f = resolve(rel); if (!f) return null; try { const st = fs.lstatSync(f); return st.isFile() ? 'file' : st.isDirectory() ? 'dir' : null; } catch { return null; } });
  const file = (rel) => memo(`f:${rel}`, () => { const f = kind(rel) === 'file' ? resolve(rel) : null; if (!f) return null; try { return sha256(fs.readFileSync(f)); } catch { return null; } });
  const digest = (rel, recursive) => memo(`${recursive ? 't' : 'd'}:${rel}`, () => {
    const base = resolve(rel);
    if (!base) return null;
    const lines = [];
    let ok = true;
    (function walk(dir, prefix) {
      let ents;
      try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { ok = false; return; }
      for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
        if (!ok) return;
        const r = prefix ? `${prefix}/${e.name}` : e.name;
        if (e.isSymbolicLink()) continue;
        if (e.isDirectory()) { if (recursive && !HASH_SKIP.has(e.name)) walk(path.join(dir, e.name), r); continue; }
        if (!e.isFile()) continue;
        if (lines.length >= HASH_TREE_MAX) { ok = false; return; }
        try { lines.push(`${r}\t${sha256(fs.readFileSync(path.join(dir, e.name)))}`); } catch { ok = false; }
      }
    })(base, '');
    return ok ? sha256(lines.join('\n')) : null;
  });
  return { root, kind, file, digest };
}
const posixDir = (rel) => { const i = rel.lastIndexOf('/'); return i === -1 ? '.' : rel.slice(0, i); };
// The hash keys a unit's live state depends on.
function unitHashKeys(u, h) {
  const files = new Set(); const trees = new Set(); const dirs = new Set(); const blocks = new Set();
  const addPath = (p) => { if (typeof p !== 'string') return; if (h.kind(p) === 'dir') trees.add(p); else files.add(p); };
  for (const p of isArr(u.start_paths) ? u.start_paths : []) {
    addPath(p);
    if (typeof p === 'string') { if (h.kind(p) === 'dir') trees.add(p); else dirs.add(posixDir(p)); }
  }
  for (const p of isArr(u.paths) ? u.paths : []) addPath(p);
  for (const c of isArr(u.checks) ? u.checks : []) {
    if (!isObj(c)) continue;
    for (const p of isArr(c.paths) ? c.paths : []) addPath(p);
    for (const a of isArr(c.anchors) ? c.anchors : []) if (isObj(a) && typeof a.file === 'string') files.add(a.file);
  }
  const boundary = isObj(u.refs) && typeof u.refs.boundary === 'string' ? u.refs.boundary.split('#')[0] : null;
  if (boundary && isRelPath(boundary)) addPath(boundary);
  for (const b of [u.class_block, isObj(u.refs) ? u.refs.class : null, ...(isArr(u.pack_blocks) ? u.pack_blocks : [])]) if (typeof b === 'string') blocks.add(b);
  return { files, trees, dirs, blocks, boundary };
}
const blockHash = (ref) => { try { return sha256(briefLib.extractBlock(ref)); } catch { return null; } };
function recordHashes(run, target, units) {
  if (!target || !units.length) return;
  const h = makeHasher(target);
  const f = path.join(run, 'hashes.json');
  const cur = tryLoad(f, LEDGER_LIMITS);
  const out = isObj(cur) ? cur : {};
  for (const k of ['files', 'trees', 'dirs', 'blocks']) if (!isObj(out[k])) out[k] = {};
  out.skill_version = skillVersion();
  for (const u of units) {
    const k = unitHashKeys(u, h);
    for (const p of k.files) out.files[p] = h.file(p);
    for (const p of k.trees) out.trees[p] = h.digest(p, true);
    for (const p of k.dirs) out.dirs[p] = h.digest(p, false);
    for (const b of k.blocks) out.blocks[b] = blockHash(b);
  }
  writeJson(f, out);
}

// ---------- carry (incremental re-audit) ----------
const CARRY_MAX_CHAIN = 2;
const STRONG_PRIORS = new Set(['confirmed_same', 'confirmed_changed', 'nv', 'rejected_changed']);
// Why a prior unit's code is not provably unchanged (null = unchanged). Order = reporting category.
function carryChange(pu, prior, h) {
  const k = unitHashKeys(pu, h);
  const ph = prior.hashes;
  if (!ph) return 'prior run has no hashes.json';
  const cmp = (map, key, now) => {
    if (!isObj(ph[map]) || !Object.prototype.hasOwnProperty.call(ph[map], key) || ph[map][key] === null) return 'not hashed in the prior run';
    return ph[map][key] === now ? null : 'changed';
  };
  if (k.boundary && isRelPath(k.boundary)) {
    const map = h.kind(k.boundary) === 'dir' ? 'trees' : 'files';
    const r = cmp(map, k.boundary, map === 'trees' ? h.digest(k.boundary, true) : h.file(k.boundary));
    if (r) return r === 'changed' ? 'boundary file changed' : r;
  }
  for (const p of k.files) { const r = cmp('files', p, h.file(p)); if (r) return r === 'changed' ? 'cited file changed' : r; }
  for (const p of k.trees) { const r = cmp('trees', p, h.digest(p, true)); if (r) return r === 'changed' ? 'cited directory changed' : r; }
  for (const p of k.dirs) { const r = cmp('dirs', p, h.digest(p, false)); if (r) return r === 'changed' ? 'file changed in a start_path directory' : r; }
  return null;
}
function carryBlocked(pu, prior, h) {
  if (pu.checks.some((c) => !isObj(c) || c.method !== 'source')) return 'local evidence is not portable';
  if (!pu.checks.some((c) => isArr(c.anchors) && c.anchors.length)) return 'no anchors';
  for (const c of pu.checks) for (const a of isArr(c.anchors) ? c.anchors : []) {
    const ls = h.kind(a.file) === 'file' ? (() => { try { return fs.readFileSync(path.join(h.root, ...a.file.split('/')), 'utf8').split(/\r?\n/); } catch { return null; } })() : null;
    if (!ls || !quoteMatches(ls, a.line, a.quote).ok) return 'anchor quote no longer matches';
  }
  const ph = prior.hashes;
  if (!ph.skill_version || ph.skill_version !== skillVersion()) return 'skill version changed';
  for (const b of unitHashKeys(pu, h).blocks) {
    const was = isObj(ph.blocks) ? ph.blocks[b] : undefined;
    if (!was || was !== blockHash(b)) return 'class block text changed';
  }
  if (pu.status === 'carried' && (!isObj(pu.carried_from) || pu.carried_from.chain >= CARRY_MAX_CHAIN)) return `already carried ${CARRY_MAX_CHAIN} runs in a row (re-hunt)`;
  return null;
}
function priorValue(pu, changed, verdicts) {
  switch (pu.status) {
    case 'covered': case 'carried': return changed ? 'covered_changed' : 'covered_same';
    case 'candidate': {
      const v = (isArr(pu.fingerprints) ? pu.fingerprints : []).map((fp) => verdicts.get(fp));
      if (v.includes('confirmed')) return changed ? 'confirmed_changed' : 'confirmed_same';
      if (v.includes('needs_validation')) return 'nv';
      return changed ? 'rejected_changed' : 'none';
    }
    case 'blocked': return 'blocked';
    case 'deferred': return 'deferred';
    case 'out_of_scope': return 'out_of_scope';
    default: return 'none';
  }
}
function carry(run, priorDir) {
  return withLock(run, () => {
    if (!priorDir) die('carry needs --from <prior run dir>');
    const r = load(path.join(run, 'run.json'));
    const target = targetOf(run);
    if (!target) die('run.json.target must be an existing directory');
    const pdir = path.resolve(priorDir);
    if (pdir === path.resolve(run)) die('--from must be a different run directory');
    const pr = load(path.join(pdir, 'run.json'));
    if (!isObj(pr) || pr.repo !== r.repo) die(`prior run is for repo ${JSON.stringify(isObj(pr) ? pr.repo : null)}, this run is ${JSON.stringify(r.repo)}`);
    if (pr.status !== 'complete') die(`prior run status is ${pr.status}; only a complete run can be carried from`);
    if (pr.profile === 'quick') die('a quick prior run cannot be carried from');
    const pl = load(path.join(pdir, 'ledger.json'), true, LEDGER_LIMITS);
    if (!isArr(pl)) die('prior ledger.json must be an array');
    const ph = tryLoad(path.join(pdir, 'hashes.json'), LEDGER_LIMITS);
    const pf = tryLoad(path.join(pdir, 'findings.json'));
    const verdicts = new Map((isArr(pf) ? pf : []).filter(isObj).map((x) => [x.fingerprint, x.verdict]));
    const prior = { hashes: isObj(ph) ? ph : null };
    const ledger = loadLedger(run, false) || [];
    const byId = new Map(ledger.map((u) => [u.id, u]));
    const opts = ledgerOpts(run);
    const h = makeHasher(target);
    const why = new Map(); const note = (k) => why.set(k, (why.get(k) || 0) + 1);
    const carriedUnits = []; let planned = 0;
    for (const pu of pl) {
      if (!isObj(pu) || typeof pu.id !== 'string') { note('malformed prior unit'); continue; }
      if (pu.status === 'not_applicable') { note('prior not_applicable (left to recon)'); continue; }
      const existing = byId.get(pu.id);
      if (existing && existing.status !== 'planned') { note(`already ${existing.status} in this run`); continue; }
      const change = carryChange(pu, prior, h);
      let reason = null;
      if (pu.status === 'covered' || pu.status === 'carried') reason = change || carryBlocked(pu, prior, h);
      else reason = `prior ${pu.status}`;
      const base = existing || {
        id: pu.id, refs: pu.refs, labels: pu.labels, start_paths: pu.start_paths, class_block: pu.class_block, pack_blocks: pu.pack_blocks,
        skipped_blocks: pu.skipped_blocks, history: [],
      };
      const notes = {};
      const pn = isObj(base.notes) ? base.notes : isObj(pu.notes) ? pu.notes : {};
      for (const k of ['priority', 'priority_why']) if (pn[k] !== undefined) notes[k] = pn[k];
      let u = null;
      if (!reason) {
        const chain = pu.status === 'carried' ? pu.carried_from.chain + 1 : 1;
        u = { ...base, prior: 'covered_same', wave: 1, status: 'carried', owner: null, paths: pu.paths, checks: pu.checks, fingerprints: [], open: [], history: [],
          carried_from: { run_id: String(pr.run_id), wave: pu.wave, chain }, notes };
        const one = new Reporter();
        validateLedger([u], one, opts);
        if (one.errors.length) { reason = `carried unit invalid here: ${one.errors[0].replace(/^unit\[0\][^:]*: /, '')}`.slice(0, 120); u = null; }
      }
      if (!u) {
        u = { ...base, prior: priorValue(pu, !!change, verdicts), wave: 1, status: 'planned', owner: null, paths: [], checks: [], fingerprints: [], open: [], history: [], notes };
        delete u.carried_from;
        const one = new Reporter();
        validateLedger([u], one, opts);
        if (one.errors.length) { note(`not added, invalid in this run: ${one.errors[0].replace(/^unit\[0\][^:]*: /, '').slice(0, 80)}`); continue; }
        note(reason.startsWith('not hashed') || reason.startsWith('prior run has no') ? reason : reason);
        planned++;
      } else carriedUnits.push(u);
      byId.set(u.id, u);
    }
    const all = [...byId.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    saveLedger(run, all);
    recordHashes(run, target, carriedUnits);
    journal(run, { cmd: 'carry', from: pr.run_id, carried: carriedUnits.length, planned });
    return [`carry from ${pr.run_id}: ${carriedUnits.length} unit(s) carried unchanged, ${planned} planned for hunting`,
      ...[...why.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).map(([k, n]) => `  ${n}\t${k}`)].join('\n');
  });
}

// ---------- tiers ----------
// notes.tier = "high" | "standard" (profile standard only; every other profile, and every unit before
// `tier` runs, is high). Standard-tier units may go to bsec-hunter-lite; everything else to strong hunters.
const HIGH_CORE = new Set(['Access control', 'Injection', 'Crypto and secrets', 'Business logic', 'Wildcard', 'Obvious things']);
const HIGH_PACKS = /^packs\/(app-stack|web-and-identity|ai-agents|supply-chain)\.md#/;
const tierOf = (u, profile) => (profile === 'standard' && isObj(u.notes) && u.notes.tier === 'standard' ? 'standard' : 'high');
function tierReasons(u, ctx) {
  const why = [];
  const refsFile = isObj(u.refs) && typeof u.refs.surface === 'string' ? u.refs.surface.split('#')[0] : null;
  const mine = [...(isArr(u.start_paths) ? u.start_paths : []), ...(isArr(u.paths) ? u.paths : []), ...(refsFile ? [refsFile] : [])];
  for (const s of ctx.surfaces) {
    if (!under(s.file, mine)) continue;
    if (s.auth_hint === false) { why.push(`inventory: ${s.kind} without auth hint`); break; }
    if (s.rls === false) { why.push('inventory: table without RLS'); break; }
    if (['webhook', 'edge-function', 'server-action'].includes(s.kind)) { why.push(`inventory: ${s.kind}`); break; }
    if (s.kind === 'ci-workflow' && /\[RISKY\]/.test(String(s.label))) { why.push('inventory: CI workflow with risky trigger'); break; }
  }
  if (ctx.hits.some((x) => (x.confidence === 'high' || x.confidence === 'medium') && under(x.file, isArr(u.start_paths) ? u.start_paths : []))) why.push('detector lead (confidence >= medium) under start paths');
  for (const c of [isObj(u.refs) ? u.refs.class : null, u.class_block]) {
    if (typeof c !== 'string') continue;
    const [file, name] = [c.slice(0, c.indexOf('#')), c.slice(c.indexOf('#') + 1)];
    if (file === 'core-classes.md' && HIGH_CORE.has(name)) { why.push(`class ${name}`); break; }
    if (HIGH_PACKS.test(c)) { why.push(`pack class ${c}`); break; }
  }
  if (STRONG_PRIORS.has(u.prior)) why.push(`prior ${u.prior}`);
  if (isObj(u.notes) && Number.isFinite(u.notes.priority) && u.notes.priority <= 2) why.push(`priority ${u.notes.priority}`);
  return why;
}
function tier(run) {
  return withLock(run, () => {
    const r = runInfo(run);
    const ledger = loadLedger(run);
    const inv = tryLoad(path.join(run, 'inventory.json'), LEDGER_LIMITS);
    const det = tryLoad(path.join(run, 'detector.json'), LEDGER_LIMITS);
    const ctx = {
      surfaces: isObj(inv) && isArr(inv.surfaces) ? inv.surfaces.filter((s) => isObj(s) && typeof s.file === 'string') : [],
      hits: isObj(det) && isArr(det.hits) ? det.hits.filter((x) => isObj(x) && typeof x.file === 'string') : [],
    };
    const n = { high: 0, standard: 0, locked: 0 };
    for (const u of ledger) {
      const notes = isObj(u.notes) ? { ...u.notes } : {};
      if (notes.tier_lock === true) { notes.tier = 'high'; n.locked++; n.high++; u.notes = notes; continue; }
      if (r.profile !== 'standard') { notes.tier = 'high'; notes.tier_why = `${r.profile} profile: every unit is high`; }
      else {
        const why = tierReasons(u, ctx);
        notes.tier = why.length ? 'high' : 'standard';
        notes.tier_why = why.length ? why.join('; ') : 'no high-risk signal';
      }
      n[notes.tier]++;
      u.notes = notes;
    }
    saveLedger(run, ledger);
    journal(run, { cmd: 'tier', high: n.high, standard: n.standard });
    return `tier (${r.profile}): ${n.high} high${n.locked ? ` (${n.locked} locked high after a failed lite recheck)` : ''}, ${n.standard} standard${r.profile === 'standard' ? '' : ' (tiering applies only to the standard profile)'}`;
  });
}

// ---------- next --batch ----------
function nextBatch(run, maxUnits, maxBytes) {
  if (!(Number.isInteger(maxUnits) && maxUnits >= 1)) die('--max-units must be an integer >= 1');
  if (!(Number.isInteger(maxBytes) && maxBytes >= 1)) die('--max-bytes must be an integer >= 1');
  const ledger = loadLedger(run);
  const profile = runInfo(run).profile;
  const t = targetOf(run);
  const sizes = new Map();
  const sizeOf = (rel) => {
    if (sizes.has(rel)) return sizes.get(rel);
    let total = 0; let count = 0;
    if (t && isRelPath(rel)) {
      (function walk(full) {
        let st;
        try { st = fs.lstatSync(full); } catch { return; }
        if (st.isFile()) { total += st.size; return; }
        if (!st.isDirectory() || count > 20000) return;
        let ents = [];
        try { ents = fs.readdirSync(full); } catch { return; }
        for (const e of ents) { if (HASH_SKIP.has(e)) continue; count++; walk(path.join(full, e)); }
      })(path.join(t, ...rel.split('/')));
    }
    sizes.set(rel, total);
    return total;
  };
  const bytesOf = (units) => [...new Set(units.flatMap((u) => u.start_paths))].reduce((s, p) => s + sizeOf(p), 0);
  const dirsOf = (u) => new Set(u.start_paths.map((p) => (t && fs.existsSync(path.join(t, ...p.split('/'))) && fs.statSync(path.join(t, ...p.split('/'))).isDirectory() ? p : posixDir(p))));
  const rank = (u) => (isObj(u.notes) && Number.isFinite(u.notes.priority) ? u.notes.priority : 99);
  const planned = ledger.filter((u) => u.status === 'planned').sort((a, b) => rank(a) - rank(b) || (a.id < b.id ? -1 : 1));
  const used = new Set(); const lines = [];
  for (const u of planned) {
    if (used.has(u.id)) continue;
    used.add(u.id);
    const g = [u];
    const key = `${tierOf(u, profile)}\u0000${u.refs.subsystem}`;
    const files = new Set(u.start_paths); const dirs = dirsOf(u);
    for (const v of planned) {
      if (g.length >= maxUnits) break;
      if (used.has(v.id) || `${tierOf(v, profile)}\u0000${v.refs.subsystem}` !== key) continue;
      const vd = dirsOf(v);
      if (!v.start_paths.some((p) => files.has(p)) && ![...vd].some((d) => dirs.has(d))) continue;
      if (bytesOf([...g, v]) > maxBytes) continue;
      g.push(v); used.add(v.id);
      for (const p of v.start_paths) files.add(p);
      for (const d of vd) dirs.add(d);
    }
    const tr = tierOf(u, profile);
    lines.push(`${g.map((x) => x.id).join(' ')}  # tier=${tr} (${tr === 'standard' ? 'bsec-hunter-lite' : 'strong hunter'}) subsystem=${briefLib.sanitize(u.refs.subsystem).replace(/\s+/g, '_')} units=${g.length} bytes=${bytesOf(g)}`);
  }
  return lines.join('\n');
}

// ---------- recheck ----------
// Sample size rule: max(min, ceil(rate x covered)), capped at the number of covered units.
const recheckRule = (rate, min, covered) => Math.min(covered, Math.max(min, Math.ceil(rate * covered)));
const coveredSetHash = (ledger) => sha256(ledger.filter((u) => isObj(u) && SAMPLEABLE.has(u.status)).map((u) => `${u.id}:${u.wave}:${u.status}:${isLiteCovered(u) ? 'lite' : ''}`).sort().join('\n'));
function sampleRecheck(run, rateArg, minArg, redraw = false) {
  return withLock(run, () => {
    const old = tryLoad(planFile(run));
    if (old !== undefined && !redraw) die('recheck/plan.json already exists; the sample is fixed once drawn (use --redraw only after the covered set changed)');
    if (old === undefined && redraw) die('no recheck/plan.json to redraw; run sample-recheck without --redraw');
    const rate = rateArg !== undefined ? rateArg : isObj(old) && Number.isFinite(old.rate) ? old.rate : 0.1;
    const min = minArg !== undefined ? minArg : isObj(old) && Number.isInteger(old.min) ? old.min : 3;
    if (!(Number.isFinite(rate) && rate > 0 && rate <= 1)) die('--rate must be a number in (0, 1]');
    if (!(Number.isInteger(min) && min >= 0)) die('--min must be an integer >= 0');
    const r = runInfo(run);
    if (typeof r.run_id !== 'string') die('run.json needs a run_id');
    const ledger = loadLedger(run);
    const open = ledger.filter((u) => u.status === 'planned' || u.status === 'in_progress').length;
    if (open) die(`${open} unit(s) are still planned or in_progress; draw the recheck sample after hunting has finished`);
    const covered = ledger.filter((u) => SAMPLEABLE.has(u.status));
    if (!covered.length) die('no covered or carried units to sample (complete needs no recheck plan while none exists)');
    const ch = coveredSetHash(ledger);
    if (isObj(old) && old.covered_hash === ch) die('the covered set has not changed since the plan was drawn; nothing to redraw');
    const rankBy = (units, salt) => units.map((u) => ({ u, h: sha256(r.run_id + salt + u.id) })).sort((a, b) => (a.h < b.h ? -1 : a.h > b.h ? 1 : a.u.id < b.u.id ? -1 : 1)).map((x) => x.u);
    // Stratified: the lite stratum (units covered by lite hunters, re-hunted by strong agents) is drawn first and
    // separately; the normal sample is drawn from the remaining reviewed units.
    const liteUnits = covered.filter(isLiteCovered);
    const liteSample = rankBy(liteUnits, ':lite:').slice(0, liteRule(liteUnits.length));
    const inLite = new Set(liteSample.map((u) => u.id));
    const nNormal = Math.min(recheckRule(rate, min, covered.length), covered.length - liteSample.length);
    const normal = rankBy(covered.filter((u) => !inLite.has(u.id)), '').slice(0, nNormal);
    const n = normal.length + liteSample.length;
    const entry = (stratum) => (u) => ({ id: u.id, wave: u.wave, owner: u.owner, status: u.status, stratum });
    const plan = { run_id: r.run_id, rate, min, covered: covered.length, covered_hash: ch, at: now(), ...(isObj(old) ? { redraw_of: old.at || null } : {}),
      units: [...normal.map(entry('normal')), ...liteSample.map(entry('lite'))] };
    fs.mkdirSync(path.join(run, 'recheck'), { recursive: true });
    unseal(run);
    writeJson(planFile(run), plan);
    journal(run, { cmd: 'sample-recheck', sampled: n, covered: covered.length, redraw: !!old });
    const kept = isObj(old) ? recheckState(run, ledger) : null;
    return `recheck sample${old ? ' (redrawn)' : ''}: ${n} of ${covered.length} reviewed unit(s)${liteSample.length ? ` (${liteSample.length} in the lite stratum: give those to strong agents)` : ''} → recheck/plan.json${kept ? `; ${kept.recorded} already recorded` : ''}\n${plan.units.map((p) => `  ${p.id}`).join('\n')}`;
  });
}

function recheckResult(run, agent, replyPath) {
  if (!isAgentId(agent)) die(`bad agent id ${JSON.stringify(String(agent))}`);
  return withLock(run, () => {
    const plan = tryLoad(planFile(run));
    if (!isObj(plan) || !isArr(plan.units)) die('no recheck/plan.json; run sample-recheck first');
    const resFile = path.join(run, 'recheck', 'results', `${agent}.json`);
    if (fs.existsSync(resFile)) die(`${agent} already recorded a recheck; use a fresh id`);
    const d = load(replyPath ? path.resolve(replyPath) : outResult(run, agent));
    const entries = isArr(d) ? d : isObj(d) && isArr(d.units) ? d.units : null;
    if (!entries) die('recheck reply must be {"units": [{"id", "agree", "why", "anchors"?}]}');
    const ledger = loadLedger(run);
    const byId = new Map(ledger.map((u) => [u.id, u]));
    const inPlan = new Map(plan.units.filter(isObj).map((p) => [p.id, p]));
    const rc = recheckState(run, ledger);
    const t = targetOf(run);
    const reader = t ? makeTargetReader(t) : null;
    const accepted = []; const problems = []; const seen = new Set();
    for (const e of entries) {
      const id = isObj(e) && typeof e.id === 'string' ? e.id : null;
      if (!id || !inPlan.has(id)) { problems.push(`ignored entry ${id || '?'}: not in the recheck plan`); continue; }
      if (seen.has(id) || rc.recordedMap.has(id)) { problems.push(`${id}: already recorded`); continue; }
      seen.add(id);
      const u = byId.get(id);
      if (u && unitPeople(u).has(agent)) { problems.push(`${id}: ${agent} owns or has a check on this unit and cannot re-check it`); continue; }
      if (typeof e.agree !== 'boolean') { problems.push(`${id}: agree must be true or false`); continue; }
      if (!isVisible(e.why)) { problems.push(`${id}: why must be visible text`); continue; }
      if (e.anchors !== undefined) {
        const rep = new Reporter();
        checkAnchors(e.anchors, `${id}.anchors`, rep);
        if (!rep.errors.length && reader) for (const a of e.anchors) {
          const ls = reader.kind(a.file) === 'file' ? reader.lines(a.file) : null;
          const m = ls ? quoteMatches(ls, a.line, a.quote) : { ok: false, why: 'file not found in the target' };
          if (!m.ok) rep.err(`${id}.anchors`, `${a.file}:${a.line}: ${m.why}`);
        }
        if (rep.errors.length) { problems.push(`${id}: ${rep.errors[0]}`); continue; }
      }
      accepted.push({ id, wave: inPlan.get(id).wave, agree: e.agree, why: e.why, ...(e.anchors !== undefined ? { anchors: e.anchors } : {}) });
    }
    if (!accepted.length) die(`nothing recorded:\n  ${problems.join('\n  ') || 'no entries'}`);
    fs.mkdirSync(path.dirname(resFile), { recursive: true });
    unseal(run);
    writeJson(resFile, { agent, at: now(), results: accepted });
    markApplied(run, agent, 'recheck-result');
    const dis = accepted.filter((x) => !x.agree);
    journal(run, { cmd: 'recheck-result', agent, recorded: accepted.length, disagreements: dis.length });
    const out = [`recheck ${agent}: ${accepted.length} recorded, ${dis.length} disagreement(s)`];
    for (const x of dis) {
      out.push(`DISAGREE ${x.id}: the ledger is unchanged. Reopen it for a fresh Hunter (history rules, phases/1-recon.md):`);
      out.push(`  run-state.cjs reopen <run> ${x.id} --reason "recheck by ${agent} disagrees (recheck/results/${agent}.json)"`);
    }
    if (problems.length) out.push(...problems.map((p) => `  ${p}`));
    return out.join('\n');
  });
}

// ---------- complete / incomplete ----------
function complete(run) {
  return withLock(run, () => {
    const r = load(path.join(run, 'run.json'));
    if (!isObj(r)) die('run.json must be an object');
    const profile = r.profile;
    const strict = profile === 'standard' || profile === 'deep';
    const unmet = []; const warnings = [];
    const ledger = loadLedger(run);
    // (a)
    const rep = new Reporter();
    validateLedger(ledger, rep, ledgerOpts(run));
    if (rep.errors.length) unmet.push(`(a) ledger invalid: ${rep.errors.slice(0, 5).join('; ')}${rep.errors.length > 5 ? ` (+${rep.errors.length - 5} more)` : ''}`);
    const open = ledger.filter((u) => u.status === 'planned' || u.status === 'in_progress');
    if (open.length) unmet.push(`(a) ${open.length} unit(s) still planned or in_progress`);
    // (b)
    const live = [...liveFps(ledger)].sort();
    const undecided = live.filter((fp) => !fs.existsSync(decFile(run, fp)));
    if (undecided.length) unmet.push(`(b) ${undecided.length} live fingerprint(s) without a decision: ${undecided.slice(0, 5).join(', ')}`);
    // (c)
    if (strict) {
      const unverified = [...decisionsMap(run).entries()].filter(([fp, d]) => d.decision !== 'rejected' && !isVerified(provenance(run, ledger, fp))).map(([fp]) => fp);
      if (unverified.length) unmet.push(`(c) ${unverified.length} confirmed/needs_validation record(s) without a verification of the current record: ${unverified.slice(0, 5).join(', ')}`);
    }
    // (d)
    const cs = criticState(run, ledger, profile);
    if (!cs.ok) unmet.push(strict ? '(d) the two most recent critic records must both be clean, by different critics, at the current coverage hash' : '(d) quick needs at least one critic record');
    // (e)
    const inv = inventoryGaps(run, ledger);
    if (!inv.present) (strict ? unmet : warnings).push('(e) inventory.json is not present (inventory.cjs --json RUN_DIR/inventory.json)');
    else {
      if (inv.errors.length) unmet.push(`(e) inventory: ${inv.errors.slice(0, 3).join('; ')}`);
      if (inv.gaps.length) unmet.push(`(e) ${inv.gaps.length} inventory surface(s) not referenced by any unit and not waived (inventory-gaps)`);
    }
    // (f)
    const rc = recheckState(run, ledger);
    for (const x of recheckNeeds(ledger, rc, profile)) unmet.push(`(f) ${x.text}`);
    // (g)
    const ff = path.join(run, 'findings.json');
    if (!fs.existsSync(ff)) unmet.push('(g) findings.json does not exist (assemble)');
    else {
      const { records, rep: frep } = buildFindings(run);
      if (frep.errors.length) unmet.push(`(g) assemble would fail: ${frep.errors.slice(0, 3).join('; ')}`);
      const cur = tryLoad(ff);
      if (cur === undefined || canonicalJson(cur) !== canonicalJson(records)) unmet.push('(g) findings.json differs from what assemble would write now (assemble)');
    }
    const warn = warnings.length ? `\nwarnings:\n  ${warnings.join('\n  ')}` : '';
    if (unmet.length) die(`not complete; unmet conditions:\n  ${unmet.join('\n  ')}${warn}`);
    const upd = { ...r, status: 'complete', incomplete_reason: null };
    writeJson(path.join(run, 'run.json'), upd);
    journal(run, { cmd: 'complete', coverage_hash: cs.hash });
    return `run.json: status complete${warn}`;
  });
}

function incomplete(run, reason) {
  return withLock(run, () => {
    const r = load(path.join(run, 'run.json'));
    if (!isObj(r)) die('run.json must be an object');
    const upd = { ...r, status: 'incomplete', incomplete_reason: reason === undefined ? null : reason };
    const rep = new Reporter();
    checkRun(upd, rep);
    const bad = rep.errors.filter((e) => /incomplete_reason/.test(e));
    if (bad.length || typeof reason !== 'string') die(bad.join('; ') || 'usage: incomplete <run> <reason>');
    writeJson(path.join(run, 'run.json'), upd);
    journal(run, { cmd: 'incomplete', reason });
    return `run.json: status incomplete (${reason})`;
  });
}

// ---------- brief ----------
function makeBrief(run, agent, role, opts = {}) {
  if (!isAgentId(agent)) die(`bad agent id ${JSON.stringify(String(agent))}`);
  if (!briefLib.ROLES.includes(role)) die(`--role must be one of ${briefLib.ROLES.join('|')}`);
  if (opts.priorFile && role !== 'skeptic') die('--prior-file is only for skeptic briefs');
  if (opts.noteUntrusted && !opts.noteFile) die('--note-untrusted needs --note-file');
  return withLock(run, () => {
    load(path.join(run, 'run.json'));
    const dir = agentDir(run, agent);
    const meta = tryLoad(path.join(dir, 'brief.json'));
    if (isObj(meta) && meta.role !== role) die(`agent ${agent} already has a ${meta.role} brief; use a fresh id`);
    const hasAssign = fs.existsSync(path.join(dir, 'assignment.json'));
    if (role === 'hunter' && !hasAssign) die(`${agent} has no assignment; run assign first`);
    if (role !== 'hunter' && hasAssign) die(`${agent} is a hunter (it has an assignment); use a fresh id for a ${role}`);
    if (role !== 'hunter' && !isObj(meta) && fs.existsSync(dir)) die(`agent ${agent} already exists; use a fresh id`);
    const scout = role.startsWith('scout-');
    const ledger = scout ? (loadLedger(run, false) || []) : loadLedger(run);
    const archFile = path.join(run, 'architecture.md');
    const ctx = { role, agent, trust: runInfo(run).trust, agentDir: path.resolve(dir), architecture: fs.existsSync(archFile) ? readRegular(archFile, 1024 * 1024) : null };
    const byId = new Map(ledger.map((u) => [u.id, u]));
    const det = tryLoad(path.join(run, 'detector.json'), LEDGER_LIMITS);
    const hits = isObj(det) && isArr(det.hits) ? det.hits.filter((h) => isObj(h) && typeof h.file === 'string') : [];
    const leadView = (h) => ({ rule: h.rule, confidence: h.confidence, file: h.file, line: h.line, snippet: h.snippet, verify: h.verify });
    const record = { role };
    const fpArg = () => {
      const fp = opts.fingerprint;
      if (typeof fp !== 'string' || !FINGERPRINT.test(fp)) die(`--role ${role} needs --fingerprint <fp>`);
      if (!liveFps(ledger).has(fp)) die(`${fp} is not a live fingerprint of any ledger unit`);
      record.fingerprint = fp; ctx.fingerprint = fp;
      return fp;
    };
    if (role === 'hunter') {
      const ids = [...new Set(load(path.join(dir, 'assignment.json')).units)].sort();
      if (opts.units && opts.units.length && [...new Set(opts.units)].sort().join('\n') !== ids.join('\n')) die('--units differs from the agent\'s assignment; a hunter brief always uses the assignment');
      ctx.units = ids.map((id) => byId.get(id) || die(`assigned unit ${id} is not in the ledger`));
      ctx.leads = hits.filter((h) => ctx.units.some((u) => under(h.file, u.start_paths))).map(leadView);
      let excl = [];
      if (opts.excludeFile) {
        const x = load(path.resolve(opts.excludeFile));
        if (!isArr(x)) die('--exclude-file must hold a JSON array of {fingerprint, title, root_cause}');
        excl = x.map((e) => (isObj(e) ? { fingerprint: e.fingerprint, title: e.title, root_cause: e.root_cause } : e));
      }
      ctx.exclusions = excl;
      const mine = new Set(ctx.units.flatMap((u) => u.start_paths));
      ctx.peers = ledger.filter((u) => u.status === 'in_progress' && u.owner !== agent && u.start_paths.some((p) => mine.has(p))).map((u) => u.id);
      record.units = ids;
    } else if (role === 'skeptic') {
      const fp = fpArg();
      const p = provenance(run, ledger, fp);
      const why = independenceProblem(p, agent, fp);
      if (why) die(why);
      if (p.authors.has(agent) || p.verifiers.has(agent)) die(`${agent} already decided or verified ${fp}; use a fresh id`);
      if (!p.cand) die(`no candidate file for ${fp}`);
      const { found_by: _f, carried_by: _c, alternates, ...body } = p.cand;
      ctx.candidate = body;
      ctx.alternates = isArr(alternates) ? alternates.filter(isObj).map((a) => a.candidate) : [];
      const units = ledger.filter((u) => isArr(u.fingerprints) && u.fingerprints.includes(fp));
      ctx.gateUnits = units;
      // Never show another Skeptic's (decision author's) conclusion.
      ctx.checks = units.map((u) => ({ unit: u.id, checks: u.checks.filter((c) => !p.authors.has(c.by)) }));
    } else if (role === 'record-check') {
      const fp = fpArg();
      const p = provenance(run, ledger, fp);
      if (!p.decision) die(`no decision stored for ${fp}`);
      const why = independenceProblem(p, agent, fp);
      if (why) die(why);
      if (p.authors.has(agent) || p.verifiers.has(agent)) die(`${agent} already decided or verified ${fp}; use a fresh id`);
      ctx.decision = p.decision.record;
    } else if (role === 'critic') {
      if (criticRecords(run).some((c) => c.critic === agent)) die(`critic id ${agent} was already used`);
      ctx.ledgerView = ledger.map((u) => ({ id: u.id, status: u.status, class: isObj(u.refs) ? u.refs.class : null, start_paths: u.start_paths, paths: u.paths, checks: isArr(u.checks) ? u.checks.length : 0 }));
      const decisions = decisionsMap(run);
      ctx.fpStates = [...liveFps(ledger)].sort().map((fp) => ({ fingerprint: fp, state: decisions.has(fp) ? decisions.get(fp).decision : 'undecided', units: ledger.filter((u) => u.fingerprints.includes(fp)).length }));
      const inv = inventoryGaps(run, ledger);
      ctx.gaps = inv.present ? inv.gaps.map((s) => ({ id: s.id, kind: s.kind, file: s.file, line: s.line, label: s.label })) : null;
      const allPaths = ledger.flatMap((u) => [...(isArr(u.start_paths) ? u.start_paths : []), ...(isArr(u.paths) ? u.paths : [])]);
      ctx.strayLeads = hits.filter((h) => h.confidence === 'high' && !under(h.file, allPaths)).map(leadView);
    } else if (role === 'recheck') {
      const plan = tryLoad(planFile(run));
      if (!isObj(plan) || !isArr(plan.units)) die('no recheck/plan.json; run sample-recheck first');
      const ids = [...new Set(opts.units || [])].sort();
      if (!ids.length) die('--role recheck needs --units <id>...');
      const inPlan = new Set(plan.units.filter(isObj).map((p) => p.id));
      ctx.units = ids.map((id) => {
        if (!inPlan.has(id)) die(`unit ${id} is not in the recheck plan`);
        const u = byId.get(id) || die(`unit ${id} is not in the ledger`);
        if (unitPeople(u).has(agent)) die(`${agent} owns or has a check on ${id} and cannot re-check it`);
        return u;
      });
      record.units = ids;
    }
    if (opts.noteUntrusted && !opts.noteFile) die('--note-untrusted needs --note-file');
    if (opts.noteFile) {
      ctx.note = { text: readRegular(path.resolve(opts.noteFile), 256 * 1024), untrusted: !!opts.noteUntrusted };
      record.note_sha256 = sha256(ctx.note.text);
    }
    if (opts.priorFile) {
      const fp = ctx.fingerprint;
      if (!ledger.some((u) => u.fingerprints.includes(fp) && CARRIED_PRIORS.has(u.prior))) die(`--prior-file: no carried prior unit (prior confirmed_same|nv) carries ${fp}`);
      const pr = load(path.resolve(opts.priorFile));
      const recs = (isArr(pr) ? pr : [pr]).filter((x) => isObj(x) && x.fingerprint === fp);
      if (!recs.length) die(`--prior-file holds no record with fingerprint ${fp}`);
      ctx.priorRecords = recs;
    }
    let text;
    try { text = briefLib.render(ctx); } catch (e) { die(`brief not written: ${e.message}`); }
    ensureAgentDirs(run, agent);
    const file = path.join(dir, 'brief.md');
    writeAtomic(file, text);
    writeJson(path.join(dir, 'brief.json'), { ...record, sha256: sha256(text) });
    journal(run, { cmd: 'brief', agent, role, ...(record.fingerprint ? { fingerprint: record.fingerprint } : {}), bytes: Buffer.byteLength(text) });
    return path.resolve(file);
  });
}

// ---------- recover ----------
function removePartials(run, out) {
  (function walk(dir, rel) {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        const parts = r.split('/');
        if (parts.length === 3 && parts[0] === 'agents' && parts[2] === 'scratch') continue; // agent-owned
        walk(path.join(dir, e.name), r);
      } else if (e.isFile() && /\.tmp-\d+$/.test(e.name)) {
        fs.unlinkSync(path.join(dir, e.name)); out.push(`removed partial write ${r}`);
      }
    }
  })(run, '');
}
function recover(run) {
  return withLock(run, () => {
    const out = [];
    removePartials(run, out);
    const agentsDir = path.join(run, 'agents');
    const pend = pendingOutputs(run);
    for (const a of pend.hunters) {
      const stored = path.join(agentsDir, a, 'result.json');
      out.push(ingest(run, a, fs.existsSync(stored) ? stored : outResult(run, a)));
    }
    for (const o of pend.others) out.push(`waiting: ${o.role} output from ${o.agent}: run-state.cjs ${ROLE_CMD[o.role]} <run> ${o.agent}`);
    const ledger = loadLedger(run);
    let lost = 0;
    for (const u of ledger) {
      if (u.status !== 'in_progress') continue;
      if (fs.existsSync(path.join(agentsDir, u.owner, 'result.json')) || fs.existsSync(outResult(run, u.owner))) continue;
      Object.assign(u, { status: 'planned', owner: null }); lost++; // the lost agent id is never reused (assign refuses existing dirs)
    }
    if (lost) { saveLedger(run, ledger); out.push(`${lost} unit(s) from lost agents returned to planned`); }
    journal(run, { cmd: 'recover', lost });
    out.push(status(run));
    return out.join('\n');
  });
}

// ---------- CLI ----------
const BOOL_FLAGS = new Set(['--from-queue', '--redraw', '--reopen', '--note-untrusted', '--batch', '--lite-tier', '--strong', '--allow-ref-drift']);
const USAGE = 'usage: run-state.cjs estimate|status|next|carry|tier|merge-runs|add-units|assign|brief|ingest|decide|verify|critic|reopen|set-status|resume|inventory-gaps|sample-recheck|recheck-result|assemble|complete|incomplete|recover ... (see header)';
function parseArgs(a) {
  const pos = []; const flags = {};
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--units') { const v = []; while (i + 1 < a.length && !a[i + 1].startsWith('--')) v.push(a[++i]); flags.units = v; }
    else if (BOOL_FLAGS.has(a[i])) flags[a[i].slice(2)] = true;
    else if (a[i].startsWith('--')) { flags[a[i].slice(2)] = a[i + 1]; i++; }
    else pos.push(a[i]);
  }
  return { pos, flags };
}
function main(argv) {
  const say = (text) => { console.log(text); if (unsealNote) console.log(unsealNote); };
  const [cmd, ...a] = argv.slice(2);
  const { pos, flags } = parseArgs(a);
  const need = (n, u) => { if (pos.length < n) die(`usage: ${u}`); };
  switch (cmd) {
    case 'estimate': {
      const profile = flags.profile || 'deep';
      if (!pos[0] || !EST.unitsPerKloc[profile]) die('usage: estimate <target> [--profile deep|standard|quick] [--price-in $/M --price-out $/M] [--cache-hit 0.85]');
      const e = estimate(path.resolve(pos[0]), profile);
      console.log(`${e.files} files, ${e.loc.toLocaleString('en-US')} non-blank lines (tests and vendored code excluded)`);
      console.log(`${e.profile}: ~${e.units} units → ${e.agents} agents (${e.scouts} scouts, ${e.hunters} hunters, ${e.verifiers} verifiers, ${e.critics} critic calls)`);
      console.log(`tokens processed: ~${human(e.tokens_low)}-${human(e.tokens_high)} input, ~${human(e.output_low)}-${human(e.output_high)} output (rough, ±60%)`);
      const pin = Number(flags['price-in'] ?? NaN); const pout = Number(flags['price-out'] ?? NaN); const hit = Number(flags['cache-hit'] ?? 0.85);
      if (Number.isFinite(pin) && Number.isFinite(pout)) {
        const lo = dollars(e.tokens_low, e.output_low, pin, pout, hit); const hi = dollars(e.tokens_high, e.output_high, pin, pout, hit);
        console.log(`cost at $${pin}/M in, $${pout}/M out: ~$${lo.cached.toFixed(0)}-$${hi.cached.toFixed(0)} with ${Math.round(hit * 100)}% cache hits; ~$${lo.uncached.toFixed(0)}-$${hi.uncached.toFixed(0)} with no caching`);
      }
      if (e.scoped_runs_needed > 1) console.log(`split into ≥ ${e.scoped_runs_needed} scoped runs (10,000-unit ledger cap)`);
      return 0;
    }
    case 'status': need(1, 'status <run>'); say(status(pos[0])); return 0;
    case 'next':
      need(1, 'next <run> [--n 10] | next <run> --batch [--max-units 8] [--max-bytes 400000]');
      say(flags.batch ? nextBatch(pos[0], Number(flags['max-units'] ?? 8), Number(flags['max-bytes'] ?? 400000)) : next(pos[0], Number(flags.n ?? 10))); return 0;
    case 'carry': need(1, 'carry <run> --from <prior run dir>'); say(carry(pos[0], flags.from)); return 0;
    case 'tier': need(1, 'tier <run>'); say(tier(pos[0])); return 0;
    case 'merge-runs': {
      need(3, 'merge-runs <out dir> <run dir> <run dir>... [--allow-ref-drift]');
      const { mergeRuns, MergeError } = require('./merge-runs.cjs');
      try { say(mergeRuns(pos[0], pos.slice(1), { allowRefDrift: !!flags['allow-ref-drift'] })); } catch (e) { if (e instanceof MergeError) die(e.message); throw e; }
      return 0;
    }
    case 'add-units': {
      need(1, 'add-units <run> [seeds.json] | --from-critic <critic-id> | --from-queue');
      if (flags['from-critic'] !== undefined && typeof flags['from-critic'] !== 'string') die('--from-critic needs a critic id');
      if ((flags['from-critic'] || flags['from-queue']) && pos[1]) die('add-units takes either a seeds file, --from-critic or --from-queue');
      if (flags['from-critic'] && flags['from-queue']) die('use one of --from-critic and --from-queue');
      say(addUnits(pos[0], { file: pos[1], fromCritic: flags['from-critic'], fromQueue: !!flags['from-queue'] })); return 0;
    }
    case 'set-status': need(2, 'set-status <run> <unit-id>... --to deferred|out_of_scope|not_applicable --reason <text>'); say(setStatus(pos[0], pos.slice(1), flags.to, flags.reason)); return 0;
    case 'resume': need(1, 'resume <run> [--reopen]'); say(resume(pos[0], !!flags.reopen)); return 0;
    case 'assign': need(2, 'assign <run> <agent-id> <unit-id>... [--strong]'); say(assign(pos[0], pos[1], pos.slice(2), !!flags.strong)); return 0;
    case 'brief': need(2, 'brief <run> <agent-id> --role <role> [--fingerprint <fp>] [--units <id>...] [--exclude-file <json>] [--note-file <path> [--note-untrusted]] [--prior-file <json>]');
      say(makeBrief(pos[0], pos[1], flags.role, { fingerprint: flags.fingerprint, units: flags.units, excludeFile: flags['exclude-file'], noteFile: flags['note-file'], noteUntrusted: !!flags['note-untrusted'], priorFile: flags['prior-file'] })); return 0;
    case 'ingest': need(2, 'ingest <run> <agent-id> [result.json]'); say(ingest(pos[0], pos[1], pos[2])); return 0;
    case 'decide': need(2, 'decide <run> <verifier-id> [decision.json]'); say(decide(pos[0], pos[1], pos[2])); return 0;
    case 'verify': need(2, 'verify <run> <verifier-id> [reply.json]'); say(verify(pos[0], pos[1], pos[2])); return 0;
    case 'critic': need(2, 'critic <run> <critic-id> [reply.json]'); say(critic(pos[0], pos[1], pos[2])); return 0;
    case 'reopen': need(flags['lite-tier'] ? 1 : 2, 'reopen <run> <unit-id> --reason <text> | reopen <run> --lite-tier --reason <text>'); say(reopen(pos[0], pos[1], flags.reason, !!flags['lite-tier'])); return 0;
    case 'inventory-gaps': {
      need(1, 'inventory-gaps <run>');
      const inv = inventoryGaps(pos[0], loadLedger(pos[0]));
      if (!inv.present) { console.log('inventory.json not present (node inventory.cjs <target> --json RUN_DIR/inventory.json)'); return 1; }
      const clip = (s) => briefLib.sanitize(String(s)).replace(/\n/g, ' ').slice(0, 160);
      const lines = [`inventory: ${inv.total} surfaces, ${inv.gaps.length} gap(s), ${inv.waived} waived${inv.errors.length ? `, ${inv.errors.length} waiver error(s)` : ''}`];
      for (const g of inv.gaps.slice(0, 50)) lines.push(`  ${clip(g.file)}:${g.line}  ${clip(g.id)}`);
      if (inv.gaps.length > 50) lines.push(`  ... ${inv.gaps.length - 50} more`);
      for (const e of inv.errors) lines.push(`  error: ${e}`);
      console.log(lines.join('\n'));
      return inv.gaps.length || inv.errors.length ? 1 : 0;
    }
    case 'sample-recheck': need(1, 'sample-recheck <run> [--rate 0.1] [--min 3] [--redraw]'); say(sampleRecheck(pos[0], flags.rate === undefined ? undefined : Number(flags.rate), flags.min === undefined ? undefined : Number(flags.min), !!flags.redraw)); return 0;
    case 'recheck-result': need(2, 'recheck-result <run> <agent-id> [reply.json]'); say(recheckResult(pos[0], pos[1], pos[2])); return 0;
    case 'assemble': need(1, 'assemble <run>'); say(assemble(pos[0])); return 0;
    case 'complete': need(1, 'complete <run>'); say(complete(pos[0])); return 0;
    case 'incomplete': need(2, 'incomplete <run> <reason>'); say(incomplete(pos[0], pos[1])); return 0;
    case 'recover': need(1, 'recover <run>'); say(recover(pos[0])); return 0;
    default:
      console.error(USAGE);
      return 2;
  }
}

if (require.main === module) process.exitCode = main(process.argv);
module.exports = {
  carry, tier, nextBatch, recordHashes, makeHasher, setStatus, resume, estimate, dollars, status, next, addUnits, assign, ingest, decide, verify, critic, reopen, inventoryGaps, sampleRecheck, recheckResult,
  assemble, complete, incomplete, makeBrief, recover, writeAtomic, coverageHash, EST, LOCK,
};
