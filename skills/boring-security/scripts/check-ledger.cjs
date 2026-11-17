#!/usr/bin/env node
'use strict';
// Validate a boring-security coverage ledger. Zero dependencies.
// Usage: node check-ledger.cjs <ledger.json> [--run-dir <dir>] [--target <repo>] [--no-evidence-files] [--no-block-check]
//   --run-dir            where agents/<id>/evidence/ and run.json live (default: the ledger's directory)
//   --target <repo>      verify against the target checkout: every check anchor quote (lib.quoteMatches rule)
//                        and every start_paths / paths / check paths entry exists as a file or directory
//                        inside the target (symlinks leading outside are refused)
//   --no-evidence-files  skip checking that local-check evidence files exist on disk
//   --no-block-check     skip checking that FILE#Block references exist in the skill files
// The ledger is loaded with LEDGER_LIMITS (64 MB, 5,000,000 JSON values); at most 10,000 units.
// Status `carried` (set only by run-state.cjs carry): unchanged since a complete prior run; owner null, the
// prior source checks/paths with anchors kept, and carried_from: {run_id, wave, chain (1..2)}.
// A live `covered` unit needs at least one check with a non-empty `anchors` array:
//   anchors: [{ "file": "<repo-relative path>", "line": <int >= 1>, "quote": "<verbatim control>" }]

const fs = require('fs');
const path = require('path');
const {
  Reporter, loadJson, LEDGER_LIMITS, hasOwn, isObj, isStr, isArr, isAgentId, isRelPath, FINGERPRINT, INVISIBLE, LONE_SURROGATE,
  checkKeys, dupes, quoteMatches, makeTargetReader,
} = require('./lib.cjs');

const SKILL_DIR = path.resolve(__dirname, '..');
const DIMS = ['surface', 'boundary', 'subsystem', 'class'];
const QUICK_SUBSYSTEM = 'profile/quick/all';
const STATUSES = new Set(['planned', 'not_applicable', 'out_of_scope', 'deferred', 'in_progress', 'blocked', 'covered', 'candidate', 'carried']);
const PRIORS = new Set(['none', 'new', 'confirmed_same', 'confirmed_changed', 'nv', 'deferred', 'blocked', 'out_of_scope', 'covered_same', 'covered_changed', 'rejected_changed']);
const UNIT_KEYS = new Set(['id', 'refs', 'labels', 'start_paths', 'class_block', 'pack_blocks', 'skipped_blocks', 'prior', 'wave', 'status', 'owner', 'paths', 'checks', 'fingerprints', 'open', 'history', 'notes', 'carried_from']);
const UNIT_REQUIRED = [...UNIT_KEYS].filter((k) => k !== 'notes' && k !== 'carried_from');
const MAX_CARRY_CHAIN = 2;
const HISTORY_KEYS = new Set(['wave', 'status', 'owner', 'paths', 'checks', 'fingerprints', 'open', 'reopen_reason']);
const CHECK_KEYS = new Set(['by', 'paths', 'invariant', 'method', 'result', 'evidence', 'anchors']);
const CHECK_REQUIRED = ['by', 'paths', 'invariant', 'method', 'result', 'evidence'];
const ANCHOR_KEYS = new Set(['file', 'line', 'quote']);
const MAX_UNITS = 10000;
const MAX_COLLECTION = 1000;
const MAX_ANCHORS = 50;
const MAX_QUOTE = 300;

// ---- canonical id derivation -------------------------------------------------
function refProblem(r) {
  if (typeof r !== 'string' || r.length === 0) return 'must be a non-empty string';
  if (r !== r.trim()) return 'has leading/trailing whitespace';
  if (r.normalize('NFC') !== r) return 'is not Unicode NFC';
  if (INVISIBLE.test(r)) return 'contains control, format or invisible characters';
  if (/[\ud800-\udfff]/.test(r.replace(/[\ud800-\udbff][\udc00-\udfff]/g, ''))) return 'contains a lone surrogate';
  return null;
}
function enc(s) {
  const bytes = Buffer.from(s, 'utf8');
  let out = '';
  for (const b of bytes) {
    const c = String.fromCharCode(b);
    out += /[A-Za-z0-9\-._~]/.test(c) ? c : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}
function deriveId(refs) {
  const parts = DIMS.map((d) => enc(refs[d]));
  if (refs.lifecycle !== undefined) parts.push(enc(refs.lifecycle));
  return parts.join('::');
}

// ---- block references --------------------------------------------------------
const blockCache = new Map();
function blockNames(file) {
  if (blockCache.has(file)) return blockCache.get(file);
  let names = null;
  const full = path.resolve(SKILL_DIR, file);
  if (full.startsWith(SKILL_DIR + path.sep) && fs.existsSync(full)) {
    names = new Set();
    const text = fs.readFileSync(full, 'utf8');
    for (const line of text.split(/\r?\n/)) {
      const h = /^#{1,6}\s+(.+?)\s*$/.exec(line);
      if (h) {
        let t = h[1].replace(/^Pack:\s*/, '');
        names.add(t);
        names.add(t.replace(/\s*\(.*\)\s*$/, ''));
      }
      for (const m of line.matchAll(/\*\*([^*]+?)\*\*/g)) names.add(m[1].replace(/\s*\(.*\)\s*$/, ''));
    }
  }
  blockCache.set(file, names);
  return names;
}
function blockProblem(ref, doCheck) {
  if (typeof ref !== 'string') return 'must be a string';
  const i = ref.indexOf('#');
  if (i <= 0 || i === ref.length - 1) return 'must look like FILE.md#Block name';
  const file = ref.slice(0, i);
  const name = ref.slice(i + 1);
  if (!isRelPath(file) || !file.endsWith('.md')) return 'file part must be a skill-relative .md path';
  if (!doCheck) return null;
  const names = blockNames(file);
  if (!names) return `skill file "${file}" not found`;
  if (!names.has(name)) return `block "${name}" not found in ${file}`;
  return null;
}

// ---- anchors -----------------------------------------------------------------
// Shape only: [{file, line, quote}] with a repo-relative file, an integer line >= 1 and a visible quote.
// Content is verified against a target by verifyUnitAgainstTarget.
function checkAnchors(anchors, where, rep) {
  if (!isArr(anchors)) { rep.err(where, 'must be an array'); return; }
  if (anchors.length > MAX_ANCHORS) rep.err(where, `more than ${MAX_ANCHORS} entries`);
  anchors.forEach((a, k) => {
    const aw = `${where}[${k}]`;
    if (!isObj(a)) { rep.err(aw, 'must be an object {file, line, quote}'); return; }
    checkKeys(a, ANCHOR_KEYS, [...ANCHOR_KEYS], aw, rep);
    if (!isRelPath(a.file)) rep.err(aw, `file ${JSON.stringify(a.file)} is not a safe repo-relative path`);
    if (!Number.isInteger(a.line) || a.line < 1) rep.err(aw, 'line must be an integer >= 1');
    if (!isStr(a.quote)) rep.err(aw, 'quote must contain visible text');
    else if (LONE_SURROGATE.test(a.quote)) rep.err(aw, 'quote contains a lone surrogate');
    else if ([...a.quote].length > MAX_QUOTE) rep.err(aw, `quote longer than ${MAX_QUOTE} characters`);
  });
  if (dupes(anchors).length) rep.err(where, 'contains duplicate anchors');
}
const hasAnchor = (checks) => isArr(checks) && checks.some((c) => isObj(c) && isArr(c.anchors) && c.anchors.length > 0);

// ---- target verification -----------------------------------------------------
// Verify one unit (live state and history) against a target checkout:
//   - every anchor quote passes lib.quoteMatches (>= 10 chars within 2 lines, or a whole short line)
//   - every start_paths / paths / checks[].paths entry exists as a regular file or directory in the target
// `reader` is an optional lib.makeTargetReader(target) so callers validating many units share one cache.
// Returns the number of errors it reported.
function verifyUnitAgainstTarget(unit, target, rep, reader = makeTargetReader(target)) {
  let n = 0;
  const err = (where, msg) => { n++; rep.err(where, msg); };
  if (!reader.root) { err('target', `${target} is not a readable directory`); return n; }
  if (!isObj(unit)) return n;
  const w = typeof unit.id === 'string' ? `unit ${unit.id.length > 80 ? unit.id.slice(0, 77) + '...' : unit.id}` : 'unit';
  const pathExists = (p, where, label) => {
    if (!isRelPath(p)) return; // shape errors are reported by validateLedger
    if (!reader.kind(p)) err(where, `${label} "${p}" does not exist as a file or directory inside the target`);
  };
  if (isArr(unit.start_paths)) unit.start_paths.forEach((p) => pathExists(p, w, 'start_path'));
  const states = [[unit, w]];
  if (isArr(unit.history)) unit.history.forEach((h, j) => { if (isObj(h)) states.push([h, `${w}.history[${j}]`]); });
  for (const [s, sw] of states) {
    if (isArr(s.paths)) s.paths.forEach((p) => pathExists(p, sw, 'path'));
    if (!isArr(s.checks)) continue;
    s.checks.forEach((c, i) => {
      if (!isObj(c)) return;
      const cw = `${sw}.checks[${i}]`;
      if (isArr(c.paths)) c.paths.forEach((p) => pathExists(p, cw, 'path'));
      if (!isArr(c.anchors)) return;
      c.anchors.forEach((a, k) => {
        if (!isObj(a) || !isRelPath(a.file) || !Number.isInteger(a.line) || typeof a.quote !== 'string') return;
        const aw = `${cw}.anchors[${k}]`;
        const ls = reader.kind(a.file) === 'file' ? reader.lines(a.file) : null;
        if (!ls) { err(aw, `${a.file} not found as a readable regular file inside the target`); return; }
        const m = quoteMatches(ls, a.line, a.quote);
        if (!m.ok) err(aw, `anchor quote not found at ${a.file}:${a.line} (${m.why})`);
      });
    });
  }
  return n;
}

// ---- unit checks -------------------------------------------------------------
function checkChecks(checks, where, rep, opts) {
  const union = new Set();
  if (!isArr(checks)) { rep.err(where, 'must be an array'); return union; }
  if (checks.length > MAX_COLLECTION) rep.err(where, `more than ${MAX_COLLECTION} entries`);
  checks.forEach((c, i) => {
    const w = `${where}[${i}]`;
    if (!isObj(c)) { rep.err(w, 'must be an object'); return; }
    checkKeys(c, CHECK_KEYS, CHECK_REQUIRED, w, rep);
    if (hasOwn(c, 'anchors')) checkAnchors(c.anchors, `${w}.anchors`, rep);
    if (!isAgentId(c.by)) rep.err(w, `by "${c.by}" is not a canonical agent id`);
    if (!isArr(c.paths) || !c.paths.length) rep.err(w, 'paths must be a non-empty array');
    else {
      c.paths.forEach((p) => { if (!isRelPath(p)) rep.err(w, `path "${p}" is not repo-relative`); else union.add(p); });
      if (dupes(c.paths).length) rep.err(w, 'paths contains duplicates');
    }
    if (!isStr(c.invariant)) rep.err(w, 'invariant must be a non-empty string');
    if (!isStr(c.result)) rep.err(w, 'result must be a non-empty string');
    if (c.method === 'source') {
      if (c.evidence !== null) rep.err(w, 'source checks must have evidence: null');
    } else if (c.method === 'local') {
      const prefix = `agents/${c.by}/evidence/`;
      if (typeof c.evidence !== 'string' || !c.evidence.startsWith(prefix) || c.evidence.length === prefix.length || !isRelPath(c.evidence)) {
        rep.err(w, `local evidence must be a file under ${prefix}`);
      } else if (opts.checkFiles) {
        const full = path.join(opts.runDir, ...c.evidence.split('/'));
        try {
          const st = fs.lstatSync(full);
          if (!st.isFile()) rep.err(w, `evidence ${c.evidence} is not a regular file`);
          else if (st.nlink !== 1) rep.err(w, `evidence ${c.evidence} has ${st.nlink} hard links`);
        } catch { rep.err(w, `evidence ${c.evidence} does not exist under run dir`); }
      }
    } else rep.err(w, 'method must be source|local');
  });
  return union;
}

function checkState(s, where, rep, opts, live) {
  const { status, owner, paths, checks, fingerprints, open } = s;
  if (!STATUSES.has(status)) { rep.err(where, `unknown status "${status}"`); return; }
  for (const [k, v] of [['paths', paths], ['fingerprints', fingerprints], ['open', open]]) {
    if (!isArr(v)) { rep.err(where, `${k} must be an array`); return; }
    if (v.length > MAX_COLLECTION) rep.err(where, `${k} has more than ${MAX_COLLECTION} entries`);
  }
  const union = checkChecks(checks, `${where}.checks`, rep, opts);
  if (!isArr(checks)) return;
  paths.forEach((p) => { if (!isRelPath(p)) rep.err(where, `path "${p}" is not repo-relative`); });
  open.forEach((o, i) => { if (!isStr(o)) rep.err(where, `open[${i}] must be a non-empty string`); });
  if (dupes(open).length) rep.err(where, 'open contains duplicates');
  const fpSet = new Set();
  fingerprints.forEach((f) => {
    if (typeof f !== 'string' || !FINGERPRINT.test(f)) rep.err(where, `fingerprint "${f}" has an invalid format`);
    if (fpSet.has(f)) rep.err(where, `duplicate fingerprint "${f}"`);
    fpSet.add(f);
  });
  const pathSet = new Set(paths);
  if (pathSet.size !== paths.length) rep.err(where, 'paths contains duplicates');
  const same = pathSet.size === union.size && [...union].every((p) => pathSet.has(p));
  if (!same && checks.length) rep.err(where, 'paths must equal the union of every check\'s paths');

  const noOwner = owner === null;
  const emptyEvidence = paths.length === 0 && checks.length === 0;
  switch (status) {
    case 'planned':
      if (!noOwner || !emptyEvidence || fingerprints.length || open.length) rep.err(where, 'planned: owner null, no paths/checks/fingerprints/open');
      break;
    case 'not_applicable': case 'out_of_scope': case 'deferred':
      if (!noOwner || !emptyEvidence || fingerprints.length) rep.err(where, `${status}: owner null, no paths/checks/fingerprints`);
      if (!open.length) rep.err(where, `${status}: needs at least one reason in open`);
      break;
    case 'in_progress':
      if (!isAgentId(owner)) rep.err(where, 'in_progress: owner must be a canonical agent id');
      if (!emptyEvidence || fingerprints.length || open.length) rep.err(where, 'in_progress: live evidence must be empty');
      break;
    case 'blocked':
      if (!isAgentId(owner)) rep.err(where, 'blocked: owner must be a canonical agent id');
      if (!paths.length || !checks.length) rep.err(where, 'blocked: needs owned paths and checks');
      if (fingerprints.length) rep.err(where, 'blocked: must not carry fingerprints');
      if (!open.length) rep.err(where, 'blocked: needs at least one blocker in open');
      break;
    case 'covered':
      if (!isAgentId(owner)) rep.err(where, 'covered: owner must be a canonical agent id');
      if (!paths.length || !checks.length) rep.err(where, 'covered: needs paths and checks');
      if (fingerprints.length || open.length) rep.err(where, 'covered: no fingerprints, no open items');
      // Archived (history) covered states predate anchors and stay valid without them.
      if (live && checks.length && !hasAnchor(checks)) rep.err(where, 'covered: at least one check needs a non-empty anchors array [{file, line, quote}] quoting the enforcing control');
      break;
    case 'carried':
      // Carried unchanged from a complete prior run (run-state.cjs carry): owner null, the prior checks and
      // anchors kept, provenance in carried_from.
      if (!noOwner) rep.err(where, 'carried: owner must be null');
      if (!paths.length || !checks.length) rep.err(where, 'carried: needs the prior paths and checks');
      if (fingerprints.length || open.length) rep.err(where, 'carried: no fingerprints, no open items');
      if (live && checks.length && !hasAnchor(checks)) rep.err(where, 'carried: at least one check needs a non-empty anchors array');
      if (live && checks.some((c) => isObj(c) && c.method !== 'source')) rep.err(where, 'carried: only source checks can be carried (local evidence is not portable)');
      if (live) {
        const cf = s.carried_from;
        if (!isObj(cf)) rep.err(where, 'carried: needs carried_from {run_id, wave, chain}');
        else {
          checkKeys(cf, new Set(['run_id', 'wave', 'chain']), ['run_id', 'wave', 'chain'], `${where}.carried_from`, rep);
          if (!isStr(cf.run_id)) rep.err(`${where}.carried_from`, 'run_id must be a non-empty string');
          if (!Number.isInteger(cf.wave) || cf.wave < 1) rep.err(`${where}.carried_from`, 'wave must be an integer >= 1');
          if (!Number.isInteger(cf.chain) || cf.chain < 1 || cf.chain > MAX_CARRY_CHAIN) rep.err(`${where}.carried_from`, `chain must be an integer 1..${MAX_CARRY_CHAIN}`);
        }
      }
      break;
    case 'candidate':
      if (!isAgentId(owner)) rep.err(where, 'candidate: owner must be a canonical agent id');
      if (!paths.length || !checks.length) rep.err(where, 'candidate: needs paths and checks');
      if (!fingerprints.length) rep.err(where, 'candidate: needs at least one fingerprint');
      break;
  }
  if (!live && !['blocked', 'covered', 'candidate', 'carried'].includes(status)) rep.err(where, 'history may only archive blocked|covered|candidate|carried states');
  if (live && status !== 'carried' && hasOwn(s, 'carried_from')) rep.err(where, 'carried_from is only allowed on a carried unit');
}

// opts: { runDir, checkFiles, checkBlocks, profile?, status?, target? }. With opts.target (a repo path),
// every unit is also checked with verifyUnitAgainstTarget (one shared reader/cache).
function validateLedger(data, rep, opts = {}) {
  if (!isArr(data)) { rep.err('ledger', 'top level must be a JSON array'); return; }
  if (data.length > MAX_UNITS) { rep.err('ledger', `more than ${MAX_UNITS} units`); return; }
  let reader = null;
  if (opts.target !== undefined && opts.target !== null) {
    reader = makeTargetReader(opts.target);
    if (!reader.root) { rep.err('target', `${opts.target} is not a readable directory`); reader = null; }
  }
  const ids = new Map();
  const refLabels = new Map();
  const tuples = new Map();
  let prevId = null;
  const counts = {};
  data.forEach((u, i) => {
    let w = `unit[${i}]`;
    if (!isObj(u)) { rep.err(w, 'must be an object'); return; }
    if (typeof u.id === 'string') w = `unit[${i}] ${u.id.length > 80 ? u.id.slice(0, 77) + '...' : u.id}`;
    checkKeys(u, UNIT_KEYS, UNIT_REQUIRED, w, rep);
    const sk = STATUSES.has(u.status) ? u.status : 'invalid_status';
    counts[sk] = (counts[sk] || 0) + 1;
    if (reader) verifyUnitAgainstTarget(u, opts.target, rep, reader);

    // refs / labels / id
    if (!isObj(u.refs)) rep.err(w, 'refs must be an object');
    else {
      const allowed = new Set([...DIMS, 'lifecycle']);
      checkKeys(u.refs, allowed, DIMS, `${w}.refs`, rep);
      let ok = true;
      for (const k of Object.keys(u.refs)) { const p = refProblem(u.refs[k]); if (p) { rep.err(`${w}.refs.${k}`, p); ok = false; } }
      if (ok && DIMS.every((d) => typeof u.refs[d] === 'string')) {
        const expect = deriveId(u.refs);
        if (u.id !== expect) rep.err(w, `id does not match canonical derivation; expected ${expect}`);
        const cp = blockProblem(u.refs.class, opts.checkBlocks);
        if (cp) rep.err(`${w}.refs.class`, cp);
      }
      if (isObj(u.labels)) {
        checkKeys(u.labels, allowed, DIMS, `${w}.labels`, rep);
        if (hasOwn(u.refs, 'lifecycle') !== hasOwn(u.labels, 'lifecycle')) rep.err(w, 'refs.lifecycle and labels.lifecycle must appear together');
        for (const k of Object.keys(u.labels)) if (!isStr(u.labels[k])) rep.err(`${w}.labels.${k}`, 'must be a non-empty string');
        for (const k of DIMS) {
          const key = `${k}\u0000${u.refs[k]}`;
          if (typeof u.refs[k] !== 'string') continue;
          if (refLabels.has(key) && refLabels.get(key) !== u.labels[k]) rep.warn(`${w}.labels.${k}`, `same ref "${u.refs[k]}" uses different labels across units`);
          else refLabels.set(key, u.labels[k]);
        }
        // One semantic unit must have one canonical ref set.
        const tuple = JSON.stringify([...DIMS, 'lifecycle'].map((k) => u.labels[k] ?? null));
        if (tuples.has(tuple) && tuples.get(tuple).id !== u.id) rep.err(w, `same labels as unit[${tuples.get(tuple).i}] but different refs - reuse one canonical ref set`);
        else tuples.set(tuple, { id: u.id, i });
      } else rep.err(w, 'labels must be an object');
    }
    if (typeof u.id !== 'string' || !u.id) rep.err(w, 'id must be a non-empty string');
    else {
      if (ids.has(u.id)) rep.err(w, `duplicate id (also unit[${ids.get(u.id)}]) - never merge colliding units`);
      ids.set(u.id, i);
      if (prevId !== null && u.id < prevId) rep.err(w, 'units must be sorted by id');
      prevId = u.id;
    }

    // planning fields
    if (!isArr(u.start_paths) || !u.start_paths.length) rep.err(w, 'start_paths must be a non-empty array');
    else {
      u.start_paths.forEach((p) => { if (!isRelPath(p)) rep.err(w, `start_path "${p}" is not repo-relative`); });
      if (dupes(u.start_paths).length) rep.err(w, 'start_paths contains duplicates');
    }
    if (opts.profile === 'quick' && isObj(u.refs) && u.refs.subsystem !== QUICK_SUBSYSTEM) rep.err(`${w}.refs.subsystem`, `quick profile requires "${QUICK_SUBSYSTEM}"`);
    if (opts.profile && opts.profile !== 'quick' && isObj(u.refs) && u.refs.subsystem === QUICK_SUBSYSTEM) rep.err(`${w}.refs.subsystem`, `"${QUICK_SUBSYSTEM}" is only valid in the quick profile`);
    if (opts.status === 'complete' && (u.status === 'planned' || u.status === 'in_progress')) rep.err(w, `run.json says complete but unit is ${u.status}`);
    if (u.class_block !== null) { const p = blockProblem(u.class_block, opts.checkBlocks); if (p) rep.err(`${w}.class_block`, p); }
    const selected = new Set();
    if (!isArr(u.pack_blocks)) rep.err(w, 'pack_blocks must be an array');
    else {
      u.pack_blocks.forEach((b) => { const p = blockProblem(b, opts.checkBlocks); if (p) rep.err(`${w}.pack_blocks`, `${b}: ${p}`); selected.add(b); });
      if (dupes(u.pack_blocks).length) rep.err(`${w}.pack_blocks`, 'contains duplicates');
      const packs = new Set(u.pack_blocks.filter((b) => typeof b === 'string' && b.startsWith('packs/')).map((b) => b.split('#')[0]));
      for (const f of packs) for (const req of ['Discipline', 'Moves', 'Gate']) {
        if (!selected.has(`${f}#${req}`)) rep.err(`${w}.pack_blocks`, `selecting from ${f} requires ${f}#${req}`);
      }
    }
    // The unit's own class must be one of the blocks its hunter is actually given.
    if (isObj(u.refs) && typeof u.refs.class === 'string' && u.refs.class !== u.class_block && !selected.has(u.refs.class)) {
      rep.err(`${w}.refs.class`, 'class is neither class_block nor in pack_blocks, so its hunter would never see it');
    }
    if (!isArr(u.skipped_blocks)) rep.err(w, 'skipped_blocks must be an array');
    else if (dupes(u.skipped_blocks.map((s) => isObj(s) ? s.block : s)).length) rep.err(`${w}.skipped_blocks`, 'lists the same block twice');
    if (isArr(u.skipped_blocks)) u.skipped_blocks.forEach((s, j) => {
      const sw = `${w}.skipped_blocks[${j}]`;
      if (!isObj(s)) { rep.err(sw, 'must be an object'); return; }
      checkKeys(s, new Set(['block', 'why']), ['block', 'why'], sw, rep);
      const p = blockProblem(s.block, opts.checkBlocks); if (p) rep.err(sw, p);
      if (!isStr(s.why)) rep.err(sw, 'why must be a non-empty string');
      if (selected.has(s.block) || s.block === u.class_block) rep.err(sw, 'block is both selected and skipped');
    });
    if (!PRIORS.has(u.prior)) rep.err(w, `prior must be one of ${[...PRIORS].join('|')}`);
    if (!Number.isInteger(u.wave) || u.wave < 1) rep.err(w, 'wave must be an integer >= 1');
    if (u.owner !== null && !isAgentId(u.owner)) rep.err(w, `owner "${u.owner}" is not a canonical agent id`);
    if (hasOwn(u, 'notes') && !isObj(u.notes)) rep.err(w, 'notes must be an object');

    checkState(u, w, rep, opts, true);

    // history
    if (!isArr(u.history)) rep.err(w, 'history must be an array');
    else {
      let lastWave = 0;
      const pastOwners = new Set();
      u.history.forEach((h, j) => {
        const hw = `${w}.history[${j}]`;
        if (!isObj(h)) { rep.err(hw, 'must be an object'); return; }
        checkKeys(h, HISTORY_KEYS, [...HISTORY_KEYS], hw, rep);
        if (!Number.isInteger(h.wave) || h.wave <= lastWave) rep.err(hw, 'history waves must be strictly increasing integers');
        if (Number.isInteger(u.wave) && Number.isInteger(h.wave) && h.wave >= u.wave) rep.err(hw, 'history wave must be below the live wave');
        if (Number.isInteger(h.wave)) lastWave = h.wave;
        if (!isStr(h.reopen_reason)) rep.err(hw, 'reopen_reason must be a non-empty string');
        checkState(h, hw, rep, opts, false);
        if (typeof h.owner === 'string') pastOwners.add(h.owner);
        for (const c of isArr(h.checks) ? h.checks : []) if (isObj(c) && typeof c.by === 'string') pastOwners.add(c.by); // archived verifiers too
      });
      if (u.owner && pastOwners.has(u.owner)) rep.err(w, `live owner "${u.owner}" also owned an archived attempt - reassignment needs a fresh owner`);
      // Archived evidence stays archived: no archived owner's checks or files in the live attempt.
      const archivedEvidence = new Set();
      for (const h of u.history) if (isObj(h) && isArr(h.checks)) for (const c of h.checks) if (isObj(c) && typeof c.evidence === 'string') archivedEvidence.add(c.evidence);
      if (isArr(u.checks)) u.checks.forEach((c, j) => {
        if (!isObj(c)) return;
        if (pastOwners.has(c.by)) rep.err(`${w}.checks[${j}]`, `check by archived owner "${c.by}" must stay in history`);
        if (typeof c.evidence === 'string' && archivedEvidence.has(c.evidence)) rep.err(`${w}.checks[${j}]`, `evidence ${c.evidence} belongs to an archived attempt`);
      });
    }
  });
  return counts;
}

// ---- run.json ----------------------------------------------------------------
const RUN_ENUMS = {
  profile: ['quick', 'standard', 'deep'],
  status: ['in_progress', 'complete', 'incomplete'],
  execution: ['sandboxed-local-only', 'source-only'],
};
// Optional run.json fields: validated only when present.
const RUN_OPTIONAL_ENUMS = {
  trust: ['own', 'untrusted'],
  advisories: ['checked', 'not_checked'],
};
const INCOMPLETE_REASONS = ['recon_only', 'budget_below_minimum', 'validation_budget_exhausted', 'critic_budget_exhausted', 'verification_unavailable', 'stopped_early'];
const SCOPE_KINDS = ['full', 'paths', 'pack', 'diff'];

function checkRun(run, rep) {
  const w = 'run.json';
  if (!isObj(run)) { rep.err(w, 'must be an object'); return; }
  for (const k of ['run_id', 'repo', 'target', 'source_ref', 'profile', 'scope', 'execution', 'status']) if (!hasOwn(run, k)) rep.err(w, `missing "${k}"`);
  for (const [k, vals] of Object.entries(RUN_ENUMS)) if (hasOwn(run, k) && !vals.includes(run[k])) rep.err(w, `${k} must be one of ${vals.join('|')}`);
  for (const [k, vals] of Object.entries(RUN_OPTIONAL_ENUMS)) if (hasOwn(run, k) && !vals.includes(run[k])) rep.err(w, `${k} must be one of ${vals.join('|')} when present`);
  if (isObj(run.scope) && !SCOPE_KINDS.includes(run.scope.kind)) rep.err(w, `scope.kind must be one of ${SCOPE_KINDS.join('|')}`);
  if (run.status === 'incomplete' && !INCOMPLETE_REASONS.includes(run.incomplete_reason)) rep.err(w, `incomplete_reason must be one of ${INCOMPLETE_REASONS.join('|')}`);
  if (run.status !== 'incomplete' && run.incomplete_reason != null) rep.err(w, 'incomplete_reason is only allowed when status is incomplete');
  if (run.budget_agents != null && (!Number.isInteger(run.budget_agents) || run.budget_agents < 1)) rep.err(w, 'budget_agents must be null or a positive integer');
}

function main(argv) {
  const args = argv.slice(2);
  if (!args.length || args.includes('-h') || args.includes('--help')) {
    console.log([
      'usage: node check-ledger.cjs <ledger.json> [--run-dir <dir>] [--target <repo>] [--no-evidence-files] [--no-block-check]',
      '  --run-dir <dir>      where agents/<id>/evidence/ and run.json live (default: the ledger\'s directory)',
      '  --target <repo>      verify every check anchor quote and every start_paths/paths/check paths entry',
      '                       against the target checkout (paths must exist inside it as a file or directory)',
      '  --no-evidence-files  skip checking that local-check evidence files exist on disk',
      '  --no-block-check     skip checking that FILE#Block references exist in the skill files',
      'A live covered unit needs >= 1 check with anchors: [{"file", "line", "quote"}]. Anchor quotes follow the',
      'findings rule: >= 10 characters within 2 lines of `line`, or exactly the whole text of a nearby line.',
      `Limits: ${MAX_UNITS} units; ledger file up to ${LEDGER_LIMITS.maxBytes} bytes and ${LEDGER_LIMITS.maxNodes} JSON values.`,
    ].join('\n'));
    return args.length ? 0 : 2;
  }
  const file = args[0];
  const ri = args.indexOf('--run-dir');
  const ti = args.indexOf('--target');
  const opts = {
    runDir: ri !== -1 && args[ri + 1] ? path.resolve(args[ri + 1]) : path.dirname(path.resolve(file)),
    checkFiles: !args.includes('--no-evidence-files'),
    checkBlocks: !args.includes('--no-block-check'),
  };
  const rep = new Reporter();
  if (ri !== -1 && !args[ri + 1]) rep.err('args', '--run-dir needs a path');
  if (ti !== -1) {
    if (!args[ti + 1] || args[ti + 1].startsWith('--')) rep.err('args', '--target needs a path');
    else opts.target = path.resolve(args[ti + 1]);
  }
  const runPath = path.join(opts.runDir, 'run.json');
  if (fs.existsSync(runPath)) {
    const run = loadJson(runPath, rep);
    if (run !== undefined) { checkRun(run, rep); if (isObj(run)) { opts.profile = run.profile; opts.status = run.status; } }
  }
  const data = loadJson(file, rep, LEDGER_LIMITS);
  let counts = {};
  if (data !== undefined) counts = validateLedger(data, rep, opts) || {};
  const summary = Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ');
  return rep.finish('ledger', summary || 'empty');
}

if (require.main === module) process.exitCode = main(process.argv);
module.exports = {
  validateLedger, verifyUnitAgainstTarget, checkAnchors, checkRun, blockProblem, deriveId, enc,
  QUICK_SUBSYSTEM, MAX_UNITS, MAX_CARRY_CHAIN, STATUSES, RUN_OPTIONAL_ENUMS, main,
};
