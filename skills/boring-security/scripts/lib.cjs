'use strict';
// Shared helpers for boring-security validators. Zero dependencies, Node >= 18.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Default limits for small JSON inputs (findings.json, run.json, decisions). Pass per-call overrides to loadJson.
const LIMITS = Object.freeze({ maxBytes: 5 * 1024 * 1024, maxDepth: 64, maxNodes: 500000, maxErrors: 100 });
// Preset for ledger.json: the ledger may hold MAX_UNITS (10,000) units of ~1-2 KB each.
const LEDGER_LIMITS = Object.freeze({ maxBytes: 64 * 1024 * 1024, maxNodes: 5000000 });

// Own-property test. Never use `k in obj` on untrusted data: it sees Object.prototype
// (constructor, toString, __proto__, ...).
const hasOwn = (o, k) => o !== null && o !== undefined && Object.prototype.hasOwnProperty.call(o, k);

class Reporter {
  constructor() { this.errors = []; this.warnings = []; this.truncated = false; }
  err(where, msg) {
    if (this.errors.length >= LIMITS.maxErrors) { this.truncated = true; return; }
    this.errors.push(`${where}: ${msg}`);
  }
  warn(where, msg) { if (this.warnings.length < LIMITS.maxErrors) this.warnings.push(`${where}: ${msg}`); }
  finish(label, okMsg) {
    for (const w of this.warnings) console.error(`warning  ${w}`);
    if (this.errors.length) {
      for (const e of this.errors) console.error(`error    ${e}`);
      if (this.truncated) console.error(`error    (more errors suppressed after ${LIMITS.maxErrors})`);
      console.error(`\n${label}: FAILED with ${this.errors.length}${this.truncated ? '+' : ''} error(s)`);
      return 1;
    }
    console.log(`${label}: OK${okMsg ? ' - ' + okMsg : ''}`);
    return 0;
  }
}

function resolveLimits(limits) {
  const out = { maxBytes: LIMITS.maxBytes, maxDepth: LIMITS.maxDepth, maxNodes: LIMITS.maxNodes };
  if (limits !== null && typeof limits === 'object') {
    for (const k of Object.keys(out)) {
      if (!hasOwn(limits, k) || limits[k] === undefined) continue;
      if (!Number.isSafeInteger(limits[k]) || limits[k] < 1) throw new TypeError(`loadJson: ${k} must be a positive integer`);
      out[k] = limits[k];
    }
  }
  return out;
}

// Read a JSON file defensively: regular file (not a symlink), size cap, strict UTF-8, depth and node caps.
// limits: optional { maxBytes, maxNodes, maxDepth }; omitted keys use LIMITS. Use LEDGER_LIMITS for ledgers.
function loadJson(file, rep, limits) {
  const L = resolveLimits(limits);
  let st;
  try { st = fs.lstatSync(file); } catch (e) { rep.err(file, `cannot stat: ${e.code || e.message}`); return undefined; }
  if (st.isSymbolicLink()) { rep.err(file, 'input must not be a symlink'); return undefined; }
  if (!st.isFile()) { rep.err(file, 'input must be a regular file'); return undefined; }
  if (st.size > L.maxBytes) { rep.err(file, `larger than ${L.maxBytes} bytes`); return undefined; }
  // Identity-checked open: works on Windows (no O_NOFOLLOW needed) and detects a swap between lstat and open.
  let buf;
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const fst = fs.fstatSync(fd);
    if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) { rep.err(file, 'file changed between check and open'); return undefined; }
    if (fst.size > L.maxBytes) { rep.err(file, `larger than ${L.maxBytes} bytes`); return undefined; }
    buf = Buffer.alloc(fst.size);
    let off = 0;
    while (off < fst.size) { const n = fs.readSync(fd, buf, off, fst.size - off, off); if (!n) break; off += n; }
    buf = buf.subarray(0, off);
  } catch (e) { rep.err(file, `cannot open safely: ${e.code || e.message}`); return undefined; } finally { if (fd !== undefined) fs.closeSync(fd); }
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch { rep.err(file, 'input is not valid UTF-8'); return undefined; }
  buf = null;
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  let data;
  try { data = JSON.parse(text); } catch (e) { rep.err(file, `invalid JSON: ${e.message}`); return undefined; }
  text = null;
  // Iterative walk with parallel stacks (no per-node allocation): linear in the number of values.
  let nodes = 0;
  const vals = [data];
  const depths = [1];
  while (vals.length) {
    const v = vals.pop();
    const d = depths.pop();
    if (++nodes > L.maxNodes) { rep.err(file, `more than ${L.maxNodes} JSON values`); return undefined; }
    if (d > L.maxDepth) { rep.err(file, `nesting deeper than ${L.maxDepth}`); return undefined; }
    if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) { vals.push(v[i]); depths.push(d + 1); } }
    else if (v && typeof v === 'object') { for (const k of Object.keys(v)) { vals.push(v[k]); depths.push(d + 1); } }
  }
  return data;
}

// ---- hashing helpers -------------------------------------------------------------------------
// sha256(text): lowercase hex SHA-256 of a string (UTF-8) or Buffer.
function sha256(text) {
  if (typeof text !== 'string' && !Buffer.isBuffer(text)) throw new TypeError('sha256 expects a string or Buffer');
  return crypto.createHash('sha256').update(text).digest('hex');
}
// canonicalJson(value): JSON text with object keys sorted (code-unit order) at every level, no whitespace.
// Same value model as JSON.stringify (undefined/function members dropped, in arrays -> null); throws on
// non-finite numbers, BigInt and cycles so a hash never silently covers a lossy encoding.
function canonicalJson(value) {
  const seen = new Set();
  const enc = (v) => {
    if (v === null) return 'null';
    switch (typeof v) {
      case 'string': case 'boolean': return JSON.stringify(v);
      case 'number': if (!Number.isFinite(v)) throw new TypeError('canonicalJson: non-finite number'); return JSON.stringify(v);
      case 'object': break;
      default: throw new TypeError(`canonicalJson: unsupported ${typeof v}`);
    }
    if (seen.has(v)) throw new TypeError('canonicalJson: cyclic value');
    seen.add(v);
    let out;
    if (Array.isArray(v)) {
      out = '[' + v.map((x) => (x === undefined || typeof x === 'function' ? 'null' : enc(x))).join(',') + ']';
    } else {
      const keys = Object.keys(v).filter((k) => v[k] !== undefined && typeof v[k] !== 'function').sort();
      out = '{' + keys.map((k) => JSON.stringify(k) + ':' + enc(v[k])).join(',') + '}';
    }
    seen.delete(v);
    return out;
  };
  return enc(value);
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isArr = Array.isArray;

// Control, format and invisible code points; strings made only of these (plus whitespace) are not "visible".
const INVISIBLE = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u061c\\u180e\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\ufeff\\ufe00-\\ufe0f]', 'u');
const INVISIBLE_G = new RegExp(INVISIBLE.source, 'gu');
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const isVisible = (s) => typeof s === 'string' && s.replace(INVISIBLE_G, '').trim().length > 0;
const isStr = isVisible;

const AGENT_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const WIN_DEVICES = new Set(['con', 'prn', 'aux', 'nul', ...Array.from({ length: 9 }, (_, i) => `com${i + 1}`), ...Array.from({ length: 9 }, (_, i) => `lpt${i + 1}`)]);
const isAgentId = (v) => typeof v === 'string' && AGENT_ID.test(v) && !WIN_DEVICES.has(v);

const FINGERPRINT = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;

function isRelPath(p) {
  if (typeof p !== 'string' || !p.length || p.includes('\\') || p.startsWith('/') || p.startsWith('~') || /^[A-Za-z]:/.test(p)) return false;
  if (INVISIBLE.test(p)) return false;
  return p.split('/').every((s) => s !== '..' && s !== '' && s !== '.');
}

function checkKeys(obj, allowed, required, where, rep) {
  for (const k of Object.keys(obj)) if (!allowed.has(k)) rep.err(where, `unexpected property "${k}"`);
  for (const k of required) if (!hasOwn(obj, k)) rep.err(where, `missing required property "${k}"`);
}

// ---- quote verification against a target checkout ---------------------------------------------
// Rule shared by findings (trace/evidence quotes) and ledger anchors. After collapsing whitespace runs
// to one space and trimming, a quote must either
//   (1) be at least QUOTE_MIN_CHARS code points long and appear inside the window of lines
//       line-2 .. line+2 (1-based, joined with spaces, whitespace-normalised), or
//   (2) be exactly equal to the whole normalised text of one line inside that window
//       (for genuinely short lines) and contain at least one letter or digit.
const QUOTE_MIN_CHARS = 10;
const QUOTE_WINDOW = 2;
const normWs = (s) => String(s).replace(/\s+/g, ' ').trim();
const HAS_WORD_CHAR = /[\p{L}\p{N}]/u;

function quoteMatches(fileLines, line, quote) {
  if (!Array.isArray(fileLines)) return { ok: false, why: 'file is not readable' };
  if (!Number.isInteger(line) || line < 1) return { ok: false, why: 'line must be an integer >= 1' };
  if (typeof quote !== 'string') return { ok: false, why: 'quote must be a string' };
  const q = normWs(quote);
  if (!q) return { ok: false, why: 'quote is empty after whitespace normalisation' };
  if (line > fileLines.length) return { ok: false, why: `line ${line} is past the end of the file (${fileLines.length} lines)` };
  const win = fileLines.slice(Math.max(0, line - 1 - QUOTE_WINDOW), line + QUOTE_WINDOW).map((l) => normWs(l));
  const len = [...q].length;
  if (len >= QUOTE_MIN_CHARS) {
    if (win.join(' ').includes(q)) return { ok: true, why: null };
    return { ok: false, why: `quote not found within ${QUOTE_WINDOW} lines of line ${line}` };
  }
  if (HAS_WORD_CHAR.test(q) && win.some((l) => l === q)) return { ok: true, why: null };
  return { ok: false, why: `quote is shorter than ${QUOTE_MIN_CHARS} characters and is not the whole text of a line within ${QUOTE_WINDOW} lines of line ${line}` };
}

// Safe, cached read-only access to files of a target checkout. Paths must pass isRelPath; the resolved
// real path (symlinks followed) must stay inside the real target root, so a symlink can never lead out.
//   kind(rel)  -> 'file' | 'dir' | null
//   lines(rel) -> array of lines (regular files <= maxFileBytes) | null
function makeTargetReader(target, { maxFileBytes = 5 * 1024 * 1024 } = {}) {
  let realRoot = null;
  try { realRoot = fs.realpathSync(path.resolve(String(target))); if (!fs.statSync(realRoot).isDirectory()) realRoot = null; } catch { realRoot = null; }
  const kinds = new Map();
  const texts = new Map();
  const resolve = (rel) => {
    if (!realRoot || !isRelPath(rel)) return null;
    try {
      const full = fs.realpathSync(path.join(realRoot, ...rel.split('/')));
      const inside = path.relative(realRoot, full);
      if (inside === '' || inside === '..' || inside.startsWith('..' + path.sep) || path.isAbsolute(inside)) return null;
      return full;
    } catch { return null; }
  };
  const kind = (rel) => {
    if (kinds.has(rel)) return kinds.get(rel);
    let k = null;
    const full = resolve(rel);
    if (full) { try { const st = fs.statSync(full); k = st.isFile() ? 'file' : st.isDirectory() ? 'dir' : null; } catch { k = null; } }
    kinds.set(rel, k);
    return k;
  };
  const lines = (rel) => {
    if (texts.has(rel)) return texts.get(rel);
    let v = null;
    const full = kind(rel) === 'file' ? resolve(rel) : null;
    if (full) {
      try {
        const st = fs.statSync(full);
        if (st.isFile() && st.size <= maxFileBytes) v = fs.readFileSync(full, 'utf8').split(/\r?\n/);
      } catch { v = null; }
    }
    texts.set(rel, v);
    return v;
  };
  return { root: realRoot, kind, lines };
}

function dupes(arr) {
  const seen = new Set(); const out = [];
  for (const v of arr) { const k = JSON.stringify(v); if (seen.has(k)) out.push(v); seen.add(k); }
  return out;
}

// ---- minimal JSON Schema engine (the subset findings.schema.json uses) ------------------------
// Unknown keywords make the schema invalid, so schema and engine cannot silently drift apart.
const ANNOTATIONS = new Set(['$schema', '$id', '$defs', '$comment', 'title', 'description']);
const KEYWORDS = new Set(['$ref', 'type', 'const', 'enum', 'required', 'properties', 'additionalProperties', 'items', 'minItems', 'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'pattern', 'minimum', 'minProperties', 'oneOf', 'x-visible', 'x-relpath']);

function lintSchema(schema, where, errors) {
  if (!isObj(schema)) { errors.push(`${where}: schema must be an object`); return; }
  for (const k of Object.keys(schema)) {
    if (!KEYWORDS.has(k) && !ANNOTATIONS.has(k)) errors.push(`${where}: unsupported keyword "${k}"`);
  }
  if (hasOwn(schema, 'pattern')) { try { new RegExp(schema.pattern, 'u'); } catch { errors.push(`${where}.pattern: invalid regular expression`); } }
  if (isObj(schema.$defs)) for (const [k, v] of Object.entries(schema.$defs)) lintSchema(v, `${where}.$defs.${k}`, errors);
  if (isObj(schema.properties)) for (const [k, v] of Object.entries(schema.properties)) lintSchema(v, `${where}.properties.${k}`, errors);
  if (isObj(schema.items)) lintSchema(schema.items, `${where}.items`, errors);
  if (isArr(schema.oneOf)) schema.oneOf.forEach((s, i) => lintSchema(s, `${where}.oneOf[${i}]`, errors));
}

function resolveRef(root, ref) {
  if (!ref.startsWith('#/')) throw new Error(`unsupported $ref ${ref}`);
  let cur = root;
  for (const part of ref.slice(2).split('/')) {
    if (!isObj(cur) || !hasOwn(cur, part)) throw new Error(`unresolvable $ref ${ref}`);
    cur = cur[part];
  }
  return cur;
}

function typeOf(v) {
  if (v === null) return 'null';
  if (isArr(v)) return 'array';
  if (Number.isInteger(v)) return 'integer';
  return typeof v;
}

// Returns a list of "path: message" strings.
function validateSchema(value, schema, root, p = '$') {
  const errs = [];
  if (hasOwn(schema, '$ref')) return validateSchema(value, resolveRef(root, schema.$ref), root, p);
  if (typeof value === 'string' && LONE_SURROGATE.test(value)) errs.push(`${p}: contains a lone surrogate`);
  if (hasOwn(schema, 'const') && value !== schema.const) errs.push(`${p}: must equal ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errs.push(`${p}: must be one of ${schema.enum.join('|')}`);
  if (schema.type) {
    const t = typeOf(value);
    const ok = schema.type === t || (schema.type === 'number' && t === 'integer');
    if (!ok) { errs.push(`${p}: expected ${schema.type}, got ${t}`); return errs; }
  }
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && [...value].length < schema.minLength) errs.push(`${p}: shorter than ${schema.minLength}`);
    if (schema.maxLength !== undefined && [...value].length > schema.maxLength) errs.push(`${p}: longer than ${schema.maxLength}`);
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) errs.push(`${p}: does not match ${schema.pattern}`);
    if (schema['x-visible'] && !isVisible(value)) errs.push(`${p}: must contain visible text`);
    if (schema['x-relpath'] && !isRelPath(value)) errs.push(`${p}: "${value}" is not a safe repo-relative path`);
  }
  if (typeof value === 'number' && schema.minimum !== undefined && value < schema.minimum) errs.push(`${p}: must be >= ${schema.minimum}`);
  if (isArr(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errs.push(`${p}: needs at least ${schema.minItems} item(s)`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errs.push(`${p}: more than ${schema.maxItems} items`);
    if (schema.uniqueItems && dupes(value).length) errs.push(`${p}: items must be unique`);
    if (schema.items) value.forEach((v, i) => errs.push(...validateSchema(v, schema.items, root, `${p}[${i}]`)));
  }
  if (isObj(value)) {
    const props = schema.properties || {};
    for (const k of schema.required || []) if (!hasOwn(value, k)) errs.push(`${p}: missing required property "${k}"`);
    if (schema.additionalProperties === false) for (const k of Object.keys(value)) if (!hasOwn(props, k)) errs.push(`${p}: unexpected property ${JSON.stringify(k)}`);
    if (schema.minProperties !== undefined && Object.keys(value).length < schema.minProperties) errs.push(`${p}: needs at least ${schema.minProperties} propert(ies)`);
    for (const [k, s] of Object.entries(props)) if (hasOwn(value, k)) errs.push(...validateSchema(value[k], s, root, `${p}.${k}`));
  }
  if (schema.oneOf) {
    const results = schema.oneOf.map((s) => validateSchema(value, s, root, p));
    const passing = results.filter((r) => r.length === 0).length;
    if (passing !== 1) {
      // Report the branch whose discriminating const matches, so messages stay readable.
      const idx = schema.oneOf.findIndex((s) => {
        const b = hasOwn(s, '$ref') ? resolveRef(root, s.$ref) : s;
        return isObj(value) && isObj(b.properties) && Object.entries(b.properties).some(([k, v]) => hasOwn(v, 'const') && hasOwn(value, k) && value[k] === v.const);
      });
      if (passing > 1) errs.push(`${p}: matches more than one oneOf branch`);
      else if (idx >= 0) errs.push(...results[idx]);
      else errs.push(`${p}: matches no allowed variant${isObj(value) && hasOwn(value, 'verdict') ? ` (verdict ${JSON.stringify(value.verdict)} is not one of confirmed|needs_validation|rejected)` : ''}`);
    }
  }
  return errs;
}

// Report area for a ledger class ref (FILE#Class). Shared by detect.cjs and score.cjs.
const CORE_AREA = {
  'Injection': 'Injection', 'Access control': 'Access control', 'Files, fetches and parsing': 'Files, fetches & parsing',
  'Crypto and secrets': 'Secrets & crypto', 'Business logic': 'Business logic', 'Feature abuse and data leakage': 'Business logic',
  'Chains and trust gaps': 'Business logic', 'Wildcard': 'Basics & other', 'Obvious things': 'Basics & other',
};
const PACK_AREA = {
  'web-and-identity': 'Web & identity', 'browser-client': 'Browser & XSS', mobile: 'Mobile', 'desktop-and-local-ipc': 'Desktop & IPC',
  'ai-agents': 'AI & agents', 'native-memory': 'Memory safety', 'supply-chain': 'Supply chain & CI', 'cloud-infra': 'Cloud & infra',
  'messaging-rpc': 'Messaging & RPC', availability: 'Availability', 'data-lifecycle': 'Data isolation', 'data-integrity': 'Data integrity',
  'app-stack': 'App stack (BaaS & serverless)',
};

function areaOf(classRef) {
  if (typeof classRef !== 'string') return 'Basics & other';
  const [file, name] = classRef.split('#');
  const pack = /^packs\/([\w-]+)\.md$/.exec(file);
  if (pack) return hasOwn(PACK_AREA, pack[1]) ? PACK_AREA[pack[1]] : 'Basics & other';
  return hasOwn(CORE_AREA, name) ? CORE_AREA[name] : 'Basics & other';
}

module.exports = {
  areaOf, PACK_AREA, CORE_AREA, LIMITS, LEDGER_LIMITS, Reporter, loadJson, hasOwn, isObj, isStr, isArr, isVisible, isAgentId, isRelPath,
  FINGERPRINT, INVISIBLE, LONE_SURROGATE, checkKeys, dupes, lintSchema, validateSchema,
  sha256, canonicalJson, normWs, quoteMatches, makeTargetReader, QUOTE_MIN_CHARS, QUOTE_WINDOW,
};
