'use strict';
// Shared helpers for boring-security validators. Zero dependencies, Node >= 18.

const fs = require('fs');

const LIMITS = { maxBytes: 5 * 1024 * 1024, maxDepth: 64, maxNodes: 500000, maxErrors: 100 };

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

// Read a JSON file defensively: regular file (not a symlink), size cap, strict UTF-8, depth and node caps.
function loadJson(path, rep) {
  let st;
  try { st = fs.lstatSync(path); } catch (e) { rep.err(path, `cannot stat: ${e.code || e.message}`); return undefined; }
  if (st.isSymbolicLink()) { rep.err(path, 'input must not be a symlink'); return undefined; }
  if (!st.isFile()) { rep.err(path, 'input must be a regular file'); return undefined; }
  if (st.size > LIMITS.maxBytes) { rep.err(path, `larger than ${LIMITS.maxBytes} bytes`); return undefined; }
  // Identity-checked open: works on Windows (no O_NOFOLLOW needed) and detects a swap between lstat and open.
  let buf;
  let fd;
  try {
    fd = fs.openSync(path, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const fst = fs.fstatSync(fd);
    if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) { rep.err(path, 'file changed between check and open'); return undefined; }
    if (fst.size > LIMITS.maxBytes) { rep.err(path, `larger than ${LIMITS.maxBytes} bytes`); return undefined; }
    buf = Buffer.alloc(fst.size);
    let off = 0;
    while (off < fst.size) { const n = fs.readSync(fd, buf, off, fst.size - off, off); if (!n) break; off += n; }
    buf = buf.subarray(0, off);
  } catch (e) { rep.err(path, `cannot open safely: ${e.code || e.message}`); return undefined; } finally { if (fd !== undefined) fs.closeSync(fd); }
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch { rep.err(path, 'input is not valid UTF-8'); return undefined; }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  let data;
  try { data = JSON.parse(text); } catch (e) { rep.err(path, `invalid JSON: ${e.message}`); return undefined; }
  let nodes = 0;
  const stack = [[data, 1]];
  while (stack.length) {
    const [v, d] = stack.pop();
    if (++nodes > LIMITS.maxNodes) { rep.err(path, `more than ${LIMITS.maxNodes} JSON values`); return undefined; }
    if (d > LIMITS.maxDepth) { rep.err(path, `nesting deeper than ${LIMITS.maxDepth}`); return undefined; }
    if (v && typeof v === 'object') for (const k of Object.keys(v)) stack.push([v[k], d + 1]);
  }
  return data;
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
  for (const k of required) if (!(k in obj)) rep.err(where, `missing required property "${k}"`);
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
  if ('pattern' in schema) { try { new RegExp(schema.pattern, 'u'); } catch { errors.push(`${where}.pattern: invalid regular expression`); } }
  if (isObj(schema.$defs)) for (const [k, v] of Object.entries(schema.$defs)) lintSchema(v, `${where}.$defs.${k}`, errors);
  if (isObj(schema.properties)) for (const [k, v] of Object.entries(schema.properties)) lintSchema(v, `${where}.properties.${k}`, errors);
  if (isObj(schema.items)) lintSchema(schema.items, `${where}.items`, errors);
  if (isArr(schema.oneOf)) schema.oneOf.forEach((s, i) => lintSchema(s, `${where}.oneOf[${i}]`, errors));
}

function resolveRef(root, ref) {
  if (!ref.startsWith('#/')) throw new Error(`unsupported $ref ${ref}`);
  let cur = root;
  for (const part of ref.slice(2).split('/')) {
    if (!isObj(cur) || !(part in cur)) throw new Error(`unresolvable $ref ${ref}`);
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
  if (schema.$ref) return validateSchema(value, resolveRef(root, schema.$ref), root, p);
  if (typeof value === 'string' && LONE_SURROGATE.test(value)) errs.push(`${p}: contains a lone surrogate`);
  if ('const' in schema && value !== schema.const) errs.push(`${p}: must equal ${JSON.stringify(schema.const)}`);
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
    for (const k of schema.required || []) if (!(k in value)) errs.push(`${p}: missing required property "${k}"`);
    if (schema.additionalProperties === false) for (const k of Object.keys(value)) if (!(k in props)) errs.push(`${p}: unexpected property "${k}"`);
    if (schema.minProperties !== undefined && Object.keys(value).length < schema.minProperties) errs.push(`${p}: needs at least ${schema.minProperties} propert(ies)`);
    for (const [k, s] of Object.entries(props)) if (k in value) errs.push(...validateSchema(value[k], s, root, `${p}.${k}`));
  }
  if (schema.oneOf) {
    const results = schema.oneOf.map((s) => validateSchema(value, s, root, p));
    const passing = results.filter((r) => r.length === 0).length;
    if (passing !== 1) {
      // Report the branch whose discriminating const matches, so messages stay readable.
      const idx = schema.oneOf.findIndex((s) => {
        const b = s.$ref ? resolveRef(root, s.$ref) : s;
        return isObj(value) && b.properties && Object.entries(b.properties).some(([k, v]) => 'const' in v && value[k] === v.const);
      });
      if (passing > 1) errs.push(`${p}: matches more than one oneOf branch`);
      else if (idx >= 0) errs.push(...results[idx]);
      else errs.push(`${p}: matches no allowed variant${isObj(value) && 'verdict' in value ? ` (verdict ${JSON.stringify(value.verdict)} is not one of confirmed|needs_validation|rejected)` : ''}`);
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
};

function areaOf(classRef) {
  if (typeof classRef !== 'string') return 'Basics & other';
  const [file, name] = classRef.split('#');
  const pack = /^packs\/([\w-]+)\.md$/.exec(file);
  if (pack) return PACK_AREA[pack[1]] || 'Basics & other';
  return CORE_AREA[name] || 'Basics & other';
}

module.exports = { areaOf, LIMITS, Reporter, loadJson, isObj, isStr, isArr, isVisible, isAgentId, isRelPath, FINGERPRINT, INVISIBLE, checkKeys, dupes, lintSchema, validateSchema };
