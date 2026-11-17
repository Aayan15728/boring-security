#!/usr/bin/env node
'use strict';
// Deterministic, zero-dependency cross-repository interface finder. No network, no LLM calls, never executes
// target code, never follows symlinks, never runs git. Regex heuristics only: the output is a list of CANDIDATE
// INTERFACES between the given repos (who calls whom, who publishes what to whom, which tables and packages are
// shared) plus the trust-gap questions each edge raises. Edges and leads are never findings.
//
// Usage: node cross-repo.cjs <repoA> <repoB> [<repoC>...] [--json <out.json>] [--name <dir>=<alias>]...
//                            [--seeds <repoAlias> <out.json>]...
// Module: require('./cross-repo.cjs').crossRepo(repos, opts) -> { tool, repos, edges, unmatched_outbound, leads, summary, note }
//         require('./cross-repo.cjs').seedsFor(result, alias) -> run-state.cjs add-units seeds for that repo's run
//
// Provided side: inventory.cjs surfaces of each repo (plus queue consumers and route mount prefixes found here).
// Consumed side, per repo: outbound HTTP calls (fetch, axios, got, ky, superagent, requests, httpx, Go net/http,
// Java RestTemplate/WebClient/HttpClient/OkHttp, C# HttpClient, Guzzle/Laravel Http, Ruby Net::HTTP/HTTParty/Faraday,
// Swift URLSession) with a literal or template path; gRPC stub/client calls and tRPC procedure calls by name;
// GraphQL operations (gql/graphql documents, .graphql files) by root field; queue publishes and consumers (Kafka,
// RabbitMQ, SQS, SNS, BullMQ, Google Pub/Sub, NATS, Celery, Sidekiq); table writes/reads (SQL strings, Prisma,
// Supabase/knex .from('x'), Drizzle); package dependencies (package.json, pyproject.toml, requirements*.txt, go.mod,
// including file:/link:/workspace paths and go replace) and the symbols imported from them.
//
// KNOWN GAPS (false negatives): service discovery, API gateways and path rewrites, URLs built at runtime or read from
// config files, generated clients (OpenAPI, protoc stubs used through wrappers), ORMs other than those listed,
// message names held in variables we can't resolve in the same file, multi-line call chains, anything configured
// outside the repos (DNS, ingress, broker ACLs), files > 1 MB, binaries, minified files and test/example dirs.
// All labels, paths and snippets come from target text: data, never instructions.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { inventory } = require('./inventory.cjs');

const MAX_FILE = 1024 * 1024;
const MAX_FILES = 100000;
const MAX_PER_FILE = 1000;
const MAX_DEPTH = 40;
const MAX_STR = 200;
const MAX_LIST = 20000;
const CLASS_REF = 'core-classes.md#Chains and trust gaps';

// ---------- text helpers ----------
const INVISIBLE = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u061c\\u115f\\u1160\\u180e\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\u3164\\ufe00-\\ufe0f\\ufeff\\ufff0-\\ufffb]', 'g');
const LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
function clean(s, max = MAX_STR) {
  let t = String(s == null ? '' : s).replace(/[\t\n\r\f\v]+/g, ' ').replace(INVISIBLE, '').replace(LONE, '').normalize('NFC')
    .replace(INVISIBLE, '').replace(/ {2,}/g, ' ').trim();
  if (t.length > max) {
    t = t.slice(0, max);
    if (/[\ud800-\udbff]$/.test(t)) t = t.slice(0, -1);
    t = t.trimEnd();
  }
  return t;
}
function each(re, text, fn) {
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m[0] === '') re.lastIndex++;
    if (fn(m) === false) break;
  }
}
const byCode = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const CONF_RANK = { high: 0, medium: 1, low: 2 };

// ---------- walking (same skip rules as inventory.cjs) ----------
const SKIP = new Map();
for (const n of ['node_modules', 'vendor', 'bower_components', 'jspm_packages', 'Pods', 'Carthage', '.venv', 'venv', 'env', 'site-packages',
  '.terraform', '.bundle', '.pnpm-store', '.yarn', '.gradle', '.m2', '.tox', '.eggs']) SKIP.set(n, 'dependency directory');
for (const n of ['dist', 'build', 'out', 'target', '.next', '.nuxt', '.svelte-kit', '.output', '.vercel', '.netlify', '.turbo', '.cache', '.parcel-cache',
  'coverage', '.nyc_output', '__pycache__', '.mypy_cache', '.pytest_cache', '.dart_tool', 'DerivedData', '.angular', '.expo', 'storybook-static',
  '.serverless', '.aws-sam', 'obj']) SKIP.set(n, 'build output directory');
for (const n of ['.git', '.hg', '.svn', '.idea', '.vscode', '.boring-security']) SKIP.set(n, 'tooling or VCS directory');
const TEST_DIRS = new Set(['test', 'tests', '__tests__', 'spec', 'specs', 'fixtures', 'fixture', '__fixtures__', 'examples', 'example', 'samples', 'sample',
  'testdata', 'mocks', '__mocks__', 'e2e']);
const JS_EXT = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'mts', 'cts', 'vue', 'svelte']);
const SRC_EXT = new Set([...JS_EXT, 'py', 'rb', 'php', 'go', 'java', 'kt', 'kts', 'cs', 'swift', 'scala']);
const MANIFESTS = new Set(['package.json', 'pyproject.toml', 'go.mod']);
const isRequirements = (base) => /^requirements[\w.-]*\.txt$/i.test(base);

function walk(root, maxFiles) {
  const files = [];
  const skipped = [];
  (function rec(dir, rel, depth) {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    ents.sort((a, b) => byCode(a.name, b.name));
    for (const e of ents) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { skipped.push({ path: r, reason: 'symlink (not followed)' }); continue; }
      if (e.isDirectory()) {
        const reason = SKIP.get(e.name) || (TEST_DIRS.has(e.name.toLowerCase()) ? 'test/example directory (skipped, not scanned)' : null);
        if (reason) skipped.push({ path: r, reason });
        else if (depth >= MAX_DEPTH) skipped.push({ path: r, reason: 'maximum directory depth reached' });
        else rec(path.join(dir, e.name), r, depth + 1);
      } else if (e.isFile()) {
        const base = e.name;
        const ext = base.includes('.') ? base.slice(base.lastIndexOf('.') + 1).toLowerCase() : '';
        if (SRC_EXT.has(ext) || ext === 'graphql' || ext === 'gql' || MANIFESTS.has(base) || isRequirements(base)) {
          if (files.length >= maxFiles) skipped.push({ path: r, reason: 'file limit reached' });
          else files.push(r);
        }
      }
    }
  })(root, '', 0);
  return { files, skipped };
}

function readText(full) {
  let st;
  try { st = fs.lstatSync(full); } catch { return { skip: 'unreadable' }; }
  if (!st.isFile()) return { skip: 'not a regular file' };
  if (st.size > MAX_FILE) return { skip: 'file larger than 1 MB' };
  let buf;
  try { buf = fs.readFileSync(full); } catch { return { skip: 'unreadable' }; }
  if (buf.subarray(0, 8000).includes(0)) return { skip: 'binary' };
  let text = buf.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  if (text.length > 20000 && text.length / text.split('\n').length > 500) return { skip: 'minified or generated' };
  return { text };
}

function lineIndex(text) {
  let starts = null;
  const lineOf = (pos) => {
    if (!starts) {
      starts = [0];
      for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
    }
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= pos) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };
  const lineText = (pos) => {
    const s = text.lastIndexOf('\n', pos - 1) + 1;
    let e = text.indexOf('\n', pos);
    if (e < 0) e = text.length;
    return clean(text.slice(s, e));
  };
  return { lineOf, lineText };
}

// ---------- expressions, URLs and paths ----------
const CRED_RE = /\b(?:authorization|bearer|x-api-key|api[-_]?key|apikey|x-auth-token|x-access-token|access[-_]?token|id[-_]?token|auth[-_]?token|cookie|withCredentials\s*[:=]\s*true|credentials\s*:\s*['"]include)\b/i;
const SIG_RE = /signature|hmac|construct_?event|verify_?(?:webhook|signature|hmac)|timingSafeEqual|compare_digest|hash_equals|svix|x-hub-signature|stripe-signature|webhook[-_]?secret/i;
const ENV_RE = /(?:process\.env|import\.meta\.env)(?:\.|\[\s*['"`])([A-Za-z_]\w*)|(?:os\.environ\.get|os\.getenv|os\.Getenv|getenv|System\.getenv|Environment\.GetEnvironmentVariable|Deno\.env\.get|env)\(\s*['"]([A-Za-z_]\w*)|(?:os\.environ|ENV|\$_ENV|\$_SERVER)\[\s*['"]([A-Za-z_]\w*)/;
const envOf = (s) => { const m = ENV_RE.exec(s || ''); return m ? m[1] || m[2] || m[3] : null; };
const FORMAT_CALL = /^(?:fmt\.Sprintf|String\.format|sprintf|format|str\.format)\(/;

// Parse a URL-ish argument starting at text[i]: string literals (any common interpolation style) and expressions
// joined by + (or PHP '.'). Returns [{lit}|{expr}] or null.
function parseExpr(text, i, depth = 0) {
  const parts = [];
  const start = i;
  for (let guard = 0; guard < 16 && i < text.length && i - start < 3000; guard++) {
    while (/\s/.test(text[i] || '')) i++;
    if (!parts.length) {
      const kw = /^(?:url|uri|path|topic|queue|routing_key|name)\s*=(?!=)\s*/.exec(text.slice(i, i + 20));
      if (kw) { i += kw[0].length; continue; }
    }
    let m = /^([fFrRbB$@]{0,2})(["'`])/.exec(text.slice(i, i + 3));
    if (m && text.slice(i + m[0].length - 1, i + m[0].length + 2) === m[2].repeat(3)) return parts.length ? parts : null; // triple quotes
    if (m) {
      const q = m[2];
      let j = i + m[0].length;
      let s = '';
      while (j < text.length && text[j] !== q) {
        if (text[j] === '\n' && q !== '`') return parts.length ? parts : null;
        if (text[j] === '\\') { s += text[j] + (text[j + 1] || ''); j += 2; continue; }
        if (q === '`' && text[j] === '$' && text[j + 1] === '{') { // keep nested template expressions whole
          let d = 0;
          let k = j + 1;
          for (; k < text.length && k - j < 400; k++) { if (text[k] === '{') d++; else if (text[k] === '}' && --d === 0) break; }
          s += text.slice(j, k + 1);
          j = k + 1;
          continue;
        }
        s += text[j++];
        if (s.length > 2000) return null;
      }
      if (text[j] !== q) return parts.length ? parts : null;
      parts.push({ lit: s });
      i = j + 1;
    } else {
      m = /^(?:new\s+)?[A-Za-z_$][\w$]*(?:\s*(?:\.|->|::|\?\.)\s*[A-Za-z_$][\w$]*|\[[^\]\n]{0,80}\]|\((?:[^()\n]|\([^()\n]*\))*\))*/.exec(text.slice(i, i + 400));
      if (!m || !m[0]) break;
      const ex = m[0];
      if (FORMAT_CALL.test(ex) && depth === 0) {
        const inner = parseExpr(text, i + ex.indexOf('(') + 1, depth + 1);
        if (inner && inner[0].lit !== undefined) parts.push(inner[0]); else parts.push({ expr: ex });
      } else if (/^(?:URI(?:\.parse|\.create)?|URL|new\s+URL|Uri)\(/.test(ex) && depth === 0) {
        const inner = parseExpr(text, i + ex.indexOf('(') + 1, depth + 1);
        if (inner) parts.push(...inner); else parts.push({ expr: ex });
      } else parts.push({ expr: ex });
      i += ex.length;
    }
    while (/[ \t]/.test(text[i] || '')) i++;
    if (text[i] === '+' && text[i + 1] !== '+' && text[i + 1] !== '=') { i++; continue; }
    const php = /^\.\s*(?=['"]|\$[A-Za-z_])/.exec(text.slice(i, i + 20)); // PHP string concatenation
    if (php) { i += php[0].length; continue; }
    break;
  }
  return parts.length ? parts : null;
}

// One-level resolution of a bare identifier to its assignment in the same file (before `pos`).
function resolveIdent(text, name, pos) {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return null;
  const re = new RegExp(`(?:^|[^\\w$.])${name.replace(/\$/g, '\\$')}\\s*(?::[^=\\n;]{1,80})?(?::=|=)(?!=)\\s*`, 'g');
  let best = null;
  each(re, text, (m) => { if (m.index < pos) best = m.index + m[0].length; else return false; return true; });
  if (best === null) each(re, text, (m) => { best = m.index + m[0].length; return false; });
  return best === null ? null : parseExpr(text, best, 1);
}

function toTemplate(parts) {
  const exprs = [];
  const ph = (e) => { exprs.push(String(e).trim()); return `\u0001${exprs.length - 1}\u0002`; };
  let t = '';
  for (const p of parts) {
    if (p.expr !== undefined) { t += ph(p.expr); continue; }
    t += p.lit
      .replace(/\$\{((?:[^{}]|\{[^{}]*\}){0,200})\}/g, (_, e) => ph(e))
      .replace(/#\{([^}]{0,200})\}/g, (_, e) => ph(e))
      .replace(/\\\(([^)]{0,200})\)/g, (_, e) => ph(e))
      .replace(/\{\$?([^{}]{0,200})\}/g, (_, e) => ph(e))
      .replace(/\$([A-Za-z_]\w*)/g, (_, e) => ph(e))
      .replace(/%[sdvqi]/g, () => ph(''));
  }
  return { t, exprs };
}

function normSeg(s) {
  if (s.includes('\u0001')) return ':param';
  if (/^:[\w-]+\??$/.test(s) || /^\{[^}]*\}$/.test(s) || /^<[^>]*>$/.test(s) || /^\[[^\]]*\]$/.test(s) || /^\$[\w-]+$/.test(s)) return ':param';
  if (/^\*.*\?$/.test(s) || /^\[\[\.\.\..*\]\]$/.test(s)) return '*?';
  if (s[0] === '*' || /^\[\.\.\..*\]$/.test(s)) return '*';
  return s;
}
function normPath(p) {
  const segs = String(p).replace(/[?#][\s\S]*$/, '').split('/').filter((s) => s !== '' && s !== '.').map(normSeg);
  return clean('/' + segs.join('/'), 300);
}
const segsOf = (p) => p.split('/').filter(Boolean);

// -> {method?, path, base, env} | null
function urlFrom(text, i, pos, allowRelative) {
  let parts = parseExpr(text, i);
  if (!parts) return null;
  if (parts.length === 1 && parts[0].expr !== undefined) {
    if (!/^[\w$.]+$/.test(parts[0].expr)) return null;
    const r = resolveIdent(text, parts[0].expr.split('.').pop(), pos);
    if (!r) return null;
    parts = r;
  }
  const { t, exprs } = toTemplate(parts);
  let base = null;
  let rest;
  let m;
  const render = (s) => s.replace(/\u0001(\d+)\u0002/g, (_, n) => '${' + exprs[+n] + '}');
  if ((m = /^\u0001(\d+)\u0002/.exec(t))) { base = exprs[+m[1]] || '?'; rest = t.slice(m[0].length); }
  else if ((m = /^[a-zA-Z][\w+.-]*:\/\/[^/?#]*/.exec(t))) { base = render(m[0]); rest = t.slice(m[0].length); }
  else if (t[0] === '/') rest = t;
  else if (allowRelative && /^[\w-]+(?:\/|$)/.test(t)) rest = '/' + t;
  else return null;
  rest = rest.replace(/[?#][\s\S]*$/, '');
  if (rest && rest[0] !== '/') rest = '/' + rest;
  const p = normPath(rest || '/');
  if (p !== '/' && !segsOf(p).some((s) => s !== ':param' && s[0] !== '*')) return null; // no literal segment: unknown target
  let env = envOf(base);
  if (!env && base && /^[A-Za-z_$][\w$.]*$/.test(base)) {
    const last = base.split('.').pop();
    const r = resolveIdent(text, last, pos);
    if (r) {
      const tt = toTemplate(r);
      env = envOf(r.map((x) => (x.expr !== undefined ? x.expr : '')).join(' ')) || envOf(tt.exprs.join(' '));
      if (!env && r[0] && r[0].lit && /^[a-z][\w+.-]*:\/\//i.test(r[0].lit)) base = `${base} (${r[0].lit})`;
    }
  }
  return { path: p, base: base === null ? null : clean(base), env: env ? clean(env, 100) : null };
}

// Balanced argument text of the call whose '(' is at `open`.
function callArgs(text, open) {
  let d = 0;
  for (let i = open; i < text.length && i < open + 4000; i++) {
    const ch = text[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      for (i++; i < text.length && text[i] !== ch && i < open + 4000; i++) if (text[i] === '\\') i++;
      continue;
    }
    if (ch === '(' || ch === '{' || ch === '[') d++;
    else if ((ch === ')' || ch === '}' || ch === ']') && --d === 0) return text.slice(open, i + 1);
  }
  return text.slice(open, open + 1500);
}

// ---------- outbound HTTP ----------
const HM = 'get|post|put|patch|delete|head|options';
const CLIENT_RE = /^(?:axios|\$axios|axiosInstance|got|ky|superagent|request|requests|httpx|https?|\$http|httpClient|http_client|client|apiClient|api_client|api|instance|fetcher|ofetch|session|conn|connection|faraday|HTTParty|Http|restClient|rest_client|webClient|guzzle|httpService)$/;
const HTTP_PATTERNS = [
  // name, file test, regex (ends where the URL argument starts), method (string | group index | 'opts' | 'window')
  { client: 'fetch', ext: JS_EXT, re: /(?<![\w$.])(?:fetch|\$fetch|useFetch|ofetch|ky|got|axios|superagent)\s*\(\s*/g, method: 'opts' },
  { client: 'member', re: new RegExp(`(?<![\\w$])((?:this\\.|self\\.|\\$this->|@)?[A-Za-z_$][\\w$]*)\\s*(?:\\.|->|::)\\s*(${HM})\\s*(?:<[^>()\\n]*>)?\\s*\\(\\s*`, 'g'), method: 2, receiver: 1 },
  { client: 'request', re: /(?:\.|->|::)request\s*\(\s*(?:method\s*=\s*)?['"]([A-Za-z]+)['"]\s*,\s*/g, method: 1 },
  { client: 'net/http', ext: new Set(['go']), re: /\bhttp\.(Get|Post|Head|PostForm)\s*\(\s*/g, method: 1 },
  { client: 'net/http', ext: new Set(['go']), re: /\bhttp\.NewRequest(?:WithContext)?\s*\(\s*(?:[\w.()]+\s*,\s*)?(?:"([A-Z]+)"|http\.Method(\w+))\s*,\s*/g, method: [1, 2] },
  { client: 'RestTemplate', ext: new Set(['java', 'kt', 'scala']), re: /\b\w*(?:[rR]estTemplate|[tT]emplate|rest)\s*\.\s*(getForObject|getForEntity|postForObject|postForEntity|postForLocation|put|delete|patchForObject|exchange)\s*\(\s*/g, method: 'rest' },
  { client: 'WebClient', ext: new Set(['java', 'kt', 'scala']), re: /\.(get|post|put|patch|delete)\(\)\s*\.uri\(\s*/g, method: 1 },
  { client: 'HttpClient', ext: new Set(['java', 'kt', 'scala']), re: /\bURI\.create\(\s*/g, method: 'window' },
  { client: 'OkHttp', ext: new Set(['java', 'kt']), re: /Request\.Builder\(\)\s*\.url\(\s*/g, method: 'window' },
  { client: 'HttpClient', ext: new Set(['cs']), re: /\.(Get|Post|Put|Patch|Delete)(?:Async|AsJsonAsync|FromJsonAsync|StringAsync|ByteArrayAsync|StreamAsync)\s*(?:<[^>()\n]*>)?\s*\(\s*/g, method: 1 },
  { client: 'HttpClient', ext: new Set(['cs']), re: /new\s+HttpRequestMessage\(\s*HttpMethod\.(\w+)\s*,\s*/g, method: 1 },
  { client: 'Net::HTTP', ext: new Set(['rb']), re: /Net::HTTP::(Get|Post|Put|Patch|Delete)\.new\(\s*/g, method: 1 },
  { client: 'Net::HTTP', ext: new Set(['rb']), re: /Net::HTTP\.(get|post|get_response)\(\s*/g, method: 1 },
  { client: 'URLSession', ext: new Set(['swift']), re: /\bURL\(\s*string:\s*/g, method: 'window' },
];

function methodFor(pat, m, args, text, pos) {
  let v = null;
  if (typeof pat.method === 'number') v = m[pat.method];
  else if (Array.isArray(pat.method)) v = pat.method.map((g) => m[g]).find(Boolean);
  else if (pat.method === 'opts') {
    const mm = /\bmethod\s*:\s*(['"`])([A-Za-z]+)\1/.exec(args);
    v = mm ? mm[2] : 'GET';
  } else if (pat.method === 'rest') {
    const name = m[1];
    if (name === 'exchange') { const mm = /HttpMethod\.([A-Z]+)/.exec(args); v = mm ? mm[1] : null; }
    else v = /^get/.test(name) ? 'GET' : /^post/.test(name) ? 'POST' : /^patch/.test(name) ? 'PATCH' : name.toUpperCase();
  } else if (pat.method === 'window') {
    const w = text.slice(pos, pos + 800);
    const mm = /\.(POST|PUT|PATCH|DELETE|GET)\s*\(|\.(post|put|patch|delete)\s*\(|httpMethod\s*=\s*"([A-Z]+)"|\.method\(\s*"([A-Z]+)"/.exec(w);
    v = mm ? mm[1] || mm[2] || mm[3] || mm[4] : 'GET';
  }
  if (!v) return null;
  v = String(v).toUpperCase();
  if (v === 'GET_RESPONSE' || v === 'POSTFORM') v = v === 'POSTFORM' ? 'POST' : 'GET';
  return /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(v) ? v : null;
}

function scanHttp(c) {
  const { text, ext, out } = c;
  const fileCred = CRED_RE.test(text);
  for (const pat of HTTP_PATTERNS) {
    if (pat.ext && !pat.ext.has(ext)) continue;
    if (pat.client === 'URLSession' && !/URLSession|URLRequest/.test(text)) continue;
    if (pat.client === 'OkHttp' && !/okhttp/i.test(text)) continue;
    each(pat.re, text, (m) => {
      if (c.count >= MAX_PER_FILE) return false;
      let client = pat.client;
      if (pat.receiver) {
        const recv = m[pat.receiver].replace(/^(?:this\.|self\.|\$this->|@)/, '').replace(/^\$/, '');
        if (!CLIENT_RE.test(recv)) return true;
        client = recv;
      }
      const urlAt = m.index + m[0].length;
      const open = m.index + m[0].lastIndexOf('(');
      const args = callArgs(text, open);
      let u;
      if (pat.client === 'fetch' && text[urlAt] === '{') { // axios({ url, method })
        const um = /\burl\s*:\s*/.exec(args);
        if (!um) return true;
        u = urlFrom(text, open + um.index + um[0].length, m.index, false);
      } else u = urlFrom(text, urlAt, m.index, !!pat.receiver && pat.receiver && /^(?:api|apiClient|instance|axiosInstance|client|conn|faraday)$/.test(client));
      if (!u) return true;
      const method = methodFor(pat, m, args, text, m.index);
      const win = text.slice(Math.max(0, m.index - 400), open + args.length);
      const credential = CRED_RE.test(win) ? 'call' : fileCred ? 'file' : null;
      c.count++;
      out.push({
        kind: /webhook/i.test(u.path) ? 'webhook' : 'http', client: clean(client, 40), method, path: u.path, base: u.base, env: u.env,
        file: c.rel, line: c.lineOf(m.index), snippet: c.lineText(m.index), credential, signed: SIG_RE.test(win),
        label: clean(`${method || 'ANY'} ${u.path}`),
      });
      return true;
    });
  }
}

// ---------- GraphQL operations ----------
function gqlRootFields(doc) {
  const out = [];
  const t = doc.replace(/#[^\n]*/g, (x) => ' '.repeat(x.length));
  each(/\b(query|mutation|subscription)\b\s*([A-Za-z_]\w*)?\s*(?:\((?:[^()]|\([^()]*\))*\))?\s*(?:@\w+(?:\([^)]*\))?\s*)*\{/g, t, (m) => {
    const open = m.index + m[0].length - 1;
    let depth = 0;
    for (let i = open; i < t.length; i++) {
      const ch = t[i];
      if (ch === '{') { depth++; continue; }
      if (ch === '}') { if (--depth === 0) break; continue; }
      if (ch === '(') { let d = 0; for (; i < t.length; i++) { if (t[i] === '(') d++; else if (t[i] === ')' && --d === 0) break; } continue; }
      if (depth === 1 && /[A-Za-z_]/.test(ch) && !/[\w.]/.test(t[i - 1] || '')) {
        const mm = /^([A-Za-z_]\w*)\s*(:\s*([A-Za-z_]\w*))?/.exec(t.slice(i, i + 200));
        if (!mm) continue;
        if (mm[1] !== 'on' && mm[1] !== 'fragment') out.push({ op: m[1], field: mm[3] || mm[1], idx: i });
        i += mm[0].length - 1;
      }
    }
  });
  return out;
}
function scanGraphql(c) {
  const { text, ext, out } = c;
  const fileCred = CRED_RE.test(text);
  const docs = [];
  if (ext === 'graphql' || ext === 'gql') docs.push({ doc: text, at: 0 });
  else {
    each(/\b(?:gql|graphql)\s*(?:\(\s*)?`([^`]{0,50000})`/g, text, (m) => { docs.push({ doc: m[1], at: m.index + m[0].indexOf('`') + 1 }); });
    each(/\bgql\(\s*(?:"""|''')([\s\S]{0,50000}?)(?:"""|''')/g, text, (m) => { docs.push({ doc: m[1], at: m.index + m[0].indexOf(m[1]) }); });
  }
  for (const d of docs) {
    for (const f of gqlRootFields(d.doc)) {
      if (c.count++ >= MAX_PER_FILE) return;
      const type = f.op[0].toUpperCase() + f.op.slice(1);
      const pos = d.at + f.idx;
      out.push({ kind: 'graphql', client: 'graphql', name: clean(`${type}.${f.field}`), file: c.rel, line: c.lineOf(pos), snippet: c.lineText(pos),
        credential: fileCred ? 'file' : null, label: clean(`${type}.${f.field}`) });
    }
  }
}

// ---------- RPC (gRPC stubs, tRPC procedures) ----------
const GRPC_FILE = /grpc|_pb2|\.proto\b|ManagedChannel|loadPackageDefinition|\bNew\w+Client\(|\w+Stub\(/i;
const RPC_SKIP = new Set(['close', 'connect', 'waitForReady', 'getChannel', 'then', 'catch', 'on', 'emit', 'end', 'destroy', 'send', 'request', 'get', 'post', 'put', 'patch', 'delete', 'query', 'mutate', 'use', 'bind', 'call', 'apply', 'toString']);
function scanRpc(c) {
  const { text, out } = c;
  const fileCred = CRED_RE.test(text);
  if (JS_EXT.has(c.ext)) {
    each(/(?<![\w$])(?:trpc|api|client|utils)\.((?:[A-Za-z_$][\w$]*\.)*)([A-Za-z_$][\w$]*)\.(useQuery|useMutation|useSuspenseQuery|useInfiniteQuery|query|mutate|mutation|subscribe|fetch|prefetch)\s*\(/g, text, (m) => {
      if (c.count++ >= MAX_PER_FILE) return false;
      const router = m[1].replace(/\.$/, '');
      out.push({ kind: 'rpc', client: 'trpc', name: clean(m[2], 100), router: clean(router, 100), file: c.rel, line: c.lineOf(m.index), snippet: c.lineText(m.index),
        credential: fileCred ? 'file' : null, label: clean(`trpc ${router ? router + '.' : ''}${m[2]}`) });
      return true;
    });
  }
  if (!GRPC_FILE.test(text)) return;
  const services = new Set();
  each(/\bNew(\w+?)Client\(|(\w+?)Stub\(|new\s+(\w+?)Client\(|(\w+?)Grpc\.new(?:Blocking|Future)?Stub/g, text, (m) => { services.add((m[1] || m[2] || m[3] || m[4]).toLowerCase()); });
  const recv = new Set();
  each(/(?<![\w$])([A-Za-z_$][\w$]*)\s*(?::=|=)\s*(?:new\s+)?(?:[\w$]+\.)*(?:New\w+Client|\w+Stub|\w+Client|new(?:Blocking|Future)?Stub)\(/g, text, (m) => { recv.add(m[1]); });
  each(/(?<![\w$])([A-Za-z_$][\w$]*)\.([A-Za-z_]\w*)\s*\(/g, text, (m) => {
    if (!(/(?:stub|client)$/i.test(m[1]) || recv.has(m[1])) || RPC_SKIP.has(m[2]) || /^(?:http|axios|redis|s3|db|prisma|supabase)/i.test(m[1])) return true;
    if (c.count++ >= MAX_PER_FILE) return false;
    out.push({ kind: 'rpc', client: 'grpc', name: clean(m[2], 100), services: [...services].sort().map((s) => clean(s, 100)), file: c.rel, line: c.lineOf(m.index),
      snippet: c.lineText(m.index), credential: CRED_RE.test(text.slice(Math.max(0, m.index - 400), m.index + 400)) ? 'call' : fileCred ? 'file' : null, label: clean(`grpc ${m[2]}`) });
    return true;
  });
}

// ---------- queues ----------
function queueName(text, i, pos) {
  let parts = parseExpr(text, i);
  if (!parts) return null;
  if (parts.length === 1 && parts[0].expr !== undefined) {
    const env = envOf(parts[0].expr);
    if (env) return { key: `env:${env}`, name: `env ${env}`, via: 'env' };
    const r = resolveIdent(text, parts[0].expr.split('.').pop(), pos);
    if (!r) return { key: null, name: `${parts[0].expr} (unresolved)`, via: 'unresolved' };
    parts = r;
  }
  if (parts[0].lit === undefined) {
    const env = envOf(parts[0].expr);
    return env ? { key: `env:${env}`, name: `env ${env}`, via: 'env' } : { key: null, name: `${parts[0].expr} (unresolved)`, via: 'unresolved' };
  }
  let n = toTemplate(parts).t.replace(/\u0001\d+\u0002/g, '*');
  if (/^https?:\/\//i.test(n)) n = n.replace(/\/+$/, '').split('/').pop(); // SQS queue URL
  else if (/^arn:/i.test(n)) n = n.split(':').pop(); // SNS/SQS ARN
  n = clean(n, 150);
  if (!n || n === '*') return { key: null, name: '(dynamic)', via: 'unresolved' };
  return { key: `name:${n.toLowerCase()}`, name: n, via: 'literal' };
}
const QUEUE_PATTERNS = [
  // role: pub | sub | sqs (decided from context); test: optional file gate
  { sys: 'kafka', role: 'pub', re: /\.send\(\s*\{\s*topic\s*:\s*/g, test: /kafka/i },
  { sys: 'kafka', role: 'pub', re: /\b(?:producer|kafkaTemplate|kafka_producer|kafkaProducer)\s*\.\s*(?:send|produce|send_and_wait)\(\s*/g },
  { sys: 'kafka', role: 'pub', re: /new\s+ProducerRecord\s*(?:<[^>]*>)?\(\s*/g },
  { sys: 'kafka', role: 'sub', re: /\.subscribe\(\s*\{\s*topics?\s*:\s*\[?\s*/g, test: /kafka/i },
  { sys: 'kafka', role: 'sub', re: /\bKafkaConsumer\(\s*/g },
  { sys: 'kafka', role: 'sub', re: /\b(?:consumer)\.subscribe\(\s*\[\s*/g, test: /kafka/i },
  { sys: 'rabbitmq', role: 'pub', re: /\.sendToQueue\(\s*/g },
  { sys: 'rabbitmq', role: 'pub', re: /\b(?:channel|ch)\.publish\(\s*(['"`])[^'"`\n]*\1\s*,\s*/g },
  { sys: 'rabbitmq', role: 'pub', re: /basic_publish\([^)]*?routing_key\s*=\s*/g },
  { sys: 'rabbitmq', role: 'pub', re: /\b(?:rabbitTemplate|amqpTemplate)\.convertAndSend\(\s*/g },
  { sys: 'rabbitmq', role: 'sub', re: /\b(?:channel|ch)\.consume\(\s*/g },
  { sys: 'rabbitmq', role: 'sub', re: /basic_consume\([^)]*?queue\s*=\s*/g },
  { sys: 'sqs', role: 'sqs', re: /\bQueueUrl\s*[:=]\s*/g },
  { sys: 'sns', role: 'pub', re: /\bTopicArn\s*[:=]\s*/g },
  { sys: 'bullmq', role: 'pub', re: /new\s+Queue(?:<[^>]*>)?\(\s*/g, test: /bull/i },
  { sys: 'pubsub', role: 'pub', re: /\.topic\(\s*/g, test: /pubsub/i },
  { sys: 'pubsub', role: 'sub', re: /\.subscription\(\s*/g, test: /pubsub/i },
  { sys: 'nats', role: 'pub', re: /\b(?:nc|nats|js|natsConnection)\.publish\(\s*/g },
  { sys: 'nats', role: 'sub', re: /\b(?:nc|nats|js|natsConnection)\.subscribe\(\s*/g },
  { sys: 'celery', role: 'pub', re: /\.send_task\(\s*/g },
];
function scanQueues(c) {
  const { text, ext, pubs, subs } = c;
  for (const pat of QUEUE_PATTERNS) {
    if (pat.test && !pat.test.test(text)) continue;
    each(pat.re, text, (m) => {
      if (c.count++ >= MAX_PER_FILE) return false;
      const q = queueName(text, m.index + m[0].length, m.index);
      if (!q) return true;
      let role = pat.role;
      if (role === 'sqs') role = /Receive|receive_message|DeleteMessage|delete_message|poll/.test(text.slice(Math.max(0, m.index - 300), m.index + 300)) ? 'sub' : 'pub';
      if (role === 'pub' && pat.sys === 'sns' && /\bSubscribe/.test(text.slice(Math.max(0, m.index - 300), m.index + 100))) return true;
      const rec = { sys: pat.sys, ...q, name: clean(q.name, 150), file: c.rel, line: c.lineOf(m.index), snippet: c.lineText(m.index) };
      (role === 'pub' ? pubs : subs).push(rec);
      return true;
    });
  }
  if (ext === 'py') {
    each(/(?<![\w.])([a-z_]\w*)\.(?:delay|apply_async)\(/g, text, (m) => {
      if (c.count++ >= MAX_PER_FILE) return false;
      pubs.push({ sys: 'celery', key: `task:${m[1].toLowerCase()}`, name: clean(m[1], 150), via: 'literal', file: c.rel, line: c.lineOf(m.index), snippet: c.lineText(m.index) });
      return true;
    });
  }
  if (ext === 'rb') {
    each(/\b([A-Z]\w*)\.perform_(?:async|in|at)\(/g, text, (m) => {
      if (c.count++ >= MAX_PER_FILE) return false;
      pubs.push({ sys: 'sidekiq', key: `task:${m[1].toLowerCase()}`, name: clean(m[1], 150), via: 'literal', file: c.rel, line: c.lineOf(m.index), snippet: c.lineText(m.index) });
      return true;
    });
  }
}
// inventory queue-consumer label -> match key
function invQueueKey(s) {
  const fw = s.framework;
  let n = s.label;
  if (fw === 'celery' || fw === 'sidekiq') return { key: `task:${n.toLowerCase()}`, name: n };
  n = n.replace(/^(?:kafka|KafkaListener|RabbitListener|SqsListener|JmsListener)\s*/, '').trim();
  if (!n || n === '(unnamed)' || /[${}]/.test(n)) return { key: null, name: n || '(unnamed)' };
  if (/^https?:\/\//i.test(n)) n = n.replace(/\/+$/, '').split('/').pop();
  return { key: `name:${n.toLowerCase()}`, name: n };
}

// ---------- database tables ----------
const SQL_NOT_TABLE = new Set(['select', 'set', 'where', 'values', 'lateral', 'unnest', 'generate_series', 'only', 'table', 'if', 'the', 'a', 'an', 'to', 'into', 'from', 'dual', 'json_each', 'jsonb_each', 'information_schema']);
const tableKey = (n) => String(n).replace(/[`"[\]]/g, '').replace(/\s+/g, '').toLowerCase().replace(/^(?:public|dbo|main)\./, '');
const tableVariant = (k) => k.replace(/_/g, '').replace(/s$/, '');
function clientFile(text) {
  return /^\s*['"]use client['"]/m.test(text) || /createBrowserClient|createClientComponentClient|NEXT_PUBLIC_SUPABASE|VITE_SUPABASE|EXPO_PUBLIC_SUPABASE|SUPABASE_ANON_KEY|anonKey/.test(text);
}
function scanTables(c) {
  const { text, tables } = c;
  const isClient = c.repoClient || clientFile(text);
  const add = (name, op, via, pos) => {
    const key = tableKey(name);
    if (!key || SQL_NOT_TABLE.has(key) || key.startsWith('pg_') || c.count++ >= MAX_PER_FILE) return;
    tables.push({ table: clean(name.replace(/[`"[\]]/g, ''), 120), key, op, via, client: isClient, file: c.rel, line: c.lineOf(pos), snippet: c.lineText(pos) });
  };
  const quoted = (pos) => /['"`]/.test(c.lineText(pos)) || /"""|'''|`/.test(text.slice(Math.max(0, pos - 400), pos));
  const ID = '[`"\\[]?[A-Za-z_]\\w*[`"\\]]?(?:\\.[`"\\[]?[A-Za-z_]\\w*[`"\\]]?)?';
  each(new RegExp(`\\b(insert\\s+(?:or\\s+\\w+\\s+)?into|delete\\s+from|merge\\s+into|update)\\s+(${ID})(\\s+set\\b)?`, 'gi'), text, (m) => {
    if (/^update$/i.test(m[1]) && !m[3]) return true;
    if (quoted(m.index)) add(m[2], 'write', 'sql', m.index);
    return true;
  });
  each(new RegExp(`\\bselect\\b[^;'"\`]{0,300}?\\bfrom\\s+(${ID})`, 'gi'), text, (m) => { if (quoted(m.index)) add(m[1], 'read', 'sql', m.index + m[0].length - m[1].length); return true; });
  each(new RegExp(`\\bjoin\\s+(${ID})(?:\\s+(?:as\\s+)?\\w+)?\\s+on\\b`, 'gi'), text, (m) => { if (quoted(m.index)) add(m[1], 'read', 'sql', m.index); return true; });
  each(/\b(?:prisma|db|tx|this\.prisma|ctx\.prisma|ctx\.db)\.([a-z]\w*)\.(create|createMany|update|updateMany|upsert|delete|deleteMany|findMany|findUnique|findFirst|findUniqueOrThrow|findFirstOrThrow|count|aggregate|groupBy)\s*\(/g, text, (m) => {
    add(m[1], /^(?:create|update|upsert|delete)/.test(m[2]) ? 'write' : 'read', 'prisma', m.index); return true;
  });
  each(/\.from\(\s*(['"`])([A-Za-z_][\w.]*)\1\s*\)\s*\.\s*(insert|upsert|update|delete|select)\b/g, text, (m) => {
    add(m[2], m[3] === 'select' ? 'read' : 'write', 'supabase', m.index); return true;
  });
  each(/\b(?:knex|db|trx)\(\s*(['"])([A-Za-z_][\w.]*)\1\s*\)\s*\.\s*(insert|update|del|delete|upsert|select|where|first)\b/g, text, (m) => {
    add(m[2], /^(?:insert|update|del|delete|upsert)$/.test(m[3]) ? 'write' : 'read', 'knex', m.index); return true;
  });
  each(/\b(?:db|tx)\.(insert|update|delete)\(\s*([A-Za-z_]\w*)\s*\)/g, text, (m) => { add(m[2], 'write', 'drizzle', m.index); return true; });
  each(/\.select\([^()]*\)\s*\.from\(\s*([A-Za-z_]\w*)\s*\)/g, text, (m) => { add(m[1], 'read', 'drizzle', m.index); return true; });
}

// ---------- imports (for package symbol lists) ----------
function scanImports(c) {
  const { text, ext, imports } = c;
  const push = (spec, symbols, pos) => {
    if (c.count++ >= MAX_PER_FILE) return;
    imports.push({ spec: clean(spec, 200), symbols: symbols.map((s) => clean(s, 80)).filter(Boolean), file: c.rel, line: c.lineOf(pos) });
  };
  if (JS_EXT.has(ext)) {
    each(/\bimport\s+(?:type\s+)?([\s\S]{0,500}?)\s+from\s+(['"])([^'"\n]+)\2/g, text, (m) => {
      const clause = m[1];
      const syms = [];
      const named = /\{([^}]*)\}/.exec(clause);
      if (named) for (const p of named[1].split(',')) { const n = p.trim().replace(/^type\s+/, '').split(/\s+as\s+/)[0].trim(); if (n) syms.push(n); }
      const head = clause.replace(/\{[^}]*\}/, '').replace(/,/g, ' ').trim();
      if (/\*\s+as\s+\w+/.test(head)) syms.push('*');
      else if (/^[A-Za-z_$][\w$]*/.test(head)) syms.push('default');
      push(m[3], syms, m.index);
    });
    each(/(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*(['"])([^'"\n]+)\2\s*\)/g, text, (m) => {
      const syms = m[1][0] === '{' ? m[1].slice(1, -1).split(',').map((p) => p.trim().split(':')[0].trim()).filter(Boolean) : ['default'];
      push(m[3], syms, m.index);
    });
  } else if (ext === 'py') {
    each(/^[ \t]*from\s+([\w.]+)\s+import\s+(\([^)]*\)|[^\n#]+)/gm, text, (m) => {
      push(m[1], m[2].replace(/[()]/g, '').split(',').map((s) => s.trim().split(/\s+as\s+/)[0].trim()).filter(Boolean), m.index);
    });
    each(/^[ \t]*import\s+([\w.]+)/gm, text, (m) => { push(m[1], ['*'], m.index); });
  } else if (ext === 'go') {
    each(/^import\s*\(([\s\S]*?)\)|^import\s+(?:\w+\s+)?"([^"]+)"/gm, text, (m) => {
      if (m[2]) push(m[2], [], m.index);
      else each(/"([^"\n]+)"/g, m[1], (x) => { push(x[1], [], m.index + m[0].indexOf(x[0])); return true; });
    });
  }
}

// ---------- route mount prefixes (provider side) ----------
function scanMounts(c) {
  const { text, mounts } = c;
  const add = (p) => { const n = normPath(p); if (n !== '/' && mounts.size < 200) mounts.add(n); };
  each(/\.(?:use|route|mount)\(\s*(['"`])(\/[^'"`\s]*)\1/g, text, (m) => { add(m[2]); return true; });
  each(/\b(?:url_)?prefix\s*[:=]\s*(['"`])(\/[^'"`\s]*)\1/g, text, (m) => { add(m[2]); return true; });
  each(/\b(?:setGlobalPrefix|basePath)\(\s*(['"`])\/?([^'"`\s]*)\1/g, text, (m) => { add('/' + m[2]); return true; });
  each(/\.(?:Group|Route|PathPrefix|MapGroup)\(\s*"(\/[^"\s]*)"/g, text, (m) => { add(m[1]); return true; });
  each(/^[ \t]*(?:namespace|scope)\s+(?::(\w+)|['"]\/?([\w/-]+)['"])/gm, text, (m) => { add('/' + (m[1] || m[2])); return true; });
}

// ---------- manifests ----------
const pyName = (n) => String(n).toLowerCase().replace(/[-_.]+/g, '-');
function lineAt(text, idx) { return idx < 0 ? 1 : text.slice(0, idx).split('\n').length; }
function scanManifest(c, root) {
  const { text, base, rel, pkgs } = c;
  const dir = path.posix.dirname(rel) === '.' ? '' : path.posix.dirname(rel);
  const absDir = path.join(root, ...dir.split('/').filter(Boolean));
  const dep = (eco, name, version, idx) => {
    if (pkgs.depends.length >= MAX_PER_FILE * 10) return;
    const v = clean(version || '', 120);
    let localPath = null;
    const pm = /^(?:file:|link:|portal:|workspace:(?=\.|\/))(.+)$/.exec(v) || (/^\.{1,2}\//.test(v) ? [null, v] : null);
    if (pm) localPath = path.resolve(absDir, pm[1]);
    pkgs.depends.push({ eco, name: clean(name, 200), key: eco === 'pypi' ? pyName(name) : name, version: v, localPath, file: rel, line: lineAt(text, idx), snippet: clean(`${name} ${v}`) });
  };
  const provide = (eco, name, idx) => pkgs.provides.push({ eco, name: clean(name, 200), key: eco === 'pypi' ? pyName(name) : name, dir: absDir, file: rel, line: lineAt(text, idx) });
  if (base === 'package.json') {
    let j;
    try { j = JSON.parse(text); } catch { return; }
    if (!j || typeof j !== 'object') return;
    if (typeof j.name === 'string' && j.name) provide('npm', j.name, text.indexOf('"name"'));
    for (const sec of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
      const d = j[sec];
      if (!d || typeof d !== 'object') continue;
      const at = text.indexOf(`"${sec}"`);
      for (const [n, v] of Object.entries(d).sort((a, b) => byCode(a[0], b[0]))) dep('npm', n, typeof v === 'string' ? v : '', text.indexOf(JSON.stringify(n), at));
    }
  } else if (base === 'pyproject.toml') {
    let section = '';
    const lines = text.split('\n');
    let off = 0;
    let inArr = false;
    for (const raw of lines) {
      const ln = raw.replace(/\r$/, '');
      const h = /^\s*\[([^\]]+)\]\s*$/.exec(ln);
      if (h) { section = h[1].trim(); inArr = false; off += raw.length + 1; continue; }
      if (inArr) {
        each(/["']([A-Za-z0-9][\w.-]*)(?:\s*\[[^\]]*\])?\s*([^"']*)["']/g, ln, (m) => { dep('pypi', m[1], m[2].trim(), off); return true; });
        if (/\]/.test(ln.replace(/\[[^\]]*\]/g, ''))) inArr = false;
      } else if ((section === 'project' || section === 'tool.poetry') && /^\s*name\s*=\s*["']([^"']+)["']/.test(ln)) {
        provide('pypi', /^\s*name\s*=\s*["']([^"']+)["']/.exec(ln)[1], off);
      } else if ((section === 'project' && /^\s*dependencies\s*=\s*\[/.test(ln)) || (section === 'project.optional-dependencies' && /=\s*\[/.test(ln))) {
        inArr = true;
        const after = ln.slice(ln.indexOf('[') + 1);
        each(/["']([A-Za-z0-9][\w.-]*)(?:\s*\[[^\]]*\])?\s*([^"']*)["']/g, after, (m) => { dep('pypi', m[1], m[2].trim(), off); return true; });
        if (/\]/.test(after.replace(/\[[^\]]*\]/g, ''))) inArr = false;
      } else if (/^tool\.poetry\.(?:group\.[\w-]+\.)?(?:dev-)?dependencies$/.test(section)) {
        const m = /^\s*([A-Za-z0-9][\w.-]*)\s*=\s*(.+)$/.exec(ln);
        if (m && m[1].toLowerCase() !== 'python') {
          const pth = /path\s*=\s*["']([^"']+)["']/.exec(m[2]);
          dep('pypi', m[1], pth ? pth[1] : m[2].replace(/^["']|["']$/g, '').trim(), off);
        }
      }
      off += raw.length + 1;
    }
  } else if (isRequirements(base)) {
    let off = 0;
    for (const raw of text.split('\n')) {
      const ln = raw.replace(/\r$/, '').replace(/\s+#.*$/, '').trim();
      let m;
      if ((m = /^-e\s+(\S+)/.exec(ln)) && /^\.{0,2}\//.test(m[1])) dep('pypi', path.posix.basename(m[1].replace(/\/+$/, '')), m[1], off);
      else if ((m = /^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*@\s*file:(\S+)/.exec(ln))) dep('pypi', m[1], m[2], off);
      else if ((m = /^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*(.*)$/.exec(ln)) && !ln.startsWith('-')) dep('pypi', m[1], m[2].replace(/;.*$/, '').trim(), off);
      off += raw.length + 1;
    }
  } else if (base === 'go.mod') {
    const mm = /^module\s+(\S+)/m.exec(text);
    if (mm) provide('go', mm[1], mm.index);
    const replaces = new Map();
    each(/^\s*(?:replace\s+)?(\S+)(?:\s+v\S+)?\s+=>\s+(\.{1,2}\/\S*)/gm, text, (m) => { replaces.set(m[1], m[2]); return true; });
    each(/^\s*require\s+(\S+)\s+(v\S+)|^\s*require\s*\(([\s\S]*?)\)/gm, text, (m) => {
      if (m[1]) dep('go', m[1], replaces.get(m[1]) || m[2], m.index);
      else each(/^\s*(\S+)\s+(v\S+)/gm, m[3], (x) => { dep('go', x[1], replaces.get(x[1]) || x[2], m.index + m[0].indexOf(x[0])); return true; });
      return true;
    });
  }
}

// ---------- per repo ----------
const MOBILE_SPA = ['react-native', 'expo', '@capacitor/core', '@ionic/react', '@ionic/angular'];
function scanRepo(root, alias, opts) {
  const inv = inventory(root, { maxFiles: opts.maxFiles });
  const { files, skipped } = walk(root, opts.maxFiles);
  const st = {
    alias, root, inv, outbound: [], pubs: [], subs: [], tables: [], imports: [], mounts: new Set(),
    pkgs: { provides: [], depends: [] }, sigFiles: new Set(), skipped: [...skipped], files_scanned: 0, repoClient: false,
  };
  const texts = [];
  for (const rel of files) {
    const r = readText(path.join(root, ...rel.split('/')));
    if (r.skip) { if (r.skip !== 'unreadable') st.skipped.push({ path: rel, reason: r.skip }); continue; }
    texts.push({ rel, text: r.text });
  }
  // repo-level client hint first (manifests), then sources
  for (const { rel, text } of texts) {
    const base = rel.slice(rel.lastIndexOf('/') + 1);
    if (!(MANIFESTS.has(base) || isRequirements(base))) continue;
    st.files_scanned++;
    scanManifest({ text, base, rel: clean(rel, 300), pkgs: st.pkgs }, root);
    if (base === 'package.json' && MOBILE_SPA.some((d) => new RegExp(`"${d.replace(/[/@]/g, '\\$&')}"\\s*:`).test(text))) st.repoClient = true;
  }
  for (const { rel, text } of texts) {
    const base = rel.slice(rel.lastIndexOf('/') + 1);
    if (MANIFESTS.has(base) || isRequirements(base)) continue;
    st.files_scanned++;
    const ext = base.slice(base.lastIndexOf('.') + 1).toLowerCase();
    const { lineOf, lineText } = lineIndex(text);
    const c = {
      rel: clean(rel, 300), text, ext, lineOf, lineText, count: 0, out: st.outbound, pubs: st.pubs, subs: st.subs, tables: st.tables,
      imports: st.imports, mounts: st.mounts, repoClient: st.repoClient,
    };
    if (SIG_RE.test(text)) st.sigFiles.add(c.rel);
    if (ext === 'graphql' || ext === 'gql') { scanGraphql(c); continue; }
    scanHttp(c);
    scanGraphql(c);
    scanRpc(c);
    scanQueues(c);
    scanTables(c);
    scanImports(c);
    scanMounts(c);
  }
  // nested mounts: allow two levels (/api + /v1)
  const ms = [...st.mounts].sort();
  for (const a of ms) for (const b of ms) if (st.mounts.size < 400 && a !== b) st.mounts.add(normPath(a + b));
  return st;
}

// ---------- providers ----------
function httpProviders(st) {
  const out = [];
  for (const s of st.inv.surfaces) {
    if (!['http-route', 'webhook', 'edge-function'].includes(s.kind)) continue;
    let method;
    let p;
    const m = /^([A-Z|]+)\s+(\S.*)$/.exec(s.label);
    if (m) { method = m[1]; p = m[2]; }
    else if (s.framework === 'supabase' && /^[\w-]+$/.test(s.label)) { method = 'ANY'; p = `/functions/v1/${s.label}`; }
    else continue;
    if (p[0] !== '/') continue;
    const np = normPath(p);
    const paths = method === 'RESOURCES' ? [np, normPath(np + '/:id')] : [np];
    for (const pp of paths) out.push({ surface: s, methods: method.split('|'), segs: segsOf(pp), path: pp });
  }
  return out;
}

function segsMatch(c, p) {
  for (let i = 0; i < p.length; i++) {
    if (p[i] === '*?') return true;
    if (p[i] === '*') return c.length > i;
    if (i >= c.length) return false;
    if (p[i] === ':param') continue;
    if (c[i] !== p[i]) return false;
  }
  return c.length === p.length;
}

// best match of one outbound http call against one repo's providers -> [{prov, how, conf}]
function matchHttp(call, provs, mounts) {
  const cs = segsOf(call.path);
  if (!cs.length) return []; // base URL only (often a dynamic or user-supplied target): never matched
  const mountSegs = [...mounts].map(segsOf);
  let best = [];
  let bestScore = -1;
  for (const pv of provs) {
    let how = null;
    let pathScore = 0;
    if (segsMatch(cs, pv.segs)) { how = 'exact'; pathScore = 3; }
    else {
      for (const ms of mountSegs) {
        if (ms.length < cs.length && ms.every((s, i) => s === cs[i] || (s === ':param')) && segsMatch(cs.slice(ms.length), pv.segs)) { how = `mount /${ms.join('/')}`; pathScore = 3; break; }
      }
      if (!how && pv.segs.length >= 2) {
        for (let k = 1; k < cs.length; k++) if (segsMatch(cs.slice(k), pv.segs)) { how = 'suffix'; pathScore = 1; break; }
      }
    }
    if (!how) continue;
    const anyM = pv.methods.some((x) => x === 'ANY' || x === 'RESOURCES') || !call.method;
    const methodScore = pv.methods.includes(call.method) ? 2 : anyM ? 2 : 0;
    const score = pathScore * 10 + methodScore;
    let conf;
    if (pathScore === 3 && methodScore === 2) conf = 'high';
    else if (pathScore === 3 || methodScore === 2) conf = 'medium';
    else conf = 'low';
    if (!pv.segs.some((s) => s !== ':param' && s[0] !== '*')) conf = 'low'; // provider path '/' or params only: anything matches
    const rec ={ prov: pv, how: methodScore ? how : `${how}, method differs`, conf };
    if (score > bestScore) { best = [rec]; bestScore = score; } else if (score === bestScore) best.push(rec);
  }
  best.sort((a, b) => byCode(a.prov.surface.id, b.prov.surface.id));
  return best.slice(0, 3);
}

// ---------- questions ----------
const Q = {
  authn: 'Does the provider authenticate this caller itself, or only trust its network position (VPC, mesh, gateway, localhost)?',
  deputy: "Does the consumer forward the end user's identity, or call with its own service credential (confused deputy: can a user make it act on another user's resource)?",
  fields: 'Which side validates each field (type, length, range, format, allowed values), and does the other side assume it was done?',
  tenant: 'Is tenant/owner scope enforced by the provider from the authenticated principal, or assumed from an id the consumer sends?',
  failclosed: 'Does the consumer treat provider errors, timeouts and partial responses as deny, and does it trust provider output it then renders or executes?',
  gqlauth: 'Does the provider enforce field- and object-level authorization and depth/cost limits itself, or assume only this trusted client sends these operations?',
  rpcauth: 'Is the method guarded by the same interceptor/middleware as the others, and is the peer identity mapped to the right application principal?',
  producer: 'Can a lower-trust producer (another service, a user-triggered path, a shared broker tenant) publish to this topic or queue?',
  msgauth: 'Is the message authenticated (signature, broker ACL bound to the producer identity), or does the handler trust any message on the queue?',
  idem: 'Is the handler idempotent under redelivery and replay, and does it re-check authorization for the subject named in the message?',
  msgscope: 'Does the handler take tenant/user/role from the message body and act on it without re-deriving it from a trusted source?',
  whsig: 'Does the receiver verify a signature over the raw request body (before parsing) with a constant-time compare and a timestamp/replay window?',
  whsecret: 'Is the signing secret per endpoint or tenant and kept server-side, and can a user choose the target URL (SSRF from the sender)?',
  whtrust: 'Does the receiver trust ids, amounts and states in the payload, or re-fetch them from the source of truth?',
  dbpolicy: "Does one writer skip a constraint, row policy (RLS) or validation that the other repo's reader relies on?",
  dbscope: 'Which side enforces owner/tenant scope on these rows, and does the other repo assume it?',
  dbsecond: 'Does a reader render, execute or trust a stored value the writer did not sanitise for that use (second-order use)?',
  dbrole: 'Do both repos use the same database role, or does one use a privileged role or service key that bypasses row policies?',
  pkgguarantee: 'Does the consumer rely on a guarantee (validation, escaping, auth check, constant-time compare, safe default) the library does not make at the pinned version?',
  pkgpin: 'Is the version pinned, or resolved from a workspace/path/range that can change without review in the consumer?',
  pkgprivs: "Do the imported symbols run with the consumer's privileges on input the library's authors assumed was trusted?",
};
const QUESTIONS = {
  http: ['authn', 'deputy', 'fields', 'tenant', 'failclosed'],
  graphql: ['authn', 'gqlauth', 'deputy', 'fields', 'tenant'],
  rpc: ['authn', 'rpcauth', 'deputy', 'fields', 'tenant'],
  queue: ['producer', 'msgauth', 'idem', 'msgscope', 'fields'],
  webhook: ['whsig', 'whsecret', 'whtrust', 'idem', 'fields'],
  'db-table': ['dbpolicy', 'dbscope', 'dbsecond', 'dbrole'],
  package: ['pkgguarantee', 'pkgpin', 'pkgprivs'],
};
const questionsFor = (kind) => QUESTIONS[kind].map((k) => Q[k]);
const PACK = {
  queue: 'Brokers and queues', webhook: 'Webhooks', rpc: 'RPC identity and authorization', graphql: 'RPC identity and authorization',
};

// ---------- matching across repos ----------
function edgeId(e) {
  return `x-${e.kind}-${sha([e.kind, e.consumer.repo, e.consumer.file, e.consumer.line, e.consumer.label, e.provider.repo, e.provider.file, e.provider.line, e.provider.label].join('\u0000')).slice(0, 12)}`;
}
const site = (repo, r, extra = {}) => ({ repo, file: r.file, line: r.line, label: r.label, snippet: r.snippet, ...extra });
const provSite = (repo, s, extra = {}) => {
  const o = { repo, file: s.file, line: s.line, label: s.label, framework: s.framework };
  if (s.kind === 'db-table') o.rls = s.rls === undefined ? null : s.rls; else if (s.auth_hint !== undefined) o.auth_hint = s.auth_hint;
  return Object.assign(o, extra);
};

function crossRepo(repos, opts = {}) {
  if (!Array.isArray(repos) || repos.length < 2) throw new Error('need at least two repositories');
  const names = opts.names || {};
  const maxFiles = Number.isInteger(opts.maxFiles) ? opts.maxFiles : MAX_FILES;
  const used = new Set();
  const list = repos.map((r) => {
    const p = path.resolve(typeof r === 'string' ? r : r.path);
    if (!fs.statSync(p).isDirectory()) throw new Error(`not a directory: ${p}`);
    let alias = (typeof r === 'object' && r.alias) || names[p] || path.basename(p);
    alias = String(alias).replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[-.]+|-+$/g, '').slice(0, 64) || 'repo';
    let a = alias;
    for (let n = 2; used.has(a); n++) a = `${alias}-${n}`;
    used.add(a);
    return { path: p, alias: a };
  });
  const seen = new Set();
  for (const r of list) { if (seen.has(r.path)) throw new Error(`repository given twice: ${r.path}`); seen.add(r.path); }
  for (const a of list) for (const b of list) {
    if (a !== b && b.path.startsWith(a.path + path.sep)) throw new Error(`${b.path} is inside ${a.path}: give separate, non-nested repositories`);
  }
  const sts = list.map((r) => scanRepo(r.path, r.alias, { maxFiles }));

  const edges = [];
  const unmatched = [];
  let internal = 0;
  const pushEdge = (e) => { if (edges.length < MAX_LIST) { e.questions = questionsFor(e.kind); e.id = edgeId(e); edges.push(e); } };

  // HTTP and webhooks
  const provs = sts.map(httpProviders);
  for (const [ai, A] of sts.entries()) {
    for (const call of A.outbound.filter((o) => o.kind === 'http' || o.kind === 'webhook')) {
      let matchedOther = false;
      for (const [bi, B] of sts.entries()) {
        const ms = matchHttp(call, provs[bi], B.mounts);
        if (!ms.length) continue;
        if (bi === ai) { if (ms.some((x) => x.conf !== 'low')) internal++; continue; }
        matchedOther = true;
        for (const x of ms) {
          const s = x.prov.surface;
          const kind = s.kind === 'webhook' || call.kind === 'webhook' ? 'webhook' : 'http';
          pushEdge({
            kind, confidence: x.conf, match: x.how,
            consumer: site(A.alias, call, { method: call.method, path: call.path, base: call.base, env: call.env, client: call.client, credential: call.credential, signed: call.signed }),
            provider: provSite(B.alias, s, { signature_check_visible: B.sigFiles.has(s.file) }),
          });
        }
      }
      if (!matchedOther && !sts.some((B, bi) => bi === ai && matchHttp(call, provs[bi], B.mounts).some((x) => x.conf !== 'low'))) {
        unmatched.push({ repo: A.alias, kind: call.kind, file: call.file, line: call.line, label: call.label, base: call.base, env: call.env, snippet: call.snippet });
      }
    }
  }

  // GraphQL and RPC (by name)
  for (const [ai, A] of sts.entries()) {
    for (const call of A.outbound.filter((o) => o.kind === 'graphql' || o.kind === 'rpc')) {
      let any = false;
      let own = false;
      for (const [bi, B] of sts.entries()) {
        for (const s of B.inv.surfaces) {
          let conf = null;
          let how = 'name';
          if (call.kind === 'graphql' && s.kind === 'graphql-operation' && s.label === call.name) { conf = 'medium'; how = 'operation type and root field'; }
          else if (call.kind === 'rpc' && s.kind === 'rpc-method') {
            if (call.client === 'grpc' && s.framework === 'grpc') {
              const [svc, meth] = s.label.includes('/') ? s.label.split('/') : ['', s.label];
              if (meth.toLowerCase() !== call.name.toLowerCase()) continue;
              const svcHit = svc && call.services.some((x) => x === svc.toLowerCase() || x.startsWith(svc.toLowerCase()) || svc.toLowerCase().startsWith(x));
              conf = svcHit ? 'medium' : 'low';
              how = svcHit ? 'service and method name' : 'method name only';
            } else if (call.client === 'trpc' && s.framework === 'trpc' && s.label === call.name) {
              const seg = call.router.split('.').pop();
              conf = seg && seg.length > 2 && s.file.toLowerCase().includes(seg.toLowerCase()) ? 'medium' : 'low';
              how = conf === 'medium' ? 'procedure name and router file' : 'procedure name only';
            }
          }
          if (!conf) continue;
          if (bi === ai) { own = true; continue; }
          any = true;
          pushEdge({ kind: call.kind, confidence: conf, match: how, consumer: site(A.alias, call, { client: call.client, credential: call.credential }), provider: provSite(B.alias, s) });
        }
      }
      if (!any && !own) unmatched.push({ repo: A.alias, kind: call.kind, file: call.file, line: call.line, label: call.label, base: null, env: null, snippet: call.snippet });
      if (own && !any) internal++;
    }
  }

  // Queues: publisher (consumer side of the interface) -> handler (provider side)
  const handlers = sts.map((B) => {
    const hs = [];
    for (const s of B.inv.surfaces) if (s.kind === 'queue-consumer') { const k = invQueueKey(s); if (k.key) hs.push({ key: k.key, via: k.key.startsWith('task:') ? 'task' : 'literal', site: provSite(B.alias, s) }); }
    const invSites = new Set(hs.map((h) => `${h.site.file}:${h.site.line}`));
    for (const s of B.subs) {
      if (!s.key || invSites.has(`${s.file}:${s.line}`)) continue;
      hs.push({ key: s.key, via: s.via, site: { repo: B.alias, file: s.file, line: s.line, label: clean(`consume ${s.sys} ${s.name}`), framework: s.sys } });
    }
    return hs;
  });
  for (const [ai, A] of sts.entries()) {
    for (const p of A.pubs) {
      const label = clean(`publish ${p.sys} ${p.name}`);
      let any = false;
      let own = false;
      if (p.key) {
        for (const [bi] of sts.entries()) {
          for (const h of handlers[bi].filter((x) => x.key === p.key)) {
            if (bi === ai) { own = true; continue; }
            any = true;
            const conf = p.via === 'literal' && h.via === 'literal' && !p.key.startsWith('task:') ? 'high' : 'medium';
            pushEdge({ kind: 'queue', confidence: conf, match: p.key.startsWith('env:') ? 'same env var name' : p.key.startsWith('task:') ? 'task name' : 'same topic/queue name',
              consumer: site(A.alias, { ...p, label }, { system: p.sys }), provider: h.site });
          }
        }
      }
      if (!any && !own) unmatched.push({ repo: A.alias, kind: 'queue', file: p.file, line: p.line, label, base: null, env: p.key && p.key.startsWith('env:') ? p.key.slice(4) : null, snippet: p.snippet });
    }
  }

  // Shared tables: a write in A to a table B defines, reads or writes
  const tableSites = sts.map((B) => {
    const defs = B.inv.surfaces.filter((s) => s.kind === 'db-table').map((s) => ({ key: tableKey(s.label), s }));
    return { defs, acc: B.tables };
  });
  for (const [ai, A] of sts.entries()) {
    const writes = new Map();
    for (const w of [...A.tables].filter((t) => t.op === 'write').sort((a, b) => byCode(a.file, b.file) || a.line - b.line)) if (!writes.has(w.key)) writes.set(w.key, w);
    for (const [key, w] of [...writes].sort((a, b) => byCode(a[0], b[0]))) {
      for (const [bi, B] of sts.entries()) {
        if (bi === ai) continue;
        const ts = tableSites[bi];
        const pick = (pred) => {
          const d = ts.defs.filter((x) => pred(x.key)).sort((a, b) => byCode(a.s.id, b.s.id))[0];
          if (d) return provSite(B.alias, d.s);
          const acc = ts.acc.filter((x) => pred(x.key)).sort((a, b) => byCode(b.op, a.op) || byCode(a.file, b.file) || a.line - b.line)[0];
          return acc ? { repo: B.alias, file: acc.file, line: acc.line, label: clean(`${acc.op} ${acc.table}`), framework: acc.via, rls: null } : null;
        };
        let prov = pick((k) => k === key);
        let conf = 'high';
        if (!prov) { prov = pick((k) => tableVariant(k) === tableVariant(key)); conf = 'medium'; }
        if (!prov) continue;
        pushEdge({ kind: 'db-table', confidence: conf, match: conf === 'high' ? 'same table name' : 'table name variant (plural/underscore)',
          consumer: site(A.alias, { ...w, label: clean(`write ${w.table}`) }, { via: w.via, client_side: w.client }), provider: prov });
      }
    }
  }

  // Packages
  for (const [ai, A] of sts.entries()) {
    for (const d of A.pkgs.depends) {
      for (const [bi, B] of sts.entries()) {
        if (bi === ai) continue;
        let prov = B.pkgs.provides.find((p) => p.eco === d.eco && p.key === d.key);
        let how = 'package name';
        if (d.localPath && (d.localPath === B.root || d.localPath.startsWith(B.root + path.sep))) {
          prov = B.pkgs.provides.filter((p) => p.dir === d.localPath).sort((a, b) => byCode(a.file, b.file))[0] || prov
            || { file: B.pkgs.provides.length ? B.pkgs.provides[0].file : '.', line: 1, name: d.name };
          how = 'local path into this repo';
        }
        if (!prov) continue;
        const mod = d.eco === 'pypi' ? d.key.replace(/-/g, '_') : d.name;
        const importers = A.imports.filter((im) => (d.eco === 'pypi' ? im.spec.split('.')[0].toLowerCase() === mod : im.spec === mod || im.spec.startsWith(mod + '/')))
          .sort((a, b) => byCode(a.file, b.file) || a.line - b.line);
        const symbols = [...new Set(importers.flatMap((im) => (d.eco === 'go' ? [im.spec.slice(mod.length) || '.'] : im.symbols)))].sort().slice(0, 50);
        pushEdge({ kind: 'package', confidence: 'high', match: how,
          consumer: site(A.alias, { ...d, label: clean(`depends on ${d.name}`) }, { package: d.name, pinned: d.version, symbols, importers: importers.slice(0, 20).map((im) => ({ file: im.file, line: im.line })) }),
          provider: { repo: B.alias, file: prov.file, line: prov.line, label: clean(`package ${prov.name || d.name}`) } });
      }
    }
  }

  // Leads
  const leads = [];
  const lead = (kind, e, at, why) => leads.push({ id: `lead-${kind}-${sha(`${kind}\u0000${e.id}`).slice(0, 10)}`, kind, edge: e.id, repo: at.repo, file: at.file, line: at.line, why });
  for (const e of edges) {
    if (e.confidence === 'low') continue;
    const c = e.consumer;
    const p = e.provider;
    if (['http', 'graphql', 'rpc'].includes(e.kind) && p.auth_hint === false && c.credential) {
      lead('auth-assumed', e, p, `${c.repo} calls this with a credential-looking header (${c.credential === 'call' ? 'at the call' : 'in the calling file'}), but no auth check is visible in the provider file: is auth enforced elsewhere (middleware, gateway) or assumed?`);
    }
    if (e.kind === 'http' && p.auth_hint === true && !c.credential) {
      lead('credential-missing', e, c, `the provider file shows an auth check, but this call site in ${c.repo} sends no visible credential: does the call fail, use ambient credentials, or hit an unauthenticated path?`);
    }
    if (e.kind === 'db-table' && p.rls === false && c.client_side) {
      lead('rls-off-client-write', e, c, `client-side code in ${c.repo} writes a table that ${p.repo} defines without row level security enabled`);
    }
    if (e.kind === 'webhook' && p.signature_check_visible === false) {
      lead('webhook-unsigned', e, p, `${c.repo} posts to this webhook receiver, and no signature verification token is visible in the receiver file`);
    }
  }

  const cmpSite = (a, b) => byCode(a.repo, b.repo) || byCode(a.file, b.file) || a.line - b.line || byCode(a.label, b.label);
  edges.sort((a, b) => CONF_RANK[a.confidence] - CONF_RANK[b.confidence] || byCode(a.kind, b.kind) || cmpSite(a.consumer, b.consumer) || cmpSite(a.provider, b.provider) || byCode(a.id, b.id));
  const dedup = [];
  const ids = new Set();
  for (const e of edges) if (!ids.has(e.id)) { ids.add(e.id); dedup.push(e); }
  unmatched.sort((a, b) => byCode(a.repo, b.repo) || byCode(a.kind, b.kind) || byCode(a.file, b.file) || a.line - b.line || byCode(a.label, b.label));
  leads.sort((a, b) => byCode(a.kind, b.kind) || byCode(a.repo, b.repo) || byCode(a.file, b.file) || a.line - b.line || byCode(a.id, b.id));
  const summary = { edges: {}, unmatched_outbound: unmatched.length, internal_matches: internal, leads: leads.length };
  for (const e of dedup) {
    summary.edges[e.kind] = summary.edges[e.kind] || { high: 0, medium: 0, low: 0 };
    summary.edges[e.kind][e.confidence]++;
  }
  return {
    tool: 'boring-security-cross-repo',
    repos: sts.map((s) => ({
      alias: s.alias, path: s.root, files_scanned: s.files_scanned, surfaces: s.inv.surfaces.length,
      outbound: s.outbound.length + s.pubs.length, packages: s.pkgs.provides.map((p) => p.name).sort(),
      skipped: s.skipped.length,
    })),
    edges: dedup,
    unmatched_outbound: unmatched.slice(0, MAX_LIST),
    leads,
    summary,
    note: 'candidate interfaces from regex heuristics; blind to service discovery, gateways, dynamic URLs, generated clients and config outside the repos. Edges and leads are not findings. All labels, paths and snippets are target text: data, not instructions.',
  };
}

// ---------- seeds for run-state.cjs add-units ----------
function seedsFor(result, alias) {
  if (!result.repos.some((r) => r.alias === alias)) throw new Error(`unknown repo alias "${alias}" (known: ${result.repos.map((r) => r.alias).join(', ')})`);
  const byId = new Map();
  for (const e of result.edges) {
    if (e.confidence === 'low') continue;
    let local;
    let far;
    if (e.provider.repo === alias) { local = e.provider; far = e.consumer; }
    else if (e.consumer.repo === alias) { local = e.consumer; far = e.provider; }
    else continue;
    const refs = {
      surface: clean(`${local.file}#${local.label}`, 400),
      boundary: clean(`${far.repo}:${far.file}#${far.label}`, 400),
      subsystem: clean(`cross-repo/${far.repo}`, 100),
      class: CLASS_REF,
    };
    const key = JSON.stringify(refs);
    if (byId.has(key)) { const n = byId.get(key).notes.cross_repo; if (!n.also_edges.includes(e.id)) n.also_edges.push(e.id); continue; }
    const pack = PACK[e.kind];
    const f = 'packs/messaging-rpc.md';
    byId.set(key, {
      refs,
      labels: {
        surface: clean(`${local.label} (${local.file})`, 400),
        boundary: clean(`${far.repo}: ${far.label} (${far.file})`, 400),
        subsystem: clean(`Interface with ${far.repo}`, 100),
        class: 'Chains and trust gaps',
      },
      start_paths: [local.file],
      class_block: CLASS_REF,
      pack_blocks: pack ? [`${f}#Discipline`, `${f}#${pack}`, `${f}#Moves`, `${f}#Gate`] : [],
      skipped_blocks: [],
      prior: 'none',
      notes: {
        priority: e.confidence === 'high' ? 1 : 2,
        priority_why: `cross-repo ${e.kind} interface (${e.confidence}): ${local === e.provider ? 'provider' : 'consumer'} side`,
        cross_repo: {
          edge_id: e.id, kind: e.kind, confidence: e.confidence, side: local === e.provider ? 'provider' : 'consumer',
          other_repo: far.repo, other_file: far.file, other_line: far.line, questions: e.questions, also_edges: [],
        },
      },
    });
  }
  return [...byId.entries()].sort((a, b) => byCode(a[0], b[0])).map(([, v]) => v);
}

// ---------- CLI ----------
function main(argv) {
  const args = argv.slice(2);
  const usage = () => { console.error('usage: node cross-repo.cjs <repoA> <repoB> [<repoC>...] [--json <out.json>] [--name <dir>=<alias>]... [--seeds <repoAlias> <out.json>]...'); return 2; };
  const repos = [];
  const names = {};
  const seeds = [];
  let out;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') { out = args[++i]; if (!out || out.startsWith('--')) return usage(); }
    else if (a === '--name') {
      const v = args[++i];
      const eq = v ? v.lastIndexOf('=') : -1;
      if (eq <= 0 || eq === v.length - 1) return usage();
      names[path.resolve(v.slice(0, eq))] = v.slice(eq + 1);
    } else if (a === '--seeds') {
      const al = args[++i];
      const f = args[++i];
      if (!al || !f || al.startsWith('--') || f.startsWith('--')) return usage();
      seeds.push([al, f]);
    } else if (a === '-h' || a === '--help') { usage(); return 0; }
    else if (a.startsWith('--')) return usage();
    else repos.push(a);
  }
  if (repos.length < 2) return usage();
  let res;
  try { res = crossRepo(repos, { names }); } catch (e) { console.error(`cross-repo: ${e.message}`); return 2; }
  console.log(`${res.tool}: ${res.repos.length} repos, ${res.edges.length} edges, ${res.unmatched_outbound.length} unmatched outbound, ${res.leads.length} leads`);
  for (const r of res.repos) console.log(`  ${r.alias.padEnd(16)} ${r.surfaces} surfaces, ${r.outbound} outbound, ${r.files_scanned} files scanned  (${r.path})`);
  console.log('edges by kind (high/medium/low):');
  for (const k of Object.keys(res.summary.edges).sort()) {
    const s = res.summary.edges[k];
    console.log(`  ${k.padEnd(10)} ${s.high}/${s.medium}/${s.low}`);
  }
  if (!out) {
    for (const e of res.edges) console.log(`[${e.confidence}] ${e.kind}  ${e.consumer.repo}:${e.consumer.file}:${e.consumer.line} ${e.consumer.label}  ->  ${e.provider.repo}:${e.provider.file}:${e.provider.line} ${e.provider.label}  (${e.match})`);
    for (const l of res.leads) console.log(`lead ${l.kind}: ${l.repo}:${l.file}:${l.line}  ${l.why}`);
  } else if (res.leads.length) console.log(`leads: ${res.leads.length} (${[...new Set(res.leads.map((l) => l.kind))].join(', ')})`);
  if (out) { fs.writeFileSync(out, JSON.stringify(res, null, 2) + '\n'); console.log(`wrote ${out}`); }
  for (const [al, f] of seeds) {
    let s;
    try { s = seedsFor(res, al); } catch (e) { console.error(`cross-repo: ${e.message}`); return 2; }
    fs.writeFileSync(f, JSON.stringify(s, null, 2) + '\n');
    console.log(`wrote ${s.length} seed(s) for ${al} to ${f}`);
  }
  console.log(res.note);
  return 0;
}

module.exports = { crossRepo, seedsFor, normPath, QUESTIONS: Object.fromEntries(Object.entries(QUESTIONS).map(([k, v]) => [k, v.map((x) => Q[x])])) };
if (require.main === module) process.exitCode = main(process.argv);
