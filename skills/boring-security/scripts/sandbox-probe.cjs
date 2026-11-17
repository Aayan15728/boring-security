#!/usr/bin/env node
'use strict';
// Fail-closed sandbox check. Run it INSIDE the sandbox before any target-controlled execution.
// Usage: node sandbox-probe.cjs --scratch <dir> --target <dir>
// Exit 0 only if every control holds; otherwise the run stays source-only.
//
// Every check is a pure exported function that takes its inputs as parameters (interfaces, env,
// file text, a connect function, ...) so it can be unit-tested with fake inputs; main() only gathers
// the real inputs. A check that cannot be evaluated fails. Passing proves these signals only: it is
// not a proof of isolation, which comes from the recipe in references/sandbox.md.

const fs = require('fs');
const net = require('net');
const dns = require('dns');
const os = require('os');
const path = require('path');

const PROBE_TIMEOUT_MS = 2500; // per attempt, all attempts run in parallel => total stays about 3 s
const PROXY_VARS = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'];
const SECRET_PATHS = ['.ssh', '.aws', '.config/gcloud', '.claude', '.npmrc', '.netrc', '.git-credentials', '.docker/config.json', '.kube/config'];
const HOME_ROOTS = ['/home', '/root', '/Users', '/mnt/c/Users'];
const SOCKET_PATHS = ['/var/run/docker.sock', '/run/docker.sock', '/run/podman/podman.sock', '/var/run/podman/podman.sock'];
const CRED_ENV = /TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE|CREDENTIAL|^AWS_|^GITHUB_|^GH_|^AZURE_|^GOOGLE_|^ANTHROPIC|^OPENAI|SSH_AUTH_SOCK|KUBECONFIG|DOCKER_HOST/i;

const mk = (name, ok, detail) => ({ name, ok: !!ok, detail });
const inside = (p, root) => { const r = path.relative(path.resolve(root), path.resolve(p)); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };

// ---- network -------------------------------------------------------------------------------------

const isLoopback = (a) => /^127\./.test(a) || a === '::1' || /^::ffff:127\./i.test(a);

// os.networkInterfaces() shape: { name: [{ address, internal, ... }] }
function checkInterfaces(ifaces) {
  const found = [];
  for (const [name, list] of Object.entries(ifaces || {})) {
    for (const i of list || []) if (i && i.address && !i.internal && !isLoopback(i.address)) found.push(`${name}=${i.address}`);
  }
  return mk('no non-loopback network interface', found.length === 0, found.join(', ') || 'only loopback');
}

function checkProxyEnv(env) {
  const set = PROXY_VARS.filter((v) => env && env[v]);
  return mk('no proxy environment variables', set.length === 0, set.join(', ') || 'none set');
}

// /proc/net/route: Iface Destination Gateway Flags ... (addresses are little-endian hex)
function parseDefaultGateway(routeText) {
  for (const line of String(routeText || '').split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 4 || f[1] !== '00000000') continue;
    if (!(parseInt(f[3], 16) & 2)) continue; // RTF_GATEWAY
    const g = f[2];
    if (!/^[0-9A-Fa-f]{8}$/.test(g) || /^0+$/.test(g)) continue;
    return [6, 4, 2, 0].map((i) => parseInt(g.slice(i, i + 2), 16)).join('.');
  }
  return null;
}

function networkTargets(gateway) {
  const t = [
    { host: '1.1.1.1', port: 443 }, { host: '8.8.8.8', port: 53 },
    { host: '169.254.169.254', port: 80 }, { host: '172.17.0.1', port: 80 }, { host: '10.0.2.2', port: 80 },
    { host: 'host.docker.internal', port: 80 }, { host: '2606:4700:4700::1111', port: 443 },
  ];
  if (gateway) t.push({ host: gateway, port: 80 });
  return t;
}

// Real connect with a hard timer (covers DNS too). Resolves { outcome: 'connected'|'refused'|'unreachable' }.
function tryConnect(host, port, timeoutMs = PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    let s;
    let timer;
    let settled = false;
    const done = (outcome, code) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      try { if (s) s.destroy(); } catch { /* ignore */ }
      resolve({ outcome, code });
    };
    timer = setTimeout(() => done('unreachable', 'TIMEOUT'), timeoutMs);
    try {
      s = net.connect({ host, port });
      s.on('connect', () => done('connected'));
      s.on('error', (e) => done(classifyError(e && e.code), e && e.code));
    } catch (e) { done('unreachable', e && e.code); }
  });
}

// A refusal or reset means something off this host answered, so a route exists: treat it as reachable.
function classifyError(code) { return code === 'ECONNREFUSED' || code === 'ECONNRESET' ? 'refused' : 'unreachable'; }

// connect(host, port) -> Promise<{ outcome }>. All targets run in parallel.
async function probeTargets(targets, connect) {
  return Promise.all(targets.map(async (t) => {
    let r;
    try { r = await connect(t.host, t.port); } catch { r = { outcome: 'unreachable' }; }
    return { ...t, outcome: (r && r.outcome) || 'unreachable' };
  }));
}

function checkReachability(results) {
  const bad = results.filter((r) => r.outcome === 'connected' || r.outcome === 'refused');
  return mk('no outbound network', bad.length === 0,
    bad.length ? bad.map((r) => `${r.host}:${r.port} ${r.outcome}`).join(', ') : `${results.length} targets unreachable`);
}

function checkDns(resolved) {
  return mk('no external DNS', !resolved, resolved ? 'example.com resolved' : 'lookup failed');
}

function lookupDns(host, timeoutMs = PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(false), timeoutMs);
    try { dns.lookup(host, (e) => { clearTimeout(t); resolve(!e); }); } catch { clearTimeout(t); resolve(false); }
  });
}

// ---- host secrets, sockets, privilege, layout -----------------------------------------------------

// listDir(dir) -> string[] (empty when unreadable or missing); canRead(path) -> boolean.
function checkHostSecrets(listDir, canRead, roots = HOME_ROOTS) {
  const exposed = [];
  for (const root of roots) {
    const bases = [root, ...(listDir(root) || []).slice(0, 500).map((n) => path.posix.join(root, n))];
    for (const b of bases) for (const s of SECRET_PATHS) {
      const p = path.posix.join(b, s);
      if (canRead(p)) exposed.push(p);
    }
  }
  return mk('no host secrets readable', exposed.length === 0, exposed.slice(0, 8).join(', ') || 'none visible');
}

function checkSockets(exists, listDir, extra = []) {
  const paths = [...SOCKET_PATHS, ...extra];
  for (const u of (listDir('/run/user') || []).slice(0, 200)) paths.push(`/run/user/${u}/podman/podman.sock`);
  const found = paths.filter((p) => exists(p));
  return mk('no container runtime socket', found.length === 0, found.join(', ') || 'none present');
}

function parseCapEff(statusText) {
  const m = /^CapEff:\s*([0-9a-fA-F]+)\s*$/m.exec(String(statusText || ''));
  return m ? m[1] : null;
}

function checkCapabilities(statusText) {
  const cap = parseCapEff(statusText);
  if (cap === null) return mk('no effective capabilities', false, 'CapEff not readable');
  return mk('no effective capabilities', /^0+$/.test(cap), `CapEff ${cap}`);
}

function checkLayout(target, scratch, real = (p) => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } }) {
  const t = real(target);
  const s = real(scratch);
  const rel = (a, b) => { const r = path.relative(a, b); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };
  const bad = rel(t, s) || rel(s, t);
  return mk('target and scratch are separate', !bad, bad ? `${t} and ${s} overlap` : 'disjoint directories');
}

// ---- environment, filesystem, limits ----------------------------------------------------------------

function checkEnvInside(env, homedir, scratch) {
  const out = [];
  for (const v of ['HOME', 'USERPROFILE', 'TMPDIR', 'TMP', 'TEMP']) {
    if (env[v]) out.push(mk(`${v} inside scratch`, inside(env[v], scratch), env[v]));
  }
  out.push(mk('os.homedir inside scratch', inside(homedir, scratch), homedir));
  return out;
}

function checkEnvClean(env) {
  const names = Object.keys(env);
  const secretish = names.filter((k) => CRED_ENV.test(k));
  return [
    mk('no credential-like env vars', secretish.length === 0, secretish.join(', ') || 'none'),
    mk('small allowlisted environment', names.length <= 40, `${names.length} vars`),
  ];
}

function checkFilesystem(target, scratch, fsApi = fs, pid = process.pid) {
  const probeT = path.join(target, `.bsec-probe-${pid}`);
  let targetWritable = false;
  try { fsApi.writeFileSync(probeT, 'x'); targetWritable = true; fsApi.unlinkSync(probeT); } catch { /* expected */ }
  const probeS = path.join(scratch, `.bsec-probe-${pid}`);
  let scratchOk = false;
  try { fsApi.writeFileSync(probeS, 'x'); scratchOk = fsApi.readFileSync(probeS, 'utf8') === 'x'; fsApi.unlinkSync(probeS); } catch { /* fail */ }
  return [
    mk('target is read-only', !targetWritable, targetWritable ? 'wrote into target' : 'write refused'),
    mk('scratch is writable', scratchOk, scratch),
  ];
}

// Linux: cgroup files or rlimits. `files` = { memMax, pidsMax, limits } as text ('' when unreadable).
function checkLimits(platform, files) {
  if (platform !== 'linux') return [mk('resource limits verifiable', false, `cannot verify limits on ${platform}; use a Linux container or VM`)];
  const memMax = String(files.memMax || '').trim();
  const pidsMax = String(files.pidsMax || '').trim();
  const limits = String(files.limits || '');
  const lim = (name) => { const m = new RegExp(`^${name}\\s+(\\S+)`, 'm').exec(limits); return m ? m[1] : 'unknown'; };
  return [
    mk('memory limited', (memMax && memMax !== 'max') || lim('Max address space') !== 'unlimited', `cgroup ${memMax || 'n/a'}, rlimit ${lim('Max address space')}`),
    mk('process count limited', (pidsMax && pidsMax !== 'max') || lim('Max processes') !== 'unlimited', `cgroup ${pidsMax || 'n/a'}, rlimit ${lim('Max processes')}`),
    mk('file size limited', lim('Max file size') !== 'unlimited', lim('Max file size')),
  ];
}

// ---- driver -----------------------------------------------------------------------------------------

const read = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
const listDir = (d) => { try { return fs.readdirSync(d); } catch { return []; } };
const canRead = (p) => { try { fs.accessSync(p, fs.constants.R_OK); return true; } catch { return false; } };

async function runProbe(scratch, target, platform = process.platform) {
  const results = [];
  const linux = platform === 'linux';
  const gateway = linux ? parseDefaultGateway(read('/proc/net/route')) : null;
  const [reach, resolved] = await Promise.all([probeTargets(networkTargets(gateway), tryConnect), lookupDns('example.com')]);

  results.push(checkInterfaces(os.networkInterfaces()));
  results.push(checkProxyEnv(process.env));
  results.push(checkReachability(reach));
  results.push(checkDns(resolved));
  results.push(...checkEnvInside(process.env, os.homedir(), scratch));
  results.push(checkLayout(target, scratch));
  results.push(...checkFilesystem(target, scratch));
  results.push(...checkEnvClean(process.env));
  results.push(checkHostSecrets(listDir, canRead));
  results.push(checkSockets(fs.existsSync, listDir, process.env.XDG_RUNTIME_DIR ? [path.join(process.env.XDG_RUNTIME_DIR, 'podman', 'podman.sock')] : []));
  if (linux) results.push(checkCapabilities(read('/proc/self/status')));
  results.push(...checkLimits(platform, linux ? { memMax: read('/sys/fs/cgroup/memory.max'), pidsMax: read('/sys/fs/cgroup/pids.max'), limits: read('/proc/self/limits') } : {}));
  return results;
}

async function main(argv) {
  const arg = (f) => { const i = argv.indexOf(f); return i !== -1 ? argv[i + 1] : undefined; };
  const scratch = arg('--scratch');
  const target = arg('--target');
  if (!scratch || !target) { console.error('usage: node sandbox-probe.cjs --scratch <dir> --target <dir>'); return 2; }
  const results = await runProbe(scratch, target);
  for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}  (${r.detail})`);
  const ok = results.every((r) => r.ok);
  console.log(ok ? 'sandbox-probe: OK - sandboxed-local-only allowed' : 'sandbox-probe: FAILED - stay source-only');
  return ok ? 0 : 1;
}

// A pending DNS lookup must not keep the CLI alive past the verdict.
const finish = (c) => { process.exitCode = c; setTimeout(() => process.exit(c), 200).unref(); };
if (require.main === module) main(process.argv).then(finish, (e) => { console.error(e); finish(1); });

module.exports = {
  PROXY_VARS, SECRET_PATHS, HOME_ROOTS, SOCKET_PATHS,
  checkInterfaces, checkProxyEnv, parseDefaultGateway, networkTargets, tryConnect, classifyError, probeTargets, checkReachability, checkDns,
  checkHostSecrets, checkSockets, parseCapEff, checkCapabilities, checkLayout,
  checkEnvInside, checkEnvClean, checkFilesystem, checkLimits, runProbe, inside,
};
