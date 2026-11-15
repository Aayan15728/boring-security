#!/usr/bin/env node
'use strict';
// Fail-closed sandbox check. Run it INSIDE the sandbox before any target-controlled execution.
// Usage: node sandbox-probe.cjs --scratch <dir> --target <dir>
// Exit 0 only if every control holds; otherwise the run stays source-only.

const fs = require('fs');
const net = require('net');
const dns = require('dns');
const os = require('os');
const path = require('path');

const arg = (f) => { const i = process.argv.indexOf(f); return i !== -1 ? process.argv[i + 1] : undefined; };
const scratch = arg('--scratch');
const target = arg('--target');
const results = [];
const check = (name, ok, detail) => results.push({ name, ok, detail });
const inside = (p, root) => { const r = path.relative(path.resolve(root), path.resolve(p)); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };

function tryConnect(host, port) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port, timeout: 2000 });
    const done = (v) => { s.destroy(); resolve(v); };
    s.on('connect', () => done(true)); s.on('timeout', () => done(false)); s.on('error', () => done(false));
  });
}

async function main() {
  if (!scratch || !target) { console.error('usage: node sandbox-probe.cjs --scratch <dir> --target <dir>'); return 2; }

  // 1. No outbound network.
  const reach = await Promise.all([tryConnect('1.1.1.1', 443), tryConnect('8.8.8.8', 53)]);
  check('no outbound network', !reach.some(Boolean), reach.some(Boolean) ? 'connected to a public address' : 'connections refused/timed out');
  const resolved = await new Promise((r) => dns.lookup('example.com', (e) => r(!e)));
  check('no external DNS', !resolved, resolved ? 'example.com resolved' : 'lookup failed');

  // 2. HOME/TMP live in scratch.
  for (const v of ['HOME', 'USERPROFILE', 'TMPDIR', 'TMP', 'TEMP']) {
    if (process.env[v]) check(`${v} inside scratch`, inside(process.env[v], scratch), process.env[v]);
  }
  check('os.homedir inside scratch', inside(os.homedir(), scratch), os.homedir());

  // 3. Target read-only, scratch writable.
  const probeT = path.join(target, `.bsec-probe-${process.pid}`);
  let targetWritable = false;
  try { fs.writeFileSync(probeT, 'x'); targetWritable = true; fs.unlinkSync(probeT); } catch { /* expected */ }
  check('target is read-only', !targetWritable, targetWritable ? 'wrote into target' : 'write refused');
  const probeS = path.join(scratch, `.bsec-probe-${process.pid}`);
  let scratchOk = false;
  try { fs.writeFileSync(probeS, 'x'); scratchOk = fs.readFileSync(probeS, 'utf8') === 'x'; fs.unlinkSync(probeS); } catch { /* fail */ }
  check('scratch is writable', scratchOk, scratch);

  // 4. Clean environment.
  const secretish = Object.keys(process.env).filter((k) => /TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE|CREDENTIAL|^AWS_|^GITHUB_|^GH_|^AZURE_|^GOOGLE_|^ANTHROPIC|^OPENAI|SSH_AUTH_SOCK|KUBECONFIG|DOCKER_HOST/i.test(k));
  check('no credential-like env vars', secretish.length === 0, secretish.join(', ') || 'none');
  check('small allowlisted environment', Object.keys(process.env).length <= 40, `${Object.keys(process.env).length} vars`);

  // 5. Resource limits (Linux: cgroup or rlimits).
  if (process.platform === 'linux') {
    const read = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
    const memMax = read('/sys/fs/cgroup/memory.max').trim();
    const pidsMax = read('/sys/fs/cgroup/pids.max').trim();
    const limits = read('/proc/self/limits');
    const lim = (name) => { const m = new RegExp(`^${name}\\s+(\\S+)`, 'm').exec(limits); return m ? m[1] : 'unknown'; };
    check('memory limited', (memMax && memMax !== 'max') || lim('Max address space') !== 'unlimited', `cgroup ${memMax || 'n/a'}, rlimit ${lim('Max address space')}`);
    check('process count limited', (pidsMax && pidsMax !== 'max') || lim('Max processes') !== 'unlimited', `cgroup ${pidsMax || 'n/a'}, rlimit ${lim('Max processes')}`);
    check('file size limited', lim('Max file size') !== 'unlimited', lim('Max file size'));
  } else {
    check('resource limits verifiable', false, `cannot verify limits on ${process.platform}; use a Linux container or VM`);
  }

  for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}  (${r.detail})`);
  const ok = results.every((r) => r.ok);
  console.log(ok ? 'sandbox-probe: OK - sandboxed-local-only allowed' : 'sandbox-probe: FAILED - stay source-only');
  return ok ? 0 : 1;
}

main().then((c) => { process.exitCode = c; }, (e) => { console.error(e); process.exitCode = 1; });
