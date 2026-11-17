'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const P = require('../sandbox-probe.cjs');

const ifaceLo = { lo: [{ address: '127.0.0.1', internal: true }, { address: '::1', internal: true }] };

test('interfaces: loopback only passes; any other address fails', () => {
  assert.strictEqual(P.checkInterfaces(ifaceLo).ok, true);
  assert.strictEqual(P.checkInterfaces({}).ok, true);
  const eth = P.checkInterfaces({ ...ifaceLo, eth0: [{ address: '172.17.0.2', internal: false }] });
  assert.strictEqual(eth.ok, false);
  assert.match(eth.detail, /eth0=172\.17\.0\.2/);
  assert.strictEqual(P.checkInterfaces({ ...ifaceLo, wlan0: [{ address: 'fe80::1', internal: false }] }).ok, false, 'link-local v6 counts');
  assert.strictEqual(P.checkInterfaces({ lo: [{ address: '127.0.0.2', internal: false }] }).ok, true, '127/8 is loopback even if not flagged internal');
});

test('proxy env: any of the six variables fails', () => {
  assert.strictEqual(P.checkProxyEnv({ PATH: '/usr/bin' }).ok, true);
  for (const v of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) {
    const r = P.checkProxyEnv({ [v]: 'http://10.0.0.1:3128' });
    assert.strictEqual(r.ok, false, v);
    assert.match(r.detail, new RegExp(v));
  }
  assert.strictEqual(P.checkProxyEnv({ HTTP_PROXY: '' }).ok, true, 'empty value is not a proxy');
});

test('default gateway parsing from /proc/net/route', () => {
  const route = [
    'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT',
    'eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0',
    'eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0',
  ].join('\n');
  assert.strictEqual(P.parseDefaultGateway(route), '192.168.0.1');
  assert.strictEqual(P.parseDefaultGateway('Iface\tDestination\tGateway\tFlags\n'), null);
  assert.strictEqual(P.parseDefaultGateway(''), null);
  assert.strictEqual(P.parseDefaultGateway('h\neth0\t00000000\t00000000\t0001'), null, 'no gateway flag / zero gateway');
});

test('network targets include the required hosts and the gateway', () => {
  const hosts = P.networkTargets('192.168.0.1').map((t) => t.host);
  for (const h of ['1.1.1.1', '8.8.8.8', '169.254.169.254', '172.17.0.1', '10.0.2.2', 'host.docker.internal', '192.168.0.1']) assert.ok(hosts.includes(h), h);
  assert.ok(hosts.some((h) => h.includes(':')), 'one IPv6 address');
  assert.ok(!P.networkTargets(null).some((t) => t.host === 'null'));
  assert.strictEqual(P.networkTargets(null).find((t) => t.host === '169.254.169.254').port, 80);
});

test('reachability: any connected or refused target fails; all unreachable passes; connect runs in parallel', async () => {
  const targets = P.networkTargets('192.168.0.1');
  const none = await P.probeTargets(targets, async () => ({ outcome: 'unreachable' }));
  assert.strictEqual(P.checkReachability(none).ok, true);
  const one = await P.probeTargets(targets, async (h) => ({ outcome: h === '10.0.2.2' ? 'connected' : 'unreachable' }));
  const r = P.checkReachability(one);
  assert.strictEqual(r.ok, false);
  assert.match(r.detail, /10\.0\.2\.2:80 connected/);
  const refused = await P.probeTargets(targets, async (h) => ({ outcome: h === '192.168.0.1' ? 'refused' : 'unreachable' }));
  assert.strictEqual(P.checkReachability(refused).ok, false, 'a refusal proves something off-host answered');
  const throwing = await P.probeTargets(targets, async () => { throw new Error('boom'); });
  assert.strictEqual(P.checkReachability(throwing).ok, true, 'a thrown connect is a failed connect');
  const started = Date.now();
  await P.probeTargets(targets, () => new Promise((res) => setTimeout(() => res({ outcome: 'unreachable' }), 100)));
  assert.ok(Date.now() - started < 100 * targets.length, 'attempts are concurrent');
  assert.strictEqual(P.classifyError('ECONNREFUSED'), 'refused');
  assert.strictEqual(P.classifyError('ENETUNREACH'), 'unreachable');
});

test('tryConnect is bounded and succeeds against a local listener', async () => {
  const net = require('net');
  const srv = net.createServer((s) => s.end());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const ok = await P.tryConnect('127.0.0.1', srv.address().port, 1000);
  assert.strictEqual(ok.outcome, 'connected');
  await new Promise((r) => srv.close(r));
  const t0 = Date.now();
  const gone = await P.tryConnect('203.0.113.1', 9, 300); // TEST-NET-3, never routable
  assert.ok(Date.now() - t0 < 1500);
  assert.ok(['unreachable', 'refused'].includes(gone.outcome) && gone.outcome !== 'connected');
});

test('dns check', () => {
  assert.strictEqual(P.checkDns(false).ok, true);
  assert.strictEqual(P.checkDns(true).ok, false);
});

test('host secrets: any readable secret under any home root fails', () => {
  const none = P.checkHostSecrets(() => [], () => false);
  assert.strictEqual(none.ok, true);
  const tree = { '/home': ['alice'], '/Users': ['bob'], '/mnt/c/Users': ['carol'], '/root': [] };
  const list = (d) => tree[d] || [];
  for (const secret of ['/home/alice/.ssh', '/home/alice/.aws', '/home/alice/.config/gcloud', '/home/alice/.claude', '/home/alice/.npmrc', '/home/alice/.netrc', '/home/alice/.git-credentials', '/home/alice/.docker/config.json', '/home/alice/.kube/config', '/root/.ssh', '/Users/bob/.aws', '/mnt/c/Users/carol/.claude']) {
    const r = P.checkHostSecrets(list, (p) => p === secret);
    assert.strictEqual(r.ok, false, secret);
    assert.ok(r.detail.includes(secret));
  }
  assert.strictEqual(P.checkHostSecrets(list, (p) => p === '/home/alice/.bashrc').ok, true, 'unrelated files do not count');
});

test('sockets: docker and podman sockets fail', () => {
  const absent = () => false;
  assert.strictEqual(P.checkSockets(absent, () => []).ok, true);
  for (const s of ['/var/run/docker.sock', '/run/docker.sock', '/run/podman/podman.sock', '/run/user/1000/podman/podman.sock']) {
    const r = P.checkSockets((p) => p === s, (d) => (d === '/run/user' ? ['1000'] : []));
    assert.strictEqual(r.ok, false, s);
  }
  assert.strictEqual(P.checkSockets((p) => p === '/x/podman.sock', () => [], ['/x/podman.sock']).ok, false, 'XDG_RUNTIME_DIR socket');
});

test('capabilities: non-zero CapEff or unreadable status fails', () => {
  const st = (cap) => `Name:\tnode\nCapInh:\t0000000000000000\nCapPrm:\t${cap}\nCapEff:\t${cap}\nCapBnd:\t000001ffffffffff\n`;
  assert.strictEqual(P.checkCapabilities(st('0000000000000000')).ok, true);
  assert.strictEqual(P.checkCapabilities(st('00000000a80425fb')).ok, false);
  assert.strictEqual(P.checkCapabilities(st('000001ffffffffff')).ok, false);
  assert.strictEqual(P.checkCapabilities('').ok, false, 'fail closed');
  assert.strictEqual(P.parseCapEff(st('0000000000000000')), '0000000000000000');
});

test('layout: same, nested either way, or overlapping fails; siblings pass', () => {
  const id = (p) => path.resolve(p);
  assert.strictEqual(P.checkLayout('/src', '/scratch', id).ok, true);
  assert.strictEqual(P.checkLayout('/run/a/src', '/run/a/scratch', id).ok, true);
  assert.strictEqual(P.checkLayout('/run/a/src', '/run/a/src2', id).ok, true, 'prefix-sharing names are not nesting');
  assert.strictEqual(P.checkLayout('/w', '/w', id).ok, false);
  assert.strictEqual(P.checkLayout('/w', '/w/scratch', id).ok, false);
  assert.strictEqual(P.checkLayout('/w/target', '/w', id).ok, false);
  assert.strictEqual(P.checkLayout('/w/./t/..', '/w', id).ok, false);
});

test('env and limits checks', () => {
  const s = path.resolve('/scratch');
  const good = P.checkEnvInside({ HOME: '/scratch', TMPDIR: '/scratch/tmp' }, '/scratch', s);
  assert.ok(good.every((r) => r.ok));
  assert.ok(P.checkEnvInside({ HOME: '/root' }, '/scratch', s).some((r) => !r.ok));
  assert.ok(P.checkEnvClean({ PATH: '/usr/bin', AWS_PROFILE: 'x' }).some((r) => !r.ok));
  assert.ok(P.checkEnvClean({ PATH: '/usr/bin', HOME: '/scratch' }).every((r) => r.ok));
  const limits = 'Limit Soft Limit Hard Limit Units\nMax file size 52428800 52428800 bytes\nMax processes 128 128 processes\nMax address space 536870912 536870912 bytes\n';
  assert.ok(P.checkLimits('linux', { memMax: 'max', pidsMax: 'max', limits }).every((r) => r.ok));
  const open = limits.replace(/Max address space \d+ \d+/, 'Max address space unlimited unlimited');
  assert.ok(P.checkLimits('linux', { memMax: 'max', pidsMax: 'max', limits: open }).some((r) => !r.ok && r.name === 'memory limited'));
  assert.ok(P.checkLimits('linux', { memMax: '536870912', pidsMax: '128', limits: open.replace('52428800', 'unlimited') }).some((r) => !r.ok && r.name === 'file size limited'));
  assert.strictEqual(P.checkLimits('win32', {})[0].ok, false);
  assert.strictEqual(P.checkLimits('darwin', {})[0].ok, false);
});

test('filesystem check against real temp dirs', () => {
  const t = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-t-'));
  const s = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-s-'));
  const [ro, rw] = P.checkFilesystem(t, s);
  assert.strictEqual(ro.ok, false, 'a writable target fails the read-only check');
  assert.strictEqual(rw.ok, true);
  const blocked = { ...fs, writeFileSync: (f, d) => { if (f.startsWith(t)) throw new Error('EROFS'); return fs.writeFileSync(f, d); } };
  const [ro2] = P.checkFilesystem(t, s, blocked);
  assert.strictEqual(ro2.ok, true);
});

test('CLI: usage error exits 2; outside a sandbox it fails closed', () => {
  const script = path.resolve(__dirname, '..', 'sandbox-probe.cjs');
  assert.strictEqual(spawnSync(process.execPath, [script], { encoding: 'utf8' }).status, 2);
  const t = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-t-'));
  const s = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-s-'));
  const r = spawnSync(process.execPath, [script, '--scratch', s, '--target', t], { encoding: 'utf8', timeout: 20000 });
  assert.strictEqual(r.status, 1, 'a normal dev host is not a sandbox');
  assert.match(r.stdout, /sandbox-probe: FAILED - stay source-only/);
  assert.match(r.stdout, /FAIL {2}target is read-only/);
});
