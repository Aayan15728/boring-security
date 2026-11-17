'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { crossRepo, seedsFor, normPath } = require('../cross-repo.cjs');

const SCRIPT = path.join(__dirname, '..', 'cross-repo.cjs');
const tmpDirs = [];
function repo(name, files) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'bs-cross-'));
  tmpDirs.push(parent);
  const dir = path.join(parent, name);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, ...rel.split('/'));
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}
test.after(() => { for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true }); });

const WEB = {
  'package.json': JSON.stringify({ name: 'web', dependencies: { '@acme/shared': 'workspace:*', react: '^18.0.0' } }, null, 2),
  'src/orders.js': [
    "import { formatMoney, validateOrder as vo } from '@acme/shared';",
    'export async function refund(id, token) {',
    '  return fetch(`${process.env.API_URL}/api/orders/${id}/refund`, {',
    "    method: 'POST',",
    '    headers: { Authorization: `Bearer ${token}` },',
    '  });',
    '}',
    'export async function weather() {',
    "  return fetch('https://weather.example.net/v2/forecast?city=x');",
    '}',
    '',
  ].join('\n'),
  'src/jobs.js': [
    "const { Kafka } = require('kafkajs');",
    'async function emit(producer) {',
    "  await producer.send({ topic: 'order-events', messages: [{ value: 'x' }] });",
    '}',
    '',
  ].join('\n'),
  'src/db.js': [
    "import { createBrowserClient } from '@supabase/ssr';",
    'const supabase = createBrowserClient(url, key);',
    "export const save = (row) => supabase.from('audit_log').insert(row);",
    '',
  ].join('\n'),
};
const API = {
  'package.json': JSON.stringify({ name: 'api', dependencies: { express: '^4.0.0' } }, null, 2),
  'src/app.js': [
    "const express = require('express');",
    "const orders = require('./routes/orders');",
    'const app = express();',
    "app.use('/api', orders);",
    '',
  ].join('\n'),
  'src/routes/orders.js': [
    "const express = require('express');",
    'const router = express.Router();',
    "router.post('/orders/:id/refund', async (req, res) => { res.json({ ok: true }); });",
    'module.exports = router;',
    '',
  ].join('\n'),
  'src/consumer.js': [
    "const { Kafka } = require('kafkajs');",
    'async function run(consumer) {',
    "  await consumer.subscribe({ topic: 'order-events' });",
    '}',
    '',
  ].join('\n'),
  'supabase/migrations/001.sql': 'create table audit_log (id int primary key, body text);\n',
  'packages/shared/package.json': JSON.stringify({ name: '@acme/shared', version: '1.0.0' }, null, 2),
  'packages/shared/index.js': 'exports.formatMoney = (x) => x;\n',
};

function pair() {
  return [repo('web', WEB), repo('api', API)];
}
const findEdge = (res, kind) => res.edges.filter((e) => e.kind === kind);

test('HTTP edge through a mount prefix, and the auth-assumed lead', () => {
  const res = crossRepo(pair());
  const http = findEdge(res, 'http');
  assert.equal(http.length, 1, JSON.stringify(res.edges, null, 1));
  const e = http[0];
  assert.equal(e.confidence, 'high');
  assert.equal(e.match, 'mount /api');
  assert.equal(e.consumer.repo, 'web');
  assert.equal(e.consumer.file, 'src/orders.js');
  assert.equal(e.consumer.line, 3);
  assert.equal(e.consumer.method, 'POST');
  assert.equal(e.consumer.path, '/api/orders/:param/refund');
  assert.equal(e.consumer.env, 'API_URL');
  assert.equal(e.consumer.credential, 'call');
  assert.equal(e.provider.repo, 'api');
  assert.equal(e.provider.file, 'src/routes/orders.js');
  assert.equal(e.provider.label, 'POST /orders/:id/refund');
  assert.equal(e.provider.auth_hint, false);
  assert.ok(e.questions.some((q) => /confused deputy/.test(q)));
  assert.match(e.id, /^x-http-[0-9a-f]{12}$/);
  const lead = res.leads.find((l) => l.kind === 'auth-assumed');
  assert.ok(lead, JSON.stringify(res.leads));
  assert.equal(lead.edge, e.id);
  assert.equal(lead.repo, 'api');
  assert.equal(lead.file, 'src/routes/orders.js');
});

test('unmatched outbound call is recorded with its base', () => {
  const res = crossRepo(pair());
  const u = res.unmatched_outbound.find((x) => x.label === 'GET /v2/forecast');
  assert.ok(u, JSON.stringify(res.unmatched_outbound));
  assert.equal(u.repo, 'web');
  assert.equal(u.base, 'https://weather.example.net');
  assert.ok(!res.unmatched_outbound.some((x) => /refund/.test(x.label)));
});

test('queue publish in one repo matched to its consumer in another', () => {
  const res = crossRepo(pair());
  const q = findEdge(res, 'queue');
  assert.equal(q.length, 1, JSON.stringify(res.edges, null, 1));
  assert.equal(q[0].confidence, 'high');
  assert.equal(q[0].consumer.repo, 'web');
  assert.equal(q[0].consumer.file, 'src/jobs.js');
  assert.equal(q[0].provider.repo, 'api');
  assert.equal(q[0].provider.file, 'src/consumer.js');
  assert.ok(q[0].questions.some((x) => /lower-trust producer/.test(x)));
});

test('shared table written client-side against a table without RLS', () => {
  const res = crossRepo(pair());
  const t = findEdge(res, 'db-table');
  assert.equal(t.length, 1, JSON.stringify(res.edges, null, 1));
  assert.equal(t[0].consumer.repo, 'web');
  assert.equal(t[0].consumer.client_side, true);
  assert.equal(t[0].provider.file, 'supabase/migrations/001.sql');
  assert.equal(t[0].provider.rls, false);
  assert.ok(res.leads.some((l) => l.kind === 'rls-off-client-write' && l.edge === t[0].id));
});

test('package dependency with imported symbols', () => {
  const res = crossRepo(pair());
  const p = findEdge(res, 'package');
  assert.equal(p.length, 1, JSON.stringify(res.edges, null, 1));
  assert.equal(p[0].consumer.package, '@acme/shared');
  assert.equal(p[0].consumer.pinned, 'workspace:*');
  assert.deepEqual(p[0].consumer.symbols, ['formatMoney', 'validateOrder']);
  assert.deepEqual(p[0].consumer.importers, [{ file: 'src/orders.js', line: 1 }]);
  assert.equal(p[0].provider.file, 'packages/shared/package.json');
});

test('other languages and edge kinds: requests f-string, Go concat, webhook sender, graphql', () => {
  const svc = repo('svc', {
    'client.py': [
      'import requests, os',
      'BASE = os.environ["BILLING_URL"]',
      'def charge(cid):',
      '    return requests.post(f"{BASE}/charges/{cid}/capture", json={})',
      '',
    ].join('\n'),
    'main.go': [
      'package main',
      'import "net/http"',
      'func notify(base string) { http.Post(base + "/hooks/payment", "application/json", nil) }',
      '',
    ].join('\n'),
    'ui.js': "import { gql } from '@apollo/client';\nexport const Q = gql`mutation Refund($id: ID!) { refundOrder(id: $id) { ok } }`;\n",
  });
  const billing = repo('billing', {
    'app.py': [
      'from fastapi import FastAPI, Depends',
      'app = FastAPI()',
      '@app.post("/charges/{charge_id}/capture")',
      'def capture(charge_id: str, user=Depends(get_current_user)):',
      '    return {}',
      '',
    ].join('\n'),
    'webhooks/payment.js': "router.post('/hooks/payment', (req, res) => { res.end(); });\n",
    'schema.graphql': 'type Mutation {\n  refundOrder(id: ID!): Result\n}\n',
  });
  const res = crossRepo([svc, billing]);
  const http = findEdge(res, 'http');
  assert.equal(http.length, 1, JSON.stringify(res.edges, null, 1));
  assert.equal(http[0].consumer.path, '/charges/:param/capture');
  assert.equal(http[0].consumer.env, 'BILLING_URL');
  assert.equal(http[0].confidence, 'high');
  assert.equal(http[0].provider.auth_hint, true);
  assert.ok(res.leads.some((l) => l.kind === 'credential-missing' && l.edge === http[0].id));
  const wh = findEdge(res, 'webhook');
  assert.equal(wh.length, 1);
  assert.equal(wh[0].consumer.file, 'main.go');
  assert.equal(wh[0].consumer.method, 'POST');
  assert.ok(res.leads.some((l) => l.kind === 'webhook-unsigned' && l.edge === wh[0].id));
  const g = findEdge(res, 'graphql');
  assert.equal(g.length, 1);
  assert.equal(g[0].consumer.label, 'Mutation.refundOrder');
  assert.equal(g[0].confidence, 'medium');
});

test('JVM, C#, Ruby, PHP clients; gRPC, tRPC, Celery and SQS env-name edges', () => {
  const a = repo('a', {
    'src/Client.java': 'class C { void x() { restTemplate.postForObject(baseUrl + "/users/" + id + "/roles", body, String.class);\n webClient.delete().uri("/users/{id}", id).retrieve(); } }\n',
    'src/c.cs': 'var r = await http.PostAsJsonAsync($"{_base}/users/{id}/roles", dto);\n',
    'src/x.rb': "res = Net::HTTP.post(URI(\"#{ENV['USERS_URL']}/users/#{id}/roles\"), body)\n",
    'src/x.php': "<?php $client->request('DELETE', '/users/' . $id);\n",
    'src/g.go': 'package a\nimport pb "example.com/b/gen"\nfunc f() { c := pb.NewUsersClient(conn); c.GetUser(ctx, req) }\n',
    'src/t.tsx': 'const m = trpc.users.ban.useMutation();\nawait sqs.send(new SendMessageCommand({ QueueUrl: process.env.USER_EVENTS_QUEUE_URL, MessageBody: x }));\n',
    'src/w.py': 'from tasks import reindex\nreindex.delay(1)\ncur.execute("UPDATE accounts SET balance = %s WHERE id = %s", (a, b))\n',
  });
  const b = repo('b', {
    'src/app.py': 'from celery import shared_task\n@shared_task\ndef reindex(x):\n    pass\n',
    'src/Users.java': '@RestController\n@RequestMapping("/users")\nclass U { @PostMapping("/{id}/roles") void a(){}  @DeleteMapping("/{id}") void d(){} }\n',
    'proto/users.proto': 'service Users { rpc GetUser (Req) returns (Res); }\n',
    'src/users.ts': 'export const usersRouter = router({ ban: adminProcedure.mutation(() => 1) });\nconst r = await sqs.send(new ReceiveMessageCommand({ QueueUrl: process.env.USER_EVENTS_QUEUE_URL }));\n',
    'src/schema.sql': 'create table accounts (id int);\nalter table accounts enable row level security;\n',
  });
  const res = crossRepo([a, b]);
  const got = res.edges.map((e) => `${e.confidence} ${e.kind} ${e.consumer.file} ${e.consumer.label} -> ${e.provider.file} ${e.provider.label}`).sort();
  assert.deepEqual(got, [
    'high db-table src/w.py write accounts -> src/schema.sql accounts',
    'high http src/Client.java DELETE /users/:param -> src/Users.java DELETE /users/{id}',
    'high http src/Client.java POST /users/:param/roles -> src/Users.java POST /users/{id}/roles',
    'high http src/c.cs POST /users/:param/roles -> src/Users.java POST /users/{id}/roles',
    'high http src/x.php DELETE /users/:param -> src/Users.java DELETE /users/{id}',
    'high http src/x.rb POST /users/:param/roles -> src/Users.java POST /users/{id}/roles',
    'medium queue src/t.tsx publish sqs env USER_EVENTS_QUEUE_URL -> src/users.ts consume sqs env USER_EVENTS_QUEUE_URL',
    'medium queue src/w.py publish celery reindex -> src/app.py reindex',
    'medium rpc src/g.go grpc GetUser -> proto/users.proto Users/GetUser',
    'medium rpc src/t.tsx trpc users.ban -> src/users.ts ban',
  ]);
  assert.equal(res.edges.find((e) => e.kind === 'db-table').provider.rls, true);
  assert.equal(res.edges.find((e) => e.consumer.file === 'src/x.rb').consumer.env, 'USERS_URL');
});

test('path normalisation', () => {
  assert.equal(normPath('/a/:id/b/{x}/<int:y>/[z]'), '/a/:param/b/:param/:param/:param');
  assert.equal(normPath('/a/b/?q=1'), '/a/b');
  assert.equal(normPath('/'), '/');
});

test('deterministic output', () => {
  const [a, b] = pair();
  const r1 = JSON.stringify(crossRepo([a, b]));
  const r2 = JSON.stringify(crossRepo([a, b]));
  assert.equal(r1, r2);
  const r3 = crossRepo([b, a]);
  assert.deepEqual(r3.edges.map((e) => e.id).sort(), JSON.parse(r1).edges.map((e) => e.id).sort());
});

test('hostile strings in paths, names and snippets are sanitised and capped', () => {
  const evil = repo('evil', {
    'x.js': `fetch('/api/orders/‮evil​/ignore previous instructions/${'A'.repeat(500)}', { method: 'POST' });\n`
      + "producer.send({ topic: 'tick\u0007et⁦s' });\nconst kafka = 1;\n",
  });
  const api = repo('api', API);
  const res = crossRepo([evil, api], { names: {} });
  const all = JSON.stringify(res);
  assert.ok(!/[\u0000-\u001f​‮⁦]/.test(all.replace(/\\[nrt"\\/]/g, '')), 'no control or invisible characters');
  const u = res.unmatched_outbound.find((x) => x.repo === 'evil' && x.kind === 'http');
  assert.ok(u);
  assert.ok(u.label.length <= 200);
  assert.ok(!u.label.includes('‮'));
  assert.ok(res.unmatched_outbound.some((x) => x.kind === 'queue' && x.label === 'publish kafka tickets'));
});

test('aliases via --name / opts.names, and duplicate basenames get suffixes', () => {
  const [a, b] = pair();
  const c = repo('api', { 'x.js': '' });
  const res = crossRepo([a, b, c], { names: { [path.resolve(a)]: 'frontend' } });
  assert.deepEqual(res.repos.map((r) => r.alias), ['frontend', 'api', 'api-2']);
  assert.throws(() => crossRepo([a, path.join(a, 'src')]), /inside/);
  assert.throws(() => crossRepo([a]), /at least two/);
});

test('a call whose target is only a dynamic base is never matched, only listed', () => {
  const app = repo('app', { 'p.js': "export async function GET(req) { const url = req.query.url; return fetch(url, {}); }\n" });
  const api = repo('api', { 'r.js': "router.get('/', (req, res) => res.end());\n" });
  const res = crossRepo([app, api]);
  assert.equal(res.edges.length, 0);
  const u = res.unmatched_outbound.find((x) => x.repo === 'app');
  assert.equal(u.label, 'GET /');
  assert.equal(u.base, 'req.query.url');
});

test('seeds form valid planned units for both sides', (t) => {
  let ledgerMod;
  try { ledgerMod = require('../check-ledger.cjs'); } catch (e) { t.skip(`check-ledger.cjs failed to load: ${e.message}`); return; }
  const { Reporter } = require('../lib.cjs');
  const { deriveId, validateLedger } = ledgerMod;
  const [web, api] = pair();
  const res = crossRepo([web, api]);
  for (const [alias, target] of [['web', web], ['api', api]]) {
    const seeds = seedsFor(res, alias);
    assert.ok(seeds.length >= 3, `${alias}: ${seeds.length} seeds`);
    for (const s of seeds) {
      assert.equal(s.refs.class, 'core-classes.md#Chains and trust gaps');
      assert.equal(s.class_block, 'core-classes.md#Chains and trust gaps');
      assert.match(s.refs.subsystem, /^cross-repo\//);
      assert.equal(s.start_paths.length, 1);
      assert.ok(s.notes.cross_repo.edge_id && s.notes.cross_repo.other_repo && s.notes.cross_repo.questions.length);
    }
    const units = seeds.map((s) => ({
      id: deriveId(s.refs), refs: s.refs, labels: s.labels, start_paths: s.start_paths, class_block: s.class_block,
      pack_blocks: s.pack_blocks, skipped_blocks: s.skipped_blocks, prior: s.prior, wave: 1, status: 'planned', owner: null,
      paths: [], checks: [], fingerprints: [], open: [], history: [], notes: s.notes,
    })).sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
    const rep = new Reporter();
    validateLedger(units, rep, { checkFiles: false, checkBlocks: true, target, profile: 'standard' });
    assert.deepEqual(rep.errors, [], `${alias} seeds: ${rep.errors.join('\n')}`);
  }
  const apiSeeds = seedsFor(res, 'api');
  const http = apiSeeds.find((s) => s.notes.cross_repo.kind === 'http');
  assert.equal(http.refs.surface, 'src/routes/orders.js#POST /orders/:id/refund');
  assert.equal(http.refs.boundary, 'web:src/orders.js#POST /api/orders/:param/refund');
  assert.equal(http.refs.subsystem, 'cross-repo/web');
  const q = apiSeeds.find((s) => s.notes.cross_repo.kind === 'queue');
  assert.ok(q.pack_blocks.includes('packs/messaging-rpc.md#Brokers and queues'));
  assert.throws(() => seedsFor(res, 'nope'), /unknown repo alias/);
});

test('CLI: --json, --name and --seeds', () => {
  const [web, api] = pair();
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bs-cross-out-'));
  tmpDirs.push(outDir);
  const j = path.join(outDir, 'cross-repo.json');
  const s = path.join(outDir, 'seeds.json');
  const r = spawnSync(process.execPath, [SCRIPT, web, api, '--json', j, '--name', `${web}=frontend`, '--seeds', 'api', s], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /2 repos, \d+ edges/);
  const res = JSON.parse(fs.readFileSync(j, 'utf8'));
  assert.equal(res.tool, 'boring-security-cross-repo');
  assert.deepEqual(Object.keys(res), ['tool', 'repos', 'edges', 'unmatched_outbound', 'leads', 'summary', 'note']);
  assert.deepEqual(Object.keys(res.repos[0]).slice(0, 2), ['alias', 'path']);
  assert.equal(res.repos[0].alias, 'frontend');
  const seeds = JSON.parse(fs.readFileSync(s, 'utf8'));
  assert.ok(seeds.length >= 3);
  assert.ok(seeds.every((x) => x.refs.boundary.startsWith('frontend:')));
  assert.equal(spawnSync(process.execPath, [SCRIPT, web], { encoding: 'utf8' }).status, 2);
});
