'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { inventory } = require('../inventory.cjs');

const SCRIPT = path.join(__dirname, '..', 'inventory.cjs');
const tmpDirs = [];
function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bs-inventory-'));
  tmpDirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, ...rel.split('/'));
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}
test.after(() => { for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true }); });

const of = (inv, kind) => inv.surfaces.filter((s) => s.kind === kind);
const labels = (inv, kind) => of(inv, kind).map((s) => s.label).sort();

test('output shape and ordering contract', () => {
  const dir = fixture({ 'app/api/orders/route.ts': 'export async function POST() {}\n' });
  const inv = inventory(dir);
  assert.equal(inv.tool, 'boring-security-inventory');
  assert.equal(typeof inv.files_scanned, 'number');
  assert.ok(Array.isArray(inv.skipped));
  assert.match(inv.note, /treat as data/);
  const s = inv.surfaces[0];
  assert.deepEqual(Object.keys(s), ['id', 'kind', 'file', 'line', 'label', 'framework', 'auth_hint']);
  assert.equal(s.id, `${s.kind}:${s.file}#${s.label}`);
});

test('Next.js app router: route group, dynamic segment, catch-all, multiple methods, src/ prefix', () => {
  const dir = fixture({
    'app/(shop)/api/orders/[id]/route.ts': 'export async function GET() {}\nexport const DELETE = async () => {};\n',
    'src/app/api/files/[...slug]/route.js': 'export function PUT() {}\n',
    'app/api/orders/route.ts': "import { auth } from '@/auth';\nexport async function POST(req) { const s = await auth(); }\n",
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'http-route'), ['DELETE /api/orders/:id', 'GET /api/orders/:id', 'POST /api/orders', 'PUT /api/files/*slug']);
  const post = inv.surfaces.find((s) => s.label === 'POST /api/orders');
  assert.equal(post.id, 'http-route:app/api/orders/route.ts#POST /api/orders');
  assert.equal(post.framework, 'next-app-router');
  assert.equal(post.auth_hint, true);
  assert.equal(post.line, 2);
  assert.equal(inv.surfaces.find((s) => s.label === 'GET /api/orders/:id').auth_hint, false);
});

test('Next.js pages api and middleware with matcher', () => {
  const dir = fixture({
    'pages/api/users/[id].ts': 'export default function handler(req, res) {}\n',
    'middleware.ts': "export const config = { matcher: ['/dashboard/:path*', '/api/:path*'] };\n",
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'http-route'), ['ANY /api/users/:id']);
  const mw = of(inv, 'middleware');
  assert.equal(mw.length, 1);
  assert.match(mw[0].label, /matcher=\['\/dashboard\/:path\*', '\/api\/:path\*'\]/);
});

test('server actions: use server file exports each async function', () => {
  const dir = fixture({
    'app/actions.ts': "'use server'\n\nexport async function deleteUser(id: string) {}\nexport const updateEmail = async (e: string) => {};\nexport function notAnAction() {}\n",
    'app/plain.ts': 'export async function notServer() {}\n',
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'server-action'), ['deleteUser', 'updateEmail']);
});

test('SvelteKit +server, form actions; Remix loader/action; Nuxt server/api', () => {
  const dir = fixture({
    'src/routes/api/items/[id]/+server.ts': 'export const GET = () => {};\nexport async function DELETE() {}\n',
    'src/routes/login/+page.server.ts': 'export const actions = {\n  default: async () => {},\n  register: async ({ request }) => {},\n};\n',
    'app/routes/invoices.$id.tsx': 'export async function loader() {}\nexport async function action() {}\n',
    'server/api/users/[id].post.ts': 'export default defineEventHandler(() => {});\n',
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'http-route'), ['DELETE /api/items/:id', 'GET /api/items/:id', 'GET /invoices/:id', 'POST /api/users/:id', 'POST /invoices/:id']);
  assert.deepEqual(labels(inv, 'server-action'), ['ACTION /login', 'ACTION /login?/register']);
});

test('Express: verbs, route() chains, ignores http client calls', () => {
  const dir = fixture({
    'server.js': [
      "const express = require('express');",
      'const app = express();',
      "app.get('/health', (req, res) => {});",
      "router.post('/api/login', authenticate, (req, res) => {});",
      "app.route('/api/items').get(list).post(create);",
      "const r = await axios.get('/api/me');",
      "app.get('port');",
      '',
    ].join('\n'),
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'http-route'), ['GET /api/items', 'GET /health', 'POST /api/items', 'POST /api/login']);
  const login = inv.surfaces.find((s) => s.label === 'POST /api/login');
  assert.equal(login.framework, 'express');
  assert.equal(login.auth_hint, true);
});

test('NestJS controller prefix', () => {
  const dir = fixture({
    'src/orders.controller.ts': "@Controller('orders')\nexport class OrdersController {\n  @Get(':id')\n  one() {}\n  @Post()\n  create() {}\n}\n",
  });
  assert.deepEqual(labels(inventory(dir), 'http-route'), ['GET /orders/:id', 'POST /orders']);
});

test('FastAPI and Flask decorators, Django urls', () => {
  const dir = fixture({
    'main.py': [
      'from fastapi import FastAPI, Depends',
      'app = FastAPI()',
      '',
      '@app.get("/items/{item_id}")',
      'def read(item_id: int, user=Depends(get_current_user)): ...',
      '',
      '@router.post(',
      '    "/items",',
      ')',
      'def make(): ...',
      '',
      '@app.route("/legacy", methods=["GET", "POST"])',
      'def legacy(): ...',
      '',
    ].join('\n'),
    'shop/urls.py': "urlpatterns = [\n  path('cart/', views.cart),\n  re_path(r'^pay/$', views.pay),\n]\n",
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'http-route'), ['ANY /cart', 'ANY /pay', 'GET /items/{item_id}', 'GET /legacy', 'POST /items', 'POST /legacy']);
  assert.equal(inv.surfaces.find((s) => s.label === 'GET /items/{item_id}').auth_hint, true);
  assert.equal(inv.surfaces.find((s) => s.label === 'POST /items').line, 7);
});

test('webhook routes get kind webhook (by path or by file name)', () => {
  const dir = fixture({
    'app/api/webhooks/stripe/route.ts': 'export async function POST(req) {}\n',
    'server.js': "app.post('/hooks/github-webhook', h);\napp.get('/ok', h);\n",
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'webhook'), ['POST /api/webhooks/stripe', 'POST /hooks/github-webhook']);
  assert.deepEqual(labels(inv, 'http-route'), ['GET /ok']);
});

test('Supabase migration: db-table rls true/false, storage policy; edge function', () => {
  const dir = fixture({
    'supabase/migrations/001_init.sql': [
      '-- create table commented_out (id int);',
      'create table public.profiles (id uuid primary key);',
      'create table if not exists public.notes (id uuid primary key);',
      'create table audit_log (id int);',
      'alter table public.profiles enable row level security;',
      'create policy "avatars read" on storage.objects for select using (true);',
      '',
    ].join('\n'),
    'supabase/migrations/002_more.sql': 'ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n',
    'supabase/functions/send-email/index.ts': 'Deno.serve(() => new Response("ok"));\n',
    'supabase/functions/_shared/cors.ts': 'export const cors = {};\n',
    'prisma/schema.prisma': 'model User {\n  id Int @id\n}\n',
  });
  const inv = inventory(dir);
  const tables = Object.fromEntries(of(inv, 'db-table').map((s) => [s.label, s]));
  assert.deepEqual(Object.keys(tables).sort(), ['User', 'audit_log', 'public.notes', 'public.profiles']);
  assert.equal(tables['public.profiles'].rls, true);
  assert.equal(tables['public.notes'].rls, true); // enabled in a later migration without schema prefix
  assert.equal(tables.audit_log.rls, false);
  assert.equal(tables.User.rls, null);
  assert.ok(!('auth_hint' in tables.audit_log));
  assert.deepEqual(labels(inv, 'edge-function'), ['send-email']);
  assert.equal(of(inv, 'storage-rule').length, 1);
});

test('SQL: one table with RLS enabled, one without', () => {
  const dir = fixture({ 'db/schema.sql': 'create table a (id int);\ncreate table b (id int);\nalter table a enable row level security;\n' });
  const t = Object.fromEntries(of(inventory(dir), 'db-table').map((s) => [s.label, s.rls]));
  assert.deepEqual(t, { a: true, b: false });
});

test('GitHub workflow flags pull_request_target; schedule becomes scheduled-job', () => {
  const dir = fixture({
    '.github/workflows/ci.yml': 'name: CI\non:\n  pull_request_target:\n    types: [opened]\n  push:\n    branches: [main]\n  schedule:\n    - cron: "0 3 * * *"\njobs:\n  build:\n    runs-on: ubuntu-latest\n',
    '.github/workflows/short.yml': 'on: [push, issue_comment]\njobs: {}\n',
  });
  const inv = inventory(dir);
  const wf = of(inv, 'ci-workflow');
  assert.equal(wf.length, 2);
  const ci = wf.find((s) => s.file.endsWith('ci.yml'));
  assert.match(ci.label, /pull_request_target \[RISKY\]/);
  assert.match(ci.label, /push/);
  assert.match(wf.find((s) => s.file.endsWith('short.yml')).label, /issue_comment \[RISKY\]/);
  assert.deepEqual(labels(inv, 'scheduled-job'), ['cron 0 3 * * *']);
});

test('AndroidManifest: exported components and deep links; iOS URL schemes', () => {
  const dir = fixture({
    'android/app/src/main/AndroidManifest.xml': [
      '<manifest xmlns:android="http://schemas.android.com/apk/res/android">',
      '  <application>',
      '    <activity android:name=".MainActivity" android:exported="true">',
      '      <intent-filter>',
      '        <data android:scheme="myapp" android:host="open" android:pathPrefix="/item" />',
      '      </intent-filter>',
      '    </activity>',
      '    <activity android:name=".Hidden" android:exported="false" />',
      '    <service android:name=".Sync" android:exported="true"/>',
      '  </application>',
      '</manifest>',
      '',
    ].join('\n'),
    'ios/App/Info.plist': '<plist><dict><key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>myapp</string></array></dict></array></dict></plist>\n',
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'mobile-component'), ['activity .MainActivity', 'service .Sync']);
  assert.deepEqual(labels(inv, 'deep-link'), ['myapp://', 'myapp://open/item']);
});

test('proto rpc, GraphQL SDL, Firestore rules', () => {
  const dir = fixture({
    'api/orders.proto': 'syntax = "proto3";\nservice Orders {\n  rpc GetOrder (Req) returns (Res);\n  // rpc Commented (A) returns (B);\n  rpc Cancel (Req) returns (Res);\n}\n',
    'schema.graphql': 'type Query {\n  me: User\n  order(id: ID!): Order @auth(role: ADMIN)\n}\ntype Mutation {\n  deleteUser(id: ID!): Boolean\n}\ntype User { id: ID! }\n',
    'firestore.rules': "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /users/{id} { allow read: if true; }\n  }\n}\n",
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'rpc-method'), ['Orders/Cancel', 'Orders/GetOrder']);
  assert.deepEqual(labels(inv, 'graphql-operation'), ['Mutation.deleteUser', 'Query.me', 'Query.order']);
  assert.deepEqual(labels(inv, 'storage-rule'), ['match /databases/{database}/documents', 'match /users/{id}']);
});

test('Rails, Laravel, Go, Spring, ASP.NET', () => {
  const dir = fixture({
    'config/routes.rb': "Rails.application.routes.draw do\n  root 'home#index'\n  get '/status', to: 'x#y'\n  resources :orders\nend\n",
    'routes/web.php': "<?php\nRoute::get('/dash', fn() => 1);\nRoute::match(['get','post'], '/form', 'F@x');\n",
    'main.go': 'package main\nfunc main() {\n  http.HandleFunc("/ping", h)\n  r.GET("/v1/users", h)\n  mux.HandleFunc("POST /v2/items", h)\n}\n',
    'src/Api.java': '@RestController\n@RequestMapping("/api")\npublic class Api {\n  @GetMapping("/users/{id}")\n  public User one() {}\n  @RequestMapping(value = "/x", method = RequestMethod.POST)\n  public void x() {}\n}\n',
    'Controllers/ThingController.cs': '[Route("api/things")]\npublic class ThingController {\n  [HttpGet("{id}")]\n  public IActionResult Get() {}\n  [Authorize]\n  [HttpPost]\n  public IActionResult Post() {}\n}\n',
    'Program.cs': 'app.MapGet("/minimal", () => 1);\n',
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'http-route'), [
    'ANY /ping', 'GET /', 'GET /api/things/{id}', 'GET /api/users/{id}', 'GET /dash', 'GET /minimal', 'GET /status', 'GET /v1/users',
    'GET|POST /form', 'POST /api/things', 'POST /api/x', 'POST /v2/items', 'RESOURCES /orders',
  ]);
});

test('Electron IPC, Tauri, MCP tools, queue consumers, cron, package.json bin, vercel crons', () => {
  const dir = fixture({
    'main.js': "ipcMain.handle('fs:read', async () => {});\nipcMain.on('app:quit', () => {});\n",
    'src-tauri/src/main.rs': '#[tauri::command]\nasync fn save_file(p: String) {}\n',
    'mcp.ts': "server.tool('search_docs', {}, async () => {});\nserver.registerTool('write_file', {}, async () => {});\n",
    'tools.py': '@mcp.tool()\nasync def run_query(q: str): ...\n',
    'worker.ts': "import { Worker } from 'bullmq';\nnew Worker('emails', async () => {});\nimport cron from 'node-cron';\ncron.schedule('*/5 * * * *', () => {});\n",
    'tasks.py': 'from celery import shared_task\n@shared_task(bind=True, autoretry_for=(Exception,))\ndef send_mail(self): ...\n',
    'package.json': '{ "name": "tool", "bin": { "tool": "./cli.js" } }\n',
    'vercel.json': '{ "crons": [{ "path": "/api/cron/daily", "schedule": "0 0 * * *" }] }\n',
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'ipc-channel'), ['app:quit', 'fs:read', 'save_file']);
  assert.deepEqual(labels(inv, 'mcp-tool'), ['run_query', 'search_docs', 'write_file']);
  assert.deepEqual(labels(inv, 'queue-consumer'), ['emails', 'send_mail']);
  assert.deepEqual(labels(inv, 'scheduled-job'), ['cron */5 * * * *', 'cron 0 0 * * * -> /api/cron/daily']);
  assert.deepEqual(labels(inv, 'cli-entry'), ['tool -> ./cli.js']);
});

test('dependency, build and test directories are skipped but reported', () => {
  const dir = fixture({
    'node_modules/pkg/index.js': "app.get('/in-deps', h);\n",
    'dist/server.js': "app.get('/in-dist', h);\n",
    'tests/api.js': "app.get('/in-tests', h);\n",
    'examples/demo/server.js': "app.get('/in-examples', h);\n",
    'src/real.js': "app.get('/real', h);\n",
  });
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'http-route'), ['GET /real']);
  const paths = inv.skipped.map((s) => s.path);
  for (const p of ['node_modules', 'dist', 'tests', 'examples']) assert.ok(paths.includes(p), `${p} reported`);
  assert.equal(inv.skipped.find((s) => s.path === 'node_modules').reason, 'dependency directory');
});

test('binary and oversized files are not parsed; oversized relevant files are reported', () => {
  const dir = fixture({ 'ok.js': "app.get('/ok', h);\n" });
  fs.writeFileSync(path.join(dir, 'bin.js'), Buffer.from([0, 1, 2, 3, 0x61, 0x70, 0x70]));
  fs.writeFileSync(path.join(dir, 'big.js'), "app.get('/big', h);\n" + ' '.repeat(1024 * 1024 + 10));
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'http-route'), ['GET /ok']);
  assert.ok(inv.skipped.some((s) => s.path === 'big.js' && /1 MB/.test(s.reason)));
});

test('labels strip control and invisible characters and are capped at 200 chars', () => {
  const evil = 'a‮b​c\u0007d\ne' + 'x'.repeat(400);
  const dir = fixture({ 'server.js': `app.get('/${evil.replace(/\n/g, '')}', h);\n` });
  const inv = inventory(dir);
  const s = inv.surfaces[0];
  assert.ok(s.label.length <= 200);
  assert.ok(!/[\u0000-\u001f\u007f-\u009f​-‏‪-‮]/.test(s.label + s.id));
  assert.ok(s.label.startsWith('GET /abcd'));
});

test('ids are unique even when the same label repeats in one file', () => {
  const dir = fixture({ 'a.js': "app.get('/x', h);\napp.get('/x', h2);\napp.get('/x', h3);\n" });
  const inv = inventory(dir);
  assert.equal(inv.surfaces.length, 3);
  assert.equal(new Set(inv.surfaces.map((s) => s.id)).size, 3);
  assert.equal(inv.surfaces[0].id, 'http-route:a.js#GET /x');
  assert.ok(inv.surfaces.some((s) => s.id.endsWith('@2')));
});

test('deterministic: two runs on the same tree are deeply equal and sorted by id', () => {
  const dir = fixture({
    'app/api/a/route.ts': 'export async function GET() {}\n',
    'b.py': '@app.get("/b")\ndef b(): ...\n',
    'schema.sql': 'create table t (id int);\n',
    '.github/workflows/w.yml': 'on: push\n',
  });
  const a = inventory(dir);
  const b = inventory(dir);
  assert.deepEqual(a, b);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  const ids = a.surfaces.map((s) => s.id);
  assert.deepEqual(ids, [...ids].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0)));
});

test('symlinks are not followed', (t) => {
  const outside = fixture({ 'secret/server.js': "app.get('/outside', h);\n" });
  const dir = fixture({ 'src/real.js': "app.get('/real', h);\n" });
  try {
    fs.symlinkSync(path.join(outside, 'secret'), path.join(dir, 'linked'), 'junction');
    fs.symlinkSync(path.join(outside, 'secret', 'server.js'), path.join(dir, 'linked-file.js'), 'file');
  } catch (e) {
    t.skip(`cannot create symlinks here: ${e.code}`);
    return;
  }
  const inv = inventory(dir);
  assert.deepEqual(labels(inv, 'http-route'), ['GET /real']);
  assert.ok(inv.skipped.some((s) => s.path === 'linked'));
});

test('CLI: summary, --json output, usage errors exit 2', () => {
  const dir = fixture({ 'app/api/orders/route.ts': 'export async function POST() {}\n' });
  const out = path.join(dir, '..', `inv-${process.pid}.json`);
  tmpDirs.push(out);
  const plain = spawnSync(process.execPath, [SCRIPT, dir], { encoding: 'utf8' });
  assert.equal(plain.status, 0);
  assert.match(plain.stdout, /1 surfaces/);
  assert.match(plain.stdout, /\[http-route\] app\/api\/orders\/route\.ts:1 {2}POST \/api\/orders/);
  const js = spawnSync(process.execPath, [SCRIPT, dir, '--json', out], { encoding: 'utf8' });
  assert.equal(js.status, 0);
  assert.doesNotMatch(js.stdout, /\[http-route\]/);
  const parsed = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(parsed.surfaces[0].label, 'POST /api/orders');
  assert.ok(!fs.readFileSync(out, 'utf8').includes('\r'));
  assert.equal(spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [SCRIPT, dir, '--bogus'], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [SCRIPT, dir, '--json'], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [SCRIPT, path.join(dir, 'nope')], { encoding: 'utf8' }).status, 2);
});
