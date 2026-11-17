'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const HOOK = path.join(__dirname, '..', 'secret-guard.cjs');
const PLUGIN_ROOT = path.join(__dirname, '..', '..');

// Obviously fake values, assembled at runtime so this test file itself holds no key-shaped literal.
const FAKE_AWS = 'AKIA' + 'FAKEFAKEFAKEFAKE';
const FAKE_LLM = 'sk-proj-' + 'fakefakefake0000fakefakefake0000fake';

function run(input, env = {}) {
  const r = spawnSync(process.execPath, [HOOK], {
    input: typeof input === 'string' ? input : JSON.stringify(input),
    encoding: 'utf8', timeout: 10000,
    env: { ...process.env, CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT, BORING_SECURITY_GUARD: '', ...env },
  });
  assert.strictEqual(r.status, 0, `hook exited ${r.status}: ${r.stderr}`);
  return r.stdout.trim() ? JSON.parse(r.stdout) : null;
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bsec-guard-'));
const app = path.join(tmp, 'app', 'src');
fs.mkdirSync(app, { recursive: true });
const leaky = path.join(app, 'client.js');
fs.writeFileSync(leaky, `const openai = new OpenAI({ apiKey: "${FAKE_LLM}" });\nconst aws = "${FAKE_AWS}";\n`);
const clean = path.join(app, 'clean.js');
fs.writeFileSync(clean, 'const key = process.env.OPENAI_API_KEY;\nexport default key;\n');
const browser = path.join(app, 'browser.ts');
fs.writeFileSync(browser, 'const c = new OpenAI({ apiKey, dangerouslyAllowBrowser: true });\n');
const bin = path.join(app, 'blob.js');
fs.writeFileSync(bin, Buffer.concat([Buffer.from(`"${FAKE_AWS}"`), Buffer.from([0, 1, 2, 0])]));
const big = path.join(app, 'big.js');
fs.writeFileSync(big, `const k = "${FAKE_AWS}";\n` + 'x'.repeat(1024 * 1024 + 10));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const post = (file_path, extra = {}) => ({
  hook_event_name: 'PostToolUse', cwd: path.join(tmp, 'app'), tool_name: 'Write',
  tool_input: { file_path, content: '...' }, tool_response: { filePath: file_path }, ...extra,
});

test('reports a fake high-confidence secret without printing it', () => {
  const out = run(post(leaky));
  assert.ok(out, 'expected output');
  const ctx = out.hookSpecificOutput.additionalContext;
  assert.strictEqual(out.hookSpecificOutput.hookEventName, 'PostToolUse');
  assert.match(ctx, /secret\.llm-api-key at src\/client\.js:1/);
  assert.match(ctx, /secret\.aws-access-key at src\/client\.js:2/);
  assert.match(ctx, /environment variable/);
  assert.match(ctx, /rotate/);
  const all = JSON.stringify(out);
  assert.ok(!all.includes(FAKE_LLM), 'LLM key leaked into output');
  assert.ok(!all.includes(FAKE_AWS), 'AWS key leaked into output');
  assert.ok(!('decision' in out), 'must never block');
});

test('reports ai.browser-key', () => {
  const out = run(post(browser, { tool_name: 'Edit', tool_input: { file_path: browser, old_string: 'a', new_string: 'b' } }));
  assert.ok(out);
  assert.match(out.hookSpecificOutput.additionalContext, /ai\.browser-key/);
});

test('silent on a clean file', () => {
  assert.strictEqual(run(post(clean)), null);
});

test('file outside cwd uses its own directory as root', () => {
  const out = run(post(leaky, { cwd: path.join(tmp, 'elsewhere') }));
  assert.ok(out);
  assert.match(out.hookSpecificOutput.additionalContext, /client\.js:1/);
});

test('relative path resolves against cwd', () => {
  const out = run(post(path.join('src', 'client.js')));
  assert.ok(out);
});

test('silent on binary and oversized files, missing files and other tools', () => {
  assert.strictEqual(run(post(bin)), null);
  assert.strictEqual(run(post(big)), null);
  assert.strictEqual(run(post(path.join(app, 'nope.js'))), null);
  assert.strictEqual(run(post(leaky, { tool_name: 'Read' })), null);
});

test('off switch silences it', () => {
  assert.strictEqual(run(post(leaky), { BORING_SECURITY_GUARD: 'off' }), null);
  assert.strictEqual(run(post(leaky), { BORING_SECURITY_GUARD: 'OFF' }), null);
});

test('malformed input fails open', () => {
  assert.strictEqual(run(''), null);
  assert.strictEqual(run('{not json'), null);
  assert.strictEqual(run('null'), null);
  assert.strictEqual(run({ tool_name: 'Write' }), null);
  assert.strictEqual(run({ tool_name: 'Write', tool_input: { file_path: 42 } }), null);
});

test('fast enough', () => {
  const t0 = Date.now();
  run(post(leaky));
  const ms = Date.now() - t0;
  assert.ok(ms < 2000, `took ${ms} ms including node startup`);
});
