#!/usr/bin/env node
'use strict';
// PostToolUse write-time secret guard (all sessions).
//
// After Write / Edit / MultiEdit / NotebookEdit, runs boring-security's deterministic detector on
// just the written file. If it finds a high-confidence secret-class lead (`secret.*` or
// `ai.browser-key`), it tells the model via additionalContext so the key can be moved out of the
// code before it ships. Otherwise it prints nothing.
//
// Never blocks, never prints a secret (detector snippets are redacted, and this script masks any
// remaining long token-like value), skips files over 1 MB and binary files, and fails open on any
// error. Off switch: environment variable BORING_SECURITY_GUARD=off.

const fs = require('fs');
const path = require('path');

const MAX_FILE = 1024 * 1024;
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
const MAX_REPORTED = 10;

function isOff() {
  const v = String(process.env.BORING_SECURITY_GUARD || '').trim().toLowerCase();
  return v === 'off' || v === '0' || v === 'false' || v === 'disabled';
}

function loadDetector() {
  const roots = [];
  if (process.env.CLAUDE_PLUGIN_ROOT) roots.push(process.env.CLAUDE_PLUGIN_ROOT);
  roots.push(path.join(__dirname, '..'));
  for (const r of roots) {
    const p = path.join(r, 'skills', 'boring-security', 'scripts', 'detect.cjs');
    if (fs.existsSync(p)) return require(p);
  }
  return null;
}

/** Mask anything that still looks like a credential value. */
function mask(s) {
  return String(s)
    .replace(/(["'`])([^"'`\s]{8,})\1/g, (_, q, v) => `${q}${v.slice(0, 4)}…[masked]${q}`)
    .replace(/(?=[A-Za-z0-9_\-+/=]*[a-z])(?=[A-Za-z0-9_\-+/=]*\d)[A-Za-z0-9_\-+/=]{20,}/g, (v) => `${v.slice(0, 4)}…[masked]`)
    .slice(0, 200);
}

function within(child, parent) {
  const cf = process.platform === 'win32' || process.platform === 'darwin';
  const rel = path.relative(cf ? parent.toLowerCase() : parent, cf ? child.toLowerCase() : child);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function analyse(input) {
  if (isOff() || !input || typeof input !== 'object') return null;
  if (!WRITE_TOOLS.has(input.tool_name)) return null;
  const ti = input.tool_input && typeof input.tool_input === 'object' ? input.tool_input : {};
  const raw = ti.file_path ?? ti.notebook_path;
  if (typeof raw !== 'string' || !raw || raw.includes('\0')) return null;
  const cwd = typeof input.cwd === 'string' && path.isAbsolute(input.cwd) ? input.cwd : process.cwd();
  const abs = path.resolve(cwd, raw);

  let st;
  try { st = fs.lstatSync(abs); } catch { return null; }
  if (!st.isFile() || st.size === 0 || st.size > MAX_FILE) return null;
  const fd = fs.openSync(abs, 'r');
  try {
    const head = Buffer.alloc(Math.min(8192, st.size));
    fs.readSync(fd, head, 0, head.length, 0);
    if (head.includes(0)) return null; // binary
  } finally { fs.closeSync(fd); }

  const det = loadDetector();
  if (!det || typeof det.detect !== 'function') return null;
  const root = within(abs, cwd) ? cwd : path.dirname(abs);
  const rel = path.relative(root, abs);
  const out = det.detect(root, { files: [rel], minConfidence: 'high' });
  const hits = (out && Array.isArray(out.hits) ? out.hits : []).filter((h) => h && h.confidence === 'high'
    && typeof h.rule === 'string' && (h.rule.startsWith('secret.') || h.rule === 'ai.browser-key'));
  if (!hits.length) return null;

  const shown = rel.split(path.sep).join('/');
  const lines = [`boring-security write-time guard: ${hits.length} high-confidence secret lead(s) in the file you just wrote (${shown}). Fix this now, before it ships:`];
  for (const h of hits.slice(0, MAX_REPORTED)) {
    lines.push(`- ${h.rule} at ${shown}:${h.line}: ${mask(h.snippet || '')}`);
    if (h.verify) lines.push(`  check: ${String(h.verify).slice(0, 300)}`);
  }
  if (hits.length > MAX_REPORTED) lines.push(`- …and ${hits.length - MAX_REPORTED} more.`);
  lines.push('Advice: move the value to a server-side environment variable or secret store and read it at runtime; never bundle it into client code. If this value was ever committed or deployed, treat it as leaked and rotate it. Do not echo the secret back. If it is a deliberate dummy, keep it obviously fake or add a `boring-security-ignore <rule> -- <reason>` comment.');
  return { context: lines.join('\n'), count: hits.length, file: shown };
}

function main() {
  if (isOff()) return;
  let input;
  try { input = JSON.parse(fs.readFileSync(0, 'utf8')); } catch { return; }
  const r = analyse(input);
  if (!r) return;
  process.stdout.write(JSON.stringify({
    systemMessage: `boring-security: possible hard-coded secret in ${r.file} (${r.count} lead(s)); Claude was asked to fix it.`,
    hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: r.context },
  }) + '\n');
}

if (require.main === module) {
  try { main(); } catch { /* fail open: never disturb the session */ }
  process.exitCode = 0;
}

module.exports = { analyse, mask };
