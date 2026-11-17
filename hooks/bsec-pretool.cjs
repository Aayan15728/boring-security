#!/usr/bin/env node
'use strict';
// PreToolUse guard for boring-security's own subagents (bsec-*).
//
// Scope: acts ONLY when the hook input's `agent_type` names one of this plugin's bsec-* agents
// (plain `bsec-hunter` or plugin-scoped `boring-security:bsec-hunter`). Every other session,
// subagent or tool call is left alone: no output, exit 0.
//
// What it enforces for bsec-* agents:
//   - Write / Edit / MultiEdit / NotebookEdit: only inside RUN_DIR/agents/<id>/scratch/ or
//     RUN_DIR/agents/<id>/out/, where RUN_DIR is a directory holding run.json. `..` is resolved and
//     the real path (symlinks, junctions) must stay inside that zone.
//   - Bash / PowerShell / Monitor: denied outright for agents without a sandbox role; for the
//     *-sandbox roles, a deny-list of commands that fetch, install or reach the network.
//     THIS IS DEFENCE IN DEPTH, NOT A SANDBOX. A shell string can be obfuscated in endless ways
//     (variables, eval, base64, interpreters with inline code); the real network/filesystem
//     barrier is the OS sandbox the lead must verify before choosing a *-sandbox agent.
//   - WebFetch / WebSearch / Artifact / mcp__* : denied (background subagents keep MCP tools even
//     with a `tools` allowlist, so the allowlist alone is not enough).
//
// Fail open: malformed input, unknown fields or any internal error -> no decision (exit 0).
// Exit 2 is never used; denials are JSON permissionDecision "deny" on stdout.

const fs = require('fs');
const path = require('path');

const AGENTS = new Set([
  'bsec-scout', 'bsec-hunter', 'bsec-hunter-lite', 'bsec-hunter-sandbox', 'bsec-skeptic', 'bsec-skeptic-sandbox',
  'bsec-critic', 'bsec-record-check',
]);
const SHELL_AGENTS = new Set(['bsec-hunter-sandbox', 'bsec-skeptic-sandbox']);
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
const SHELL_TOOLS = new Set(['Bash', 'PowerShell']);
const NET_TOOLS = new Set(['WebFetch', 'WebSearch', 'Artifact', 'Monitor']);
const AGENT_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const ZONES = new Set(['scratch', 'out']);

/** Returns the bare bsec role name, or null when the caller is not one of ours. */
function bsecRole(agentType) {
  if (typeof agentType !== 'string' || !agentType) return null;
  const parts = agentType.split(':');
  const name = parts[parts.length - 1];
  if (!AGENTS.has(name)) return null;
  // Accept bare names and the plugin-scoped form. Any plugin prefix is accepted on purpose:
  // a plugin installed under another marketplace name keeps the manifest namespace anyway.
  return name;
}

// ---------------------------------------------------------------- write paths

const caseFold = process.platform === 'win32' || process.platform === 'darwin';
const norm = (p) => (caseFold ? p.toLowerCase() : p);
function inside(child, parent) {
  const rel = path.relative(norm(parent), norm(child));
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

/** realpath of the longest existing prefix, with the non-existing tail appended. */
function realOf(p) {
  let cur = p;
  const tail = [];
  for (;;) {
    try {
      const real = fs.realpathSync.native(cur);
      return tail.length ? path.join(real, ...tail.reverse()) : real;
    } catch {
      const parent = path.dirname(cur);
      if (parent === cur) return p;
      tail.push(path.basename(cur));
      cur = parent;
    }
  }
}

function checkWritePath(raw, cwd) {
  if (typeof raw !== 'string' || !raw) return 'no target path in tool input';
  if (raw.includes('\0')) return 'path contains a NUL byte';
  if (process.platform !== 'win32' && raw.includes('\\')) return 'backslashes are not path separators here; use a plain POSIX path';
  if (process.platform === 'win32' && raw.slice(2).includes(':')) return 'alternate data streams and device paths are not allowed';
  const base = typeof cwd === 'string' && path.isAbsolute(cwd) ? cwd : process.cwd();
  const abs = path.resolve(base, raw);
  const segs = abs.split(path.sep);
  // Find the innermost .../agents/<id>/(scratch|out)/<something> whose parent holds run.json.
  for (let i = segs.length - 4; i >= 1; i--) {
    if (norm(segs[i]) !== 'agents' || !ZONES.has(norm(segs[i + 2]))) continue;
    const id = segs[i + 1];
    if (!AGENT_ID.test(id)) continue;
    const runDir = segs.slice(0, i).join(path.sep) || path.sep;
    const runDirAbs = /^[A-Za-z]:$/.test(runDir) ? runDir + path.sep : runDir;
    let isRun = false;
    try { isRun = fs.statSync(path.join(runDirAbs, 'run.json')).isFile(); } catch { isRun = false; }
    if (!isRun) continue;
    const zone = path.join(runDirAbs, 'agents', id, segs[i + 2]);
    const realRun = realOf(runDirAbs);
    const realZone = realOf(zone);
    const expectZone = path.join(realRun, 'agents', id, segs[i + 2]);
    if (norm(realZone) !== norm(expectZone)) return `the agents/${id}/${segs[i + 2]} directory is a link that leaves the run directory`;
    if (!inside(realOf(abs), realZone)) return 'the resolved real path escapes the agent zone (symlink or junction)';
    return null;
  }
  return `writes are allowed only under RUN_DIR/agents/<agent-id>/scratch/ or RUN_DIR/agents/<agent-id>/out/ of a run directory containing run.json; refused: ${abs}`;
}

function writeTargets(toolName, input) {
  if (!input || typeof input !== 'object') return [undefined];
  const p = input.file_path ?? input.notebook_path ?? input.path;
  return [p];
}

// ---------------------------------------------------------------- shell commands

const ALWAYS = new Set([
  'curl', 'wget', 'aria2c', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'start-bitstransfer',
  'bitsadmin', 'certutil', 'ssh', 'scp', 'sftp', 'rsync', 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ftp', 'tftp',
  'npx', 'bunx', 'pnpx', 'uvx', 'pipx', 'gh', 'aws', 'gcloud', 'gsutil', 'az', 'kubectl', 'helm', 'oc',
  'brew', 'apt', 'apt-get', 'aptitude', 'dnf', 'yum', 'pacman', 'zypper', 'apk', 'snap', 'flatpak', 'port',
  'choco', 'winget', 'scoop', 'install-module', 'install-package', 'save-module', 'nuget',
]);
const SUB = {
  npm: ['install', 'i', 'add', 'ci', 'isntall', 'in', 'update', 'up', 'upgrade', 'exec', 'x', 'init', 'create', 'publish', 'login', 'adduser'],
  pnpm: ['install', 'i', 'add', 'ci', 'update', 'up', 'dlx', 'exec', 'create', 'publish', 'fetch'],
  yarn: ['install', 'add', 'up', 'upgrade', 'dlx', 'create', 'publish', 'npm'],
  bun: ['install', 'i', 'add', 'x', 'create', 'update', 'publish', 'pm'],
  pip: ['install', 'download', 'wheel'],
  pip3: ['install', 'download', 'wheel'],
  uv: ['install', 'add', 'sync', 'pip', 'tool', 'python', 'lock'],
  poetry: ['install', 'add', 'update', 'lock'],
  pipenv: ['install', 'update', 'sync'],
  conda: ['install', 'create', 'update'],
  gem: ['install', 'update', 'fetch'],
  bundle: ['install', 'update', 'add'],
  cargo: ['install', 'add', 'fetch', 'update', 'publish'],
  go: ['install', 'get', 'mod'],
  composer: ['install', 'require', 'update', 'create-project'],
  dotnet: ['add', 'restore', 'tool'],
  git: ['clone', 'fetch', 'pull', 'push', 'remote', 'submodule', 'ls-remote', 'archive', 'send-email', 'request-pull', 'svn'],
  docker: ['pull', 'push', 'login', 'search'],
  podman: ['pull', 'push', 'login', 'search'],
  terraform: ['apply', 'init', 'destroy', 'import', 'get', 'login'],
  tofu: ['apply', 'init', 'destroy', 'import', 'get', 'login'],
};
const NO_ARG_DENY = new Set(['yarn', 'bundle']); // bare `yarn` / `bundle` installs
const WRAPPERS = new Set(['sudo', 'doas', 'env', 'command', 'builtin', 'exec', 'nohup', 'time', 'nice', 'ionice',
  'timeout', 'xargs', 'stdbuf', 'unbuffer', 'busybox', 'call', 'start', 'start-process', '&', '.']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'cmd', 'powershell', 'pwsh']);
const PYTHONS = /^(python[\d.]*|py)$/;
const GIT_ARG_FLAGS = new Set(['-c', '-C', '--git-dir', '--work-tree', '--namespace']);

const WHOLE = [
  [/\/dev\/(tcp|udp)\//i, 'raw /dev/tcp or /dev/udp socket'],
  [/\b(net\.webclient|system\.net\.(webclient|http|sockets)|downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|start-bitstransfer)\b/i, 'PowerShell download/network API'],
  [/\b(curl|wget|iwr|irm|fetch)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b/i, 'piping a download into a shell'],
  [/\b(iex|invoke-expression)\b/i, 'Invoke-Expression'],
];

function cmdName(w) {
  let b = w.replace(/^['"]+|['"]+$/g, '');
  b = b.split(/[\\/]/).pop().toLowerCase();
  return b.replace(/\.(exe|cmd|bat|ps1|com)$/, '');
}

function checkSegment(words) {
  let i = 0;
  while (i < words.length) {
    const w = words[i];
    const c = cmdName(w);
    if (!w || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { i++; continue; }
    if (WRAPPERS.has(c)) { i++; while (i < words.length && /^-/.test(words[i])) i++; if (c === 'timeout' && /^\d/.test(words[i] || '')) i++; continue; }
    if (SHELLS.has(c)) { i++; while (i < words.length && /^[-/]/.test(words[i])) i++; continue; }
    if (ALWAYS.has(c)) return `\`${c}\` reaches the network or installs software`;
    const rest = words.slice(i + 1).map((x) => x.replace(/^['"]+|['"]+$/g, ''));
    if (PYTHONS.test(c)) {
      const m = rest.indexOf('-m');
      const mod = m === -1 ? '' : (rest[m + 1] || '').toLowerCase();
      if (/^(ensurepip|pipx)$/.test(mod)) return `\`python -m ${mod}\` installs software`;
      if (/^(pip|pip3|uv)$/.test(mod) && rest.slice(m + 2).some((x) => /^(install|download|wheel)$/i.test(x))) return `\`python -m ${mod} install\` installs software`;
      return null;
    }
    if (SUB[c]) {
      let j = 0;
      while (j < rest.length && /^-/.test(rest[j])) { j += c === 'git' && GIT_ARG_FLAGS.has(rest[j]) ? 2 : 1; }
      const sub = (rest[j] || '').toLowerCase();
      if (!sub && NO_ARG_DENY.has(c)) return `bare \`${c}\` installs dependencies`;
      if (SUB[c].includes(sub)) return `\`${c} ${sub}\` fetches, installs or reaches the network`;
      // `uv pip install`, `npm exec`, `yarn workspace x add`
      if (c === 'yarn' && sub === 'workspace' && SUB.yarn.includes((rest[j + 2] || '').toLowerCase())) return '`yarn workspace … add/install` installs dependencies';
    }
    return null;
  }
  return null;
}

function checkCommand(cmd) {
  if (typeof cmd !== 'string') return null;
  for (const [re, why] of WHOLE) if (re.test(cmd)) return why;
  const segments = cmd.split(/\|\||&&|[;&|\n\r]|\$\(|`|[(){}]/);
  for (const seg of segments) {
    const words = seg.trim().split(/\s+/).filter(Boolean);
    const r = checkSegment(words);
    if (r) return r;
  }
  return null;
}

// ---------------------------------------------------------------- main

function decide(input) {
  if (!input || typeof input !== 'object') return null;
  const role = bsecRole(input.agent_type);
  if (!role) return null;
  const tool = input.tool_name;
  const ti = input.tool_input && typeof input.tool_input === 'object' ? input.tool_input : {};
  if (typeof tool !== 'string') return null;
  if (WRITE_TOOLS.has(tool)) {
    for (const p of writeTargets(tool, ti)) {
      const why = checkWritePath(p, input.cwd);
      if (why) return `boring-security: ${role} may not write here: ${why}.`;
    }
    return null;
  }
  if (SHELL_TOOLS.has(tool)) {
    if (!SHELL_AGENTS.has(role)) return `boring-security: ${role} has no shell access; use Read, Grep and Glob.`;
    const why = checkCommand(ti.command);
    if (why) return `boring-security: blocked for ${role}: ${why}. Audit agents never fetch, install or contact remote systems; report the exact command you would have run as a needs_validation blocker instead.`;
    return null;
  }
  if (NET_TOOLS.has(tool) || tool.startsWith('mcp__')) {
    return `boring-security: ${role} may not use ${tool}; audit agents work from local source only.`;
  }
  return null;
}

function main() {
  let input;
  try { input = JSON.parse(fs.readFileSync(0, 'utf8')); } catch { return; }
  const reason = decide(input);
  if (!reason) return;
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason },
  }) + '\n');
}

if (require.main === module) {
  try { main(); } catch { /* fail open */ }
  process.exitCode = 0;
}

module.exports = { decide, checkCommand, checkWritePath, bsecRole };
