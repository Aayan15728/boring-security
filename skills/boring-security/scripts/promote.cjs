#!/usr/bin/env node
'use strict';
// Lead-only: copy ONE allowlisted file from an agent's scratch/ into its evidence/.
// Usage: node promote.cjs <scratch-root> <evidence-root> <relpath> <maxBytes>
// Exit 0 = promoted. Anything else = NOT evidence. Rules: references/evidence-promotion.md.
//
// Linux: every component is resolved relative to an open directory descriptor via
// /proc/self/fd/<fd>/<name> with O_NOFOLLOW, so a concurrent writer can't redirect the walk.
// Other OSes: per-component lstat; correct only once every sandboxed process has exited.

const fs = require('fs');
const path = require('path');

const C = fs.constants;
const NOFOLLOW = C.O_NOFOLLOW || 0;
const NONBLOCK = C.O_NONBLOCK || 0;
const DIRECTORY = C.O_DIRECTORY || 0;
const FD_RELATIVE = process.platform === 'linux' && fs.existsSync('/proc/self/fd');

function fail(msg) { console.error(`promote: REFUSED - ${msg}`); process.exit(1); }

function segments(rel) {
  if (typeof rel !== 'string' || !rel.length) fail('empty path');
  if (rel.includes('\\') || rel.startsWith('/') || /^[A-Za-z]:/.test(rel) || /[\u0000-\u001f]/.test(rel)) fail('path must be relative with forward slashes');
  const segs = rel.split('/');
  if (segs.some((s) => s === '' || s === '.' || s === '..')) fail('path contains an empty, "." or ".." segment');
  return segs;
}

// A directory handle: on Linux an fd (child paths go through /proc/self/fd), elsewhere a plain path.
function openRoot(p) {
  const st = fs.lstatSync(p, { throwIfNoEntry: false });
  if (!st || st.isSymbolicLink() || !st.isDirectory()) fail(`${p} is not a real directory`);
  if (!FD_RELATIVE) return { path: p, fd: null };
  return { fd: fs.openSync(p, C.O_RDONLY | DIRECTORY | NOFOLLOW), path: null };
}
const child = (dir, name) => (dir.fd !== null ? `/proc/self/fd/${dir.fd}/${name}` : path.join(dir.path, name));
function close(dir) { if (dir.fd !== null) fs.closeSync(dir.fd); }

function openSubdir(dir, name, create) {
  const p = child(dir, name);
  if (create) { try { fs.mkdirSync(p, 0o755); } catch (e) { if (e.code !== 'EEXIST') fail(`cannot create ${name}: ${e.code}`); } }
  if (dir.fd !== null) {
    let fd;
    try { fd = fs.openSync(p, C.O_RDONLY | DIRECTORY | NOFOLLOW); } catch (e) { fail(`component ${name} is not a real directory (${e.code})`); }
    return { fd, path: null };
  }
  const st = fs.lstatSync(p, { throwIfNoEntry: false });
  if (!st || st.isSymbolicLink() || !st.isDirectory()) fail(`component ${name} is not a real directory`);
  return { fd: null, path: p };
}

function walk(root, segs, create) {
  let dir = openRoot(root);
  for (const s of segs) { const next = openSubdir(dir, s, create); close(dir); dir = next; }
  return dir;
}

function main() {
  const [, , scratchRoot, evidenceRoot, rel, maxStr] = process.argv;
  if (!scratchRoot || !evidenceRoot || !rel || !maxStr) { console.error('usage: node promote.cjs <scratch-root> <evidence-root> <relpath> <maxBytes>'); process.exit(2); }
  const max = Number(maxStr);
  if (!Number.isSafeInteger(max) || max <= 0) fail('maxBytes must be a positive integer');
  if (!NOFOLLOW && process.platform !== 'win32') fail('O_NOFOLLOW unavailable on this platform');

  const segs = segments(rel);
  const leaf = segs.pop();
  const srcDir = walk(path.resolve(scratchRoot), segs, false);
  const srcPath = child(srcDir, leaf);
  if (!FD_RELATIVE) {
    const pre = fs.lstatSync(srcPath, { throwIfNoEntry: false });
    if (!pre || pre.isSymbolicLink() || !pre.isFile()) fail('source is not a regular file');
  }

  let fd;
  try { fd = fs.openSync(srcPath, C.O_RDONLY | NOFOLLOW | NONBLOCK); } catch (e) { fail(`cannot open source without following links: ${e.code}`); }
  close(srcDir);
  let buf;
  let size;
  try {
    const a = fs.fstatSync(fd);
    if (!a.isFile()) fail('source is not a regular file');
    if (a.nlink !== 1) fail(`source has ${a.nlink} hard links`);
    if (a.size > max) fail(`source is ${a.size} bytes, cap is ${max}`);
    size = a.size;
    buf = Buffer.alloc(size);
    let off = 0;
    while (off < size) { const n = fs.readSync(fd, buf, off, size - off, off); if (n === 0) break; off += n; }
    if (off !== size || fs.readSync(fd, Buffer.alloc(1), 0, 1, off) !== 0) fail('source size changed while reading');
    const b = fs.fstatSync(fd);
    if (b.ino !== a.ino || b.dev !== a.dev || b.size !== a.size || b.nlink !== 1 || !b.isFile()) fail('source identity changed while reading');
  } finally { fs.closeSync(fd); }

  const dstDir = walk(path.resolve(evidenceRoot), segs, true);
  let out;
  try { out = fs.openSync(child(dstDir, leaf), C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o444); } catch (e) { fail(`cannot create destination exclusively: ${e.code}`); }
  close(dstDir);
  try {
    const d = fs.fstatSync(out);
    if (!d.isFile() || d.nlink !== 1 || d.size !== 0) fail('destination is not a fresh regular file');
    fs.writeSync(out, buf, 0, buf.length, 0);
  } finally { fs.closeSync(out); }
  console.log(`promote: OK ${rel} (${size} bytes${FD_RELATIVE ? ', fd-relative' : ''})`);
}

main();
