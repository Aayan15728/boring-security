'use strict';
// Shared helpers for the benchmark scripts. Zero dependencies, Node >= 18.

const fs = require('fs');
const path = require('path');

const CORPORA = ['vuln-shop', 'hostile-repo', 'clean-api'];
const CORPUS_DIR = path.join(__dirname, 'corpus');

const normFile = (f) => String(f == null ? '' : f).replace(/\\/g, '/').replace(/^(?:\.\/)+/, '');

// A cited path matches an expected path when equal, or when the citation carries an extra leading prefix
// (for example the corpus directory) in front of the expected repo-relative path.
function fileMatches(cited, expected) {
  const c = normFile(cited);
  const e = normFile(expected);
  if (!c || !e) return false;
  return c === e || c.endsWith('/' + e);
}

function inRange(line, range, tol = 0) {
  const n = Number(line);
  if (!Number.isFinite(n) || !Array.isArray(range) || range.length < 1) return false;
  const lo = Number(range[0]);
  const hi = Number(range.length > 1 ? range[1] : range[0]);
  return n >= lo - tol && n <= hi + tol;
}

// Primary location plus any extra `locations` of an item.
function itemLocations(item) {
  const locs = [{ file: item.file, lines: item.lines, anchor: item.anchor }];
  if (Array.isArray(item.locations)) for (const l of item.locations) if (l && l.file && l.lines) locs.push(l);
  return locs;
}

function citationMatchesItem(cite, item, tol) {
  if (!cite) return false;
  return itemLocations(item).some((l) => fileMatches(cite.file, l.file) && inRange(cite.line, l.lines, tol));
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function pad(value, width) {
  const s = String(value);
  return s.length >= width ? s : s + ' '.repeat(width - s.length);
}

function table(rows, header) {
  const all = header ? [header, ...rows] : rows;
  const widths = [];
  for (const r of all) r.forEach((c, i) => { widths[i] = Math.max(widths[i] || 0, String(c).length); });
  const line = (r) => r.map((c, i) => pad(c, widths[i])).join('  ').trimEnd();
  const out = [];
  if (header) { out.push(line(header)); out.push(widths.map((w) => '-'.repeat(w)).join('  ')); }
  for (const r of rows) out.push(line(r));
  return out.join('\n');
}

const pct = (num, den) => (den > 0 ? `${Math.round((num / den) * 100)}% (${num}/${den})` : 'n/a');

module.exports = { CORPORA, CORPUS_DIR, normFile, fileMatches, inRange, itemLocations, citationMatchesItem, readJson, table, pct };
