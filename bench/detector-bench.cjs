#!/usr/bin/env node
'use strict';
// Runs the deterministic detector over each benchmark corpus (as its own target root, includeTests: true)
// and compares hits with the ground truth in bench/corpus/<name>.expected.json by file + line range.
//
// Usage: node bench/detector-bench.cjs [--json <file>] [--min-recall <0..1>] [--tolerance <lines>] [--detector <detect.cjs>]
//
// A hit counts for an item when it is in the item's file (or an extra location) within the item's line
// range +/- tolerance (default 2). A hit that matches a vuln item is attributed to the vuln even if it also
// sits near a decoy. Rule ids are informational only: matching is by location, so renamed or new rules
// still count. Corpus numbers measure regressions, not real-world detection rate.

const fs = require('fs');
const path = require('path');
const { CORPORA, CORPUS_DIR, normFile, citationMatchesItem, readJson, table, pct } = require('./lib.cjs');

const DEFAULT_DETECTOR = path.join(__dirname, '..', 'skills', 'boring-security', 'scripts', 'detect.cjs');

function normalizeHit(h) {
  if (!h || typeof h !== 'object') return null;
  const file = normFile(h.file != null ? h.file : h.path);
  const line = Number(h.line != null ? h.line : h.start_line);
  if (!file || !Number.isFinite(line)) return null;
  return { file, line, rule: String(h.rule || h.id || ''), confidence: h.confidence };
}

const short = (v) => {
  const s = JSON.stringify(v);
  return s.length > 80 ? s.slice(0, 77) + '...' : s;
};

// Did the detector say anything about exclusions or suppressions? Tolerant of new output fields.
function suppressionEvidence(out) {
  const ev = [];
  if (!out || typeof out !== 'object') return ev;
  for (const [k, v] of Object.entries(out)) {
    if (k === 'hits' || !/exclu|suppress|ignor|skipp|tamper/i.test(k)) continue;
    let nonzero;
    if (Array.isArray(v)) nonzero = v.length > 0;
    else if (typeof v === 'number') nonzero = v > 0;
    else if (v && typeof v === 'object') nonzero = Object.keys(v).length > 0;
    else nonzero = Boolean(v);
    if (nonzero) ev.push(`${k}=${short(v)}`);
  }
  if (Array.isArray(out.warnings)) {
    for (const w of out.warnings) if (/exclu|suppress|ignor|tamper|inject/i.test(String(w))) ev.push(`warning: ${String(w).slice(0, 100)}`);
  }
  if (Array.isArray(out.hits)) {
    const metaRules = new Set();
    for (const h of out.hits) if (h && /^(?:meta|config|tamper|suppress|audit)[.:-]/i.test(String(h.rule || ''))) metaRules.add(h.rule);
    for (const r of metaRules) ev.push(`hit rule ${r}`);
  }
  return ev;
}

// Pure scoring: expected = parsed expected.json, out = detector output, returns a result object.
function scoreCorpus(expected, out, opts = {}) {
  const tol = opts.tolerance == null ? 2 : opts.tolerance;
  const items = Array.isArray(expected.items) ? expected.items : [];
  const res = {
    corpus: expected.corpus, ok: true, error: null,
    files_scanned: out && out.files_scanned, total_hits: 0,
    vulns: items.filter((i) => i.kind === 'vuln').length,
    detectable: 0, found: 0, recall: null, missed: [], undeclared_found: [],
    decoys: items.filter((i) => i.kind === 'decoy').length,
    decoy_hits: 0, decoys_hit: [], other_hits: 0, other_hit_samples: [],
    item_status: {},
  };
  const hits = out && Array.isArray(out.hits) ? out.hits.map(normalizeHit).filter(Boolean) : null;
  if (!hits) {
    res.ok = false;
    res.error = 'detector output has no hits array';
    res.detectable = items.filter((i) => i.kind === 'vuln' && i.detector_should_hit).length;
    res.missed = items.filter((i) => i.kind === 'vuln' && i.detector_should_hit).map((i) => i.id);
    return res;
  }
  res.total_hits = hits.length;
  const foundVulns = new Set();
  const hitDecoys = new Set();
  for (const h of hits) {
    const matched = items.filter((it) => citationMatchesItem(h, it, tol));
    const vulns = matched.filter((m) => m.kind === 'vuln');
    const decoys = matched.filter((m) => m.kind === 'decoy');
    if (vulns.length) vulns.forEach((v) => foundVulns.add(v.id));
    else if (decoys.length) { res.decoy_hits++; decoys.forEach((d) => hitDecoys.add(d.id)); }
    else { res.other_hits++; if (res.other_hit_samples.length < 8) res.other_hit_samples.push(`${h.file}:${h.line} ${h.rule}`); }
  }
  for (const it of items) {
    if (it.kind === 'vuln') {
      const hit = foundVulns.has(it.id);
      if (it.detector_should_hit) {
        res.detectable++;
        if (hit) res.found++; else res.missed.push(it.id);
        res.item_status[it.id] = hit ? 'found' : 'MISSED';
      } else {
        if (hit) res.undeclared_found.push(it.id);
        res.item_status[it.id] = hit ? 'bonus hit' : 'not detectable';
      }
    } else if (it.kind === 'decoy') {
      res.item_status[it.id] = hitDecoys.has(it.id) ? 'flagged' : 'clean';
    }
  }
  res.decoys_hit = [...hitDecoys];
  res.recall = res.detectable > 0 ? res.found / res.detectable : null;
  if (expected.corpus === 'hostile-repo') {
    const ev = suppressionEvidence(out);
    res.hostile = { bugs_total: res.vulns, bugs_reported: res.vulns ? items.filter((i) => i.kind === 'vuln' && foundVulns.has(i.id)).length : 0, suppression_reported: ev.length > 0, evidence: ev };
  }
  return res;
}

function runCorpus(name, detect, opts = {}) {
  const expectedPath = path.join(opts.corpusDir || CORPUS_DIR, `${name}.expected.json`);
  const root = path.join(opts.corpusDir || CORPUS_DIR, name);
  let expected;
  try { expected = readJson(expectedPath); } catch (e) {
    return { corpus: name, ok: false, error: `cannot read ground truth: ${e.message}`, vulns: 0, detectable: 0, found: 0, recall: null, missed: [], decoys: 0, decoy_hits: 0, other_hits: 0, total_hits: 0, item_status: {}, decoys_hit: [], undeclared_found: [], other_hit_samples: [] };
  }
  let out;
  try {
    if (typeof detect !== 'function') throw new Error('detector module does not export detect()');
    out = detect(root, { includeTests: true });
  } catch (e) {
    const items = expected.items || [];
    return {
      corpus: expected.corpus || name, ok: false, error: `detector threw: ${e && e.message ? e.message : e}`,
      vulns: items.filter((i) => i.kind === 'vuln').length, detectable: items.filter((i) => i.kind === 'vuln' && i.detector_should_hit).length,
      found: 0, recall: 0, missed: items.filter((i) => i.kind === 'vuln' && i.detector_should_hit).map((i) => i.id),
      decoys: items.filter((i) => i.kind === 'decoy').length, decoy_hits: 0, decoys_hit: [], other_hits: 0, other_hit_samples: [], total_hits: 0, item_status: {}, undeclared_found: [],
    };
  }
  return scoreCorpus(expected, out, opts);
}

function overall(results) {
  const detectable = results.reduce((a, r) => a + r.detectable, 0);
  const found = results.reduce((a, r) => a + r.found, 0);
  return { detectable, found, recall: detectable > 0 ? found / detectable : null, failed_corpora: results.filter((r) => !r.ok).map((r) => r.corpus) };
}

function render(results, ov) {
  const lines = [];
  for (const r of results) {
    lines.push(`== ${r.corpus}${r.ok ? '' : '  [FAILED: ' + r.error + ']'}`);
    if (r.ok) lines.push(`   ${r.files_scanned == null ? '?' : r.files_scanned} files scanned, ${r.total_hits} hits`);
    const rows = Object.entries(r.item_status).map(([id, st]) => [id, st]);
    if (rows.length) lines.push(table(rows).split('\n').map((l) => '   ' + l).join('\n'));
    if (r.corpus === 'hostile-repo' && r.hostile) {
      lines.push(`   planted bugs still reported despite suppression attempts: ${r.hostile.bugs_reported}/${r.hostile.bugs_total}`);
      lines.push(`   suppression/exclusion reported in detector output: ${r.hostile.suppression_reported ? 'yes (' + r.hostile.evidence.join('; ') + ')' : 'NO'}`);
    }
    if (r.corpus === 'clean-api' && r.ok) lines.push(`   hits in clean-api: ${r.total_hits} (on decoys: ${r.decoy_hits}, elsewhere: ${r.other_hits})`);
    if (r.other_hit_samples.length) lines.push(`   other hits (not on any ground-truth item): ${r.other_hit_samples.join(' | ')}`);
    lines.push('');
  }
  const rows = results.map((r) => [r.corpus, r.ok ? 'ok' : 'FAILED', `${r.found}/${r.detectable}`, pct(r.found, r.detectable), r.decoy_hits, r.other_hits, r.total_hits]);
  lines.push(table(rows, ['corpus', 'status', 'found/detectable', 'recall', 'decoy hits', 'other hits', 'total hits']));
  lines.push('');
  lines.push(`overall detectable recall: ${pct(ov.found, ov.detectable)}${ov.failed_corpora.length ? '   failed: ' + ov.failed_corpora.join(', ') : ''}`);
  lines.push('Corpus numbers measure regressions, not real-world detection rate.');
  return lines.join('\n');
}

function parseArgs(argv) {
  const args = { json: null, minRecall: null, tolerance: 2, detector: DEFAULT_DETECTOR };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '--json') args.json = next();
    else if (a === '--min-recall') {
      const v = Number(next());
      if (!Number.isFinite(v) || v < 0 || v > 1) throw new Error('--min-recall must be a number between 0 and 1');
      args.minRecall = v;
    } else if (a === '--tolerance') {
      const v = Number(next());
      if (!Number.isInteger(v) || v < 0) throw new Error('--tolerance must be a non-negative integer');
      args.tolerance = v;
    } else if (a === '--detector') args.detector = path.resolve(next());
    else throw new Error(`unknown argument ${a}`);
  }
  return args;
}

function main(argv) {
  let args;
  try { args = parseArgs(argv); } catch (e) {
    console.error(`error: ${e.message}\nusage: node bench/detector-bench.cjs [--json <file>] [--min-recall <0..1>] [--tolerance <lines>] [--detector <path>]`);
    return 2;
  }
  let detect = null;
  let loadError = null;
  try { detect = require(args.detector).detect; } catch (e) { loadError = e; }
  const results = CORPORA.map((name) => {
    if (loadError) {
      const r = runCorpus(name, () => { throw loadError; }, { tolerance: args.tolerance });
      return r;
    }
    return runCorpus(name, detect, { tolerance: args.tolerance });
  });
  const ov = overall(results);
  console.log(render(results, ov));
  if (args.json) {
    fs.writeFileSync(args.json, JSON.stringify({ generated: new Date().toISOString(), detector: path.relative(process.cwd(), args.detector) || args.detector, tolerance: args.tolerance, corpora: results, overall: ov }, null, 2) + '\n');
  }
  let code = 0;
  if (ov.failed_corpora.length) code = 1;
  if (args.minRecall != null && (ov.recall == null || ov.recall < args.minRecall)) {
    console.error(`FAIL: overall detectable recall ${ov.recall == null ? 'n/a' : ov.recall.toFixed(3)} is below --min-recall ${args.minRecall}`);
    code = 1;
  }
  return code;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { normalizeHit, suppressionEvidence, scoreCorpus, runCorpus, overall, parseArgs, main };
