#!/usr/bin/env node
'use strict';
// Convert boring-security findings.json to SARIF 2.1.0 on stdout.
// Usage: node to-sarif.cjs <findings.json> > findings.sarif
// Runs check-findings first and refuses to convert invalid input.

const fs = require('fs');
const path = require('path');
const { Reporter, loadJson } = require('./lib.cjs');
const { validateFindings } = require('./check-findings.cjs');

// Tool version = metadata.version in the front matter of ../SKILL.md (present in skill-only installs too).
// Unreadable or missing: omit the optional field rather than invent a number.
function skillVersion(text) {
  const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(String(text));
  if (!fm) return null;
  const meta = /^metadata:[ \t]*\r?\n((?:[ \t]+.*(?:\r?\n|$))*)/m.exec(fm[1]);
  const v = meta && /^[ \t]+version:[ \t]*["']?([^"'\s#]+)/m.exec(meta[1]);
  return v ? v[1] : null;
}
function readSkillVersion(file = path.join(__dirname, '..', 'SKILL.md')) {
  try { return skillVersion(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

// Repo-relative, forward-slash, percent-encoded URI reference (no scheme, no leading slash).
const relUri = (p) => String(p).replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/^\/+/, '').split('/').map(encodeURIComponent).join('/');

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', informational: 'note' };
const SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', informational: '0.5' };

function toSarif(findings, version = readSkillVersion()) {
  const rules = [];
  const results = [];
  const ruleIndex = new Map();
  for (const r of findings) {
    if (r.verdict === 'rejected') continue;
    const ruleId = r.category || r.fingerprint.split(':')[0] || 'boring-security';
    if (!ruleIndex.has(ruleId)) {
      ruleIndex.set(ruleId, rules.length);
      rules.push({
        id: ruleId,
        name: ruleId.replace(/[^A-Za-z0-9]+(.)?/g, (_, c) => (c ? c.toUpperCase() : '')),
        shortDescription: { text: ruleId },
        properties: { tags: ['security', ...(r.cwe || []).map((c) => `external/cwe/${c.toLowerCase()}`)] },
      });
    }
    const sink = r.trace[r.trace.length - 1];
    const loc = (t) => ({ physicalLocation: { artifactLocation: { uri: relUri(t.file), uriBaseId: '%SRCROOT%' }, region: { startLine: t.line } }, message: { text: `${t.step}: ${t.scope} - ${t.note}` } });
    const confirmed = r.verdict === 'confirmed';
    const text = confirmed
      ? `${r.title}. ${r.root_cause} Observed: ${r.execution.observed_result} Fix: ${r.remediation.strategy}`
      : `[needs validation] ${r.title}. ${r.claimed_root_cause} Blocked on: ${r.blockers.join('; ')}`;
    const res = {
      ruleId,
      ruleIndex: ruleIndex.get(ruleId),
      level: confirmed ? LEVEL[r.severity.overall] : 'note',
      kind: confirmed ? 'fail' : 'review',
      message: { text },
      locations: [loc(sink)],
      partialFingerprints: { 'boringSecurity/v1': r.fingerprint },
      codeFlows: [{ threadFlows: [{ locations: r.trace.map((t) => ({ location: loc(t) })) }] }],
      properties: { verdict: r.verdict, fingerprint: r.fingerprint },
    };
    if (confirmed) {
      res.properties['security-severity'] = SCORE[r.severity.overall];
      res.properties.severity = r.severity.overall;
      res.properties.confidence = r.confidence.level;
      if (r.execution && r.execution.proof) res.properties.proof = r.execution.proof;
    } else if (r.max_impact_if_true) {
      res.properties.max_impact_if_true = r.max_impact_if_true; // triage hint, not a severity
    }
    results.push(res);
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'boring-security', ...(version ? { version } : {}), rules } },
      results,
    }],
  };
}

function main(argv) {
  const file = argv[2];
  if (!file) { console.error('usage: node to-sarif.cjs <findings.json> > findings.sarif'); return 2; }
  const rep = new Reporter();
  const data = loadJson(file, rep);
  if (data !== undefined) validateFindings(data, rep);
  if (rep.errors.length) { rep.finish('findings'); console.error('refusing to convert invalid findings'); return 1; }
  process.stdout.write(JSON.stringify(toSarif(data), null, 2) + '\n');
  return 0;
}

if (require.main === module) process.exitCode = main(process.argv);
module.exports = { toSarif, skillVersion, readSkillVersion, relUri };
