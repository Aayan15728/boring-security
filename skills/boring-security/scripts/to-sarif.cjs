#!/usr/bin/env node
'use strict';
// Convert boring-security findings.json to SARIF 2.1.0 on stdout.
// Usage: node to-sarif.cjs <findings.json> > findings.sarif
// Runs check-findings first and refuses to convert invalid input.

const { Reporter, loadJson } = require('./lib.cjs');
const { validateFindings } = require('./check-findings.cjs');

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', informational: 'note' };
const SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', informational: '0.5' };

function toSarif(findings) {
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
    const loc = (t) => ({ physicalLocation: { artifactLocation: { uri: t.file, uriBaseId: 'SRCROOT' }, region: { startLine: t.line } }, message: { text: `${t.step}: ${t.scope} - ${t.note}` } });
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
    }
    results.push(res);
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'boring-security', version: '0.3.0', rules } },
      originalUriBaseIds: { SRCROOT: { uri: 'file:///' } },
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
module.exports = { toSarif };
