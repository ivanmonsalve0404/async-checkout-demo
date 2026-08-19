#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { appendFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const sarifFiles = (inputPath) => {
  const resolved = path.resolve(inputPath);
  if (statSync(resolved).isFile()) return [resolved];
  return readdirSync(resolved, { withFileTypes: true })
    .flatMap((entry) =>
      entry.isDirectory()
        ? sarifFiles(path.join(resolved, entry.name))
        : /\.sarif(?:\.json)?$/iu.test(entry.name)
          ? [path.join(resolved, entry.name)]
          : [],
    )
    .sort();
};

const toolComponents = (run) => [run.tool?.driver, ...(run.tool?.extensions ?? [])].filter(Boolean);

const ruleFor = (run, result) => {
  const components = toolComponents(run);
  const componentIndex = result.rule?.toolComponent?.index;
  const referencedComponent = Number.isSafeInteger(componentIndex)
    ? run.tool?.extensions?.[componentIndex]
    : run.tool?.driver;
  const ruleIndex = result.ruleIndex ?? result.rule?.index;

  if (typeof result.ruleId === 'string') {
    const matchingRule = components
      .flatMap((component) => component.rules ?? [])
      .find(({ id }) => id === result.ruleId);
    if (matchingRule !== undefined) return matchingRule;
  }
  return Number.isSafeInteger(ruleIndex) ? referencedComponent?.rules?.[ruleIndex] : undefined;
};

const classificationFor = (run, result) => {
  const rule = ruleFor(run, result);
  const value = result.properties?.['security-severity'] ?? rule?.properties?.['security-severity'];
  if (value === 'critical') return { kind: 'score', score: 9 };
  if (value === 'high') return { kind: 'score', score: 7 };
  if (value !== undefined) {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 10
      ? { kind: 'score', score: parsed }
      : { kind: 'security-unclassified' };
  }
  if (rule === undefined) return { kind: 'unresolved' };

  const tags = [...(result.properties?.tags ?? []), ...(rule.properties?.tags ?? [])];
  return tags.some((tag) => tag === 'security' || /^external\/cwe\//u.test(tag))
    ? { kind: 'security-unclassified' }
    : { kind: 'non-security' };
};

export const summarizeCodeqlSarif = (documents) => {
  if (!Array.isArray(documents) || documents.length === 0) {
    throw new Error('CODEQL_SARIF_MISSING');
  }
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unclassified: 0,
    securityUnclassified: 0,
    unresolved: 0,
    total: 0,
  };
  const blockingRuleIds = new Set();
  for (const document of documents) {
    if (
      document?.version !== '2.1.0' ||
      !Array.isArray(document.runs) ||
      document.runs.length === 0
    ) {
      throw new Error('CODEQL_SARIF_INVALID');
    }
    for (const run of document.runs) {
      if (!Array.isArray(run.results)) throw new Error('CODEQL_SARIF_RESULTS_INVALID');
      for (const result of run.results) {
        counts.total += 1;
        const classification = classificationFor(run, result);
        if (classification.kind === 'non-security') counts.unclassified += 1;
        else if (classification.kind === 'security-unclassified') {
          counts.securityUnclassified += 1;
          blockingRuleIds.add(result.ruleId ?? 'RULE_ID_MISSING');
        } else if (classification.kind === 'unresolved') {
          counts.unresolved += 1;
          blockingRuleIds.add(result.ruleId ?? 'RULE_ID_MISSING');
        } else if (classification.score >= 9) counts.critical += 1;
        else if (classification.score >= 7) counts.high += 1;
        else if (classification.score >= 4) counts.medium += 1;
        else counts.low += 1;
      }
    }
  }
  return {
    schemaVersion: 1,
    status:
      counts.critical === 0 &&
      counts.high === 0 &&
      counts.securityUnclassified === 0 &&
      counts.unresolved === 0
        ? 'PASS'
        : 'FAIL',
    threshold: 'security-severity >= 7.0',
    findings: counts,
    blockingRuleIds: [...blockingRuleIds].sort(),
  };
};

const loadSummary = (inputPath) => {
  const files = sarifFiles(inputPath);
  if (files.length === 0) throw new Error('CODEQL_SARIF_MISSING');
  const sources = files.map((file) => readFileSync(file));
  const documents = sources.map((source) => JSON.parse(source.toString('utf8')));
  const summary = summarizeCodeqlSarif(documents);
  const digest = createHash('sha256');
  files.forEach((file, index) => {
    digest.update(path.basename(file));
    digest.update('\0');
    digest.update(sources[index]);
  });
  return { ...summary, files: files.length, sarifSha256: digest.digest('hex') };
};

const argument = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};

const selfTest = () => {
  const document = (score, includeResult = score !== undefined, tags = []) => ({
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            rules: [{ id: 'js/example', properties: { 'security-severity': score, tags } }],
          },
        },
        results: includeResult ? [{ ruleId: 'js/example' }] : [],
      },
    ],
  });
  assert.equal(summarizeCodeqlSarif([document(undefined)]).status, 'PASS');
  assert.equal(summarizeCodeqlSarif([document(undefined, true)]).status, 'PASS');
  assert.equal(summarizeCodeqlSarif([document(undefined, true)]).findings.unclassified, 1);
  assert.equal(summarizeCodeqlSarif([document(undefined, true, ['security'])]).status, 'FAIL');
  assert.equal(
    summarizeCodeqlSarif([document(undefined, true, ['external/cwe/cwe-079'])]).findings
      .securityUnclassified,
    1,
  );
  assert.equal(summarizeCodeqlSarif([document('6.9')]).status, 'PASS');
  assert.equal(summarizeCodeqlSarif([document('0.0')]).status, 'PASS');
  assert.equal(summarizeCodeqlSarif([document('7.0')]).status, 'FAIL');
  assert.equal(summarizeCodeqlSarif([document('9.0')]).findings.critical, 1);
  assert.equal(summarizeCodeqlSarif([document('not-a-score')]).status, 'FAIL');
  assert.equal(
    summarizeCodeqlSarif([
      {
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: { rules: [] },
              extensions: [
                {
                  rules: [{ id: 'js/extension-rule', properties: { 'security-severity': '8.1' } }],
                },
              ],
            },
            results: [{ rule: { index: 0, toolComponent: { index: 0 } } }],
          },
        ],
      },
    ]).findings.high,
    1,
  );
  assert.equal(
    summarizeCodeqlSarif([
      {
        version: '2.1.0',
        runs: [
          {
            tool: { driver: { rules: [{ id: 'js/indexed', properties: {} }] } },
            results: [{ ruleIndex: 0 }],
          },
        ],
      },
    ]).status,
    'PASS',
  );
  assert.equal(
    summarizeCodeqlSarif([
      {
        version: '2.1.0',
        runs: [{ tool: { driver: { rules: [] } }, results: [{ ruleId: 'js/missing' }] }],
      },
    ]).findings.unresolved,
    1,
  );
  assert.throws(() => summarizeCodeqlSarif([]), /CODEQL_SARIF_MISSING/u);
  assert.throws(
    () => summarizeCodeqlSarif([{ version: '2.1.0', runs: [] }]),
    /CODEQL_SARIF_INVALID/u,
  );
  assert.equal(sha256('stage6').length, 64);
};

if (process.argv.includes('--self-test')) {
  selfTest();
  process.stdout.write('stage-6 CodeQL SARIF self-test: PASS\n');
} else {
  const inputPath = argument('--input');
  if (inputPath === undefined) throw new Error('CODEQL_SARIF_INPUT_REQUIRED');
  const summary = loadSummary(inputPath);
  const githubOutput = argument('--github-output');
  if (githubOutput !== undefined) {
    appendFileSync(
      githubOutput,
      [
        `status=${summary.status}`,
        `critical=${summary.findings.critical}`,
        `high=${summary.findings.high}`,
        `unclassified=${summary.findings.unclassified}`,
        `security_unclassified=${summary.findings.securityUnclassified}`,
        `unresolved=${summary.findings.unresolved}`,
        `total=${summary.findings.total}`,
        `sarif_sha256=${summary.sarifSha256}`,
      ].join('\n') + '\n',
      'utf8',
    );
  }
  process.stdout.write(
    `codeql-sarif: ${summary.status} (${summary.findings.high} high; ${summary.findings.critical} critical; ` +
      `${summary.findings.unclassified} non-security; ${summary.findings.securityUnclassified} security-unclassified; ` +
      `${summary.findings.unresolved} unresolved)` +
      (summary.blockingRuleIds.length > 0
        ? `; blocking rules: ${summary.blockingRuleIds.join(', ')}`
        : '') +
      '\n',
  );
  if (summary.status !== 'PASS') {
    const diagnostic =
      `critical=${summary.findings.critical}, high=${summary.findings.high}, ` +
      `security-unclassified=${summary.findings.securityUnclassified}, unresolved=${summary.findings.unresolved}, ` +
      `blocking-rules=${summary.blockingRuleIds.join(',') || 'none'}`;
    process.stderr.write(`::error title=CodeQL SARIF severity gate::${diagnostic}\n`);
    process.exitCode = 1;
  }
}
