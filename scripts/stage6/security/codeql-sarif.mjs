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

const scoreFor = (run, result) => {
  const rule =
    run.tool?.driver?.rules?.find(({ id }) => id === result.ruleId) ??
    run.tool?.driver?.rules?.[result.rule?.index];
  const value = result.properties?.['security-severity'] ?? rule?.properties?.['security-severity'];
  if (value === 'critical') return 9;
  if (value === 'high') return 7;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

export const summarizeCodeqlSarif = (documents) => {
  if (!Array.isArray(documents) || documents.length === 0) {
    throw new Error('CODEQL_SARIF_MISSING');
  }
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unclassified: 0, total: 0 };
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
        const score = scoreFor(run, result);
        if (score === undefined) counts.unclassified += 1;
        else if (score >= 9) counts.critical += 1;
        else if (score >= 7) counts.high += 1;
        else if (score >= 4) counts.medium += 1;
        else counts.low += 1;
      }
    }
  }
  return {
    schemaVersion: 1,
    status:
      counts.critical === 0 && counts.high === 0 && counts.unclassified === 0 ? 'PASS' : 'FAIL',
    threshold: 'security-severity >= 7.0',
    findings: counts,
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
  const document = (score, includeResult = score !== undefined) => ({
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            rules: [{ id: 'js/example', properties: { 'security-severity': score } }],
          },
        },
        results: includeResult ? [{ ruleId: 'js/example' }] : [],
      },
    ],
  });
  assert.equal(summarizeCodeqlSarif([document(undefined)]).status, 'PASS');
  assert.equal(summarizeCodeqlSarif([document(undefined, true)]).status, 'FAIL');
  assert.equal(summarizeCodeqlSarif([document('6.9')]).status, 'PASS');
  assert.equal(summarizeCodeqlSarif([document('7.0')]).status, 'FAIL');
  assert.equal(summarizeCodeqlSarif([document('9.0')]).findings.critical, 1);
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
        `total=${summary.findings.total}`,
        `sarif_sha256=${summary.sarifSha256}`,
      ].join('\n') + '\n',
      'utf8',
    );
  }
  process.stdout.write(
    `codeql-sarif: ${summary.status} (${summary.findings.high} high; ${summary.findings.critical} critical)\n`,
  );
  if (summary.status !== 'PASS') process.exitCode = 1;
}
