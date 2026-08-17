#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const selfPath = 'scripts/check-test-focus.mjs';
const sourceExtension = /\.(?:cjs|cts|js|jsx|mjs|mts|ts|tsx)$/u;

const patterns = [
  {
    kind: 'FOCUSED_TEST',
    expression: new RegExp(
      String.raw`\b(?:describe|it|test)(?:\.(?:concurrent|failing|serial))*\.only\b`,
      'gu',
    ),
  },
  {
    kind: 'SKIPPED_TEST',
    expression: new RegExp(
      String.raw`\b(?:describe|it|test)(?:\.(?:concurrent|failing|serial))*\.(?:skip|todo)\b`,
      'gu',
    ),
  },
  {
    kind: 'FOCUSED_TEST',
    expression: new RegExp(String.raw`\b(?:fdescribe|fit)\s*\(`, 'gu'),
  },
  {
    kind: 'SKIPPED_TEST',
    expression: new RegExp(String.raw`\b(?:xdescribe|xit|xtest)\s*\(`, 'gu'),
  },
];

export const findTestFocusViolations = (source) => {
  const findings = [];
  for (const { kind, expression } of patterns) {
    expression.lastIndex = 0;
    for (const match of source.matchAll(expression)) {
      const line = source.slice(0, match.index).split('\n').length;
      findings.push({ kind, line });
    }
  }
  return findings.sort(
    (left, right) => left.line - right.line || left.kind.localeCompare(right.kind),
  );
};

const trackedSources = () => {
  const result = spawnSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    {
      cwd: workspaceRoot,
      encoding: 'buffer',
    },
  );
  if (result.status !== 0) throw new Error('TEST_FOCUS_GIT_LIST_FAILED');
  return result.stdout
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .map((file) => file.replaceAll('\\', '/'))
    .filter(
      (file) =>
        file !== selfPath &&
        sourceExtension.test(file) &&
        (file.startsWith('apps/') || file.startsWith('infra/') || file.startsWith('scripts/')),
    )
    .sort();
};

const selfTest = () => {
  assert.deepEqual(findTestFocusViolations('describe("safe", () => {});'), []);
  assert.equal(findTestFocusViolations('test.' + 'only("x", () => {});')[0]?.kind, 'FOCUSED_TEST');
  assert.equal(
    findTestFocusViolations('describe.' + 'skip("x", () => {});')[0]?.kind,
    'SKIPPED_TEST',
  );
  assert.equal(findTestFocusViolations('fit("x", () => {});')[0]?.kind, 'FOCUSED_TEST');
  assert.equal(findTestFocusViolations('xtest("x", () => {});')[0]?.kind, 'SKIPPED_TEST');
  assert.equal(
    findTestFocusViolations('test.concurrent.' + 'only("x", async () => {});')[0]?.kind,
    'FOCUSED_TEST',
  );
  assert.equal(
    findTestFocusViolations('test.concurrent.' + 'skip("x", async () => {});')[0]?.kind,
    'SKIPPED_TEST',
  );
};

if (process.argv.includes('--self-test')) {
  selfTest();
  process.stdout.write('test-focus guard self-test: PASS\n');
} else {
  const findings = trackedSources().flatMap((file) =>
    findTestFocusViolations(readFileSync(path.join(workspaceRoot, file), 'utf8')).map(
      (finding) => ({
        file,
        ...finding,
      }),
    ),
  );
  if (findings.length > 0) {
    findings.forEach(({ file, line, kind }) => process.stderr.write(`${kind}: ${file}:${line}\n`));
    process.exitCode = 1;
  } else {
    process.stdout.write('test-focus guard: PASS\n');
  }
}
