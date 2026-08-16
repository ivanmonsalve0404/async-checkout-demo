#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import process from 'node:process';

const root = process.cwd();
const evidencePath = resolve(root, 'output/evidence/runtime/stage-5-dependencies.json');
const pnpmEntry = process.env.npm_execpath;
const executable = pnpmEntry
  ? process.execPath
  : process.platform === 'win32'
    ? 'pnpm.cmd'
    : 'pnpm';
const args = pnpmEntry
  ? [pnpmEntry, 'audit', '--prod', '--audit-level', 'high', '--json']
  : ['audit', '--prod', '--audit-level', 'high', '--json'];
const audit = spawnSync(executable, args, {
  cwd: root,
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
  shell: !pnpmEntry && process.platform === 'win32',
});

let parsed;
try {
  parsed = JSON.parse(audit.stdout);
} catch {
  throw new Error('dependency audit returned an unreadable response');
}

const source = parsed?.metadata?.vulnerabilities ?? {};
const vulnerabilities = Object.fromEntries(
  ['info', 'low', 'moderate', 'high', 'critical'].map((severity) => [
    severity,
    Number.isInteger(source[severity]) ? source[severity] : 0,
  ]),
);
if (audit.status !== 0 || vulnerabilities.high > 0 || vulnerabilities.critical > 0) {
  throw new Error(
    'dependency audit found a production vulnerability at or above the high threshold',
  );
}

const evidence = {
  schemaVersion: 1,
  status: 'PASS',
  scope: 'production',
  threshold: 'high',
  dependencies: Number.isInteger(parsed?.metadata?.dependencies)
    ? parsed.metadata.dependencies
    : undefined,
  vulnerabilities,
};
mkdirSync(dirname(evidencePath), { recursive: true });
writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n', 'utf8');
process.stdout.write(
  `dependency-audit: PASS (${vulnerabilities.high} high; ${vulnerabilities.critical} critical)\n`,
);
