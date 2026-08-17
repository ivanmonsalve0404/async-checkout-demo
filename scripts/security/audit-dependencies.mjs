#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import process from 'node:process';

import {
  selfTestArtifactSanitizer,
  writeSanitizedJsonAtomic,
} from '../stage6/lib/artifact-sanitizer.mjs';

const root = process.cwd();
const evidencePath = resolve(root, 'output/evidence/runtime/stage-5-dependencies.json');
const pnpmEntry = process.env.npm_execpath;

const pnpmCommand = (arguments_) => {
  const entry = pnpmEntry ?? (process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm');
  if (/\.(?:c?js|mjs)$/iu.test(entry)) {
    return { executable: process.execPath, arguments: [entry, ...arguments_], shell: false };
  }
  if (process.platform === 'win32' && /\.cmd$/iu.test(entry)) {
    return {
      executable: process.env.ComSpec ?? 'cmd.exe',
      arguments: ['/d', '/s', '/c', entry, ...arguments_],
      shell: false,
    };
  }
  return { executable: entry, arguments: arguments_, shell: false };
};

const probe = pnpmCommand(['--version']);
const probeResult = spawnSync(probe.executable, probe.arguments, {
  cwd: root,
  encoding: 'utf8',
  shell: probe.shell,
  windowsHide: true,
});
if (probeResult.status !== 0 || probeResult.stdout.trim() !== '11.19.0') {
  throw new Error('the pinned pnpm executable could not be invoked reproducibly');
}
if (process.argv.includes('--self-test')) {
  selfTestArtifactSanitizer();
  process.stdout.write('dependency-audit pnpm and sanitizer probe: PASS\n');
  process.exit(0);
}

const command = pnpmCommand(['audit', '--prod', '--audit-level', 'high', '--json']);
const audit = spawnSync(command.executable, command.arguments, {
  cwd: root,
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
  shell: command.shell,
  windowsHide: true,
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
await writeSanitizedJsonAtomic(evidencePath, 'stage-5-dependencies.json', evidence);
process.stdout.write(
  `dependency-audit: PASS (${vulnerabilities.high} high; ${vulnerabilities.critical} critical)\n`,
);
