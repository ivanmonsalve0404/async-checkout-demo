import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { ROOT } from './harness.mjs';

import { stage6Branch, stage6Environment, stage6RunId } from '../lib/evidence.mjs';
import { writeSanitizedJsonAtomic } from '../lib/artifact-sanitizer.mjs';
const commandOutput = (executable, arguments_) => {
  const result = spawnSync(executable, arguments_, {
    cwd: ROOT,
    encoding: 'utf8',
    windowsHide: true,
  });
  return result.status === 0 ? result.stdout.trim() : 'UNKNOWN';
};

export const evidenceBase = async ({ command, scriptPath, tool }) => {
  const commitSha = commandOutput('git', ['rev-parse', 'HEAD']);
  return {
    schemaVersion: 1,
    stage: 6,
    generatedAtUtc: new Date().toISOString(),
    commitSha,
    runId: stage6RunId(),
    command,
    tool,
    environment: stage6Environment(),
    executionScope: 'LOCAL_SYNTHETIC_LOOPBACK_ONLY',
    branch: stage6Branch({
      gitBranch: commandOutput('git', ['branch', '--show-current']),
      commitSha,
    }),
    nodeVersion: process.version,
    scriptSha256: createHash('sha256')
      .update(await readFile(scriptPath))
      .digest('hex'),
    networkPolicy: 'LOOPBACK_ONLY_DENY_EXTERNAL',
    containsSensitiveData: false,
  };
};

export const writeEvidence = async (category, report) => {
  const filename = `${category}.json`;
  const target = path.join(ROOT, 'output', 'evidence', 'runtime', 'stage-6', filename);
  await writeSanitizedJsonAtomic(target, filename, report);
  process.stdout.write(`${category}: ${report.status} (${target})\n`);
};
