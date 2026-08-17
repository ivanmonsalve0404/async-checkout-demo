#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import process from 'node:process';

import {
  baseEvidence,
  candidate,
  normalizedText,
  selfTestEvidence,
  sha256File,
  stage6RunId,
  workspaceRoot,
  writeRuntimeEvidence,
} from './lib/evidence.mjs';
import {
  EXTERNAL_CAPABILITY_KEYS,
  externalEvidenceCapabilityDecision,
  resolveExternalEvidence,
  selfTestExternalEvidence,
} from './external-evidence.mjs';

const fail = (message) => {
  throw new Error(message);
};

const uniqueMatches = (source, pattern) => new Set(source.match(pattern) ?? []).size;

const expandedNumericInventory = (source, prefix) => {
  const ids = new Set(source.match(new RegExp(`\\b${prefix}-\\d{2}\\b`, 'gu')) ?? []);
  const rangePattern = new RegExp(
    `\\b${prefix}-(\\d{2})\\s+(?:a|hasta|\\.\\.)\\s+${prefix}-(\\d{2})\\b`,
    'gu',
  );
  for (const match of source.matchAll(rangePattern)) {
    const start = Number(match[1]);
    const end = Number(match[2]);
    if (!Number.isInteger(start) || !Number.isInteger(end) || end < start || end > 99) {
      fail(`Invalid ${prefix} range in canonical baseline`);
    }
    for (let value = start; value <= end; value += 1) {
      ids.add(`${prefix}-${String(value).padStart(2, '0')}`);
    }
  }
  return ids.size;
};

const canonicalInventory = () => {
  const requirements = normalizedText('output/etapas-0-1-incepcion-y-requisitos.md');
  return {
    acceptanceCriteria: uniqueMatches(requirements, /\bAC-US-\d{2}-\d{2}\b/gu),
    scenarios: uniqueMatches(requirements, /\bSC-(?:US|EN|TSK)-\d{2}-\d{2}\b/gu),
    errors: expandedNumericInventory(requirements, 'ERR'),
    data: expandedNumericInventory(requirements, 'DAT'),
    uat: expandedNumericInventory(requirements, 'UAT'),
  };
};

const expectedInventory = {
  acceptanceCriteria: 45,
  scenarios: 51,
  errors: 24,
  data: 72,
  uat: 48,
};

if (process.argv.includes('--self-test')) {
  selfTestEvidence();
  selfTestExternalEvidence();
  process.stdout.write('stage-6 preflight self-test: PASS\n');
  process.exit(0);
}

const manifest = JSON.parse(readFileSync(resolve(workspaceRoot, 'package.json'), 'utf8'));
const stage5Baseline = JSON.parse(
  readFileSync(resolve(workspaceRoot, 'scripts', 'stage6', 'baseline.json'), 'utf8'),
);
if (
  stage5Baseline.schemaVersion !== 1 ||
  !/^[0-9a-f]{40}$/u.test(stage5Baseline.stage5CommitSha) ||
  !/^[0-9a-f]{64}$/u.test(stage5Baseline.stage5ManifestSha256) ||
  sha256File(stage5Baseline.stage5ManifestPath) !== stage5Baseline.stage5ManifestSha256
) {
  fail('Stage 5 baseline manifest is invalid or has drifted');
}
if (process.version !== 'v24.19.0') {
  fail(`Node must be v24.19.0; received ${process.version}`);
}
if (manifest.packageManager !== 'pnpm@11.19.0') fail('pnpm must remain pinned to 11.19.0');
if (!process.env.npm_config_user_agent?.startsWith('pnpm/11.19.0')) {
  fail('Run Stage 6 preflight through pnpm 11.19.0');
}

const inventory = canonicalInventory();
for (const [name, expected] of Object.entries(expectedInventory)) {
  if (inventory[name] !== expected) {
    fail(`Canonical ${name} inventory drift: ${inventory[name]} != ${expected}`);
  }
}

const currentCandidate = candidate();
const ancestry = spawnSync(
  'git',
  ['merge-base', '--is-ancestor', stage5Baseline.stage5CommitSha, currentCandidate.commitSha],
  { cwd: workspaceRoot, windowsHide: true, stdio: 'ignore' },
);
if (ancestry.status !== 0) fail('Stage 6 candidate must descend from the pinned Stage 5 baseline');
const requireClean = process.argv.includes('--require-clean');
if (requireClean && currentCandidate.workingTree !== 'CLEAN') {
  fail('A release-candidate preflight requires a clean working tree');
}

const runId = stage6RunId();
const externalExecution = { commitSha: currentCandidate.commitSha, runId };
const externalEvidence = await resolveExternalEvidence(externalExecution);
const externalDecision = (capability) =>
  externalEvidenceCapabilityDecision(externalEvidence, capability, externalExecution);
const authorizationState = (capability) => {
  const decision = externalDecision(capability);
  return decision === 'PASS'
    ? 'APPROVED_BY_EXTERNAL_VERSIONED_EVIDENCE'
    : decision === 'NOT_RUN_AUTH_REQUIRED'
      ? decision
      : 'REJECTED_INVALID_EXTERNAL_EVIDENCE';
};
const externalEvidenceReady = EXTERNAL_CAPABILITY_KEYS.every(
  (capability) => externalDecision(capability) === 'PASS',
);
const externalEvidenceFailed = externalEvidence.status === 'FAIL';
const evidence = {
  ...baseEvidence({
    artifactId: 'ART-VER-02',
    command: `pnpm stage6:preflight${requireClean ? ' -- --require-clean' : ''}`,
    tool: { node: process.version, packageManager: manifest.packageManager },
    runId,
  }),
  status: externalEvidenceFailed ? 'FAIL' : 'PASS',
  baselineMode: requireClean ? 'RELEASE_CANDIDATE' : 'IMPLEMENTATION',
  lockfileSha256: sha256File('pnpm-lock.yaml'),
  canonicalInventory: inventory,
  corrections: {
    instructionAcceptanceCriteria66: 'SUPERSEDED_BY_CANONICAL_45',
    instructionErrors22: 'SUPERSEDED_BY_CANONICAL_24',
    instructionUat34: 'SUPERSEDED_BY_CANONICAL_48',
  },
  entryGate: {
    stage5Head: stage5Baseline.stage5CommitSha,
    stage5ManifestSha256: stage5Baseline.stage5ManifestSha256,
    candidateDescendsFromStage5: true,
    reconciliation: 'CHG-E6-01',
    state: externalEvidenceFailed
      ? 'FAIL_INVALID_EXTERNAL_EVIDENCE'
      : externalEvidenceReady
        ? 'GO_AUTHORIZED_EXTERNAL_EVIDENCE_READY'
        : 'CONDITIONAL_GO_POST_MERGE_CI_GREEN_EXTERNAL_AUTH_BLOCKED',
  },
  authorizations: {
    AUTH_E6_01: authorizationState('ownedTarget'),
    AUTH_E6_02: authorizationState('sandboxSmoke'),
    AUTH_E6_03: authorizationState('passiveSecurity'),
    AUTH_E6_04: 'PROHIBITED_WITHOUT_AUTH_E6_04',
  },
  externalEvidence,
  externalRequests: 0,
};

writeRuntimeEvidence('preflight.json', evidence);
process.stdout.write(
  `stage-6 preflight: ${evidence.status} (${currentCandidate.workingTree}, ${inventory.uat} UAT)\n`,
);
if (evidence.status === 'FAIL') process.exitCode = 1;
