#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import process from 'node:process';

import {
  baseEvidence,
  candidate,
  stage6RunId,
  workspaceRoot,
  writeRuntimeEvidence,
} from './lib/evidence.mjs';

const manifest = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
const pnpmEntry = process.env.npm_execpath;
const runId = stage6RunId();
const isCi = process.env.CI === 'true';
const sharedEnvironment = {
  ...process.env,
  CI: process.env.CI ?? 'false',
  STAGE6_RUN_ID: runId,
};

if (process.version !== 'v24.19.0') {
  throw new Error(`Node must be v24.19.0; received ${process.version}`);
}
if (
  manifest.packageManager !== 'pnpm@11.19.0' ||
  !process.env.npm_config_user_agent?.startsWith('pnpm/11.19.0')
) {
  throw new Error('Run verify:stage6 through pnpm 11.19.0');
}

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

const normalizeStepExitCode = (rawExitCode, audit) =>
  rawExitCode === 0 && audit !== undefined && audit.status !== 'PASS' ? 1 : rawExitCode;

const exactStringSet = (actual, expected) =>
  Array.isArray(actual) &&
  actual.length === expected.length &&
  [...actual].sort().every((value, index) => value === [...expected].sort()[index]);

const isExactPullRequestOpenGateState = ({
  environment,
  results,
  closeout,
  accessibility,
  sandbox,
  uat,
}) => {
  const partialIds = results.filter(({ status }) => status === 'PARTIAL').map(({ id }) => id);
  const uatNotRun = uat?.results
    ?.filter(({ status }) => status.startsWith('NOT_RUN_'))
    .map(({ id, status }) => `${id}:${status}`);
  return (
    environment.CI === 'true' &&
    environment.GITHUB_ACTIONS === 'true' &&
    environment.GITHUB_EVENT_NAME === 'pull_request' &&
    results.every(({ status }) => status === 'PASS' || status === 'PARTIAL') &&
    exactStringSet(partialIds, ['E6-SANDBOX-EVIDENCE', 'E6-UAT']) &&
    closeout?.schemaVersion === 1 &&
    closeout?.stage === 6 &&
    closeout?.status === 'VERIFICATION_INCOMPLETE' &&
    closeout?.releasePolicy === 'STAGE_7_BLOCKED' &&
    closeout?.requiredDocumentsValid === true &&
    closeout?.entryGate?.state === 'CONDITIONAL_GO_POST_MERGE_CI_GREEN_EXTERNAL_AUTH_BLOCKED' &&
    closeout?.externalRequestsMadeByCloseout === 0 &&
    closeout?.externalEvidence?.externalNetworkAttemptsByIngestion === 0 &&
    closeout?.externalEvidence?.summary?.status === 'NOT_PROVIDED' &&
    closeout?.externalEvidence?.summary?.source === 'NOT_PROVIDED' &&
    closeout?.externalEvidence?.summary?.containsSensitiveData === false &&
    closeout?.artifactSummary?.total === 18 &&
    closeout?.artifactSummary?.validStates === 18 &&
    closeout?.artifactSummary?.failed === 0 &&
    exactStringSet(Object.keys(closeout?.gates ?? {}), [
      'GATE-E6-01',
      'GATE-E6-02',
      'GATE-E6-03',
    ]) &&
    closeout.gates['GATE-E6-01'] === 'PASS' &&
    closeout.gates['GATE-E6-02'] === 'FAIL' &&
    closeout.gates['GATE-E6-03'] === 'FAIL' &&
    accessibility?.status === 'PARTIAL_NOT_RUN_MANUAL_REQUIRED' &&
    accessibility?.automated?.status === 'PASS' &&
    accessibility?.automated?.blockedExternalRequests === 0 &&
    accessibility?.manualEvidence?.status === 'NOT_RUN_MANUAL_REQUIRED' &&
    accessibility?.manualEvidence?.reason === 'MANUAL_EVIDENCE_NOT_PROVIDED' &&
    accessibility?.manualEvidence?.containsSensitiveData === false &&
    sandbox?.status === 'NOT_RUN_AUTH_REQUIRED' &&
    sandbox?.externalEvidence?.status === 'NOT_PROVIDED' &&
    sandbox?.externalEvidence?.containsSensitiveData === false &&
    sandbox?.externalRequestsByIngestion === 0 &&
    sandbox?.providerRequestsExecutedByThisProcess === 0 &&
    uat?.status === 'PARTIAL' &&
    uat?.summary?.total === 48 &&
    uat?.summary?.passed === 46 &&
    uat?.summary?.failed === 0 &&
    uat?.summary?.notRunManualRequired === 1 &&
    uat?.summary?.notRunAuthRequired === 1 &&
    uat?.summary?.negativeE2eTotal === 12 &&
    uat?.summary?.negativeE2ePassed === 12 &&
    uat?.summary?.negativeE2eFailed === 0 &&
    uat?.summary?.refreshRecoveryTotal === 8 &&
    uat?.summary?.refreshRecoveryPassed === 8 &&
    uat?.summary?.refreshRecoveryFailed === 0 &&
    uat?.externalNetworkAttempts === 0 &&
    uat?.results?.length === 48 &&
    uat.results.every(({ status }) => status === 'PASS' || status.startsWith('NOT_RUN_')) &&
    exactStringSet(uatNotRun, ['UAT-16:NOT_RUN_MANUAL_REQUIRED', 'UAT-33:NOT_RUN_AUTH_REQUIRED'])
  );
};

const selfTestPullRequestOpenGates = () => {
  const fixture = {
    environment: { CI: 'true', GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'pull_request' },
    results: [
      { id: 'E6-PREFLIGHT', status: 'PASS' },
      { id: 'E6-ACCESSIBILITY', status: 'PASS' },
      { id: 'E6-SANDBOX-EVIDENCE', status: 'PARTIAL' },
      { id: 'E6-UAT', status: 'PARTIAL' },
    ],
    closeout: {
      schemaVersion: 1,
      stage: 6,
      status: 'VERIFICATION_INCOMPLETE',
      releasePolicy: 'STAGE_7_BLOCKED',
      requiredDocumentsValid: true,
      entryGate: { state: 'CONDITIONAL_GO_POST_MERGE_CI_GREEN_EXTERNAL_AUTH_BLOCKED' },
      externalRequestsMadeByCloseout: 0,
      externalEvidence: {
        externalNetworkAttemptsByIngestion: 0,
        summary: {
          status: 'NOT_PROVIDED',
          source: 'NOT_PROVIDED',
          containsSensitiveData: false,
        },
      },
      artifactSummary: { total: 18, validStates: 18, failed: 0 },
      gates: { 'GATE-E6-01': 'PASS', 'GATE-E6-02': 'FAIL', 'GATE-E6-03': 'FAIL' },
    },
    accessibility: {
      status: 'PARTIAL_NOT_RUN_MANUAL_REQUIRED',
      automated: { status: 'PASS', blockedExternalRequests: 0 },
      manualEvidence: {
        status: 'NOT_RUN_MANUAL_REQUIRED',
        reason: 'MANUAL_EVIDENCE_NOT_PROVIDED',
        containsSensitiveData: false,
      },
    },
    sandbox: {
      status: 'NOT_RUN_AUTH_REQUIRED',
      externalEvidence: { status: 'NOT_PROVIDED', containsSensitiveData: false },
      externalRequestsByIngestion: 0,
      providerRequestsExecutedByThisProcess: 0,
    },
    uat: {
      status: 'PARTIAL',
      summary: {
        total: 48,
        passed: 46,
        failed: 0,
        notRunManualRequired: 1,
        notRunAuthRequired: 1,
        negativeE2eTotal: 12,
        negativeE2ePassed: 12,
        negativeE2eFailed: 0,
        refreshRecoveryTotal: 8,
        refreshRecoveryPassed: 8,
        refreshRecoveryFailed: 0,
      },
      externalNetworkAttempts: 0,
      results: [
        ...Array.from({ length: 46 }, (_, index) => ({ id: `UAT-PASS-${index}`, status: 'PASS' })),
        { id: 'UAT-16', status: 'NOT_RUN_MANUAL_REQUIRED' },
        { id: 'UAT-33', status: 'NOT_RUN_AUTH_REQUIRED' },
      ],
    },
  };
  if (!isExactPullRequestOpenGateState(fixture)) return false;
  const mutations = [
    (value) => {
      value.environment.GITHUB_EVENT_NAME = 'push';
    },
    (value) => {
      value.results[0].status = 'FAIL';
    },
    (value) => {
      value.results[1].status = 'PARTIAL';
    },
    (value) => {
      value.closeout.status = 'RELEASE_CANDIDATE';
    },
    (value) => {
      value.closeout.gates['GATE-E6-01'] = 'FAIL';
    },
    (value) => {
      value.closeout.gates['GATE-E6-03'] = 'PASS';
    },
    (value) => {
      value.closeout.artifactSummary.failed = 1;
      value.closeout.artifactSummary.validStates = 17;
    },
    (value) => {
      value.sandbox.externalRequestsByIngestion = 1;
    },
    (value) => {
      value.uat.results[0].status = 'FAIL';
      value.uat.summary.failed = 1;
      value.uat.summary.passed = 45;
    },
  ];
  return mutations.every((mutate) => {
    const candidate = globalThis.structuredClone(fixture);
    mutate(candidate);
    return !isExactPullRequestOpenGateState(candidate);
  });
};

const pnpmProbe = pnpmCommand(['--version']);
const pnpmProbeResult = spawnSync(pnpmProbe.executable, pnpmProbe.arguments, {
  cwd: workspaceRoot,
  encoding: 'utf8',
  shell: pnpmProbe.shell,
  windowsHide: true,
});
if (pnpmProbeResult.status !== 0 || pnpmProbeResult.stdout.trim() !== '11.19.0') {
  throw new Error('The pinned pnpm executable could not be invoked reproducibly');
}

const summarizeAudit = (stdout) => {
  try {
    const parsed = JSON.parse(stdout);
    const levels = ['info', 'low', 'moderate', 'high', 'critical'];
    const vulnerabilities = Object.fromEntries(
      levels.map((level) => [level, parsed?.metadata?.vulnerabilities?.[level]]),
    );
    if (!levels.every((level) => Number.isInteger(vulnerabilities[level]))) {
      throw new Error('missing vulnerability counts');
    }
    return {
      scope: 'development-and-production',
      threshold: 'high',
      status: vulnerabilities.high === 0 && vulnerabilities.critical === 0 ? 'PASS' : 'FAIL',
      vulnerabilities,
    };
  } catch {
    return {
      scope: 'development-and-production',
      threshold: 'high',
      status: 'INVALID_RESPONSE',
    };
  }
};

const steps = [
  {
    id: 'E6-PREFLIGHT-SELF-TEST',
    executable: process.execPath,
    arguments: ['scripts/stage6/preflight.mjs', '--self-test'],
  },
  {
    id: 'E6-PREFLIGHT',
    executable: process.execPath,
    arguments: ['scripts/stage6/preflight.mjs', ...(isCi ? ['--require-clean'] : [])],
  },
  { id: 'E6-BASELINE', ...pnpmCommand(['verify']) },
  {
    id: 'E6-FULL-DEPENDENCY-AUDIT',
    ...pnpmCommand(['audit', '--audit-level', 'high', '--json']),
    captureAuditSummary: true,
  },
  { id: 'E6-INTEGRITY', ...pnpmCommand(['test:integrity']) },
  {
    id: 'E6-COMPATIBILITY',
    ...pnpmCommand([
      'test:e2e:cross-browser',
      '--',
      '--skip-build',
      ...(!isCi ? ['--allow-partial'] : []),
    ]),
  },
  {
    id: 'E6-ACCESSIBILITY',
    ...pnpmCommand(['test:a11y', '--', '--skip-build']),
    allowedExitCodes: [0, 2],
  },
  {
    id: 'E6-PERFORMANCE',
    ...pnpmCommand(['test:perf', '--', '--skip-build', ...(!isCi ? ['--allow-partial'] : [])]),
  },
  { id: 'E6-LOAD', ...pnpmCommand(['test:load']) },
  {
    id: 'E6-SANDBOX-AUTHORIZED-DRY-RUN',
    ...pnpmCommand(['test:sandbox:authorized']),
  },
  {
    id: 'E6-SANDBOX-EVIDENCE',
    ...pnpmCommand(['test:sandbox:smoke']),
    allowedExitCodes: [0, 2],
  },
  { id: 'E6-SECURITY', ...pnpmCommand(['test:security']) },
  { id: 'E6-SMOKE-REFRESH', ...pnpmCommand(['test:smoke']) },
  {
    id: 'E6-UAT',
    ...pnpmCommand(['test:uat']),
    allowedExitCodes: [0, 2],
  },
  {
    id: 'E6-FINAL-ARTIFACT-SCAN',
    executable: process.execPath,
    arguments: ['scripts/stage6/final-artifact-scan.mjs'],
  },
];

if (process.argv.includes('--self-test')) {
  const stepIds = steps.map(({ id }) => id);
  const authorizedSandboxIndex = stepIds.indexOf('E6-SANDBOX-AUTHORIZED-DRY-RUN');
  const sandboxIndex = stepIds.indexOf('E6-SANDBOX-EVIDENCE');
  const smokeRefreshIndex = stepIds.indexOf('E6-SMOKE-REFRESH');
  const uatIndex = stepIds.indexOf('E6-UAT');
  if (
    normalizeStepExitCode(0, undefined) !== 0 ||
    normalizeStepExitCode(0, { status: 'PASS' }) !== 0 ||
    normalizeStepExitCode(0, { status: 'INVALID_RESPONSE' }) !== 1 ||
    normalizeStepExitCode(2, undefined) !== 2 ||
    manifest.scripts?.['test:sandbox:authorized'] !==
      'tsc -p scripts/stage6/sandbox-authorized/tsconfig.json --noEmit && node scripts/stage6/sandbox-authorized/run.mjs --self-test && node scripts/stage6/sandbox-authorized/run.mjs --dry-run' ||
    manifest.scripts?.['sandbox:authorized:execute'] !==
      'node scripts/stage6/sandbox-authorized/run.mjs --execute' ||
    manifest.scripts?.['test:sandbox:smoke'] !== 'node scripts/stage6/sandbox-evidence.mjs' ||
    stepIds.filter((id) => id === 'E6-SANDBOX-AUTHORIZED-DRY-RUN').length !== 1 ||
    authorizedSandboxIndex >= sandboxIndex ||
    authorizedSandboxIndex >= stepIds.indexOf('E6-SECURITY') ||
    authorizedSandboxIndex >= stepIds.indexOf('E6-UAT') ||
    steps[authorizedSandboxIndex]?.allowedExitCodes !== undefined ||
    steps.some(({ arguments: arguments_ = [] }) =>
      arguments_.some(
        (argument) => argument === 'sandbox:authorized:execute' || argument === '--execute',
      ),
    ) ||
    stepIds.filter((id) => id === 'E6-SANDBOX-EVIDENCE').length !== 1 ||
    sandboxIndex >= stepIds.indexOf('E6-SECURITY') ||
    sandboxIndex >= stepIds.indexOf('E6-UAT') ||
    !steps[sandboxIndex]?.allowedExitCodes?.includes(2) ||
    stepIds.filter((id) => id === 'E6-SMOKE-REFRESH').length !== 1 ||
    smokeRefreshIndex !== uatIndex - 1 ||
    steps[smokeRefreshIndex]?.arguments?.at(-1) !== 'test:smoke' ||
    !selfTestPullRequestOpenGates()
  ) {
    throw new Error('stage-6 orchestration self-test failed');
  }
  process.stdout.write('stage-6 orchestration pnpm probe: PASS\n');
  process.exit(0);
}

const results = [];
for (const step of steps) {
  const startedAt = Date.now();
  const result = spawnSync(step.executable, step.arguments, {
    cwd: workspaceRoot,
    env: sharedEnvironment,
    shell: step.shell ?? false,
    stdio: step.captureAuditSummary ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    encoding: step.captureAuditSummary ? 'utf8' : undefined,
    windowsHide: true,
  });
  const rawExitCode = result.status ?? 1;
  const audit = step.captureAuditSummary ? summarizeAudit(result.stdout ?? '') : undefined;
  const exitCode = normalizeStepExitCode(rawExitCode, audit);

  const allowedExitCodes = step.allowedExitCodes ?? [0];
  if (audit !== undefined) {
    process.stdout.write(
      `full-dependency-audit: ${audit.status} (${
        audit.vulnerabilities?.high ?? '?'
      } high; ${audit.vulnerabilities?.critical ?? '?'} critical)\n`,
    );
  }
  results.push({
    id: step.id,
    command: [step.executable, ...step.arguments].join(' '),
    status: exitCode === 0 ? 'PASS' : allowedExitCodes.includes(exitCode) ? 'PARTIAL' : 'FAIL',
    exitCode,
    signal: result.signal,
    durationMs: Date.now() - startedAt,
    retryCount: 0,
    ...(audit === undefined ? {} : { audit }),
  });
}

writeRuntimeEvidence('orchestration.json', {
  ...baseEvidence({
    artifactId: 'ART-VER-04',
    command: 'pnpm verify:stage6',
    tool: { node: process.version, packageManager: manifest.packageManager },
    runId,
  }),
  status: results.some(({ status }) => status === 'FAIL') ? 'FAIL' : 'PASS_WITH_OPEN_GATES',
  candidate: candidate(),
  retriesUsed: 0,
  externalAuthorizationsInvoked: [],
  steps: results,
});

const closeout = spawnSync(process.execPath, ['scripts/evidence/stage6-closeout.mjs'], {
  cwd: workspaceRoot,
  env: sharedEnvironment,
  stdio: 'inherit',
  windowsHide: true,
});
const loadRuntimeJson = (filename) => {
  try {
    return JSON.parse(
      readFileSync(new URL(`../../output/evidence/runtime/stage-6/${filename}`, import.meta.url)),
    );
  } catch {
    return undefined;
  }
};
const exactOpenGates = isExactPullRequestOpenGateState({
  environment: process.env,
  results,
  closeout: loadRuntimeJson('closeout.json'),
  accessibility: loadRuntimeJson('accessibility.json'),
  sandbox: loadRuntimeJson('sandbox.json'),
  uat: loadRuntimeJson('uat.json'),
});
if (exactOpenGates) {
  process.stdout.write(
    'stage-6 pull-request CI: PASS_WITH_OPEN_GATES (release remains STAGE_7_BLOCKED)\n',
  );
} else if (results.some(({ status }) => status === 'FAIL') || closeout.status !== 0) {
  process.exitCode = 1;
}
