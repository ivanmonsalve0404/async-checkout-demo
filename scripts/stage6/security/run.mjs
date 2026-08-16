#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import {
  assertLoopbackUrl,
  baseEvidence,
  candidate,
  stage6RunId,
  workspaceRoot,
  writeRuntimeEvidence,
} from '../lib/evidence.mjs';
import {
  externalEvidenceCapabilityDecision,
  externalPassiveSecurityChecks,
  resolveExternalEvidence,
  selfTestExternalEvidence,
} from '../external-evidence.mjs';
import { codeqlEvidenceStatus } from './codeql-evidence.mjs';

const COMMAND = 'node scripts/stage6/security/run.mjs';
const PORT = Number(process.env.STAGE6_SECURITY_PORT ?? 3107);
const API_ORIGIN = `http://127.0.0.1:${PORT}`;
const WEB_ORIGIN = 'http://127.0.0.1:4173';
const NETWORK_GUARD = path.join(workspaceRoot, 'scripts', 'smoke', 'deny-external-network.cjs');
const API_ENTRY = path.join(workspaceRoot, 'apps', 'api', 'dist', 'main.js');
const JEST = path.join(workspaceRoot, 'apps', 'api', 'node_modules', 'jest', 'bin', 'jest.js');
const securityTestFiles = [
  'src/infrastructure/configuration/app-config.spec.ts',
  'src/infrastructure/logging/safe-logger.spec.ts',
  'src/infrastructure/payment/sandbox-payment-provider.spec.ts',
  'src/infrastructure/security/system-runtime-security.spec.ts',
  'src/interfaces/http/middleware/http-boundary.middleware.spec.ts',
  'src/interfaces/http/middleware/rate-limit.middleware.spec.ts',
];
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

selfTestExternalEvidence();
if (process.argv.includes('--self-test')) {
  process.stdout.write('stage-6 security runner self-test: PASS\n');
  process.exit(0);
}

assertLoopbackUrl(API_ORIGIN);
if (!Number.isInteger(PORT) || PORT < 1_024 || PORT > 65_535) {
  throw new Error('INVALID_LOCAL_PORT');
}

const run = (executable, arguments_, options = {}) =>
  new Promise((resolve) => {
    const child = spawn(executable, arguments_, {
      cwd: options.cwd ?? workspaceRoot,
      windowsHide: true,
      stdio: ['ignore', 'ignore', 'ignore'],
      env: options.env ?? process.env,
    });
    child.once('error', () => resolve(1));
    child.once('exit', (code) => resolve(code ?? 1));
  });

const localStaticChecks = async (temporaryDirectory) => {
  const checks = [];
  const commands = [
    {
      id: 'SEC-E6-STATIC-01',
      name: 'secret-scanner-self-test',
      executable: process.execPath,
      arguments_: ['scripts/security/scan-repository.mjs', '--self-test'],
    },
    {
      id: 'SEC-E6-STATIC-02',
      name: 'working-tree-and-history-secret-scan',
      executable: process.execPath,
      arguments_: ['scripts/security/scan-repository.mjs', '--history'],
    },
    {
      id: 'SEC-E6-STATIC-03',
      name: 'workflow-least-privilege-policy',
      executable: process.execPath,
      arguments_: ['scripts/security/validate-workflows.mjs'],
    },
    {
      id: 'SEC-E6-STATIC-04',
      name: 'codeql-same-sha-evidence-self-test',
      executable: process.execPath,
      arguments_: ['scripts/stage6/security/codeql-evidence.mjs', '--self-test'],
    },
    {
      id: 'SEC-E6-STATIC-05',
      name: 'codeql-sarif-severity-gate-self-test',
      executable: process.execPath,
      arguments_: ['scripts/stage6/security/codeql-sarif.mjs', '--self-test'],
    },
  ];
  for (const command of commands) {
    const exitCode = await run(command.executable, command.arguments_);
    checks.push({
      id: command.id,
      name: command.name,
      status: exitCode === 0 ? 'PASS' : 'FAIL',
      exitCode,
    });
  }

  const outputPath = path.join(temporaryDirectory, 'security-jest.json');
  const guardedEnvironment = {
    ...process.env,
    CI: 'true',
    NODE_OPTIONS:
      `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(NETWORK_GUARD).href}`.trim(),
  };
  const exitCode = await run(
    process.execPath,
    [
      JEST,
      '--config',
      'jest.config.cjs',
      '--runInBand',
      '--runTestsByPath',
      ...securityTestFiles,
      '--json',
      `--outputFile=${outputPath}`,
    ],
    { cwd: path.join(workspaceRoot, 'apps', 'api'), env: guardedEnvironment },
  );
  let totals = { passed: 0, failed: 0, total: 0 };
  try {
    const report = JSON.parse(await readFile(outputPath, 'utf8'));
    totals = {
      passed: report.numPassedTests ?? 0,
      failed: report.numFailedTests ?? 0,
      total: report.numTotalTests ?? 0,
    };
  } catch {
    // A missing report is represented by the non-zero/unknown result below.
  }
  checks.push({
    id: 'SEC-E6-STATIC-06',
    name: 'security-focused-unit-and-integration-tests',
    status: exitCode === 0 && totals.total > 0 && totals.failed === 0 ? 'PASS' : 'FAIL',
    exitCode,
    ...totals,
  });
  return checks;
};

const waitForApi = async (child) => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error('API_EXITED');
    try {
      const response = await fetch(`${API_ORIGIN}/api/health`, {
        signal: AbortSignal.timeout(500),
      });
      if (response.ok) return;
    } catch {
      // Bounded loopback-only startup polling.
    }
    await sleep(100);
  }
  throw new Error('API_NOT_READY');
};

const stop = async (child) => {
  if (child.exitCode !== null) return;
  child.kill();
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    sleep(3_000).then(() => child.kill('SIGKILL')),
  ]);
};

const safeProblem = async (response, expectedCode, rejectedMarker) => {
  let body;
  try {
    body = await response.json();
  } catch {
    return false;
  }
  const serialized = JSON.stringify(body);
  return (
    body?.code === expectedCode &&
    body?.stack === undefined &&
    typeof body?.detail === 'string' &&
    response.headers.get('cache-control') === 'no-store' &&
    (rejectedMarker === undefined || !serialized.includes(rejectedMarker))
  );
};

const dynamicChecks = async () => {
  let blockedExternalRequests = 0;
  const child = spawn(process.execPath, [API_ENTRY], {
    cwd: workspaceRoot,
    windowsHide: true,
    stdio: ['ignore', 'ignore', 'pipe'],
    env: {
      ...process.env,
      ALLOWED_ORIGIN: WEB_ORIGIN,
      API_PORT: String(PORT),
      APP_ENV: 'test',
      DATA_ADAPTER: 'memory',
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
      FAKE_RECONCILE_INTERVAL_MS: '60000',
      NODE_OPTIONS:
        `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(NETWORK_GUARD).href}`.trim(),
      PAYMENT_ADAPTER: 'fake',
      PAYMENTS_ENABLED: 'false',
      PRODUCT_INITIAL_STOCK: '20',
      PUBLIC_ASSET_ORIGIN: WEB_ORIGIN,
      TOKENIZATION_MODE: 'disabled',
    },
  });
  child.stderr.on('data', (chunk) => {
    blockedExternalRequests += String(chunk).match(/SMOKE_EXTERNAL_NETWORK_BLOCKED/gu)?.length ?? 0;
  });

  try {
    await waitForApi(child);
    const checks = [];
    const health = await fetch(`${API_ORIGIN}/api/health`, {
      headers: { Origin: WEB_ORIGIN },
      signal: AbortSignal.timeout(2_000),
    });
    const requiredHeaders = [
      'content-security-policy',
      'referrer-policy',
      'x-content-type-options',
      'x-frame-options',
    ];
    checks.push({
      id: 'SEC-E6-DYNAMIC-01',
      name: 'application-security-headers',
      status:
        health.status === 200 &&
        health.headers.get('cache-control') === 'no-store' &&
        requiredHeaders.every((header) => health.headers.has(header))
          ? 'PASS'
          : 'FAIL',
      requiredHeaders: Object.fromEntries(
        requiredHeaders.map((header) => [header, health.headers.has(header)]),
      ),
      cacheControlNoStore: health.headers.get('cache-control') === 'no-store',
    });
    await health.arrayBuffer();

    const allowedCors = await fetch(`${API_ORIGIN}/api/v1/products`, {
      headers: { Origin: WEB_ORIGIN },
      signal: AbortSignal.timeout(2_000),
    });
    checks.push({
      id: 'SEC-E6-DYNAMIC-02',
      name: 'cors-exact-allowlist',
      status:
        allowedCors.status === 200 &&
        allowedCors.headers.get('access-control-allow-origin') === WEB_ORIGIN &&
        allowedCors.headers.get('access-control-allow-credentials') === 'true'
          ? 'PASS'
          : 'FAIL',
    });
    await allowedCors.arrayBuffer();

    const hostile = await fetch(`${API_ORIGIN}/api/v1/products`, {
      headers: { Origin: 'https://hostile.example.invalid' },
      signal: AbortSignal.timeout(2_000),
    });
    checks.push({
      id: 'SEC-E6-DYNAMIC-03',
      name: 'hostile-origin-safe-problem',
      status:
        hostile.status === 403 &&
        (await safeProblem(hostile, 'ORIGIN_FORBIDDEN', 'hostile.example.invalid'))
          ? 'PASS'
          : 'FAIL',
    });

    const wrongType = await fetch(`${API_ORIGIN}/api/v1/checkouts`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', Origin: WEB_ORIGIN },
      body: 'synthetic-invalid-body',
      signal: AbortSignal.timeout(2_000),
    });
    checks.push({
      id: 'SEC-E6-DYNAMIC-04',
      name: 'json-content-type-boundary',
      status:
        wrongType.status === 415 &&
        (await safeProblem(wrongType, 'REQUEST_MALFORMED', 'synthetic-invalid-body'))
          ? 'PASS'
          : 'FAIL',
    });

    const oversized = await fetch(`${API_ORIGIN}/api/v1/checkouts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: WEB_ORIGIN },
      body: JSON.stringify({ productId: 'x'.repeat(17_000) }),
      signal: AbortSignal.timeout(2_000),
    });
    checks.push({
      id: 'SEC-E6-DYNAMIC-05',
      name: 'request-body-limit',
      status:
        oversized.status === 413 &&
        (await safeProblem(oversized, 'REQUEST_MALFORMED', 'x'.repeat(32)))
          ? 'PASS'
          : 'FAIL',
    });

    const created = await fetch(`${API_ORIGIN}/api/v1/checkouts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: WEB_ORIGIN },
      body: JSON.stringify({ productId: 'product-demo-001' }),
      signal: AbortSignal.timeout(2_000),
    });
    const cookie = created.headers.get('set-cookie') ?? '';
    checks.push({
      id: 'SEC-E6-DYNAMIC-06',
      name: 'secure-capability-cookie',
      status:
        created.status === 201 &&
        created.headers.get('cache-control') === 'no-store' &&
        ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/api/v1'].every((attribute) =>
          cookie.includes(attribute),
        )
          ? 'PASS'
          : 'FAIL',
      cookieValueCaptured: false,
    });
    await created.arrayBuffer();

    for (let attempt = 0; attempt < 9; attempt += 1) {
      const response = await fetch(`${API_ORIGIN}/api/v1/checkouts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: WEB_ORIGIN },
        body: JSON.stringify({ productId: 'product-demo-001' }),
        signal: AbortSignal.timeout(2_000),
      });
      await response.arrayBuffer();
    }
    const limited = await fetch(`${API_ORIGIN}/api/v1/checkouts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: WEB_ORIGIN },
      body: JSON.stringify({ productId: 'product-demo-001' }),
      signal: AbortSignal.timeout(2_000),
    });
    checks.push({
      id: 'SEC-E6-DYNAMIC-07',
      name: 'rate-limit-contract',
      status:
        limited.status === 429 &&
        /^\d+$/u.test(limited.headers.get('retry-after') ?? '') &&
        (await safeProblem(limited, 'RATE_LIMITED'))
          ? 'PASS'
          : 'FAIL',
      retryAfterPresent: /^\d+$/u.test(limited.headers.get('retry-after') ?? ''),
    });

    checks.push({
      id: 'SEC-E6-DYNAMIC-08',
      name: 'external-network-attempts',
      status: blockedExternalRequests === 0 ? 'PASS' : 'FAIL',
      blockedExternalRequests,
    });
    return checks;
  } finally {
    await stop(child);
  }
};

const runId = stage6RunId();
const currentCandidate = candidate();
const externalExecution = { commitSha: currentCandidate.commitSha, runId };
const externalEvidence = await resolveExternalEvidence(externalExecution);
const passiveSecurityDecision = externalEvidenceCapabilityDecision(
  externalEvidence,
  'passiveSecurity',
  externalExecution,
);
const passiveSecurityChecks = externalPassiveSecurityChecks(externalEvidence, externalExecution);
const codeqlResult = process.env.STAGE6_CODEQL_RESULT;
const codeqlSha = process.env.STAGE6_CODEQL_SHA;
const codeqlSarifStatus = process.env.STAGE6_CODEQL_SARIF_STATUS;
const codeqlHigh = process.env.STAGE6_CODEQL_HIGH;
const codeqlCritical = process.env.STAGE6_CODEQL_CRITICAL;
const codeqlSarifSha256 = process.env.STAGE6_CODEQL_SARIF_SHA256;
const codeqlStatus = codeqlEvidenceStatus({
  ci: process.env.CI === 'true',
  result: codeqlResult,
  sha: codeqlSha,
  candidateSha: currentCandidate.commitSha,
  sarifStatus: codeqlSarifStatus,
  high: codeqlHigh,
  critical: codeqlCritical,
  sarifSha256: codeqlSarifSha256,
});
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'checkout-e6-security-'));
let evidence;
try {
  if (passiveSecurityDecision === 'FAIL' || passiveSecurityChecks === undefined) {
    throw new Error(externalEvidence.failureCode ?? 'EXTERNAL_EVIDENCE_CONTRACT_INVALID');
  }
  const staticChecks = await localStaticChecks(temporaryDirectory);
  const applicationChecks = await dynamicChecks();
  const localPassed = [...staticChecks, ...applicationChecks].every(
    ({ status }) => status === 'PASS',
  );
  evidence = {
    ...baseEvidence({
      artifactId: 'ART-VER-12',
      command: COMMAND,
      tool: { node: process.version, jest: '30.4.2', httpClient: 'node-fetch-native' },
      runId,
    }),
    commitSha: currentCandidate.commitSha,
    status: localPassed ? 'PASS_LOCAL' : 'FAIL',
    staticChecks,
    applicationChecks,
    externalChecks: [
      { id: 'SEC-E6-EXT-01', name: 'dependency-advisory-audit', status: 'NOT_RUN_CI_REQUIRED' },
      {
        id: 'SEC-E6-EXT-02',
        name: 'codeql-sast',
        status: codeqlStatus,
        source: 'same-workflow-sarif-gate',
        commitSha: codeqlSha,
        analysisResult: codeqlResult,
        sarifStatus: codeqlSarifStatus,
        high: codeqlStatus === 'PASS' ? Number(codeqlHigh) : undefined,
        critical: codeqlStatus === 'PASS' ? Number(codeqlCritical) : undefined,
        sarifSha256: codeqlSarifSha256,
      },
      ...passiveSecurityChecks,
      { id: 'SEC-E6-EXT-05', name: 'active-dast', status: 'PROHIBITED_WITHOUT_AUTH_E6_04' },
    ],
    confirmedCritical: 0,
    confirmedHigh: 0,
    sensitiveValuesCaptured: 0,
    declaration:
      passiveSecurityDecision === 'PASS'
        ? 'LOCAL_AND_AUTHORIZED_OWNED_TARGET_CONTROLS_NO_SECURITY_CERTIFICATION'
        : 'LOCAL_CONTROLS_ONLY_NO_SECURITY_CERTIFICATION',
    externalEvidence,
    externalRequestsByIngestion: 0,
  };
} catch (error) {
  evidence = {
    ...baseEvidence({
      artifactId: 'ART-VER-12',
      command: COMMAND,
      tool: { node: process.version, jest: '30.4.2', httpClient: 'node-fetch-native' },
      runId,
    }),
    commitSha: currentCandidate.commitSha,
    status: 'FAIL',
    failureCodes: [error instanceof Error ? error.message : 'UNEXPECTED_FAILURE'],
    sensitiveValuesCaptured: 0,
  };
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

writeRuntimeEvidence('security.json', evidence);
process.stdout.write(
  `stage-6 security: ${evidence.status} (${evidence.staticChecks?.length ?? 0} static; ${evidence.applicationChecks?.length ?? 0} local dynamic)\n`,
);
if (evidence.status === 'FAIL') process.exitCode = 1;
