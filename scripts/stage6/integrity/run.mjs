#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { stage6Environment, stage6RunId } from '../lib/evidence.mjs';
import { writeSanitizedJsonAtomic } from '../lib/artifact-sanitizer.mjs';

const ROOT = process.cwd();
const COMMAND = 'node scripts/stage6/integrity/run.mjs';
const EVIDENCE_DIRECTORY = path.join(ROOT, 'output', 'evidence', 'runtime', 'stage-6');
const NETWORK_GUARD = path.join(ROOT, 'scripts', 'smoke', 'deny-external-network.cjs');
const RUN_ID = stage6RunId();

const suites = [
  {
    workspace: 'api',
    cwd: path.join(ROOT, 'apps', 'api'),
    executable: path.join(ROOT, 'apps', 'api', 'node_modules', 'jest', 'bin', 'jest.js'),
    config: 'jest.config.cjs',
    files: [
      'src/application/use-cases/checkout-service.spec.ts',
      'src/infrastructure/persistence/in-memory-checkout.repository.spec.ts',
      'src/infrastructure/persistence/dynamodb-checkout.repository.spec.ts',
      'src/infrastructure/payment/e5-scripted-payment-provider.spec.ts',
      'src/infrastructure/payment/__e6__/uat14-event-fixtures.spec.ts',
      'src/interfaces/http/checkout-http.spec.ts',
      'src/interfaces/http/contract/checkout.e5.contract.spec.ts',
      'src/interfaces/http/__e6__/initial-stock.spec.ts',
      'src/interfaces/http/__e6__/negative-boundaries.spec.ts',
    ],
  },
  {
    workspace: 'web',
    cwd: path.join(ROOT, 'apps', 'web'),
    executable: path.join(ROOT, 'apps', 'web', 'node_modules', 'jest', 'bin', 'jest.js'),
    config: 'jest.config.cjs',
    files: [
      'src/features/checkout/components/acceptances-review-transaction.spec.tsx',
      'src/features/checkout/components/checkout-dialog.spec.tsx',
      'src/features/checkout/components/customer-delivery-step.spec.tsx',
      'src/features/checkout/model/checkout-storage.spec.ts',
      'src/features/checkout/services/save-with-canonical-recovery.spec.ts',
      'src/features/checkout/services/submit-payment.spec.ts',
      'src/features/checkout/services/use-ephemeral-payment-token.spec.ts',
    ],
  },
];

const source = (workspace, needle) => ({ workspace, needle });

const integrityMatrix = [
  [
    'INT-E6-01',
    'last stock is awarded once',
    source('api', 'preserves one unit under concurrent checkout submissions'),
  ],
  [
    'INT-E6-02',
    'double submit creates one logical transaction',
    source('api', 'atomically reserves stock and returns stable idempotent replays'),
  ],
  [
    'INT-E6-03',
    'same key and payload replays the same result',
    source('api', 'atomically reserves stock and returns stable idempotent replays'),
  ],
  [
    'INT-E6-04',
    'same key and changed semantics conflicts',
    source(
      'api',
      'replays after TTL/config/price drift, excludes token C3, and conflicts on semantic changes',
    ),
  ],
  [
    'INT-E6-05',
    'approved final replay applies one stock and delivery effect',
    source(
      'api',
      'finalizes APPROVED exactly once with one delivery and detects conflicting finals',
    ),
  ],
  [
    'INT-E6-06',
    'failed final replay releases once and creates no delivery',
    source(
      'api',
      'releases failed reservations and marks proven-not-sent without an acknowledgement',
    ),
  ],
  [
    'INT-E6-07',
    'out-of-order final state cannot regress silently',
    source(
      'api',
      'FAKE-E5-10 repeats final and FAKE-E5-11 regresses final to PENDING at the port boundary',
    ),
  ],
  [
    'INT-E6-08',
    'unknown pending outcome retains its reservation',
    source('api', 'keeps an unknown POST reserved when no provider ID permits safe lookup'),
  ],
  [
    'INT-E6-09',
    'late approval conflict is quarantined',
    source(
      'api',
      'keeps approved inventory safe when delivery data is absent and records terminal conflict',
    ),
  ],
  [
    'INT-E6-10',
    'stale quote is rejected deterministically',
    source(
      'api',
      'expires checkout and quote deterministically without sleeps and fails payment config closed',
    ),
  ],
  [
    'INT-E6-11',
    'concurrent tabs elect one dispatch leader',
    source('api', 'recovers a crash after prepare: two concurrent replays elect one POST leader'),
  ],
  [
    'INT-E6-12',
    'restart after durable prepare recovers without a second POST',
    source('api', 'recovers NOT_SENT autonomously after a crash without calling the provider'),
  ],
];

const negativeMatrix = [
  [
    'E2E-E6-13',
    'client total manipulation is rejected',
    source('api', '[E2E-E6-13] rejects a client-supplied total'),
  ],
  [
    'E2E-E6-14',
    'same key with changed payload conflicts',
    source(
      'api',
      'replays after TTL/config/price drift, excludes token C3, and conflicts on semantic changes',
    ),
  ],
  [
    'E2E-E6-15',
    'foreign or malformed capability is rejected',
    source('api', '[E2E-E6-15] accepts only the scoped, well-encoded capability cookie'),
  ],
  [
    'E2E-E6-16',
    'stock change before payment cannot oversell',
    source('api', 'preserves one unit under concurrent checkout submissions'),
  ],
  [
    'E2E-E6-17',
    'late out-of-order provider state is quarantined',
    source(
      'api',
      'FAKE-E5-10 repeats final and FAKE-E5-11 regresses final to PENDING at the port boundary',
    ),
  ],
  [
    'E2E-E6-18',
    'pending state remains recoverable after navigation',
    source('web', 'keeps pending state recoverable after automatic polling stops'),
  ],
  [
    'E2E-E6-19',
    'two concurrent clients keep one active transaction',
    source('api', 'recovers a crash after prepare: two concurrent replays elect one POST leader'),
  ],
  [
    'E2E-E6-20',
    'lost submit response is reconciled without blind mutation retry',
    source('web', 'recognises a committed snapshot after the response is lost'),
  ],
  [
    'E2E-E6-21',
    'approved state is recovered canonically before redirect',
    source('web', 'returns the canonical approved result to the product'),
  ],
  [
    'E2E-E6-22',
    'safe API error preserves permitted UI data',
    source('api', '[E2E-E6-22] returns a safe problem without echoing rejected fields'),
    source('web', 'preserves input after a recoverable network failure and supports back'),
  ],
  [
    'E2E-E6-23',
    'initially unavailable product cannot start checkout',
    source('api', '[E2E-E6-23] rejects checkout when the product starts without stock'),
  ],
  [
    'E2E-E6-24',
    'abandoned or failed session can recover or restart safely',
    source('api', 'recovers NOT_SENT autonomously after a crash without calling the provider'),
    source('web', 'clears a final failed checkout before starting another attempt'),
  ],
];

const uat14Matrix = [
  [
    'UAT-14-IF-01',
    'invalid-signature fixture is rejected before network or mutation',
    source(
      'api',
      '[UAT-14-IF-01] rejects an invalid-signature fixture with zero network or mutation',
    ),
  ],
  [
    'UAT-14-IF-02',
    'duplicate event hash is a no-op',
    source('api', 'claims due work once with bounded limits and deduplicates internal events'),
  ],
  [
    'UAT-14-IF-03',
    'out-of-order final adds no effects',
    source(
      'api',
      'preserves the original final and records a conflicting later final without effects',
    ),
  ],
];

const resilienceMatrix = [
  [
    'RES-E6-01',
    'provider latency is modeled without real sleeps',
    source('api', 'FAKE-E5-12 uses an injected clock and no real sleep'),
  ],
  [
    'RES-E6-02',
    'create timeout remains an unknown durable outcome',
    source('api', 'FAKE-E5-05 records that an external operation exists despite create timeout'),
  ],
  [
    'RES-E6-03',
    'status timeout preserves pending and reservation',
    source(
      'api',
      'classifies provider timeouts while preserving PENDING and the active reservation',
    ),
  ],
  [
    'RES-E6-04',
    'provider rate limit remains technical pending',
    source('api', 'keeps 429 and 5xx provider reads PENDING/UNKNOWN with the reservation intact'),
  ],
  [
    'RES-E6-05',
    'temporary provider 5xx remains technical pending',
    source('api', 'keeps 429 and 5xx provider reads PENDING/UNKNOWN with the reservation intact'),
  ],
  [
    'RES-E6-06',
    'malformed provider result fails closed',
    source('api', 'FAKE-E5-06 fails reads and FAKE-E5-07 returns malformed/protocol outcome'),
  ],
  [
    'RES-E6-07',
    'client network failure exposes GET-only recovery',
    source('web', 'offers only GET recovery on loading and network errors'),
  ],
  [
    'RES-E6-08',
    'API restart after prepare is recoverable',
    source('api', 'recovers a crash after prepare: two concurrent replays elect one POST leader'),
  ],
  [
    'RES-E6-09',
    'repository unavailability maps to safe application failure',
    source(
      'api',
      'maps catalog and repository failures and hides related resources from other capabilities',
    ),
  ],
  [
    'RES-E6-10',
    'conditional conflict causes no partial effect',
    source(
      'api',
      'maps authorization, version, active-payment, out-of-stock and repository failures',
    ),
  ],
  [
    'RES-E6-11',
    'duplicate reconciler claims one lease',
    source('api', 'uses claim/lease so two workers query a sustained PENDING only once'),
  ],
  [
    'RES-E6-12',
    'clock jump invalidates ephemeral payment state',
    source('web', 'fails closed against clock jumps and cancels cleanup on unmount'),
  ],
  [
    'RES-E6-13',
    'expired quote fails without side effects',
    source(
      'api',
      'expires checkout and quote deterministically without sleeps and fails payment config closed',
    ),
  ],
  [
    'RES-E6-14',
    'expired payment token requires recapture',
    source('web', 'rejects a five-minute-old token and returns to an empty card capture'),
  ],
  [
    'RES-E6-15',
    'offline form data survives recoverable failure',
    source('web', 'preserves input after a recoverable network failure and supports back'),
  ],
  [
    'RES-E6-16',
    'lost save response reconciles canonical state once',
    source('web', 'reconciles a lost retry response and never submits a third PUT'),
  ],
  [
    'RES-E6-17',
    'pending close or reopen retains manual recovery',
    source('web', 'keeps pending state recoverable after automatic polling stops'),
  ],
];

const commitSha = () => {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : 'UNKNOWN';
};

const runSuite = async (suite, temporaryDirectory) => {
  const outputPath = path.join(temporaryDirectory, `${suite.workspace}.json`);
  const arguments_ = [
    suite.executable,
    '--config',
    suite.config,
    '--runInBand',
    '--runTestsByPath',
    ...suite.files,
    '--json',
    `--outputFile=${outputPath}`,
  ];
  const child = spawn(process.execPath, arguments_, {
    cwd: suite.cwd,
    windowsHide: true,
    stdio: ['ignore', 'ignore', 'ignore'],
    env: {
      ...process.env,
      CI: 'true',
      NODE_OPTIONS:
        `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(NETWORK_GUARD).href}`.trim(),
    },
  });
  const exitCode = await new Promise((resolve) => child.once('exit', (code) => resolve(code ?? 1)));
  let report;
  try {
    report = JSON.parse(await readFile(outputPath, 'utf8'));
  } catch {
    return { workspace: suite.workspace, exitCode, assertions: [] };
  }
  const assertions = report.testResults.flatMap((testResult) =>
    testResult.assertionResults.map((assertion) => ({
      fullName: assertion.fullName,
      status: assertion.status,
    })),
  );
  return { workspace: suite.workspace, exitCode, assertions };
};

const evaluateMatrix = (matrix, reports) =>
  matrix.map(([id, title, ...sources]) => {
    const failures = [];
    for (const expected of sources) {
      const report = reports.find((candidate) => candidate.workspace === expected.workspace);
      const assertion = report?.assertions.find((candidate) =>
        candidate.fullName.includes(expected.needle),
      );
      if (assertion === undefined) failures.push('ASSERTION_NOT_FOUND');
      else if (assertion.status !== 'passed') failures.push('ASSERTION_FAILED');
    }
    return {
      id,
      title,
      status: failures.length === 0 ? 'PASS' : 'FAIL',
      verificationLayer: 'unit-integration-supporting-evidence',
      failureCodes: [...new Set(failures)].sort(),
    };
  });

const evidenceBase = (sha) => ({
  schemaVersion: 1,
  stage: 6,
  generatedAt: new Date().toISOString(),
  commitSha: sha,
  runId: RUN_ID,
  command: COMMAND,
  tool: 'jest',
  toolVersion: '30.4.2',
  containsSensitiveData: false,
  environment: stage6Environment(),
  executionScope: 'LOCAL_MEMORY_FAKE_LOOPBACK_ONLY',
  networkPolicy: 'loopback-only-enforced',
});

const writeEvidence = async (name, evidence) => {
  const filename = `${name}.json`;
  await writeSanitizedJsonAtomic(path.join(EVIDENCE_DIRECTORY, filename), filename, evidence);
};

const main = async () => {
  const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'checkout-e6-integrity-'));
  try {
    const reports = [];
    for (const suite of suites) reports.push(await runSuite(suite, temporaryDirectory));
    const sha = commitSha();
    const integrity = evaluateMatrix(integrityMatrix, reports);
    const negative = evaluateMatrix(negativeMatrix, reports);
    const uat14 = evaluateMatrix(uat14Matrix, reports);
    const resilience = evaluateMatrix(resilienceMatrix, reports);
    const suiteFailures = reports.filter((report) => report.exitCode !== 0).length;

    const integrityEvidence = {
      ...evidenceBase(sha),
      status:
        suiteFailures === 0 &&
        integrity.every((item) => item.status === 'PASS') &&
        negative.every((item) => item.status === 'PASS') &&
        uat14.every((item) => item.status === 'PASS')
          ? 'PASS'
          : 'FAIL',
      integrityPassed: integrity.filter((item) => item.status === 'PASS').length,
      integrityTotal: integrity.length,
      negativePassed: negative.filter((item) => item.status === 'PASS').length,
      negativeTotal: negative.length,
      uat14Passed: uat14.filter((item) => item.status === 'PASS').length,
      uat14Total: uat14.length,
      suiteFailures,
      integrity,
      negative,
      uat14,
    };
    const resilienceEvidence = {
      ...evidenceBase(sha),
      status:
        suiteFailures === 0 && resilience.every((item) => item.status === 'PASS') ? 'PASS' : 'FAIL',
      passed: resilience.filter((item) => item.status === 'PASS').length,
      total: resilience.length,
      suiteFailures,
      results: resilience,
    };
    await writeEvidence('integrity', integrityEvidence);
    await writeEvidence('resilience', resilienceEvidence);
    process.stdout.write(
      `${JSON.stringify(
        {
          integrity: integrityEvidence.status,
          integrityMatrix: `${integrityEvidence.integrityPassed}/${integrityEvidence.integrityTotal}`,
          negativeMatrix: `${integrityEvidence.negativePassed}/${integrityEvidence.negativeTotal}`,
          uat14Matrix: `${integrityEvidence.uat14Passed}/${integrityEvidence.uat14Total}`,
          resilience: resilienceEvidence.status,
          resilienceMatrix: `${resilienceEvidence.passed}/${resilienceEvidence.total}`,
        },
        null,
        2,
      )}\n`,
    );
    if (integrityEvidence.status !== 'PASS' || resilienceEvidence.status !== 'PASS') {
      process.exitCode = 1;
    }
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
};

await main();
