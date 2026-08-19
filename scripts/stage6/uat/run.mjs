#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

import { expect } from '@playwright/test';

import { selfTestManualEvidence, validateManualEvidenceSummary } from '../a11y/manual-evidence.mjs';
import {
  externalEvidenceCapabilityDecision,
  failedExternalEvidence,
  missingExternalEvidence,
  resolveExternalEvidence,
  selfTestExternalEvidence,
  validateExternalEvidenceSummary,
} from '../external-evidence.mjs';
import { detectBrowserTargets } from '../compat/harness.mjs';
import {
  baseEvidence,
  candidate,
  sha256File,
  stage6Environment,
  stage6RunId,
  workspaceRoot,
  writeRuntimeEvidence,
} from '../lib/evidence.mjs';
import {
  API_ORIGIN,
  ApiSession,
  PRODUCT_ID,
  UatFailure,
  WEB_ORIGIN,
  browserJson,
  browserProgressContainsForbiddenData,
  check,
  countRequests,
  exactBrowserTargets,
  expectStatus,
  fillCard,
  fillCustomerDelivery,
  getStock,
  getTransaction,
  loopbackFetch,
  installCapabilityBridge,
  observedExternalNetworkAttempts,
  waitForUiState,
  openPayment,
  prepareReady,
  reachReview,
  readProgress,
  runExternalNetworkObservationCanary,
  submitPrepared,
  withApi,
  withWebPreview,
} from './harness.mjs';
import { withFixtureApi } from './fixture-app.mjs';
import {
  NEGATIVE_E2E_CONTRACT,
  negativeE2eMetadataIsExact,
  selfTestNegativeE2eContract,
} from './negative-e2e-contract.mjs';
import {
  REFRESH_RECOVERY_CONTRACT,
  refreshRecoveryMetadataIsExact,
  refreshRecoveryMatrixPassed,
  selfTestRefreshRecoveryContract,
} from './refresh-recovery-contract.mjs';

const COMMAND = 'node scripts/stage6/uat/run.mjs';
const RUNTIME_ROOT = path.join(workspaceRoot, 'output', 'evidence', 'runtime');
const STAGE6_ROOT = path.join(RUNTIME_ROOT, 'stage-6');
const SENSITIVE_STATE_KEY_ALIASES = [
  'accesskey',
  'accesstoken',
  'apikey',
  'authorization',
  'bearer',
  'cardholder',
  'cardnumber',
  'clientsecret',
  'credential',
  'cvc',
  'cvv',
  'expiry',
  'hmackey',
  'pan',
  'password',
  'paymentmethodtoken',
  'privatekey',
  'rootkey',
  'securitycode',
  'secret',
  'sessiontoken',
  'token',
];
const LOW_ENTROPY_CONTEXT_PATTERN =
  '(?:cvc|cvv|expiry|expiration|card[^a-z0-9]{0,4}expiry|security[^a-z0-9]{0,4}code)';
const MAX_NESTED_STATE_DEPTH = 8;
const RUN_ID = stage6RunId();
const CANDIDATE = candidate();
const NETWORK_OBSERVATION_CANARY = runExternalNetworkObservationCanary();
const NEGATIVE_E2E_IDS = NEGATIVE_E2E_CONTRACT.map(({ id }) => id);
const normalizedStateKey = (value) =>
  value
    .normalize('NFKC')
    .replaceAll(/[^a-z0-9]/giu, '')
    .toLowerCase();
const isSensitiveStateKey = (value) => {
  const normalized = normalizedStateKey(value);
  return SENSITIVE_STATE_KEY_ALIASES.some((alias) => normalized.includes(alias));
};
const parseNestedState = (value) => {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed[0] !== '"' && trimmed[0] !== '{' && trimmed[0] !== '[') return undefined;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed === value ? undefined : parsed;
  } catch {
    return undefined;
  }
};
const stateContainsSensitiveKey = (value, depth = 0) => {
  if (depth > MAX_NESTED_STATE_DEPTH) return true;
  if (Array.isArray(value)) {
    return value.some((nested) => stateContainsSensitiveKey(nested, depth + 1));
  }
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).some(
      ([key, nested]) => isSensitiveStateKey(key) || stateContainsSensitiveKey(nested, depth + 1),
    );
  }
  const nested = parseNestedState(value);
  return nested === undefined ? false : stateContainsSensitiveKey(nested, depth + 1);
};
const escapeRegExpValue = (value) =>
  Array.from(value, (character) =>
    '\\^$.*+?()[]{}|'.includes(character) ? '\\' + character : character,
  ).join('');
const hasContextualLowEntropyValue = (scalar, exactValues) =>
  exactValues.some((exactValue) => {
    const escapedValue = escapeRegExpValue(exactValue);
    const separator = '[^a-z0-9]{0,16}';
    const boundaryBefore = '(?:^|[^a-z0-9])';
    const boundaryAfter = '(?:$|[^a-z0-9])';
    return (
      new RegExp(
        boundaryBefore + LOW_ENTROPY_CONTEXT_PATTERN + separator + escapedValue + boundaryAfter,
        'iu',
      ).test(scalar) ||
      new RegExp(
        boundaryBefore + escapedValue + separator + LOW_ENTROPY_CONTEXT_PATTERN + boundaryAfter,
        'iu',
      ).test(scalar)
    );
  });
const stateContainsSensitiveValue = (value, { exactValues, substringValues }, depth = 0) => {
  if (depth > MAX_NESTED_STATE_DEPTH) return true;
  if (Array.isArray(value)) {
    return value.some((nested) =>
      stateContainsSensitiveValue(nested, { exactValues, substringValues }, depth + 1),
    );
  }
  if (value !== null && typeof value === 'object') {
    return Object.values(value).some((nested) =>
      stateContainsSensitiveValue(nested, { exactValues, substringValues }, depth + 1),
    );
  }
  const scalar = String(value);
  if (
    exactValues.includes(scalar) ||
    substringValues.some((secret) => scalar.includes(secret)) ||
    hasContextualLowEntropyValue(scalar, exactValues)
  ) {
    return true;
  }
  const nested = parseNestedState(value);
  return nested === undefined
    ? false
    : stateContainsSensitiveValue(nested, { exactValues, substringValues }, depth + 1);
};
const privacyStateIsSafe = (value, { exactValues = [], substringValues = [] }) => {
  const usableExactValues = exactValues.filter(
    (candidateValue) => typeof candidateValue === 'string' && candidateValue.length > 0,
  );
  const usableSubstringValues = substringValues.filter(
    (candidateValue) => typeof candidateValue === 'string' && candidateValue.length >= 12,
  );
  return (
    !stateContainsSensitiveKey(value) &&
    !stateContainsSensitiveValue(value, {
      exactValues: usableExactValues,
      substringValues: usableSubstringValues,
    })
  );
};
const selfTestPrivacyStateOracle = () => {
  const token = 'tok_fake_0123456789abcdef01234567';
  const cardNumber = ['4111', '1111', '1111', '1111'].join('');
  const exactValues = ['12/30', '731'];
  const substringValues = [token, cardNumber];
  const safeOpaqueState = {
    cache: 'opaque_safe_cvc_segment_without_value_000',
    doubleEncodedOpaque: JSON.stringify(
      JSON.stringify({ reference: 'transaction_safe_CvC_segment' }),
    ),
    transactionId: 'transaction_safe_CvC_segment',
    statusUrl: '/api/v1/transactions/transaction_safe_CvC_segment',
    nestedJson: JSON.stringify({ checkoutId: 'checkout_safe_cvc_segment' }),
  };
  check(
    privacyStateIsSafe(safeOpaqueState, { exactValues, substringValues }),
    'PRIVACY_ORACLE_SAFE_OPAQUE_VALUE',
  );
  check(
    !privacyStateIsSafe(
      { ...safeOpaqueState, nested: { payment_method_token: 'redacted' } },
      { exactValues, substringValues },
    ),
    'PRIVACY_ORACLE_SENSITIVE_KEY_CANARY',
  );
  check(
    !privacyStateIsSafe(
      { reference: 'prefix-' + token + '-suffix' },
      { exactValues, substringValues },
    ),
    'PRIVACY_ORACLE_TOKEN_VALUE_CANARY',
  );
  check(
    !privacyStateIsSafe(
      { reference: 'prefix-' + cardNumber + '-suffix' },
      { exactValues, substringValues },
    ),
    'PRIVACY_ORACLE_PAN_VALUE_CANARY',
  );
  check(
    !privacyStateIsSafe({ reference: exactValues[0] }, { exactValues, substringValues }) &&
      !privacyStateIsSafe({ reference: exactValues[1] }, { exactValues, substringValues }),
    'PRIVACY_ORACLE_LOW_ENTROPY_VALUE_CANARY',
  );
  check(
    [
      { cache: 'cvc=' + exactValues[1] },
      { cache: 'expiry=' + exactValues[0] },
      { cache: 'security_code: "' + exactValues[1] + '"' },
      { cache: exactValues[0] + ' (card-expiry)' },
    ].every((state) => !privacyStateIsSafe(state, { exactValues, substringValues })),
    'PRIVACY_ORACLE_CONTEXTUAL_LOW_ENTROPY_CANARY',
  );
  check(
    !privacyStateIsSafe(
      {
        cache: JSON.stringify(JSON.stringify({ nested: { private_key: 'redacted' } })),
      },
      { exactValues, substringValues },
    ) &&
      !privacyStateIsSafe(
        { cache: JSON.stringify(JSON.stringify({ cache: 'cvc=' + exactValues[1] })) },
        { exactValues, substringValues },
      ),
    'PRIVACY_ORACLE_DOUBLE_ENCODED_CANARY',
  );
  check(
    [
      { api_key: 'redacted' },
      { clientSecret: 'redacted' },
      { password: 'redacted' },
      { private_key: 'redacted' },
    ].every((state) => !privacyStateIsSafe(state, { exactValues, substringValues })),
    'PRIVACY_ORACLE_SECRET_KEY_CANARY',
  );
};
const manualUat16Decision = (
  accessibilityEvidence,
  expectedExecution,
  validate = validateManualEvidenceSummary,
) => {
  const automated = accessibilityEvidence?.automated;
  const manual = accessibilityEvidence?.manualEvidence;
  const explicitlyMissing =
    manual?.status === 'NOT_RUN_MANUAL_REQUIRED' &&
    manual.reason === 'MANUAL_EVIDENCE_NOT_PROVIDED' &&
    manual.containsSensitiveData === false;
  if (explicitlyMissing) {
    return accessibilityEvidence?.status === 'PARTIAL_NOT_RUN_MANUAL_REQUIRED' &&
      automated?.status === 'PASS'
      ? 'NOT_RUN_MANUAL_REQUIRED'
      : 'FAIL';
  }
  return accessibilityEvidence?.status === 'PASS' &&
    automated?.status === 'PASS' &&
    validate(manual, automated.axeScans, expectedExecution)
    ? 'PASS'
    : 'FAIL';
};

const selfTestManualUat16Decision = () => {
  const expected = {
    commitSha: 'a'.repeat(40),
    runId: 'e6-20260816t120000z-0123abcd',
  };
  const exactValidator = (_manual, _scans, execution) =>
    execution.commitSha === expected.commitSha && execution.runId === expected.runId;
  const passed = {
    status: 'PASS',
    automated: { status: 'PASS', axeScans: [] },
    manualEvidence: { status: 'PASS' },
  };
  const missing = {
    status: 'PARTIAL_NOT_RUN_MANUAL_REQUIRED',
    automated: { status: 'PASS', axeScans: [] },
    manualEvidence: {
      status: 'NOT_RUN_MANUAL_REQUIRED',
      reason: 'MANUAL_EVIDENCE_NOT_PROVIDED',
      containsSensitiveData: false,
    },
  };
  check(manualUat16Decision(passed, expected, exactValidator) === 'PASS', 'UAT16_CANARY_PASS');
  check(
    manualUat16Decision(missing, expected, exactValidator) === 'NOT_RUN_MANUAL_REQUIRED',
    'UAT16_CANARY_MISSING',
  );
  check(
    manualUat16Decision(
      { ...passed, status: 'FAIL', manualEvidence: { status: 'FAIL' } },
      expected,
      exactValidator,
    ) === 'FAIL',
    'UAT16_CANARY_INVALID',
  );
  check(
    manualUat16Decision(passed, { ...expected, commitSha: 'b'.repeat(40) }, exactValidator) ===
      'FAIL',
    'UAT16_CANARY_WRONG_SHA',
  );
  check(
    manualUat16Decision(
      passed,
      { ...expected, runId: 'e6-20260816t120000z-deadbeef' },
      exactValidator,
    ) === 'FAIL',
    'UAT16_CANARY_WRONG_RUN',
  );
};
const externalUat33Decision = (summary, execution, decide = externalEvidenceCapabilityDecision) => {
  const decision = decide(summary, 'ownedTarget', execution);
  return ['PASS', 'FAIL', 'NOT_RUN_AUTH_REQUIRED'].includes(decision) ? decision : 'FAIL';
};
const selfTestExternalUat33Decision = () => {
  const execution = {
    commitSha: 'a'.repeat(40),
    runId: 'e6-20260816t120000z-0123abcd',
  };
  check(
    externalUat33Decision(missingExternalEvidence(execution), execution) ===
      'NOT_RUN_AUTH_REQUIRED',
    'UAT33_CANARY_MISSING',
  );
  check(
    externalUat33Decision(
      failedExternalEvidence(execution, 'EXTERNAL_EVIDENCE_CONTRACT_INVALID'),
      execution,
    ) === 'FAIL',
    'UAT33_CANARY_INVALID',
  );
  check(externalUat33Decision({}, execution, () => 'PASS') === 'PASS', 'UAT33_CANARY_PASS');
  check(externalUat33Decision({}, execution, () => 'UNKNOWN') === 'FAIL', 'UAT33_CANARY_UNKNOWN');
};
selfTestExternalEvidence();
selfTestExternalUat33Decision();
selfTestManualEvidence();
selfTestManualUat16Decision();
selfTestNegativeE2eContract();
selfTestRefreshRecoveryContract();
selfTestPrivacyStateOracle();
if (process.argv.includes('--self-test')) {
  process.stdout.write('stage-6 uat contract self-test: PASS\n');
  process.exit(0);
}
const EXTERNAL_EXECUTION = { commitSha: CANDIDATE.commitSha, runId: RUN_ID };
const EXTERNAL_EVIDENCE = await resolveExternalEvidence({
  commitSha: CANDIDATE.commitSha,
  runId: RUN_ID,
});
const UAT33_DECISION = externalUat33Decision(EXTERNAL_EVIDENCE, EXTERNAL_EXECUTION);
const results = new Map();
const evidenceCache = new Map();
const priorityFor = (id) => (['UAT-14', 'UAT-15', 'UAT-16'].includes(id) ? 'P1' : 'P0');
const now = () => new Date().toISOString();

const cleanCell = (value) => value.trim().replaceAll(String.fromCharCode(96), '');
const canonicalRows = (text) =>
  text
    .split(String.fromCharCode(10))
    .filter((line) => line.startsWith('|') && line.includes('UAT-'))
    .map((line) => line.split('|').slice(1, -1).map(cleanCell))
    .filter((cells) => /^UAT-[0-9]{2}$/u.test(cells[0] ?? ''));

const [executionMatrixText, designMatrixText] = await Promise.all([
  readFile(path.join(workspaceRoot, 'docs', 'verification', 'uat-results.md'), 'utf8'),
  readFile(path.join(workspaceRoot, 'output', 'etapas-0-1-incepcion-y-requisitos.md'), 'utf8'),
]);
const executionRows = canonicalRows(executionMatrixText);
const designRows = canonicalRows(designMatrixText);
check(executionRows.length === 48 && designRows.length === 48, 'CANONICAL_UAT_MATRIX_SIZE');
const UAT_METADATA = new Map(
  executionRows.map((execution) => {
    const design = designRows.find(([id]) => id === execution[0]);
    check(design !== undefined, 'CANONICAL_UAT_DESIGN_ROW_MISSING');
    check(execution[1] === design[1], 'CANONICAL_UAT_PRIORITY_DRIFT');
    return [
      execution[0],
      {
        priority: execution[1],
        requirements: design[2],
        traceability: design[6],
        precondition: design[3],
        expectedHttpResult: design[4],
        expectedStateAndEffects: design[5],
        expectedResult: design[4] + '; ' + design[5],
      },
    ];
  }),
);

const stepsFor = (id, evidenceIds) => {
  const metadata = UAT_METADATA.get(id);
  check(metadata !== undefined, 'CANONICAL_UAT_METADATA_MISSING');
  if (id === 'UAT-04') {
    return [
      'Preparar ' + metadata.precondition + ' con datos sintéticos aislados por runId.',
      'Enviar 10 confirms aceptados con la misma key/hash; insertar 1 probe adicional 429 (11 requests HTTP en total) y respetar Retry-After antes de continuar.',
      'Comparar los 10 responses aceptados y observar por GET/stock/logs allowlisted un único recurso, reserva, líder y dispatch.',
    ];
  }
  if (id === 'UAT-16') {
    return [
      'Preparar ' + metadata.precondition + '.',
      'Ejecutar protocolo manual con teclado, lector de pantalla, contraste y reduced motion.',
      'Registrar hallazgos sanitizados contra: ' + metadata.expectedResult + '.',
    ];
  }
  if (id === 'UAT-33') {
    return [
      'Ingerir evidencia externa v1 autorizada AUTH-E6-01 del mismo commit mediante hash, sin URL ni secretos.',
      'Validar el target propio efímero, redirect HTTP 301/308, HTTPS 200 y mixed-content = 0.',
      'Cruzar sourceSha256, autorización, ventana UTC y requests acotados contra: ' +
        metadata.expectedResult +
        '.',
    ];
  }
  return [
    'Preparar ' + metadata.precondition + ' con datos sintéticos aislados por runId.',
    'Ejecutar ' +
      COMMAND +
      ' y la sonda ' +
      evidenceIds.join(', ') +
      ' sólo sobre loopback con red externa denegada.',
    'Observar HTTP/UI/estado público y conteos allowlisted; comparar HTTP con: ' +
      metadata.expectedHttpResult +
      '.',
    'Verificar estado y efectos contra: ' + metadata.expectedStateAndEffects + '.',
  ];
};

const rowMetadata = (id, evidenceIds, runnerRole, executedAt) => {
  const metadata = UAT_METADATA.get(id);
  check(metadata !== undefined, 'CANONICAL_UAT_METADATA_MISSING');
  return {
    requirements: metadata.requirements,
    traceability: metadata.traceability,
    precondition: metadata.precondition,
    steps: stepsFor(id, evidenceIds),
    expectedResult: metadata.expectedResult,
    runnerRole,
    runId: RUN_ID,
    runnerPersona: 'QA_INDEPENDENT_UAT_RUNNER',
    executedAt,
    executedAtUtc: executedAt,
    commitSha: CANDIDATE.commitSha,
    utcSha: executedAt + ' / ' + CANDIDATE.commitSha,
    environment: stage6Environment(),
    executionScope:
      id === 'UAT-33'
        ? 'AUTHORIZED_OWNED_EPHEMERAL_QA_EXTERNAL_EVIDENCE'
        : 'LOCAL_LOOPBACK_FAKE_MEMORY_FIXTURES',
    ...(id === 'UAT-04'
      ? {
          executionAccounting: {
            acceptedConfirms: 10,
            controlledRateLimitProbes: 1,
            totalHttpAttempts: 11,
            retryAfterHonored: true,
          },
        }
      : {}),
    ...(id === 'UAT-22' || id === 'UAT-45'
      ? {
          approvedExpectationDelta: {
            id: 'CHG-E6-UAT-22-45',
            authority: ['CHG-16', 'OAS-TRANSACTION-200'],
            rule: 'POST aceptado permanece 202; el estado de error se observa por GET 200.',
          },
        }
      : {}),
  };
};

const normalizeFailureCode = (value) =>
  value
    .toUpperCase()
    .replaceAll(/[^A-Z0-9_:-]+/gu, '_')
    .replace(/^_+|_+$/gu, '')
    .slice(0, 96);

const safeFailure = (error) => {
  if (error instanceof UatFailure) {
    return { code: normalizeFailureCode(error.code), category: 'ORACLE_ASSERTION' };
  }
  const value = error instanceof Error ? error.message : '';
  if (/^FIXTURE_[A-Z0-9_:-]{3,110}$/u.test(value)) {
    return { code: value, category: 'CONTROLLED_HARNESS_ERROR' };
  }
  const category = /EADDRINUSE/iu.test(value)
    ? 'LOOPBACK_PORT_IN_USE'
    : /fetch failed|ECONNREFUSED|socket hang up/iu.test(value)
      ? 'LOOPBACK_TRANSPORT_FAILURE'
      : /timeout|timed out|exceeded/iu.test(value)
        ? 'UAT_PROBE_TIMEOUT'
        : /target (?:page|context|browser).*closed/iu.test(value)
          ? 'BROWSER_CONTEXT_CLOSED'
          : error instanceof TypeError
            ? 'UAT_PROBE_TYPE_ERROR'
            : 'UAT_PROBE_ERROR';
  const errorType = normalizeFailureCode(error instanceof Error ? error.name : 'UNKNOWN_ERROR');
  return { code: category + '_' + errorType, category };
};

const execute = async (id, observableResult, evidenceIds, run, runnerRole = 'BLACK_BOX_UAT') => {
  const startedAt = Date.now();
  try {
    await run();
    const executedAt = now();
    results.set(id, {
      ...rowMetadata(id, evidenceIds, runnerRole, executedAt),
      id,
      priority: priorityFor(id),
      status: 'PASS',
      observableResult,
      actualResult: observableResult,
      defect: 'N/A',
      evidence: evidenceIds,
      evidenceIds,
      runnerRole,
      executedAt,
      commitSha: CANDIDATE.commitSha,
      durationMs: Date.now() - startedAt,
    });
  } catch (error) {
    const executedAt = now();
    const failure = safeFailure(error);
    results.set(id, {
      ...rowMetadata(id, evidenceIds, runnerRole, executedAt),
      id,
      priority: priorityFor(id),
      status: 'FAIL',
      observableResult: 'No cumplió el oráculo: ' + failure.code,
      actualResult: 'FAIL: ' + failure.code,
      failureCode: failure.code,
      failureCategory: failure.category,
      defect: 'DEF-E6-' + id,
      evidence: evidenceIds,
      evidenceIds,
      runnerRole,
      executedAt,
      commitSha: CANDIDATE.commitSha,
      durationMs: Date.now() - startedAt,
    });
  }
};

const omit = (id, status, observableResult, evidenceIds) => {
  const runnerRole = status === 'NOT_RUN_MANUAL_REQUIRED' ? 'MANUAL_UAT_PENDING' : 'AUTH_GATE';
  const executedAt = now();
  results.set(id, {
    ...rowMetadata(id, evidenceIds, runnerRole, executedAt),
    id,
    priority: priorityFor(id),
    status,
    observableResult,
    actualResult: observableResult,
    defect: 'N/A',
    evidence: evidenceIds,
    evidenceIds,
    runnerRole,
    executedAt,
    commitSha: CANDIDATE.commitSha,
    durationMs: 0,
  });
};
const loadJson = async (filename) => {
  if (evidenceCache.has(filename)) return evidenceCache.get(filename);
  const promise = readFile(filename, 'utf8').then(JSON.parse);
  evidenceCache.set(filename, promise);
  return promise;
};

const stage6Evidence = async (name) => {
  const evidence = await loadJson(path.join(STAGE6_ROOT, `${name}.json`));
  check(evidence.stage === 6, `${name.toUpperCase()}_WRONG_STAGE`);
  check(evidence.runId === RUN_ID, `${name.toUpperCase()}_STALE_RUN_ID`);
  const evidenceCommitSha =
    evidence.commitSha ?? evidence.candidate?.commitSha ?? evidence.baseEvidence?.commitSha;
  check(evidenceCommitSha === CANDIDATE.commitSha, `${name.toUpperCase()}_WRONG_SHA`);
  check(evidence.containsSensitiveData === false, `${name.toUpperCase()}_SENSITIVE`);
  check(evidence.environment === stage6Environment(), `${name.toUpperCase()}_WRONG_ENVIRONMENT`);
  return evidence;
};

const smokeEvidence = async () => {
  const [preflight, smoke] = await Promise.all([
    stage6Evidence('preflight'),
    loadJson(path.join(RUNTIME_ROOT, 'stage-5-smoke-results.json')),
  ]);
  check(smoke.exitCode === 0 && smoke.total === 12 && smoke.passed === 12, 'SMOKE_NOT_GREEN');
  check(smoke.networkGuardCanaries === 'PASS', 'SMOKE_NETWORK_GUARD_FAILED');
  check(smoke.smokeScriptSha256 === sha256File('scripts/smoke/run.mjs'), 'SMOKE_SCRIPT_DRIFT');
  check(
    new Date(smoke.executedAt).getTime() >= new Date(preflight.generatedAt).getTime(),
    'SMOKE_STALE',
  );
  return smoke;
};

const smokePassed = async (...ids) => {
  const smoke = await smokeEvidence();
  check(new Set(smoke.results.map(({ id }) => id)).size === 12, 'SMOKE_IDS_INVALID');
  for (const id of ids) {
    check(smoke.results.find((item) => item.id === id)?.status === 'PASS', `${id}_NOT_PASS`);
  }
};

const safeProblem = (response, status, code) => {
  check(response.status === status, `${code}_HTTP_${response.status}`);
  check(response.body?.code === code, `${code}_BODY`);
  const serialized = JSON.stringify(response.body);
  check(!/stack|token|securitycode|paymentmethod|privatekey/iu.test(serialized), `${code}_LEAK`);
};

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

const acceptanceFixture = () => ({
  termsAcceptanceToken: `${'A'.repeat(32)}.${'B'.repeat(43)}`,
  personalDataAcceptanceToken: `${'C'.repeat(32)}.${'D'.repeat(43)}`,
});

await execute(
  'UAT-01',
  'Checkout aprobado: 202, final APPROVED/PAID, stock -1 y una entrega observable.',
  ['EVD-E6-36/UAT-01', 'stage-5-smoke-results.json#SMK-E5-01'],
  () => smokePassed('SMK-E5-01'),
);
await execute(
  'UAT-02',
  'Declinado: reserva liberada, stock neto intacto y ninguna entrega.',
  ['EVD-E6-36/UAT-02', 'stage-5-smoke-results.json#SMK-E5-02'],
  () => smokePassed('SMK-E5-02'),
);
await execute(
  'UAT-03',
  'PENDING se recuperó por GET/refresh sin falso final ni segundo POST.',
  ['EVD-E6-36/UAT-03', 'stage-5-smoke-results.json#SMK-E5-04/06'],
  () => smokePassed('SMK-E5-04', 'SMK-E5-06'),
);

await execute(
  'UAT-04',
  'Diez confirms aceptados con la misma key devolvieron el mismo recurso y un solo efecto.',
  ['EVD-E6-36/UAT-04', 'HTTP-UAT-04', 'OBS-UAT-04'],
  () =>
    withApi(
      {
        FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
        PRODUCT_INITIAL_STOCK: '1',
      },
      async ({ countLog }) => {
        const session = new ApiSession();
        const ready = await prepareReady(session);
        const idempotencyKey = 'idem-uat04-confirm-0001';
        const accepted = [];
        let retryAfterSeconds;
        for (let index = 0; index < 10; index += 1) {
          if (index === 2) {
            const limited = await submitPrepared(session, ready, { idempotencyKey });
            safeProblem(limited, 429, 'RATE_LIMITED');
            retryAfterSeconds = Number(limited.headers.get('retry-after'));
            check(Number.isSafeInteger(retryAfterSeconds) && retryAfterSeconds > 0, 'RETRY_AFTER');
            await delay(retryAfterSeconds * 1_000 + 250);
          } else if (index > 2) {
            await delay((retryAfterSeconds ?? 30) * 1_000 + 250);
          }
          const response = await submitPrepared(session, ready, { idempotencyKey });
          expectStatus(response, 202, `CONFIRM_${index + 1}`);
          accepted.push({
            transactionId: response.body.transactionId,
            statusUrl: response.body.statusUrl,
            location: response.headers.get('location'),
          });
        }
        check(
          accepted.every(
            (item) =>
              item.transactionId === accepted[0].transactionId &&
              item.statusUrl === accepted[0].statusUrl &&
              item.location === accepted[0].location,
          ),
          'CONFIRM_RESOURCE_DRIFT',
        );
        const transaction = expectStatus(
          await getTransaction(session, accepted[0].transactionId),
          200,
          'CONFIRM_TRANSACTION',
        );
        check(
          transaction.paymentStatus === 'PENDING' && transaction.reservationStatus === 'ACTIVE',
          'CONFIRM_STATE_DRIFT',
        );
        check((await getStock(session)).available === 0, 'CONFIRM_RESERVED_MORE_THAN_ONCE');
        await delay(100);
        check(countLog('payment.dispatch_claimed') === 1, 'CONFIRM_MULTIPLE_DISPATCH');
        check(countLog('payment.idempotency_replayed') === 9, 'CONFIRM_REPLAY_COUNT');
      },
    ),
);

await execute(
  'UAT-05',
  'Misma key con semántica distinta devolvió 409 y preservó el intento original.',
  ['EVD-E6-36/UAT-05', 'HTTP-UAT-05', 'OBS-UAT-05'],
  () =>
    withApi(
      { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04', PRODUCT_INITIAL_STOCK: '1' },
      async ({ countLog }) => {
        const session = new ApiSession();
        const ready = await prepareReady(session);
        const idempotencyKey = 'idem-uat05-conflict-0001';
        const first = await submitPrepared(session, ready, { idempotencyKey });
        expectStatus(first, 202, 'CONFLICT_ORIGINAL');
        const conflict = await submitPrepared(session, ready, {
          idempotencyKey,
          body: { ...ready.body, installments: 2 },
        });
        safeProblem(conflict, 409, 'IDEMPOTENCY_CONFLICT');
        const original = expectStatus(
          await getTransaction(session, first.body.transactionId),
          200,
          'CONFLICT_ORIGINAL_GET',
        );
        check(original.reservationStatus === 'ACTIVE', 'CONFLICT_RELEASED_ORIGINAL');
        check((await getStock(session)).available === 0, 'CONFLICT_STOCK_DRIFT');
        await delay(50);
        check(countLog('payment.dispatch_claimed') === 1, 'CONFLICT_EXTRA_DISPATCH');
      },
    ),
);

await execute(
  'UAT-06',
  'Dos compradores sobre la última unidad produjeron un ganador, un 409 y stock no negativo.',
  ['EVD-E6-36/UAT-06', 'stage-5-smoke-results.json#SMK-E5-08'],
  () => smokePassed('SMK-E5-08'),
);

await execute(
  'UAT-07',
  'El total enviado por cliente fue rechazado; stock y efectos quedaron intactos.',
  ['EVD-E6-36/UAT-07', 'HTTP-UAT-07'],
  () =>
    withApi(
      { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04', PRODUCT_INITIAL_STOCK: '1' },
      async ({ countLog }) => {
        const session = new ApiSession();
        const ready = await prepareReady(session);
        const response = await submitPrepared(session, ready, {
          idempotencyKey: 'idem-uat07-tamper-0001',
          body: { ...ready.body, total: 1 },
        });
        safeProblem(response, 422, 'FIELD_INVALID');
        check((await getStock(session)).available === 1, 'TAMPER_CHANGED_STOCK');
        check(countLog('payment.dispatch_claimed') === 0, 'TAMPER_DISPATCHED');
      },
    ),
);

const verifyProvenNotSent = () =>
  withApi(
    { FAKE_PAYMENT_SCENARIO: 'FAKE-PAY-05', PRODUCT_INITIAL_STOCK: '1' },
    async ({ countLog }) => {
      const session = new ApiSession();
      const ready = await prepareReady(session);
      const submission = await submitPrepared(session, ready, {
        idempotencyKey: 'idem-uat22-not-sent-001',
      });
      expectStatus(submission, 202, 'NOT_SENT_ACCEPTED');
      const transaction = expectStatus(
        await getTransaction(session, submission.body.transactionId),
        200,
        'NOT_SENT_TRANSACTION',
      );
      check(
        transaction.paymentStatus === 'ERROR' &&
          transaction.dispatchPhase === 'NOT_SENT_FAILED' &&
          transaction.reservationStatus === 'RELEASED' &&
          transaction.recoveryCode === 'PROVIDER_NOT_SENT' &&
          transaction.deliveryId === undefined,
        'NOT_SENT_FINAL_STATE',
      );
      check((await getStock(session)).available === 1, 'NOT_SENT_STOCK_NOT_RELEASED');
      await delay(50);
      check(countLog('payment.dispatch_claimed') === 1, 'NOT_SENT_DISPATCH_COUNT');
    },
  );

const verifyUnknownAfterPossibleSend = () =>
  withApi(
    { FAKE_PAYMENT_SCENARIO: 'FAKE-PAY-07', PRODUCT_INITIAL_STOCK: '1' },
    async ({ countLog }) => {
      const session = new ApiSession();
      const ready = await prepareReady(session);
      const submission = await submitPrepared(session, ready, {
        idempotencyKey: 'idem-uat23-unknown-0001',
      });
      expectStatus(submission, 202, 'UNKNOWN_ACCEPTED');
      for (let index = 0; index < 2; index += 1) {
        const transaction = expectStatus(
          await getTransaction(session, submission.body.transactionId),
          200,
          'UNKNOWN_TRANSACTION',
        );
        check(
          transaction.paymentStatus === 'PENDING' &&
            transaction.dispatchPhase === 'UNKNOWN' &&
            transaction.reservationStatus === 'ACTIVE' &&
            transaction.deliveryId === undefined,
          'UNKNOWN_STATE',
        );
      }
      check((await getStock(session)).available === 0, 'UNKNOWN_RESERVATION_RELEASED');
      await delay(50);
      check(countLog('payment.dispatch_claimed') === 1, 'UNKNOWN_BLIND_POST');
    },
  );

await execute(
  'UAT-08',
  'Cero bytes liberó sólo tras aceptación; outcome ambiguo conservó reserva y evitó retry ciego.',
  ['EVD-E6-36/UAT-08', 'HTTP-UAT-08A', 'HTTP-UAT-08B', 'CHG-16'],
  async () => {
    await verifyProvenNotSent();
    await verifyUnknownAfterPossibleSend();
  },
);

await execute(
  'UAT-17',
  'Capability ajena y origen hostil devolvieron 404/403 seguros, sin PII ni mutación.',
  ['EVD-E6-36/UAT-17', 'HTTP-UAT-17'],
  () =>
    withApi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ countLog }) => {
      const owner = new ApiSession();
      const createdResponse = await owner.request('POST', '/api/v1/checkouts', {
        body: { productId: PRODUCT_ID },
      });
      const created = expectStatus(createdResponse, 201, 'IDOR_CREATE');
      const attacker = new ApiSession();
      attacker.cookie = '__Secure-checkout_cap=foreign.synthetic';
      const forbidden = await attacker.request('GET', `/api/v1/checkouts/${created.checkoutId}`);
      safeProblem(forbidden, 404, 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN');
      const absent = await attacker.request('GET', '/api/v1/checkouts/checkout_missing_001');
      safeProblem(absent, 404, 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN');
      const hostile = await loopbackFetch(`${API_ORIGIN}/api/v1/products`, {
        headers: { Origin: 'https://hostile.example.invalid' },
      }).then(async (response) => ({
        status: response.status,
        headers: response.headers,
        body: await response.json(),
      }));
      safeProblem(hostile, 403, 'ORIGIN_FORBIDDEN');
      check((await getStock(owner)).available === 1, 'IDOR_CHANGED_STOCK');
      check(countLog('payment.dispatch_claimed') === 0, 'IDOR_DISPATCHED');
    }),
);

await execute(
  'UAT-21',
  'Quote COP usó enteros y total = subtotal + baseFee + deliveryFee sin reservar stock.',
  ['EVD-E6-36/UAT-21', 'HTTP-UAT-21'],
  () =>
    withApi({ PRODUCT_INITIAL_STOCK: '2' }, async () => {
      const session = new ApiSession();
      const created = expectStatus(
        await session.request('POST', '/api/v1/checkouts', { body: { productId: PRODUCT_ID } }),
        201,
        'QUOTE_CREATE',
      );
      const quote = created.quote;
      const amounts = [quote.subtotal, quote.baseFee, quote.deliveryFee, quote.total];
      check(
        amounts.every((money) => money.currency === 'COP'),
        'QUOTE_CURRENCY',
      );
      check(
        amounts.every((money) => Number.isSafeInteger(money.amountInCents)),
        'QUOTE_INTEGER',
      );
      check(
        quote.total.amountInCents ===
          quote.subtotal.amountInCents +
            quote.baseFee.amountInCents +
            quote.deliveryFee.amountInCents,
        'QUOTE_ARITHMETIC',
      );
      check((await getStock(session)).available === 2, 'QUOTE_RESERVED_STOCK');
    }),
);

await execute(
  'UAT-22',
  'PROVIDER_ZERO_BYTES aceptado por 202 se observó por GET como NOT_SENT_FAILED, liberado y sin entrega.',
  ['EVD-E6-36/UAT-22', 'HTTP-UAT-22', 'CHG-16', 'OAS-TRANSACTION-200'],
  verifyProvenNotSent,
);
await execute(
  'UAT-23',
  'Posible envío quedó PENDING/UNKNOWN, reserva activa y sólo GET posteriores.',
  ['EVD-E6-36/UAT-23', 'HTTP-UAT-23'],
  verifyUnknownAfterPossibleSend,
);

await execute(
  'UAT-24',
  'Key nueva durante intento activo devolvió 409 + Location sin nuevo despacho.',
  ['EVD-E6-36/UAT-24', 'HTTP-UAT-24'],
  () =>
    withApi(
      { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04', PRODUCT_INITIAL_STOCK: '1' },
      async ({ countLog }) => {
        const session = new ApiSession();
        const ready = await prepareReady(session);
        const first = await submitPrepared(session, ready, {
          idempotencyKey: 'idem-uat24-original-0001',
        });
        expectStatus(first, 202, 'ACTIVE_ORIGINAL');
        const checkout = await session.request('GET', `/api/v1/checkouts/${ready.checkoutId}`);
        expectStatus(checkout, 200, 'ACTIVE_CHECKOUT');
        const conflict = await session.request(
          'POST',
          `/api/v1/checkouts/${ready.checkoutId}/transactions`,
          {
            headers: {
              'Idempotency-Key': 'idem-uat24-second-key01',
              'If-Match': checkout.headers.get('etag'),
            },
            body: ready.body,
          },
        );
        safeProblem(conflict, 409, 'PAYMENT_ALREADY_IN_PROGRESS');
        check(conflict.headers.get('location') === first.body.statusUrl, 'ACTIVE_LOCATION');
        check((await getStock(session)).available === 0, 'ACTIVE_RESERVATION_DRIFT');
        await delay(50);
        check(countLog('payment.dispatch_claimed') === 1, 'ACTIVE_EXTRA_DISPATCH');
      },
    ),
);

await execute(
  'UAT-28',
  'Checkout expirado devolvió 410 al dueño, capability ajena 404 y la UI limpió progreso.',
  ['EVD-E6-36/UAT-28', 'HTTP-UAT-28', 'stage-5-smoke-results.json#SMK-E5-10'],
  async () => {
    await smokePassed('SMK-E5-10');
    await withApi(
      { CHECKOUT_TTL_SECONDS: '0', PRODUCT_INITIAL_STOCK: '1' },
      async ({ countLog }) => {
        const owner = new ApiSession();
        const created = expectStatus(
          await owner.request('POST', '/api/v1/checkouts', { body: { productId: PRODUCT_ID } }),
          201,
          'EXPIRED_CREATE',
        );
        safeProblem(
          await owner.request('GET', '/api/v1/checkouts/' + created.checkoutId),
          410,
          'CHECKOUT_EXPIRED',
        );
        const attacker = new ApiSession();
        attacker.cookie = '__Secure-checkout_cap=capability.synthetic.foreign';
        safeProblem(
          await attacker.request('GET', '/api/v1/checkouts/' + created.checkoutId),
          404,
          'CHECKOUT_NOT_FOUND_OR_FORBIDDEN',
        );
        check((await getStock(owner)).available === 1, 'EXPIRED_CHANGED_STOCK');
        check(countLog('payment.dispatch_claimed') === 0, 'EXPIRED_DISPATCHED');
      },
    );
  },
);

await execute(
  'UAT-30',
  'Contrato OpenAPI versionado cubrió las rutas públicas; HTTP y ejemplos quedaron sanitizados.',
  ['EVD-E6-36/UAT-30', 'HTTP-UAT-30', 'OAS-UAT-30'],
  async () => {
    const openApiPath = path.join(workspaceRoot, 'output', 'architecture', 'openapi.yaml');
    const contract = await readFile(openApiPath, 'utf8');
    const requiredPaths = [
      '/api/v1/products:',
      '/api/v1/products/{productId}:',
      '/api/v1/stock/{productId}:',
      '/api/v1/checkouts:',
      '/api/v1/checkouts/{checkoutId}:',
      '/api/v1/checkouts/{checkoutId}/customer:',
      '/api/v1/checkouts/{checkoutId}/delivery-details:',
      '/api/v1/payment-configuration:',
      '/api/v1/checkouts/{checkoutId}/transactions:',
      '/api/v1/transactions/{transactionId}:',
      '/api/v1/webhooks/payment:',
      '/api/v1/deliveries/{deliveryId}:',
    ];
    check(contract.startsWith('openapi: 3.1.'), 'OPENAPI_VERSION');
    check(
      requiredPaths.every((entry) => contract.includes(entry)),
      'OPENAPI_PATH_MISSING',
    );
    check(
      Array.from({ length: 12 }, (_, index) => 'API-' + String(index + 1).padStart(2, '0')).every(
        (id) => contract.includes('x-api-id: ' + id),
      ),
      'OPENAPI_OPERATION_MISSING',
    );
    check(
      !/(?:Bearer\s+(?!REDACTED|SYNTHETIC|EXAMPLE)[A-Za-z0-9._-]{24,}|tok_(?!fake_)[A-Za-z0-9_-]{8,})/iu.test(
        contract,
      ),
      'OPENAPI_EXAMPLE_SENSITIVE',
    );
    check(createHash('sha256').update(contract).digest('hex').length === 64, 'OPENAPI_HASH_FAILED');
    await withApi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ countLog }) => {
      const session = new ApiSession();
      const docs = await loopbackFetch(API_ORIGIN + '/api/docs');
      check(
        docs.status === 200 && docs.headers.get('content-type')?.includes('application/yaml'),
        'OPENAPI_DOCS_HTTP',
      );
      check((await docs.text()) === contract, 'OPENAPI_DOCS_BODY');
      const missing = await session.request('GET', '/api/v1/products/product_missing_001');
      safeProblem(missing, 404, 'PRODUCT_NOT_FOUND');
      expectStatus(await session.request('GET', '/api/v1/products'), 200, 'OPENAPI_PRODUCTS');
      expectStatus(
        await session.request('POST', '/api/v1/checkouts', {
          body: { productId: PRODUCT_ID },
        }),
        201,
        'OPENAPI_CHECKOUT_CREATE',
      );
      check((await getStock(session)).available === 1, 'OPENAPI_CHANGED_STOCK');
      check(countLog('payment.dispatch_claimed') === 0, 'OPENAPI_DISPATCHED');
    });
  },
);

await execute(
  'UAT-32',
  'Configuración que parece productiva falló cerrada con health/config 503, OBS-INCIDENT sanitizado y cero efectos.',
  ['EVD-E6-36/UAT-32', 'HTTP-UAT-32', 'OBS-UAT-32'],
  () =>
    withApi(
      { APP_ENV: 'preview', PAYMENT_ADAPTER: 'sandbox', PRODUCT_INITIAL_STOCK: '1' },
      async ({ countLog }) => {
        const health = await loopbackFetch(API_ORIGIN + '/api/health').then(async (response) => ({
          status: response.status,
          headers: response.headers,
          body: await response.json(),
        }));
        safeProblem(health, 503, 'ENVIRONMENT_MISMATCH');
        const session = new ApiSession();
        safeProblem(
          await session.request('GET', '/api/v1/payment-configuration'),
          503,
          'PROVIDER_AUTH_OR_CONFIG_INVALID',
        );
        check((await getStock(session)).available === 1, 'ENVIRONMENT_CHANGED_STOCK');
        check(countLog('payment.dispatch_claimed') === 0, 'ENVIRONMENT_DISPATCHED');
        check(countLog('sandbox_guard.blocked') === 1, 'ENVIRONMENT_INCIDENT_MISSING');
      },
    ),
);

await execute(
  'UAT-34',
  'PENDING/UNKNOWN siguió recuperable tras TTL, con reserva activa y un único despacho.',
  ['EVD-E6-36/UAT-34', 'HTTP-UAT-34'],
  () =>
    withApi(
      {
        CHECKOUT_TTL_SECONDS: '1',
        FAKE_PAYMENT_SCENARIO: 'FAKE-PAY-07',
        PRODUCT_INITIAL_STOCK: '1',
      },
      async ({ countLog }) => {
        const session = new ApiSession();
        const ready = await prepareReady(session);
        const accepted = await submitPrepared(session, ready, {
          idempotencyKey: 'idem-uat34-ttl-pending01',
        });
        expectStatus(accepted, 202, 'TTL_PENDING_ACCEPTED');
        await delay(1_250);
        const transaction = expectStatus(
          await getTransaction(session, accepted.body.transactionId),
          200,
          'TTL_PENDING_GET',
        );
        check(
          transaction.paymentStatus === 'PENDING' &&
            transaction.dispatchPhase === 'UNKNOWN' &&
            transaction.reservationStatus === 'ACTIVE',
          'TTL_PENDING_STATE',
        );
        check((await getStock(session)).available === 0, 'TTL_PENDING_RELEASED');
        check(countLog('payment.dispatch_claimed') === 1, 'TTL_PENDING_DISPATCH_COUNT');
      },
    ),
);

await execute(
  'UAT-37',
  'Producto inexistente devolvió 404 seguro y no produjo reserva ni llamada de pago.',
  ['EVD-E6-36/UAT-37', 'HTTP-UAT-37'],
  () =>
    withApi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ countLog }) => {
      const session = new ApiSession();
      safeProblem(
        await session.request('GET', '/api/v1/products/product_missing_001'),
        404,
        'PRODUCT_NOT_FOUND',
      );
      safeProblem(
        await session.request('POST', '/api/v1/checkouts', {
          body: { productId: 'product_missing_001' },
        }),
        404,
        'PRODUCT_NOT_FOUND',
      );
      check((await getStock(session)).available === 1, 'MISSING_PRODUCT_STOCK_DRIFT');
      check(countLog('payment.dispatch_claimed') === 0, 'MISSING_PRODUCT_DISPATCHED');
    }),
);

await execute(
  'UAT-38',
  'Producto sin disponibilidad devolvió 409, mantuvo stock en cero y no llamó al proveedor.',
  ['EVD-E6-36/UAT-38', 'HTTP-UAT-38'],
  () =>
    withApi({ PRODUCT_INITIAL_STOCK: '0' }, async ({ countLog }) => {
      const session = new ApiSession();
      safeProblem(
        await session.request('POST', '/api/v1/checkouts', { body: { productId: PRODUCT_ID } }),
        409,
        'OUT_OF_STOCK',
      );
      check((await getStock(session)).available === 0, 'OUT_OF_STOCK_DRIFT');
      check(countLog('payment.dispatch_claimed') === 0, 'OUT_OF_STOCK_DISPATCHED');
    }),
);

await execute(
  'UAT-39',
  'Quote obsoleta devolvió 409, exigió re-cotización y no reservó ni despachó.',
  ['EVD-E6-36/UAT-39', 'HTTP-UAT-39', 'stage-5-smoke-results.json#SMK-E5-09'],
  async () => {
    await smokePassed('SMK-E5-09');
    await withApi({ PRODUCT_INITIAL_STOCK: '1', QUOTE_TTL_SECONDS: '0' }, async ({ countLog }) => {
      const session = new ApiSession();
      const ready = await prepareReady(session);
      safeProblem(
        await submitPrepared(session, ready, {
          idempotencyKey: 'idem-uat39-stale-quote01',
        }),
        409,
        'QUOTE_STALE',
      );
      check((await getStock(session)).available === 1, 'STALE_QUOTE_CHANGED_STOCK');
      check(countLog('payment.dispatch_claimed') === 0, 'STALE_QUOTE_DISPATCHED');
    });
  },
);
const verifyInvalidCustomerAndDelivery = () =>
  withApi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ countLog, outputContains }) => {
    const session = new ApiSession();
    const createdResponse = await session.request('POST', '/api/v1/checkouts', {
      body: { productId: PRODUCT_ID },
    });
    const created = expectStatus(createdResponse, 201, 'INVALID_DETAILS_CREATE');
    safeProblem(
      await session.request('PUT', '/api/v1/checkouts/' + created.checkoutId + '/customer', {
        headers: { 'If-Match': createdResponse.headers.get('etag') },
        body: { fullName: 'X', email: 'not-an-email', phone: 'invalid-phone' },
      }),
      422,
      'FIELD_INVALID',
    );
    safeProblem(
      await session.request(
        'PUT',
        '/api/v1/checkouts/' + created.checkoutId + '/delivery-details',
        {
          headers: { 'If-Match': createdResponse.headers.get('etag') },
          body: { addressLine1: 'X', city: 'X', region: 'X', postalCode: '!' },
        },
      ),
      422,
      'FIELD_INVALID',
    );
    check((await getStock(session)).available === 1, 'INVALID_DETAILS_CHANGED_STOCK');
    check(countLog('payment.dispatch_claimed') === 0, 'INVALID_DETAILS_DISPATCHED');
    check(
      !outputContains('not-an-email') && !outputContains('invalid-phone'),
      'INVALID_PII_LOGGED',
    );
  });

await execute(
  'UAT-45',
  'Token rechazado fue aceptado localmente por 202 y GET mostró ERROR liberado, sin entrega.',
  ['EVD-E6-36/UAT-45', 'HTTP-UAT-45', 'CHG-16', 'OAS-TRANSACTION-200'],
  () =>
    withApi(
      { FAKE_PAYMENT_SCENARIO: 'FAKE-PAY-11', PRODUCT_INITIAL_STOCK: '1' },
      async ({ countLog, outputContains }) => {
        const session = new ApiSession();
        const ready = await prepareReady(session);
        const paymentToken = ready.body.paymentMethodToken;
        const accepted = await submitPrepared(session, ready, {
          idempotencyKey: 'idem-uat45-token-reject01',
        });
        expectStatus(accepted, 202, 'TOKEN_REJECTION_ACCEPTED');
        const transaction = expectStatus(
          await getTransaction(session, accepted.body.transactionId),
          200,
          'TOKEN_REJECTION_GET',
        );
        check(
          transaction.paymentStatus === 'ERROR' &&
            transaction.dispatchPhase === 'ACKNOWLEDGED' &&
            transaction.reservationStatus === 'RELEASED' &&
            transaction.recoveryCode === 'PAYMENT_TOKEN_REJECTED' &&
            transaction.deliveryId === undefined,
          'TOKEN_REJECTION_STATE',
        );
        check((await getStock(session)).available === 1, 'TOKEN_REJECTION_STOCK');
        check(countLog('payment.dispatch_claimed') === 1, 'TOKEN_REJECTION_DISPATCH_COUNT');
        check(!outputContains(paymentToken), 'TOKEN_REJECTION_TOKEN_LOGGED');
      },
    ),
);

await execute(
  'UAT-46',
  'El tercer request controlado devolvió 429 + Retry-After seguro, sin mutación ni despacho.',
  ['EVD-E6-36/UAT-46', 'HTTP-UAT-46'],
  () =>
    withApi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ countLog }) => {
      const session = new ApiSession();
      const pathname = '/api/v1/checkouts/checkout_missing_001/transactions';
      for (let attempt = 0; attempt < 2; attempt += 1) {
        safeProblem(
          await session.request('POST', pathname, {
            headers: {
              'Idempotency-Key': 'idem-uat46-missing-' + attempt + '0001',
              'If-Match': '"checkout-v1"',
            },
            body: {
              quoteId: 'quote_missing_001',
              paymentMethodToken: 'tok_fake_synthetic_uat46',
              installments: 1,
              acceptances: acceptanceFixture(),
            },
          }),
          404,
          'CHECKOUT_NOT_FOUND_OR_FORBIDDEN',
        );
      }
      const limited = await session.request('POST', pathname, {
        headers: {
          'Idempotency-Key': 'idem-uat46-missing-20001',
          'If-Match': '"checkout-v1"',
        },
        body: {
          quoteId: 'quote_missing_001',
          paymentMethodToken: 'tok_fake_synthetic_uat46',
          installments: 1,
          acceptances: acceptanceFixture(),
        },
      });
      safeProblem(limited, 429, 'RATE_LIMITED');
      check(Number(limited.headers.get('retry-after')) > 0, 'RATE_LIMIT_RETRY_AFTER');
      check((await getStock(session)).available === 1, 'RATE_LIMIT_CHANGED_STOCK');
      check(countLog('payment.dispatch_claimed') === 0, 'RATE_LIMIT_DISPATCHED');
    }),
);

await execute(
  'UAT-48',
  'Adapter sandbox sin autenticación/config devolvió 503 antes de reservar o enviar.',
  ['EVD-E6-36/UAT-48', 'HTTP-UAT-48', 'ADR-09-DEFERRED'],
  () =>
    withApi({ PAYMENT_ADAPTER: 'sandbox', PRODUCT_INITIAL_STOCK: '1' }, async ({ countLog }) => {
      const session = new ApiSession();
      const createdResponse = await session.request('POST', '/api/v1/checkouts', {
        body: { productId: PRODUCT_ID },
      });
      const created = expectStatus(createdResponse, 201, 'SANDBOX_CREATE');
      const customerResponse = await session.request(
        'PUT',
        '/api/v1/checkouts/' + created.checkoutId + '/customer',
        {
          headers: { 'If-Match': createdResponse.headers.get('etag') },
          body: {
            fullName: 'Persona Sintetica',
            email: 'uat@example.invalid',
            phone: '+573001112233',
          },
        },
      );
      expectStatus(customerResponse, 200, 'SANDBOX_CUSTOMER');
      const deliveryResponse = await session.request(
        'PUT',
        '/api/v1/checkouts/' + created.checkoutId + '/delivery-details',
        {
          headers: { 'If-Match': customerResponse.headers.get('etag') },
          body: {
            addressLine1: 'Calle Sintetica 1',
            city: 'Bogota',
            region: 'Cundinamarca',
            postalCode: '110111',
          },
        },
      );
      expectStatus(deliveryResponse, 200, 'SANDBOX_DELIVERY');
      const unavailable = await session.request(
        'POST',
        '/api/v1/checkouts/' + created.checkoutId + '/transactions',
        {
          headers: {
            'Idempotency-Key': 'idem-uat48-sandbox-disabled1',
            'If-Match': deliveryResponse.headers.get('etag'),
          },
          body: {
            quoteId: created.quote.quoteId,
            paymentMethodToken: 'tok_fake_synthetic_uat48',
            installments: 1,
            acceptances: acceptanceFixture(),
          },
        },
      );
      safeProblem(unavailable, 503, 'PROVIDER_AUTH_OR_CONFIG_INVALID');
      check((await getStock(session)).available === 1, 'SANDBOX_CONFIG_CHANGED_STOCK');
      check(countLog('payment.dispatch_claimed') === 0, 'SANDBOX_CONFIG_DISPATCHED');
    }),
);
const chromiumTarget = detectBrowserTargets().find(({ id }) => id === 'chromium');

const runBrowserSession = async (target, apiOverrides, run, bridgeOptions = {}) => {
  check(target !== undefined && typeof target.launch === 'function', 'BROWSER_RUNTIME_MISSING');
  return withApi(apiOverrides, async (apiObservation) => {
    const browser = await target.launch();
    const context = await browser.newContext({
      viewport: { width: 390, height: 844 },
      locale: 'es-CO',
      colorScheme: 'light',
    });
    const page = await context.newPage();
    const network = await installCapabilityBridge(page, bridgeOptions);
    try {
      return await run({ page, context, apiObservation, network });
    } finally {
      let externalRequests;
      let lifecycleCancellations;
      try {
        await network.dispose();
        externalRequests = network.externalRequests();
        lifecycleCancellations = network.lifecycleCancellations();
      } finally {
        await context.close();
        await browser.close();
      }
      check(lifecycleCancellations <= 4, 'UI_LIFECYCLE_CANCELLATION_BURST');
      check(externalRequests === 0, 'UI_EXTERNAL_NETWORK_ATTEMPT');
    }
  });
};

const withChromiumUi = (apiOverrides, run) =>
  withWebPreview(() => runBrowserSession(chromiumTarget, apiOverrides, run));

const withChromiumUiBridge = (apiOverrides, bridgeOptions, run) =>
  withWebPreview(() => runBrowserSession(chromiumTarget, apiOverrides, run, bridgeOptions));

const browserRequest = (page, method, pathname, options = {}) =>
  page.evaluate(
    async ({ method: requestMethod, pathname: requestPath, headers, body }) => {
      const response = await fetch(requestPath, {
        method: requestMethod,
        headers: {
          Accept: 'application/json',
          ...(requestMethod === 'GET' ? {} : { 'Content-Type': 'application/json' }),
          ...headers,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(5_000),
      });
      const text = await response.text();
      let responseBody = null;
      if (text.length > 0) {
        try {
          responseBody = JSON.parse(text);
        } catch {
          responseBody = text;
        }
      }
      return {
        status: response.status,
        body: responseBody,
        etag: response.headers.get('etag'),
        location: response.headers.get('location'),
      };
    },
    { method, pathname, headers: options.headers ?? {}, body: options.body },
  );

await execute(
  'UAT-11',
  'UI bloqueó tarjeta/cuotas inválidas; bypass API devolvió 422, limpió C4 y no produjo efectos.',
  ['EVD-E6-36/UAT-11', 'UI-UAT-11', 'HTTP-UAT-11'],
  () =>
    withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page, apiObservation }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await openPayment(page);
      await page.getByLabel('Número de tarjeta').fill('411');
      await page.getByLabel('Vencimiento').fill('01/20');
      await page.getByLabel('Código de seguridad').fill('1');
      await page.getByLabel('Nombre en la tarjeta').fill('X');
      await page.getByTestId('payment-tokenize').click();
      await expect(page.getByRole('alert')).toBeVisible();
      await expect(page.getByRole('alert')).toBeFocused();
      await expect(page.getByTestId('checkout-step-payment')).toBeVisible();
      check(transactionPosts() === 0, 'INVALID_PAYMENT_UI_POSTED');
      check(!(await browserProgressContainsForbiddenData(page)), 'INVALID_PAYMENT_UI_PERSISTED_C4');

      const session = new ApiSession();
      const ready = await prepareReady(session);
      safeProblem(
        await submitPrepared(session, ready, {
          idempotencyKey: 'idem-uat11-invalid-install01',
          body: { ...ready.body, installments: 4 },
        }),
        422,
        'FIELD_INVALID',
      );
      check((await getStock(session)).available === 1, 'INVALID_PAYMENT_CHANGED_STOCK');
      check(
        apiObservation.countLog('payment.dispatch_claimed') === 0,
        'INVALID_PAYMENT_DISPATCHED',
      );
    }),
);

await execute(
  'UAT-15',
  'Journey crítico preservó 202→APPROVED, stock y entrega en Chromium, Firefox y WebKit.',
  ['EVD-E6-36/UAT-15', 'UI-UAT-15-CHROMIUM', 'UI-UAT-15-FIREFOX', 'UI-UAT-15-WEBKIT'],
  async () => {
    const targets = await exactBrowserTargets();
    check(targets.map(({ id }) => id).join(',') === 'chromium,firefox,webkit', 'BROWSER_SET_DRIFT');
    await withWebPreview(async () => {
      for (const target of targets) {
        check(existsSync(target.browserType.executablePath()), 'BROWSER_BINARY_' + target.id);
        await runBrowserSession(
          {
            id: target.id,
            launch: () => target.browserType.launch({ headless: true }),
          },
          {
            FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
            FAKE_RECONCILE_INTERVAL_MS: '10',
            PRODUCT_INITIAL_STOCK: '1',
          },
          async ({ page, apiObservation }) => {
            const transactionPosts = countRequests(page, 'POST', '/transactions');
            await reachReview(page);
            await page.getByTestId('checkout-submit').click();
            await waitForUiState(page, 'transaction-approved');
            check(transactionPosts() === 1, 'BROWSER_PAYMENT_POST_COUNT_' + target.id);
            const progress = await readProgress(page);
            check(typeof progress.transactionId === 'string', 'BROWSER_TRANSACTION_' + target.id);
            const transaction = await browserJson(
              page,
              '/api/v1/transactions/' + progress.transactionId,
              200,
            );
            check(
              transaction.paymentStatus === 'APPROVED' &&
                transaction.reservationStatus === 'CONSUMED' &&
                typeof transaction.deliveryId === 'string',
              'BROWSER_SEMANTICS_' + target.id,
            );
            const stock = await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200);
            check(stock.available === 0, 'BROWSER_STOCK_' + target.id);
            check(
              apiObservation.countLog('payment.dispatch_claimed') === 1,
              'BROWSER_DISPATCH_' + target.id,
            );
            check(
              !(await browserProgressContainsForbiddenData(page)),
              'BROWSER_STORAGE_' + target.id,
            );
            await page.getByTestId('return-product').click();
            await expect(page.getByTestId('product-surface')).toBeVisible();
          },
        );
      }
    });
  },
);

await execute(
  'UAT-19',
  'Datos, entrega, aceptaciones y cuotas válidos llegaron a resumen sin reserva ni pago.',
  ['EVD-E6-36/UAT-19', 'UI-UAT-19'],
  () =>
    withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page, apiObservation }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await reachReview(page);
      check(transactionPosts() === 0, 'VALID_REVIEW_POSTED_PAYMENT');
      const progress = await readProgress(page);
      check(typeof progress.checkoutId === 'string', 'VALID_REVIEW_CHECKOUT_MISSING');
      const checkout = await browserJson(page, '/api/v1/checkouts/' + progress.checkoutId, 200);
      check(
        checkout.status === 'READY' && checkout.activeTransactionId === null,
        'VALID_REVIEW_SERVER_STATE',
      );
      check(
        (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 1,
        'VALID_REVIEW_STOCK',
      );
      check(apiObservation.countLog('payment.dispatch_claimed') === 0, 'VALID_REVIEW_DISPATCHED');
      check(!(await browserProgressContainsForbiddenData(page)), 'VALID_REVIEW_PERSISTED_C4');
    }),
);

await execute(
  'UAT-20',
  'Falta de una aceptación bloqueó UI y API con 422, sin reserva, pago ni entrega.',
  ['EVD-E6-36/UAT-20', 'UI-UAT-20', 'HTTP-UAT-20'],
  () =>
    withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page, apiObservation }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await openPayment(page);
      await fillCard(page);
      await fillCustomerDelivery(page);
      await page.getByTestId('customer-delivery-save').click();
      await expect(page.getByTestId('checkout-step-acceptances')).toBeVisible();
      await page.getByLabel(/términos y condiciones/iu).check();
      await page.getByTestId('acceptances-continue').click();
      await expect(page.getByRole('alert')).toBeVisible();
      await expect(page.getByRole('alert')).toBeFocused();
      await expect(page.getByTestId('checkout-step-acceptances')).toBeVisible();
      check(transactionPosts() === 0, 'MISSING_ACCEPTANCE_UI_POSTED');

      const session = new ApiSession();
      const ready = await prepareReady(session);
      safeProblem(
        await submitPrepared(session, ready, {
          idempotencyKey: 'idem-uat20-missing-accept01',
          body: { ...ready.body, acceptances: acceptanceFixture() },
        }),
        422,
        'FIELD_INVALID',
      );
      check((await getStock(session)).available === 1, 'MISSING_ACCEPTANCE_STOCK');
      check(
        apiObservation.countLog('payment.dispatch_claimed') === 0,
        'MISSING_ACCEPTANCE_DISPATCHED',
      );
    }),
);

await execute(
  'UAT-25',
  'Refresh durante captura eliminó PAN/CVC/vencimiento y no creó transacción.',
  ['EVD-E6-36/UAT-25', 'UI-UAT-25'],
  () =>
    withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page, apiObservation }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await openPayment(page);
      await fillCard(page, { tokenize: false });
      await page.reload();
      await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
      await expect(page.getByLabel('Número de tarjeta')).toHaveValue('');
      await expect(page.getByLabel('Vencimiento')).toHaveValue('');
      await expect(page.getByLabel('Código de seguridad')).toHaveValue('');
      check(transactionPosts() === 0, 'CAPTURE_REFRESH_POSTED');
      check(!(await browserProgressContainsForbiddenData(page)), 'CAPTURE_REFRESH_PERSISTED_C4');
      check(
        (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 1,
        'CAPTURE_REFRESH_STOCK',
      );
      check(
        apiObservation.countLog('payment.dispatch_claimed') === 0,
        'CAPTURE_REFRESH_DISPATCHED',
      );
    }),
);

await execute(
  'UAT-26',
  'Refresh en resumen recuperó checkout/quote y exigió reingresar el método, sin create de pago.',
  ['EVD-E6-36/UAT-26', 'UI-UAT-26'],
  () =>
    withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page, apiObservation }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await reachReview(page);
      const before = await readProgress(page);
      check(typeof before.checkoutId === 'string', 'REVIEW_REFRESH_CHECKOUT_MISSING');
      const quoteBefore = (await browserJson(page, '/api/v1/checkouts/' + before.checkoutId, 200))
        .quote.quoteId;
      await page.reload();
      await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
      const after = await readProgress(page);
      check(after.checkoutId === before.checkoutId, 'REVIEW_REFRESH_CHECKOUT_DRIFT');
      const quoteAfter = (await browserJson(page, '/api/v1/checkouts/' + after.checkoutId, 200))
        .quote.quoteId;
      check(quoteAfter === quoteBefore, 'REVIEW_REFRESH_QUOTE_DRIFT');
      await expect(page.getByLabel('Número de tarjeta')).toHaveValue('');
      check(transactionPosts() === 0, 'REVIEW_REFRESH_POSTED');
      check(!(await browserProgressContainsForbiddenData(page)), 'REVIEW_REFRESH_PERSISTED_C4');
      check(apiObservation.countLog('payment.dispatch_claimed') === 0, 'REVIEW_REFRESH_DISPATCHED');
    }),
);

await execute(
  'UAT-27',
  'Refresh recuperó PENDING y final por GET, sin segundo POST ni efecto duplicado.',
  ['EVD-E6-36/UAT-27', 'UI-UAT-27', 'stage-5-smoke-results.json#SMK-E5-06'],
  async () => {
    await smokePassed('SMK-E5-06');
    await withChromiumUi(
      {
        FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
        FAKE_RECONCILE_INTERVAL_MS: '10',
        PRODUCT_INITIAL_STOCK: '1',
      },
      async ({ page, apiObservation }) => {
        const transactionPosts = countRequests(page, 'POST', '/transactions');
        await reachReview(page);
        await page.getByTestId('checkout-submit').click();
        await waitForUiState(page, 'transaction-approved');
        const before = await readProgress(page);
        check(typeof before.transactionId === 'string', 'FINAL_REFRESH_TRANSACTION_MISSING');
        await page.reload();
        await expect(page.getByTestId('transaction-approved')).toBeVisible({ timeout: 8_000 });
        const after = await readProgress(page);
        check(after.transactionId === before.transactionId, 'FINAL_REFRESH_TRANSACTION_DRIFT');
        check(transactionPosts() === 1, 'FINAL_REFRESH_DUPLICATED_POST');
        check(
          (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 0,
          'FINAL_REFRESH_STOCK',
        );
        check(
          apiObservation.countLog('payment.dispatch_claimed') === 1,
          'FINAL_REFRESH_DISPATCH_COUNT',
        );
      },
    );
  },
);

await execute(
  'UAT-36',
  'Modal cumplió foco inicial, trap, Escape/retorno, labels y errores enfocados.',
  ['EVD-E6-36/UAT-36', 'UI-UAT-36'],
  () =>
    withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page }) => {
      await openPayment(page);
      const dialog = page.getByTestId('checkout-dialog');
      await expect(dialog).toBeVisible();
      await expect(dialog.locator('#checkout-step-title')).toBeFocused();
      const focusable = dialog.locator(
        'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      const count = await focusable.count();
      check(count >= 2, 'MODAL_FOCUSABLES');
      await focusable.first().focus();
      await page.keyboard.press('Shift+Tab');
      await expect(focusable.nth(count - 1)).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(focusable.first()).toBeFocused();
      await page.keyboard.press('Escape');
      await expect(dialog).toBeHidden();
      await expect(page.getByTestId('product-checkout-cta')).toBeFocused();

      await page.getByTestId('product-checkout-cta').click();
      await expect(page.getByTestId('checkout-step-payment')).toBeVisible();
      await expect(page.getByLabel('Número de tarjeta')).toBeVisible();
      await expect(page.getByLabel('Vencimiento')).toBeVisible();
      await expect(page.getByLabel('Código de seguridad')).toBeVisible();
      await page.getByTestId('payment-tokenize').click();
      await expect(page.getByRole('alert')).toBeVisible();
      await expect(page.getByRole('alert')).toBeFocused();
      check((await page.locator('.field-error').count()) >= 4, 'MODAL_FIELD_ERRORS');
    }),
);

await execute(
  'UAT-44',
  'Cliente/delivery inválidos fueron bloqueados por UI/API 422 sin persistir PII ni efectos.',
  ['EVD-E6-36/UAT-44', 'UI-UAT-44', 'HTTP-UAT-44'],
  async () => {
    await withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page, apiObservation }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await openPayment(page);
      await fillCard(page);
      await page.getByLabel('Nombre completo').fill('X');
      await page.getByLabel('Correo electrónico').fill('not-an-email');
      await page.getByLabel('Teléfono').fill('bad');
      await page.getByLabel('Dirección', { exact: true }).fill('X');
      await page.getByLabel('Ciudad').fill('X');
      await page.getByLabel('Departamento o región').fill('X');
      await page.getByLabel('Código postal (opcional)').fill('!');
      await page.getByTestId('customer-delivery-save').click();
      await expect(page.getByRole('alert')).toBeVisible();
      await expect(page.getByRole('alert')).toBeFocused();
      await expect(page.getByTestId('checkout-step-customer')).toBeVisible();
      check(transactionPosts() === 0, 'INVALID_DETAILS_UI_POSTED');
      check(!(await browserProgressContainsForbiddenData(page)), 'INVALID_DETAILS_UI_PERSISTED');
      check(
        (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 1,
        'INVALID_DETAILS_UI_STOCK',
      );
      check(
        apiObservation.countLog('payment.dispatch_claimed') === 0,
        'INVALID_DETAILS_UI_DISPATCH',
      );
    });
    await verifyInvalidCustomerAndDelivery();
  },
);
// UAT_UI_PROBES

await execute(
  'UAT-18',
  'Ejecutar seed dos veces conservó un único producto y exactamente el mismo stock.',
  ['EVD-E6-36/UAT-18', 'FIXTURE-UAT-18', 'HTTP-UAT-18'],
  () =>
    withFixtureApi({ providerStatus: 'PENDING' }, async (controls) => {
      const session = new ApiSession();
      const before = expectStatus(
        await session.request('GET', '/api/v1/products'),
        200,
        'SEED_BEFORE',
      );
      check(before.count === 1 && before.items[0]?.productId === PRODUCT_ID, 'SEED_BEFORE_COUNT');
      const stockBefore = await getStock(session);
      await controls.seedTwice();
      const after = expectStatus(
        await session.request('GET', '/api/v1/products'),
        200,
        'SEED_AFTER',
      );
      const stockAfter = await getStock(session);
      check(after.count === 1 && after.items[0]?.productId === PRODUCT_ID, 'SEED_DUPLICATED');
      check(
        stockAfter.onHand === stockBefore.onHand &&
          stockAfter.reserved === stockBefore.reserved &&
          stockAfter.available === stockBefore.available,
        'SEED_CHANGED_STOCK',
      );
      check(controls.providerCreateCalls() === 0, 'SEED_CALLED_PROVIDER');
    }),
);

await execute(
  'UAT-35',
  'APPROVED sin reserva física quedó en conflicto de integridad, sin consumo ni entrega.',
  ['EVD-E6-36/UAT-35', 'FIXTURE-UAT-35', 'HTTP-UAT-35', 'OBS-INCIDENT-UAT-35'],
  () =>
    withFixtureApi({ providerStatus: 'PENDING' }, async (controls) => {
      const session = new ApiSession();
      const ready = await prepareReady(session);
      const accepted = await submitPrepared(session, ready, {
        idempotencyKey: 'idem-uat35-no-reservation1',
      });
      expectStatus(accepted, 202, 'NO_RESERVATION_ACCEPTED');
      const pending = expectStatus(
        await getTransaction(session, accepted.body.transactionId),
        200,
        'NO_RESERVATION_PENDING',
      );
      check(
        pending.paymentStatus === 'PENDING' && pending.reservationStatus === 'ACTIVE',
        'NO_RESERVATION_PRECONDITION',
      );
      await controls.approveWithoutReservation(accepted.body.transactionId);
      const conflicted = expectStatus(
        await getTransaction(session, accepted.body.transactionId),
        200,
        'NO_RESERVATION_CONFLICT',
      );
      check(
        conflicted.paymentStatus === 'APPROVED' &&
          conflicted.integrityStatus === 'APPROVED_INVENTORY_CONFLICT' &&
          conflicted.recoveryCode === 'STATE_TRANSITION_CONFLICT' &&
          conflicted.deliveryId === undefined,
        'NO_RESERVATION_CONFLICT_STATE',
      );
      check((await getStock(session)).available === 1, 'NO_RESERVATION_CONSUMED_STOCK');
      check(controls.providerCreateCalls() === 1, 'NO_RESERVATION_PROVIDER_COUNT');
    }),
);

await execute(
  'UAT-40',
  'VOIDED con reserva activa liberó stock y no creó entrega.',
  ['EVD-E6-36/UAT-40', 'FIXTURE-UAT-40', 'HTTP-UAT-40'],
  () =>
    withFixtureApi({ providerStatus: 'VOIDED' }, async (controls) => {
      const session = new ApiSession();
      const ready = await prepareReady(session);
      const accepted = await submitPrepared(session, ready, {
        idempotencyKey: 'idem-uat40-voided-active01',
      });
      expectStatus(accepted, 202, 'VOIDED_ACCEPTED');
      const transaction = expectStatus(
        await getTransaction(session, accepted.body.transactionId),
        200,
        'VOIDED_GET',
      );
      check(
        transaction.paymentStatus === 'VOIDED' &&
          transaction.reservationStatus === 'RELEASED' &&
          transaction.integrityStatus === 'OK' &&
          transaction.deliveryId === undefined,
        'VOIDED_STATE',
      );
      check((await getStock(session)).available === 1, 'VOIDED_STOCK_NOT_RELEASED');
      check(controls.providerCreateCalls() === 1, 'VOIDED_PROVIDER_COUNT');
    }),
);

await execute(
  'UAT-41',
  'VOIDED posterior a consumo/entrega activó revisión manual y preservó ambos efectos.',
  ['EVD-E6-36/UAT-41', 'FIXTURE-UAT-41', 'HTTP-UAT-41', 'OBS-INCIDENT-UAT-41'],
  () =>
    withFixtureApi({ providerStatus: 'APPROVED' }, async (controls) => {
      const session = new ApiSession();
      const ready = await prepareReady(session);
      const accepted = await submitPrepared(session, ready, {
        idempotencyKey: 'idem-uat41-void-after-paid1',
      });
      expectStatus(accepted, 202, 'VOID_AFTER_PAID_ACCEPTED');
      const approved = expectStatus(
        await getTransaction(session, accepted.body.transactionId),
        200,
        'VOID_AFTER_PAID_APPROVED',
      );
      check(
        approved.paymentStatus === 'APPROVED' &&
          approved.reservationStatus === 'CONSUMED' &&
          typeof approved.deliveryId === 'string',
        'VOID_AFTER_PAID_PRECONDITION',
      );
      const deliveryId = approved.deliveryId;
      await controls.injectConflictingFinal(accepted.body.transactionId, 'VOIDED');
      const conflicted = expectStatus(
        await getTransaction(session, accepted.body.transactionId),
        200,
        'VOID_AFTER_PAID_CONFLICT',
      );
      check(
        conflicted.paymentStatus === 'APPROVED' &&
          conflicted.integrityStatus === 'FINAL_STATE_CONFLICT' &&
          conflicted.reservationStatus === 'CONSUMED' &&
          conflicted.deliveryId === deliveryId,
        'VOID_AFTER_PAID_STATE',
      );
      expectStatus(
        await session.request('GET', '/api/v1/deliveries/' + deliveryId),
        200,
        'VOID_AFTER_PAID_DELIVERY',
      );
      check((await getStock(session)).available === 0, 'VOID_AFTER_PAID_RESTOCKED');
      check(controls.providerCreateCalls() === 1, 'VOID_AFTER_PAID_PROVIDER_COUNT');
    }),
);

await execute(
  'UAT-42',
  'Final incompatible preservó el primer VOIDED/liberación y no aplicó efectos adicionales.',
  ['EVD-E6-36/UAT-42', 'FIXTURE-UAT-42', 'HTTP-UAT-42'],
  () =>
    withFixtureApi({ providerStatus: 'VOIDED' }, async (controls) => {
      const session = new ApiSession();
      const ready = await prepareReady(session);
      const accepted = await submitPrepared(session, ready, {
        idempotencyKey: 'idem-uat42-final-conflict01',
      });
      expectStatus(accepted, 202, 'FINAL_CONFLICT_ACCEPTED');
      const first = expectStatus(
        await getTransaction(session, accepted.body.transactionId),
        200,
        'FINAL_CONFLICT_FIRST',
      );
      check(
        first.paymentStatus === 'VOIDED' && first.reservationStatus === 'RELEASED',
        'FINAL_CONFLICT_PRECONDITION',
      );
      await controls.injectConflictingFinal(accepted.body.transactionId, 'APPROVED');
      const conflicted = expectStatus(
        await getTransaction(session, accepted.body.transactionId),
        200,
        'FINAL_CONFLICT_GET',
      );
      check(
        conflicted.paymentStatus === 'VOIDED' &&
          conflicted.integrityStatus === 'FINAL_STATE_CONFLICT' &&
          conflicted.reservationStatus === 'RELEASED' &&
          conflicted.deliveryId === undefined,
        'FINAL_CONFLICT_STATE',
      );
      check((await getStock(session)).available === 1, 'FINAL_CONFLICT_EFFECT');
      check(controls.providerCreateCalls() === 1, 'FINAL_CONFLICT_PROVIDER_COUNT');
    }),
);

await execute(
  'UAT-47',
  'Excepción interna pre-I/O devolvió 500 seguro y dejó stock/proveedor intactos.',
  ['EVD-E6-36/UAT-47', 'FIXTURE-UAT-47', 'HTTP-UAT-47'],
  () =>
    withFixtureApi({ providerStatus: 'PENDING', catalogFailure: true }, async (controls) => {
      const session = new ApiSession();
      controls.setCatalogFindFailure(true);
      const failed = await session.request('POST', '/api/v1/checkouts', {
        body: { productId: PRODUCT_ID },
      });
      safeProblem(failed, 500, 'INTERNAL_ERROR');
      controls.setCatalogFindFailure(false);
      check((await getStock(session)).available === 1, 'INTERNAL_ERROR_CHANGED_STOCK');
      check(controls.providerCreateCalls() === 0, 'INTERNAL_ERROR_CALLED_PROVIDER');
    }),
);
const verifyPrivacySurfaces = async () => {
  const security = await stage6Evidence('security');
  check(security.status === 'PASS_LOCAL', 'PRIVACY_SECURITY_NOT_GREEN');
  check(
    [...security.staticChecks, ...security.applicationChecks].every(
      ({ status }) => status === 'PASS',
    ),
    'PRIVACY_SECURITY_CHECK_FAILED',
  );
  check(security.sensitiveValuesCaptured === 0, 'PRIVACY_SECURITY_CAPTURED_VALUE');

  await withChromiumUi(
    {
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
      FAKE_RECONCILE_INTERVAL_MS: '10',
      PRODUCT_INITIAL_STOCK: '1',
    },
    async ({ page, apiObservation }) => {
      let paymentRequest;
      page.on('request', (request) => {
        if (
          request.method() === 'POST' &&
          new URL(request.url()).pathname.endsWith('/transactions')
        ) {
          paymentRequest = request.postDataJSON();
        }
      });
      await openPayment(page);
      const card = await fillCard(page);
      await fillCustomerDelivery(page);
      await page.getByTestId('customer-delivery-save').click();
      await expect(page.getByTestId('checkout-step-acceptances')).toBeVisible();
      await page.getByLabel(/términos y condiciones/iu).check();
      await page.getByLabel(/tratamiento de mis datos personales/iu).check();
      await page.getByTestId('acceptances-continue').click();
      await expect(page.getByTestId('checkout-step-review')).toBeVisible();
      await page.getByTestId('checkout-submit').click();
      await waitForUiState(page, 'transaction-approved');

      check(
        typeof paymentRequest?.paymentMethodToken === 'string',
        'PRIVACY_TOKEN_NOT_TRANSPORTED',
      );
      const token = paymentRequest.paymentMethodToken;
      const requestText = JSON.stringify(paymentRequest);
      const requestScalarValues = [];
      const collectRequestScalars = (value) => {
        if (Array.isArray(value)) {
          for (const item of value) collectRequestScalars(item);
        } else if (value !== null && typeof value === 'object') {
          for (const item of Object.values(value)) collectRequestScalars(item);
        } else if (value !== undefined) {
          requestScalarValues.push(String(value));
        }
      };
      collectRequestScalars(paymentRequest);
      check(
        !requestScalarValues.includes(card.number) &&
          !requestScalarValues.includes(card.expiry) &&
          !requestScalarValues.includes(card.securityCode) &&
          !/securityCode|cardNumber|expiry|cvc/iu.test(requestText),
        'PRIVACY_RAW_CARD_IN_REQUEST',
      );

      const progress = await readProgress(page);
      check(typeof progress.transactionId === 'string', 'PRIVACY_TRANSACTION_MISSING');
      const transaction = await browserJson(
        page,
        '/api/v1/transactions/' + progress.transactionId,
        200,
      );
      check(
        privacyStateIsSafe(transaction, {
          exactValues: [card.expiry, card.securityCode],
          substringValues: [token, card.number],
        }),
        'PRIVACY_PUBLIC_STATE_LEAK',
      );
      const browserState = await page.evaluate(async () => {
        const databases =
          typeof globalThis.indexedDB?.databases === 'function'
            ? await globalThis.indexedDB.databases()
            : [];
        return {
          localStorage: { ...globalThis.localStorage },
          sessionStorage: { ...globalThis.sessionStorage },
          historyState: globalThis.history.state,
          databases: databases.map(({ name, version }) => ({ name, version })),
        };
      });
      check(
        privacyStateIsSafe(browserState, {
          exactValues: [card.expiry, card.securityCode],
          substringValues: [token, card.number],
        }),
        'PRIVACY_BROWSER_PERSISTENCE_LEAK',
      );
      check(!(await browserProgressContainsForbiddenData(page)), 'PRIVACY_PROGRESS_LEAK');
      check(
        !apiObservation.outputContains(token) && !apiObservation.outputContains(card.number),
        'PRIVACY_LOG_LEAK',
      );
      check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'PRIVACY_DISPATCH_COUNT');
    },
  );
};

await execute(
  'UAT-12',
  'Siete viewports quedaron sin overflow; imagen, LCP y CLS cumplieron presupuesto local.',
  ['EVD-E6-36/UAT-12', 'stage-6/compatibility.json', 'stage-6/performance.json'],
  async () => {
    const [compatibility, performanceEvidence] = await Promise.all([
      stage6Evidence('compatibility'),
      stage6Evidence('performance'),
    ]);
    check(compatibility.status === 'PASS', 'RESPONSIVE_MATRIX_NOT_PASS');
    check(compatibility.requiredViewports.length === 7, 'RESPONSIVE_VIEWPORT_COUNT');
    check(
      compatibility.results.length === 3 &&
        compatibility.results.every(
          (engine) =>
            engine.status === 'PASS' &&
            engine.viewports.length === 7 &&
            engine.viewports.every(
              (viewport) =>
                viewport.status === 'PASS' &&
                viewport.horizontalOverflowPx === 0 &&
                viewport.blockedExternalRequests === 0,
            ),
        ),
      'RESPONSIVE_ENGINE_MATRIX',
    );
    check(performanceEvidence.status === 'PASS', 'PERFORMANCE_NOT_PASS');
    check(performanceEvidence.assetCheck.status === 'PASS', 'PERFORMANCE_IMAGE_BUDGET');
    check(
      performanceEvidence.browserLab.status === 'PASS_BROWSER_LAB_EQUIVALENT' &&
        performanceEvidence.browserLab.metrics.lcpMs < 2_500 &&
        performanceEvidence.browserLab.metrics.cls < 0.1,
      'PERFORMANCE_BROWSER_BUDGET',
    );
    check(
      performanceEvidence.lighthouse.status === 'PASS' &&
        performanceEvidence.lighthouse.assertions.status === 'PASS',
      'PERFORMANCE_LIGHTHOUSE_MATRIX',
    );
  },
);

await execute(
  'UAT-13',
  'Persistencia, bundle/historial, respuestas y logs conservaron cero C3/C4 prohibidos.',
  ['EVD-E6-36/UAT-13', 'UI-PRIVACY-UAT-13', 'stage-6/security.json'],
  verifyPrivacySurfaces,
);

await execute(
  'UAT-14',
  'Fixtures locales rechazaron firma inválida y deduplicaron duplicado/fuera de orden 3/3.',
  ['EVD-E6-36/UAT-14', 'stage-6/integrity.json#uat14'],
  async () => {
    const integrity = await stage6Evidence('integrity');
    check(
      integrity.status === 'PASS' &&
        integrity.uat14Total === 3 &&
        integrity.uat14Passed === 3 &&
        integrity.uat14.every(({ status }) => status === 'PASS'),
      'UAT14_FIXTURE_MATRIX',
    );
  },
  'LOCAL_INTEGRATION_FIXTURE_UAT',
);

const uat16EvidenceIds = [
  'EVD-E6-36/UAT-16',
  'stage-6/accessibility.json#manualEvidence',
  'EVD-E6-28/A11Y-MAN-01..04',
];
let uat16Accessibility;
let uat16LoadFailure;
try {
  uat16Accessibility = await stage6Evidence('accessibility');
} catch (error) {
  uat16LoadFailure = error;
}
const uat16Decision =
  uat16LoadFailure === undefined
    ? manualUat16Decision(uat16Accessibility, {
        commitSha: CANDIDATE.commitSha,
        runId: RUN_ID,
      })
    : 'FAIL';
if (uat16Decision === 'NOT_RUN_MANUAL_REQUIRED') {
  omit(
    'UAT-16',
    'NOT_RUN_MANUAL_REQUIRED',
    'Evidencia manual v2 aún no fue aportada; no se infiere PASS desde axe o tests automatizados.',
    uat16EvidenceIds,
  );
} else {
  await execute(
    'UAT-16',
    'Evidencia manual v2 externa verificó 4/4 casos, 17/17 checks y todos los axe incomplete del mismo commit/campaña.',
    uat16EvidenceIds,
    async () => {
      if (uat16LoadFailure !== undefined) throw uat16LoadFailure;
      check(uat16Decision === 'PASS', 'UAT16_MANUAL_EVIDENCE_INVALID');
    },
    'INDEPENDENT_MANUAL_EVIDENCE_REVIEWER',
  );
}

await execute(
  'UAT-29',
  'PAN/CVC/vencimiento/token/secretos persistidos en storage, historial, respuesta y logs = 0.',
  ['EVD-E6-36/UAT-29', 'UI-PRIVACY-UAT-29', 'stage-6/security.json'],
  verifyPrivacySurfaces,
);

await execute(
  'UAT-31',
  'Resultado aprobado y CTA retornaron al producto con stock actualizado.',
  ['EVD-E6-36/UAT-31', 'stage-5-smoke-results.json#SMK-E5-01'],
  () => smokePassed('SMK-E5-01'),
);

const uat33EvidenceIds = ['EVD-E6-36/UAT-33', 'AUTH-E6-01', 'EXTERNAL_VERSIONED_JSON'];
if (UAT33_DECISION === 'NOT_RUN_AUTH_REQUIRED') {
  omit(
    'UAT-33',
    'NOT_RUN_AUTH_REQUIRED',
    'AUTH-E6-01 o evidencia externa v1 del target propio no fue aportada; no se infiere PASS.',
    uat33EvidenceIds,
  );
} else {
  await execute(
    'UAT-33',
    'Evidencia externa v1 del mismo commit verificó target propio efímero: HTTP redirect, HTTPS 200 y mixed-content 0; sólo se conservaron hashes.',
    uat33EvidenceIds,
    async () => {
      check(UAT33_DECISION === 'PASS', 'UAT33_EXTERNAL_EVIDENCE_INVALID');
      check(
        validateExternalEvidenceSummary(EXTERNAL_EVIDENCE, EXTERNAL_EXECUTION),
        'UAT33_EXTERNAL_SUMMARY_INVALID',
      );
      const capability = EXTERNAL_EVIDENCE.capabilities.ownedTarget;
      check(capability.authorization.id === 'AUTH-E6-01', 'UAT33_AUTHORIZATION_INVALID');
      check(capability.target.production === false, 'UAT33_PRODUCTION_TARGET_FORBIDDEN');
      check(
        capability.checks.every(({ status }) => status === 'PASS'),
        'UAT33_CHECK_FAILED',
      );
      check(capability.requests.outsideAllowlist === 0, 'UAT33_OUTSIDE_ALLOWLIST');
    },
    'INDEPENDENT_EXTERNAL_EVIDENCE_REVIEWER',
  );
}

await execute(
  'UAT-43',
  'Replay/concurrencia de finalización conservó un consumo y exactamente una entrega.',
  ['EVD-E6-36/UAT-43', 'stage-5-smoke-results.json#SMK-E5-12'],
  () => smokePassed('SMK-E5-12'),
);
// UAT_NONFUNCTIONAL

const requirePass = (...ids) => {
  for (const id of ids) {
    check(results.get(id)?.status === 'PASS', 'AGGREGATE_DEPENDENCY_' + id);
  }
};

await execute(
  'UAT-09',
  'Refresh en captura, resumen, PENDING y final recuperó canónico sin C4/token ni segundo POST.',
  ['EVD-E6-36/UAT-09', 'UI-UAT-25', 'UI-UAT-26', 'UI-UAT-27'],
  () => requirePass('UAT-25', 'UAT-26', 'UAT-27'),
  'BLACK_BOX_UAT_AGGREGATOR_OVER_EXECUTED_ATOMICS',
);

await execute(
  'UAT-10',
  'Missing, stock cero y quote stale devolvieron 404/409/409 sin efectos.',
  ['EVD-E6-36/UAT-10', 'HTTP-UAT-37', 'HTTP-UAT-38', 'HTTP-UAT-39'],
  () => requirePass('UAT-37', 'UAT-38', 'UAT-39'),
  'BLACK_BOX_UAT_AGGREGATOR_OVER_EXECUTED_ATOMICS',
);

const negativeE2e = [];
const negativeMapping = (kind, sourceCaseIds, rationale) => ({
  kind,
  sourceCaseIds,
  exactOracle: true,
  rationale,
});
const recordNegativeE2e = async ({
  id,
  canonicalScenario,
  mapping,
  observableResult,
  evidenceIds,
  probeType,
  run,
}) => {
  const startedAt = Date.now();
  const executedAtUtc = now();
  try {
    await run();
    negativeE2e.push({
      id,
      canonicalScenario,
      status: 'PASS',
      verificationLayer: 'BLACK_BOX_PUBLIC_HTTP_UI',
      probeType,
      mapping,
      observableResult,
      actualResult: observableResult,
      defect: 'N/A',
      runnerRole: 'INDEPENDENT_NEGATIVE_E2E_RUNNER',
      runnerPersona: 'QA_INDEPENDENT_BLACK_BOX_RUNNER',
      runId: RUN_ID,
      executedAtUtc,
      commitSha: CANDIDATE.commitSha,
      evidence: evidenceIds,
      evidenceIds,
      durationMs: Date.now() - startedAt,
    });
  } catch (error) {
    const failure = safeFailure(error);
    negativeE2e.push({
      id,
      canonicalScenario,
      status: 'FAIL',
      verificationLayer: 'BLACK_BOX_PUBLIC_HTTP_UI',
      probeType,
      mapping,
      observableResult: 'No cumplió el oráculo: ' + failure.code,
      actualResult: 'FAIL: ' + failure.code,
      failureCode: failure.code,
      failureCategory: failure.category,
      defect: 'DEF-E6-' + id,
      runnerRole: 'INDEPENDENT_NEGATIVE_E2E_RUNNER',
      runnerPersona: 'QA_INDEPENDENT_BLACK_BOX_RUNNER',
      runId: RUN_ID,
      executedAtUtc,
      commitSha: CANDIDATE.commitSha,
      evidence: evidenceIds,
      evidenceIds,
      durationMs: Date.now() - startedAt,
    });
  }
};
const reuseExactNegativeE2e = ({
  id,
  canonicalScenario,
  sourceCaseIds,
  rationale,
  observableResult,
  evidenceIds,
}) =>
  recordNegativeE2e({
    id,
    canonicalScenario,
    mapping: negativeMapping('EXACT_EXECUTED_BLACK_BOX_REUSE', sourceCaseIds, rationale),
    observableResult,
    evidenceIds,
    probeType: 'REUSED_EXACT_BLACK_BOX_UAT_SMOKE',
    run: () => requirePass(...sourceCaseIds),
  });

await reuseExactNegativeE2e({
  id: 'E2E-E6-13',
  canonicalScenario: 'Manipulación del total en DevTools',
  sourceCaseIds: ['UAT-07'],
  rationale:
    'UAT-07 envía total manipulado por HTTP público y observa 422, stock intacto y cero dispatch.',
  observableResult: 'Total aportado por cliente fue rechazado por 422 sin reserva ni pago.',
  evidenceIds: ['NEG-E2E-E6-13', 'UAT-07', 'HTTP-UAT-07'],
});
await reuseExactNegativeE2e({
  id: 'E2E-E6-14',
  canonicalScenario: 'Idempotency key igual con payload distinto',
  sourceCaseIds: ['UAT-05'],
  rationale:
    'UAT-05 reusa la misma key con semántica distinta por HTTP público y observa 409 sin efecto adicional.',
  observableResult:
    'Misma key con payload distinto produjo conflicto y preservó el intento original.',
  evidenceIds: ['NEG-E2E-E6-14', 'UAT-05', 'HTTP-UAT-05'],
});
await reuseExactNegativeE2e({
  id: 'E2E-E6-15',
  canonicalScenario: 'Token de sesión ajeno/expirado',
  sourceCaseIds: ['UAT-17', 'UAT-28'],
  rationale:
    'UAT-17 observa capability ajena por 404 y UAT-28 observa la sesión expirada por 410, ambos por HTTP público.',
  observableResult:
    'Capability ajena quedó oculta por 404 y la sesión vencida devolvió 410 sin mutación.',
  evidenceIds: ['NEG-E2E-E6-15', 'UAT-17', 'UAT-28', 'HTTP-UAT-17', 'HTTP-UAT-28'],
});
await reuseExactNegativeE2e({
  id: 'E2E-E6-16',
  canonicalScenario: 'Stock cambia entre quote y pago',
  sourceCaseIds: ['UAT-06'],
  rationale:
    'UAT-06 ejecuta dos compradores ya cotizados sobre la última unidad y observa un ganador, un 409 y stock no negativo.',
  observableResult: 'Cambio concurrente de stock entre quote y pago impidió oversell.',
  evidenceIds: ['NEG-E2E-E6-16', 'UAT-06', 'stage-5-smoke-results.json#SMK-E5-08'],
});
await reuseExactNegativeE2e({
  id: 'E2E-E6-17',
  canonicalScenario: 'Respuesta final fuera de orden',
  sourceCaseIds: ['UAT-42'],
  rationale:
    'UAT-42 inyecta un final público incompatible posterior y observa que no regresa el primer final ni repite efectos.',
  observableResult:
    'Final tardío incompatible quedó en conflicto y no revirtió ni duplicó efectos.',
  evidenceIds: ['NEG-E2E-E6-17', 'UAT-42', 'FIXTURE-UAT-42', 'HTTP-UAT-42'],
});

await recordNegativeE2e({
  id: 'E2E-E6-18',
  canonicalScenario: 'Usuario vuelve atrás durante pending',
  mapping: negativeMapping(
    'DEDICATED_PUBLIC_UI_PROBE',
    [],
    'Navegación real back/reopen durante PENDING; no se sustituye por refresh ni test de componente.',
  ),
  observableResult:
    'Back volvió al producto y reabrir recuperó el mismo PENDING por GET, con un solo POST/dispatch.',
  evidenceIds: ['NEG-E2E-E6-18', 'UI-NEG-E6-18', 'HTTP-NEG-E6-18'],
  probeType: 'PLAYWRIGHT_CHROMIUM_PUBLIC_UI',
  run: () =>
    withChromiumUi(
      {
        FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
        FAKE_RECONCILE_INTERVAL_MS: '60000',
        PRODUCT_INITIAL_STOCK: '1',
      },
      async ({ page, apiObservation }) => {
        const transactionPosts = countRequests(page, 'POST', '/transactions');
        await reachReview(page);
        await page.getByTestId('checkout-submit').click();
        await waitForUiState(page, 'transaction-pending');
        const before = await readProgress(page);
        check(typeof before.transactionId === 'string', 'NEG18_TRANSACTION_MISSING');
        await page.goBack();
        await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
        await page.getByTestId('product-checkout-cta').click();
        await waitForUiState(page, 'transaction-pending');
        const after = await readProgress(page);
        check(after.transactionId === before.transactionId, 'NEG18_TRANSACTION_DRIFT');
        check(transactionPosts() === 1, 'NEG18_DUPLICATE_POST');
        const transaction = await browserJson(
          page,
          '/api/v1/transactions/' + before.transactionId,
          200,
        );
        check(
          transaction.paymentStatus === 'PENDING' && transaction.reservationStatus === 'ACTIVE',
          'NEG18_PENDING_STATE',
        );
        check(
          (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 0,
          'NEG18_STOCK',
        );
        check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'NEG18_DISPATCH');
      },
    ),
});

await recordNegativeE2e({
  id: 'E2E-E6-19',
  canonicalScenario: 'Dos pestañas intentan pagar la misma sesión',
  mapping: negativeMapping(
    'DEDICATED_TWO_TAB_PUBLIC_HTTP_PROBE',
    [],
    'Dos Pages del mismo BrowserContext comparten capability de sesión y ejecutan POST públicos concurrentes.',
  ),
  observableResult:
    'Dos pestañas recibieron el mismo transactionId y dejaron una transacción activa, una reserva y un dispatch.',
  evidenceIds: ['NEG-E2E-E6-19', 'BROWSER-TABS-NEG-E6-19', 'HTTP-NEG-E6-19'],
  probeType: 'PLAYWRIGHT_TWO_TABS_PUBLIC_HTTP',
  run: () =>
    withWebPreview(() =>
      runBrowserSession(
        chromiumTarget,
        {
          FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
          FAKE_RECONCILE_INTERVAL_MS: '60000',
          PRODUCT_INITIAL_STOCK: '1',
        },
        async ({ page, context, apiObservation, network }) => {
          await page.goto(WEB_ORIGIN + '/products/' + PRODUCT_ID);
          await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
          const created = await browserRequest(page, 'POST', '/api/v1/checkouts', {
            body: { productId: PRODUCT_ID },
          });
          check(
            created.status === 201 && typeof created.body?.checkoutId === 'string',
            'NEG19_CREATE',
          );
          const checkoutId = created.body.checkoutId;
          const customer = await browserRequest(
            page,
            'PUT',
            '/api/v1/checkouts/' + checkoutId + '/customer',
            {
              headers: { 'If-Match': created.etag },
              body: {
                fullName: 'Persona Sintetica',
                email: 'uat@example.invalid',
                phone: '+573001112233',
              },
            },
          );
          check(customer.status === 200, 'NEG19_CUSTOMER');
          const delivery = await browserRequest(
            page,
            'PUT',
            '/api/v1/checkouts/' + checkoutId + '/delivery-details',
            {
              headers: { 'If-Match': customer.etag },
              body: {
                addressLine1: 'Calle Sintetica 1',
                city: 'Bogota',
                region: 'Cundinamarca',
                postalCode: '110111',
              },
            },
          );
          check(delivery.status === 200, 'NEG19_DELIVERY');
          const configuration = await browserRequest(page, 'GET', '/api/v1/payment-configuration');
          check(configuration.status === 200, 'NEG19_CONFIGURATION');
          const terms = configuration.body.acceptanceContracts.find(({ type }) => type === 'TERMS');
          const personal = configuration.body.acceptanceContracts.find(
            ({ type }) => type === 'PERSONAL_DATA',
          );
          check(terms !== undefined && personal !== undefined, 'NEG19_ACCEPTANCES');
          const paymentBody = {
            quoteId: created.body.quote.quoteId,
            paymentMethodToken: 'tok_fake_negative_multitab_0001',
            installments: 1,
            acceptances: {
              termsAcceptanceToken: terms.acceptanceToken,
              personalDataAcceptanceToken: personal.acceptanceToken,
            },
          };
          const paymentHeaders = {
            'Idempotency-Key': 'idem-negative-two-tabs-0001',
            'If-Match': delivery.etag,
          };
          const sharedCapability = network.capability();
          check(typeof sharedCapability === 'string', 'NEG19_CAPABILITY');
          const secondPage = await context.newPage();
          const secondNetwork = await installCapabilityBridge(secondPage, {
            initialCapability: sharedCapability,
          });
          try {
            await secondPage.goto(WEB_ORIGIN + '/products/' + PRODUCT_ID);
            await expect(secondPage.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
            const [firstSubmission, secondSubmission] = await Promise.all([
              browserRequest(page, 'POST', '/api/v1/checkouts/' + checkoutId + '/transactions', {
                headers: paymentHeaders,
                body: paymentBody,
              }),
              browserRequest(
                secondPage,
                'POST',
                '/api/v1/checkouts/' + checkoutId + '/transactions',
                { headers: paymentHeaders, body: paymentBody },
              ),
            ]);
            check(
              firstSubmission.status === 202 && secondSubmission.status === 202,
              'NEG19_ACCEPTED',
            );
            check(
              firstSubmission.body.transactionId === secondSubmission.body.transactionId,
              'NEG19_TRANSACTION_DRIFT',
            );
            const transactionId = firstSubmission.body.transactionId;
            const checkout = await browserRequest(page, 'GET', '/api/v1/checkouts/' + checkoutId);
            check(
              checkout.status === 200 && checkout.body.activeTransactionId === transactionId,
              'NEG19_ACTIVE_TRANSACTION',
            );
            const transaction = await browserRequest(
              page,
              'GET',
              '/api/v1/transactions/' + transactionId,
            );
            check(
              transaction.status === 200 &&
                transaction.body.paymentStatus === 'PENDING' &&
                transaction.body.reservationStatus === 'ACTIVE',
              'NEG19_PENDING_STATE',
            );
            check(
              (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 0,
              'NEG19_STOCK',
            );
            await delay(50);
            check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'NEG19_DISPATCH');
          } finally {
            try {
              await secondNetwork.dispose();
            } finally {
              await secondPage.close();
            }
            check(secondNetwork.externalRequests() === 0, 'NEG19_EXTERNAL_NETWORK');
            check(secondNetwork.lifecycleCancellations() <= 4, 'NEG19_LIFECYCLE');
          }
        },
      ),
    ),
});

let negative20ResponseLost = false;
await recordNegativeE2e({
  id: 'E2E-E6-20',
  canonicalScenario: 'Red se corta después de submit',
  mapping: negativeMapping(
    'DEDICATED_POST_COMMIT_RESPONSE_LOSS_PROBE',
    [],
    'El bridge completa el POST público en API y aborta sólo su respuesta antes de entregarla a la UI.',
  ),
  observableResult:
    'Respuesta 202 se perdió tras commit; UI reconcilió por GET sin repetir POST ni dispatch.',
  evidenceIds: ['NEG-E2E-E6-20', 'UI-NEG-E6-20', 'HTTP-POSTCOMMIT-NEG-E6-20'],
  probeType: 'PLAYWRIGHT_POST_COMMIT_NETWORK_ABORT',
  run: () =>
    withChromiumUiBridge(
      {
        FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
        FAKE_RECONCILE_INTERVAL_MS: '10',
        PRODUCT_INITIAL_STOCK: '1',
      },
      {
        responsePolicy: ({ method, pathname, status }) => {
          if (
            !negative20ResponseLost &&
            method === 'POST' &&
            pathname.endsWith('/transactions') &&
            status === 202
          ) {
            negative20ResponseLost = true;
            return 'ABORT_AFTER_COMMIT';
          }
          return 'FULFILL';
        },
      },
      async ({ page, apiObservation }) => {
        const transactionPosts = countRequests(page, 'POST', '/transactions');
        await reachReview(page);
        await page.getByTestId('checkout-submit').click();
        await waitForUiState(page, 'transaction-approved');
        check(negative20ResponseLost, 'NEG20_RESPONSE_NOT_LOST');
        check(transactionPosts() === 1, 'NEG20_DUPLICATE_POST');
        const progress = await readProgress(page);
        check(typeof progress.transactionId === 'string', 'NEG20_TRANSACTION');
        const transaction = await browserJson(
          page,
          '/api/v1/transactions/' + progress.transactionId,
          200,
        );
        check(
          transaction.paymentStatus === 'APPROVED' &&
            transaction.reservationStatus === 'CONSUMED' &&
            typeof transaction.deliveryId === 'string',
          'NEG20_FINAL_STATE',
        );
        check(
          (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 0,
          'NEG20_STOCK',
        );
        check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'NEG20_DISPATCH');
      },
    ),
});

let negative21ApprovedObserved = false;
let negative21AllowRender = false;
await recordNegativeE2e({
  id: 'E2E-E6-21',
  canonicalScenario: 'Recarga después de aprobación antes de render final',
  mapping: negativeMapping(
    'DEDICATED_APPROVED_BEFORE_RENDER_RELOAD_PROBE',
    [],
    'La API pública devuelve APPROVED al bridge, se aborta antes del render y luego se recarga la ruta status.',
  ),
  observableResult:
    'Reload posterior a aprobación no renderizada recuperó el final canónico con un solo POST/efecto.',
  evidenceIds: ['NEG-E2E-E6-21', 'UI-NEG-E6-21', 'HTTP-NEG-E6-21'],
  probeType: 'PLAYWRIGHT_APPROVED_RESPONSE_ABORT_THEN_RELOAD',
  run: () =>
    withChromiumUiBridge(
      {
        FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
        FAKE_RECONCILE_INTERVAL_MS: '10',
        PRODUCT_INITIAL_STOCK: '1',
      },
      {
        responsePolicy: ({ method, pathname, responseJson }) => {
          if (
            method === 'GET' &&
            pathname.includes('/transactions/') &&
            responseJson?.paymentStatus === 'APPROVED'
          ) {
            negative21ApprovedObserved = true;
            if (!negative21AllowRender) return 'ABORT_AFTER_COMMIT';
          }
          return 'FULFILL';
        },
      },
      async ({ page, apiObservation }) => {
        const transactionPosts = countRequests(page, 'POST', '/transactions');
        await reachReview(page);
        await page.getByTestId('checkout-submit').click();
        for (let attempt = 0; attempt < 200 && !negative21ApprovedObserved; attempt += 1) {
          await delay(25);
        }
        check(negative21ApprovedObserved, 'NEG21_APPROVED_NOT_OBSERVED');
        check(
          (await page.getByTestId('transaction-approved').count()) === 0,
          'NEG21_RENDERED_EARLY',
        );
        negative21AllowRender = true;
        await page.reload();
        await waitForUiState(page, 'transaction-approved');
        check(transactionPosts() === 1, 'NEG21_DUPLICATE_POST');
        const progress = await readProgress(page);
        check(typeof progress.transactionId === 'string', 'NEG21_TRANSACTION');
        const transaction = await browserJson(
          page,
          '/api/v1/transactions/' + progress.transactionId,
          200,
        );
        check(
          transaction.paymentStatus === 'APPROVED' &&
            transaction.reservationStatus === 'CONSUMED' &&
            typeof transaction.deliveryId === 'string',
          'NEG21_FINAL_STATE',
        );
        check(
          (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 0,
          'NEG21_STOCK',
        );
        check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'NEG21_DISPATCH');
      },
    ),
});

let negative22RequestMutated = false;
let negative22Problem;
await recordNegativeE2e({
  id: 'E2E-E6-22',
  canonicalScenario: 'API devuelve error validado y UI preserva datos permitidos',
  mapping: negativeMapping(
    'DEDICATED_VALIDATION_ERROR_UI_PRESERVATION_PROBE',
    [],
    'Se altera una copia del PUT público tras validación de UI; API responde 422 real y se observa el formulario.',
  ),
  observableResult:
    'API 422 seguro no hizo eco del payload; UI conservó campos permitidos y limpió secretos al volver.',
  evidenceIds: ['NEG-E2E-E6-22', 'UI-NEG-E6-22', 'HTTP-422-NEG-E6-22'],
  probeType: 'PLAYWRIGHT_PUBLIC_REQUEST_MUTATION_AND_UI_ORACLE',
  run: () =>
    withChromiumUiBridge(
      { PRODUCT_INITIAL_STOCK: '1' },
      {
        requestOverride: ({ method, pathname, postDataJson }) => {
          if (
            !negative22RequestMutated &&
            method === 'PUT' &&
            pathname.endsWith('/customer') &&
            postDataJson !== undefined
          ) {
            negative22RequestMutated = true;
            return { postData: JSON.stringify({ ...postDataJson, fullName: 'X' }) };
          }
          return undefined;
        },
        responsePolicy: ({ method, pathname, status, responseJson }) => {
          if (method === 'PUT' && pathname.endsWith('/customer') && status === 422) {
            negative22Problem = { status, body: responseJson };
          }
          return 'FULFILL';
        },
      },
      async ({ page, apiObservation }) => {
        await openPayment(page);
        await fillCard(page);
        await fillCustomerDelivery(page);
        await page.getByTestId('customer-delivery-save').click();
        await expect(page.getByRole('alert')).toContainText('Conservamos el formulario', {
          timeout: 5_000,
        });
        check(negative22RequestMutated, 'NEG22_REQUEST_NOT_MUTATED');
        check(
          negative22Problem?.status === 422 && negative22Problem.body?.code === 'FIELD_INVALID',
          'NEG22_PROBLEM',
        );
        const serializedProblem = JSON.stringify(negative22Problem.body);
        check(
          !serializedProblem.includes('Persona Sintetica') &&
            !serializedProblem.includes('uat@example.invalid') &&
            !/stack|paymentMethodToken|securityCode|cardNumber|cvc/iu.test(serializedProblem),
          'NEG22_PROBLEM_ECHO',
        );
        await expect(page.getByLabel('Nombre completo')).toHaveValue('Persona Sintetica');
        await expect(page.getByLabel('Correo electrónico')).toHaveValue('uat@example.invalid');
        await expect(page.getByLabel('Dirección', { exact: true })).toHaveValue(
          'Calle Sintetica 1',
        );
        await page.getByRole('button', { name: 'Atrás' }).click();
        await expect(page.getByTestId('checkout-step-payment')).toBeVisible();
        await expect(page.getByLabel('Número de tarjeta')).toHaveValue('');
        check(
          (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 1,
          'NEG22_STOCK',
        );
        check(apiObservation.countLog('payment.dispatch_claimed') === 0, 'NEG22_DISPATCH');
      },
    ),
});

await reuseExactNegativeE2e({
  id: 'E2E-E6-23',
  canonicalScenario: 'Producto sin stock desde el inicio',
  sourceCaseIds: ['UAT-38'],
  rationale:
    'UAT-38 arranca API con stock cero y observa 409 al crear checkout, stock cero y ningún dispatch.',
  observableResult:
    'Producto inicialmente agotado impidió iniciar checkout y no llamó al proveedor.',
  evidenceIds: ['NEG-E2E-E6-23', 'UAT-38', 'HTTP-UAT-38'],
});

await recordNegativeE2e({
  id: 'E2E-E6-24',
  canonicalScenario: 'Cleanup/reintento de una sesión abandonada',
  mapping: negativeMapping(
    'DEDICATED_FAILED_SESSION_RESTART_PROBE',
    [],
    'Journey público declinado usa CTA de retry, verifica cleanup y abre un checkout nuevo sin segundo pago.',
  ),
  observableResult:
    'Sesión fallida liberó stock; retry limpió IDs y abrió checkout nuevo sin pago ciego.',
  evidenceIds: ['NEG-E2E-E6-24', 'UI-NEG-E6-24', 'HTTP-NEG-E6-24'],
  probeType: 'PLAYWRIGHT_FAILED_SESSION_CLEANUP_AND_RESTART',
  run: () =>
    withChromiumUi(
      {
        FAKE_PAYMENT_SCENARIO: 'FAKE-E5-02',
        FAKE_RECONCILE_INTERVAL_MS: '10',
        PRODUCT_INITIAL_STOCK: '1',
      },
      async ({ page, apiObservation }) => {
        const transactionPosts = countRequests(page, 'POST', '/transactions');
        await reachReview(page);
        await page.getByTestId('checkout-submit').click();
        await waitForUiState(page, 'transaction-declined');
        const failedProgress = await readProgress(page);
        check(
          typeof failedProgress.checkoutId === 'string' &&
            typeof failedProgress.transactionId === 'string',
          'NEG24_FAILED_PROGRESS',
        );
        const failedTransaction = await browserJson(
          page,
          '/api/v1/transactions/' + failedProgress.transactionId,
          200,
        );
        check(
          failedTransaction.paymentStatus === 'DECLINED' &&
            failedTransaction.reservationStatus === 'RELEASED' &&
            failedTransaction.deliveryId === undefined,
          'NEG24_FAILED_STATE',
        );
        await page.getByTestId('retry-payment').click();
        await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
        const cleared = await readProgress(page);
        check(
          cleared.checkoutId === undefined && cleared.transactionId === undefined,
          'NEG24_NOT_CLEARED',
        );
        await page.getByTestId('product-checkout-cta').click();
        await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
        const restarted = await readProgress(page);
        check(
          typeof restarted.checkoutId === 'string' &&
            restarted.checkoutId !== failedProgress.checkoutId,
          'NEG24_RESTART_ID',
        );
        check(transactionPosts() === 1, 'NEG24_BLIND_PAYMENT_RETRY');
        check(
          (await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200)).available === 1,
          'NEG24_STOCK',
        );
        check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'NEG24_DISPATCH');
      },
    ),
});

const REFRESH_PRODUCT_PATH = '/products/' + PRODUCT_ID;
const REFRESH_CAPTURE_PATH = REFRESH_PRODUCT_PATH + '/checkout';
const REFRESH_STATUS_PATH = REFRESH_CAPTURE_PATH + '/status';
const refreshRecovery = [];

const withReopenedPublicPage = async ({ context, network }, pathname, run) => {
  const capability = network.capability();
  check(typeof capability === 'string', 'REFRESH_REOPEN_CAPABILITY_MISSING');
  const reopenedPage = await context.newPage();
  const reopenedNetwork = await installCapabilityBridge(reopenedPage, {
    initialCapability: capability,
  });
  try {
    await reopenedPage.goto(WEB_ORIGIN + pathname);
    return await run(reopenedPage);
  } finally {
    let externalRequests;
    let lifecycleCancellations;
    try {
      await reopenedNetwork.dispose();
      externalRequests = reopenedNetwork.externalRequests();
      lifecycleCancellations = reopenedNetwork.lifecycleCancellations();
    } finally {
      await reopenedPage.close();
    }
    check(externalRequests === 0, 'REFRESH_REOPEN_EXTERNAL_NETWORK');
    check(lifecycleCancellations <= 4, 'REFRESH_REOPEN_LIFECYCLE_CANCELLATIONS');
  }
};

const recordRefreshRecovery = async (expected, run) => {
  const startedAt = Date.now();
  const networkBefore = observedExternalNetworkAttempts().total;
  try {
    await run();
    const externalNetworkAttempts = observedExternalNetworkAttempts().total - networkBefore;
    check(externalNetworkAttempts === 0, expected.id + '_EXTERNAL_NETWORK');
    const executedAtUtc = now();
    refreshRecovery.push({
      ...expected,
      status: 'PASS',
      verificationLayer: 'BLACK_BOX_PUBLIC_HTTP_UI',
      observableResult: expected.expectedResult,
      actualResult: expected.expectedResult,
      defect: 'N/A',
      runnerRole: 'INDEPENDENT_REFRESH_RECOVERY_RUNNER',
      runnerPersona: 'QA_INDEPENDENT_BLACK_BOX_RUNNER',
      runId: RUN_ID,
      commitSha: CANDIDATE.commitSha,
      environment: stage6Environment(),
      executionScope: 'LOCAL_LOOPBACK_FAKE_MEMORY_FIXTURES',
      executedAtUtc,
      evidence: expected.evidenceIds,
      externalNetworkAttempts,
      serverAuthorityObserved: true,
      duplicateEffectsObserved: 0,
      impossibleStatesObserved: 0,
      sensitiveValuesCaptured: 0,
      durationMs: Date.now() - startedAt,
    });
  } catch (error) {
    const failure = safeFailure(error);
    const executedAtUtc = now();
    refreshRecovery.push({
      ...expected,
      status: 'FAIL',
      verificationLayer: 'BLACK_BOX_PUBLIC_HTTP_UI',
      observableResult: 'No cumplió el oráculo: ' + failure.code,
      actualResult: 'FAIL: ' + failure.code,
      failureCode: failure.code,
      failureCategory: failure.category,
      defect: 'DEF-E6-03',
      runnerRole: 'INDEPENDENT_REFRESH_RECOVERY_RUNNER',
      runnerPersona: 'QA_INDEPENDENT_BLACK_BOX_RUNNER',
      runId: RUN_ID,
      commitSha: CANDIDATE.commitSha,
      environment: stage6Environment(),
      executionScope: 'LOCAL_LOOPBACK_FAKE_MEMORY_FIXTURES',
      executedAtUtc,
      evidence: expected.evidenceIds,
      externalNetworkAttempts: observedExternalNetworkAttempts().total - networkBefore,
      serverAuthorityObserved: false,
      duplicateEffectsObserved: null,
      impossibleStatesObserved: null,
      sensitiveValuesCaptured: 0,
      durationMs: Date.now() - startedAt,
    });
  }
};

await recordRefreshRecovery(REFRESH_RECOVERY_CONTRACT[0], () =>
  withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page, apiObservation }) => {
    const transactionPosts = countRequests(page, 'POST', '/transactions');
    await page.goto(WEB_ORIGIN + REFRESH_PRODUCT_PATH);
    await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
    await expect(page.getByText('1 unidades disponibles')).toBeVisible();
    const before = await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200);
    await page.reload();
    await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
    await expect(page.getByText('1 unidades disponibles')).toBeVisible();
    const after = await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200);
    const progress = await readProgress(page);
    check(before.available === 1 && after.available === 1, 'REFRESH01_STOCK_DRIFT');
    check(progress.checkoutId === undefined, 'REFRESH01_CREATED_CHECKOUT');
    check(transactionPosts() === 0, 'REFRESH01_PAYMENT_POST');
    check(apiObservation.countLog('payment.dispatch_claimed') === 0, 'REFRESH01_DISPATCH');
    check(!(await browserProgressContainsForbiddenData(page)), 'REFRESH01_SENSITIVE_STORAGE');
  }),
);

await recordRefreshRecovery(REFRESH_RECOVERY_CONTRACT[1], () =>
  withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page, apiObservation }) => {
    const transactionPosts = countRequests(page, 'POST', '/transactions');
    await openPayment(page);
    await fillCard(page, { tokenize: false });
    const before = await readProgress(page);
    check(typeof before.checkoutId === 'string', 'REFRESH02_CHECKOUT_MISSING');
    const checkoutBefore = await browserJson(page, '/api/v1/checkouts/' + before.checkoutId, 200);
    check(
      checkoutBefore.status === 'DRAFT' && checkoutBefore.activeTransactionId === null,
      'REFRESH02_SERVER_STATE_BEFORE',
    );
    await page.reload();
    await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
    await expect(page.getByLabel('Número de tarjeta')).toHaveValue('');
    await expect(page.getByLabel('Vencimiento')).toHaveValue('');
    await expect(page.getByLabel('Código de seguridad')).toHaveValue('');
    const after = await readProgress(page);
    const checkoutAfter = await browserJson(page, '/api/v1/checkouts/' + after.checkoutId, 200);
    check(after.checkoutId === before.checkoutId, 'REFRESH02_CHECKOUT_DRIFT');
    check(
      checkoutAfter.status === 'DRAFT' && checkoutAfter.activeTransactionId === null,
      'REFRESH02_SERVER_STATE_AFTER',
    );
    check(transactionPosts() === 0, 'REFRESH02_PAYMENT_POST');
    check(apiObservation.countLog('payment.dispatch_claimed') === 0, 'REFRESH02_DISPATCH');
    check(!(await browserProgressContainsForbiddenData(page)), 'REFRESH02_SENSITIVE_STORAGE');
  }),
);

await recordRefreshRecovery(REFRESH_RECOVERY_CONTRACT[2], () =>
  withChromiumUi({ PRODUCT_INITIAL_STOCK: '1' }, async ({ page, apiObservation }) => {
    const transactionPosts = countRequests(page, 'POST', '/transactions');
    await reachReview(page);
    const before = await readProgress(page);
    check(typeof before.checkoutId === 'string', 'REFRESH03_CHECKOUT_MISSING');
    const checkoutBefore = await browserJson(page, '/api/v1/checkouts/' + before.checkoutId, 200);
    check(
      checkoutBefore.status === 'READY' && checkoutBefore.activeTransactionId === null,
      'REFRESH03_SERVER_STATE_BEFORE',
    );
    await page.reload();
    await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
    await expect(page.getByLabel('Número de tarjeta')).toHaveValue('');
    const after = await readProgress(page);
    const checkoutAfter = await browserJson(page, '/api/v1/checkouts/' + after.checkoutId, 200);
    check(after.checkoutId === before.checkoutId, 'REFRESH03_CHECKOUT_DRIFT');
    check(checkoutAfter.quote.quoteId === checkoutBefore.quote.quoteId, 'REFRESH03_QUOTE_DRIFT');
    check(
      checkoutAfter.status === 'READY' && checkoutAfter.activeTransactionId === null,
      'REFRESH03_SERVER_STATE_AFTER',
    );
    check(transactionPosts() === 0, 'REFRESH03_PAYMENT_POST');
    check(apiObservation.countLog('payment.dispatch_claimed') === 0, 'REFRESH03_DISPATCH');
    check(!(await browserProgressContainsForbiddenData(page)), 'REFRESH03_SENSITIVE_STORAGE');
  }),
);

await recordRefreshRecovery(REFRESH_RECOVERY_CONTRACT[3], () =>
  withChromiumUi(
    { PRODUCT_INITIAL_STOCK: '1' },
    async ({ page, context, apiObservation, network }) => {
      let transactionPosts = 0;
      context.on('request', (request) => {
        if (
          request.method() === 'POST' &&
          new URL(request.url()).pathname.endsWith('/transactions')
        ) {
          transactionPosts += 1;
        }
      });
      await reachReview(page);
      await expect(page.getByTestId('checkout-submit')).toBeEnabled();
      const before = await readProgress(page);
      check(typeof before.checkoutId === 'string', 'REFRESH04_CHECKOUT_MISSING');
      await withReopenedPublicPage(
        { context, network },
        REFRESH_CAPTURE_PATH,
        async (reopenedPage) => {
          await expect(reopenedPage.getByTestId('checkout-step-payment')).toBeVisible({
            timeout: 5_000,
          });
          await expect(reopenedPage.getByLabel('Número de tarjeta')).toHaveValue('');
          const after = await readProgress(reopenedPage);
          const checkout = await browserJson(
            reopenedPage,
            '/api/v1/checkouts/' + after.checkoutId,
            200,
          );
          check(after.checkoutId === before.checkoutId, 'REFRESH04_CHECKOUT_DRIFT');
          check(
            checkout.status === 'READY' && checkout.activeTransactionId === null,
            'REFRESH04_SERVER_STATE',
          );
          check(
            !(await browserProgressContainsForbiddenData(reopenedPage)),
            'REFRESH04_SENSITIVE_STORAGE',
          );
        },
      );
      check(transactionPosts === 0, 'REFRESH04_PAYMENT_POST');
      check(apiObservation.countLog('payment.dispatch_claimed') === 0, 'REFRESH04_DISPATCH');
    },
  ),
);

await recordRefreshRecovery(REFRESH_RECOVERY_CONTRACT[4], () =>
  withChromiumUi(
    {
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
      FAKE_RECONCILE_INTERVAL_MS: '60000',
      PRODUCT_INITIAL_STOCK: '1',
    },
    async ({ page, apiObservation }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await reachReview(page);
      const acceptedResponse = page.waitForResponse(
        (response) =>
          response.request().method() === 'POST' &&
          new URL(response.url()).pathname.endsWith('/transactions') &&
          response.status() === 202,
      );
      await page.getByTestId('checkout-submit').click();
      await acceptedResponse;
      await page.reload();
      await waitForUiState(page, 'transaction-pending');
      const progress = await readProgress(page);
      check(typeof progress.transactionId === 'string', 'REFRESH05_TRANSACTION_MISSING');
      const transaction = await browserJson(
        page,
        '/api/v1/transactions/' + progress.transactionId,
        200,
      );
      check(
        transaction.paymentStatus === 'PENDING' && transaction.reservationStatus === 'ACTIVE',
        'REFRESH05_SERVER_STATE',
      );
      check(transactionPosts() === 1, 'REFRESH05_DUPLICATE_POST');
      check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'REFRESH05_DISPATCH');
      check(!(await browserProgressContainsForbiddenData(page)), 'REFRESH05_SENSITIVE_STORAGE');
    },
  ),
);

await recordRefreshRecovery(REFRESH_RECOVERY_CONTRACT[5], () =>
  withChromiumUi(
    {
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
      FAKE_RECONCILE_INTERVAL_MS: '60000',
      PRODUCT_INITIAL_STOCK: '1',
    },
    async ({ page, context, apiObservation, network }) => {
      let transactionPosts = 0;
      context.on('request', (request) => {
        if (
          request.method() === 'POST' &&
          new URL(request.url()).pathname.endsWith('/transactions')
        ) {
          transactionPosts += 1;
        }
      });
      await reachReview(page);
      await page.getByTestId('checkout-submit').click();
      await waitForUiState(page, 'transaction-pending');
      const before = await readProgress(page);
      check(typeof before.transactionId === 'string', 'REFRESH06_TRANSACTION_MISSING');
      await withReopenedPublicPage(
        { context, network },
        REFRESH_STATUS_PATH,
        async (reopenedPage) => {
          await waitForUiState(reopenedPage, 'transaction-pending');
          const after = await readProgress(reopenedPage);
          check(after.transactionId === before.transactionId, 'REFRESH06_TRANSACTION_DRIFT');
          const transaction = await browserJson(
            reopenedPage,
            '/api/v1/transactions/' + after.transactionId,
            200,
          );
          check(
            transaction.paymentStatus === 'PENDING' && transaction.reservationStatus === 'ACTIVE',
            'REFRESH06_SERVER_STATE',
          );
          check(
            !(await browserProgressContainsForbiddenData(reopenedPage)),
            'REFRESH06_SENSITIVE_STORAGE',
          );
        },
      );
      check(transactionPosts === 1, 'REFRESH06_DUPLICATE_POST');
      check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'REFRESH06_DISPATCH');
    },
  ),
);

await recordRefreshRecovery(REFRESH_RECOVERY_CONTRACT[6], () =>
  withChromiumUi(
    {
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
      FAKE_RECONCILE_INTERVAL_MS: '10',
      PRODUCT_INITIAL_STOCK: '1',
    },
    async ({ page, apiObservation }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await reachReview(page);
      await page.getByTestId('checkout-submit').click();
      await waitForUiState(page, 'transaction-approved');
      const before = await readProgress(page);
      check(typeof before.transactionId === 'string', 'REFRESH07_TRANSACTION_MISSING');
      await page.reload();
      await waitForUiState(page, 'transaction-approved');
      const after = await readProgress(page);
      check(after.transactionId === before.transactionId, 'REFRESH07_TRANSACTION_DRIFT');
      const transaction = await browserJson(
        page,
        '/api/v1/transactions/' + after.transactionId,
        200,
      );
      check(
        transaction.paymentStatus === 'APPROVED' &&
          transaction.reservationStatus === 'CONSUMED' &&
          typeof transaction.deliveryId === 'string',
        'REFRESH07_SERVER_STATE',
      );
      check(transactionPosts() === 1, 'REFRESH07_DUPLICATE_POST');
      check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'REFRESH07_DISPATCH');
      check(!(await browserProgressContainsForbiddenData(page)), 'REFRESH07_SENSITIVE_STORAGE');
    },
  ),
);

await recordRefreshRecovery(REFRESH_RECOVERY_CONTRACT[7], () =>
  withChromiumUi(
    {
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
      FAKE_RECONCILE_INTERVAL_MS: '10',
      PRODUCT_INITIAL_STOCK: '1',
    },
    async ({ page, apiObservation }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await reachReview(page);
      await page.getByTestId('checkout-submit').click();
      await waitForUiState(page, 'transaction-approved');
      const finalProgress = await readProgress(page);
      check(typeof finalProgress.transactionId === 'string', 'REFRESH08_TRANSACTION_MISSING');
      await page.getByTestId('return-product').click();
      await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
      await expect(
        page.getByText('Compra completada. Actualizamos la disponibilidad.'),
      ).toBeVisible();
      await expect(page.getByText('Agotado por ahora')).toBeVisible();
      await expect(page.getByTestId('product-checkout-cta')).toBeDisabled();
      await page.reload();
      await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
      await expect(page.getByText('Agotado por ahora')).toBeVisible();
      await expect(page.getByTestId('product-checkout-cta')).toBeDisabled();
      const stock = await browserJson(page, '/api/v1/stock/' + PRODUCT_ID, 200);
      const transaction = await browserJson(
        page,
        '/api/v1/transactions/' + finalProgress.transactionId,
        200,
      );
      check(stock.available === 0, 'REFRESH08_STOCK_DRIFT');
      check(
        transaction.paymentStatus === 'APPROVED' &&
          transaction.reservationStatus === 'CONSUMED' &&
          typeof transaction.deliveryId === 'string',
        'REFRESH08_SERVER_STATE',
      );
      check(transactionPosts() === 1, 'REFRESH08_DUPLICATE_POST');
      check(apiObservation.countLog('payment.dispatch_claimed') === 1, 'REFRESH08_DISPATCH');
      check(!(await browserProgressContainsForbiddenData(page)), 'REFRESH08_SENSITIVE_STORAGE');
    },
  ),
);

check(
  refreshRecoveryMetadataIsExact(refreshRecovery, {
    runId: RUN_ID,
    commitSha: CANDIDATE.commitSha,
    environment: stage6Environment(),
  }),
  'REFRESH_RECOVERY_METADATA_DRIFT',
);
check(negativeE2e.length === 12, 'NEGATIVE_E2E_COUNT');
check(new Set(negativeE2e.map(({ id }) => id)).size === 12, 'NEGATIVE_E2E_DUPLICATE');
check(
  NEGATIVE_E2E_IDS.every((id, index) => negativeE2e[index]?.id === id),
  'NEGATIVE_E2E_CANONICAL_IDS',
);
check(
  negativeE2eMetadataIsExact(negativeE2e, {
    runId: RUN_ID,
    commitSha: CANDIDATE.commitSha,
  }),
  'NEGATIVE_E2E_METADATA_DRIFT',
);
const expectedIds = Array.from(
  { length: 48 },
  (_, index) => 'UAT-' + String(index + 1).padStart(2, '0'),
);
check(results.size === 48, 'UAT_RESULT_COUNT');
check(
  expectedIds.every((id) => results.has(id)),
  'UAT_RESULT_ID_MISSING',
);
const orderedResults = expectedIds.map((id) => results.get(id));
check(
  orderedResults.filter(({ priority }) => priority === 'P0').length === 45 &&
    orderedResults.filter(({ priority }) => priority === 'P1').length === 3,
  'UAT_PRIORITY_DENOMINATOR',
);
check(
  orderedResults.every((row) => row.priority === UAT_METADATA.get(row.id)?.priority),
  'UAT_PRIORITY_CANONICAL_DRIFT',
);
check(
  orderedResults.every(
    (row) =>
      typeof row.requirements === 'string' &&
      row.requirements.length > 0 &&
      typeof row.traceability === 'string' &&
      row.traceability.length > 0 &&
      typeof row.precondition === 'string' &&
      row.precondition.length > 0 &&
      Array.isArray(row.steps) &&
      row.steps.length >= 3 &&
      row.steps.every((step) => typeof step === 'string' && step.length > 0) &&
      typeof row.expectedResult === 'string' &&
      row.expectedResult.length > 0 &&
      typeof row.actualResult === 'string' &&
      row.actualResult.length > 0 &&
      typeof row.defect === 'string' &&
      row.defect.length > 0 &&
      typeof row.runnerRole === 'string' &&
      row.runnerRole.length > 0 &&
      typeof row.runnerPersona === 'string' &&
      row.runnerPersona.length > 0 &&
      row.environment === stage6Environment() &&
      ((row.id === 'UAT-33' &&
        row.executionScope === 'AUTHORIZED_OWNED_EPHEMERAL_QA_EXTERNAL_EVIDENCE') ||
        (row.id !== 'UAT-33' && row.executionScope === 'LOCAL_LOOPBACK_FAKE_MEMORY_FIXTURES')) &&
      typeof row.executedAtUtc === 'string' &&
      row.commitSha === CANDIDATE.commitSha &&
      row.evidence.length > 0 &&
      row.evidenceIds.length > 0,
  ),
  'UAT_ROW_24_2_INCOMPLETE',
);
const notRunResults = orderedResults.filter(({ status }) => status.startsWith('NOT_RUN_'));
check(
  notRunResults.every(
    ({ id, status }) =>
      (id === 'UAT-16' && status === 'NOT_RUN_MANUAL_REQUIRED') ||
      (id === 'UAT-33' && status === 'NOT_RUN_AUTH_REQUIRED'),
  ) &&
    notRunResults.filter(({ id }) => id === 'UAT-33').length ===
      (UAT33_DECISION === 'NOT_RUN_AUTH_REQUIRED' ? 1 : 0) &&
    notRunResults.filter(({ id }) => id === 'UAT-16').length <= 1,
  'UAT_UNAUTHORIZED_NOT_RUN',
);
check(
  orderedResults.every(({ status }) =>
    ['PASS', 'FAIL', 'NOT_RUN_MANUAL_REQUIRED', 'NOT_RUN_AUTH_REQUIRED'].includes(status),
  ),
  'UAT_STATUS_INVALID',
);
const failures = orderedResults.filter(({ status }) => status === 'FAIL');
const passed = orderedResults.filter(({ status }) => status === 'PASS');
const negativeE2eFailures = negativeE2e.filter(({ status: value }) => value === 'FAIL');
const negativeE2ePassed = negativeE2e.filter(({ status: value }) => value === 'PASS');
const refreshRecoveryFailures = refreshRecovery.filter(({ status: value }) => value === 'FAIL');
const refreshRecoveryPassed = refreshRecoveryMatrixPassed(refreshRecovery, {
  runId: RUN_ID,
  commitSha: CANDIDATE.commitSha,
  environment: stage6Environment(),
});
const status =
  failures.length > 0 || negativeE2eFailures.length > 0 || !refreshRecoveryPassed
    ? 'FAIL'
    : notRunResults.length > 0
      ? 'PARTIAL'
      : 'PASS';
const networkObservation = observedExternalNetworkAttempts();
const report = {
  ...baseEvidence({
    artifactId: 'ART-VER-14',
    command: COMMAND,
    tool: {
      node: process.version,
      playwright: '1.62.1',
      httpClient: 'node-fetch-native',
      fixtureComposition: '@nestjs/testing-11.2.1',
    },
    runId: RUN_ID,
  }),
  commitSha: CANDIDATE.commitSha,
  candidate: CANDIDATE,
  externalEvidence: EXTERNAL_EVIDENCE,
  externalEvidenceIngestionNetworkAttempts: 0,
  status,
  runnerRole: 'INDEPENDENT_BLACK_BOX_UAT',
  runnerPersona: 'QA_INDEPENDENT_UAT_RUNNER',
  networkPolicy: 'EXTERNAL_DENY_LOOPBACK_ONLY',
  externalNetworkAttempts: networkObservation.total,
  networkObservation: {
    ...networkObservation,
    canary: NETWORK_OBSERVATION_CANARY,
  },
  syntheticDataOnly: true,
  sensitiveValuesCaptured: 0,
  results: orderedResults,
  negativeE2e,
  refreshRecovery,
  summary: {
    total: 48,
    passed: passed.length,
    failed: failures.length,
    notRunManualRequired: notRunResults.filter(
      ({ status: value }) => value === 'NOT_RUN_MANUAL_REQUIRED',
    ).length,
    notRunAuthRequired: notRunResults.filter(
      ({ status: value }) => value === 'NOT_RUN_AUTH_REQUIRED',
    ).length,
    priorityP0: 45,
    priorityP1: 3,
    uniqueIds: new Set(orderedResults.map(({ id }) => id)).size,
    negativeE2eTotal: 12,
    negativeE2ePassed: negativeE2ePassed.length,
    negativeE2eFailed: negativeE2eFailures.length,
    refreshRecoveryTotal: 8,
    refreshRecoveryPassed: refreshRecovery.length - refreshRecoveryFailures.length,
    refreshRecoveryFailed: refreshRecoveryFailures.length,
  },
  defects: [...failures, ...negativeE2eFailures, ...refreshRecoveryFailures].map(
    ({ id, defect, failureCode }) => ({
      id,
      defect,
      failureCode,
    }),
  ),
  approvedExpectationDeltas: [
    {
      id: 'CHG-E6-UAT-22-45',
      uat: ['UAT-22', 'UAT-45'],
      authority: ['CHG-16', 'OAS-TRANSACTION-200'],
      actualContract:
        'Una submission local aceptada permanece POST 202; GET Transaction 200 expone ERROR/recovery.',
      preAcceptanceOnly:
        '503 se reserva para PROVIDER_NOT_SENT/PROVIDER_AUTH_OR_CONFIG_INVALID antes de aceptación.',
    },
  ],
  declarations: [
    'UAT-16 sólo queda NOT_RUN cuando falta manual v2; evidencia válida lo promueve a PASS e inválida produce FAIL.',
    'UAT-33 queda NOT_RUN sólo sin AUTH-E6-01; evidencia externa v1 válida del mismo commit lo promueve a PASS e inválida produce FAIL.',
    'API-11 real permanece diferida; UAT-14 se ejecuta 3/3 con fixtures locales.',
    'Ningún unit test se remapeó como sustituto de una sonda black-box.',
    'REFRESH-E6-01..08 ejecuta los ocho estados de §27 por UI/HTTP pública y red externa denegada.',
    'E2E-E6-13..24 se ejecutan 12/12 por HTTP/UI pública; Jest queda sólo como evidencia de soporte.',
  ],
};

const evidenceSensitivePatterns = [
  { id: 'PAN_LIKE_SEQUENCE', pattern: /\b[0-9]{13,19}\b/u },
  { id: 'PAYMENT_TOKEN_VALUE', pattern: /\btok_[a-z0-9_-]{8,}\b/iu },
  {
    id: 'ACCEPTANCE_TOKEN_VALUE',
    pattern: /\b[A-Za-z0-9_-]{32}\.[A-Za-z0-9_-]{43}\b/u,
  },
  { id: 'PRIVATE_KEY_MARKER', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/u },
  { id: 'PROVIDER_KEY_VALUE', pattern: /\b(?:pk|sk)_(?:live|test)_[a-z0-9_-]{8,}\b/iu },
];
const serializedEvidence = JSON.stringify(report);
const sensitiveEvidenceMatches = evidenceSensitivePatterns.filter(({ pattern }) =>
  pattern.test(serializedEvidence),
);
check(sensitiveEvidenceMatches.length === 0, 'UAT_EVIDENCE_SENSITIVE_VALUE');
report.sanitizationVerification = {
  status: 'PASS',
  matchedSensitiveValues: 0,
  checks: evidenceSensitivePatterns.map(({ id }) => id),
};
const evidencePath = writeRuntimeEvidence('uat.json', report);
process.stdout.write(
  'stage-6 uat: ' +
    status +
    ' (' +
    passed.length +
    ' PASS; ' +
    failures.length +
    ' FAIL; ' +
    notRunResults.length +
    ' NOT_RUN; ' +
    negativeE2ePassed.length +
    '/12 NEGATIVE_E2E) -> ' +
    evidencePath +
    String.fromCharCode(10),
);
if (status === 'FAIL') process.exitCode = 1;
else if (status === 'PARTIAL') process.exitCode = 2;
// UAT_FINALIZE
