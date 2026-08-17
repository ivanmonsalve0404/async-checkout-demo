import { strict as assert } from 'node:assert';

export const REFRESH_RECOVERY_CONTRACT = [
  {
    id: 'REFRESH-E6-01',
    sequence: 1,
    canonicalState: 'PRODUCT_PAGE',
    recoveryAction: 'REFRESH',
    probeType: 'PLAYWRIGHT_CHROMIUM_PUBLIC_UI_REFRESH',
    expectedResult: 'Product and stock are reloaded from public APIs without checkout mutation.',
    evidenceIds: ['REFRESH-E6-01', 'UI-REFRESH-E6-01', 'HTTP-STOCK-REFRESH-E6-01'],
  },
  {
    id: 'REFRESH-E6-02',
    sequence: 2,
    canonicalState: 'DATA_CAPTURE',
    recoveryAction: 'REFRESH',
    probeType: 'PLAYWRIGHT_CHROMIUM_PUBLIC_UI_REFRESH',
    expectedResult: 'Refresh restores the server checkout and clears ephemeral card fields.',
    evidenceIds: ['REFRESH-E6-02', 'UI-REFRESH-E6-02', 'HTTP-CHECKOUT-REFRESH-E6-02'],
  },
  {
    id: 'REFRESH-E6-03',
    sequence: 3,
    canonicalState: 'SUMMARY',
    recoveryAction: 'REFRESH',
    probeType: 'PLAYWRIGHT_CHROMIUM_PUBLIC_UI_REFRESH',
    expectedResult: 'Refresh keeps the canonical ready checkout and requires payment re-entry.',
    evidenceIds: ['REFRESH-E6-03', 'UI-REFRESH-E6-03', 'HTTP-CHECKOUT-REFRESH-E6-03'],
  },
  {
    id: 'REFRESH-E6-04',
    sequence: 4,
    canonicalState: 'IMMEDIATELY_BEFORE_PAYMENT',
    recoveryAction: 'REOPEN',
    probeType: 'PLAYWRIGHT_CHROMIUM_PUBLIC_UI_REOPEN',
    expectedResult: 'Reopen preserves the ready checkout but never restores payment secrets.',
    evidenceIds: ['REFRESH-E6-04', 'UI-REOPEN-E6-04', 'HTTP-CHECKOUT-REFRESH-E6-04'],
  },
  {
    id: 'REFRESH-E6-05',
    sequence: 5,
    canonicalState: 'IMMEDIATELY_AFTER_SUBMIT',
    recoveryAction: 'REFRESH',
    probeType: 'PLAYWRIGHT_CHROMIUM_PUBLIC_UI_POST_SUBMIT_REFRESH',
    expectedResult:
      'Refresh after accepted submit recovers the active transaction without another POST.',
    evidenceIds: ['REFRESH-E6-05', 'UI-REFRESH-E6-05', 'HTTP-TRANSACTION-REFRESH-E6-05'],
  },
  {
    id: 'REFRESH-E6-06',
    sequence: 6,
    canonicalState: 'PENDING',
    recoveryAction: 'REOPEN',
    probeType: 'PLAYWRIGHT_CHROMIUM_PUBLIC_UI_PENDING_REOPEN',
    expectedResult: 'Reopen during PENDING recovers the same active transaction by GET only.',
    evidenceIds: ['REFRESH-E6-06', 'UI-REOPEN-E6-06', 'HTTP-TRANSACTION-REFRESH-E6-06'],
  },
  {
    id: 'REFRESH-E6-07',
    sequence: 7,
    canonicalState: 'FINAL_BEFORE_REDIRECT',
    recoveryAction: 'REFRESH',
    probeType: 'PLAYWRIGHT_CHROMIUM_PUBLIC_UI_FINAL_REFRESH',
    expectedResult: 'Refresh before return recovers the same final transaction and single effect.',
    evidenceIds: ['REFRESH-E6-07', 'UI-REFRESH-E6-07', 'HTTP-TRANSACTION-REFRESH-E6-07'],
  },
  {
    id: 'REFRESH-E6-08',
    sequence: 8,
    canonicalState: 'AFTER_REDIRECT_WITH_UPDATED_STOCK',
    recoveryAction: 'REFRESH',
    probeType: 'PLAYWRIGHT_CHROMIUM_PUBLIC_UI_POST_REDIRECT_REFRESH',
    expectedResult:
      'Product refresh after return shows canonical consumed stock and no duplicate effect.',
    evidenceIds: ['REFRESH-E6-08', 'UI-REFRESH-E6-08', 'HTTP-STOCK-REFRESH-E6-08'],
  },
];

const exactStrings = (actual, expected) =>
  Array.isArray(actual) &&
  actual.length === expected.length &&
  actual.every((value, index) => value === expected[index]);

export const refreshRecoveryMetadataIsExact = (rows, { runId, commitSha, environment }) =>
  Array.isArray(rows) &&
  rows.length === REFRESH_RECOVERY_CONTRACT.length &&
  new Set(rows.map(({ id }) => id)).size === REFRESH_RECOVERY_CONTRACT.length &&
  rows.every((row, index) => {
    const expected = REFRESH_RECOVERY_CONTRACT[index];
    return (
      row?.id === expected.id &&
      row.sequence === expected.sequence &&
      row.canonicalState === expected.canonicalState &&
      row.recoveryAction === expected.recoveryAction &&
      row.probeType === expected.probeType &&
      row.expectedResult === expected.expectedResult &&
      exactStrings(row.evidenceIds, expected.evidenceIds) &&
      exactStrings(row.evidence, expected.evidenceIds) &&
      (row.status === 'PASS' || row.status === 'FAIL') &&
      row.verificationLayer === 'BLACK_BOX_PUBLIC_HTTP_UI' &&
      row.runnerRole === 'INDEPENDENT_REFRESH_RECOVERY_RUNNER' &&
      row.runnerPersona === 'QA_INDEPENDENT_BLACK_BOX_RUNNER' &&
      row.runId === runId &&
      row.commitSha === commitSha &&
      row.environment === environment &&
      row.executionScope === 'LOCAL_LOOPBACK_FAKE_MEMORY_FIXTURES' &&
      typeof row.executedAtUtc === 'string' &&
      Number.isFinite(Date.parse(row.executedAtUtc)) &&
      typeof row.observableResult === 'string' &&
      row.observableResult.length > 0 &&
      typeof row.actualResult === 'string' &&
      row.actualResult.length > 0 &&
      typeof row.defect === 'string' &&
      row.defect.length > 0 &&
      Number.isInteger(row.externalNetworkAttempts) &&
      row.externalNetworkAttempts >= 0 &&
      Number.isInteger(row.durationMs) &&
      row.durationMs >= 0
    );
  });

export const refreshRecoveryMatrixPassed = (rows, expectedExecution) =>
  refreshRecoveryMetadataIsExact(rows, expectedExecution) &&
  rows.every(
    (row) =>
      row.status === 'PASS' &&
      row.externalNetworkAttempts === 0 &&
      row.serverAuthorityObserved === true &&
      row.duplicateEffectsObserved === 0 &&
      row.impossibleStatesObserved === 0 &&
      row.sensitiveValuesCaptured === 0,
  );

const fixture = () => {
  const execution = {
    runId: 'e6-20260816t120000z-0123abcd',
    commitSha: 'a'.repeat(40),
    environment: 'ENV-E6-CI',
  };
  return {
    execution,
    rows: REFRESH_RECOVERY_CONTRACT.map((expected) => ({
      ...expected,
      status: 'PASS',
      verificationLayer: 'BLACK_BOX_PUBLIC_HTTP_UI',
      observableResult: expected.expectedResult,
      actualResult: expected.expectedResult,
      defect: 'N/A',
      runnerRole: 'INDEPENDENT_REFRESH_RECOVERY_RUNNER',
      runnerPersona: 'QA_INDEPENDENT_BLACK_BOX_RUNNER',
      ...execution,
      executionScope: 'LOCAL_LOOPBACK_FAKE_MEMORY_FIXTURES',
      executedAtUtc: '2026-08-16T12:00:00.000Z',
      evidence: expected.evidenceIds,
      externalNetworkAttempts: 0,
      serverAuthorityObserved: true,
      duplicateEffectsObserved: 0,
      impossibleStatesObserved: 0,
      sensitiveValuesCaptured: 0,
      durationMs: 1,
    })),
  };
};

export const selfTestRefreshRecoveryContract = () => {
  const { rows, execution } = fixture();
  assert.equal(refreshRecoveryMetadataIsExact(rows, execution), true);
  assert.equal(refreshRecoveryMatrixPassed(rows, execution), true);
  assert.equal(refreshRecoveryMatrixPassed(rows.slice(1), execution), false);
  assert.equal(refreshRecoveryMatrixPassed([rows[1], rows[0], ...rows.slice(2)], execution), false);
  assert.equal(
    refreshRecoveryMatrixPassed(
      rows.map((row, index) => (index === 4 ? { ...row, status: 'FAIL' } : row)),
      execution,
    ),
    false,
  );
};
