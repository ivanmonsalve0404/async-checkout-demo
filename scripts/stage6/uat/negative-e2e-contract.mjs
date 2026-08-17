import { strict as assert } from 'node:assert';

const definitions = [
  [
    'E2E-E6-13',
    'Manipulación del total en DevTools',
    'REUSED_EXACT_BLACK_BOX_UAT_SMOKE',
    'EXACT_EXECUTED_BLACK_BOX_REUSE',
    ['UAT-07'],
    ['NEG-E2E-E6-13', 'UAT-07', 'HTTP-UAT-07'],
  ],
  [
    'E2E-E6-14',
    'Idempotency key igual con payload distinto',
    'REUSED_EXACT_BLACK_BOX_UAT_SMOKE',
    'EXACT_EXECUTED_BLACK_BOX_REUSE',
    ['UAT-05'],
    ['NEG-E2E-E6-14', 'UAT-05', 'HTTP-UAT-05'],
  ],
  [
    'E2E-E6-15',
    'Token de sesión ajeno/expirado',
    'REUSED_EXACT_BLACK_BOX_UAT_SMOKE',
    'EXACT_EXECUTED_BLACK_BOX_REUSE',
    ['UAT-17', 'UAT-28'],
    ['NEG-E2E-E6-15', 'UAT-17', 'UAT-28', 'HTTP-UAT-17', 'HTTP-UAT-28'],
  ],
  [
    'E2E-E6-16',
    'Stock cambia entre quote y pago',
    'REUSED_EXACT_BLACK_BOX_UAT_SMOKE',
    'EXACT_EXECUTED_BLACK_BOX_REUSE',
    ['UAT-06'],
    ['NEG-E2E-E6-16', 'UAT-06', 'stage-5-smoke-results.json#SMK-E5-08'],
  ],
  [
    'E2E-E6-17',
    'Respuesta final fuera de orden',
    'REUSED_EXACT_BLACK_BOX_UAT_SMOKE',
    'EXACT_EXECUTED_BLACK_BOX_REUSE',
    ['UAT-42'],
    ['NEG-E2E-E6-17', 'UAT-42', 'FIXTURE-UAT-42', 'HTTP-UAT-42'],
  ],
  [
    'E2E-E6-18',
    'Usuario vuelve atrás durante pending',
    'PLAYWRIGHT_CHROMIUM_PUBLIC_UI',
    'DEDICATED_PUBLIC_UI_PROBE',
    [],
    ['NEG-E2E-E6-18', 'UI-NEG-E6-18', 'HTTP-NEG-E6-18'],
  ],
  [
    'E2E-E6-19',
    'Dos pestañas intentan pagar la misma sesión',
    'PLAYWRIGHT_TWO_TABS_PUBLIC_HTTP',
    'DEDICATED_TWO_TAB_PUBLIC_HTTP_PROBE',
    [],
    ['NEG-E2E-E6-19', 'BROWSER-TABS-NEG-E6-19', 'HTTP-NEG-E6-19'],
  ],
  [
    'E2E-E6-20',
    'Red se corta después de submit',
    'PLAYWRIGHT_POST_COMMIT_NETWORK_ABORT',
    'DEDICATED_POST_COMMIT_RESPONSE_LOSS_PROBE',
    [],
    ['NEG-E2E-E6-20', 'UI-NEG-E6-20', 'HTTP-POSTCOMMIT-NEG-E6-20'],
  ],
  [
    'E2E-E6-21',
    'Recarga después de aprobación antes de render final',
    'PLAYWRIGHT_APPROVED_RESPONSE_ABORT_THEN_RELOAD',
    'DEDICATED_APPROVED_BEFORE_RENDER_RELOAD_PROBE',
    [],
    ['NEG-E2E-E6-21', 'UI-NEG-E6-21', 'HTTP-NEG-E6-21'],
  ],
  [
    'E2E-E6-22',
    'API devuelve error validado y UI preserva datos permitidos',
    'PLAYWRIGHT_PUBLIC_REQUEST_MUTATION_AND_UI_ORACLE',
    'DEDICATED_VALIDATION_ERROR_UI_PRESERVATION_PROBE',
    [],
    ['NEG-E2E-E6-22', 'UI-NEG-E6-22', 'HTTP-422-NEG-E6-22'],
  ],
  [
    'E2E-E6-23',
    'Producto sin stock desde el inicio',
    'REUSED_EXACT_BLACK_BOX_UAT_SMOKE',
    'EXACT_EXECUTED_BLACK_BOX_REUSE',
    ['UAT-38'],
    ['NEG-E2E-E6-23', 'UAT-38', 'HTTP-UAT-38'],
  ],
  [
    'E2E-E6-24',
    'Cleanup/reintento de una sesión abandonada',
    'PLAYWRIGHT_FAILED_SESSION_CLEANUP_AND_RESTART',
    'DEDICATED_FAILED_SESSION_RESTART_PROBE',
    [],
    ['NEG-E2E-E6-24', 'UI-NEG-E6-24', 'HTTP-NEG-E6-24'],
  ],
];

export const NEGATIVE_E2E_CONTRACT = Object.freeze(
  definitions.map(([id, canonicalScenario, probeType, mappingKind, sourceCaseIds, evidenceIds]) =>
    Object.freeze({
      id,
      canonicalScenario,
      probeType,
      mappingKind,
      sourceCaseIds: Object.freeze(sourceCaseIds),
      evidenceIds: Object.freeze(evidenceIds),
    }),
  ),
);

const exactStrings = (actual, expected) =>
  Array.isArray(actual) &&
  actual.length === expected.length &&
  actual.every((value, index) => value === expected[index]);

export const negativeE2eMetadataIsExact = (rows, { runId, commitSha }) =>
  Array.isArray(rows) &&
  rows.length === NEGATIVE_E2E_CONTRACT.length &&
  new Set(rows.map((row) => row?.id)).size === NEGATIVE_E2E_CONTRACT.length &&
  rows.every((row, index) => {
    const expected = NEGATIVE_E2E_CONTRACT[index];
    return (
      row?.id === expected.id &&
      ['PASS', 'FAIL'].includes(row.status) &&
      row.verificationLayer === 'BLACK_BOX_PUBLIC_HTTP_UI' &&
      row.canonicalScenario === expected.canonicalScenario &&
      row.probeType === expected.probeType &&
      row.mapping?.kind === expected.mappingKind &&
      row.mapping?.exactOracle === true &&
      exactStrings(row.mapping?.sourceCaseIds, expected.sourceCaseIds) &&
      typeof row.mapping?.rationale === 'string' &&
      row.mapping.rationale.trim().length > 0 &&
      typeof row.observableResult === 'string' &&
      row.observableResult.trim().length > 0 &&
      row.runnerRole === 'INDEPENDENT_NEGATIVE_E2E_RUNNER' &&
      row.runId === runId &&
      row.commitSha === commitSha &&
      exactStrings(row.evidence, expected.evidenceIds) &&
      exactStrings(row.evidenceIds, expected.evidenceIds)
    );
  });

export const selfTestNegativeE2eContract = () => {
  const runId = 'e6-20260816t120000z-0123abcd';
  const commitSha = 'a'.repeat(40);
  const rows = NEGATIVE_E2E_CONTRACT.map((expected) => ({
    ...expected,
    status: 'PASS',
    verificationLayer: 'BLACK_BOX_PUBLIC_HTTP_UI',
    mapping: {
      kind: expected.mappingKind,
      sourceCaseIds: [...expected.sourceCaseIds],
      exactOracle: true,
      rationale: 'Oráculo público exacto y reproducible.',
    },
    observableResult: 'Resultado público observado y sanitizado.',
    runnerRole: 'INDEPENDENT_NEGATIVE_E2E_RUNNER',
    runId,
    commitSha,
    evidence: [...expected.evidenceIds],
    evidenceIds: [...expected.evidenceIds],
  }));
  assert.equal(negativeE2eMetadataIsExact(rows, { runId, commitSha }), true);
  assert.equal(
    negativeE2eMetadataIsExact(
      rows.map((row, index) =>
        index === 0 ? { ...row, mapping: { ...row.mapping, sourceCaseIds: ['UAT-08'] } } : row,
      ),
      { runId, commitSha },
    ),
    false,
  );
  assert.equal(
    negativeE2eMetadataIsExact(
      rows.map((row, index) => (index === 5 ? { ...row, probeType: 'HTTP_ONLY' } : row)),
      { runId, commitSha },
    ),
    false,
  );
};
