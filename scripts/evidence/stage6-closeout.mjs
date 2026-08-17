#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import process from 'node:process';

import {
  selfTestManualEvidence,
  validateManualEvidenceSummary,
} from '../stage6/a11y/manual-evidence.mjs';
import {
  canonicalRowsAuthorized,
  finalAuthorityText,
  reportAuthorityReady,
  selfTestDocumentAuthority,
} from '../stage6/docs-authority.mjs';
import {
  externalEvidenceCapabilityDecision,
  externalEvidenceMissingIsExact,
  missingExternalEvidence,
  selfTestExternalEvidence,
  validateExternalEvidenceSummary,
} from '../stage6/external-evidence.mjs';
import {
  baseEvidence,
  candidate,
  sha256,
  sourceSnapshot,
  stage6RunId,
  workspaceRoot,
  writeRuntimeEvidence,
} from '../stage6/lib/evidence.mjs';
import { selfTestLoadEvidence, validateLoadEvidence } from '../stage6/load/evidence.mjs';
import {
  selfTestPerformanceEvidence,
  validatePerformanceEvidence,
} from '../stage6/perf/evidence.mjs';
import {
  calculateStage6Rubric,
  selfTestStage6Rubric,
  stage6RubricIsExact,
} from '../stage6/rubric.mjs';
import {
  selfTestSecurityEvidence,
  validateSecurityEvidence,
} from '../stage6/security/evidence.mjs';
import {
  NEGATIVE_E2E_CONTRACT,
  negativeE2eMetadataIsExact,
  selfTestNegativeE2eContract,
} from '../stage6/uat/negative-e2e-contract.mjs';
import {
  refreshRecoveryMatrixPassed,
  selfTestRefreshRecoveryContract,
} from '../stage6/uat/refresh-recovery-contract.mjs';

const trackedPath = resolve(
  workspaceRoot,
  'output',
  'evidence',
  'stage-6',
  'verification-manifest.json',
);
const expectedArtifactIds = Array.from(
  { length: 18 },
  (_, index) => 'ART-VER-' + String(index + 1).padStart(2, '0'),
);
const expectedEvidenceIds = Array.from(
  { length: 40 },
  (_, index) => 'EVD-E6-' + String(index + 1).padStart(2, '0'),
);
const expectedUatIds = Array.from(
  { length: 48 },
  (_, index) => 'UAT-' + String(index + 1).padStart(2, '0'),
);
const expectedNegativeE2eIds = NEGATIVE_E2E_CONTRACT.map(({ id }) => id);
const expectedIntegrityIds = Array.from(
  { length: 12 },
  (_, index) => 'INT-E6-' + String(index + 1).padStart(2, '0'),
);
const expectedUat14FixtureIds = Array.from(
  { length: 3 },
  (_, index) => 'UAT-14-IF-' + String(index + 1).padStart(2, '0'),
);
const expectedResilienceIds = Array.from(
  { length: 17 },
  (_, index) => 'RES-E6-' + String(index + 1).padStart(2, '0'),
);
const runIdPattern = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const stage6EnvelopeIsFresh = (value, expected) =>
  value?.schemaVersion === 1 &&
  value?.stage === 6 &&
  value?.runId === expected.runId &&
  value?.environment === expected.environment &&
  value?.containsSensitiveData === false &&
  (value?.candidate?.commitSha ?? value?.commitSha ?? value?.baseEvidence?.commitSha) ===
    expected.commitSha;
const rubricOutputReady = (rubric, evidence) =>
  rubric !== undefined && stage6RubricIsExact(rubric, evidence);
const exactPassedMatrix = (results, expectedIds) =>
  Array.isArray(results) &&
  results.length === expectedIds.length &&
  new Set(results.map(({ id }) => id)).size === expectedIds.length &&
  results.every(({ id, status }, index) => id === expectedIds[index] && status === 'PASS');
const uatAuthorityRowsReady = (text) =>
  canonicalRowsAuthorized({
    text,
    pattern: /^\|\s*`(UAT-\d{2})`\s*\|/u,
    expectedIds: expectedUatIds,
    expectedStatuses: expectedUatIds.map(() => 'STATUS_BY_SAME_SHA_MANIFEST'),
    expectedAuthorityToken: 'STATUS_BY_SAME_SHA_MANIFEST',
    statusColumnIndex: 7,
  });
const AXE_IMPACTS = new Set(['minor', 'moderate', 'serious', 'critical']);
const REQUIRED_KEYBOARD_FOCUS_COVERAGE = [
  'dialog-forward-and-backward-focus-cycle',
  'step-heading-focus-on-transition',
  'validation-summary-focus',
  'pending-and-final-state-focus',
  'escape-close-and-opener-focus-return',
];
const FINAL_ARTIFACT_SCAN_CANARY_KEYS = [
  'assignedSecret',
  'panLuhn',
  'cvcContextual',
  'expiryContextual',
  'emailPii',
  'phonePii',
  'sensitiveField',
];
const FINAL_ARTIFACT_SCAN_DATA_CLASSES = [
  'SECRET',
  'PAN',
  'CVC',
  'EXPIRY',
  'EMAIL',
  'PHONE',
  'PII_FIELD',
  'SENSITIVE_FIELD',
];
const exactStringInventory = (actual, expected) =>
  Array.isArray(actual) &&
  actual.length === expected.length &&
  actual.every((value, index) => value === expected[index]);
const externalEvidenceSummariesMatch = (summaries) =>
  Array.isArray(summaries) &&
  summaries.length === 4 &&
  summaries.slice(1).every((summary) => isDeepStrictEqual(summary, summaries[0]));
const externalEvidenceSetReady = (summaries, execution) =>
  externalEvidenceSummariesMatch(summaries) &&
  summaries.every(
    (summary) =>
      validateExternalEvidenceSummary(summary, execution) ||
      externalEvidenceMissingIsExact(summary, execution),
  );
const externalCapabilityDecisionFromSet = (summaries, capability, execution) =>
  externalEvidenceSetReady(summaries, execution)
    ? externalEvidenceCapabilityDecision(summaries[0], capability, execution)
    : 'FAIL';

const sandboxEvidenceContractReady = (value, summary, execution) => {
  const decision = externalEvidenceCapabilityDecision(summary, 'sandboxSmoke', execution);
  const commonReady =
    value?.artifactId === 'ART-VER-07' &&
    value?.command === 'node scripts/stage6/sandbox-evidence.mjs' &&
    value?.tool?.node === process.version &&
    value?.tool?.protocol === 'stage6-external-evidence-v1' &&
    value?.commitSha === execution.commitSha &&
    isDeepStrictEqual(value?.externalEvidence, summary) &&
    value?.externalRequestsByIngestion === 0 &&
    value?.providerRequestsExecutedByThisProcess === 0 &&
    value?.containsSensitiveData === false;
  if (!commonReady || decision === 'FAIL') return false;
  if (decision === 'PASS') {
    return (
      value.status === 'PASS' &&
      isDeepStrictEqual(value.sandboxSmoke, summary.capabilities.sandboxSmoke) &&
      exactStringInventory(value.authorizationsInvoked, ['AUTH-E6-02']) &&
      value.failureCode === undefined &&
      value.declaration === 'AUTHORIZED_EXTERNAL_SANITIZED_SANDBOX_SMOKE_EVIDENCE'
    );
  }
  return (
    value.status === 'NOT_RUN_AUTH_REQUIRED' &&
    value.sandboxSmoke === undefined &&
    value.authorizationsInvoked === undefined &&
    value.failureCode === undefined &&
    value.declaration === 'SANDBOX_NOT_CONTACTED_AUTH_E6_02_REQUIRED'
  );
};

const finalArtifactScanContractReady = (value) =>
  value?.artifactId === 'EVD-E6-35' &&
  value?.command === 'node scripts/stage6/final-artifact-scan.mjs' &&
  value?.tool?.baseScanner === 'scripts/security/scan-repository.mjs' &&
  value?.scope === 'output/evidence/runtime' &&
  value?.history === 'COVERED_BY_E6_SECURITY_STEP' &&
  value?.tool?.scanner === 'stage6-artifact-sanitizer-v1' &&
  exactStringInventory(Object.keys(value?.canaries ?? {}), FINAL_ARTIFACT_SCAN_CANARY_KEYS) &&
  FINAL_ARTIFACT_SCAN_CANARY_KEYS.every((key) => value.canaries[key] === 'PASS') &&
  exactStringInventory(value?.dataClasses, FINAL_ARTIFACT_SCAN_DATA_CLASSES);
const cleanMarkdownCell = (value) => value.trim().replaceAll('`', '');
const defectRegisterReady = (text) => {
  if (typeof text !== 'string') return false;
  const rows = text
    .split('\n')
    .filter((line) => /^\|\s*`DEF-E6-\d{2}`\s*\|/u.test(line))
    .map((line) => {
      const cells = line
        .trim()
        .replace(/^\|/u, '')
        .replace(/\|$/u, '')
        .split('|')
        .map(cleanMarkdownCell);
      return {
        line,
        cells,
        id: cells[0],
        priority: cells[2]?.match(/^(P[0-3])\b/u)?.[1],
        owner: cells[9],
        state: cells[10],
      };
    });
  const ids = rows.map(({ id }) => id);
  if (
    rows.length < 2 ||
    rows.some(({ cells }) => cells.length !== 15) ||
    new Set(ids).size !== rows.length ||
    !['DEF-E6-01', 'DEF-E6-02'].every((id) => ids.includes(id))
  ) {
    return false;
  }
  return rows.every(({ line, owner, priority, state }) => {
    if (priority === 'P0' || priority === 'P1') {
      return state === 'VERIFIED_BY_SAME_SHA_MANIFEST';
    }
    if (priority !== 'P2' && priority !== 'P3') return false;
    if (state === 'VERIFIED_BY_SAME_SHA_MANIFEST') return true;
    const ownerReady =
      typeof owner === 'string' &&
      owner.length > 1 &&
      !/^(?:N\/A|TBD|PENDING|UNASSIGNED|-)$/iu.test(owner);
    return (
      state === 'ACCEPTED_RISK' &&
      ownerReady &&
      /\b20\d{2}-\d{2}-\d{2}\b/u.test(line) &&
      /\bimpacto\s*[:=]\s*[^|]{3,}/iu.test(line)
    );
  });
};
const accessibilityAutomatedMatrixPassed = (automated, expectedSurfaces) => {
  const exactOrder = (actual, expected) =>
    Array.isArray(actual) &&
    actual.length === expected.length &&
    actual.every((value, index) => value === expected[index]);
  if (
    automated?.status !== 'PASS' ||
    !exactOrder(automated.requiredSurfaces, expectedSurfaces) ||
    automated.surfaceCoverage !== `${expectedSurfaces.length}/${expectedSurfaces.length}` ||
    automated.keyboardDialogContract !== 'PASS' ||
    automated.keyboardFocusContract !== 'PASS' ||
    automated.reducedMotionEmulation !== 'PASS' ||
    !exactOrder(automated.keyboardFocusCoverage, REQUIRED_KEYBOARD_FOCUS_COVERAGE) ||
    automated.blockedExternalRequests !== 0 ||
    automated.unknownApiRequests !== 0 ||
    !Array.isArray(automated.axeScans) ||
    automated.axeScans.length !== expectedSurfaces.length ||
    new Set(automated.axeScans.map((scan) => scan?.surface)).size !== expectedSurfaces.length
  ) {
    return false;
  }
  const valid = automated.axeScans.every(
    (scan, index) =>
      scan?.surface === expectedSurfaces[index] &&
      scan.status === 'PASS' &&
      scan.domIdsUnique === true &&
      Number.isInteger(scan.domIdCount) &&
      scan.domIdCount >= 0 &&
      Array.isArray(scan.violations) &&
      scan.violations.length === 0 &&
      Array.isArray(scan.incomplete) &&
      scan.incomplete.every(
        (finding) =>
          finding !== null &&
          typeof finding === 'object' &&
          /^[a-z0-9][a-z0-9-]{1,63}$/u.test(finding.id) &&
          AXE_IMPACTS.has(finding.impact) &&
          Number.isInteger(finding.nodeCount) &&
          finding.nodeCount >= 1,
      ),
  );
  return (
    valid &&
    automated.axeIncompleteCount ===
      automated.axeScans.reduce((total, scan) => total + scan.incomplete.length, 0)
  );
};

const selfTest = () => {
  selfTestDocumentAuthority();
  selfTestExternalEvidence();
  const externalExecutionFixture = {
    commitSha: 'a'.repeat(40),
    runId: 'e6-20260816t120000z-0123abcd',
  };
  const missingExternalFixture = missingExternalEvidence(externalExecutionFixture);
  const matchingMissingSummaries = Array.from({ length: 4 }, () =>
    globalThis.structuredClone(missingExternalFixture),
  );
  assert.equal(externalEvidenceSetReady(matchingMissingSummaries, externalExecutionFixture), true);
  assert.equal(
    externalCapabilityDecisionFromSet(
      matchingMissingSummaries,
      'ownedTarget',
      externalExecutionFixture,
    ),
    'NOT_RUN_AUTH_REQUIRED',
  );
  const mismatchedRunSummaries = globalThis.structuredClone(matchingMissingSummaries);
  mismatchedRunSummaries[3].ingestedByRunId = 'e6-20260816t120001z-0123abcd';
  assert.equal(externalEvidenceSetReady(mismatchedRunSummaries, externalExecutionFixture), false);
  assert.equal(
    externalCapabilityDecisionFromSet(
      mismatchedRunSummaries,
      'ownedTarget',
      externalExecutionFixture,
    ),
    'FAIL',
  );
  const sourceFingerprint = {
    sourceSha256: 'b'.repeat(64),
    sourceExternalRunId: 'e6-20260816t110000z-0123abcd',
    protocolDocumentSha256: 'c'.repeat(64),
    schemaSha256: 'd'.repeat(64),
    commitSha: externalExecutionFixture.commitSha,
    ingestedByRunId: externalExecutionFixture.runId,
  };
  const matchingFingerprints = Array.from({ length: 4 }, () =>
    globalThis.structuredClone(sourceFingerprint),
  );
  assert.equal(externalEvidenceSummariesMatch(matchingFingerprints), true);
  for (const field of Object.keys(sourceFingerprint)) {
    const mismatched = globalThis.structuredClone(matchingFingerprints);
    mismatched[2][field] = 'mismatch-' + field;
    assert.equal(externalEvidenceSummariesMatch(mismatched), false);
  }
  const missingSandboxFixture = {
    artifactId: 'ART-VER-07',
    command: 'node scripts/stage6/sandbox-evidence.mjs',
    tool: { node: process.version, protocol: 'stage6-external-evidence-v1' },
    commitSha: externalExecutionFixture.commitSha,
    status: 'NOT_RUN_AUTH_REQUIRED',
    externalEvidence: missingExternalFixture,
    externalRequestsByIngestion: 0,
    providerRequestsExecutedByThisProcess: 0,
    containsSensitiveData: false,
    declaration: 'SANDBOX_NOT_CONTACTED_AUTH_E6_02_REQUIRED',
  };
  assert.equal(
    sandboxEvidenceContractReady(
      missingSandboxFixture,
      missingExternalFixture,
      externalExecutionFixture,
    ),
    true,
  );
  assert.equal(
    sandboxEvidenceContractReady(
      { ...missingSandboxFixture, status: 'PASS' },
      missingExternalFixture,
      externalExecutionFixture,
    ),
    false,
  );
  assert.equal(
    sandboxEvidenceContractReady(
      { ...missingSandboxFixture, providerRequestsExecutedByThisProcess: 1 },
      missingExternalFixture,
      externalExecutionFixture,
    ),
    false,
  );
  assert.equal(new Set(expectedArtifactIds).size, 18);
  selfTestManualEvidence();
  selfTestNegativeE2eContract();
  selfTestRefreshRecoveryContract();
  selfTestLoadEvidence();
  selfTestPerformanceEvidence();
  selfTestSecurityEvidence();
  selfTestStage6Rubric();
  const delegatedUatRows = expectedUatIds
    .map(
      (id) =>
        '| `' +
        id +
        '` | P0 | requirements | precondition | steps | expected | observed | `STATUS_BY_SAME_SHA_MANIFEST` | evidence |',
    )
    .join('\n');
  assert.equal(uatAuthorityRowsReady(delegatedUatRows), true);
  assert.equal(
    uatAuthorityRowsReady(delegatedUatRows.replace('`STATUS_BY_SAME_SHA_MANIFEST`', '`PASS`')),
    false,
  );
  assert.equal(
    uatAuthorityRowsReady(
      delegatedUatRows.replace('`STATUS_BY_SAME_SHA_MANIFEST`', '`X_BY_SAME_SHA_MANIFEST`'),
    ),
    false,
  );
  const finalScanContract = {
    artifactId: 'EVD-E6-35',
    command: 'node scripts/stage6/final-artifact-scan.mjs',
    tool: {
      scanner: 'stage6-artifact-sanitizer-v1',
      baseScanner: 'scripts/security/scan-repository.mjs',
    },
    scope: 'output/evidence/runtime',
    history: 'COVERED_BY_E6_SECURITY_STEP',
    canaries: Object.fromEntries(FINAL_ARTIFACT_SCAN_CANARY_KEYS.map((key) => [key, 'PASS'])),
    dataClasses: FINAL_ARTIFACT_SCAN_DATA_CLASSES,
  };
  assert.equal(finalArtifactScanContractReady(finalScanContract), true);
  assert.equal(
    finalArtifactScanContractReady({
      ...finalScanContract,
      canaries: Object.fromEntries(
        FINAL_ARTIFACT_SCAN_CANARY_KEYS.slice(1).map((key) => [key, 'PASS']),
      ),
    }),
    false,
  );
  assert.equal(
    finalArtifactScanContractReady({
      ...finalScanContract,
      dataClasses: [
        FINAL_ARTIFACT_SCAN_DATA_CLASSES[1],
        FINAL_ARTIFACT_SCAN_DATA_CLASSES[0],
        ...FINAL_ARTIFACT_SCAN_DATA_CLASSES.slice(2),
      ],
    }),
    false,
  );
  assert.equal(
    finalArtifactScanContractReady({
      ...finalScanContract,
      command: 'node scripts/stage6/not-the-final-scanner.mjs',
    }),
    false,
  );
  assert.equal(
    finalArtifactScanContractReady({
      ...finalScanContract,
      scope: 'output/evidence/not-runtime',
    }),
    false,
  );
  const defectRow = ({ id, priority, owner = 'QA', state, gate = 'closed' }) =>
    '| `' +
    id +
    '` | Title | ' +
    priority +
    ' | RF-01 | ENV-E6 | steps | expected | evidence | cause | ' +
    owner +
    ' | `' +
    state +
    '` | SHA_BY_SAME_SHA_MANIFEST | regression | re-run | ' +
    gate +
    ' |';
  const verifiedDefects = [
    defectRow({
      id: 'DEF-E6-01',
      priority: 'P1 accessibility',
      state: 'VERIFIED_BY_SAME_SHA_MANIFEST',
    }),
    defectRow({
      id: 'DEF-E6-02',
      priority: 'P1 functional',
      state: 'VERIFIED_BY_SAME_SHA_MANIFEST',
    }),
  ].join('\n');
  assert.equal(defectRegisterReady(verifiedDefects), true);
  assert.equal(
    defectRegisterReady(
      verifiedDefects +
        '\n' +
        defectRow({ id: 'DEF-E6-03', priority: 'P2', owner: '', state: 'OPEN' }),
    ),
    false,
  );
  assert.equal(
    defectRegisterReady(
      verifiedDefects +
        '\n' +
        defectRow({
          id: 'DEF-E6-03',
          priority: 'P2',
          owner: 'QA',
          state: 'ACCEPTED_RISK',
          gate: 'impacto: cosmetic; acceptedUntil=2026-09-01',
        }),
    ),
    true,
  );
  assert.equal(
    defectRegisterReady(
      verifiedDefects +
        '\n' +
        defectRow({
          id: 'DEF-E6-03',
          priority: 'P2',
          owner: 'QA',
          state: 'ACCEPTED_RISK',
          gate: 'missing acceptance metadata',
        }),
    ),
    false,
  );
  assert.equal(expectedArtifactIds.at(-1), 'ART-VER-18');
  assert.equal(new Set(expectedEvidenceIds).size, 40);
  assert.equal(expectedEvidenceIds.at(-1), 'EVD-E6-40');
  assert.equal(new Set(expectedUatIds).size, 48);
  assert.equal(expectedUatIds.at(-1), 'UAT-48');
  assert.equal(new Set(expectedNegativeE2eIds).size, 12);
  assert.equal(expectedNegativeE2eIds.at(-1), 'E2E-E6-24');
  const exactRows = expectedIntegrityIds.map((id) => ({ id, status: 'PASS' }));
  assert.equal(exactPassedMatrix(exactRows, expectedIntegrityIds), true);
  assert.equal(exactPassedMatrix(exactRows.slice(1), expectedIntegrityIds), false);
  assert.equal(
    exactPassedMatrix([...exactRows.slice(0, -1), exactRows[0]], expectedIntegrityIds),
    false,
  );
  assert.equal(
    exactPassedMatrix([exactRows[1], exactRows[0], ...exactRows.slice(2)], expectedIntegrityIds),
    false,
  );
  const rubricEvidence = expectedEvidenceIds.map((id) => ({ id, status: 'PASS' }));
  const rubric = calculateStage6Rubric(rubricEvidence);
  assert.equal(rubricOutputReady(rubric, rubricEvidence), true);
  assert.equal(rubricOutputReady(undefined, rubricEvidence), false);
  assert.equal(
    rubricOutputReady({ ...rubric, baseTotal: { awarded: 101, max: 100 } }, rubricEvidence),
    false,
  );
  const axeSurfaces = ['surface-one', 'surface-two'];
  const axeScans = axeSurfaces.map((surface, index) => ({
    surface,
    status: 'PASS',
    domIdsUnique: true,
    domIdCount: 1,
    violations: [],
    incomplete: index === 0 ? [{ id: 'color-contrast', impact: 'serious', nodeCount: 1 }] : [],
  }));
  const automated = {
    status: 'PASS',
    requiredSurfaces: axeSurfaces,
    surfaceCoverage: '2/2',
    axeScans,
    axeIncompleteCount: 1,
    keyboardDialogContract: 'PASS',
    keyboardFocusContract: 'PASS',
    keyboardFocusCoverage: REQUIRED_KEYBOARD_FOCUS_COVERAGE,
    reducedMotionEmulation: 'PASS',
    blockedExternalRequests: 0,
    unknownApiRequests: 0,
  };
  assert.equal(accessibilityAutomatedMatrixPassed(automated, axeSurfaces), true);
  assert.equal(
    accessibilityAutomatedMatrixPassed({ ...automated, axeScans: axeScans.slice(1) }, axeSurfaces),
    false,
  );
  assert.equal(
    accessibilityAutomatedMatrixPassed(
      { ...automated, axeScans: [axeScans[0], axeScans[0]] },
      axeSurfaces,
    ),
    false,
  );
  assert.equal(
    accessibilityAutomatedMatrixPassed(
      { ...automated, axeScans: [axeScans[1], axeScans[0]] },
      axeSurfaces,
    ),
    false,
  );
  assert.equal(
    accessibilityAutomatedMatrixPassed(
      {
        ...automated,
        axeScans: [
          {
            ...axeScans[0],
            incomplete: [{ id: 'color-contrast', impact: 'serious', nodeCount: 0 }],
          },
          axeScans[1],
        ],
      },
      axeSurfaces,
    ),
    false,
  );
  assert.equal(
    accessibilityAutomatedMatrixPassed(
      { ...automated, keyboardFocusContract: 'FAIL' },
      axeSurfaces,
    ),
    false,
  );
  assert.equal(
    accessibilityAutomatedMatrixPassed(
      { ...automated, keyboardFocusCoverage: undefined },
      axeSurfaces,
    ),
    false,
  );
  assert.equal(
    accessibilityAutomatedMatrixPassed(
      {
        ...automated,
        keyboardFocusCoverage: [
          REQUIRED_KEYBOARD_FOCUS_COVERAGE[1],
          REQUIRED_KEYBOARD_FOCUS_COVERAGE[0],
          ...REQUIRED_KEYBOARD_FOCUS_COVERAGE.slice(2),
        ],
      },
      axeSurfaces,
    ),
    false,
  );
  const envelope = {
    schemaVersion: 1,
    stage: 6,
    runId: 'e6-20260816t120000z-0123abcd',
    environment: 'ENV-E6-CI',
    containsSensitiveData: false,
    commitSha: 'a'.repeat(40),
  };
  const expectedEnvelope = {
    runId: envelope.runId,
    environment: envelope.environment,
    commitSha: envelope.commitSha,
  };
  assert.equal(stage6EnvelopeIsFresh(envelope, expectedEnvelope), true);
  assert.equal(
    stage6EnvelopeIsFresh({ ...envelope, environment: 'ENV-E6-LOCAL' }, expectedEnvelope),
    false,
  );
};

selfTest();
if (process.argv.includes('--self-test')) {
  process.stdout.write('stage-6 closeout self-test: PASS\n');
  process.exit(0);
}

const loadText = (relativePath) => {
  try {
    const value = readFileSync(resolve(workspaceRoot, relativePath), 'utf8').replace(
      /\r\n?/gu,
      '\n',
    );
    return { path: relativePath, state: 'LOADED', value, checksum: sha256(value) };
  } catch (error) {
    return {
      path: relativePath,
      state: error?.code === 'ENOENT' ? 'MISSING' : 'INVALID',
      error: error instanceof Error ? error.message : 'UNREADABLE',
    };
  }
};

const loadJson = (relativePath) => {
  const source = loadText(relativePath);
  if (source.state !== 'LOADED') return source;
  try {
    return { ...source, value: JSON.parse(source.value) };
  } catch {
    return { ...source, state: 'INVALID', error: 'INVALID_JSON' };
  }
};

const orchestration = loadJson('output/evidence/runtime/stage-6/orchestration.json');
const runId =
  process.env.STAGE6_RUN_ID ??
  (orchestration.state === 'LOADED' ? orchestration.value?.runId : undefined) ??
  stage6RunId();
if (!runIdPattern.test(runId)) throw new Error('Stage 6 closeout runId is invalid');

const preflight = loadJson('output/evidence/runtime/stage-6/preflight.json');
const sandbox = loadJson('output/evidence/runtime/stage-6/sandbox.json');
const integrity = loadJson('output/evidence/runtime/stage-6/integrity.json');
const resilience = loadJson('output/evidence/runtime/stage-6/resilience.json');
const compatibility = loadJson('output/evidence/runtime/stage-6/compatibility.json');
const accessibility = loadJson('output/evidence/runtime/stage-6/accessibility.json');
const performanceReport = loadJson('output/evidence/runtime/stage-6/performance.json');
const performanceHtml = loadText('output/evidence/runtime/stage-6/performance-report.html');
const loadReport = loadJson('output/evidence/runtime/stage-6/load.json');
const security = loadJson('output/evidence/runtime/stage-6/security.json');
const uat = loadJson('output/evidence/runtime/stage-6/uat.json');
const finalArtifactScan = loadJson('output/evidence/runtime/stage-6/final-artifact-scan.json');
const apiTests = loadJson('output/evidence/runtime/api-tests.json');
const webTests = loadJson('output/evidence/runtime/web-tests.json');
const dynamodb = loadJson('output/evidence/runtime/stage-5-dynamodb-integration.json');
const smoke = loadJson('output/evidence/runtime/stage-5-smoke-results.json');
const secrets = loadJson('output/evidence/runtime/stage-5-secrets.json');
const dependencies = loadJson('output/evidence/runtime/stage-5-dependencies.json');
const stage5Manifest = loadJson('output/evidence/stage-5/verification-manifest.json');
const stage6Baseline = loadJson('scripts/stage6/baseline.json');
const coveragePolicy = loadJson('scripts/stage6/coverage-policy.json');
const apiCoverage = loadJson('coverage/api/coverage-summary.json');
const webCoverage = loadJson('coverage/web/coverage-summary.json');

const documents = {
  plan: loadText('docs/verification/test-plan.md'),
  environments: loadText('docs/verification/environments.md'),
  traceability: loadText('docs/verification/traceability.md'),
  uat: loadText('docs/verification/uat-results.md'),
  defects: loadText('docs/verification/defects.md'),
  index: loadText('docs/verification/evidence-index.md'),
  rubric: loadText('docs/verification/rubric-scorecard.md'),
  report: loadText('output/etapa-6-integracion-verificacion.md'),
};

const currentCandidate = candidate();
const expectedStage6Environment = process.env.CI === 'true' ? 'ENV-E6-CI' : 'ENV-E6-LOCAL';
const pinnedStage5Baseline =
  stage6Baseline.state === 'LOADED' &&
  stage6Baseline.value?.schemaVersion === 1 &&
  /^[0-9a-f]{40}$/u.test(stage6Baseline.value?.stage5CommitSha ?? '') &&
  /^[0-9a-f]{64}$/u.test(stage6Baseline.value?.stage5ManifestSha256 ?? '') &&
  stage6Baseline.value?.stage5ManifestPath === stage5Manifest.path &&
  stage6Baseline.value?.stage5ManifestSha256 === stage5Manifest.checksum;
const freshStage6 = (source) =>
  source.state === 'LOADED' &&
  stage6EnvelopeIsFresh(source.value, {
    runId,
    commitSha: currentCandidate.commitSha,
    environment: expectedStage6Environment,
  });
const stage6Sources = [
  orchestration,
  preflight,
  sandbox,
  integrity,
  resilience,
  compatibility,
  accessibility,
  performanceReport,
  loadReport,
  security,
  uat,
  finalArtifactScan,
];
const externalExecution = { commitSha: currentCandidate.commitSha, runId };
const externalEvidenceSources = [preflight, sandbox, security, uat];
const externalEvidenceSummaries = externalEvidenceSources.map(
  (source) => source.value?.externalEvidence,
);
const externalEvidenceCrossSourceReady =
  externalEvidenceSources.every(freshStage6) &&
  externalEvidenceSetReady(externalEvidenceSummaries, externalExecution);
const ownedTargetDecision = externalCapabilityDecisionFromSet(
  externalEvidenceSummaries,
  'ownedTarget',
  externalExecution,
);
const sandboxSmokeDecision = externalCapabilityDecisionFromSet(
  externalEvidenceSummaries,
  'sandboxSmoke',
  externalExecution,
);
const passiveSecurityDecision = externalCapabilityDecisionFromSet(
  externalEvidenceSummaries,
  'passiveSecurity',
  externalExecution,
);
const allExternalCapabilitiesPassed = [
  ownedTargetDecision,
  sandboxSmokeDecision,
  passiveSecurityDecision,
].every((decision) => decision === 'PASS');
const authorizationStateForDecision = (decision) =>
  decision === 'PASS'
    ? 'APPROVED_BY_EXTERNAL_VERSIONED_EVIDENCE'
    : decision === 'NOT_RUN_AUTH_REQUIRED'
      ? decision
      : 'REJECTED_INVALID_EXTERNAL_EVIDENCE';
const expectedPreflightExternalState = allExternalCapabilitiesPassed
  ? 'GO_AUTHORIZED_EXTERNAL_EVIDENCE_READY'
  : 'CONDITIONAL_GO_POST_MERGE_CI_GREEN_EXTERNAL_AUTH_BLOCKED';
const preflightExternalContractReady =
  freshStage6(preflight) &&
  preflight.value?.status === 'PASS' &&
  externalEvidenceCrossSourceReady &&
  preflight.value?.entryGate?.state === expectedPreflightExternalState &&
  isDeepStrictEqual(preflight.value?.authorizations, {
    AUTH_E6_01: authorizationStateForDecision(ownedTargetDecision),
    AUTH_E6_02: authorizationStateForDecision(sandboxSmokeDecision),
    AUTH_E6_03: authorizationStateForDecision(passiveSecurityDecision),
    AUTH_E6_04: 'PROHIBITED_WITHOUT_AUTH_E6_04',
  }) &&
  preflight.value?.externalRequests === 0;
const candidateFrozenInCi =
  process.env.CI === 'true' &&
  currentCandidate.workingTree === 'CLEAN' &&
  stage6Sources.every(freshStage6);
const stepById = new Map(
  freshStage6(orchestration) ? orchestration.value.steps.map((step) => [step.id, step]) : [],
);
const stepPassed = (id) => stepById.get(id)?.status === 'PASS';
const stepFailed = (id) => stepById.get(id)?.status === 'FAIL';
const sandboxStep = stepById.get('E6-SANDBOX-EVIDENCE');
const sandboxContractReady =
  freshStage6(sandbox) &&
  externalEvidenceCrossSourceReady &&
  sandboxEvidenceContractReady(sandbox.value, externalEvidenceSummaries[0], externalExecution);
const sandboxPassed =
  sandboxContractReady &&
  sandboxSmokeDecision === 'PASS' &&
  sandboxStep?.status === 'PASS' &&
  sandboxStep?.exitCode === 0;
const sandboxAuthorizationMissing =
  sandboxContractReady &&
  sandboxSmokeDecision === 'NOT_RUN_AUTH_REQUIRED' &&
  sandboxStep?.status === 'PARTIAL' &&
  sandboxStep?.exitCode === 2;
const sandboxFailed =
  sandbox.state === 'LOADED' &&
  (!sandboxContractReady ||
    sandboxSmokeDecision === 'FAIL' ||
    (!sandboxPassed && !sandboxAuthorizationMissing));
const sandboxEvidenceStatus = sandboxFailed
  ? 'FAIL'
  : sandboxPassed
    ? 'PASS'
    : sandboxAuthorizationMissing
      ? 'NOT_RUN_AUTH_REQUIRED'
      : 'FAIL';
const baselinePassed = stepPassed('E6-BASELINE');
const finalArtifactScanPassed =
  freshStage6(finalArtifactScan) &&
  finalArtifactScanContractReady(finalArtifactScan.value) &&
  stepPassed('E6-FINAL-ARTIFACT-SCAN') &&
  finalArtifactScan.value?.status === 'PASS' &&
  finalArtifactScan.value?.sequence === 'AFTER_E6_UAT_BEFORE_CLOSEOUT' &&
  finalArtifactScan.value?.findings === 0 &&
  Number.isInteger(finalArtifactScan.value?.filesScanned) &&
  finalArtifactScan.value.filesScanned > 0 &&
  finalArtifactScan.value?.blockedExternalRequests === 0;
const finalArtifactScanFailed = freshStage6(finalArtifactScan) && !finalArtifactScanPassed;

const exactStringArray = (actual, expected) =>
  Array.isArray(actual) &&
  actual.length === expected.length &&
  actual.every((value, index) => value === expected[index]);
const jestPassed = (source) =>
  source.state === 'LOADED' &&
  source.value?.schemaVersion === 1 &&
  source.value?.status === 'PASS' &&
  source.value?.failedSuites === 0 &&
  source.value?.failedTests === 0 &&
  source.value?.pendingTests === 0 &&
  source.value?.passedSuites === source.value?.suites &&
  source.value?.passedTests === source.value?.tests &&
  source.value?.containsTestPayloads === false;
const coverageMetrics = ['statements', 'branches', 'functions', 'lines'];
const requiredCriticalCoveragePaths = {
  api: [
    './src/application/use-cases/checkout-service.ts',
    './src/domain/checkout/checkout.ts',
    './src/infrastructure/logging/safe-logger.ts',
    './src/infrastructure/persistence/dynamodb-checkout.repository.ts',
    './src/infrastructure/persistence/in-memory-catalog.repository.ts',
    './src/infrastructure/persistence/in-memory-checkout.repository.ts',
    './src/interfaces/http/checkout-http.ts',
  ],
  web: [
    './src/features/checkout/api/checkout-api.ts',
    './src/features/checkout/components/checkout-dialog.tsx',
    './src/features/checkout/model/checkout-slice.ts',
    './src/features/checkout/model/checkout-storage.ts',
    './src/features/checkout/services/submit-payment.ts',
    './src/features/checkout/services/use-transaction-polling.ts',
  ],
};
const coveragePolicyPassed =
  coveragePolicy.state === 'LOADED' &&
  coveragePolicy.value?.schemaVersion === 1 &&
  coverageMetrics.every((metric) => coveragePolicy.value?.minimum?.[metric] === 85) &&
  exactStringArray(coveragePolicy.value?.api, requiredCriticalCoveragePaths.api) &&
  exactStringArray(coveragePolicy.value?.web, requiredCriticalCoveragePaths.web);
const normalizeCoveragePath = (value) => {
  const normalized = String(value).split(String.fromCharCode(92)).join('/');
  return normalized.startsWith('./') ? normalized.slice(2) : normalized;
};
const coverageEntry = (source, application, relativePath) => {
  const suffix = '/apps/' + application + '/' + normalizeCoveragePath(relativePath);
  return Object.entries(source.value ?? {}).find(([path]) =>
    normalizeCoveragePath(path).endsWith(suffix),
  )?.[1];
};
const coveragePassed = (source, application) => {
  const total = source.state === 'LOADED' ? source.value?.total : undefined;
  const paths = requiredCriticalCoveragePaths[application];
  return (
    coveragePolicyPassed &&
    Array.isArray(paths) &&
    total !== undefined &&
    coverageMetrics.every(
      (metric) =>
        typeof total[metric]?.pct === 'number' &&
        total[metric].pct >= coveragePolicy.value.minimum[metric],
    ) &&
    paths.every((path) => {
      const entry = coverageEntry(source, application, path);
      return coverageMetrics.every(
        (metric) =>
          typeof entry?.[metric]?.pct === 'number' &&
          entry[metric].pct >= coveragePolicy.value.minimum[metric],
      );
    })
  );
};
const apiCoveragePassed = coveragePassed(apiCoverage, 'api');
const webCoveragePassed = coveragePassed(webCoverage, 'web');
const smokeIds = new Set(
  smoke.state === 'LOADED' ? (smoke.value?.results ?? []).map((result) => result.id) : [],
);
const smokePassed =
  baselinePassed &&
  smoke.state === 'LOADED' &&
  smoke.value?.schemaVersion === 4 &&
  smoke.value?.exitCode === 0 &&
  smoke.value?.passed === 12 &&
  smoke.value?.total === 12 &&
  smokeIds.size === 12 &&
  expectedUatIds
    .slice(0, 12)
    .every((_, index) => smokeIds.has('SMK-E5-' + String(index + 1).padStart(2, '0'))) &&
  smoke.value.results.every((result) => result.status === 'PASS') &&
  smoke.value?.browserExternalRequests === 0 &&
  smoke.value?.apiExternalRequestsBlocked === 0;
const dynamodbPassed =
  baselinePassed &&
  dynamodb.state === 'LOADED' &&
  dynamodb.value?.status === 'PASS' &&
  dynamodb.value?.endpointLoopback === true &&
  dynamodb.value?.awsExternal === false &&
  dynamodb.value?.passed === dynamodb.value?.tests &&
  dynamodb.value?.lifecycle?.cleanup === 'PASSED';
const matrixPassed = (source, property, expectedIds) =>
  freshStage6(source) &&
  source.value?.status === 'PASS' &&
  exactPassedMatrix(source.value?.[property], expectedIds);
const negativeE2eResults =
  freshStage6(uat) && Array.isArray(uat.value?.negativeE2e) ? uat.value.negativeE2e : [];
const negativeE2eById = new Map(negativeE2eResults.map((result) => [result.id, result]));
const uatNetworkGuardPassed =
  freshStage6(uat) &&
  uat.value?.externalNetworkAttempts === 0 &&
  uat.value?.networkObservation?.apiBlockedMarkers === 0 &&
  uat.value?.networkObservation?.browserBlockedRequests === 0 &&
  uat.value?.networkObservation?.total === 0 &&
  uat.value?.networkObservation?.canary === 'PASS';
const refreshRecoveryResults =
  freshStage6(uat) && Array.isArray(uat.value?.refreshRecovery) ? uat.value.refreshRecovery : [];
const refreshRecoveryPassed =
  uatNetworkGuardPassed &&
  refreshRecoveryMatrixPassed(refreshRecoveryResults, {
    runId,
    commitSha: currentCandidate.commitSha,
    environment: expectedStage6Environment,
  });
const refreshRecoveryFailed = freshStage6(uat) && !refreshRecoveryPassed;
const negativeE2ePassed =
  uatNetworkGuardPassed &&
  negativeE2eMetadataIsExact(negativeE2eResults, {
    runId,
    commitSha: currentCandidate.commitSha,
  }) &&
  negativeE2eResults.every(({ status: resultStatus }) => resultStatus === 'PASS');
const negativeE2eIdPassed = (id) => negativeE2ePassed && negativeE2eById.get(id)?.status === 'PASS';
const integritySupportingPassed =
  matrixPassed(integrity, 'integrity', expectedIntegrityIds) &&
  matrixPassed(integrity, 'negative', expectedNegativeE2eIds) &&
  matrixPassed(integrity, 'uat14', expectedUat14FixtureIds) &&
  [...integrity.value.integrity, ...integrity.value.negative, ...integrity.value.uat14].every(
    (result) => result.verificationLayer === 'unit-integration-supporting-evidence',
  ) &&
  integrity.value?.suiteFailures === 0;
const integrityPassed = integritySupportingPassed && negativeE2ePassed;
const resiliencePassed =
  matrixPassed(resilience, 'results', expectedResilienceIds) &&
  resilience.value?.suiteFailures === 0;
const integrityIdPassed = (id) =>
  integritySupportingPassed && integrity.value.integrity.some((result) => result.id === id);

const requiredCompatibilityEngines = ['chromium', 'firefox', 'webkit'];
const requiredCompatibilityViewports = Array.from(
  { length: 7 },
  (_, index) => 'UXVP-' + String(index + 1).padStart(2, '0'),
);
const requiredCompatibilityJourneyStates = [
  'product',
  'capture-payment',
  'capture-validation',
  'summary',
  'pending',
  'unknown',
  'approved',
  'failed-declined',
];
const browserResults =
  freshStage6(compatibility) && Array.isArray(compatibility.value?.results)
    ? compatibility.value.results
    : [];
const compatibilityFailed = browserResults.some((result) => result.status === 'FAIL');
const compatibilityPassed =
  freshStage6(compatibility) &&
  compatibility.value?.status === 'PASS' &&
  exactStringArray(compatibility.value?.requiredEngines, requiredCompatibilityEngines) &&
  exactStringArray(
    compatibility.value?.requiredViewports?.map((viewport) => viewport.id),
    requiredCompatibilityViewports,
  ) &&
  exactStringArray(
    compatibility.value?.requiredJourneyStates,
    requiredCompatibilityJourneyStates,
  ) &&
  browserResults.length === requiredCompatibilityEngines.length &&
  browserResults.every(
    (result, index) =>
      result.id === requiredCompatibilityEngines[index] &&
      result.status === 'PASS' &&
      exactStringArray(
        result.viewports?.map((viewport) => viewport.id),
        requiredCompatibilityViewports,
      ) &&
      result.viewports.every(
        (viewport) =>
          viewport.status === 'PASS' &&
          viewport.horizontalOverflowPx === 0 &&
          viewport.minimumMeasuredTargetPx >= 48 &&
          viewport.blockedExternalRequests === 0 &&
          viewport.unknownApiRequests === 0,
      ) &&
      result.journey?.status === 'PASS' &&
      result.journey?.inventory?.complete === true &&
      exactStringArray(result.journey.inventory.required, requiredCompatibilityJourneyStates) &&
      exactStringArray(result.journey.inventory.observed, requiredCompatibilityJourneyStates) &&
      exactStringArray(
        result.journey.states?.map((state) => state.id),
        requiredCompatibilityJourneyStates,
      ) &&
      result.journey.states.every(
        (state) =>
          state.status === 'PASS' &&
          state.hasText === true &&
          state.documentOverflowPx === 0 &&
          state.dialogBodyOverflowPx === 0,
      ) &&
      result.journey.pageErrors === 0 &&
      result.journey.blockedExternalRequests === 0 &&
      result.journey.unknownApiRequests === 0,
  ) &&
  compatibility.value?.summary?.enginesPassed === 3 &&
  compatibility.value?.summary?.enginesRequired === 3 &&
  compatibility.value?.summary?.responsiveCasesPassed === 21 &&
  compatibility.value?.summary?.responsiveCasesExecuted === 21 &&
  compatibility.value?.summary?.journeyInventoriesComplete === 3 &&
  compatibility.value?.summary?.journeyInventoriesRequired === 3 &&
  compatibility.value?.summary?.journeyStatesPassed === 24 &&
  compatibility.value?.summary?.journeyStatesRequired === 24;
const viewportsPassed = compatibilityPassed;

const requiredAccessibilitySurfaces = [
  'product',
  'checkout-payment',
  'payment-validation',
  'checkout-customer',
  'customer-validation',
  'checkout-acceptances',
  'acceptances-validation',
  'checkout-summary',
  'transaction-pending',
  'transaction-unknown',
  'transaction-approved',
  'transaction-declined',
  'transaction-error',
  'transaction-network-error',
];
const accessibilityAutomatedPassed =
  freshStage6(accessibility) &&
  accessibilityAutomatedMatrixPassed(accessibility.value?.automated, requiredAccessibilitySurfaces);
const accessibilityManualMissing =
  freshStage6(accessibility) &&
  accessibility.value?.status === 'PARTIAL_NOT_RUN_MANUAL_REQUIRED' &&
  accessibilityAutomatedPassed &&
  accessibility.value?.manualEvidence?.status === 'NOT_RUN_MANUAL_REQUIRED' &&
  accessibility.value.manualEvidence?.reason === 'MANUAL_EVIDENCE_NOT_PROVIDED' &&
  accessibility.value.manualEvidence?.containsSensitiveData === false;
const accessibilityManualPassed =
  accessibilityAutomatedPassed &&
  accessibility.value?.status === 'PASS' &&
  validateManualEvidenceSummary(
    accessibility.value?.manualEvidence,
    accessibility.value?.automated?.axeScans,
    { commitSha: currentCandidate.commitSha, runId },
  );
const accessibilityManualInvalid =
  freshStage6(accessibility) && !accessibilityManualMissing && !accessibilityManualPassed;
const accessibilityFailed =
  freshStage6(accessibility) &&
  (accessibility.value?.status === 'FAIL' ||
    accessibility.value?.automated?.status === 'FAIL' ||
    (accessibility.value?.automated?.status === 'PASS' && !accessibilityAutomatedPassed) ||
    accessibilityManualInvalid);

const performanceHtmlPassed =
  freshStage6(performanceReport) &&
  performanceHtml.state === 'LOADED' &&
  performanceReport.value?.sanitizedHtml?.path === performanceHtml.path &&
  performanceReport.value?.sanitizedHtml?.sha256 === performanceHtml.checksum &&
  performanceReport.value?.sanitizedHtml?.containsSensitiveData === false &&
  performanceReport.value?.sanitizedHtml?.rawArtifactsPersisted === false &&
  performanceHtml.value.includes(runId) &&
  performanceHtml.value.includes(currentCandidate.commitSha) &&
  !/<script\b|https?:\/\//iu.test(performanceHtml.value);
const performancePassed =
  freshStage6(performanceReport) &&
  validatePerformanceEvidence(performanceReport.value) &&
  performanceHtmlPassed;
const performanceFailed = freshStage6(performanceReport) && !performancePassed;
const loadPassed = freshStage6(loadReport) && validateLoadEvidence(loadReport.value);
const loadFailed = freshStage6(loadReport) && !loadPassed;
const securityLocalPassed = freshStage6(security) && validateSecurityEvidence(security.value);
const securityLocalFailed = freshStage6(security) && !securityLocalPassed;
const passiveSecurityPassed =
  securityLocalPassed && externalEvidenceCrossSourceReady && passiveSecurityDecision === 'PASS';
const passiveSecurityAuthorizationMissing =
  securityLocalPassed &&
  externalEvidenceCrossSourceReady &&
  passiveSecurityDecision === 'NOT_RUN_AUTH_REQUIRED';
const passiveSecurityFailed =
  security.state === 'LOADED' &&
  (!securityLocalPassed || !externalEvidenceCrossSourceReady || passiveSecurityDecision === 'FAIL');
const passiveSecurityEvidenceStatus = passiveSecurityFailed
  ? 'FAIL'
  : passiveSecurityPassed
    ? 'PASS'
    : passiveSecurityAuthorizationMissing
      ? 'NOT_RUN_AUTH_REQUIRED'
      : 'FAIL';
const fullDependencyAudit = stepById.get('E6-FULL-DEPENDENCY-AUDIT');
const fullDependencyAuditPassed =
  fullDependencyAudit?.status === 'PASS' &&
  fullDependencyAudit?.audit?.scope === 'development-and-production' &&
  fullDependencyAudit?.audit?.threshold === 'high' &&
  fullDependencyAudit?.audit?.status === 'PASS' &&
  fullDependencyAudit?.audit?.vulnerabilities?.high === 0 &&
  fullDependencyAudit?.audit?.vulnerabilities?.critical === 0;
const fullDependencyAuditFailed =
  fullDependencyAudit?.status === 'FAIL' ||
  (fullDependencyAudit !== undefined && fullDependencyAudit?.audit?.status !== 'PASS');
const dependencyAuditPassed =
  baselinePassed &&
  fullDependencyAuditPassed &&
  dependencies.state === 'LOADED' &&
  dependencies.value?.status === 'PASS' &&
  dependencies.value?.vulnerabilities?.high === 0 &&
  dependencies.value?.vulnerabilities?.critical === 0;
const dependencyAuditFailed =
  fullDependencyAuditFailed ||
  (dependencies.state === 'LOADED' &&
    (dependencies.value?.status === 'FAIL' ||
      dependencies.value?.vulnerabilities?.high > 0 ||
      dependencies.value?.vulnerabilities?.critical > 0));
const sastCheck = freshStage6(security)
  ? security.value?.externalChecks?.find((check) => check.name === 'codeql-sast')
  : undefined;
const sastStatus = sastCheck?.status;
const sastPassed =
  process.env.CI === 'true' &&
  sastStatus === 'PASS' &&
  sastCheck?.source === 'same-workflow-sarif-gate' &&
  sastCheck?.commitSha === currentCandidate.commitSha &&
  sastCheck?.analysisResult === 'success' &&
  sastCheck?.sarifStatus === 'PASS' &&
  sastCheck?.high === 0 &&
  sastCheck?.critical === 0 &&
  /^[0-9a-f]{64}$/u.test(sastCheck?.sarifSha256 ?? '');
const sastFailed = sastStatus === 'FAIL' || (sastStatus === 'PASS' && !sastPassed);
const secretScanPassed =
  baselinePassed &&
  secrets.state === 'LOADED' &&
  secrets.value?.status === 'PASS' &&
  secrets.value?.findings === 0 &&
  secrets.value?.history === 'PASS';
const secretScanFailed =
  secrets.state === 'LOADED' &&
  (secrets.value?.status === 'FAIL' ||
    secrets.value?.findings > 0 ||
    secrets.value?.history === 'FAIL');
const noRetries =
  freshStage6(orchestration) &&
  orchestration.value?.retriesUsed === 0 &&
  orchestration.value?.steps?.every((step) => step.retryCount === 0 && step.status !== 'FAIL');

const nonEmptyStrings = (value) =>
  Array.isArray(value)
    ? value.filter((entry) => typeof entry === 'string' && entry.trim().length > 0)
    : [];
const uatSourceResults =
  freshStage6(uat) && Array.isArray(uat.value?.results) ? uat.value.results : [];
const uatById = new Map(uatSourceResults.map((result) => [result.id, result]));
const uat33Source = uatById.get('UAT-33');
const uat33EvidenceIds = ['EVD-E6-36/UAT-33', 'AUTH-E6-01', 'EXTERNAL_VERSIONED_JSON'];
const expectedUat33Status =
  ownedTargetDecision === 'PASS'
    ? 'PASS'
    : ownedTargetDecision === 'NOT_RUN_AUTH_REQUIRED'
      ? 'NOT_RUN_AUTH_REQUIRED'
      : 'FAIL';
const expectedUat33RunnerRole =
  expectedUat33Status === 'PASS' ? 'INDEPENDENT_EXTERNAL_EVIDENCE_REVIEWER' : 'AUTH_GATE';
const uat33ExternalContractReady =
  freshStage6(uat) &&
  externalEvidenceCrossSourceReady &&
  uat.value?.externalEvidenceIngestionNetworkAttempts === 0 &&
  uat33Source?.status === expectedUat33Status &&
  uat33Source?.runnerRole === expectedUat33RunnerRole &&
  uat33Source?.runnerPersona === 'QA_INDEPENDENT_UAT_RUNNER' &&
  uat33Source?.executionScope === 'AUTHORIZED_OWNED_EPHEMERAL_QA_EXTERNAL_EVIDENCE' &&
  uat33Source?.runId === runId &&
  uat33Source?.commitSha === currentCandidate.commitSha &&
  uat33Source?.environment === expectedStage6Environment &&
  exactStringInventory(uat33Source?.evidence, uat33EvidenceIds) &&
  exactStringInventory(uat33Source?.evidenceIds, uat33EvidenceIds);
const uatExact =
  uatSourceResults.length === 48 &&
  uatById.size === 48 &&
  expectedUatIds.every((id) => uatById.has(id));
const uatMatrix = expectedUatIds.map((id) => {
  const original = uatById.get(id);
  const priority = original?.priority ?? 'UNKNOWN';
  if (original === undefined) {
    return {
      id,
      priority,
      status: 'BLOCKED',
      reason: 'UAT_EVIDENCE_MISSING',
      observableResult: 'UNAVAILABLE',
      runnerRole: 'UNAVAILABLE',
      evidence: [],
      evidenceIds: [],
    };
  }
  const evidence = nonEmptyStrings(original.evidence);
  const evidenceIds = nonEmptyStrings(original.evidenceIds);
  const observableResult = original.observableResult;
  const runnerRole = original.runnerRole;
  const status = original.status;
  const allowed =
    status === 'PASS' ||
    status === 'FAIL' ||
    (id === 'UAT-16' && status === 'NOT_RUN_MANUAL_REQUIRED') ||
    (id === 'UAT-33' && status === 'NOT_RUN_AUTH_REQUIRED');
  const rowValid =
    allowed &&
    ['P0', 'P1', 'P2'].includes(priority) &&
    typeof observableResult === 'string' &&
    observableResult.trim().length > 0 &&
    typeof runnerRole === 'string' &&
    runnerRole.trim().length > 0 &&
    evidence.length > 0 &&
    evidenceIds.length > 0;
  return {
    id,
    priority,
    status: rowValid ? status : 'FAIL',
    reason: rowValid ? original.reason : 'INVALID_UAT_STATUS_OR_EVIDENCE',
    observableResult,
    runnerRole,
    evidence,
    evidenceIds,
  };
});
const uatValid =
  uatExact &&
  uatNetworkGuardPassed &&
  refreshRecoveryPassed &&
  uat33ExternalContractReady &&
  uatMatrix.every(
    (result) =>
      result.status === 'PASS' ||
      (result.id === 'UAT-16' && result.status === 'NOT_RUN_MANUAL_REQUIRED') ||
      (result.id === 'UAT-33' && result.status === 'NOT_RUN_AUTH_REQUIRED'),
  );
const uatAllPassed = uatValid && uatMatrix.every((result) => result.status === 'PASS');
const uatApprovedWithOnlyAuthOpen =
  uatValid &&
  uatMatrix.every(
    (result) =>
      result.status === 'PASS' ||
      (result.id === 'UAT-33' && result.status === 'NOT_RUN_AUTH_REQUIRED'),
  );
const uatFailed =
  freshStage6(uat) &&
  (!uatExact ||
    !uatNetworkGuardPassed ||
    !refreshRecoveryPassed ||
    !uat33ExternalContractReady ||
    uat.value?.status === 'FAIL' ||
    uatMatrix.some((result) => result.status === 'FAIL'));

const readyHeader = (document, expected) => {
  if (document.state !== 'LOADED') return false;
  const header = document.value.split('\n').slice(0, 18).join('\n');
  return expected.some((status) => header.includes('`' + status + '`'));
};
const authorityReady = (document, artifactId) => {
  if (document.state !== 'LOADED' || !finalAuthorityText(document.value)) return false;
  const marker = `<!-- stage6-status-authority: ${artifactId} SAME_SHA_RUNTIME_MANIFEST -->`;
  return document.value.split(marker).length === 2;
};
const expectedTraceSliceIds = Array.from(
  { length: 13 },
  (_, index) => 'SLI-E5-' + String(index + 1).padStart(2, '0'),
);
const expectedRubricIds = [
  ...Array.from({ length: 6 }, (_, index) => 'RUB-BASE-' + String(index + 1).padStart(2, '0')),
  ...Array.from({ length: 6 }, (_, index) => 'RUB-BONUS-' + String(index + 1).padStart(2, '0')),
];
const defectRowsClosed =
  documents.defects.state === 'LOADED' && defectRegisterReady(documents.defects.value);
const reportHeadingNumbers =
  documents.report.state === 'LOADED'
    ? [...documents.report.value.matchAll(/^## (\d+)\./gmu)].map((match) => Number(match[1]))
    : [];
const reportRunIds =
  documents.report.state === 'LOADED'
    ? new Set(documents.report.value.match(/\be6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}\b/gu) ?? [])
    : new Set();
const reportShaLiterals =
  documents.report.state === 'LOADED'
    ? new Set(documents.report.value.match(/\b[0-9a-f]{40}\b/giu) ?? [])
    : new Set();
const reportHeadingsReady =
  documents.report.state === 'LOADED' &&
  authorityReady(documents.report, 'ART-VER-18') &&
  reportAuthorityReady(documents.report.value) &&
  reportHeadingNumbers.length === 27 &&
  reportHeadingNumbers.every((value, index) => value === index + 1) &&
  reportRunIds.size === 0 &&
  reportShaLiterals.size === 0 &&
  documents.report.value.includes('RUN_ID_BY_SAME_SHA_MANIFEST') &&
  documents.report.value.includes('SHA_BY_SAME_SHA_MANIFEST');
const planReady =
  authorityReady(documents.plan, 'ART-VER-01') &&
  readyHeader(documents.plan, ['APPROVED_BY_SAME_SHA_MANIFEST', 'APPROVED']);
const environmentDeclared = readyHeader(documents.environments, [
  'FROZEN_BY_SAME_SHA_MANIFEST',
  'FROZEN',
]);
const environmentDocumentReady =
  authorityReady(documents.environments, 'ART-VER-02') && environmentDeclared;
const environmentReady = environmentDocumentReady && candidateFrozenInCi;
const traceabilityReady =
  authorityReady(documents.traceability, 'ART-VER-03') &&
  readyHeader(documents.traceability, ['COMPLETE_BY_SAME_SHA_MANIFEST', 'COMPLETE']) &&
  canonicalRowsAuthorized({
    text: documents.traceability.value,
    pattern: /^\|\s*`(SLI-E5-\d{2})`\s*\|/u,
    expectedIds: expectedTraceSliceIds,
    expectedStatuses: expectedTraceSliceIds.map(() => 'COMPLETE_BY_SAME_SHA_MANIFEST'),
    statusColumnIndex: 6,
    expectedAuthorityToken: 'COMPLETE_BY_SAME_SHA_MANIFEST',
  });
const uatDocumentReady =
  authorityReady(documents.uat, 'ART-VER-14') &&
  readyHeader(documents.uat, ['STATUS_BY_SAME_SHA_MANIFEST', 'APPROVED']) &&
  canonicalRowsAuthorized({
    text: documents.uat.value,
    pattern: /^\|\s*`(UAT-\d{2})`\s*\|/u,
    expectedIds: expectedUatIds,
    expectedStatuses: expectedUatIds.map(() => 'STATUS_BY_SAME_SHA_MANIFEST'),
    expectedAuthorityToken: 'STATUS_BY_SAME_SHA_MANIFEST',
    statusColumnIndex: 7,
  });
const defectsDeclared = readyHeader(documents.defects, [
  'CLOSED_OR_ACCEPTED_BY_SAME_SHA_MANIFEST',
  'CLOSED_OR_ACCEPTED',
]);
const defectRegressionSameSha =
  candidateFrozenInCi && baselinePassed && accessibilityAutomatedPassed;
const defectsDocumentReady =
  authorityReady(documents.defects, 'ART-VER-15') && defectsDeclared && defectRowsClosed;
const defectsReady = defectsDocumentReady && defectRegressionSameSha;
const indexReady =
  authorityReady(documents.index, 'ART-VER-16') &&
  readyHeader(documents.index, ['COMPLETE_BY_SAME_SHA_MANIFEST', 'COMPLETE']) &&
  canonicalRowsAuthorized({
    text: documents.index.value,
    pattern: /^\|\s*`(EVD-E6-\d{2})`\s*\|/u,
    expectedIds: expectedEvidenceIds,
    expectedStatuses: expectedEvidenceIds.map(() => 'COMPLETE_BY_SAME_SHA_MANIFEST'),
    statusColumnIndex: 3,
    expectedAuthorityToken: 'COMPLETE_BY_SAME_SHA_MANIFEST',
  }) &&
  canonicalRowsAuthorized({
    text: documents.index.value,
    pattern: /^\|\s*`(ART-VER-\d{2})`\s*\|/u,
    expectedIds: expectedArtifactIds,
    expectedAuthorityToken: 'COMPLETE_BY_SAME_SHA_MANIFEST',
    expectedStatuses: expectedArtifactIds.map(() => 'COMPLETE_BY_SAME_SHA_MANIFEST'),
    statusColumnIndex: 3,
  });
const rubricDocumentReady =
  authorityReady(documents.rubric, 'ART-VER-17') &&
  readyHeader(documents.rubric, ['CALCULATED_BY_SAME_SHA_MANIFEST', 'APPROVED']) &&
  canonicalRowsAuthorized({
    text: documents.rubric.value,
    pattern: /^\|\s*`(RUB-(?:BASE|BONUS)-\d{2})`\s*\|/u,
    expectedIds: expectedRubricIds,
    expectedStatuses: expectedRubricIds.map(() => 'CALCULATED_BY_SAME_SHA_MANIFEST'),
    expectedAuthorityToken: 'CALCULATED_BY_SAME_SHA_MANIFEST',
    statusColumnIndex: 5,
  });
const requiredDocumentsValid =
  Object.values(documents).every(({ state }) => state === 'LOADED') &&
  planReady &&
  environmentDocumentReady &&
  traceabilityReady &&
  uatDocumentReady &&
  defectsDocumentReady &&
  indexReady &&
  rubricDocumentReady &&
  reportHeadingsReady;
let rubricReady = rubricDocumentReady;

const reference = (source) => ({
  path: source.path,
  checksum: source.state === 'LOADED' ? source.checksum : undefined,
  sourceState: source.state,
});
const status = (passed, failed = false, blocked = 'BLOCKED') =>
  failed ? 'FAIL' : passed ? 'PASS' : blocked;
const evidenceRow = (id, value, sources, detail) => ({
  id,
  status: value,
  detail,
  sources: sources.map(reference),
});

const evidence = [
  evidenceRow(
    'EVD-E6-01',
    status(
      preflightExternalContractReady &&
        pinnedStage5Baseline &&
        preflight.value?.entryGate?.stage5Head === stage6Baseline.value.stage5CommitSha &&
        preflight.value?.entryGate?.stage5ManifestSha256 ===
          stage6Baseline.value.stage5ManifestSha256 &&
        preflight.value?.entryGate?.candidateDescendsFromStage5 === true,
    ),
    [preflight, stage6Baseline, stage5Manifest, loadText('docs/verification/stage6-intake.md')],
    'GATE-E5-03 reconciled through CHG-E6-01',
  ),
  evidenceRow(
    'EVD-E6-02',
    status(candidateFrozenInCi && preflight.value?.lockfileSha256 !== undefined),
    [preflight],
    'Candidate SHA, tree and lockfile freeze',
  ),
  evidenceRow(
    'EVD-E6-03',
    status(candidateFrozenInCi && baselinePassed),
    [orchestration, preflight],
    'Fresh checkout plus frozen install is only asserted inside CI',
  ),
  evidenceRow('EVD-E6-04', status(baselinePassed), [orchestration], 'Static and build baseline'),
  evidenceRow(
    'EVD-E6-05',
    status(
      baselinePassed &&
        stage5Manifest.state === 'LOADED' &&
        stage5Manifest.value?.contracts?.generatedTypes === 'MATCH',
    ),
    [orchestration, stage5Manifest],
    'OpenAPI validation and generated client drift',
  ),
  evidenceRow('EVD-E6-06', status(baselinePassed && jestPassed(webTests)), [webTests], 'Web unit'),
  evidenceRow('EVD-E6-07', status(baselinePassed && jestPassed(apiTests)), [apiTests], 'API unit'),
  evidenceRow(
    'EVD-E6-08',
    status(baselinePassed && webCoveragePassed),
    [webCoverage, coveragePolicy],
    'Web global and critical-path coverage x4 >= 85%',
  ),
  evidenceRow(
    'EVD-E6-09',
    status(baselinePassed && apiCoveragePassed),
    [apiCoverage, coveragePolicy],
    'API global and critical-path coverage x4 >= 85%',
  ),
  evidenceRow(
    'EVD-E6-10',
    status(integrityPassed),
    [integrity, uat],
    'Unit/integration support plus negative black-box 12/12',
  ),
  evidenceRow(
    'EVD-E6-11',
    status(dynamodbPassed && integritySupportingPassed),
    [dynamodb, integrity],
    'Repositories and transactions',
  ),
  evidenceRow(
    'EVD-E6-12',
    status(baselinePassed && integritySupportingPassed),
    [orchestration, integrity],
    'Fake/provider contracts',
  ),
  evidenceRow(
    'EVD-E6-13',
    status(smokePassed && negativeE2ePassed),
    [smoke, uat],
    'SMK-E5-01..12 plus E2E-E6-13..24 black-box',
  ),
  evidenceRow('EVD-E6-14', status(smokePassed), [smoke], 'SMK-E5-01..12'),
  evidenceRow(
    'EVD-E6-15',
    status(integrityIdPassed('INT-E6-05')),
    [integrity],
    'Atomic unique approval',
  ),
  evidenceRow(
    'EVD-E6-16',
    status(integrityIdPassed('INT-E6-06')),
    [integrity],
    'Failure releases without delivery',
  ),
  evidenceRow('EVD-E6-17', status(resiliencePassed), [resilience], 'Timeout and unknown recovery'),
  evidenceRow(
    'EVD-E6-18',
    status(['INT-E6-02', 'INT-E6-03', 'INT-E6-04'].every((id) => integrityIdPassed(id))),
    [integrity],
    'Double submit and replay',
  ),
  evidenceRow(
    'EVD-E6-19',
    status(integrityIdPassed('INT-E6-01')),
    [integrity, loadReport],
    'Last-stock concurrency',
  ),
  evidenceRow(
    'EVD-E6-20',
    status(integrityIdPassed('INT-E6-10') && negativeE2eIdPassed('E2E-E6-13')),
    [integrity, uat],
    'Expired or manipulated quote',
  ),
  evidenceRow(
    'EVD-E6-21',
    status(refreshRecoveryPassed, refreshRecoveryFailed),
    [uat],
    'REFRESH-E6-01..08 exact public refresh/reopen matrix',
  ),
  evidenceRow(
    'EVD-E6-22',
    status(smokePassed && resiliencePassed),
    [smoke, resilience],
    'Refresh while pending',
  ),
  evidenceRow(
    'EVD-E6-23',
    status(integrityIdPassed('INT-E6-11') && negativeE2eIdPassed('E2E-E6-19')),
    [integrity, uat],
    'Multitab active transaction',
  ),
  evidenceRow(
    'EVD-E6-24',
    sandboxEvidenceStatus,
    [sandbox, preflight],
    sandboxPassed
      ? 'AUTH-E6-02 sandbox smoke verified by external versioned evidence'
      : sandboxAuthorizationMissing
        ? 'Sandbox smoke requires AUTH-E6-02; no external request was made'
        : 'Sandbox evidence was missing, stale, inconsistent or invalid',
  ),
  evidenceRow(
    'EVD-E6-25',
    status(compatibilityPassed, compatibilityFailed, 'NOT_RUN_ENV_REQUIRED'),
    [compatibility],
    'Chromium, Firefox and WebKit',
  ),
  evidenceRow(
    'EVD-E6-26',
    status(viewportsPassed, compatibilityFailed),
    [compatibility],
    'UXVP-01..07',
  ),
  evidenceRow(
    'EVD-E6-27',
    status(accessibilityAutomatedPassed, accessibilityFailed),
    [accessibility],
    'Automated axe scans',
  ),
  evidenceRow(
    'EVD-E6-28',
    status(
      accessibilityAutomatedPassed && accessibilityManualPassed,
      accessibilityFailed,
      'NOT_RUN_MANUAL_REQUIRED',
    ),
    [accessibility],
    'Keyboard, focus and manual assistive-technology review',
  ),
  evidenceRow(
    'EVD-E6-29',
    status(performancePassed, performanceFailed, 'NOT_RUN_ENV_REQUIRED'),
    [performanceReport, performanceHtml],
    'Lighthouse and approved laboratory budgets',
  ),
  evidenceRow(
    'EVD-E6-30',
    status(loadPassed, loadFailed),
    [loadReport],
    'Bounded local load and rate limit',
  ),
  evidenceRow(
    'EVD-E6-31',
    status(
      secretScanPassed && finalArtifactScanPassed,
      secretScanFailed || finalArtifactScanFailed,
    ),
    [secrets, security, finalArtifactScan],
    'Tree and full-history secret scan',
  ),
  evidenceRow(
    'EVD-E6-32',
    dependencyAuditFailed || sastFailed
      ? 'FAIL'
      : dependencyAuditPassed && sastPassed
        ? 'PASS'
        : dependencyAuditPassed
          ? 'PENDING_CI'
          : 'BLOCKED',
    [dependencies, orchestration, security],
    dependencyAuditPassed && !sastPassed
      ? 'Full dev+prod dependency audit and IaC checks passed; CodeQL awaits remote same-SHA execution'
      : 'Dependency, IaC and SAST evidence is incomplete',
  ),
  evidenceRow(
    'EVD-E6-33',
    passiveSecurityEvidenceStatus,
    [security, preflight],
    passiveSecurityPassed
      ? 'AUTH-E6-03 passive ZAP baseline on the owned QA target'
      : passiveSecurityAuthorizationMissing
        ? 'ZAP baseline requires AUTH-E6-03 for an owned QA target'
        : 'Passive ZAP evidence was missing, stale, inconsistent or invalid',
  ),
  evidenceRow(
    'EVD-E6-34',
    passiveSecurityEvidenceStatus,
    [security, preflight],
    passiveSecurityPassed
      ? 'Local controls plus AUTH-E6-03 QA edge headers'
      : passiveSecurityAuthorizationMissing
        ? 'Local controls passed; QA edge headers require AUTH-E6-03'
        : 'Local or authorized QA edge-header evidence failed validation',
  ),
  evidenceRow(
    'EVD-E6-35',
    status(
      securityLocalPassed && finalArtifactScanPassed,
      securityLocalFailed || finalArtifactScanFailed,
    ),
    [security, finalArtifactScan],
    'Storage, log and network controls',
  ),
  evidenceRow(
    'EVD-E6-36',
    uatFailed
      ? 'FAIL'
      : uatAllPassed
        ? 'PASS'
        : uatApprovedWithOnlyAuthOpen
          ? 'NOT_RUN_AUTH_REQUIRED'
          : uatValid
            ? 'PARTIAL_NOT_RUN_REQUIRED'
            : 'BLOCKED',
    [uat],
    'Individual UAT-01..48 matrix; NOT_RUN never counts as PASS',
  ),
  evidenceRow('EVD-E6-37', status(defectsReady), [documents.defects], 'No open P0/P1'),
  evidenceRow(
    'EVD-E6-38',
    status(noRetries),
    [orchestration, documents.defects],
    'Zero critical retries/flaky passes',
  ),
  evidenceRow('EVD-E6-39', status(rubricReady), [documents.rubric], 'Base and bonus scorecard'),
];

const evidenceById = new Map(evidence.map((entry) => [entry.id, entry]));
const artifact = (id, value, path, sources, detail) => ({
  id,
  status: value,
  path,
  detail,
  sources: sources.map(reference),
});
const artifacts = [
  artifact(
    'ART-VER-01',
    planReady ? 'APPROVED' : 'BLOCKED',
    documents.plan.path,
    [documents.plan],
    'Master verification plan',
  ),
  artifact(
    'ART-VER-02',
    environmentReady ? 'FROZEN' : 'BLOCKED',
    documents.environments.path,
    [documents.environments, preflight],
    'Environment and candidate baseline',
  ),
  artifact(
    'ART-VER-03',
    traceabilityReady ? 'COMPLETE' : 'BLOCKED',
    documents.traceability.path,
    [documents.traceability],
    'Requirement-test-evidence traceability',
  ),
  artifact(
    'ART-VER-04',
    baselinePassed ? 'GREEN' : stepFailed('E6-BASELINE') ? 'FAILED' : 'BLOCKED',
    'output/evidence/runtime/',
    [orchestration, apiTests, webTests, dynamodb],
    'Unit, integration and contract reports',
  ),
  artifact(
    'ART-VER-05',
    baselinePassed && apiCoveragePassed && webCoveragePassed
      ? 'GREEN'
      : stepFailed('E6-BASELINE')
        ? 'FAILED'
        : 'BLOCKED',
    'coverage/',
    [apiCoverage, webCoverage, coveragePolicy],
    'Coverage summaries with exact critical-path policy',
  ),
  artifact(
    'ART-VER-06',
    smokePassed && negativeE2ePassed
      ? 'GREEN'
      : stepFailed('E6-BASELINE') || uatFailed
        ? 'FAILED'
        : 'BLOCKED',
    smoke.path,
    [smoke, uat],
    'Fake E2E suite 24/24: SMK-E5-01..12 plus E2E-E6-13..24',
  ),
  artifact(
    'ART-VER-07',
    sandboxPassed ? 'GREEN' : sandboxAuthorizationMissing ? 'NOT_RUN_AUTH_REQUIRED' : 'FAILED',
    sandbox.path,
    [sandbox, preflight],
    sandboxPassed
      ? 'AUTH-E6-02 sandbox evidence verified'
      : sandboxAuthorizationMissing
        ? 'No sandbox authorization; no request was made'
        : 'Sandbox evidence contract failed',
  ),
  artifact(
    'ART-VER-08',
    integrityPassed && resiliencePassed
      ? 'GREEN'
      : stepFailed('E6-INTEGRITY')
        ? 'FAILED'
        : 'BLOCKED',
    integrity.path,
    [integrity, resilience, uat],
    'Integrity support plus negative black-box 12/12 and resilience',
  ),
  artifact(
    'ART-VER-09',
    compatibilityPassed && viewportsPassed ? 'GREEN' : compatibilityFailed ? 'FAILED' : 'BLOCKED',
    compatibility.path,
    [compatibility],
    'Cross-browser and responsive',
  ),
  artifact(
    'ART-VER-10',
    accessibilityAutomatedPassed && accessibilityManualPassed
      ? 'GREEN'
      : accessibilityFailed
        ? 'FAILED'
        : 'BLOCKED',
    accessibility.path,
    [accessibility],
    'Accessibility, including manual review',
  ),
  artifact(
    'ART-VER-11',
    performancePassed && loadPassed
      ? 'GREEN'
      : performanceFailed || loadFailed
        ? 'FAILED'
        : 'BLOCKED',
    performanceReport.path,
    [performanceReport, performanceHtml, loadReport],
    'Performance and bounded local load',
  ),
  artifact(
    'ART-VER-12',
    securityLocalPassed && evidenceById.get('EVD-E6-32')?.status === 'PASS'
      ? 'GREEN'
      : securityLocalFailed || dependencyAuditFailed || sastFailed
        ? 'FAILED'
        : 'BLOCKED',
    security.path,
    [security, dependencies],
    'Security and privacy',
  ),
  artifact(
    'ART-VER-13',
    securityLocalPassed ? 'VERIFIED' : securityLocalFailed ? 'FAILED' : 'BLOCKED',
    security.path,
    [security, apiTests],
    'Local observability and redaction controls',
  ),
  artifact(
    'ART-VER-14',
    uatApprovedWithOnlyAuthOpen && uatDocumentReady ? 'APPROVED' : uatFailed ? 'FAILED' : 'BLOCKED',
    documents.uat.path,
    [documents.uat, uat],
    'UAT-01..48 execution and approval',
  ),
  artifact(
    'ART-VER-15',
    defectsReady ? 'CLOSED_OR_ACCEPTED' : 'BLOCKED',
    documents.defects.path,
    [documents.defects],
    'Defect and regression register',
  ),
  artifact(
    'ART-VER-16',
    indexReady ? 'COMPLETE' : 'BLOCKED',
    documents.index.path,
    [documents.index],
    'Sanitized evidence index',
  ),
  artifact(
    'ART-VER-17',
    rubricReady ? 'APPROVED' : 'BLOCKED',
    documents.rubric.path,
    [documents.rubric],
    'Rubric scorecard',
  ),
  artifact(
    'ART-VER-18',
    reportHeadingsReady ? 'APPROVED' : 'BLOCKED',
    documents.report.path,
    [documents.report],
    'Executed report and Stage 7 handoff',
  ),
];

const gate1Ids = expectedEvidenceIds.slice(0, 14).concat(['EVD-E6-31', 'EVD-E6-37', 'EVD-E6-38']);
const gate1Passed = gate1Ids.every((id) => evidenceById.get(id)?.status === 'PASS');
const gate2Ids = expectedEvidenceIds.slice(14, 35);
const gate2Failures = gate2Ids.filter((id) => evidenceById.get(id)?.status === 'FAIL');
const gate2Open = gate2Ids.filter(
  (id) =>
    evidenceById.get(id)?.status !== 'PASS' &&
    evidenceById.get(id)?.status !== 'NOT_RUN_AUTH_REQUIRED',
);
const gate2AuthOnly =
  gate2Failures.length === 0 &&
  gate2Open.length === 0 &&
  gate2Ids.some((id) => evidenceById.get(id)?.status === 'NOT_RUN_AUTH_REQUIRED');
const gate2 =
  gate2Failures.length > 0 || gate2Open.length > 0
    ? 'FAIL'
    : gate2AuthOnly
      ? 'CONDITIONAL_GO'
      : 'PASS';

const artifactBlocking = artifacts.filter(
  (entry) =>
    ![
      'GREEN',
      'VERIFIED',
      'PASSED',
      'APPROVED',
      'COMPLETE',
      'FROZEN',
      'CLOSED_OR_ACCEPTED',
    ].includes(entry.status) &&
    !(entry.id === 'ART-VER-07' && entry.status === 'NOT_RUN_AUTH_REQUIRED'),
);
const evidenceBlocking = evidence.filter(
  (entry) => entry.status !== 'PASS' && entry.status !== 'NOT_RUN_AUTH_REQUIRED',
);
const uatBlocking = uatMatrix.filter(
  (entry) =>
    entry.status !== 'PASS' && !(entry.id === 'UAT-33' && entry.status === 'NOT_RUN_AUTH_REQUIRED'),
);
const requiredBaselineSources = [
  stage6Baseline,
  coveragePolicy,
  apiTests,
  webTests,
  dynamodb,
  smoke,
  secrets,
  dependencies,
  stage5Manifest,
  apiCoverage,
  webCoverage,
  performanceHtml,
];
const technicalEvidenceMissing =
  stage6Sources.some((source) => !freshStage6(source)) ||
  (baselinePassed && requiredBaselineSources.some((source) => source.state !== 'LOADED'));
const anyTechnicalFailure =
  !pinnedStage5Baseline ||
  !requiredDocumentsValid ||
  !finalArtifactScanPassed ||
  !externalEvidenceCrossSourceReady ||
  !preflightExternalContractReady ||
  sandboxFailed ||
  passiveSecurityFailed ||
  technicalEvidenceMissing ||
  stage6Sources.some(
    (source) =>
      freshStage6(source) &&
      (source.value?.status === 'FAIL' ||
        source.value?.status === 'FAILED' ||
        source.value?.steps?.some((step) => step.status === 'FAIL')),
  ) ||
  evidence.some((entry) => entry.status === 'FAIL') ||
  artifacts.some((entry) => entry.status === 'FAILED') ||
  uatFailed;
const onlyAuthorizedExternalOpen =
  gate1Passed &&
  (gate2 === 'PASS' || gate2 === 'CONDITIONAL_GO') &&
  artifactBlocking.length === 0 &&
  evidenceBlocking.length === 0 &&
  uatBlocking.length === 0 &&
  (evidence.some((entry) => entry.status === 'NOT_RUN_AUTH_REQUIRED') ||
    uatMatrix.some((entry) => entry.status === 'NOT_RUN_AUTH_REQUIRED'));
const gate3 = anyTechnicalFailure
  ? 'FAIL'
  : onlyAuthorizedExternalOpen
    ? 'CONDITIONAL_GO'
    : gate1Passed &&
        gate2 === 'PASS' &&
        artifactBlocking.length === 0 &&
        evidenceBlocking.length === 0 &&
        uatAllPassed
      ? 'PASS'
      : 'FAIL';
evidence.push(
  evidenceRow(
    'EVD-E6-40',
    gate3,
    [documents.report, orchestration],
    'GATE-E6-03 and Stage 7 handoff; only PASS is a final release candidate',
  ),
);
const rubric = calculateStage6Rubric(evidence);
const rubricCalculated = rubricOutputReady(rubric, evidence);
rubricReady = rubricDocumentReady && rubricCalculated;
const rubricEvidenceRow = evidenceById.get('EVD-E6-39');
const rubricArtifact = artifacts.find(({ id }) => id === 'ART-VER-17');
assert.ok(rubricEvidenceRow);
assert.ok(rubricArtifact);
rubricEvidenceRow.status = status(rubricReady, !rubricCalculated);
rubricArtifact.status = rubricReady ? 'APPROVED' : rubricCalculated ? 'BLOCKED' : 'FAILED';
assert.equal(rubricOutputReady(rubric, evidence), true);

assert.deepEqual(
  artifacts.map((entry) => entry.id),
  expectedArtifactIds,
);
assert.deepEqual(
  evidence.map((entry) => entry.id),
  expectedEvidenceIds,
);

const manifest = {
  ...baseEvidence({
    artifactId: 'ART-VER-16',
    command: process.argv.includes('--promote')
      ? 'pnpm report:stage6'
      : 'node scripts/evidence/stage6-closeout.mjs',
    tool: {
      node: process.version,
      packageManager: 'pnpm@11.19.0',
      playwright: '1.61.1',
      lighthouse: '13.4.1',
    },
    runId,
  }),
  status:
    gate3 === 'PASS'
      ? 'RELEASE_CANDIDATE'
      : gate3 === 'CONDITIONAL_GO'
        ? 'CONDITIONAL_GO_NOT_PUBLIC_RELEASE'
        : anyTechnicalFailure
          ? 'REJECTED'
          : 'VERIFICATION_INCOMPLETE',
  sourceSnapshot: sourceSnapshot({
    excluded: ['output/evidence/stage-6/verification-manifest.json'],
  }),
  candidate: currentCandidate,
  requiredDocumentsValid,
  rubric,
  entryGate: preflight.state === 'LOADED' ? preflight.value?.entryGate : undefined,
  authorizations: preflight.state === 'LOADED' ? preflight.value?.authorizations : undefined,
  externalEvidence: {
    crossSourceExact: externalEvidenceCrossSourceReady,
    consumers: [
      { id: 'preflight', path: preflight.path },
      { id: 'sandbox', path: sandbox.path },
      { id: 'security', path: security.path },
      { id: 'uat', path: uat.path },
    ],
    decisions: {
      AUTH_E6_01: ownedTargetDecision,
      AUTH_E6_02: sandboxSmokeDecision,
      AUTH_E6_03: passiveSecurityDecision,
      AUTH_E6_04: 'PROHIBITED_WITHOUT_AUTH_E6_04',
    },
    summary: externalEvidenceCrossSourceReady ? externalEvidenceSummaries[0] : undefined,
    externalNetworkAttemptsByIngestion: 0,
  },
  externalRequestsMadeByCloseout: 0,
  evidenceSummary: {
    total: evidence.length,
    pass: evidence.filter((entry) => entry.status === 'PASS').length,
    notRunAuth: evidence.filter((entry) => entry.status === 'NOT_RUN_AUTH_REQUIRED').length,
    blocked: evidence.filter((entry) => !['PASS', 'NOT_RUN_AUTH_REQUIRED'].includes(entry.status))
      .length,
  },
  artifactSummary: {
    total: artifacts.length,
    validStates: artifacts.filter((entry) => entry.status !== 'FAILED').length,
    failed: artifacts.filter((entry) => entry.status === 'FAILED').length,
  },
  uat: {
    sourceState: uat.state,
    exactMatrix: uatExact,
    total: uatMatrix.length,
    passed: uatMatrix.filter((entry) => entry.status === 'PASS').length,
    failed: uatMatrix.filter((entry) => entry.status === 'FAIL').length,
    notRunManual: uatMatrix.filter((entry) => entry.status === 'NOT_RUN_MANUAL_REQUIRED').length,
    notRunAuth: uatMatrix.filter((entry) => entry.status === 'NOT_RUN_AUTH_REQUIRED').length,
    results: uatMatrix,
    networkGuardPassed: uatNetworkGuardPassed,
    externalNetworkAttempts: uat.value?.externalNetworkAttempts,
    networkObservation: uat.value?.networkObservation,
  },
  negativeE2e: {
    sourceState: uat.state,
    exactMatrix: negativeE2ePassed,
    total: negativeE2eResults.length,
    passed: negativeE2eResults.filter((entry) => entry.status === 'PASS').length,
    failed: negativeE2eResults.filter((entry) => entry.status === 'FAIL').length,
    results: negativeE2eResults,
  },
  refreshRecovery: {
    sourceState: uat.state,
    exactMatrix: refreshRecoveryPassed,
    total: refreshRecoveryResults.length,
    passed: refreshRecoveryResults.filter((entry) => entry.status === 'PASS').length,
    failed: refreshRecoveryResults.filter((entry) => entry.status === 'FAIL').length,
    results: refreshRecoveryResults,
  },
  gates: {
    'GATE-E6-01': gate1Passed ? 'PASS' : 'FAIL',
    'GATE-E6-02': gate2,
    'GATE-E6-03': gate3,
  },
  releasePolicy:
    gate3 === 'PASS'
      ? 'STAGE_7_FULL_ENABLED'
      : gate3 === 'CONDITIONAL_GO'
        ? 'STAGE_7_NON_PUBLIC_PRERELEASE_ONLY'
        : 'STAGE_7_BLOCKED',
  artifacts,
  evidence,
};

writeRuntimeEvidence('closeout.json', manifest);
if (process.argv.includes('--promote')) {
  mkdirSync(dirname(trackedPath), { recursive: true });
  const temporary = trackedPath + '.' + process.pid + '.tmp';
  writeFileSync(temporary, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  renameSync(temporary, trackedPath);
  process.stdout.write('stage-6 closeout: PROMOTED (' + gate3 + ')\n');
} else {
  process.stdout.write(
    'stage-6 closeout: ' + gate3 + ' (' + manifest.evidenceSummary.pass + '/40 PASS)\n',
  );
}

if (process.argv.includes('--uat-status')) {
  process.stdout.write(
    'stage-6 UAT: ' +
      manifest.uat.passed +
      '/48 PASS; ' +
      manifest.uat.notRunManual +
      ' manual; ' +
      manifest.uat.notRunAuth +
      ' auth\n',
  );
  if (!uatAllPassed) process.exitCode = 2;
} else if (gate3 === 'FAIL' || (process.argv.includes('--strict-gates') && gate3 !== 'PASS')) {
  process.exitCode = 1;
}
