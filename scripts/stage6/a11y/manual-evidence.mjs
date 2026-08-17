/* global structuredClone */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const MANUAL_SCHEMA_ID = 'urn:async-checkout-demo:stage6:a11y-manual-evidence:2';
export const MANUAL_PROTOCOL_VERSION = 'E6-A11Y-MANUAL-2';
const SCHEMA_PATH = fileURLToPath(new URL('./manual-evidence.schema.json', import.meta.url));
const PROTOCOL_PATH = fileURLToPath(
  new URL('../../../docs/verification/manual-accessibility.md', import.meta.url),
);
const RUN_ID = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const REVIEWER_ALIAS = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/u;
const SAFE_TOOL = /^[A-Za-z0-9][A-Za-z0-9 ._()+/-]{1,79}$/u;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const STATUS = new Set(['PASS', 'FAIL']);
const DEFECT_ID = /^DEF-E6-[0-9]{2,}$/u;
const SAFE_RESULT = /^[^\r\n]{24,500}$/u;
const AXE_RULE_ID = /^[a-z0-9][a-z0-9-]{1,63}$/u;
const SENSITIVE_RESULT_PATTERNS = [
  /(?:\d[ -]?){12,18}\d/u,
  /(?:\+\d{1,3}[ .-]?)?(?:\d[ .-]?){9,14}\d/u,
  /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu,
  /-----BEGIN [^-]*PRIVATE KEY-----/iu,
  /(?:payment[-_ ]?method[-_ ]?token|acceptance[-_ ]?token|card[-_ ]?token|capability[-_ ]?token|provider[-_ ]?(?:key|token)|private[-_ ]?key|token|secret|password)\s*["']?\s*[:=]\s*["']?\s*\S+/iu,
  /(?:cvc|cvv|security[-_ ]?code|código(?:\s+de)?\s+seguridad)\s*["']?\s*[:=]\s*["']?\s*\d{3,4}\b/iu,
  /(?:card[-_ ]?expiry|expiry(?:[-_ ]?(?:month|year))?|expiration(?:[-_ ]?(?:month|year))?|exp[-_ ]?(?:month|year)|vencimiento)\s*["']?\s*[:=]\s*["']?\s*(?:\d{1,2}[/-]\d{2,4}|\d{1,4})\b/iu,
];

export const MANUAL_CASE_DEFINITIONS = Object.freeze(
  [
    {
      id: 'A11Y-MAN-01',
      evidenceId: 'EVD-E6-28/A11Y-MAN-01',
      checkIds: ['A11Y-MAN-01-C01', 'A11Y-MAN-01-C02', 'A11Y-MAN-01-C03', 'A11Y-MAN-01-C04'],
    },
    {
      id: 'A11Y-MAN-02',
      evidenceId: 'EVD-E6-28/A11Y-MAN-02',
      checkIds: [
        'A11Y-MAN-02-C01',
        'A11Y-MAN-02-C02',
        'A11Y-MAN-02-C03',
        'A11Y-MAN-02-C04',
        'A11Y-MAN-02-C05',
      ],
    },
    {
      id: 'A11Y-MAN-03',
      evidenceId: 'EVD-E6-28/A11Y-MAN-03',
      checkIds: ['A11Y-MAN-03-C01', 'A11Y-MAN-03-C02', 'A11Y-MAN-03-C03', 'A11Y-MAN-03-C04'],
    },
    {
      id: 'A11Y-MAN-04',
      evidenceId: 'EVD-E6-28/A11Y-MAN-04',
      checkIds: ['A11Y-MAN-04-C01', 'A11Y-MAN-04-C02', 'A11Y-MAN-04-C03', 'A11Y-MAN-04-C04'],
    },
  ].map((definition) =>
    Object.freeze({ ...definition, checkIds: Object.freeze(definition.checkIds) }),
  ),
);

export const A11Y_AUTOMATED_SURFACES = Object.freeze([
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
]);

const ROOT_KEYS = [
  'schemaId',
  'schemaVersion',
  'stage',
  'protocolVersion',
  'protocolDocumentSha256',
  'commitSha',
  'runId',
  'executedAtUtc',
  'reviewerAlias',
  'browser',
  'screenReader',
  'status',
  'cases',
  'axeIncompleteReviews',
  'containsSensitiveData',
];
const CASE_KEYS = ['id', 'evidenceId', 'status', 'actualResult', 'checks'];
const CHECK_KEYS = ['id', 'status', 'actualResult'];
const AXE_REVIEW_KEYS = ['ruleId', 'surfaces', 'nodeCount', 'status', 'actualResult'];
const SUMMARY_KEYS = [
  'status',
  'source',
  'schemaId',
  'schemaVersion',
  'protocolVersion',
  'sourceSha256',
  'schemaSha256',
  'protocolDocumentSha256',
  'commitSha',
  'sourceManualRunId',
  'ingestedByRunId',
  'executedAtUtc',
  'reviewerAlias',
  'browser',
  'screenReader',
  'caseSummary',
  'axeIncompleteReviewSummary',
  'assessments',
  'containsSensitiveData',
];
const CASE_SUMMARY_KEYS = ['id', 'evidenceId', 'status', 'checks'];
const CHECK_SUMMARY_KEYS = ['total', 'passed', 'failed'];
const AXE_REVIEW_SUMMARY_KEYS = ['ruleId', 'surfaces', 'nodeCount', 'status'];
const ASSESSMENT_KEYS = ['screenReader', 'zoom200Reflow', 'forcedColors', 'axeIncompleteReview'];
const AXE_SCAN_KEYS = [
  'surface',
  'status',
  'domIdsUnique',
  'domIdCount',
  'violations',
  'incomplete',
];
const AXE_FINDING_KEYS = ['id', 'impact', 'nodeCount'];
const AXE_IMPACTS = new Set([null, 'minor', 'moderate', 'serious', 'critical']);

export class ManualEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const reject = (code) => {
  throw new ManualEvidenceError(code);
};

const record = (value, code) => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) reject(code);
  return value;
};

const list = (value, code) => {
  if (!Array.isArray(value)) reject(code);
  return value;
};

const exactKeys = (value, keys) =>
  Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

const hash = (value) => createHash('sha256').update(value).digest('hex');

const validateActualResult = (value) => {
  if (typeof value !== 'string' || !SAFE_RESULT.test(value)) {
    reject('MANUAL_EVIDENCE_ACTUAL_RESULT_INVALID');
  }
  if (SENSITIVE_RESULT_PATTERNS.some((pattern) => pattern.test(value))) {
    reject('MANUAL_EVIDENCE_ACTUAL_RESULT_SENSITIVE');
  }
};

const validateStatusAndDefect = (value, statusKey, baseKeys, fieldsCode, defectCode) => {
  const status = value[statusKey];
  if (!STATUS.has(status)) reject('MANUAL_EVIDENCE_STATUS_INVALID');
  const hasDefect = Object.hasOwn(value, 'defectId');
  if (status === 'FAIL' && !hasDefect) reject(defectCode);
  const keys = status === 'FAIL' ? [...baseKeys, 'defectId'] : baseKeys;
  if (!exactKeys(value, keys)) reject(fieldsCode);
  if (hasDefect && (typeof value.defectId !== 'string' || !DEFECT_ID.test(value.defectId))) {
    reject(defectCode);
  }
};

const validateCheck = (value, expectedId) => {
  const check = record(value, 'MANUAL_EVIDENCE_CHECK_INVALID');
  if (!exactKeys(check, CHECK_KEYS)) reject('MANUAL_EVIDENCE_CHECK_FIELDS_INVALID');
  if (check.id !== expectedId) reject('MANUAL_EVIDENCE_CHECK_INVENTORY_MISMATCH');
  if (!STATUS.has(check.status)) reject('MANUAL_EVIDENCE_STATUS_INVALID');
  validateActualResult(check.actualResult);
  return check;
};

const validateCase = (value, definition) => {
  const manualCase = record(value, 'MANUAL_EVIDENCE_CASE_INVALID');
  validateStatusAndDefect(
    manualCase,
    'status',
    CASE_KEYS,
    'MANUAL_EVIDENCE_CASE_FIELDS_INVALID',
    'MANUAL_EVIDENCE_CASE_DEFECT_REQUIRED',
  );
  if (manualCase.id !== definition.id || manualCase.evidenceId !== definition.evidenceId) {
    reject('MANUAL_EVIDENCE_CASE_INVENTORY_MISMATCH');
  }
  validateActualResult(manualCase.actualResult);
  const checks = list(manualCase.checks, 'MANUAL_EVIDENCE_CASE_CHECKS_INVALID');
  if (checks.length !== definition.checkIds.length) {
    reject('MANUAL_EVIDENCE_CASE_CHECKS_INVALID');
  }
  checks.forEach((check, index) => validateCheck(check, definition.checkIds[index]));
  const derivedStatus = checks.every(({ status }) => status === 'PASS') ? 'PASS' : 'FAIL';
  if (manualCase.status !== derivedStatus) reject('MANUAL_EVIDENCE_CASE_STATUS_INCONSISTENT');
  return manualCase;
};

const validateExpectedAxeInventory = (value) => {
  const inventory = list(value, 'MANUAL_EVIDENCE_EXPECTED_AXE_INVENTORY_INVALID');
  for (const entry of inventory) {
    if (
      !exactKeys(record(entry, 'MANUAL_EVIDENCE_EXPECTED_AXE_INVENTORY_INVALID'), [
        'ruleId',
        'surfaces',
        'nodeCount',
      ]) ||
      !AXE_RULE_ID.test(entry.ruleId) ||
      !Number.isInteger(entry.nodeCount) ||
      entry.nodeCount < 1 ||
      !Array.isArray(entry.surfaces) ||
      entry.surfaces.length < 1 ||
      entry.surfaces.some((surface) => !AXE_RULE_ID.test(surface)) ||
      new Set(entry.surfaces).size !== entry.surfaces.length
    ) {
      reject('MANUAL_EVIDENCE_EXPECTED_AXE_INVENTORY_INVALID');
    }
  }
  return inventory;
};

const validateAxeReview = (value, expected) => {
  const review = record(value, 'MANUAL_EVIDENCE_AXE_REVIEW_INVALID');
  validateStatusAndDefect(
    review,
    'status',
    AXE_REVIEW_KEYS,
    'MANUAL_EVIDENCE_AXE_REVIEW_FIELDS_INVALID',
    'MANUAL_EVIDENCE_AXE_REVIEW_DEFECT_REQUIRED',
  );
  if (
    review.ruleId !== expected.ruleId ||
    review.nodeCount !== expected.nodeCount ||
    !Array.isArray(review.surfaces) ||
    review.surfaces.length !== expected.surfaces.length ||
    review.surfaces.some((surface, index) => surface !== expected.surfaces[index])
  ) {
    reject('MANUAL_EVIDENCE_AXE_REVIEW_INVENTORY_MISMATCH');
  }
  validateActualResult(review.actualResult);
  return review;
};

export const axeIncompleteInventory = (axeScans) => {
  const inventory = new Map();
  for (const scan of Array.isArray(axeScans) ? axeScans : []) {
    for (const finding of Array.isArray(scan?.incomplete) ? scan.incomplete : []) {
      if (
        typeof scan?.surface !== 'string' ||
        !AXE_RULE_ID.test(scan.surface) ||
        typeof finding?.id !== 'string' ||
        !AXE_RULE_ID.test(finding.id) ||
        !Number.isInteger(finding.nodeCount) ||
        finding.nodeCount < 1
      ) {
        continue;
      }
      const current = inventory.get(finding.id) ?? { surfaces: new Set(), nodeCount: 0 };
      current.surfaces.add(scan.surface);
      current.nodeCount += finding.nodeCount;
      inventory.set(finding.id, current);
    }
  }
  return [...inventory.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([ruleId, detail]) => ({
      ruleId,
      surfaces: [...detail.surfaces].sort(),
      nodeCount: detail.nodeCount,
    }));
};

export const deriveManualAssessments = (evidence) => {
  const caseStatus = (id) => evidence.cases.find((manualCase) => manualCase.id === id)?.status;
  return {
    screenReader:
      caseStatus('A11Y-MAN-01') === 'PASS' && caseStatus('A11Y-MAN-02') === 'PASS'
        ? 'PASS'
        : 'FAIL',
    zoom200Reflow: caseStatus('A11Y-MAN-03') === 'PASS' ? 'PASS' : 'FAIL',
    forcedColors: caseStatus('A11Y-MAN-04') === 'PASS' ? 'PASS' : 'FAIL',
    axeIncompleteReview: evidence.axeIncompleteReviews.every(({ status }) => status === 'PASS')
      ? 'PASS'
      : 'FAIL',
  };
};

export const validateManualEvidence = (value, expected) => {
  const evidence = record(value, 'MANUAL_EVIDENCE_NOT_OBJECT');
  if (!exactKeys(evidence, ROOT_KEYS)) reject('MANUAL_EVIDENCE_FIELDS_INVALID');
  if (
    evidence.schemaId !== MANUAL_SCHEMA_ID ||
    evidence.schemaVersion !== 2 ||
    evidence.stage !== 6 ||
    evidence.protocolVersion !== MANUAL_PROTOCOL_VERSION
  ) {
    reject('MANUAL_EVIDENCE_SCHEMA_INVALID');
  }
  if (!SHA.test(evidence.commitSha) || evidence.commitSha !== expected.commitSha) {
    reject('MANUAL_EVIDENCE_SHA_MISMATCH');
  }
  if (!RUN_ID.test(evidence.runId)) reject('MANUAL_EVIDENCE_SOURCE_RUN_ID_INVALID');
  if (
    !SHA256.test(evidence.protocolDocumentSha256) ||
    evidence.protocolDocumentSha256 !== expected.protocolDocumentSha256
  ) {
    reject('MANUAL_EVIDENCE_PROTOCOL_HASH_MISMATCH');
  }
  if (
    typeof evidence.executedAtUtc !== 'string' ||
    !UTC_TIMESTAMP.test(evidence.executedAtUtc) ||
    !Number.isFinite(Date.parse(evidence.executedAtUtc)) ||
    Date.parse(evidence.executedAtUtc) > Date.now() + 5 * 60 * 1_000
  ) {
    reject('MANUAL_EVIDENCE_EXECUTED_AT_INVALID');
  }
  if (typeof evidence.reviewerAlias !== 'string' || !REVIEWER_ALIAS.test(evidence.reviewerAlias)) {
    reject('MANUAL_EVIDENCE_REVIEWER_INVALID');
  }
  if (typeof evidence.browser !== 'string' || !SAFE_TOOL.test(evidence.browser)) {
    reject('MANUAL_EVIDENCE_BROWSER_INVALID');
  }
  if (typeof evidence.screenReader !== 'string' || !SAFE_TOOL.test(evidence.screenReader)) {
    reject('MANUAL_EVIDENCE_SCREEN_READER_INVALID');
  }
  if (!STATUS.has(evidence.status)) reject('MANUAL_EVIDENCE_STATUS_INVALID');
  if (evidence.containsSensitiveData !== false) reject('MANUAL_EVIDENCE_SENSITIVE_DATA');

  const cases = list(evidence.cases, 'MANUAL_EVIDENCE_CASES_INVALID');
  if (cases.length !== MANUAL_CASE_DEFINITIONS.length) reject('MANUAL_EVIDENCE_CASES_INVALID');
  cases.forEach((manualCase, index) => validateCase(manualCase, MANUAL_CASE_DEFINITIONS[index]));

  const expectedAxeInventory = validateExpectedAxeInventory(expected.axeIncompleteInventory);
  const reviews = list(evidence.axeIncompleteReviews, 'MANUAL_EVIDENCE_AXE_REVIEWS_INVALID');
  if (reviews.length !== expectedAxeInventory.length) {
    reject('MANUAL_EVIDENCE_AXE_REVIEW_INVENTORY_MISMATCH');
  }
  reviews.forEach((review, index) => validateAxeReview(review, expectedAxeInventory[index]));

  const derivedStatus =
    cases.every(({ status }) => status === 'PASS') &&
    reviews.every(({ status }) => status === 'PASS')
      ? 'PASS'
      : 'FAIL';
  if (evidence.status !== derivedStatus) reject('MANUAL_EVIDENCE_STATUS_INCONSISTENT');
  return evidence;
};

export const manualEvidencePath = (
  arguments_ = process.argv.slice(2),
  environment = process.env,
) => {
  const flagIndex = arguments_.indexOf('--manual-evidence');
  const flagValue = flagIndex === -1 ? undefined : arguments_[flagIndex + 1];
  if (flagIndex !== -1 && (flagValue === undefined || flagValue.startsWith('--'))) {
    reject('MANUAL_EVIDENCE_PATH_MISSING');
  }
  const configured = environment.STAGE6_A11Y_MANUAL_EVIDENCE;
  if (
    flagValue !== undefined &&
    configured !== undefined &&
    path.resolve(flagValue) !== path.resolve(configured)
  ) {
    reject('MANUAL_EVIDENCE_PATH_CONFLICT');
  }
  const selected = flagValue ?? configured;
  return selected === undefined || selected === '' ? undefined : path.resolve(selected);
};

export const loadManualEvidence = async ({
  sourcePath,
  commitSha,
  ingestedByRunId,
  axeIncompleteInventory: requiredAxeIncompleteInventory,
}) => {
  if (!RUN_ID.test(ingestedByRunId)) reject('MANUAL_EVIDENCE_INGESTED_RUN_ID_INVALID');
  const [source, schemaSource, protocolSource] = await Promise.all([
    readFile(sourcePath),
    readFile(SCHEMA_PATH),
    readFile(PROTOCOL_PATH),
  ]).catch(() => reject('MANUAL_EVIDENCE_FILE_UNREADABLE'));
  if (source.length > 64 * 1_024) reject('MANUAL_EVIDENCE_FILE_TOO_LARGE');
  let parsed;
  let schema;
  try {
    parsed = JSON.parse(source.toString('utf8'));
    schema = JSON.parse(schemaSource.toString('utf8'));
  } catch {
    reject('MANUAL_EVIDENCE_JSON_INVALID');
  }
  if (
    schema.$id !== MANUAL_SCHEMA_ID ||
    schema.properties?.schemaVersion?.const !== 2 ||
    schema.properties?.protocolVersion?.const !== MANUAL_PROTOCOL_VERSION
  ) {
    reject('MANUAL_EVIDENCE_SCHEMA_FILE_INVALID');
  }
  const protocolDocumentSha256 = hash(protocolSource);
  const evidence = validateManualEvidence(parsed, {
    commitSha,
    protocolDocumentSha256,
    axeIncompleteInventory: requiredAxeIncompleteInventory,
  });
  if (evidence.runId === ingestedByRunId) {
    reject('MANUAL_EVIDENCE_RUN_IDS_NOT_DISTINCT');
  }
  const assessments = deriveManualAssessments(evidence);
  return {
    status: evidence.status,
    source: 'EXTERNAL_VERSIONED_JSON',
    schemaId: MANUAL_SCHEMA_ID,
    schemaVersion: 2,
    protocolVersion: evidence.protocolVersion,
    sourceSha256: hash(source),
    schemaSha256: hash(schemaSource),
    protocolDocumentSha256,
    commitSha: evidence.commitSha,
    sourceManualRunId: evidence.runId,
    ingestedByRunId,
    executedAtUtc: evidence.executedAtUtc,
    reviewerAlias: evidence.reviewerAlias,
    browser: evidence.browser,
    screenReader: evidence.screenReader,
    caseSummary: evidence.cases.map((manualCase) => ({
      id: manualCase.id,
      evidenceId: manualCase.evidenceId,
      status: manualCase.status,
      checks: {
        total: manualCase.checks.length,
        passed: manualCase.checks.filter(({ status }) => status === 'PASS').length,
        failed: manualCase.checks.filter(({ status }) => status === 'FAIL').length,
      },
      ...(manualCase.defectId === undefined ? {} : { defectId: manualCase.defectId }),
    })),
    axeIncompleteReviewSummary: evidence.axeIncompleteReviews.map((review) => ({
      ruleId: review.ruleId,
      surfaces: review.surfaces,
      nodeCount: review.nodeCount,
      status: review.status,
      ...(review.defectId === undefined ? {} : { defectId: review.defectId }),
    })),
    assessments,
    containsSensitiveData: false,
  };
};

export const validateManualEvidenceSummary = (manual, automatedAxeScans, expectedExecution) => {
  try {
    const summary = record(manual, 'MANUAL_EVIDENCE_SUMMARY_INVALID');
    const execution = record(expectedExecution, 'MANUAL_EVIDENCE_EXECUTION_INVALID');
    if (!exactKeys(summary, SUMMARY_KEYS)) return false;
    if (
      !exactKeys(execution, ['commitSha', 'runId']) ||
      !SHA.test(execution.commitSha) ||
      !RUN_ID.test(execution.runId)
    ) {
      return false;
    }
    const schemaSource = readFileSync(SCHEMA_PATH);
    const protocolSource = readFileSync(PROTOCOL_PATH);
    const schema = JSON.parse(schemaSource.toString('utf8'));
    if (
      schema.$id !== MANUAL_SCHEMA_ID ||
      schema.properties?.schemaVersion?.const !== 2 ||
      schema.properties?.protocolVersion?.const !== MANUAL_PROTOCOL_VERSION ||
      summary.status !== 'PASS' ||
      summary.source !== 'EXTERNAL_VERSIONED_JSON' ||
      summary.schemaId !== MANUAL_SCHEMA_ID ||
      summary.schemaVersion !== 2 ||
      summary.protocolVersion !== MANUAL_PROTOCOL_VERSION ||
      !SHA256.test(summary.sourceSha256) ||
      summary.schemaSha256 !== hash(schemaSource) ||
      summary.protocolDocumentSha256 !== hash(protocolSource) ||
      summary.commitSha !== execution.commitSha ||
      !RUN_ID.test(summary.sourceManualRunId) ||
      summary.sourceManualRunId === summary.ingestedByRunId ||
      summary.ingestedByRunId !== execution.runId ||
      typeof summary.executedAtUtc !== 'string' ||
      !UTC_TIMESTAMP.test(summary.executedAtUtc) ||
      !Number.isFinite(Date.parse(summary.executedAtUtc)) ||
      Date.parse(summary.executedAtUtc) > Date.now() + 5 * 60 * 1_000 ||
      typeof summary.reviewerAlias !== 'string' ||
      !REVIEWER_ALIAS.test(summary.reviewerAlias) ||
      typeof summary.browser !== 'string' ||
      !SAFE_TOOL.test(summary.browser) ||
      typeof summary.screenReader !== 'string' ||
      !SAFE_TOOL.test(summary.screenReader) ||
      summary.containsSensitiveData !== false
    ) {
      return false;
    }

    const cases = list(summary.caseSummary, 'MANUAL_EVIDENCE_CASE_SUMMARY_INVALID');
    if (cases.length !== MANUAL_CASE_DEFINITIONS.length) return false;
    for (const [index, definition] of MANUAL_CASE_DEFINITIONS.entries()) {
      const manualCase = record(cases[index], 'MANUAL_EVIDENCE_CASE_SUMMARY_INVALID');
      const checks = record(manualCase.checks, 'MANUAL_EVIDENCE_CHECK_SUMMARY_INVALID');
      if (
        !exactKeys(manualCase, CASE_SUMMARY_KEYS) ||
        manualCase.id !== definition.id ||
        manualCase.evidenceId !== definition.evidenceId ||
        manualCase.status !== 'PASS' ||
        !exactKeys(checks, CHECK_SUMMARY_KEYS) ||
        checks.total !== definition.checkIds.length ||
        checks.passed !== checks.total ||
        checks.failed !== 0
      ) {
        return false;
      }
    }

    const scans = list(automatedAxeScans, 'MANUAL_EVIDENCE_AXE_SCANS_INVALID');
    if (scans.length !== A11Y_AUTOMATED_SURFACES.length) return false;
    for (const [index, surface] of A11Y_AUTOMATED_SURFACES.entries()) {
      const scan = record(scans[index], 'MANUAL_EVIDENCE_AXE_SCAN_INVALID');
      if (
        !exactKeys(scan, AXE_SCAN_KEYS) ||
        scan.surface !== surface ||
        scan.status !== 'PASS' ||
        scan.domIdsUnique !== true ||
        !Number.isInteger(scan.domIdCount) ||
        scan.domIdCount < 0 ||
        !Array.isArray(scan.violations) ||
        scan.violations.length !== 0 ||
        !Array.isArray(scan.incomplete)
      ) {
        return false;
      }
      for (const findingValue of scan.incomplete) {
        const finding = record(findingValue, 'MANUAL_EVIDENCE_AXE_FINDING_INVALID');
        if (
          !exactKeys(finding, AXE_FINDING_KEYS) ||
          typeof finding.id !== 'string' ||
          !AXE_RULE_ID.test(finding.id) ||
          !AXE_IMPACTS.has(finding.impact) ||
          !Number.isInteger(finding.nodeCount) ||
          finding.nodeCount < 1
        ) {
          return false;
        }
      }
    }

    const expectedReviews = axeIncompleteInventory(scans);
    const reviews = list(
      summary.axeIncompleteReviewSummary,
      'MANUAL_EVIDENCE_AXE_REVIEW_SUMMARY_INVALID',
    );
    if (reviews.length !== expectedReviews.length) return false;
    for (const [index, expected] of expectedReviews.entries()) {
      const review = record(reviews[index], 'MANUAL_EVIDENCE_AXE_REVIEW_SUMMARY_INVALID');
      if (
        !exactKeys(review, AXE_REVIEW_SUMMARY_KEYS) ||
        review.ruleId !== expected.ruleId ||
        review.nodeCount !== expected.nodeCount ||
        review.status !== 'PASS' ||
        !Array.isArray(review.surfaces) ||
        review.surfaces.length !== expected.surfaces.length ||
        review.surfaces.some((surface, surfaceIndex) => surface !== expected.surfaces[surfaceIndex])
      ) {
        return false;
      }
    }

    const assessments = record(summary.assessments, 'MANUAL_EVIDENCE_ASSESSMENTS_INVALID');
    return (
      exactKeys(assessments, ASSESSMENT_KEYS) &&
      ASSESSMENT_KEYS.every((key) => assessments[key] === 'PASS')
    );
  } catch {
    return false;
  }
};
const validFixture = (expected) => {
  const cases = MANUAL_CASE_DEFINITIONS.map((definition) => ({
    id: definition.id,
    evidenceId: definition.evidenceId,
    status: 'PASS',
    actualResult: 'Hechos observados y verificados sin contenido sensible.',
    checks: definition.checkIds.map((id) => ({
      id,
      status: 'PASS',
      actualResult: 'Comportamiento observado coincide con el resultado esperado.',
    })),
  }));
  return {
    schemaId: MANUAL_SCHEMA_ID,
    schemaVersion: 2,
    stage: 6,
    protocolVersion: MANUAL_PROTOCOL_VERSION,
    protocolDocumentSha256: expected.protocolDocumentSha256,
    commitSha: expected.commitSha,
    runId: expected.sourceManualRunId,
    executedAtUtc: new Date(Date.now() - 1_000).toISOString(),
    reviewerAlias: 'reviewer-01',
    browser: 'Chromium 140',
    screenReader: 'NVDA 2026.1',
    status: 'PASS',
    cases,
    axeIncompleteReviews: expected.axeIncompleteInventory.map((entry) => ({
      ...entry,
      status: 'PASS',
      actualResult: 'Nodos revisados manualmente y comportamiento confirmado.',
    })),
    containsSensitiveData: false,
  };
};

export const selfTestManualEvidenceLoader = async () => {
  const expected = {
    commitSha: 'a'.repeat(40),
    sourceManualRunId: 'e6-20260815t120000z-89abcdef',
    protocolDocumentSha256: hash(readFileSync(PROTOCOL_PATH)),
    axeIncompleteInventory: [],
  };
  const ingestedByRunId = 'e6-20260816t120000z-0123abcd';
  const sensitiveJsonValues = [
    JSON.stringify({
      [['payment', 'Method', 'Token'].join('')]: ['actual', 'token', 'value'].join('-'),
    }),
    JSON.stringify({
      [['sec', 'ret'].join('')]: ['actual', 'secret', 'value'].join('-'),
    }),
    JSON.stringify({
      [['cv', 'c'].join('')]: ['1', '2', '3'].join(''),
    }),
    JSON.stringify({
      [['exp', 'iry'].join('')]: ['1', '2', '/', '3', '4'].join(''),
    }),
  ];
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'checkout-e6-manual-loader-'));
  const sourcePath = path.join(temporary, 'manual-evidence.json');
  try {
    for (const [index, sensitiveJson] of sensitiveJsonValues.entries()) {
      const candidate = validFixture(expected);
      candidate.cases[0].checks[0].actualResult = `Hecho observado ${sensitiveJson} durante la revisión manual.`;
      await writeFile(sourcePath, JSON.stringify(candidate), 'utf8');
      try {
        await loadManualEvidence({
          sourcePath,
          commitSha: expected.commitSha,
          ingestedByRunId,
          axeIncompleteInventory: [],
        });
      } catch (error) {
        if (
          error instanceof ManualEvidenceError &&
          error.code === 'MANUAL_EVIDENCE_ACTUAL_RESULT_SENSITIVE'
        ) {
          continue;
        }
        throw error;
      }
      reject(`MANUAL_EVIDENCE_LOADER_SENSITIVE_JSON_SELF_TEST_FAILED_${index}`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
};

const summaryAxeScansFixture = () =>
  A11Y_AUTOMATED_SURFACES.map((surface) => ({
    surface,
    status: 'PASS',
    domIdsUnique: true,
    domIdCount: 1,
    violations: [],
    incomplete:
      surface === 'product' || surface === 'checkout-payment'
        ? [{ id: 'color-contrast', impact: 'serious', nodeCount: 1 }]
        : [],
  }));

const validSummaryFixture = (automatedAxeScans) => ({
  status: 'PASS',
  source: 'EXTERNAL_VERSIONED_JSON',
  schemaId: MANUAL_SCHEMA_ID,
  schemaVersion: 2,
  protocolVersion: MANUAL_PROTOCOL_VERSION,
  sourceSha256: 'e'.repeat(64),
  schemaSha256: hash(readFileSync(SCHEMA_PATH)),
  protocolDocumentSha256: hash(readFileSync(PROTOCOL_PATH)),
  commitSha: 'a'.repeat(40),
  sourceManualRunId: 'e6-20260815t120000z-89abcdef',
  ingestedByRunId: 'e6-20260816t120000z-0123abcd',
  executedAtUtc: new Date(Date.now() - 1_000).toISOString(),
  reviewerAlias: 'reviewer-01',
  browser: 'Chromium 140',
  screenReader: 'NVDA 2026.1',
  caseSummary: MANUAL_CASE_DEFINITIONS.map(({ id, evidenceId, checkIds }) => ({
    id,
    evidenceId,
    status: 'PASS',
    checks: { total: checkIds.length, passed: checkIds.length, failed: 0 },
  })),
  axeIncompleteReviewSummary: axeIncompleteInventory(automatedAxeScans).map((review) => ({
    ...review,
    status: 'PASS',
  })),
  assessments: {
    screenReader: 'PASS',
    zoom200Reflow: 'PASS',
    forcedColors: 'PASS',
    axeIncompleteReview: 'PASS',
  },
  containsSensitiveData: false,
});
const expectReject = (candidate, expected, code) => {
  try {
    validateManualEvidence(candidate, expected);
  } catch (error) {
    if (error instanceof ManualEvidenceError && error.code === code) return;
    throw error;
  }
  reject(`MANUAL_EVIDENCE_NEGATIVE_SELF_TEST_FAILED_${code}`);
};

const expectSummaryReject = (candidate, automatedAxeScans, expectedExecution, code) => {
  if (validateManualEvidenceSummary(candidate, automatedAxeScans, expectedExecution)) {
    reject(`MANUAL_EVIDENCE_SUMMARY_NEGATIVE_SELF_TEST_FAILED_${code}`);
  }
};
export const selfTestManualEvidence = () => {
  const expected = {
    commitSha: 'a'.repeat(40),
    sourceManualRunId: 'e6-20260815t120000z-89abcdef',
    protocolDocumentSha256: 'c'.repeat(64),
    axeIncompleteInventory: [
      {
        ruleId: 'aria-prohibited-attr',
        surfaces: ['checkout-payment', 'payment-validation', 'product'],
        nodeCount: 3,
      },
      {
        ruleId: 'color-contrast',
        surfaces: [
          'transaction-declined',
          'transaction-network-error',
          'transaction-pending',
          'transaction-unknown',
        ],
        nodeCount: 4,
      },
    ],
  };
  const valid = validFixture(expected);
  validateManualEvidence(valid, expected);
  validateManualEvidence({ ...valid, runId: 'e6-20260814t120000z-7654abcd' }, expected);
  const derivedInventory = axeIncompleteInventory([
    { surface: 'product', incomplete: [{ id: 'color-contrast', nodeCount: 1 }] },
    { surface: 'checkout-payment', incomplete: [{ id: 'color-contrast', nodeCount: 2 }] },
  ]);
  if (
    JSON.stringify(derivedInventory) !==
    JSON.stringify([
      {
        ruleId: 'color-contrast',
        surfaces: ['checkout-payment', 'product'],
        nodeCount: 3,
      },
    ])
  ) {
    reject('MANUAL_EVIDENCE_AXE_INVENTORY_SELF_TEST_FAILED');
  }
  if (Object.values(deriveManualAssessments(valid)).some((status) => status !== 'PASS')) {
    reject('MANUAL_EVIDENCE_ASSESSMENTS_SELF_TEST_FAILED');
  }

  const summaryAxeScans = summaryAxeScansFixture();
  const validSummary = validSummaryFixture(summaryAxeScans);
  const summaryExecution = {
    commitSha: validSummary.commitSha,
    runId: validSummary.ingestedByRunId,
  };
  if (!validateManualEvidenceSummary(validSummary, summaryAxeScans, summaryExecution)) {
    reject('MANUAL_EVIDENCE_SUMMARY_PASS_SELF_TEST_FAILED');
  }
  const sameRunSummary = {
    ...validSummary,
    sourceManualRunId: validSummary.ingestedByRunId,
  };
  expectSummaryReject(sameRunSummary, summaryAxeScans, summaryExecution, 'RUN_IDS_NOT_DISTINCT');
  expectSummaryReject(undefined, summaryAxeScans, summaryExecution, 'MISSING');
  expectSummaryReject(validSummary, summaryAxeScans, undefined, 'EXECUTION_MISSING');
  expectSummaryReject(
    validSummary,
    summaryAxeScans,
    { ...summaryExecution, commitSha: 'b'.repeat(40) },
    'EXECUTION_SHA',
  );
  expectSummaryReject(
    validSummary,
    summaryAxeScans,
    { ...summaryExecution, runId: 'e6-20260816t120000z-deadbeef' },
    'EXECUTION_RUN_ID',
  );
  expectSummaryReject(
    { ...validSummary, sourceManualRunId: 'invalid' },
    summaryAxeScans,
    summaryExecution,
    'SOURCE_MANUAL_RUN_ID',
  );
  expectSummaryReject(
    { status: 'PASS', assessments: validSummary.assessments },
    summaryAxeScans,
    summaryExecution,
    'FLAGS_ONLY',
  );
  expectSummaryReject(
    { ...validSummary, protocolDocumentSha256: 'f'.repeat(64) },
    summaryAxeScans,
    summaryExecution,
    'PROTOCOL_HASH',
  );
  expectSummaryReject(
    { ...validSummary, schemaSha256: 'f'.repeat(64) },
    summaryAxeScans,
    summaryExecution,
    'SCHEMA_HASH',
  );
  expectSummaryReject(
    { ...validSummary, status: 'FAIL' },
    summaryAxeScans,
    summaryExecution,
    'STATUS',
  );
  expectSummaryReject(
    { ...validSummary, caseSummary: validSummary.caseSummary.slice(0, -1) },
    summaryAxeScans,
    summaryExecution,
    'CASE_INVENTORY',
  );
  const checkMismatch = structuredClone(validSummary);
  checkMismatch.caseSummary[0].checks.passed -= 1;
  checkMismatch.caseSummary[0].checks.failed += 1;
  expectSummaryReject(checkMismatch, summaryAxeScans, summaryExecution, 'CHECK_COUNTS');
  expectSummaryReject(
    {
      ...validSummary,
      axeIncompleteReviewSummary: validSummary.axeIncompleteReviewSummary.slice(0, -1),
    },
    summaryAxeScans,
    summaryExecution,
    'AXE_REVIEW_INVENTORY',
  );
  expectSummaryReject(
    validSummary,
    summaryAxeScans.slice(0, -1),
    summaryExecution,
    'AXE_SCAN_INVENTORY',
  );

  const missingCase = structuredClone(valid);
  missingCase.cases.pop();
  expectReject(missingCase, expected, 'MANUAL_EVIDENCE_CASES_INVALID');

  const extraCase = structuredClone(valid);
  extraCase.cases.push(structuredClone(extraCase.cases[0]));
  expectReject(extraCase, expected, 'MANUAL_EVIDENCE_CASES_INVALID');

  const missingCheck = structuredClone(valid);
  missingCheck.cases[0].checks.pop();
  expectReject(missingCheck, expected, 'MANUAL_EVIDENCE_CASE_CHECKS_INVALID');

  const inconsistentPass = structuredClone(valid);
  inconsistentPass.cases[0].checks[0].status = 'FAIL';
  expectReject(inconsistentPass, expected, 'MANUAL_EVIDENCE_CASE_STATUS_INCONSISTENT');

  const aggregateInconsistent = structuredClone(valid);
  aggregateInconsistent.cases[0].checks[0].status = 'FAIL';
  aggregateInconsistent.cases[0].status = 'FAIL';
  aggregateInconsistent.cases[0].defectId = 'DEF-E6-01';
  expectReject(aggregateInconsistent, expected, 'MANUAL_EVIDENCE_STATUS_INCONSISTENT');

  const missingDefect = structuredClone(valid);
  missingDefect.status = 'FAIL';
  missingDefect.cases[0].status = 'FAIL';
  missingDefect.cases[0].checks[0].status = 'FAIL';
  expectReject(missingDefect, expected, 'MANUAL_EVIDENCE_CASE_DEFECT_REQUIRED');

  expectReject(
    { ...valid, protocolDocumentSha256: 'd'.repeat(64) },
    expected,
    'MANUAL_EVIDENCE_PROTOCOL_HASH_MISMATCH',
  );
  expectReject(
    { ...valid, axeIncompleteReviews: valid.axeIncompleteReviews.slice(0, -1) },
    expected,
    'MANUAL_EVIDENCE_AXE_REVIEW_INVENTORY_MISMATCH',
  );
  const missingAxeDefect = structuredClone(valid);
  missingAxeDefect.status = 'FAIL';
  missingAxeDefect.axeIncompleteReviews[0].status = 'FAIL';
  expectReject(missingAxeDefect, expected, 'MANUAL_EVIDENCE_AXE_REVIEW_DEFECT_REQUIRED');
  expectReject({ ...valid, unexpected: true }, expected, 'MANUAL_EVIDENCE_FIELDS_INVALID');
  expectReject({ ...valid, commitSha: 'b'.repeat(40) }, expected, 'MANUAL_EVIDENCE_SHA_MISMATCH');
  expectReject({ ...valid, runId: 'invalid' }, expected, 'MANUAL_EVIDENCE_SOURCE_RUN_ID_INVALID');

  const panResult = structuredClone(valid);
  panResult.cases[0].actualResult = [
    'Se observó el valor ',
    ['4111', '1111', '1111', '1111'].join(' '),
    ' en pantalla.',
  ].join('');
  expectReject(panResult, expected, 'MANUAL_EVIDENCE_ACTUAL_RESULT_SENSITIVE');

  const tokenResult = structuredClone(valid);
  tokenResult.cases[0].checks[0].actualResult = 'provider_token=synthetic-but-forbidden';
  expectReject(tokenResult, expected, 'MANUAL_EVIDENCE_ACTUAL_RESULT_SENSITIVE');

  const cvcResult = structuredClone(valid);
  cvcResult.cases[0].actualResult = [
    'Se observó CVC: ',
    '1',
    '2',
    '3',
    ' durante la revisión.',
  ].join('');
  expectReject(cvcResult, expected, 'MANUAL_EVIDENCE_ACTUAL_RESULT_SENSITIVE');

  const expiryResult = structuredClone(valid);
  expiryResult.cases[0].actualResult = [
    'Se observó expiry: ',
    ['12', '99'].join('/'),
    ' durante la revisión.',
  ].join('');
  expectReject(expiryResult, expected, 'MANUAL_EVIDENCE_ACTUAL_RESULT_SENSITIVE');
};
