/* global structuredClone */
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

import {
  StrictJsonError,
  parseStrictJsonSource,
  selfTestStrictJson,
  validateJsonSchemaSubset,
} from './strict-json.mjs';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(SCRIPT_DIRECTORY, 'external-evidence.schema.json');
const PROTOCOL_PATH = path.resolve(
  SCRIPT_DIRECTORY,
  '..',
  '..',
  'docs',
  'verification',
  'external-evidence.md',
);
const SCHEMA_ID = 'async-checkout-stage6-external-evidence';
const SCHEMA_URI = 'https://async-checkout.invalid/schemas/stage6-external-evidence-v1.json';
const PROTOCOL_VERSION = '1.0.0';
const RUN_ID = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const COMMIT_SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const UTC_TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const SAFE_ALIAS = /^[a-z][a-z0-9-]{2,31}$/u;
const ALLOWED_ZAP_VERSIONS = new Set(['2.16.1']);
const MAX_SOURCE_BYTES = 128 * 1_024;
const MAX_EVIDENCE_COUNT = 100;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1_000;
const regexMatchesString = (pattern, value) => typeof value === 'string' && pattern.test(value);

export const EXTERNAL_CAPABILITY_KEYS = ['ownedTarget', 'sandboxSmoke', 'passiveSecurity'];

const OWNED_TARGET_CHECKS = [
  ['AUTH01-E6-01', 'http-redirect-to-https'],
  ['AUTH01-E6-02', 'https-document-available'],
  ['AUTH01-E6-03', 'mixed-content-requests-zero'],
];
const SANDBOX_CHECKS = [
  ['AUTH02-E6-01', 'acceptance-configuration-observed'],
  ['AUTH02-E6-02', 'authorized-test-payment-method-created'],
  ['AUTH02-E6-03', 'local-pending-created-first'],
  ['AUTH02-E6-04', 'provider-sandbox-transaction-created'],
  ['AUTH02-E6-05', 'provider-status-polled'],
  ['AUTH02-E6-06', 'amount-currency-reference-validated'],
  ['AUTH02-E6-07', 'provider-errors-redacted'],
  ['AUTH02-E6-08', 'reconciliation-replay-idempotent'],
];
const HEADER_CHECKS = [
  ['AUTH03-E6-HDR-01', 'content-security-policy'],
  ['AUTH03-E6-HDR-02', 'referrer-policy'],
  ['AUTH03-E6-HDR-03', 'x-content-type-options'],
  ['AUTH03-E6-HDR-04', 'clickjacking-protection'],
  ['AUTH03-E6-HDR-05', 'permissions-policy'],
  ['AUTH03-E6-HDR-06', 'strict-transport-security'],
];

const SUMMARY_SANITIZATION = {
  endpoints: 'SHA256_ONLY',
  providerPayloads: 'OMITTED',
  transactionAndReferenceValues: 'SHA256_ONLY',
  paymentData: 'NOT_CAPTURED',
  credentials: 'NOT_CAPTURED',
  pii: 'NOT_CAPTURED',
};
const ACCEPTED_CHANNELS = ['--external-evidence <json>', 'STAGE6_EXTERNAL_EVIDENCE=<json>'];

const hash = (value) => createHash('sha256').update(value).digest('hex');
const exact = (actual, expected) => isDeepStrictEqual(actual, expected);
const exactKeys = (value, expected) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).length === expected.length &&
  expected.every((key) => Object.hasOwn(value, key));
const exactStrings = (actual, expected) =>
  Array.isArray(actual) &&
  actual.length === expected.length &&
  actual.every((value, index) => value === expected[index]);
const nonNegativeInteger = (value) =>
  Number.isSafeInteger(value) && value >= 0 && value <= MAX_EVIDENCE_COUNT;
const positiveInteger = (value) =>
  Number.isSafeInteger(value) && value > 0 && value <= MAX_EVIDENCE_COUNT;
const validUtc = (value) =>
  regexMatchesString(UTC_TIMESTAMP, value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;

const schemaSource = readFileSync(SCHEMA_PATH);
const protocolSource = readFileSync(PROTOCOL_PATH);
const schemaSha256 = hash(schemaSource);
const protocolDocumentSha256 = hash(protocolSource);
const schemaDocument = parseStrictJsonSource(schemaSource, { scanForbiddenData: false });

export class ExternalEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ExternalEvidenceError';
    this.code = code;
  }
}

const reject = (code) => {
  throw new ExternalEvidenceError(code);
};

const validAuthorization = (authorization, expected, executedAtUtc) => {
  if (
    !exactKeys(authorization, [
      'id',
      'status',
      'scope',
      'approvalSha256',
      'approvedTargetSha256',
      'approvedAtUtc',
      'expiresAtUtc',
      'ownerAlias',
      'maxRequests',
    ]) ||
    authorization.id !== expected.id ||
    authorization.status !== 'APPROVED' ||
    authorization.scope !== expected.scope ||
    !regexMatchesString(SHA256, authorization.approvalSha256) ||
    authorization.approvedTargetSha256 !== expected.targetSha256 ||
    !validUtc(authorization.approvedAtUtc) ||
    !validUtc(authorization.expiresAtUtc) ||
    !regexMatchesString(SAFE_ALIAS, authorization.ownerAlias) ||
    !positiveInteger(authorization.maxRequests) ||
    authorization.maxRequests > 100
  ) {
    return false;
  }
  const approvedAt = Date.parse(authorization.approvedAtUtc);
  const expiresAt = Date.parse(authorization.expiresAtUtc);
  const executedAt = Date.parse(executedAtUtc);
  return approvedAt <= executedAt && executedAt <= expiresAt && approvedAt < expiresAt;
};

const validQaTarget = (target) =>
  exactKeys(target, [
    'classification',
    'environment',
    'originSha256',
    'ownershipVerified',
    'production',
  ]) &&
  target.classification === 'OWNED_EPHEMERAL_QA' &&
  target.environment === 'ENV-E6-QA' &&
  regexMatchesString(SHA256, target.originSha256) &&
  target.ownershipVerified === true &&
  target.production === false;

const validOwnedTarget = (capability, executedAtUtc) => {
  if (
    !exactKeys(capability, [
      'status',
      'authorization',
      'target',
      'checks',
      'requests',
      'evidenceIds',
      'reportSha256',
    ]) ||
    capability.status !== 'PASS' ||
    !validQaTarget(capability.target) ||
    !validAuthorization(
      capability.authorization,
      {
        id: 'AUTH-E6-01',
        scope: 'OWNED_EPHEMERAL_QA_HTTPS_VERIFICATION',
        targetSha256: capability.target.originSha256,
      },
      executedAtUtc,
    ) ||
    !Array.isArray(capability.checks) ||
    capability.checks.length !== OWNED_TARGET_CHECKS.length ||
    !exactStrings(capability.evidenceIds, ['AUTH-E6-01', 'UAT-33', 'EVD-E6-36/UAT-33']) ||
    !regexMatchesString(SHA256, capability.reportSha256)
  ) {
    return false;
  }
  const checksReady = capability.checks.every((check, index) => {
    const [id, name] = OWNED_TARGET_CHECKS[index];
    if (index === 0) {
      return (
        exactKeys(check, ['id', 'name', 'status', 'observedStatus']) &&
        check.id === id &&
        check.name === name &&
        check.status === 'PASS' &&
        [301, 308].includes(check.observedStatus)
      );
    }
    if (index === 1) {
      return exact(check, { id, name, status: 'PASS', observedStatus: 200 });
    }
    return exact(check, { id, name, status: 'PASS', observedRequests: 0 });
  });
  const requests = capability.requests;
  return (
    checksReady &&
    exactKeys(requests, ['total', 'outsideAllowlist', 'provider', 'production']) &&
    positiveInteger(requests.total) &&
    requests.total <= capability.authorization.maxRequests &&
    requests.outsideAllowlist === 0 &&
    requests.provider === 0 &&
    requests.production === 0
  );
};

const validSandboxTarget = (target) =>
  exactKeys(target, [
    'classification',
    'environment',
    'hostSha256',
    'allowlistVerified',
    'production',
  ]) &&
  target.classification === 'AUTHORIZED_PROVIDER_SANDBOX' &&
  target.environment === 'sandbox' &&
  regexMatchesString(SHA256, target.hostSha256) &&
  target.allowlistVerified === true &&
  target.production === false;

const validSandboxSmoke = (capability, executedAtUtc) => {
  if (
    !exactKeys(capability, [
      'status',
      'authorization',
      'target',
      'reference',
      'checks',
      'requests',
      'result',
      'evidenceIds',
      'reportSha256',
    ]) ||
    capability.status !== 'PASS' ||
    !validSandboxTarget(capability.target) ||
    !validAuthorization(
      capability.authorization,
      {
        id: 'AUTH-E6-02',
        scope: 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
        targetSha256: capability.target.hostSha256,
      },
      executedAtUtc,
    ) ||
    !Array.isArray(capability.checks) ||
    capability.checks.length !== SANDBOX_CHECKS.length ||
    !capability.checks.every((check, index) => {
      const [id, name] = SANDBOX_CHECKS[index];
      return exact(check, { id, name, status: 'PASS' });
    }) ||
    !exactStrings(capability.evidenceIds, ['AUTH-E6-02', 'EVD-E6-24', 'ART-VER-07']) ||
    !regexMatchesString(SHA256, capability.reportSha256)
  ) {
    return false;
  }
  const reference = capability.reference;
  if (
    !exactKeys(reference, ['prefix', 'sha256', 'runScoped', 'rawValueCaptured']) ||
    reference.prefix !== 'e6-' ||
    !regexMatchesString(SHA256, reference.sha256) ||
    reference.runScoped !== true ||
    reference.rawValueCaptured !== false
  ) {
    return false;
  }
  const requests = capability.requests;
  if (
    !exactKeys(requests, [
      'total',
      'configurationReads',
      'paymentMethodCreations',
      'transactionCreates',
      'statusReads',
      'errorMappingProbes',
      'reconciliationReplays',
      'production',
      'globalMutations',
      'outsideAllowlist',
    ]) ||
    ![
      requests.configurationReads,
      requests.paymentMethodCreations,
      requests.transactionCreates,
      requests.statusReads,
      requests.errorMappingProbes,
      requests.reconciliationReplays,
    ].every(nonNegativeInteger) ||
    requests.configurationReads < 1 ||
    requests.paymentMethodCreations !== 1 ||
    requests.transactionCreates !== 1 ||
    requests.statusReads < 1 ||
    requests.errorMappingProbes < 1 ||
    requests.reconciliationReplays < 1 ||
    requests.total !==
      requests.configurationReads +
        requests.paymentMethodCreations +
        requests.transactionCreates +
        requests.statusReads +
        requests.errorMappingProbes +
        requests.reconciliationReplays ||
    requests.total > capability.authorization.maxRequests ||
    requests.production !== 0 ||
    requests.globalMutations !== 0 ||
    requests.outsideAllowlist !== 0
  ) {
    return false;
  }
  const result = capability.result;
  const states = ['APPROVED', 'DECLINED', 'ERROR', 'PENDING'];
  return (
    exactKeys(result, [
      'providerState',
      'localState',
      'amountMatches',
      'currencyMatches',
      'referenceMatches',
      'reconciliationConsistent',
      'duplicateEffects',
      'adapterDisabledByConfiguration',
    ]) &&
    states.includes(result.providerState) &&
    result.localState === result.providerState &&
    result.amountMatches === true &&
    result.currencyMatches === true &&
    result.referenceMatches === true &&
    result.reconciliationConsistent === true &&
    result.duplicateEffects === 0 &&
    result.adapterDisabledByConfiguration === true
  );
};

const validFindings = (findings) =>
  exactKeys(findings, [
    'total',
    'reviewed',
    'critical',
    'high',
    'medium',
    'low',
    'informational',
  ]) &&
  [
    findings.total,
    findings.reviewed,
    findings.critical,
    findings.high,
    findings.medium,
    findings.low,
    findings.informational,
  ].every(nonNegativeInteger) &&
  findings.total ===
    findings.critical + findings.high + findings.medium + findings.low + findings.informational &&
  findings.reviewed === findings.total &&
  findings.critical === 0 &&
  findings.high === 0;

const validPassiveSecurity = (capability, executedAtUtc) => {
  if (
    !exactKeys(capability, [
      'status',
      'authorization',
      'target',
      'headerChecks',
      'sensitiveResponsesNoStore',
      'criticalHeadersMissing',
      'zap',
      'requests',
      'evidenceIds',
    ]) ||
    capability.status !== 'PASS' ||
    !validQaTarget(capability.target) ||
    !validAuthorization(
      capability.authorization,
      {
        id: 'AUTH-E6-03',
        scope: 'PASSIVE_BASELINE_OWNED_QA_ONLY',
        targetSha256: capability.target.originSha256,
      },
      executedAtUtc,
    ) ||
    !Array.isArray(capability.headerChecks) ||
    capability.headerChecks.length !== HEADER_CHECKS.length ||
    !capability.headerChecks.every((check, index) => {
      const [id, name] = HEADER_CHECKS[index];
      return exact(check, { id, name, status: 'PASS' });
    }) ||
    capability.sensitiveResponsesNoStore !== true ||
    capability.criticalHeadersMissing !== 0 ||
    !exactStrings(capability.evidenceIds, ['AUTH-E6-03', 'EVD-E6-33', 'EVD-E6-34'])
  ) {
    return false;
  }
  const zap = capability.zap;
  if (
    !exactKeys(zap, [
      'mode',
      'tool',
      'rulesetSha256',
      'reportSha256',
      'ownEndpointsScanned',
      'ownEndpointsOutOfScope',
      'findings',
      'manualValidation',
    ]) ||
    zap.mode !== 'PASSIVE_BASELINE' ||
    !exactKeys(zap.tool, ['name', 'version']) ||
    zap.tool.name !== 'OWASP_ZAP_BASELINE' ||
    !ALLOWED_ZAP_VERSIONS.has(zap.tool.version) ||
    !regexMatchesString(SHA256, zap.rulesetSha256) ||
    !regexMatchesString(SHA256, zap.reportSha256) ||
    !positiveInteger(zap.ownEndpointsScanned) ||
    zap.ownEndpointsOutOfScope !== 0 ||
    !validFindings(zap.findings) ||
    zap.manualValidation !== 'ALL_ALERTS_REVIEWED'
  ) {
    return false;
  }
  const requests = capability.requests;
  return (
    exactKeys(requests, [
      'total',
      'outsideAllowlist',
      'provider',
      'production',
      'externalRedirectsFollowed',
      'activeScan',
    ]) &&
    positiveInteger(requests.total) &&
    requests.total <= capability.authorization.maxRequests &&
    requests.outsideAllowlist === 0 &&
    requests.provider === 0 &&
    requests.production === 0 &&
    requests.externalRedirectsFollowed === 0 &&
    requests.activeScan === 0
  );
};

const validateRawExternalEvidence = (evidence, execution) => {
  try {
    if (
      !exactKeys(evidence, [
        'schemaId',
        'schemaVersion',
        'stage',
        'protocolVersion',
        'protocolDocumentSha256',
        'commitSha',
        'runId',
        'executedAtUtc',
        'reviewerAlias',
        'capabilities',
        'containsSensitiveData',
      ]) ||
      evidence.schemaId !== SCHEMA_ID ||
      evidence.schemaVersion !== 1 ||
      evidence.stage !== 6 ||
      evidence.protocolVersion !== PROTOCOL_VERSION ||
      evidence.protocolDocumentSha256 !== protocolDocumentSha256 ||
      evidence.commitSha !== execution.commitSha ||
      !regexMatchesString(COMMIT_SHA, evidence.commitSha) ||
      !regexMatchesString(RUN_ID, evidence.runId) ||
      evidence.runId === execution.ingestedByRunId ||
      !validUtc(evidence.executedAtUtc) ||
      Date.parse(evidence.executedAtUtc) > Date.now() + MAX_FUTURE_SKEW_MS ||
      !regexMatchesString(SAFE_ALIAS, evidence.reviewerAlias) ||
      evidence.containsSensitiveData !== false ||
      evidence.capabilities === null ||
      typeof evidence.capabilities !== 'object' ||
      Array.isArray(evidence.capabilities)
    ) {
      return false;
    }
    const capabilityKeys = Object.keys(evidence.capabilities);
    if (
      capabilityKeys.length < 1 ||
      capabilityKeys.length > EXTERNAL_CAPABILITY_KEYS.length ||
      capabilityKeys.some((key) => !EXTERNAL_CAPABILITY_KEYS.includes(key))
    ) {
      return false;
    }
    const { ownedTarget, sandboxSmoke, passiveSecurity } = evidence.capabilities;
    if (ownedTarget !== undefined && !validOwnedTarget(ownedTarget, evidence.executedAtUtc)) {
      return false;
    }
    if (sandboxSmoke !== undefined && !validSandboxSmoke(sandboxSmoke, evidence.executedAtUtc)) {
      return false;
    }
    if (
      passiveSecurity !== undefined &&
      !validPassiveSecurity(passiveSecurity, evidence.executedAtUtc)
    ) {
      return false;
    }
    return (
      ownedTarget === undefined ||
      passiveSecurity === undefined ||
      ownedTarget.target.originSha256 === passiveSecurity.target.originSha256
    );
  } catch {
    return false;
  }
};

const summarizedStatus = (capabilities) =>
  Object.keys(capabilities).length === EXTERNAL_CAPABILITY_KEYS.length ? 'PASS' : 'PARTIAL';

const summarizeExternalEvidence = (raw, sourceSha256, execution) => ({
  status: summarizedStatus(raw.capabilities),
  source: 'EXTERNAL_VERSIONED_JSON',
  schemaId: SCHEMA_ID,
  schemaVersion: 1,
  protocolVersion: PROTOCOL_VERSION,
  sourceSha256,
  schemaSha256,
  protocolDocumentSha256,
  commitSha: raw.commitSha,
  sourceExternalRunId: raw.runId,
  ingestedByRunId: execution.ingestedByRunId,
  executedAtUtc: raw.executedAtUtc,
  reviewerAlias: raw.reviewerAlias,
  capabilities: structuredClone(raw.capabilities),
  containsSensitiveData: false,
  sanitization: SUMMARY_SANITIZATION,
});

export const validateExternalEvidenceSummary = (summary, execution) => {
  try {
    if (
      !exactKeys(summary, [
        'status',
        'source',
        'schemaId',
        'schemaVersion',
        'protocolVersion',
        'sourceSha256',
        'schemaSha256',
        'protocolDocumentSha256',
        'commitSha',
        'sourceExternalRunId',
        'ingestedByRunId',
        'executedAtUtc',
        'reviewerAlias',
        'capabilities',
        'containsSensitiveData',
        'sanitization',
      ]) ||
      !['PASS', 'PARTIAL'].includes(summary.status) ||
      summary.source !== 'EXTERNAL_VERSIONED_JSON' ||
      summary.schemaId !== SCHEMA_ID ||
      summary.schemaVersion !== 1 ||
      summary.protocolVersion !== PROTOCOL_VERSION ||
      !regexMatchesString(SHA256, summary.sourceSha256) ||
      summary.schemaSha256 !== schemaSha256 ||
      summary.protocolDocumentSha256 !== protocolDocumentSha256 ||
      summary.commitSha !== execution.commitSha ||
      summary.sourceExternalRunId === summary.ingestedByRunId ||
      summary.ingestedByRunId !== execution.runId ||
      summary.containsSensitiveData !== false ||
      !exact(summary.sanitization, SUMMARY_SANITIZATION)
    ) {
      return false;
    }
    const rawShape = {
      schemaId: summary.schemaId,
      schemaVersion: summary.schemaVersion,
      stage: 6,
      protocolVersion: summary.protocolVersion,
      protocolDocumentSha256: summary.protocolDocumentSha256,
      commitSha: summary.commitSha,
      runId: summary.sourceExternalRunId,
      executedAtUtc: summary.executedAtUtc,
      reviewerAlias: summary.reviewerAlias,
      capabilities: summary.capabilities,
      containsSensitiveData: summary.containsSensitiveData,
    };
    return (
      validateJsonSchemaSubset(rawShape, schemaDocument) &&
      validateRawExternalEvidence(rawShape, {
        commitSha: execution.commitSha,
        ingestedByRunId: execution.runId,
      }) &&
      summary.status === summarizedStatus(summary.capabilities)
    );
  } catch {
    return false;
  }
};

export const missingExternalEvidence = (execution) => ({
  status: 'NOT_PROVIDED',
  source: 'NOT_PROVIDED',
  commitSha: execution.commitSha,
  ingestedByRunId: execution.runId,
  acceptedChannels: ACCEPTED_CHANNELS,
  capabilityStatus: Object.fromEntries(
    EXTERNAL_CAPABILITY_KEYS.map((key) => [key, 'NOT_RUN_AUTH_REQUIRED']),
  ),
  containsSensitiveData: false,
});

export const failedExternalEvidence = (execution, failureCode) => ({
  status: 'FAIL',
  source: 'CONFIGURED_INPUT_REJECTED',
  failureCode: regexMatchesString(/^EXTERNAL_EVIDENCE_[A-Z0-9_]{3,80}$/u, failureCode)
    ? failureCode
    : 'EXTERNAL_EVIDENCE_INGESTION_FAILED',
  commitSha: execution.commitSha,
  ingestedByRunId: execution.runId,
  containsSensitiveData: false,
});

export const externalEvidenceMissingIsExact = (summary, execution) =>
  exact(summary, missingExternalEvidence(execution));

export const externalEvidenceFailureIsExact = (summary, execution) =>
  exactKeys(summary, [
    'status',
    'source',
    'failureCode',
    'commitSha',
    'ingestedByRunId',
    'containsSensitiveData',
  ]) &&
  summary.status === 'FAIL' &&
  summary.source === 'CONFIGURED_INPUT_REJECTED' &&
  regexMatchesString(/^EXTERNAL_EVIDENCE_[A-Z0-9_]{3,80}$/u, summary.failureCode) &&
  summary.commitSha === execution.commitSha &&
  summary.ingestedByRunId === execution.runId &&
  summary.containsSensitiveData === false;

export const externalEvidenceCapabilityDecision = (summary, capability, execution) => {
  if (!EXTERNAL_CAPABILITY_KEYS.includes(capability)) return 'FAIL';
  if (externalEvidenceMissingIsExact(summary, execution)) return 'NOT_RUN_AUTH_REQUIRED';
  if (!validateExternalEvidenceSummary(summary, execution)) return 'FAIL';
  return summary.capabilities[capability] === undefined ? 'NOT_RUN_AUTH_REQUIRED' : 'PASS';
};

export const externalPassiveSecurityChecks = (summary, execution) => {
  const decision = externalEvidenceCapabilityDecision(summary, 'passiveSecurity', execution);
  if (decision === 'FAIL') return undefined;
  if (decision === 'NOT_RUN_AUTH_REQUIRED') {
    return [
      { id: 'SEC-E6-EXT-03', name: 'qa-edge-headers', status: decision },
      { id: 'SEC-E6-EXT-04', name: 'zap-baseline-own-target', status: decision },
    ];
  }
  const capability = summary.capabilities.passiveSecurity;
  return [
    {
      id: 'SEC-E6-EXT-03',
      name: 'qa-edge-headers',
      status: 'PASS',
      source: 'EXTERNAL_VERSIONED_JSON',
      authorizationId: 'AUTH-E6-03',
      sourceSha256: summary.sourceSha256,
      targetOriginSha256: capability.target.originSha256,
      headerChecks: capability.headerChecks,
      sensitiveResponsesNoStore: capability.sensitiveResponsesNoStore,
      criticalHeadersMissing: capability.criticalHeadersMissing,
    },
    {
      id: 'SEC-E6-EXT-04',
      name: 'zap-baseline-own-target',
      status: 'PASS',
      source: 'EXTERNAL_VERSIONED_JSON',
      authorizationId: 'AUTH-E6-03',
      sourceSha256: summary.sourceSha256,
      targetOriginSha256: capability.target.originSha256,
      zap: capability.zap,
      requests: capability.requests,
      evidenceIds: capability.evidenceIds,
    },
  ];
};

const FORBIDDEN_NONLOCAL_PATH = /^(?:\\\\|\/\/)/u;
export const externalEvidencePathIsLocal = (value) =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.trim() === value &&
  !FORBIDDEN_NONLOCAL_PATH.test(value);
export const externalEvidencePath = (
  arguments_ = process.argv.slice(2),
  environment = process.env,
) => {
  if (!Array.isArray(arguments_)) {
    reject('EXTERNAL_EVIDENCE_ARGUMENTS_INVALID');
  }
  const flagIndexes = arguments_
    .map((argument, index) => (argument === '--external-evidence' ? index : -1))
    .filter((index) => index >= 0);
  if (flagIndexes.length > 1) reject('EXTERNAL_EVIDENCE_PATH_DUPLICATE');
  const flagIndex = flagIndexes[0] ?? -1;
  const flagValue = flagIndex === -1 ? undefined : arguments_[flagIndex + 1];
  if (
    flagIndex !== -1 &&
    (typeof flagValue !== 'string' || flagValue.length === 0 || flagValue.startsWith('--'))
  ) {
    reject('EXTERNAL_EVIDENCE_PATH_MISSING');
  }
  const configured = environment.STAGE6_EXTERNAL_EVIDENCE;
  if (flagValue !== undefined && !externalEvidencePathIsLocal(flagValue))
    reject('EXTERNAL_EVIDENCE_PATH_NOT_LOCAL');
  if (configured !== undefined && !externalEvidencePathIsLocal(configured))
    reject('EXTERNAL_EVIDENCE_PATH_NOT_LOCAL');
  if (
    flagValue !== undefined &&
    configured !== undefined &&
    path.resolve(flagValue) !== path.resolve(configured)
  ) {
    reject('EXTERNAL_EVIDENCE_PATH_CONFLICT');
  }
  const selected = flagValue ?? configured;
  if (selected === undefined) return undefined;
  if (!externalEvidencePathIsLocal(selected)) reject('EXTERNAL_EVIDENCE_PATH_NOT_LOCAL');
  const resolved = path.resolve(selected);
  if (!externalEvidencePathIsLocal(resolved)) reject('EXTERNAL_EVIDENCE_PATH_NOT_LOCAL');
  return resolved;
};

export const loadExternalEvidence = async ({ sourcePath, commitSha, ingestedByRunId }) => {
  if (!regexMatchesString(COMMIT_SHA, commitSha)) reject('EXTERNAL_EVIDENCE_EXPECTED_SHA_INVALID');
  if (!regexMatchesString(RUN_ID, ingestedByRunId))
    reject('EXTERNAL_EVIDENCE_INGESTED_RUN_ID_INVALID');
  if (!externalEvidencePathIsLocal(sourcePath)) reject('EXTERNAL_EVIDENCE_PATH_NOT_LOCAL');
  const resolvedSourcePath = path.resolve(sourcePath);
  if (!externalEvidencePathIsLocal(resolvedSourcePath)) reject('EXTERNAL_EVIDENCE_PATH_NOT_LOCAL');
  let source;
  let handle;
  try {
    const linkInfo = await lstat(resolvedSourcePath);
    if (!linkInfo.isFile() || linkInfo.isSymbolicLink())
      reject('EXTERNAL_EVIDENCE_FILE_NOT_REGULAR');
    if (linkInfo.size > MAX_SOURCE_BYTES) reject('EXTERNAL_EVIDENCE_FILE_TOO_LARGE');
    handle = await open(resolvedSourcePath, 'r');
    const openedInfo = await handle.stat();
    if (!openedInfo.isFile()) reject('EXTERNAL_EVIDENCE_FILE_NOT_REGULAR');
    if (openedInfo.size > MAX_SOURCE_BYTES) reject('EXTERNAL_EVIDENCE_FILE_TOO_LARGE');
    source = await handle.readFile();
  } catch (error) {
    if (error instanceof ExternalEvidenceError) throw error;
    reject('EXTERNAL_EVIDENCE_FILE_UNREADABLE');
  } finally {
    if (handle !== undefined) await handle.close();
  }
  let raw;
  try {
    raw = parseStrictJsonSource(source);
  } catch (error) {
    reject(
      error instanceof StrictJsonError
        ? `EXTERNAL_EVIDENCE_${error.code}`
        : 'EXTERNAL_EVIDENCE_JSON_INVALID',
    );
  }
  if (
    schemaDocument?.$id !== SCHEMA_URI ||
    schemaDocument?.properties?.schemaId?.const !== SCHEMA_ID
  ) {
    reject('EXTERNAL_EVIDENCE_SCHEMA_FILE_INVALID');
  }
  const execution = { commitSha, ingestedByRunId };
  if (
    !validateJsonSchemaSubset(raw, schemaDocument) ||
    !validateRawExternalEvidence(raw, execution)
  )
    reject('EXTERNAL_EVIDENCE_CONTRACT_INVALID');
  return summarizeExternalEvidence(raw, hash(source), execution);
};

export const resolveExternalEvidence = async ({
  commitSha,
  runId,
  arguments_ = process.argv.slice(2),
  environment = process.env,
}) => {
  const execution = { commitSha, runId };
  let sourcePath;
  try {
    sourcePath = externalEvidencePath(arguments_, environment);
  } catch (error) {
    return failedExternalEvidence(
      execution,
      error instanceof ExternalEvidenceError
        ? error.code
        : 'EXTERNAL_EVIDENCE_CONFIGURATION_FAILED',
    );
  }
  if (sourcePath === undefined) return missingExternalEvidence(execution);
  try {
    return await loadExternalEvidence({ sourcePath, commitSha, ingestedByRunId: runId });
  } catch (error) {
    return failedExternalEvidence(
      execution,
      error instanceof ExternalEvidenceError ? error.code : 'EXTERNAL_EVIDENCE_INGESTION_FAILED',
    );
  }
};

const authorizationFixture = ({ id, scope, targetSha256, maxRequests, executedAtUtc }) => ({
  id,
  status: 'APPROVED',
  scope,
  approvalSha256: '1'.repeat(64),
  approvedTargetSha256: targetSha256,
  approvedAtUtc: new Date(Date.parse(executedAtUtc) - 60_000).toISOString(),
  expiresAtUtc: new Date(Date.parse(executedAtUtc) + 60 * 60_000).toISOString(),
  ownerAlias: 'qa-owner',
  maxRequests,
});

const validRawFixture = (capabilityKeys = EXTERNAL_CAPABILITY_KEYS) => {
  const executedAtUtc = new Date(Math.floor((Date.now() - 1_000) / 1_000) * 1_000).toISOString();
  const qaTarget = {
    classification: 'OWNED_EPHEMERAL_QA',
    environment: 'ENV-E6-QA',
    originSha256: '2'.repeat(64),
    ownershipVerified: true,
    production: false,
  };
  const sandboxTarget = {
    classification: 'AUTHORIZED_PROVIDER_SANDBOX',
    environment: 'sandbox',
    hostSha256: '3'.repeat(64),
    allowlistVerified: true,
    production: false,
  };
  const capabilities = {
    ownedTarget: {
      status: 'PASS',
      authorization: authorizationFixture({
        id: 'AUTH-E6-01',
        scope: 'OWNED_EPHEMERAL_QA_HTTPS_VERIFICATION',
        targetSha256: qaTarget.originSha256,
        maxRequests: 10,
        executedAtUtc,
      }),
      target: qaTarget,
      checks: [
        {
          id: 'AUTH01-E6-01',
          name: 'http-redirect-to-https',
          status: 'PASS',
          observedStatus: 308,
        },
        {
          id: 'AUTH01-E6-02',
          name: 'https-document-available',
          status: 'PASS',
          observedStatus: 200,
        },
        {
          id: 'AUTH01-E6-03',
          name: 'mixed-content-requests-zero',
          status: 'PASS',
          observedRequests: 0,
        },
      ],
      requests: { total: 3, outsideAllowlist: 0, provider: 0, production: 0 },
      evidenceIds: ['AUTH-E6-01', 'UAT-33', 'EVD-E6-36/UAT-33'],
      reportSha256: '4'.repeat(64),
    },
    sandboxSmoke: {
      status: 'PASS',
      authorization: authorizationFixture({
        id: 'AUTH-E6-02',
        scope: 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
        targetSha256: sandboxTarget.hostSha256,
        maxRequests: 20,
        executedAtUtc,
      }),
      target: sandboxTarget,
      reference: {
        prefix: 'e6-',
        sha256: '5'.repeat(64),
        runScoped: true,
        rawValueCaptured: false,
      },
      checks: SANDBOX_CHECKS.map(([id, name]) => ({ id, name, status: 'PASS' })),
      requests: {
        total: 7,
        configurationReads: 1,
        paymentMethodCreations: 1,
        transactionCreates: 1,
        statusReads: 2,
        errorMappingProbes: 1,
        reconciliationReplays: 1,
        production: 0,
        globalMutations: 0,
        outsideAllowlist: 0,
      },
      result: {
        providerState: 'PENDING',
        localState: 'PENDING',
        amountMatches: true,
        currencyMatches: true,
        referenceMatches: true,
        reconciliationConsistent: true,
        duplicateEffects: 0,
        adapterDisabledByConfiguration: true,
      },
      evidenceIds: ['AUTH-E6-02', 'EVD-E6-24', 'ART-VER-07'],
      reportSha256: '6'.repeat(64),
    },
    passiveSecurity: {
      status: 'PASS',
      authorization: authorizationFixture({
        id: 'AUTH-E6-03',
        scope: 'PASSIVE_BASELINE_OWNED_QA_ONLY',
        targetSha256: qaTarget.originSha256,
        maxRequests: 50,
        executedAtUtc,
      }),
      target: qaTarget,
      headerChecks: HEADER_CHECKS.map(([id, name]) => ({ id, name, status: 'PASS' })),
      sensitiveResponsesNoStore: true,
      criticalHeadersMissing: 0,
      zap: {
        mode: 'PASSIVE_BASELINE',
        tool: { name: 'OWASP_ZAP_BASELINE', version: '2.16.1' },
        rulesetSha256: '7'.repeat(64),
        reportSha256: '8'.repeat(64),
        ownEndpointsScanned: 4,
        ownEndpointsOutOfScope: 0,
        findings: {
          total: 2,
          reviewed: 2,
          critical: 0,
          high: 0,
          medium: 1,
          low: 1,
          informational: 0,
        },
        manualValidation: 'ALL_ALERTS_REVIEWED',
      },
      requests: {
        total: 10,
        outsideAllowlist: 0,
        provider: 0,
        production: 0,
        externalRedirectsFollowed: 0,
        activeScan: 0,
      },
      evidenceIds: ['AUTH-E6-03', 'EVD-E6-33', 'EVD-E6-34'],
    },
  };
  return {
    schemaId: SCHEMA_ID,
    schemaVersion: 1,
    stage: 6,
    protocolVersion: PROTOCOL_VERSION,
    protocolDocumentSha256,
    commitSha: 'a'.repeat(40),
    runId: 'e6-20260815t120000z-89abcdef',
    executedAtUtc,
    reviewerAlias: 'qa-reviewer',
    capabilities: Object.fromEntries(
      EXTERNAL_CAPABILITY_KEYS.filter((key) => capabilityKeys.includes(key)).map((key) => [
        key,
        capabilities[key],
      ]),
    ),
    containsSensitiveData: false,
  };
};

export const selfTestExternalEvidence = () => {
  selfTestStrictJson();
  const schema = schemaDocument;
  assert.equal(schema.$id, SCHEMA_URI);
  assert.equal(schema.properties.schemaId.const, SCHEMA_ID);
  const execution = {
    commitSha: 'a'.repeat(40),
    ingestedByRunId: 'e6-20260816t120000z-0123abcd',
  };
  const summaryExecution = { commitSha: execution.commitSha, runId: execution.ingestedByRunId };
  const valid = validRawFixture();
  assert.equal(validateJsonSchemaSubset(valid, schema), true);
  assert.equal(validateRawExternalEvidence(valid, execution), true);
  const reorderedTop = Object.fromEntries(Object.entries(valid).reverse());
  assert.equal(validateJsonSchemaSubset(reorderedTop, schema), true);
  assert.equal(validateRawExternalEvidence(reorderedTop, execution), true);
  const reorderedAuthorization = structuredClone(valid);
  reorderedAuthorization.capabilities.ownedTarget.authorization = Object.fromEntries(
    Object.entries(reorderedAuthorization.capabilities.ownedTarget.authorization).reverse(),
  );
  assert.equal(validateJsonSchemaSubset(reorderedAuthorization, schema), true);
  assert.equal(validateRawExternalEvidence(reorderedAuthorization, execution), true);
  const reorderedCheckFields = structuredClone(valid);
  reorderedCheckFields.capabilities.ownedTarget.checks[0] = Object.fromEntries(
    Object.entries(reorderedCheckFields.capabilities.ownedTarget.checks[0]).reverse(),
  );
  assert.equal(validateJsonSchemaSubset(reorderedCheckFields, schema), true);
  assert.equal(validateRawExternalEvidence(reorderedCheckFields, execution), true);
  const reorderedCapabilities = structuredClone(valid);
  reorderedCapabilities.capabilities = Object.fromEntries(
    Object.entries(reorderedCapabilities.capabilities).reverse(),
  );
  assert.equal(validateJsonSchemaSubset(reorderedCapabilities, schema), true);
  assert.equal(validateRawExternalEvidence(reorderedCapabilities, execution), true);
  const reorderedCheckArray = structuredClone(valid);
  [
    reorderedCheckArray.capabilities.ownedTarget.checks[0],
    reorderedCheckArray.capabilities.ownedTarget.checks[1],
  ] = [
    reorderedCheckArray.capabilities.ownedTarget.checks[1],
    reorderedCheckArray.capabilities.ownedTarget.checks[0],
  ];
  assert.equal(validateJsonSchemaSubset(reorderedCheckArray, schema), false);
  assert.equal(validateRawExternalEvidence(reorderedCheckArray, execution), false);
  const summary = summarizeExternalEvidence(valid, '9'.repeat(64), execution);
  assert.equal(validateExternalEvidenceSummary(summary, summaryExecution), true);
  assert.equal(
    EXTERNAL_CAPABILITY_KEYS.every(
      (capability) =>
        externalEvidenceCapabilityDecision(summary, capability, summaryExecution) === 'PASS',
    ),
    true,
  );
  assert.equal(externalPassiveSecurityChecks(summary, summaryExecution)?.length, 2);
  assert.equal(externalPassiveSecurityChecks(summary, summaryExecution)?.[0]?.status, 'PASS');

  const partialRaw = validRawFixture(['ownedTarget']);
  const partial = summarizeExternalEvidence(partialRaw, '9'.repeat(64), execution);
  assert.equal(validateExternalEvidenceSummary(partial, summaryExecution), true);
  assert.equal(
    externalEvidenceCapabilityDecision(partial, 'sandboxSmoke', summaryExecution),
    'NOT_RUN_AUTH_REQUIRED',
  );
  assert.equal(
    externalPassiveSecurityChecks(partial, summaryExecution)?.every(
      ({ status }) => status === 'NOT_RUN_AUTH_REQUIRED',
    ),
    true,
  );
  const missing = missingExternalEvidence(summaryExecution);
  assert.equal(externalEvidenceMissingIsExact(missing, summaryExecution), true);
  assert.equal(
    externalEvidenceCapabilityDecision(missing, 'ownedTarget', summaryExecution),
    'NOT_RUN_AUTH_REQUIRED',
  );
  const failed = failedExternalEvidence(summaryExecution, 'EXTERNAL_EVIDENCE_CONTRACT_INVALID');
  assert.equal(externalEvidenceFailureIsExact(failed, summaryExecution), true);
  assert.equal(externalEvidenceCapabilityDecision(failed, 'ownedTarget', summaryExecution), 'FAIL');

  const wrongSha = structuredClone(valid);
  wrongSha.commitSha = 'b'.repeat(40);
  assert.equal(validateRawExternalEvidence(wrongSha, execution), false);
  const wrongRun = structuredClone(valid);
  wrongRun.runId = execution.ingestedByRunId;
  assert.equal(validateJsonSchemaSubset(wrongSha, schema), true);
  assert.equal(validateRawExternalEvidence(wrongRun, execution), false);
  const wrongAuthorization = structuredClone(valid);
  wrongAuthorization.capabilities.ownedTarget.authorization.id = 'AUTH-E6-03';
  assert.equal(validateRawExternalEvidence(wrongAuthorization, execution), false);
  assert.equal(validateJsonSchemaSubset(wrongRun, schema), true);
  const wrongTarget = structuredClone(valid);
  wrongTarget.capabilities.ownedTarget.target.production = true;
  assert.equal(validateRawExternalEvidence(wrongTarget, execution), false);
  const wrongFindings = structuredClone(valid);
  assert.equal(validateJsonSchemaSubset(wrongAuthorization, schema), false);
  wrongFindings.capabilities.passiveSecurity.zap.findings.high = 1;
  wrongFindings.capabilities.passiveSecurity.zap.findings.total = 3;
  wrongFindings.capabilities.passiveSecurity.zap.findings.reviewed = 3;
  assert.equal(validateRawExternalEvidence(wrongFindings, execution), false);
  assert.equal(validateJsonSchemaSubset(wrongFindings, schema), false);
  assert.equal(validateJsonSchemaSubset(wrongTarget, schema), false);
  const sandboxProduction = structuredClone(valid);
  sandboxProduction.capabilities.sandboxSmoke.requests.production = 1;
  assert.equal(validateRawExternalEvidence(sandboxProduction, execution), false);
  assert.equal(validateJsonSchemaSubset(sandboxProduction, schema), false);
  const reorderedHeaders = structuredClone(valid);
  [
    reorderedHeaders.capabilities.passiveSecurity.headerChecks[0],
    reorderedHeaders.capabilities.passiveSecurity.headerChecks[1],
  ] = [
    reorderedHeaders.capabilities.passiveSecurity.headerChecks[1],
    reorderedHeaders.capabilities.passiveSecurity.headerChecks[0],
  ];
  assert.equal(validateRawExternalEvidence(reorderedHeaders, execution), false);
  assert.equal(
    validateExternalEvidenceSummary(
      { ...summary, ingestedByRunId: 'e6-20260816t120000z-deadbeef' },
      summaryExecution,
    ),
    false,
  );
  assert.equal(validateJsonSchemaSubset(reorderedHeaders, schema), false);
  const extraTargetField = structuredClone(valid);
  extraTargetField.capabilities.ownedTarget.target.origin = 'forbidden';
  assert.equal(validateJsonSchemaSubset(extraTargetField, schema), false);
  assert.equal(validateRawExternalEvidence(extraTargetField, execution), false);
  const reorderedEvidenceIds = structuredClone(valid);
  [
    reorderedEvidenceIds.capabilities.sandboxSmoke.evidenceIds[0],
    reorderedEvidenceIds.capabilities.sandboxSmoke.evidenceIds[1],
  ] = [
    reorderedEvidenceIds.capabilities.sandboxSmoke.evidenceIds[1],
    reorderedEvidenceIds.capabilities.sandboxSmoke.evidenceIds[0],
  ];
  assert.equal(validateJsonSchemaSubset(reorderedEvidenceIds, schema), false);
  assert.equal(validateRawExternalEvidence(reorderedEvidenceIds, execution), false);
  const activeDast = structuredClone(valid);
  activeDast.capabilities.activeDast = { authorization: 'AUTH-E6-04', status: 'PASS' };
  assert.equal(validateJsonSchemaSubset(activeDast, schema), false);
  assert.equal(validateRawExternalEvidence(activeDast, execution), false);
  const wrongCommitType = structuredClone(valid);
  wrongCommitType.commitSha = [valid.commitSha];
  assert.equal(validateJsonSchemaSubset(wrongCommitType, schema), false);
  assert.equal(validateRawExternalEvidence(wrongCommitType, execution), false);
  const wrongRunType = structuredClone(valid);
  wrongRunType.runId = [valid.runId];
  assert.equal(validateJsonSchemaSubset(wrongRunType, schema), false);
  assert.equal(validateRawExternalEvidence(wrongRunType, execution), false);
  const wrongHashType = structuredClone(valid);
  wrongHashType.capabilities.ownedTarget.authorization.approvalSha256 = ['1'.repeat(64)];
  assert.equal(validateJsonSchemaSubset(wrongHashType, schema), false);
  assert.equal(validateRawExternalEvidence(wrongHashType, execution), false);
  const wrongAliasType = structuredClone(valid);
  wrongAliasType.reviewerAlias = 7;
  assert.equal(validateJsonSchemaSubset(wrongAliasType, schema), false);
  assert.equal(validateRawExternalEvidence(wrongAliasType, execution), false);
  const wrongToolVersionType = structuredClone(valid);
  wrongToolVersionType.capabilities.passiveSecurity.zap.tool.version = 2161;
  assert.equal(validateJsonSchemaSubset(wrongToolVersionType, schema), false);
  assert.equal(validateRawExternalEvidence(wrongToolVersionType, execution), false);
  const wrongToolVersion = structuredClone(valid);
  wrongToolVersion.capabilities.passiveSecurity.zap.tool.version = '2.16.0';
  assert.equal(validateJsonSchemaSubset(wrongToolVersion, schema), false);
  assert.equal(validateRawExternalEvidence(wrongToolVersion, execution), false);
  const counterOverflow = structuredClone(valid);
  counterOverflow.capabilities.passiveSecurity.zap.ownEndpointsScanned = 101;
  assert.equal(validateJsonSchemaSubset(counterOverflow, schema), false);
  assert.equal(validateRawExternalEvidence(counterOverflow, execution), false);
  const validNonZeroMilliseconds = structuredClone(valid);
  validNonZeroMilliseconds.executedAtUtc = valid.executedAtUtc.replace('.000Z', '.123Z');
  assert.equal(validateJsonSchemaSubset(validNonZeroMilliseconds, schema), true);
  assert.equal(validateRawExternalEvidence(validNonZeroMilliseconds, execution), true);
  assert.equal(
    validateExternalEvidenceSummary(
      summarizeExternalEvidence(validNonZeroMilliseconds, '9'.repeat(64), execution),
      summaryExecution,
    ),
    true,
  );
  const secretValue = ['sk', 'live', 'value123456'].join('_');
  const forbiddenSecret = structuredClone(valid);
  forbiddenSecret.reviewerAlias = secretValue;
  assert.equal(validateJsonSchemaSubset(forbiddenSecret, schema), false);
  assert.equal(validateRawExternalEvidence(forbiddenSecret, execution), false);
  assert.equal(
    validateExternalEvidenceSummary(
      summarizeExternalEvidence(forbiddenSecret, '9'.repeat(64), execution),
      summaryExecution,
    ),
    false,
  );
  const numericPan = Number(['4111', '1111', '1111', '1111'].join(''));
  const forbiddenNumericPan = structuredClone(valid);
  forbiddenNumericPan.capabilities.ownedTarget.requests.total = numericPan;
  assert.equal(validateJsonSchemaSubset(forbiddenNumericPan, schema), false);
  assert.equal(validateRawExternalEvidence(forbiddenNumericPan, execution), false);
  assert.equal(
    validateExternalEvidenceSummary(
      summarizeExternalEvidence(forbiddenNumericPan, '9'.repeat(64), execution),
      summaryExecution,
    ),
    false,
  );
  const invalidExecutedAt = structuredClone(valid);
  invalidExecutedAt.executedAtUtc = '2026-02-31T12:00:00.000Z';
  assert.equal(validateJsonSchemaSubset(invalidExecutedAt, schema), true);
  assert.equal(validateRawExternalEvidence(invalidExecutedAt, execution), false);
  const invalidApprovedAt = structuredClone(valid);
  invalidApprovedAt.capabilities.ownedTarget.authorization.approvedAtUtc =
    '2026-02-31T11:00:00.000Z';
  assert.equal(validateJsonSchemaSubset(invalidApprovedAt, schema), true);
  assert.equal(validateRawExternalEvidence(invalidApprovedAt, execution), false);
  const invalidExpiresAt = structuredClone(valid);
  invalidExpiresAt.capabilities.ownedTarget.authorization.expiresAtUtc = '2026-02-31T13:00:00.000Z';
  assert.equal(validateJsonSchemaSubset(invalidExpiresAt, schema), true);
  assert.equal(validateRawExternalEvidence(invalidExpiresAt, execution), false);
  assert.equal(
    validateExternalEvidenceSummary({ ...summary, sourceSha256: 'invalid' }, summaryExecution),
    false,
  );
  assert.throws(
    () =>
      externalEvidencePath(['--external-evidence', 'one.json'], {
        STAGE6_EXTERNAL_EVIDENCE: 'two.json',
      }),
    (error) =>
      error instanceof ExternalEvidenceError && error.code === 'EXTERNAL_EVIDENCE_PATH_CONFLICT',
  );
  assert.throws(
    () => externalEvidencePath(['--external-evidence', ''], {}),
    (error) =>
      error instanceof ExternalEvidenceError && error.code === 'EXTERNAL_EVIDENCE_PATH_MISSING',
  );
  assert.throws(
    () => externalEvidencePath(['--external-evidence', '   '], {}),
    (error) =>
      error instanceof ExternalEvidenceError && error.code === 'EXTERNAL_EVIDENCE_PATH_NOT_LOCAL',
  );
  assert.throws(
    () => externalEvidencePath(['--external-evidence', '\\\\server\\share\\evidence.json'], {}),
    (error) =>
      error instanceof ExternalEvidenceError && error.code === 'EXTERNAL_EVIDENCE_PATH_NOT_LOCAL',
  );
  assert.throws(
    () => externalEvidencePath(['--external-evidence', '\\\\.\\pipe\\stage6-evidence'], {}),
    (error) =>
      error instanceof ExternalEvidenceError && error.code === 'EXTERNAL_EVIDENCE_PATH_NOT_LOCAL',
  );
  assert.throws(
    () =>
      externalEvidencePath(
        ['--external-evidence', 'one.json', '--external-evidence', 'one.json'],
        {},
      ),
    (error) =>
      error instanceof ExternalEvidenceError && error.code === 'EXTERNAL_EVIDENCE_PATH_DUPLICATE',
  );
  assert.throws(
    () => externalEvidencePath([], { STAGE6_EXTERNAL_EVIDENCE: '  ' }),
    (error) =>
      error instanceof ExternalEvidenceError && error.code === 'EXTERNAL_EVIDENCE_PATH_NOT_LOCAL',
  );
  assert.equal(externalEvidencePath([], {}), undefined);
  assert.equal(
    externalEvidencePath(['--external-evidence', 'evidence.json'], {}).endsWith('evidence.json'),
    true,
  );
};

const executedDirectly =
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (executedDirectly && process.argv.includes('--self-test')) {
  selfTestExternalEvidence();
  process.stdout.write('stage-6 external evidence self-test: PASS\n');
}
