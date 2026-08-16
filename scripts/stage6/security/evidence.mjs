/* global structuredClone */
import assert from 'node:assert/strict';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import {
  externalEvidenceCapabilityDecision,
  externalPassiveSecurityChecks,
  missingExternalEvidence,
  selfTestExternalEvidence,
} from '../external-evidence.mjs';

const RUN_ID = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const COMMIT_SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const exact = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected);
const regexMatchesString = (pattern, value) => typeof value === 'string' && pattern.test(value);
const validIsoDate = (value) =>
  regexMatchesString(
    /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u,
    value,
  ) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const expectedEnvironment = () => (process.env.CI === 'true' ? 'ENV-E6-CI' : 'ENV-E6-LOCAL');

const STATIC_CHECKS = [
  ['SEC-E6-STATIC-01', 'secret-scanner-self-test'],
  ['SEC-E6-STATIC-02', 'working-tree-and-history-secret-scan'],
  ['SEC-E6-STATIC-03', 'workflow-least-privilege-policy'],
  ['SEC-E6-STATIC-04', 'codeql-same-sha-evidence-self-test'],
  ['SEC-E6-STATIC-05', 'codeql-sarif-severity-gate-self-test'],
  ['SEC-E6-STATIC-06', 'security-focused-unit-and-integration-tests'],
];

const APPLICATION_CHECKS = [
  ['SEC-E6-DYNAMIC-01', 'application-security-headers'],
  ['SEC-E6-DYNAMIC-02', 'cors-exact-allowlist'],
  ['SEC-E6-DYNAMIC-03', 'hostile-origin-safe-problem'],
  ['SEC-E6-DYNAMIC-04', 'json-content-type-boundary'],
  ['SEC-E6-DYNAMIC-05', 'request-body-limit'],
  ['SEC-E6-DYNAMIC-06', 'secure-capability-cookie'],
  ['SEC-E6-DYNAMIC-07', 'rate-limit-contract'],
  ['SEC-E6-DYNAMIC-08', 'external-network-attempts'],
];

const validStaticChecks = (checks) =>
  Array.isArray(checks) &&
  checks.length === STATIC_CHECKS.length &&
  checks.every((check, index) => {
    const [id, name] = STATIC_CHECKS[index];
    if (
      check?.id !== id ||
      check.name !== name ||
      check.status !== 'PASS' ||
      check.exitCode !== 0
    ) {
      return false;
    }
    if (id !== 'SEC-E6-STATIC-06') {
      return exact(check, { id, name, status: 'PASS', exitCode: 0 });
    }
    return (
      exact(Object.keys(check), [
        'id',
        'name',
        'status',
        'exitCode',
        'passed',
        'failed',
        'total',
      ]) &&
      Number.isInteger(check.passed) &&
      check.passed > 0 &&
      check.failed === 0 &&
      check.total === check.passed
    );
  });

const validApplicationChecks = (checks) =>
  Array.isArray(checks) &&
  checks.length === APPLICATION_CHECKS.length &&
  checks.every((check, index) => {
    const [id, name] = APPLICATION_CHECKS[index];
    if (check?.id !== id || check.name !== name || check.status !== 'PASS') return false;
    switch (id) {
      case 'SEC-E6-DYNAMIC-01':
        return exact(check, {
          id,
          name,
          status: 'PASS',
          requiredHeaders: {
            'content-security-policy': true,
            'referrer-policy': true,
            'x-content-type-options': true,
            'x-frame-options': true,
          },
          cacheControlNoStore: true,
        });
      case 'SEC-E6-DYNAMIC-06':
        return exact(check, { id, name, status: 'PASS', cookieValueCaptured: false });
      case 'SEC-E6-DYNAMIC-07':
        return exact(check, { id, name, status: 'PASS', retryAfterPresent: true });
      case 'SEC-E6-DYNAMIC-08':
        return exact(check, { id, name, status: 'PASS', blockedExternalRequests: 0 });
      default:
        return exact(check, { id, name, status: 'PASS' });
    }
  });

const validCodeqlCheck = (check, candidateSha) => {
  if (
    check?.id !== 'SEC-E6-EXT-02' ||
    check.name !== 'codeql-sast' ||
    check.source !== 'same-workflow-sarif-gate'
  ) {
    return false;
  }
  if (check.status === 'NOT_RUN_CI_REQUIRED') {
    return (
      check.commitSha === undefined &&
      check.analysisResult === undefined &&
      check.sarifStatus === undefined &&
      check.high === undefined &&
      check.critical === undefined &&
      check.sarifSha256 === undefined
    );
  }
  return (
    check.status === 'PASS' &&
    check.commitSha === candidateSha &&
    check.analysisResult === 'success' &&
    check.sarifStatus === 'PASS' &&
    check.high === 0 &&
    check.critical === 0 &&
    regexMatchesString(SHA256, check.sarifSha256)
  );
};

const validExternalChecks = (checks, externalEvidence, execution) => {
  const passiveChecks = externalPassiveSecurityChecks(externalEvidence, execution);
  return (
    Array.isArray(checks) &&
    checks.length === 5 &&
    passiveChecks !== undefined &&
    exact(checks[0], {
      id: 'SEC-E6-EXT-01',
      name: 'dependency-advisory-audit',
      status: 'NOT_RUN_CI_REQUIRED',
    }) &&
    validCodeqlCheck(checks[1], execution.commitSha) &&
    exact(checks[2], passiveChecks[0]) &&
    exact(checks[3], passiveChecks[1]) &&
    exact(checks[4], {
      id: 'SEC-E6-EXT-05',
      name: 'active-dast',
      status: 'PROHIBITED_WITHOUT_AUTH_E6_04',
    })
  );
};

const validCandidate = (candidate) =>
  regexMatchesString(COMMIT_SHA, candidate?.commitSha) &&
  regexMatchesString(COMMIT_SHA, candidate.treeSha) &&
  typeof candidate.branch === 'string' &&
  candidate.branch.length > 0 &&
  ['CLEAN', 'IMPLEMENTATION_SNAPSHOT'].includes(candidate.workingTree) &&
  Number.isInteger(candidate.changedFiles) &&
  candidate.changedFiles >= 0 &&
  (candidate.workingTree === 'CLEAN' ? candidate.changedFiles === 0 : candidate.changedFiles > 0);

export const validateSecurityEvidence = (evidence) => {
  try {
    const execution = { commitSha: evidence?.candidate?.commitSha, runId: evidence?.runId };
    const passiveDecision = externalEvidenceCapabilityDecision(
      evidence?.externalEvidence,
      'passiveSecurity',
      execution,
    );
    return (
      evidence?.schemaVersion === 1 &&
      evidence.stage === 6 &&
      evidence.artifactId === 'ART-VER-12' &&
      evidence.status === 'PASS_LOCAL' &&
      regexMatchesString(RUN_ID, evidence.runId) &&
      validIsoDate(evidence.generatedAt) &&
      validCandidate(evidence.candidate) &&
      evidence.environment === expectedEnvironment() &&
      evidence.tool?.node === process.version &&
      evidence.tool?.jest === '30.4.2' &&
      evidence.tool?.httpClient === 'node-fetch-native' &&
      evidence.command === 'node scripts/stage6/security/run.mjs' &&
      evidence.dataClassification === 'C0_SANITIZED_SUMMARY' &&
      evidence.containsSensitiveData === false &&
      exact(evidence.sanitization, {
        payloads: 'OMITTED',
        pii: 'SYNTHETIC_NOT_RECORDED',
        cardData: 'NOT_CAPTURED',
        secrets: 'NOT_CAPTURED',
      }) &&
      evidence.commitSha === evidence.candidate.commitSha &&
      validStaticChecks(evidence.staticChecks) &&
      validApplicationChecks(evidence.applicationChecks) &&
      validExternalChecks(evidence.externalChecks, evidence.externalEvidence, execution) &&
      evidence.externalRequestsByIngestion === 0 &&
      evidence.confirmedCritical === 0 &&
      evidence.confirmedHigh === 0 &&
      evidence.sensitiveValuesCaptured === 0 &&
      evidence.declaration ===
        (passiveDecision === 'PASS'
          ? 'LOCAL_AND_AUTHORIZED_OWNED_TARGET_CONTROLS_NO_SECURITY_CERTIFICATION'
          : 'LOCAL_CONTROLS_ONLY_NO_SECURITY_CERTIFICATION')
    );
  } catch {
    return false;
  }
};

const validFixture = () => {
  const commitSha = 'a'.repeat(40);
  return {
    schemaVersion: 1,
    stage: 6,
    artifactId: 'ART-VER-12',
    runId: 'e6-20260816t120000z-0123abcd',
    generatedAt: '2026-08-16T12:00:00.000Z',
    candidate: {
      commitSha,
      treeSha: 'b'.repeat(40),
      branch: 'codex/stage-6-integration-verification',
      workingTree: 'IMPLEMENTATION_SNAPSHOT',
      changedFiles: 1,
    },
    environment: expectedEnvironment(),
    tool: { node: process.version, jest: '30.4.2', httpClient: 'node-fetch-native' },
    command: 'node scripts/stage6/security/run.mjs',
    dataClassification: 'C0_SANITIZED_SUMMARY',
    containsSensitiveData: false,
    sanitization: {
      payloads: 'OMITTED',
      pii: 'SYNTHETIC_NOT_RECORDED',
      cardData: 'NOT_CAPTURED',
      secrets: 'NOT_CAPTURED',
    },
    commitSha,
    status: 'PASS_LOCAL',
    staticChecks: STATIC_CHECKS.map(([id, name], index) =>
      index === STATIC_CHECKS.length - 1
        ? { id, name, status: 'PASS', exitCode: 0, passed: 85, failed: 0, total: 85 }
        : { id, name, status: 'PASS', exitCode: 0 },
    ),
    applicationChecks: APPLICATION_CHECKS.map(([id, name]) => {
      if (id === 'SEC-E6-DYNAMIC-01') {
        return {
          id,
          name,
          status: 'PASS',
          requiredHeaders: {
            'content-security-policy': true,
            'referrer-policy': true,
            'x-content-type-options': true,
            'x-frame-options': true,
          },
          cacheControlNoStore: true,
        };
      }
      if (id === 'SEC-E6-DYNAMIC-06') {
        return { id, name, status: 'PASS', cookieValueCaptured: false };
      }
      if (id === 'SEC-E6-DYNAMIC-07') {
        return { id, name, status: 'PASS', retryAfterPresent: true };
      }
      if (id === 'SEC-E6-DYNAMIC-08') {
        return { id, name, status: 'PASS', blockedExternalRequests: 0 };
      }
      return { id, name, status: 'PASS' };
    }),
    externalChecks: [
      {
        id: 'SEC-E6-EXT-01',
        name: 'dependency-advisory-audit',
        status: 'NOT_RUN_CI_REQUIRED',
      },
      {
        id: 'SEC-E6-EXT-02',
        name: 'codeql-sast',
        status: 'NOT_RUN_CI_REQUIRED',
        source: 'same-workflow-sarif-gate',
      },
      {
        id: 'SEC-E6-EXT-03',
        name: 'qa-edge-headers',
        status: 'NOT_RUN_AUTH_REQUIRED',
      },
      {
        id: 'SEC-E6-EXT-04',
        name: 'zap-baseline-own-target',
        status: 'NOT_RUN_AUTH_REQUIRED',
      },
      {
        id: 'SEC-E6-EXT-05',
        name: 'active-dast',
        status: 'PROHIBITED_WITHOUT_AUTH_E6_04',
      },
    ],
    externalEvidence: missingExternalEvidence({
      commitSha,
      runId: 'e6-20260816t120000z-0123abcd',
    }),
    externalRequestsByIngestion: 0,
    confirmedCritical: 0,
    confirmedHigh: 0,
    sensitiveValuesCaptured: 0,
    declaration: 'LOCAL_CONTROLS_ONLY_NO_SECURITY_CERTIFICATION',
  };
};

export const selfTestSecurityEvidence = () => {
  selfTestExternalEvidence();
  const valid = validFixture();
  assert.equal(validateSecurityEvidence(valid), true);
  const nonZeroMilliseconds = structuredClone(valid);
  nonZeroMilliseconds.generatedAt = '2026-08-16T12:00:00.123Z';
  assert.equal(validateSecurityEvidence(nonZeroMilliseconds), true);

  const impossibleDate = structuredClone(valid);
  impossibleDate.generatedAt = '2026-02-31T12:00:00.000Z';
  assert.equal(validateSecurityEvidence(impossibleDate), false);

  const offsetDate = structuredClone(valid);
  offsetDate.generatedAt = '2026-08-16T07:00:00.000-05:00';
  assert.equal(validateSecurityEvidence(offsetDate), false);
  const codeqlPass = structuredClone(valid);
  codeqlPass.externalChecks[1] = {
    id: 'SEC-E6-EXT-02',
    name: 'codeql-sast',
    status: 'PASS',
    source: 'same-workflow-sarif-gate',
    commitSha: valid.candidate.commitSha,
    analysisResult: 'success',
    sarifStatus: 'PASS',
    high: 0,
    critical: 0,
    sarifSha256: 'c'.repeat(64),
  };
  assert.equal(validateSecurityEvidence(codeqlPass), true);

  const codeqlWrongSha = structuredClone(codeqlPass);
  codeqlWrongSha.externalChecks[1].commitSha = 'd'.repeat(40);
  assert.equal(validateSecurityEvidence(codeqlWrongSha), false);

  const empty = structuredClone(valid);
  empty.staticChecks = [];
  assert.equal(validateSecurityEvidence(empty), false);

  const duplicate = structuredClone(valid);
  duplicate.applicationChecks[1] = structuredClone(duplicate.applicationChecks[0]);
  assert.equal(validateSecurityEvidence(duplicate), false);

  const reordered = structuredClone(valid);
  [reordered.staticChecks[0], reordered.staticChecks[1]] = [
    reordered.staticChecks[1],
    reordered.staticChecks[0],
  ];
  assert.equal(validateSecurityEvidence(reordered), false);

  const omission = structuredClone(valid);
  omission.externalChecks.pop();
  assert.equal(validateSecurityEvidence(omission), false);

  const tamperedHeader = structuredClone(valid);
  tamperedHeader.applicationChecks[0].requiredHeaders['x-frame-options'] = false;
  assert.equal(validateSecurityEvidence(tamperedHeader), false);

  const capturedCookie = structuredClone(valid);
  capturedCookie.applicationChecks[5].cookieValueCaptured = true;
  assert.equal(validateSecurityEvidence(capturedCookie), false);

  const inflatedExternal = structuredClone(valid);
  inflatedExternal.externalChecks[2].status = 'PASS';
  assert.equal(validateSecurityEvidence(inflatedExternal), false);

  const inflatedCodeql = structuredClone(valid);
  inflatedCodeql.externalChecks[1].status = 'PASS';
  assert.equal(validateSecurityEvidence(inflatedCodeql), false);
};

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  selfTestSecurityEvidence();
  process.stdout.write('stage-6 security evidence validator self-test: PASS\n');
}
