import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import process from 'node:process';

import { scanText } from '../../security/scan-repository.mjs';

let atomicWriteSequence = 0;

const ARTIFACT_PATTERNS = [
  {
    rule: 'CVC_CONTEXTUAL',
    expression: /\b(?:cvc|cvv|security\s*code)\b[^0-9\r\n]{0,24}\d{3,4}\b/giu,
  },
  {
    rule: 'EXPIRY_CONTEXTUAL',
    expression:
      /\b(?:card[_-]?expiry|expiry(?:[_-]?(?:month|year))?|expiration(?:[_-]?(?:month|year))?|exp[_-]?(?:month|year))\b[^0-9\r\n]{0,24}(?:\d{1,2}\/\d{2,4}|\d{1,4})\b/giu,
  },
  {
    rule: 'EMAIL_PII',
    expression: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu,
  },
  {
    rule: 'PHONE_PII',
    expression: /\b(?:phone|telephone|mobile|tel[eé]fono)\b[^\d\r\n]{0,24}\+?[\d ()-]{7,20}\d\b/giu,
  },
  {
    rule: 'PII_FIELD',
    expression:
      /"(?:firstName|lastName|fullName|holderName|cardholderName|address(?:Line[12])?|postalCode|email|phone|telephone|mobile)"\s*:\s*"(?!(?:\[REDACTED\]|OMITTED|NOT_CAPTURED|SYNTHETIC_NOT_RECORDED)")[^"]+"/giu,
  },
  {
    rule: 'SENSITIVE_FIELD',
    expression:
      /"(?:secret|password|privateKey|eventsKey|integrityKey|paymentMethodToken|acceptanceToken|cardToken|capabilityToken)"\s*:\s*"(?!(?:\[REDACTED\]|OMITTED|NOT_CAPTURED|SYNTHETIC_NOT_RECORDED|DISABLED)")[^"]+"/giu,
  },
];

const SECRETS_MANAGER_REFERENCE =
  /^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,256}$/u;

const allowedSecretReferenceLines = (value) => {
  const allowed = new Set();
  let credentialReferences = false;
  for (const [index, line] of value.split(/\r?\n/u).entries()) {
    const origin = /^\s*"originTokenSecretArn"\s*:\s*"([^"]+)"\s*,?\s*$/u.exec(line);
    if (origin !== null && SECRETS_MANAGER_REFERENCE.test(origin[1])) allowed.add(index + 1);
    if (/^\s*"credentialReferences"\s*:\s*\[\s*$/u.test(line)) {
      credentialReferences = true;
      continue;
    }
    if (credentialReferences && /^\s*\]\s*,?\s*$/u.test(line)) {
      credentialReferences = false;
      continue;
    }
    const entry = credentialReferences ? /^\s*"([^"]+)"\s*,?\s*$/u.exec(line) : null;
    if (entry !== null && SECRETS_MANAGER_REFERENCE.test(entry[1])) allowed.add(index + 1);
  }
  return allowed;
};

export const scanArtifactText = (label, value) => {
  const allowedReferences = allowedSecretReferenceLines(value);
  const findings = scanText(label, value).filter(
    ({ line, rule }) => rule !== 'ASSIGNED_SECRET' || !allowedReferences.has(line),
  );
  for (const [lineIndex, line] of value.split(/\r?\n/u).entries()) {
    for (const pattern of ARTIFACT_PATTERNS) {
      pattern.expression.lastIndex = 0;
      if (pattern.expression.test(line)) {
        findings.push({ label, line: lineIndex + 1, rule: pattern.rule });
      }
    }
  }
  return findings;
};

export const assertSanitizedArtifactText = (label, value) => {
  if (typeof label !== 'string' || label.trim().length === 0 || typeof value !== 'string') {
    throw new Error('RUNTIME_EVIDENCE_SANITIZATION_FAILED');
  }
  if (scanArtifactText(label, value).length > 0) {
    throw new Error('RUNTIME_EVIDENCE_SANITIZATION_FAILED');
  }
  return value;
};

export const serializeSanitizedEvidence = (label, evidence) =>
  assertSanitizedArtifactText(label, `${JSON.stringify(evidence, null, 2)}\n`);

const writeAtomic = async (target, value) => {
  if (typeof target !== 'string' || target.trim().length === 0) {
    throw new Error('RUNTIME_EVIDENCE_TARGET_INVALID');
  }
  await mkdir(dirname(target), { recursive: true });
  atomicWriteSequence += 1;
  const temporary = `${target}.${process.pid}.${atomicWriteSequence}.tmp`;
  try {
    await writeFile(temporary, value, 'utf8');
    await rename(temporary, target);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
  return value;
};

export const writeSanitizedJsonAtomic = (target, label, evidence) =>
  writeAtomic(target, serializeSanitizedEvidence(label, evidence));

export const writeSanitizedTextAtomic = (target, label, value) =>
  writeAtomic(target, assertSanitizedArtifactText(label, value));

export const selfTestArtifactSanitizer = () => {
  const safeJson = serializeSanitizedEvidence('safe-writer-canary.json', {
    status: 'PASS',
    containsSensitiveData: false,
  });
  if (!safeJson.includes('"status": "PASS"')) {
    throw new Error('ARTIFACT_SANITIZER_SAFE_JSON_CANARY_FAILED');
  }

  let unsafeJsonRejected = false;
  try {
    serializeSanitizedEvidence('unsafe-writer-canary.json', {
      paymentMethodToken: ['actual', 'token', 'value'].join('-'),
    });
  } catch (error) {
    unsafeJsonRejected =
      error instanceof Error && error.message === 'RUNTIME_EVIDENCE_SANITIZATION_FAILED';
  }
  if (!unsafeJsonRejected) throw new Error('ARTIFACT_SANITIZER_UNSAFE_JSON_CANARY_FAILED');

  const secretReference = [
    'arn:aws:secretsmanager:us-east-1:111122223333',
    ['sec', 'ret'].join(''),
    'checkout/runtime-AbCdEf',
  ].join(':');
  serializeSanitizedEvidence('safe-secret-reference.json', {
    originTokenSecretArn: secretReference,
    credentialReferences: [secretReference],
  });
  const malformedReference = ['not-an-arn', ['sec', 'ret'].join(''), 'actualmaterial123456'].join(
    ':',
  );
  for (const unsafeReferenceSource of [
    `{"originTokenSecretArn":"${malformedReference}"}\n`,
    `{"note":"${secretReference}"}\n`,
    `{"originTokenSecretArn":"${secretReference}","secret":"actualmaterial123456"}\n`,
  ]) {
    let rejected = false;
    try {
      assertSanitizedArtifactText('unsafe-secret-reference.json', unsafeReferenceSource);
    } catch (error) {
      rejected = error instanceof Error && error.message === 'RUNTIME_EVIDENCE_SANITIZATION_FAILED';
    }
    if (!rejected) throw new Error('ARTIFACT_SANITIZER_SECRET_REFERENCE_SCOPE_CANARY_FAILED');
  }

  const safeText = '<p>Status: PASS; aggregate metrics only.</p>\n';
  if (assertSanitizedArtifactText('safe-writer-canary.html', safeText) !== safeText) {
    throw new Error('ARTIFACT_SANITIZER_SAFE_TEXT_CANARY_FAILED');
  }

  let unsafeTextRejected = false;
  try {
    const syntheticAddress = [['qa', 'evidence'].join('.'), ['example', 'invalid'].join('.')].join(
      '@',
    );
    assertSanitizedArtifactText(
      'unsafe-writer-canary.html',
      `<p>Reviewer: ${syntheticAddress}</p>\n`,
    );
  } catch (error) {
    unsafeTextRejected =
      error instanceof Error && error.message === 'RUNTIME_EVIDENCE_SANITIZATION_FAILED';
  }
  if (!unsafeTextRejected) throw new Error('ARTIFACT_SANITIZER_UNSAFE_TEXT_CANARY_FAILED');
};
