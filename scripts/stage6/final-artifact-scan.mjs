#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { collectTextFiles } from '../security/scan-repository.mjs';
import { scanArtifactText } from './lib/artifact-sanitizer.mjs';
import { baseEvidence, stage6RunId, writeRuntimeEvidence } from './lib/evidence.mjs';

export { scanArtifactText } from './lib/artifact-sanitizer.mjs';

const scanDirectory = (root) => {
  const files = collectTextFiles(root);
  const findings = files.flatMap((file) =>
    scanArtifactText(path.relative(root, file).replaceAll('\\', '/'), readFileSync(file, 'utf8')),
  );
  return { filesScanned: files.length, findings };
};

const selfTest = () => {
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'checkout-e6-final-scan-'));
  try {
    writeFileSync(
      path.join(temporary, 'safe.json'),
      JSON.stringify({
        status: 'PASS',
        holderName: 'SYNTHETIC_NOT_RECORDED',
        paymentMethodToken: 'NOT_CAPTURED',
      }),
      'utf8',
    );
    const clean = scanDirectory(temporary);
    assert.equal(clean.findings.length, 0);
    assert.equal(clean.filesScanned, 1);

    const expiryCanaries = [
      { field: ['expiry', 'Month'].join(''), value: ['1', '2'].join('') },
      { field: ['expiry', 'Year'].join(''), value: ['2', '0', '3', '4'].join('') },
      { field: ['card', 'Expiry'].join(''), value: ['1', '2', '/', '3', '4'].join('') },
      { field: ['exp', '_month'].join(''), value: ['1', '2'].join('') },
      { field: ['exp', '_year'].join(''), value: ['3', '4'].join('') },
    ];
    for (const [index, canary] of expiryCanaries.entries()) {
      assert.ok(
        scanArtifactText(
          `expiry-canary-${index}`,
          JSON.stringify({ [canary.field]: canary.value }),
        ).some((finding) => finding.rule === 'EXPIRY_CONTEXTUAL'),
      );
    }

    const unsafeValue = ['4111', '1111', '1111', '1111'].join('');
    writeFileSync(
      path.join(temporary, 'unsafe.json'),
      JSON.stringify({ value: unsafeValue }),
      'utf8',
    );
    const unsafeCvc = `CVC: ${['1', '2', '3'].join('')}`;
    writeFileSync(path.join(temporary, 'unsafe-cvc.json'), unsafeCvc, 'utf8');
    const unsafeEmail = ['reviewer', '@', 'corp', '.', 'example'].join('');
    writeFileSync(path.join(temporary, 'unsafe-email.json'), unsafeEmail, 'utf8');
    const unsafeExpiry = `expiry: ${['1', '2', '/', '3', '4'].join('')}`;
    writeFileSync(path.join(temporary, 'unsafe-expiry.json'), unsafeExpiry, 'utf8');
    const unsafePhone = `phone: ${['+', '5', '7', '3', '0', '0', '1', '2', '3', '4', '5', '6', '7'].join('')}`;
    writeFileSync(path.join(temporary, 'unsafe-phone.json'), unsafePhone, 'utf8');
    const unsafeSecret = `${['s', 'e', 'c', 'r', 'e', 't'].join('')}=${[
      'l',
      'o',
      'c',
      'a',
      'l',
      's',
      'y',
      'n',
      't',
      'h',
      'e',
      't',
      'i',
      'c',
      'k',
      'e',
      'y',
    ].join('')}`;
    writeFileSync(path.join(temporary, 'unsafe-secret.json'), unsafeSecret, 'utf8');
    const unsafeTokenKey = ['payment', 'Method', 'Token'].join('');
    const unsafeTokenValue = ['fake', '-', 'only'].join('');
    writeFileSync(
      path.join(temporary, 'unsafe-token.json'),
      JSON.stringify({ [unsafeTokenKey]: unsafeTokenValue }),
      'utf8',
    );
    const prefixedTokenPlaceholder = [
      ['NOT', '_CAPTURED'].join(''),
      ['actual', '-token-value'].join(''),
    ].join(' ');
    writeFileSync(
      path.join(temporary, 'unsafe-prefixed-token-placeholder.json'),
      JSON.stringify({ paymentMethodToken: prefixedTokenPlaceholder }),
      'utf8',
    );
    const prefixedHolderPlaceholder = [
      ['SYNTHETIC', '_NOT_RECORDED'].join(''),
      ['Real', 'Person'].join(' '),
    ].join(' ');
    writeFileSync(
      path.join(temporary, 'unsafe-prefixed-holder-placeholder.json'),
      JSON.stringify({ holderName: prefixedHolderPlaceholder }),
      'utf8',
    );
    const rejected = scanDirectory(temporary);
    assert.ok(rejected.findings.some((finding) => finding.rule === 'PAN_LUHN'));
    assert.ok(rejected.findings.some((finding) => finding.rule === 'CVC_CONTEXTUAL'));
    assert.ok(rejected.findings.some((finding) => finding.rule === 'EMAIL_PII'));
    assert.ok(rejected.findings.some((finding) => finding.rule === 'EXPIRY_CONTEXTUAL'));
    assert.ok(rejected.findings.some((finding) => finding.rule === 'PHONE_PII'));
    assert.ok(rejected.findings.some((finding) => finding.rule === 'ASSIGNED_SECRET'));
    assert.ok(rejected.findings.some((finding) => finding.rule === 'SENSITIVE_FIELD'));
    assert.ok(
      rejected.findings.some(
        (finding) =>
          finding.label === 'unsafe-prefixed-token-placeholder.json' &&
          finding.rule === 'SENSITIVE_FIELD',
      ),
    );
    assert.ok(
      rejected.findings.some(
        (finding) =>
          finding.label === 'unsafe-prefixed-holder-placeholder.json' &&
          finding.rule === 'PII_FIELD',
      ),
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
};

const main = () => {
  selfTest();
  const runId = stage6RunId();
  const result = scanDirectory(path.resolve('output/evidence/runtime'));
  if (result.findings.length > 0 || result.filesScanned < 1) {
    process.stderr.write('stage-6 final artifact scan: FAIL\n');
    process.exitCode = 1;
  } else {
    writeRuntimeEvidence('final-artifact-scan.json', {
      ...baseEvidence({
        artifactId: 'EVD-E6-35',
        command: 'node scripts/stage6/final-artifact-scan.mjs',
        tool: {
          node: process.version,
          scanner: 'stage6-artifact-sanitizer-v1',
          baseScanner: 'scripts/security/scan-repository.mjs',
        },
        runId,
      }),
      status: 'PASS',
      scope: 'output/evidence/runtime',
      sequence: 'AFTER_E6_UAT_BEFORE_CLOSEOUT',
      filesScanned: result.filesScanned,
      findings: 0,
      history: 'COVERED_BY_E6_SECURITY_STEP',
      blockedExternalRequests: 0,
      canaries: {
        assignedSecret: 'PASS',
        panLuhn: 'PASS',
        cvcContextual: 'PASS',
        expiryContextual: 'PASS',
        emailPii: 'PASS',
        phonePii: 'PASS',
        sensitiveField: 'PASS',
      },
      dataClasses: [
        'SECRET',
        'PAN',
        'CVC',
        'EXPIRY',
        'EMAIL',
        'PHONE',
        'PII_FIELD',
        'SENSITIVE_FIELD',
      ],
    });
    process.stdout.write(`stage-6 final artifact scan: PASS (${result.filesScanned} files)\n`);
  }
};

const executedDirectly =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (executedDirectly) {
  if (process.argv.includes('--self-test')) {
    selfTest();
    process.stdout.write('stage-6 final artifact scan self-test: PASS\n');
  } else {
    main();
  }
}
