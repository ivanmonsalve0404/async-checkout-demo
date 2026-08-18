import { strict as assert } from 'node:assert';
import { describe, test } from 'node:test';
import * as path from 'node:path';

import type { RawFoundationConfig } from '../lib/config';
import { parseFoundationConfig } from '../lib/config';
import { inspectReleaseArtifact } from '../lib/release-artifact';

const SHA = ['01234567', '89abcdef', '01234567', '89abcdef', '01234567'].join('');
const TEST_ACCOUNT = ['000', '000', '000', '000'].join('');
const certificateArn = (id: string): string =>
  `arn:aws:acm:us-east-1:${TEST_ACCOUNT}:certificate/${id}`;
const runtimeReference = (): string =>
  ['arn:aws:secretsmanager:us-east-1:', TEST_ACCOUNT, ':secret:', 'wompi/runtime-', 'AbCdEf'].join(
    '',
  );

function release(overrides: RawFoundationConfig = {}): RawFoundationConfig {
  return {
    candidateSha: SHA,
    environment: 'assessment-release',
    expiresOn: '2099-12-31',
    owner: 'assessment-team',
    publicationMode: 'INITIAL_CLOSED',
    releaseId: 'rel-20991231-2359-0123456',
    ...overrides,
  };
}

function domain(): RawFoundationConfig {
  return {
    apiCertificateArn: certificateArn(
      ['11111111', '1111', '4111', '8111', '111111111111'].join('-'),
    ),
    apiDomainName: 'api.checkout.example.com',
    hostedZoneId: 'Z123456789ABCDE',
    hostedZoneName: 'example.com',
    webCertificateArn: certificateArn(
      ['22222222', '2222', '4222', '8222', '222222222222'].join('-'),
    ),
    webDomainName: 'checkout.example.com',
  };
}

void describe('foundation configuration', () => {
  void test('uses reversible fake-only preview defaults', () => {
    assert.deepEqual(parseFoundationConfig({}), {
      projectName: 'checkout',
      environment: 'preview',
      region: 'us-east-1',
      paymentAdapter: 'fake',
      paymentsEnabled: false,
      tokenizationMode: 'disabled',
    });
  });

  void test('keeps preview fail-closed', () => {
    assert.throws(() => parseFoundationConfig({ paymentAdapter: 'real' }), /fake payment adapter/);
    assert.throws(() => parseFoundationConfig({ paymentsEnabled: true }), /paymentsEnabled=false/);
    assert.throws(
      () => parseFoundationConfig({ tokenizationMode: 'direct_jwe' }),
      /tokenizationMode=disabled/,
    );
  });

  void test('accepts only an identified fake non-public prerelease by default', () => {
    const parsed = parseFoundationConfig(
      release({
        environment: 'assessment-prerelease-local-plan',
        publicationMode: 'EPHEMERAL_NON_PUBLIC',
      }),
    );
    assert.equal(parsed.environment, 'assessment-prerelease-local-plan');
    assert.equal(parsed.paymentAdapter, 'fake');
    assert.equal(parsed.paymentsEnabled, false);
    assert.equal(parsed.tokenizationMode, 'disabled');
    assert.equal(parsed.schedulerEnabled, false);
    assert.equal(parsed.budgetMaxUsd, 10);
    assert.deepEqual(parsed.budgetWarningUsd, [5, 8]);
    assert.equal(parsed.domain, undefined);
    assert.equal(parsed.apiArtifactPath, '../output/release/build/api');
    assert.equal(parsed.workerArtifactPath, '../output/release/build/worker');
    assert.equal(parsed.webArtifactPath, '../output/release/build/web');
  });

  void test('accepts an isolated ephemeral prerelease environment without preview semantics', () => {
    const parsed = parseFoundationConfig(
      release({
        environment: 'assessment-prerelease-pr-42-a11y',
        publicationMode: 'EPHEMERAL_NON_PUBLIC',
      }),
    );
    assert.equal(parsed.environment, 'assessment-prerelease-pr-42-a11y');
    assert.equal(parsed.paymentAdapter, 'fake');
    assert.equal(parsed.paymentsEnabled, false);
    assert.equal(parsed.tokenizationMode, 'disabled');
    assert.throws(
      () =>
        parseFoundationConfig(
          release({
            environment: 'assessment-prerelease-Unsafe',
            publicationMode: 'EPHEMERAL_NON_PUBLIC',
          }),
        ),
      /assessment-prerelease-<slug>/,
    );
  });

  void test('keeps the first full release unpublished and blocks update-like modes', () => {
    const full = {
      paymentAdapter: 'sandbox',
      paymentsEnabled: true,
      runtimeSecretArn: runtimeReference(),
      schedulerEnabled: true,
      sandboxAuthorizedUntilUtc: '2099-01-01T00:00:00.000Z',
      tokenizationMode: 'direct_jwe',
      ...domain(),
    };
    const fullConfig = parseFoundationConfig(release(full));
    if (fullConfig.environment === 'preview') assert.fail('release config expected');
    assert.equal(fullConfig.publicationMode, 'INITIAL_CLOSED');
    assert.throws(
      () => parseFoundationConfig(release({ ...full, publicationMode: 'EPHEMERAL_NON_PUBLIC' })),
      /requires INITIAL_CLOSED/,
    );
    assert.throws(
      () =>
        parseFoundationConfig(
          release({
            environment: 'assessment-prerelease-pr-42',
            publicationMode: 'INITIAL_CLOSED',
          }),
        ),
      /prerelease requires EPHEMERAL_NON_PUBLIC/,
    );
  });

  void test('requires the complete sandbox, secret and TLS bundle', () => {
    const sandbox = {
      paymentAdapter: 'sandbox',
      paymentsEnabled: true,
      runtimeSecretArn: runtimeReference(),
      schedulerEnabled: true,
      sandboxAuthorizedUntilUtc: '2099-01-01T00:00:00.000Z',
      tokenizationMode: 'direct_jwe',
    };
    const managedPrerelease = parseFoundationConfig(
      release({
        ...sandbox,
        environment: 'assessment-prerelease-sandbox',
        publicationMode: 'EPHEMERAL_NON_PUBLIC',
      }),
    );
    assert.equal(managedPrerelease.environment, 'assessment-prerelease-sandbox');
    assert.equal(managedPrerelease.domain, undefined);
    const parsed = parseFoundationConfig(release({ ...sandbox, ...domain() }));
    assert.equal(parsed.environment, 'assessment-release');
    if (parsed.environment !== 'assessment-release') assert.fail('release config expected');
    assert.equal(parsed.paymentAdapter, 'sandbox');
    assert.equal(parsed.domain?.webDomainName, 'checkout.example.com');

    assert.throws(
      () =>
        parseFoundationConfig(release({ ...sandbox, ...domain(), runtimeSecretArn: undefined })),
      /runtime JSON secret ARN/,
    );
    assert.throws(
      () => parseFoundationConfig(release({ ...sandbox, ...domain(), schedulerEnabled: false })),
      /reconciler enabled/,
    );
    assert.throws(() => parseFoundationConfig(release({ ...sandbox })), /complete custom domain/);
  });

  void test('rejects ambiguous identity, partial domains and cross-region secrets', () => {
    assert.throws(
      () => parseFoundationConfig(release({ candidateSha: 'f'.repeat(40) })),
      /SHA prefix/,
    );
    assert.throws(
      () => parseFoundationConfig(release({ webDomainName: 'checkout.example.com' })),
      /must be complete/,
    );
    assert.throws(
      () =>
        parseFoundationConfig(
          release({
            runtimeSecretArn: `arn:aws:secretsmanager:eu-west-1:${TEST_ACCOUNT}:secret:runtime-AbCdEf`,
          }),
        ),
      /ARN in region/,
    );
    assert.throws(
      () => parseFoundationConfig({ environment: 'production' }),
      /preview, assessment-release/,
    );
    assert.throws(() => parseFoundationConfig({ region: 'not-a-region' }), /AWS region identifier/);
    assert.throws(() => parseFoundationConfig({ projectName: 'Checkout Demo' }), /lowercase/);
    assert.throws(
      () => parseFoundationConfig({ projectName: { unsafe: true } }),
      /non-empty string/,
    );
    assert.throws(
      () => parseFoundationConfig(release({ budgetMaxUsd: '10.001' })),
      /positive USD amount/,
    );
    assert.throws(
      () => parseFoundationConfig(release({ budgetMaxUsd: 10, budgetWarningUsd: '8,5' })),
      /increasing amounts below max/,
    );
    assert.throws(
      () => parseFoundationConfig(release({ budgetMaxUsd: 10, budgetWarningUsd: '5,10' })),
      /increasing amounts below max/,
    );
    assert.throws(
      () => parseFoundationConfig(release({ expiresOn: '2099-02-31' })),
      /valid YYYY-MM-DD date/,
    );
    assert.throws(
      () =>
        parseFoundationConfig(
          release({
            environment: `assessment-prerelease-${'a'.repeat(40)}`,
            projectName: 'checkout-project-name-near-limit',
          }),
        ),
      /bounded AWS resource-name prefix/,
    );
  });

  void test('hashes dedicated artifacts deterministically and rejects source maps', () => {
    const validPath = path.join(__dirname, 'fixtures', 'release-api');
    const first = inspectReleaseArtifact(validPath, ['index.js'], 'api');
    const second = inspectReleaseArtifact(validPath, ['index.js'], 'api');
    assert.equal(first.sha256, second.sha256);
    assert.match(first.sha256, /^[a-f0-9]{64}$/u);
    assert.deepEqual(first.files, ['index.js']);
    assert.throws(
      () =>
        inspectReleaseArtifact(
          path.join(__dirname, 'fixtures', 'release-api-invalid'),
          ['index.js'],
          'api',
        ),
      /forbidden development or secret files/,
    );
  });
});
