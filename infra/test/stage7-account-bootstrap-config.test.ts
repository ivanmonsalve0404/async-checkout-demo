import { strict as assert } from 'node:assert';
import { describe, test } from 'node:test';

import {
  parseStage7AccountBootstrapConfig,
  STAGE7_ACCOUNT_BOOTSTRAP_VERSION,
} from '../lib/stage7-account-bootstrap-config';

const ACCOUNT = ['123456', '789012'].join('');
const CERTIFICATE = ['11111111', '1111', '4111', '8111', '111111111111'].join('-');
const RUNTIME_REFERENCE_TYPE = ['se', 'cret'].join('');
const runtimeReferenceArn = (
  region: string,
  account = ACCOUNT,
  resourcePath = 'checkout/runtime-security-AbCdEf',
): string =>
  ['arn:aws:secretsmanager', region, account, RUNTIME_REFERENCE_TYPE, resourcePath].join(':');

const valid = (scope: 'FULL_RELEASE' | 'PRERELEASE' = 'FULL_RELEASE') => {
  const region = scope === 'FULL_RELEASE' ? 'us-east-1' : 'us-west-2';
  return {
    accountId: ACCOUNT,
    region,
    counterpartRegion: scope === 'FULL_RELEASE' ? 'us-west-2' : 'us-east-1',
    candidateSha: 'a'.repeat(40),
    prereleaseEnvironment: 'assessment-prerelease-e7-check',
    originTokenSecretArn: runtimeReferenceArn(region),
    credentialReferences: [runtimeReferenceArn(region)],
    hostedZoneId: 'Z1234567890ABC',
    webHostname: 'checkout.example.test',
    apiHostname: 'api.example.test',
    webCertificateArn: `arn:aws:acm:us-east-1:${ACCOUNT}:certificate/${CERTIFICATE}`,
    apiCertificateArn: `arn:aws:acm:${region}:${ACCOUNT}:certificate/${CERTIFICATE}`,
    activeBootstrapScope: scope,
    includeAuxiliaryReadAuthority: false,
  };
};

void describe('Stage 7 account bootstrap configuration', () => {
  void test('derives exact regional CDKToolkit and separated primary authorities', () => {
    const full = parseStage7AccountBootstrapConfig(valid());
    const prerelease = parseStage7AccountBootstrapConfig(valid('PRERELEASE'));
    assert.equal(full.bootstrap.version, STAGE7_ACCOUNT_BOOTSTRAP_VERSION);
    assert.equal(full.bootstrap.version, 32);
    assert.equal(
      full.roles.release.readRoleArn,
      `arn:aws:iam::${ACCOUNT}:role/checkout/stage7-release-read`,
    );
    assert.equal(
      prerelease.roles.prerelease.readRoleArn,
      `arn:aws:iam::${ACCOUNT}:role/checkout/stage7-prerelease-read`,
    );
    assert.notEqual(full.roles.release.readRoleArn, prerelease.roles.prerelease.readRoleArn);
    assert.equal(
      full.bootstrap.roles.bootstrapDeployRoleArn,
      `arn:aws:iam::${ACCOUNT}:role/cdk-hnb659fds-deploy-role-${ACCOUNT}-us-east-1`,
    );
    assert.equal(
      prerelease.bootstrap.roles.bootstrapDeployRoleArn,
      `arn:aws:iam::${ACCOUNT}:role/cdk-hnb659fds-deploy-role-${ACCOUNT}-us-west-2`,
    );
    assert.notEqual(
      full.bootstrap.roles.bootstrapDeployRoleArn,
      prerelease.bootstrap.roles.bootstrapDeployRoleArn,
    );
    assert.equal(full.bootstrap.assetBucketName, `cdk-hnb659fds-assets-${ACCOUNT}-us-east-1`);
    assert.equal(
      prerelease.bootstrap.imageRepositoryName,
      `cdk-hnb659fds-container-assets-${ACCOUNT}-us-west-2`,
    );
    assert.equal(full.roles.release.baselineRoleArn, prerelease.roles.prerelease.baselineRoleArn);
    assert.equal(
      full.oidcProviderArn,
      prerelease.oidcProviderArn,
      'OIDC is account-global and imported by the prerelease regional stack',
    );
  });

  void test('accepts the final full authority phase and rejects it in prerelease', () => {
    const full = parseStage7AccountBootstrapConfig({
      ...valid(),
      includeAuxiliaryReadAuthority: true,
    });
    assert.equal(full.includeAuxiliaryReadAuthority, true);
    assert.throws(
      () =>
        parseStage7AccountBootstrapConfig({
          ...valid('PRERELEASE'),
          includeAuxiliaryReadAuthority: true,
        }),
      /AUXILIARY_READ_AUTHORITY_SCOPE_INVALID/u,
    );
  });

  void test('fails closed on missing, cross-region, mutable identity and secret material inputs', () => {
    assert.throws(() => parseStage7AccountBootstrapConfig({}), /ACCOUNT_ID_INVALID/u);
    assert.throws(
      () => parseStage7AccountBootstrapConfig({ ...valid(), accountId: '1234' }),
      /ACCOUNT_ID_INVALID/u,
    );
    assert.throws(
      () =>
        parseStage7AccountBootstrapConfig({
          ...valid(),
          counterpartRegion: 'us-east-1',
        }),
      /COUNTERPART_REGION_INVALID/u,
    );
    assert.throws(
      () => parseStage7AccountBootstrapConfig({ ...valid(), candidateSha: 'A'.repeat(40) }),
      /CANDIDATE_SHA_INVALID/u,
    );
    assert.throws(
      () =>
        parseStage7AccountBootstrapConfig({
          ...valid(),
          activeBootstrapScope: 'BOTH',
        }),
      /ACTIVE_BOOTSTRAP_SCOPE_INVALID/u,
    );
    assert.throws(
      () =>
        parseStage7AccountBootstrapConfig({
          ...valid(),
          credentialReferences: ['sk_test_secret_material'],
        }),
      /CREDENTIAL_REFERENCES_INVALID/u,
    );
    assert.throws(
      () =>
        parseStage7AccountBootstrapConfig({
          ...valid(),
          originTokenSecretArn: runtimeReferenceArn(
            'us-east-1',
            ['999999', '999999'].join(''),
            'checkout/runtime-security',
          ),
        }),
      /CREDENTIAL_REFERENCES_INVALID/u,
    );
  });

  void test('requires exact custom domain and regional certificate authorities', () => {
    assert.throws(
      () => parseStage7AccountBootstrapConfig({ ...valid(), hostedZoneId: 'zone' }),
      /HOSTED_ZONE_ID_INVALID/u,
    );
    assert.throws(
      () =>
        parseStage7AccountBootstrapConfig({
          ...valid(),
          apiHostname: 'checkout.example.test',
        }),
      /DOMAIN_INVALID/u,
    );
    assert.throws(
      () =>
        parseStage7AccountBootstrapConfig({
          ...valid('PRERELEASE'),
          apiCertificateArn: `arn:aws:acm:us-east-1:${ACCOUNT}:certificate/${CERTIFICATE}`,
        }),
      /API_CERTIFICATE_ARN_INVALID/u,
    );
  });

  void test('fails before synthesis when derived IAM names exceed service quotas', () => {
    const longSupportedRegion = 'ap-southeast-7';
    assert.throws(
      () =>
        parseStage7AccountBootstrapConfig({
          ...valid('PRERELEASE'),
          region: longSupportedRegion,
          prereleaseEnvironment: `assessment-prerelease-${'a'.repeat(19)}`,
          originTokenSecretArn: runtimeReferenceArn(longSupportedRegion),
          credentialReferences: [runtimeReferenceArn(longSupportedRegion)],
          apiCertificateArn: `arn:aws:acm:${longSupportedRegion}:${ACCOUNT}:certificate/${CERTIFICATE}`,
        }),
      /IAM_MANAGED_POLICY_NAME_QUOTA_EXCEEDED/u,
    );

    const oversizedRegion = `us-${'a'.repeat(40)}-1`;
    assert.throws(
      () =>
        parseStage7AccountBootstrapConfig({
          ...valid('PRERELEASE'),
          region: oversizedRegion,
          originTokenSecretArn: runtimeReferenceArn(oversizedRegion),
          credentialReferences: [runtimeReferenceArn(oversizedRegion)],
          apiCertificateArn: `arn:aws:acm:${oversizedRegion}:${ACCOUNT}:certificate/${CERTIFICATE}`,
        }),
      /IAM_ROLE_NAME_QUOTA_EXCEEDED/u,
    );
  });
});
