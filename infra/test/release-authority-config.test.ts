import { strict as assert } from 'node:assert';
import { describe, test } from 'node:test';

import {
  parseReleaseAuthorityConfig,
  STAGE7_GITHUB_OIDC_HOST,
} from '../lib/release-authority-config';

const ACCOUNT = '123456789012';
const valid = () => ({
  accountId: ACCOUNT,
  region: 'us-east-1',
  readRoleArn: `arn:aws:iam::${ACCOUNT}:role/checkout/read`,
});

void describe('Stage 7 release authority configuration', () => {
  void test('derives the four exact auxiliary ARNs and immutable OIDC provider', () => {
    const config = parseReleaseAuthorityConfig(valid());
    assert.equal(config.repository, 'ivanmonsalve0404/async-checkout-demo');
    assert.equal(
      config.oidcProviderArn,
      `arn:aws:iam::${ACCOUNT}:oidc-provider/${STAGE7_GITHUB_OIDC_HOST}`,
    );
    assert.equal(
      config.journalRoleArn,
      `arn:aws:iam::${ACCOUNT}:role/checkout/release-journal-cleanup`,
    );
    assert.equal(
      config.journalPermissionsBoundaryArn,
      `arn:aws:iam::${ACCOUNT}:policy/stage7-release-journal-cleanup-boundary`,
    );
    assert.equal(
      config.reconciliationRecoveryRoleArn,
      `arn:aws:iam::${ACCOUNT}:role/checkout/release-reconciliation-recovery`,
    );
    assert.equal(
      config.reconciliationRecoveryPermissionsBoundaryArn,
      `arn:aws:iam::${ACCOUNT}:policy/stage7-release-reconciliation-recovery-boundary`,
    );
  });

  void test('rejects missing, cross-account, wildcard, sibling-path and auxiliary collisions', () => {
    assert.throws(() => parseReleaseAuthorityConfig({}), /ACCOUNT_ID_INVALID/u);
    assert.throws(
      () => parseReleaseAuthorityConfig({ ...valid(), accountId: '1234' }),
      /ACCOUNT_ID_INVALID/u,
    );
    assert.throws(
      () => parseReleaseAuthorityConfig({ ...valid(), region: 'not-a-region' }),
      /REGION_INVALID/u,
    );
    assert.throws(
      () =>
        parseReleaseAuthorityConfig({
          ...valid(),
          readRoleArn: 'arn:aws:iam::999999999999:role/checkout/read',
        }),
      /READ_ROLE_ARN_INVALID/u,
    );
    for (const readRoleArn of [
      `arn:aws:iam::${ACCOUNT}:role/other/read`,
      `arn:aws:iam::${ACCOUNT}:role/checkout/*`,
      `arn:aws:iam::${ACCOUNT}:role/checkout/release-journal-cleanup`,
      `arn:aws:iam::${ACCOUNT}:role/checkout/release-reconciliation-recovery`,
    ]) {
      assert.throws(
        () => parseReleaseAuthorityConfig({ ...valid(), readRoleArn }),
        /READ_ROLE_ARN_INVALID|ROLE_SET_INVALID/u,
      );
    }
  });
});
