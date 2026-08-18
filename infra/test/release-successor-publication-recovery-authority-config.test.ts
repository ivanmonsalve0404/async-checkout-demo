import { strict as assert } from 'node:assert';
import { describe, test } from 'node:test';

import {
  parseReleaseSuccessorPublicationRecoveryAuthorityConfig,
  STAGE7_PUBLICATION_RECOVERY_BOUNDARY_VARIABLE,
  STAGE7_PUBLICATION_RECOVERY_ENVIRONMENT,
  STAGE7_PUBLICATION_RECOVERY_ROLE_VARIABLE,
} from '../lib/release-successor-publication-recovery-authority-config';

const ACCOUNT = '123456789012';

void describe('Stage 7 release-successor publication recovery IAM configuration', () => {
  void test('derives the exact isolated role, boundary and protected variable contract', () => {
    const config = parseReleaseSuccessorPublicationRecoveryAuthorityConfig({
      accountId: ACCOUNT,
      region: 'us-east-1',
    });
    assert.equal(config.repository, 'ivanmonsalve0404/async-checkout-demo');
    assert.equal(config.protectedEnvironment, 'assessment-release-successor-publication-recovery');
    assert.equal(config.protectedEnvironment, STAGE7_PUBLICATION_RECOVERY_ENVIRONMENT);
    assert.equal(
      config.roleArn,
      `arn:aws:iam::${ACCOUNT}:role/checkout/release-successor-publication-recovery`,
    );
    assert.equal(
      config.permissionsBoundaryArn,
      `arn:aws:iam::${ACCOUNT}:policy/stage7-release-successor-publication-recovery-boundary`,
    );
    assert.equal(
      STAGE7_PUBLICATION_RECOVERY_ROLE_VARIABLE,
      'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_ROLE_ARN',
    );
    assert.equal(
      STAGE7_PUBLICATION_RECOVERY_BOUNDARY_VARIABLE,
      'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN',
    );
  });

  void test('fails closed for missing, malformed or padded synthesis coordinates', () => {
    const invalid = [
      {},
      { accountId: '1234', region: 'us-east-1' },
      { accountId: ACCOUNT, region: 'not-a-region' },
      { accountId: ` ${ACCOUNT}`, region: 'us-east-1' },
      { accountId: ACCOUNT, region: 'us-east-1 ' },
    ];
    for (const input of invalid) {
      assert.throws(
        () => parseReleaseSuccessorPublicationRecoveryAuthorityConfig(input),
        /E7_PUBLICATION_RECOVERY_IAC_/u,
      );
    }
  });
});
