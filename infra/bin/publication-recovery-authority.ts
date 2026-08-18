#!/usr/bin/env node
import process from 'node:process';

import { App } from 'aws-cdk-lib';

import { parseReleaseSuccessorPublicationRecoveryAuthorityConfig } from '../lib/release-successor-publication-recovery-authority-config';
import { ReleaseSuccessorPublicationRecoveryAuthorityStack } from '../lib/release-successor-publication-recovery-authority-stack';

const app = new App();
const fromContextOrEnvironment = (contextKey: string, environmentKey: string): unknown =>
  app.node.tryGetContext(contextKey) ?? process.env[environmentKey];
const configuration = parseReleaseSuccessorPublicationRecoveryAuthorityConfig({
  accountId: fromContextOrEnvironment('stage7AwsAccountId', 'STAGE7_AWS_ACCOUNT_ID'),
  region: fromContextOrEnvironment('stage7AwsRegion', 'STAGE7_AWS_REGION'),
});

new ReleaseSuccessorPublicationRecoveryAuthorityStack(
  app,
  'checkout-stage7-release-successor-publication-recovery-authority',
  {
    configuration,
    description:
      'SYNTH-ONLY Stage 7 release-successor publication recovery IAM; provisioning requires separate protected authority',
    env: { account: configuration.accountId, region: configuration.region },
    terminationProtection: true,
  },
);
