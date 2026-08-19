#!/usr/bin/env node
import process from 'node:process';

import { App } from 'aws-cdk-lib';

import { parseReleaseAuthorityConfig } from '../lib/release-authority-config';
import { ReleaseAuthorityStack } from '../lib/release-authority-stack';

const app = new App();
const fromContextOrEnvironment = (contextKey: string, environmentKey: string): unknown =>
  app.node.tryGetContext(contextKey) ?? process.env[environmentKey];
const configuration = parseReleaseAuthorityConfig({
  accountId: fromContextOrEnvironment('stage7AwsAccountId', 'STAGE7_AWS_ACCOUNT_ID'),
  region: fromContextOrEnvironment('stage7AwsRegion', 'STAGE7_AWS_REGION'),
  readRoleArn: fromContextOrEnvironment('stage7AwsReadRoleArn', 'STAGE7_AWS_READ_ROLE_ARN'),
});

new ReleaseAuthorityStack(app, 'checkout-stage7-release-authority', {
  configuration,
  description:
    'SYNTH-ONLY Stage 7 auxiliary IAM authorities; provisioning is a separate protected prerequisite',
  env: { account: configuration.accountId, region: configuration.region },
  terminationProtection: true,
});
