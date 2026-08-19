#!/usr/bin/env node
import process from 'node:process';

import { App } from 'aws-cdk-lib';

import { parseStage7AccountBootstrapConfig } from '../lib/stage7-account-bootstrap-config';
import {
  Stage7FullAccountBootstrapStack,
  Stage7PrereleaseAccountBootstrapStack,
} from '../lib/stage7-account-bootstrap-stack';

const app = new App();
const fromContextOrEnvironment = (contextKey: string, environmentKey: string): unknown =>
  app.node.tryGetContext(contextKey) ?? process.env[environmentKey];

const parseCredentialReferences = (value: unknown): unknown => {
  if (Array.isArray(value)) return value;
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('E7_ACCOUNT_BOOTSTRAP_CREDENTIAL_REFERENCES_INVALID');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('E7_ACCOUNT_BOOTSTRAP_CREDENTIAL_REFERENCES_INVALID');
  }
  if (!Array.isArray(parsed)) {
    throw new Error('E7_ACCOUNT_BOOTSTRAP_CREDENTIAL_REFERENCES_INVALID');
  }
  return parsed;
};

const parseRequiredBoolean = (value: unknown): unknown => {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error('E7_ACCOUNT_BOOTSTRAP_INCLUDE_AUXILIARY_READ_AUTHORITY_INVALID');
};

const configuration = parseStage7AccountBootstrapConfig({
  accountId: fromContextOrEnvironment('stage7AwsAccountId', 'STAGE7_AWS_ACCOUNT_ID'),
  region: fromContextOrEnvironment('stage7AwsRegion', 'STAGE7_AWS_REGION'),
  counterpartRegion: fromContextOrEnvironment(
    'stage7AwsCounterpartRegion',
    'STAGE7_AWS_COUNTERPART_REGION',
  ),
  candidateSha: fromContextOrEnvironment('stage7CandidateSha', 'STAGE7_CANDIDATE_SHA'),
  prereleaseEnvironment: fromContextOrEnvironment(
    'stage7PrereleaseEnvironment',
    'STAGE7_PRERELEASE_ENVIRONMENT',
  ),
  originTokenSecretArn: fromContextOrEnvironment(
    'stage7OriginTokenSecretArn',
    'STAGE7_ORIGIN_TOKEN_SECRET_ARN',
  ),
  credentialReferences: parseCredentialReferences(
    fromContextOrEnvironment('stage7CredentialReferences', 'STAGE7_CREDENTIAL_REFERENCES_JSON'),
  ),
  hostedZoneId: fromContextOrEnvironment('stage7HostedZoneId', 'STAGE7_HOSTED_ZONE_ID'),
  webHostname: fromContextOrEnvironment('stage7WebHostname', 'STAGE7_WEB_HOSTNAME'),
  apiHostname: fromContextOrEnvironment('stage7ApiHostname', 'STAGE7_API_HOSTNAME'),
  webCertificateArn: fromContextOrEnvironment(
    'stage7WebCertificateArn',
    'STAGE7_WEB_CERTIFICATE_ARN',
  ),
  apiCertificateArn: fromContextOrEnvironment(
    'stage7ApiCertificateArn',
    'STAGE7_API_CERTIFICATE_ARN',
  ),
  activeBootstrapScope: fromContextOrEnvironment('stage7BootstrapScope', 'STAGE7_BOOTSTRAP_SCOPE'),
  includeAuxiliaryReadAuthority: parseRequiredBoolean(
    fromContextOrEnvironment(
      'stage7IncludeAuxiliaryReadAuthority',
      'STAGE7_INCLUDE_AUXILIARY_READ_AUTHORITY',
    ),
  ),
});

const StackClass =
  configuration.activeBootstrapScope === 'FULL_RELEASE'
    ? Stage7FullAccountBootstrapStack
    : Stage7PrereleaseAccountBootstrapStack;

new StackClass(app, 'Stage7AccountBootstrap', {
  configuration,
  description: `SYNTH-ONLY Stage 7 ${configuration.activeBootstrapScope} regional CDK and OIDC authority bootstrap`,
  env: { account: configuration.accountId, region: configuration.region },
  stackName: 'CDKToolkit',
  terminationProtection: true,
});
