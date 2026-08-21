#!/usr/bin/env node
import { App } from 'aws-cdk-lib';

import { parseFoundationConfig } from '../lib/config';
import { FoundationStack } from '../lib/foundation-stack';
import {
  ReleaseApiStack,
  ReleaseDataStack,
  ReleaseObservabilityStack,
  ReleaseWebStack,
} from '../lib/release-stacks';

const app = new App();
const configuration = parseFoundationConfig({
  projectName: app.node.tryGetContext('projectName'),
  environment: app.node.tryGetContext('environment'),
  region: app.node.tryGetContext('region'),
  releaseId: app.node.tryGetContext('releaseId'),
  candidateSha: app.node.tryGetContext('candidateSha'),
  owner: app.node.tryGetContext('owner'),
  expiresOn: app.node.tryGetContext('expiresOn'),
  cleanupExpiresAtUtc: app.node.tryGetContext('cleanupExpiresAtUtc'),
  paymentAdapter: app.node.tryGetContext('paymentAdapter'),
  paymentsEnabled: app.node.tryGetContext('paymentsEnabled'),
  tokenizationMode: app.node.tryGetContext('tokenizationMode'),
  schedulerEnabled: app.node.tryGetContext('schedulerEnabled'),
  sandboxAuthorizedUntilUtc: app.node.tryGetContext('sandboxAuthorizedUntilUtc'),
  pointInTimeRecoveryEnabled: app.node.tryGetContext('pointInTimeRecoveryEnabled'),
  publicationMode: app.node.tryGetContext('publicationMode'),
  prereleaseKeyGroupId: app.node.tryGetContext('prereleaseKeyGroupId'),
  prereleasePublicKeyId: app.node.tryGetContext('prereleasePublicKeyId'),
  budgetMaxUsd: app.node.tryGetContext('budgetMaxUsd'),
  budgetWarningUsd: app.node.tryGetContext('budgetWarningUsd'),
  apiArtifactPath: app.node.tryGetContext('apiArtifactPath'),
  workerArtifactPath: app.node.tryGetContext('workerArtifactPath'),
  webArtifactPath: app.node.tryGetContext('webArtifactPath'),
  runtimeSecretArn: app.node.tryGetContext('runtimeSecretArn'),
  runtimeSecretVersionId: app.node.tryGetContext('runtimeSecretVersionId'),
  hostedZoneId: app.node.tryGetContext('hostedZoneId'),
  hostedZoneName: app.node.tryGetContext('hostedZoneName'),
  webDomainName: app.node.tryGetContext('webDomainName'),
  webCertificateArn: app.node.tryGetContext('webCertificateArn'),
  apiDomainName: app.node.tryGetContext('apiDomainName'),
  apiCertificateArn: app.node.tryGetContext('apiCertificateArn'),
});

const environment = { region: configuration.region };
const prefix = configuration.projectName + '-' + configuration.environment;

if (configuration.environment === 'preview') {
  new FoundationStack(app, prefix + '-foundation', {
    configuration,
    description: 'SYNTH-ONLY fake checkout foundation; deployment requires separate authorization',
    env: environment,
    terminationProtection: true,
  });
} else {
  const ephemeralPrerelease = configuration.environment.startsWith('assessment-prerelease-');
  const shared = {
    configuration,
    env: environment,
    terminationProtection: !ephemeralPrerelease,
  };
  const dataStack = new ReleaseDataStack(app, prefix + '-data', {
    ...shared,
    description: 'Assessment release data plane; state retained across code rollback',
  });
  const apiStack = new ReleaseApiStack(app, prefix + '-api', {
    ...shared,
    dataStack,
    description: 'Versioned assessment API, worker and reconciliation scheduler',
  });
  const observabilityStack = new ReleaseObservabilityStack(app, prefix + '-observability', {
    ...shared,
    apiStack,
    dataStack,
    description: 'Assessment logs, metrics, alarms, dashboard and budget',
  });
  new ReleaseWebStack(app, prefix + '-web', {
    ...shared,
    apiStack,
    observabilityStack,
    description: 'Private S3 origin, CloudFront edge and immutable web release',
  });
}
