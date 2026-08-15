#!/usr/bin/env node
import { App } from 'aws-cdk-lib';

import { parseFoundationConfig } from '../lib/config';
import { FoundationStack } from '../lib/foundation-stack';

const app = new App();
const configuration = parseFoundationConfig({
  projectName: app.node.tryGetContext('projectName'),
  environment: app.node.tryGetContext('environment'),
  region: app.node.tryGetContext('region'),
  paymentAdapter: app.node.tryGetContext('paymentAdapter'),
  paymentsEnabled: app.node.tryGetContext('paymentsEnabled'),
  tokenizationMode: app.node.tryGetContext('tokenizationMode'),
});

new FoundationStack(
  app,
  configuration.projectName + '-' + configuration.environment + '-foundation',
  {
    configuration,
    description: 'SYNTH-ONLY fake checkout foundation; deployment requires separate authorization',
    env: { region: configuration.region },
    terminationProtection: true,
  },
);
