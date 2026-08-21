import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { validateBaselineConfig } from './baseline-establishment.mjs';
import {
  authorStage7Configs,
  authorStage7ConfigFiles,
  parseStage7ConfigAuthoringSource,
  Stage7ConfigAuthoringError,
} from './config-authoring.mjs';
import { canonicalJson, objectSha256, validateStage7Config, workspaceRoot } from './core.mjs';

const NOW = new Date('2026-08-19T14:00:00.000Z');
const ACCOUNT_ID = ['908745', '612301'].join('');
const RUNTIME_REFERENCE_TYPE = ['se', 'cret'].join('');
const runtimeReferenceArn = (region, resourcePath) =>
  ['arn:aws:secretsmanager', region, ACCOUNT_ID, RUNTIME_REFERENCE_TYPE, resourcePath].join(':');
const RELEASE_RUNTIME_REFERENCE_ARN = runtimeReferenceArn(
  'us-east-1',
  'checkout/assessment-release/runtime-N7p4Qs',
);
const PRERELEASE_RUNTIME_REFERENCE_ARN = runtimeReferenceArn(
  'us-west-2',
  'checkout/assessment-prerelease/runtime-R5w8Jc',
);

export const buildStage7ConfigAuthoringSelfTestInput = () => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'STAGE7_CONFIG_AUTHORING_INPUT',
  release: {
    authorization: {
      id: 'AUTH-E7-RELEASE-20260819',
      ownerAlias: 'ivanmonsalve0404',
      approvedAtUtc: '2026-08-19T13:30:00.000Z',
      expiresAtUtc: '2026-08-20T12:00:00.000Z',
      communicationChannelAlias: 'assessment-release',
      rollbackOwnerAlias: 'ivanmonsalve0404',
    },
    window: {
      startsAtUtc: '2026-08-19T16:00:00.000Z',
      endsAtUtc: '2026-08-19T20:00:00.000Z',
    },
    cleanup: {
      ownerAlias: 'ivanmonsalve0404',
      expiresAtUtc: '2026-08-22T20:00:00.000Z',
    },
  },
  prerelease: {
    environment: 'assessment-prerelease-e7-a1',
    authorization: {
      id: 'AUTH-E7-PRERELEASE-20260819',
      ownerAlias: 'ivanmonsalve0404',
      approvedAtUtc: '2026-08-19T13:30:00.000Z',
      expiresAtUtc: '2026-08-20T12:00:00.000Z',
      communicationChannelAlias: 'assessment-prerelease',
      rollbackOwnerAlias: 'ivanmonsalve0404',
    },
    window: {
      startsAtUtc: '2026-08-19T14:30:00.000Z',
      endsAtUtc: '2026-08-19T18:30:00.000Z',
    },
    cleanup: {
      ownerAlias: 'ivanmonsalve0404',
      expiresAtUtc: '2026-08-20T08:00:00.000Z',
    },
  },
  baseline: {
    authorization: {
      id: 'AUTH-E7-BASELINE-20260819',
      ownerAlias: 'ivanmonsalve0404',
      approvedAtUtc: '2026-08-19T13:30:00.000Z',
      expiresAtUtc: '2026-08-20T12:00:00.000Z',
      communicationChannelAlias: 'assessment-release',
      rollbackOwnerAlias: 'ivanmonsalve0404',
    },
    window: {
      startsAtUtc: '2026-08-19T13:45:00.000Z',
      endsAtUtc: '2026-08-19T15:45:00.000Z',
    },
    cleanup: {
      ownerAlias: 'ivanmonsalve0404',
      expiresAtUtc: '2026-08-22T20:00:00.000Z',
    },
  },
  aws: {
    accountId: ACCOUNT_ID,
    targets: {
      full: {
        region: 'us-east-1',
        roles: {
          readRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-full-read-a8f3`,
          deployRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-full-deploy-c6q2`,
          rollbackRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-full-rollback-r9m5`,
          cleanupRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-full-cleanup-k4v7`,
          baselineRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-full-baseline-b3x8`,
        },
      },
      prerelease: {
        region: 'us-west-2',
        roles: {
          readRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-pre-read-q2m8`,
          deployRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-pre-deploy-v7c4`,
          rollbackRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-pre-rollback-f5n9`,
          cleanupRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-pre-cleanup-h6k3`,
          baselineRoleArn: `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-full-baseline-b3x8`,
        },
      },
    },
  },
  budget: {
    maxUsd: 12,
    warningUsd: [6, 10],
    alertOwnerAlias: 'ivanmonsalve0404',
    alertChannelAlias: 'assessment-cost-alerts',
    alertDestination: 'release-alerts@acme.dev',
  },
  domains: {
    full: {
      hostname: 'app.acme.dev',
      apiHostname: 'api.acme.dev',
      hostedZoneId: 'Z09W7Q3M5K8N2P',
      hostedZoneName: 'acme.dev',
      webCertificateArn: `arn:aws:acm:us-east-1:${ACCOUNT_ID}:certificate/7d9f13a2-5c84-4b71-9e36-2a8c5f7041bd`,
      apiCertificateArn: `arn:aws:acm:us-east-1:${ACCOUNT_ID}:certificate/42b8e6d1-93f5-4a07-bc62-719d3e58f4a0`,
    },
    prerelease: {
      hostname: 'preview.acme.dev',
      apiHostname: 'api-preview.acme.dev',
      hostedZoneId: 'Z09W7Q3M5K8N2P',
      hostedZoneName: 'acme.dev',
      webCertificateArn: `arn:aws:acm:us-east-1:${ACCOUNT_ID}:certificate/35a7c9e2-64d1-4f80-b2a6-9e4137c5d8f0`,
      apiCertificateArn: `arn:aws:acm:us-west-2:${ACCOUNT_ID}:certificate/86c4b2d9-17e5-4a63-9f08-2d715b3e6c40`,
    },
  },
  access: {
    full: {
      keyGroupId: 'c2f83d9a-4f1e-4d7a-8b21-6c9d3e5f7a10',
      publicKeyId: 'K2P7D9F4H6T8XB',
      originTokenSecretArn: RELEASE_RUNTIME_REFERENCE_ARN,
      originTokenSecretVersionId: '7f3c9d2a-58b1-46e7-90ad-2c8f5b7134e6',
    },
    prerelease: {
      keyGroupId: 'd7a21c6e-8b34-49f5-a062-1e3c7d9b4f80',
      publicKeyId: 'K5C8N3R7W9T2DP',
      originTokenSecretArn: PRERELEASE_RUNTIME_REFERENCE_ARN,
      originTokenSecretVersionId: '9b6e2f41-37c8-4d05-a1f9-68c2e7543b0d',
    },
  },
});

const validInput = buildStage7ConfigAuthoringSelfTestInput;
const direct =
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;

if (direct) {
  let assertions = 0;
  let canaries = 0;
  const equal = (actual, expected) => {
    assertions += 1;
    assert.equal(actual, expected);
  };
  const deepEqual = (actual, expected) => {
    assertions += 1;
    assert.deepEqual(actual, expected);
  };
  const rejects = (mutate, expectedCode) => {
    const input = validInput();
    mutate(input);
    canaries += 1;
    assertions += 1;
    assert.throws(
      () => authorStage7Configs(input, { now: NOW }),
      (error) => error?.code === expectedCode,
    );
  };

  const input = validInput();
  const before = JSON.parse(JSON.stringify(input));
  const authored = authorStage7Configs(input, { now: NOW });
  equal(validateStage7Config(authored.fullConfig.value, { now: NOW }), authored.fullConfig.value);
  equal(
    validateStage7Config(authored.prereleaseConfig.value, { now: NOW }),
    authored.prereleaseConfig.value,
  );
  equal(
    validateBaselineConfig(authored.baselineConfig.value, { now: NOW }),
    authored.baselineConfig.value,
  );
  deepEqual(input, before);
  equal(authored.fullConfig.source, canonicalJson(authored.fullConfig.value));
  equal(authored.prereleaseConfig.source, canonicalJson(authored.prereleaseConfig.value));
  equal(authored.baselineConfig.source, canonicalJson(authored.baselineConfig.value));
  equal(authored.fullConfig.sha256, objectSha256(authored.fullConfig.value));
  equal(authored.prereleaseConfig.sha256, objectSha256(authored.prereleaseConfig.value));
  equal(authored.baselineConfig.sha256, objectSha256(authored.baselineConfig.value));
  equal(authored.fullConfig.value.authorization.scope, 'FULL_RELEASE_VERSIONED_UPDATE');
  equal(authored.prereleaseConfig.value.authorization.scope, 'EPHEMERAL_PRERELEASE');
  equal(authored.baselineConfig.value.authorization.scope, 'FULL_RELEASE_BASELINE_CLOSED');
  equal(authored.fullConfig.value.aws.region, 'us-east-1');
  equal(authored.baselineConfig.value.aws.region, 'us-east-1');
  equal(authored.prereleaseConfig.value.aws.region, 'us-west-2');
  equal(authored.fullConfig.value.prereleaseAccess.mode, 'ORIGIN_GATE_ONLY');
  equal(authored.prereleaseConfig.value.prereleaseAccess.mode, 'CLOUDFRONT_SIGNED_COOKIE');
  equal(authored.baselineConfig.value.prereleaseAccess.mode, 'CLOUDFRONT_SIGNED_COOKIE');
  equal(authored.prereleaseConfig.value.domain.mode, 'CUSTOM_AUTHORIZED');
  equal(authored.fullConfig.value.authorization.abortCriteria.length, 8);
  equal(authored.baselineConfig.value.traffic.maxRequests, 8);
  equal(authored.fullConfig.value.credentialReferences.length, 1);
  equal(authored.fullConfig.value.credentialReferences[0], RELEASE_RUNTIME_REFERENCE_ARN);
  equal(authored.prereleaseConfig.value.credentialReferences[0], PRERELEASE_RUNTIME_REFERENCE_ARN);
  equal(
    authored.alertDestinationSha256,
    createHash('sha256').update(input.budget.alertDestination).digest('hex'),
  );
  equal(authored.fullConfig.source.includes(input.budget.alertDestination), false);
  equal(authored.prereleaseConfig.source.includes(input.budget.alertDestination), false);
  equal(authored.baselineConfig.source.includes(input.budget.alertDestination), false);
  equal(authored.fullConfig.source.endsWith('\n'), false);
  equal(authored.prereleaseConfig.source.endsWith('\n'), false);
  equal(authored.baselineConfig.source.endsWith('\n'), false);
  deepEqual(Object.keys(authored.variableMapping.shared), ['STAGE7_AWS_ACCOUNT_ID']);
  deepEqual(Object.keys(authored.variableMapping.full).sort(), [
    'STAGE7_AWS_CLEANUP_ROLE_ARN',
    'STAGE7_AWS_DEPLOY_ROLE_ARN',
    'STAGE7_AWS_READ_ROLE_ARN',
    'STAGE7_AWS_REGION',
    'STAGE7_AWS_ROLLBACK_ROLE_ARN',
    'STAGE7_CONFIG_B64',
  ]);
  deepEqual(Object.keys(authored.variableMapping.baseline).sort(), [
    'STAGE7_AWS_BASELINE_ROLE_ARN',
    'STAGE7_AWS_CLEANUP_ROLE_ARN',
    'STAGE7_AWS_DEPLOY_ROLE_ARN',
    'STAGE7_AWS_READ_ROLE_ARN',
    'STAGE7_AWS_REGION',
    'STAGE7_AWS_ROLLBACK_ROLE_ARN',
    'STAGE7_BASELINE_CONFIG_B64',
  ]);
  deepEqual(Object.keys(authored.variableMapping.prerelease).sort(), [
    'STAGE7_PRERELEASE_AWS_CLEANUP_ROLE_ARN',
    'STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN',
    'STAGE7_PRERELEASE_AWS_READ_ROLE_ARN',
    'STAGE7_PRERELEASE_AWS_REGION',
    'STAGE7_PRERELEASE_AWS_ROLLBACK_ROLE_ARN',
    'STAGE7_PRERELEASE_CONFIG_B64',
  ]);
  equal(
    Buffer.from(authored.variableMapping.full.STAGE7_CONFIG_B64, 'base64').toString('utf8'),
    authored.fullConfig.source,
  );
  equal(
    Buffer.from(authored.variableMapping.baseline.STAGE7_BASELINE_CONFIG_B64, 'base64').toString(
      'utf8',
    ),
    authored.baselineConfig.source,
  );
  equal(
    Buffer.from(
      authored.variableMapping.prerelease.STAGE7_PRERELEASE_CONFIG_B64,
      'base64',
    ).toString('utf8'),
    authored.prereleaseConfig.source,
  );
  equal(authored.variableMapping.full.STAGE7_AWS_REGION, 'us-east-1');
  equal(authored.variableMapping.baseline.STAGE7_AWS_REGION, 'us-east-1');
  equal(authored.variableMapping.prerelease.STAGE7_PRERELEASE_AWS_REGION, 'us-west-2');
  equal(Object.hasOwn(authored.variableMapping.prerelease, 'STAGE7_CONFIG_B64'), false);
  equal(
    authored.variableMapping.workflowDispatchInputs.release.config_sha256,
    authored.fullConfig.sha256,
  );
  equal(
    authored.variableMapping.workflowDispatchInputs.prerelease.config_sha256,
    authored.prereleaseConfig.sha256,
  );
  equal(
    authored.variableMapping.workflowDispatchInputs.baseline.config_sha256,
    authored.baselineConfig.sha256,
  );
  deepEqual(authorStage7Configs(validInput(), { now: NOW }), authored);

  const selfTestRoot = mkdtempSync(path.join(workspaceRoot, '.stage7-config-authoring-selftest-'));
  const selfTestCleanupSafe = path.dirname(selfTestRoot) === workspaceRoot;
  assert.equal(selfTestCleanupSafe, true);
  try {
    const inputFilename = path.join(selfTestRoot, 'input.json');
    const outputDirectory = path.join(selfTestRoot, 'authored');
    writeFileSync(inputFilename, canonicalJson(validInput()), { encoding: 'utf8', flag: 'wx' });
    const summary = authorStage7ConfigFiles({ inputFilename, outputDirectory, now: NOW });
    for (const [name, document] of Object.entries({
      fullConfig: authored.fullConfig,
      prereleaseConfig: authored.prereleaseConfig,
      baselineConfig: authored.baselineConfig,
    })) {
      const output = summary.outputs[name];
      const source = readFileSync(path.join(workspaceRoot, output.filename), 'utf8');
      equal(source, document.source);
      equal(createHash('sha256').update(source).digest('hex'), output.sha256);
      equal(Buffer.byteLength(source), output.bytes);
    }
  } finally {
    if (selfTestCleanupSafe) rmSync(selfTestRoot, { recursive: true, force: true });
  }
  const processCanary = spawnSync(
    process.execPath,
    [
      path.join(workspaceRoot, 'scripts', 'stage7', 'config-authoring.mjs'),
      'author',
      '--',
      '--input',
      path.join(selfTestRoot, 'missing-input.json'),
      '--output-directory',
      path.join(selfTestRoot, 'missing-output'),
    ],
    { cwd: workspaceRoot, encoding: 'utf8', env: process.env },
  );
  canaries += 1;
  assertions += 2;
  assert.equal(processCanary.status, 1);
  assert.equal(processCanary.stderr.trim(), 'E7_CONFIG_AUTHORING_PATH_INVALID');

  rejects((value) => {
    value.release.authorization.ownerAlias = 'todo';
  }, 'E7_CONFIG_AUTHORING_PLACEHOLDER_FORBIDDEN');
  rejects((value) => {
    value.prerelease.environment = 'assessment-prerelease-x-';
  }, 'E7_CONFIG_AUTHORING_INPUT_SCHEMA_INVALID');
  rejects((value) => {
    value.release.authorization.ownerAlias = 'release-owner';
  }, 'E7_CONFIG_AUTHORING_PLACEHOLDER_FORBIDDEN');
  rejects((value) => {
    value.aws.accountId = '123456789012';
  }, 'E7_CONFIG_AUTHORING_EXAMPLE_ACCOUNT_FORBIDDEN');
  rejects((value) => {
    value.domains.full.hostname = 'checkout.example.test';
    value.domains.full.apiHostname = 'api.example.test';
    value.domains.full.hostedZoneName = 'example.test';
  }, 'E7_CONFIG_AUTHORING_RESERVED_HOST_FORBIDDEN');
  rejects((value) => {
    value.domains.prerelease.hostedZoneId = 'Z1234567890ABC';
  }, 'E7_CONFIG_AUTHORING_PLACEHOLDER_FORBIDDEN');
  rejects((value) => {
    value.domains.prerelease.hostname = value.domains.full.hostname;
  }, 'E7_CONFIG_AUTHORING_DOMAIN_SEPARATION_INVALID');
  rejects((value) => {
    value.domains.prerelease = { ...value.domains.full };
  }, 'E7_CONFIG_AUTHORING_DOMAIN_SEPARATION_INVALID');
  rejects((value) => {
    value.domains.prerelease.hostname = 'preview.other.dev';
  }, 'E7_CONFIG_AUTHORING_DOMAIN_ZONE_INVALID');
  rejects((value) => {
    value.domains.full.hostname = 'checkout.prod.acme.dev';
    value.domains.full.apiHostname = 'api.prod.acme.dev';
  }, 'E7_CONFIG_AUTHORING_DOMAIN_ZONE_INVALID');
  rejects((value) => {
    value.domains.prerelease.hostedZoneId = 'Z08R6P4N2M7K9Q';
  }, 'E7_CONFIG_AUTHORING_HOSTED_ZONE_BINDING_INVALID');
  rejects((value) => {
    value.domains.prerelease.hostedZoneId = value.domains.full.hostedZoneId;
    value.domains.prerelease.hostname = 'preview.foreign.dev';
    value.domains.prerelease.apiHostname = 'api-preview.foreign.dev';
    value.domains.prerelease.hostedZoneName = 'foreign.dev';
  }, 'E7_CONFIG_AUTHORING_HOSTED_ZONE_BINDING_INVALID');
  rejects((value) => {
    value.aws.targets.prerelease.region = value.aws.targets.full.region;
  }, 'E7_CONFIG_AUTHORING_REGION_SEPARATION_INVALID');
  rejects((value) => {
    value.release.window.endsAtUtc = '2026-08-19T15:00:00.000Z';
  }, 'E7_RELEASE_WINDOW_NOT_AUTHORIZED');
  rejects((value) => {
    value.baseline.window.startsAtUtc = '2026-08-20T13:45:00.000Z';
  }, 'E7_BASELINE_WINDOW_INVALID');
  rejects((value) => {
    value.baseline.window.startsAtUtc = '2026-02-30T13:45:00.000Z';
  }, 'E7_CONFIG_AUTHORING_TIMESTAMP_INVALID');
  rejects((value) => {
    value.aws.targets.full.roles.deployRoleArn =
      'arn:aws:iam::908745612301:role/checkout-stage7-administrator';
  }, 'E7_CONFIG_AUTHORING_ROLE_ARN_INVALID');
  rejects((value) => {
    value.aws.targets.full.roles.deployRoleArn =
      'arn:aws:iam::807654321098:role/checkout-stage7-deploy-c6q2';
  }, 'E7_CONFIG_AUTHORING_ROLE_ARN_INVALID');
  rejects((value) => {
    value.aws.targets.full.roles.deployRoleArn = value.aws.targets.full.roles.readRoleArn;
  }, 'E7_CONFIG_AUTHORING_ROLE_SEPARATION_INVALID');
  rejects((value) => {
    const roleName = value.aws.targets.full.roles.readRoleArn.split('/').at(-1);
    value.aws.targets.full.roles.deployRoleArn = `arn:aws:iam::${ACCOUNT_ID}:role/isolated/${roleName}`;
  }, 'E7_CONFIG_AUTHORING_ROLE_SEPARATION_INVALID');
  rejects((value) => {
    value.aws.targets.prerelease.roles.readRoleArn = value.aws.targets.full.roles.readRoleArn;
  }, 'E7_CONFIG_AUTHORING_SCOPE_ROLE_REUSE_FORBIDDEN');
  rejects((value) => {
    const roleName = value.aws.targets.full.roles.readRoleArn.split('/').at(-1);
    value.aws.targets.prerelease.roles.readRoleArn = `arn:aws:iam::${ACCOUNT_ID}:role/prerelease/${roleName}`;
  }, 'E7_CONFIG_AUTHORING_SCOPE_ROLE_REUSE_FORBIDDEN');
  rejects((value) => {
    value.aws.targets.prerelease.roles.readRoleArn = `arn:aws:iam::${ACCOUNT_ID}:role/prerelease/`;
  }, 'E7_CONFIG_AUTHORING_INPUT_SCHEMA_INVALID');
  rejects((value) => {
    value.aws.targets.prerelease.roles.readRoleArn = `arn:aws:iam::${ACCOUNT_ID}:role/prerelease//read`;
  }, 'E7_CONFIG_AUTHORING_INPUT_SCHEMA_INVALID');
  rejects((value) => {
    value.aws.targets.prerelease.roles.readRoleArn = `arn:aws:iam::${ACCOUNT_ID}:role/${'r'.repeat(65)}`;
  }, 'E7_CONFIG_AUTHORING_INPUT_SCHEMA_INVALID');
  rejects((value) => {
    value.aws.targets.prerelease.roles.baselineRoleArn = `arn:aws:iam::${ACCOUNT_ID}:role/checkout-stage7-pre-baseline-d4r7`;
  }, 'E7_CONFIG_AUTHORING_SHARED_BASELINE_ROLE_REQUIRED');
  rejects((value) => {
    value.access.full.originTokenSecretArn = runtimeReferenceArn(
      'eu-west-1',
      'checkout/runtime-N7p4Qs',
    );
  }, 'E7_CONFIG_AUTHORING_SECRET_ARN_INVALID');
  rejects((value) => {
    value.access.prerelease.originTokenSecretVersionId = 'a'.repeat(32);
  }, 'E7_CONFIG_AUTHORING_SECRET_VERSION_PLACEHOLDER_FORBIDDEN');
  rejects((value) => {
    value.access.full.keyGroupId = value.access.full.publicKeyId;
  }, 'E7_CONFIG_AUTHORING_INPUT_SCHEMA_INVALID');
  rejects((value) => {
    value.access.full.publicKeyId = value.access.full.keyGroupId;
  }, 'E7_CONFIG_AUTHORING_INPUT_SCHEMA_INVALID');
  rejects((value) => {
    value.domains.full.webCertificateArn = `arn:aws:acm:us-east-1:${ACCOUNT_ID}:certificate/11111111-1111-1111-1111-111111111111`;
  }, 'E7_CONFIG_AUTHORING_CERTIFICATE_ARN_INVALID');
  rejects((value) => {
    value.domains.prerelease.apiCertificateArn = `arn:aws:acm:eu-west-1:${ACCOUNT_ID}:certificate/86c4b2d9-17e5-4a63-9f08-2d715b3e6c40`;
  }, 'E7_CONFIG_AUTHORING_CERTIFICATE_ARN_INVALID');
  rejects((value) => {
    value.release.authorization.id = 'AUTH-E7-BASELINE-OTHER';
  }, 'E7_CONFIG_AUTHORING_RELEASE_AUTHORITY_INVALID');
  rejects((value) => {
    value.prerelease.authorization.id = 'AUTH-E7-RELEASE-OTHER';
  }, 'E7_CONFIG_AUTHORING_PRERELEASE_AUTHORITY_INVALID');
  rejects((value) => {
    value.baseline.authorization.id = 'AUTH-E7-RELEASE-OTHER';
  }, 'E7_CONFIG_AUTHORING_BASELINE_AUTHORITY_INVALID');
  rejects((value) => {
    value.budget.warningUsd = [10, 6];
  }, 'E7_BUDGET_INVALID');
  rejects((value) => {
    value.budget.alertDestination = 'alerts@example.com';
  }, 'E7_CONFIG_AUTHORING_RESERVED_HOST_FORBIDDEN');
  rejects((value) => {
    value.unexpected = true;
  }, 'E7_CONFIG_AUTHORING_INPUT_SCHEMA_INVALID');

  canaries += 1;
  assertions += 1;
  assert.throws(
    () =>
      parseStage7ConfigAuthoringSource(
        Buffer.from('{"schemaVersion":1,"schemaVersion":1}', 'utf8'),
      ),
    (error) => error?.code === 'SOURCE_DUPLICATE_KEY',
  );

  canaries += 1;
  assertions += 1;
  assert.throws(
    () => authorStage7Configs(validInput(), { now: new Date('invalid') }),
    (error) =>
      error instanceof Stage7ConfigAuthoringError &&
      error.code === 'E7_CONFIG_AUTHORING_VALIDATION_TIME_INVALID',
  );

  process.stdout.write(
    `config-authoring-self-test: PASS (${assertions} assertions; ${canaries} rejection canaries)\n`,
  );
}
