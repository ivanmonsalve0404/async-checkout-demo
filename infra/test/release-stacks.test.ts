import { strict as assert } from 'node:assert';
import * as path from 'node:path';
import { describe, test } from 'node:test';

import { App } from 'aws-cdk-lib';
import type { Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { parseFoundationConfig } from '../lib/config';
import {
  ReleaseApiStack,
  ReleaseDataStack,
  ReleaseObservabilityStack,
  ReleaseWebStack,
} from '../lib/release-stacks';

interface SynthesizedResource {
  readonly Properties?: Record<string, unknown>;
}

interface ReleaseAssembly {
  readonly stacks: readonly Stack[];
  readonly data: Template;
  readonly api: Template;
  readonly observability: Template;
  readonly web: Template;
}

const RELEASE_SHA = ['01234567', '89abcdef', '01234567', '89abcdef', '01234567'].join('');
const TEST_ACCOUNT = ['000', '000', '000', '000'].join('');
const certificateArn = (id: string): string =>
  `arn:aws:acm:us-east-1:${TEST_ACCOUNT}:certificate/${id}`;
const runtimeReference = (): string =>
  ['arn:aws:secretsmanager:us-east-1:', TEST_ACCOUNT, ':secret:', 'wompi/runtime-', 'AbCdEf'].join(
    '',
  );

function releaseAssembly(
  paymentAdapter: 'fake' | 'sandbox' = 'sandbox',
  customDomain = paymentAdapter === 'sandbox',
  environment: 'assessment-release' | `assessment-prerelease-${string}` = 'assessment-release',
): ReleaseAssembly {
  const fixture = (name: string): string => path.join(__dirname, 'fixtures', name);
  const sandbox =
    paymentAdapter === 'sandbox'
      ? {
          paymentAdapter: 'sandbox',
          paymentsEnabled: true,
          runtimeSecretArn: runtimeReference(),
          schedulerEnabled: true,
          sandboxAuthorizedUntilUtc: '2099-01-01T00:00:00.000Z',
          tokenizationMode: 'direct_jwe',
        }
      : {};
  const domain = customDomain
    ? {
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
      }
    : {};
  const configuration = parseFoundationConfig({
    apiArtifactPath: fixture('release-api'),
    candidateSha: RELEASE_SHA,
    environment,
    expiresOn: '2099-12-31',
    owner: 'assessment-team',
    pointInTimeRecoveryEnabled: true,
    publicationMode: environment.startsWith('assessment-prerelease-')
      ? 'EPHEMERAL_NON_PUBLIC'
      : 'INITIAL_CLOSED',
    releaseId: 'rel-20991231-2359-0123456',
    webArtifactPath: fixture('release-web'),
    workerArtifactPath: fixture('release-worker'),
    ...sandbox,
    ...domain,
  });
  if (configuration.environment === 'preview') assert.fail('release expected');
  const app = new App();
  const shared = {
    configuration,
    env: { account: TEST_ACCOUNT, region: 'us-east-1' },
    terminationProtection: !environment.startsWith('assessment-prerelease-'),
  };
  const prefix = 'checkout-' + environment;
  const data = new ReleaseDataStack(app, prefix + '-data', shared);
  const api = new ReleaseApiStack(app, prefix + '-api', {
    ...shared,
    dataStack: data,
  });
  const observability = new ReleaseObservabilityStack(app, prefix + '-observability', {
    ...shared,
    apiStack: api,
    dataStack: data,
  });
  const web = new ReleaseWebStack(app, prefix + '-web', {
    ...shared,
    apiStack: api,
    observabilityStack: observability,
  });
  return {
    stacks: [data, api, observability, web],
    data: Template.fromStack(data),
    api: Template.fromStack(api),
    observability: Template.fromStack(observability),
    web: Template.fromStack(web),
  };
}

function resourcesOf(template: Template, type: string): Record<string, SynthesizedResource> {
  return template.findResources(type);
}

function values(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [value];
}

void describe('assessment release assembly', () => {
  void test('creates four deployable checkpoints with isolated ownership', () => {
    const assembly = releaseAssembly();
    assert.deepEqual(
      assembly.stacks.map((stack) => stack.stackName),
      [
        'checkout-assessment-release-data',
        'checkout-assessment-release-api',
        'checkout-assessment-release-observability',
        'checkout-assessment-release-web',
      ],
    );
    assert.equal(Object.keys(resourcesOf(assembly.data, 'AWS::DynamoDB::Table')).length, 2);
    assert.equal(Object.keys(resourcesOf(assembly.data, 'AWS::Lambda::Function')).length, 0);
    assert.equal(Object.keys(resourcesOf(assembly.api, 'AWS::DynamoDB::Table')).length, 0);
    assert.equal(Object.keys(resourcesOf(assembly.api, 'AWS::ApiGatewayV2::Api')).length, 1);
    assert.equal(
      Object.keys(resourcesOf(assembly.observability, 'AWS::Budgets::Budget')).length,
      1,
    );
    assert.equal(Object.keys(resourcesOf(assembly.observability, 'AWS::S3::Bucket')).length, 0);
    assert.equal(Object.keys(resourcesOf(assembly.web, 'AWS::S3::Bucket')).length, 1);
    assert.equal(Object.keys(resourcesOf(assembly.web, 'AWS::CloudFront::Distribution')).length, 1);
    assert.equal(Object.keys(resourcesOf(assembly.web, 'AWS::DynamoDB::Table')).length, 0);
  });

  void test('uses dynamic but bounded stack names for ephemeral prerelease', () => {
    const assembly = releaseAssembly('fake', false, 'assessment-prerelease-pr-42-a11y');
    assert.deepEqual(
      assembly.stacks.map((stack) => stack.stackName),
      [
        'checkout-assessment-prerelease-pr-42-a11y-data',
        'checkout-assessment-prerelease-pr-42-a11y-api',
        'checkout-assessment-prerelease-pr-42-a11y-observability',
        'checkout-assessment-prerelease-pr-42-a11y-web',
      ],
    );
    const api = JSON.stringify(assembly.api.toJSON());
    assert.match(api, /APP_ENV[^}]*assessment/u);
    assert.doesNotMatch(api, /FOUNDATION_SYNTH_ONLY[^}]*true/u);
    assert.ok(assembly.stacks.every((stack) => stack.terminationProtection === false));
  });

  void test('makes every ephemeral prerelease resource removable by cleanup', () => {
    const assembly = releaseAssembly('sandbox', false, 'assessment-prerelease-cleanup-canary');
    const tables = Object.values(resourcesOf(assembly.data, 'AWS::DynamoDB::Table'));
    assert.equal(tables.length, 2);
    for (const table of tables) {
      assert.equal(table.Properties?.DeletionProtectionEnabled, false);
      assert.equal((table as Record<string, unknown>).DeletionPolicy, 'Delete');
      assert.equal((table as Record<string, unknown>).UpdateReplacePolicy, 'Delete');
    }

    const bucket = Object.values(resourcesOf(assembly.web, 'AWS::S3::Bucket'))[0] as
      (SynthesizedResource & Record<string, unknown>) | undefined;
    assert.equal(bucket?.DeletionPolicy, 'Delete');
    assert.equal(bucket?.UpdateReplacePolicy, 'Delete');
    assert.equal(Object.keys(resourcesOf(assembly.web, 'Custom::S3AutoDeleteObjects')).length, 1);
    const deployments = Object.values(resourcesOf(assembly.web, 'Custom::CDKBucketDeployment'));
    assert.equal(deployments.length, 2);
    assert.ok(deployments.every((deployment) => deployment.Properties?.RetainOnDelete === false));
    const versions = Object.values(resourcesOf(assembly.api, 'AWS::Lambda::Version'));
    assert.equal(versions.length, 2);
    for (const version of versions) {
      const policies = version as Record<string, unknown>;
      assert.equal(policies.DeletionPolicy, 'Delete');
      assert.equal(policies.UpdateReplacePolicy, 'Delete');
    }
  });

  void test('retains bounded data and emits the approved schema', () => {
    const assembly = releaseAssembly();
    assert.ok(assembly.stacks.every((stack) => stack.terminationProtection === true));
    const template = assembly.data;
    const tables = Object.values(resourcesOf(template, 'AWS::DynamoDB::Table'));
    assert.equal(tables.length, 2);
    for (const table of tables) {
      assert.equal(table.Properties?.BillingMode, 'PAY_PER_REQUEST');
      assert.equal(
        (table.Properties?.PointInTimeRecoverySpecification as Record<string, unknown>)
          .PointInTimeRecoveryEnabled,
        true,
      );
      assert.ok(table.Properties?.OnDemandThroughput);
    }
    const json = template.toJSON();
    for (const resource of Object.values(
      json.Resources as Record<string, Record<string, unknown>>,
    )) {
      if (resource.Type === 'AWS::DynamoDB::Table') {
        assert.equal(resource.DeletionPolicy, 'Retain');
        assert.equal(resource.UpdateReplacePolicy, 'Retain');
      }
    }
  });

  void test('uses exact artifacts, app configuration, versions and aliases', () => {
    const template = releaseAssembly().api;
    const templateJson = template.toJSON();
    assert.equal(templateJson.Parameters.PublicationState.Default, 'DISABLED');
    assert.deepEqual(templateJson.Conditions.PublicationEnabled, {
      'Fn::Equals': [{ Ref: 'PublicationState' }, 'ENABLED'],
    });
    const functions = Object.values(resourcesOf(template, 'AWS::Lambda::Function'));
    assert.equal(functions.length, 2);
    for (const fn of functions) {
      assert.equal(fn.Properties?.Handler, 'index.handler');
      assert.equal(fn.Properties?.Runtime, 'nodejs24.x');
      assert.deepEqual(fn.Properties?.Architectures, ['arm64']);
      const variables = (
        fn.Properties?.Environment as { readonly Variables: Record<string, unknown> }
      ).Variables;
      assert.equal(variables.APP_ENV, 'assessment');
      assert.equal(variables.DATA_ADAPTER, 'dynamodb');
      assert.equal(variables.AUTO_SEED_CATALOG, 'false');
      assert.equal(variables.TOKENIZATION_MODE, 'direct_jwe');
      assert.ok(variables.RUNTIME_SECRET_ARN);
      assert.equal(
        variables.ALLOWED_ORIGIN_PARAMETER_NAME,
        '/checkout-assessment-release/public-origin',
      );
      assert.equal(
        variables.PUBLIC_ASSET_ORIGIN_PARAMETER_NAME,
        '/checkout-assessment-release/public-origin',
      );
      assert.equal(Object.hasOwn(variables, 'RUNTIME_SECURITY_ROOT_KEY'), false);
    }
    const versions = Object.values(resourcesOf(template, 'AWS::Lambda::Version'));
    assert.equal(versions.length, 2);
    for (const version of versions) {
      const policies = version as Record<string, unknown>;
      assert.equal(policies.DeletionPolicy, 'Retain');
      assert.equal(policies.UpdateReplacePolicy, 'Retain');
    }
    const aliases = Object.values(resourcesOf(template, 'AWS::Lambda::Alias'));
    assert.equal(aliases.length, 2);
    assert.ok(aliases.every((alias) => alias.Properties?.Name === 'live'));
    assert.equal(Object.keys(resourcesOf(template, 'AWS::SecretsManager::Secret')).length, 0);
    const outputs = template.toJSON().Outputs as Record<string, { readonly Value: unknown }>;
    assert.match(String(outputs.ApiArtifactSha256?.Value), /^[a-f0-9]{64}$/u);
    assert.match(String(outputs.WorkerArtifactSha256?.Value), /^[a-f0-9]{64}$/u);
    assert.deepEqual(outputs.ApiPublicationStatus?.Value, {
      'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'],
    });
  });

  void test('uses exact application IAM and a bounded scheduler', () => {
    const template = releaseAssembly('sandbox');
    const policies = resourcesOf(template.api, 'AWS::IAM::Policy');
    const applicationPolicies = Object.entries(policies).filter(([logicalId]) =>
      /(?:ApiRole|WorkerRole|SchedulerRole)DefaultPolicy/u.test(logicalId),
    );
    assert.equal(applicationPolicies.length, 3);
    for (const [, policy] of applicationPolicies) {
      const statements = (
        policy.Properties?.PolicyDocument as {
          readonly Statement: Array<Record<string, unknown>>;
        }
      ).Statement;
      for (const statement of statements) {
        for (const resource of values(statement.Resource)) assert.notEqual(resource, '*');
      }
    }
    const schedule = Object.values(resourcesOf(template.api, 'AWS::Scheduler::Schedule'))[0];
    assert.deepEqual(schedule?.Properties?.State, {
      'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'],
    });
    const outputs = template.api.toJSON().Outputs as Record<string, { readonly Value: unknown }>;
    assert.deepEqual(outputs.SchedulerStatus?.Value, {
      'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'],
    });
    assert.ok(outputs.HttpApiId?.Value);
    assert.equal(outputs.ApiCustomDomainName?.Value, 'api.checkout.example.com');
    assert.equal(schedule?.Properties?.ScheduleExpression, 'rate(1 minute)');
  });

  void test('creates actionable observability and a bounded budget', () => {
    const template = releaseAssembly().observability;
    const alarms = Object.values(resourcesOf(template, 'AWS::CloudWatch::Alarm'));
    assert.equal(alarms.length, 14);
    assert.ok(
      alarms.some(
        (alarm) =>
          alarm.Properties?.Threshold === 600 &&
          alarm.Properties?.MetricName === 'OldestPendingAgeSeconds' &&
          alarm.Properties?.Statistic === 'Maximum',
      ),
    );
    const metricFilters = Object.values(resourcesOf(template, 'AWS::Logs::MetricFilter'));
    assert.equal(metricFilters.length, 11);
    assert.ok(
      metricFilters.some((filter) => {
        const transformations = filter.Properties?.MetricTransformations as
          Array<Readonly<Record<string, unknown>>> | undefined;
        return transformations?.some(
          (transformation: Readonly<Record<string, unknown>>) =>
            transformation.MetricName === 'OldestPendingAgeSeconds' &&
            transformation.MetricValue === '$.metricValue',
        );
      }),
    );
    assert.equal(Object.keys(resourcesOf(template, 'AWS::CloudWatch::Dashboard')).length, 1);
    assert.equal(Object.keys(resourcesOf(template, 'AWS::SNS::Topic')).length, 1);
    const budget = Object.values(resourcesOf(template, 'AWS::Budgets::Budget'))[0];
    const budgetData = budget?.Properties?.Budget as Record<string, unknown>;
    assert.deepEqual(budgetData.BudgetLimit, { Amount: 10, Unit: 'USD' });
    assert.deepEqual(budgetData.CostFilters, { TagKeyValue: ['user:Project$checkout'] });
    const notifications = budget?.Properties?.NotificationsWithSubscribers as Array<{
      readonly Notification: Readonly<Record<string, unknown>>;
    }>;
    assert.deepEqual(
      notifications.map((entry) => [
        entry.Notification.NotificationType,
        entry.Notification.Threshold,
      ]),
      [
        ['ACTUAL', 50],
        ['ACTUAL', 80],
        ['FORECASTED', 100],
      ],
    );
  });

  void test('publishes immutable web assets through a private OAC origin', () => {
    const template = releaseAssembly().web;
    const bucket = Object.values(resourcesOf(template, 'AWS::S3::Bucket'))[0];
    assert.deepEqual(bucket?.Properties?.PublicAccessBlockConfiguration, {
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    });
    assert.equal(
      Object.keys(resourcesOf(template, 'AWS::CloudFront::OriginAccessControl')).length,
      1,
    );
    assert.equal(Object.keys(resourcesOf(template, 'Custom::CDKBucketDeployment')).length, 2);
    assert.equal(Object.keys(resourcesOf(template, 'AWS::SSM::Parameter')).length, 1);
    assert.equal(Object.keys(resourcesOf(template, 'AWS::CloudWatch::Alarm')).length, 1);
    const distribution = Object.values(resourcesOf(template, 'AWS::CloudFront::Distribution'))[0];
    const config = distribution?.Properties?.DistributionConfig as {
      readonly CacheBehaviors: Array<Record<string, unknown>>;
      readonly Enabled: unknown;
    };
    assert.deepEqual(config.Enabled, {
      'Fn::If': ['PublicationEnabled', true, false],
    });
    assert.deepEqual(config.CacheBehaviors.map((behavior) => behavior.PathPattern).sort(), [
      'api/*',
      'assets/*',
    ]);
    const outputs = template.toJSON().Outputs as Record<string, { readonly Value: unknown }>;
    assert.match(String(outputs.WebArtifactSha256?.Value), /^[a-f0-9]{64}$/u);
    assert.equal(outputs.ReleaseScope?.Value, 'SANDBOX_RELEASE_CANDIDATE');
    assert.equal(outputs.TlsBaselineStatus?.Value, 'TLS12_CUSTOM_DOMAIN_CONFIGURED');
  });

  void test('keeps managed sandbox prerelease non-indexed and explicit', () => {
    const assembly = releaseAssembly('sandbox', false, 'assessment-prerelease-managed-sandbox');
    assert.equal(assembly.api.toJSON().Parameters.PublicationState.Default, 'DISABLED');
    assert.equal(assembly.web.toJSON().Parameters.PublicationState.Default, 'DISABLED');
    const api = Object.values(resourcesOf(assembly.api, 'AWS::ApiGatewayV2::Api'))[0];
    assert.deepEqual(api?.Properties?.DisableExecuteApiEndpoint, {
      'Fn::If': ['PublicationEnabled', false, true],
    });
    const combined = JSON.stringify({ api: assembly.api.toJSON(), web: assembly.web.toJSON() });
    assert.match(combined, /connect-src 'self' https:\/\/sandbox\.wompi\.co;/u);
    assert.match(combined, /X-Robots-Tag/u);
    assert.doesNotMatch(combined, /prv_test_/u);
    const outputs = assembly.web.toJSON().Outputs as Record<string, { readonly Value: unknown }>;
    const apiOutputs = assembly.api.toJSON().Outputs as Record<string, { readonly Value: unknown }>;
    assert.equal(apiOutputs.ApiCustomDomainName?.Value, 'NONE_MANAGED_PRERELEASE');
    assert.equal(outputs.ReleaseScope?.Value, 'SANDBOX_NON_PUBLIC_PRERELEASE_ONLY');
    assert.equal(
      outputs.TlsBaselineStatus?.Value,
      'BLOCKED_CUSTOM_DOMAIN_REQUIRED_PRERELEASE_ONLY',
    );
  });

  void test('enforces exact sandbox CSP, secret reference and full TLS 1.2 gate', () => {
    const assembly = releaseAssembly('sandbox');
    const apiJson = assembly.api.toJSON();
    const webJson = assembly.web.toJSON();
    const combined = JSON.stringify({ api: apiJson, web: webJson });
    assert.match(combined, /connect-src 'self' https:\/\/sandbox\.wompi\.co;/u);
    assert.doesNotMatch(combined, /PROVIDER_PRIVATE_KEY_SECRET_ARN/u);
    assert.doesNotMatch(combined, /PROVIDER_INTEGRITY_SECRET_ARN/u);
    assert.match(combined, /RUNTIME_SECRET_ARN/u);
    assert.doesNotMatch(combined, /WOMPI_PUBLIC_KEY/u);
    assert.doesNotMatch(combined, /pub_test_/u);
    assert.doesNotMatch(combined, /prv_test_/u);

    const api = Object.values(resourcesOf(assembly.api, 'AWS::ApiGatewayV2::Api'))[0];
    assert.deepEqual(api?.Properties?.DisableExecuteApiEndpoint, {
      'Fn::If': ['PublicationEnabled', true, true],
    });
    assert.equal(Object.hasOwn(api?.Properties ?? {}, 'CorsConfiguration'), false);
    const apiDomain = Object.values(resourcesOf(assembly.api, 'AWS::ApiGatewayV2::DomainName'))[0];
    const domainConfigurations = apiDomain?.Properties?.DomainNameConfigurations as Array<
      Record<string, unknown>
    >;
    assert.equal(domainConfigurations[0]?.SecurityPolicy, 'TLS_1_2');
    assert.equal(Object.keys(resourcesOf(assembly.api, 'AWS::Route53::RecordSet')).length, 2);
    const mappings = resourcesOf(assembly.api, 'AWS::ApiGatewayV2::ApiMapping');
    assert.equal(Object.keys(mappings).length, 1);
    assert.equal(
      (Object.values(mappings)[0] as Record<string, unknown>).Condition,
      'PublicationEnabled',
    );
    assert.equal(Object.keys(resourcesOf(assembly.web, 'AWS::Route53::RecordSet')).length, 2);
    const apiOutputs = apiJson.Outputs as Record<string, { readonly Value: unknown }>;
    assert.equal(apiOutputs.ApiCustomDomainName?.Value, 'api.checkout.example.com');
    assert.ok(apiOutputs.HttpApiId?.Value);

    const distribution = Object.values(
      resourcesOf(assembly.web, 'AWS::CloudFront::Distribution'),
    )[0];
    const config = distribution?.Properties?.DistributionConfig as {
      readonly Aliases: string[];
      readonly Enabled: unknown;
      readonly ViewerCertificate: Record<string, unknown>;
    };
    assert.deepEqual(config.Aliases, ['checkout.example.com']);
    assert.deepEqual(config.Enabled, {
      'Fn::If': ['PublicationEnabled', true, false],
    });
    assert.equal(config.ViewerCertificate.MinimumProtocolVersion, 'TLSv1.2_2021');
    const outputs = webJson.Outputs as Record<string, { readonly Value: unknown }>;
    assert.equal(outputs.TlsBaselineStatus?.Value, 'TLS12_CUSTOM_DOMAIN_CONFIGURED');
    assert.equal(outputs.ReleaseScope?.Value, 'SANDBOX_RELEASE_CANDIDATE');
    assert.deepEqual(outputs.WebPublicationStatus?.Value, {
      'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'],
    });
  });
});
