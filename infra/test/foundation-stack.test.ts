import { strict as assert } from 'node:assert';
import { describe, test } from 'node:test';

import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { FoundationStack } from '../lib/foundation-stack';

interface SynthesizedResource {
  readonly Properties?: Record<string, unknown>;
}

function stackTemplate(): Template {
  const app = new App();
  const stack = new FoundationStack(app, 'FoundationTest', {
    configuration: {
      projectName: 'checkout',
      environment: 'preview',
      region: 'us-east-1',
      paymentAdapter: 'fake',
      paymentsEnabled: false,
      tokenizationMode: 'disabled',
    },
    env: { account: ['000', '000', '000', '000'].join(''), region: 'us-east-1' },
  });
  return Template.fromStack(stack);
}

function resourcesOf(template: Template, type: string): Record<string, SynthesizedResource> {
  return template.findResources(type);
}

function values(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [value];
}

void describe('preview foundation stack', () => {
  void test('uses two bounded on-demand tables and separate due/age indexes', () => {
    const template = stackTemplate();
    const tables = Object.values(resourcesOf(template, 'AWS::DynamoDB::Table'));
    assert.equal(tables.length, 2);
    for (const table of tables) {
      assert.equal(table.Properties?.BillingMode, 'PAY_PER_REQUEST');
      assert.deepEqual(table.Properties?.SSESpecification, { SSEEnabled: true });
      assert.ok(table.Properties?.OnDemandThroughput);
    }
    const indexed = tables.filter((table) =>
      Array.isArray(table.Properties?.GlobalSecondaryIndexes),
    );
    assert.equal(indexed.length, 1);
    const indexes = indexed[0]?.Properties?.GlobalSecondaryIndexes as Array<
      Record<string, unknown>
    >;
    assert.deepEqual(indexes.map((index) => index.IndexName).sort(), [
      'GSI1-Reconcile',
      'GSI2-PendingAge',
    ]);
    assert.equal(indexed[0]?.Properties?.TimeToLiveSpecification instanceof Object, true);
  });

  void test('keeps both functions Node 24, arm64 and fake-only', () => {
    const functions = Object.values(resourcesOf(stackTemplate(), 'AWS::Lambda::Function'));
    assert.equal(functions.length, 2);
    for (const fn of functions) {
      assert.equal(fn.Properties?.Runtime, 'nodejs24.x');
      assert.deepEqual(fn.Properties?.Architectures, ['arm64']);
      const variables = (
        fn.Properties?.Environment as { readonly Variables: Record<string, unknown> }
      ).Variables;
      assert.equal(variables.PAYMENT_ADAPTER, 'fake');
      assert.equal(variables.PAYMENTS_ENABLED, 'false');
      assert.equal(variables.TOKENIZATION_MODE, 'disabled');
      assert.equal(variables.FOUNDATION_SYNTH_ONLY, 'true');
    }
  });

  void test('retains logs for seven days and keeps S3 private behind OAC', () => {
    const template = stackTemplate();
    const groups = Object.values(resourcesOf(template, 'AWS::Logs::LogGroup'));
    assert.equal(groups.length, 2);
    assert.ok(groups.every((group) => group.Properties?.RetentionInDays === 7));
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
    assert.equal(Object.keys(resourcesOf(template, 'AWS::CloudFront::Distribution')).length, 1);
  });

  void test('preserves API cache headers emitted by the application', () => {
    const template = stackTemplate();
    const distribution = Object.values(resourcesOf(template, 'AWS::CloudFront::Distribution'))[0];
    if (distribution === undefined) assert.fail('CloudFront distribution is missing');
    const behaviors = (
      distribution.Properties?.DistributionConfig as {
        readonly CacheBehaviors: Array<Record<string, unknown>>;
      }
    ).CacheBehaviors;
    const apiBehavior = behaviors.find((behavior) => behavior.PathPattern === 'api/*');
    const apiPolicyId = (
      apiBehavior?.ResponseHeadersPolicyId as { readonly Ref?: unknown } | undefined
    )?.Ref;
    if (typeof apiPolicyId !== 'string') assert.fail('API response headers policy is missing');
    const apiPolicy = resourcesOf(template, 'AWS::CloudFront::ResponseHeadersPolicy')[apiPolicyId];
    const apiHeaders = (
      (
        apiPolicy?.Properties?.ResponseHeadersPolicyConfig as
          | {
              readonly CustomHeadersConfig?: {
                readonly Items?: ReadonlyArray<{ readonly Header?: unknown }>;
              };
            }
          | undefined
      )?.CustomHeadersConfig?.Items ?? []
    ).map(({ Header }) => String(Header).toLowerCase());

    assert.ok(apiHeaders.includes('permissions-policy'));
    assert.equal(apiHeaders.includes('cache-control'), false);
  });

  void test('keeps preview free of CORS, secrets, budgets and deployment identities', () => {
    const template = stackTemplate();
    const api = Object.values(resourcesOf(template, 'AWS::ApiGatewayV2::Api'))[0];
    assert.equal(Object.hasOwn(api?.Properties ?? {}, 'CorsConfiguration'), false);
    const serialized = JSON.stringify(template.toJSON()).toLowerCase();
    assert.equal(serialized.includes('secretsmanager:'), false);
    assert.equal(serialized.includes('aws::iam::oidcprovider'), false);
    assert.equal(serialized.includes('aws::budgets::budget'), false);
    assert.match(serialized, /connect-src 'self';/u);
    assert.doesNotMatch(serialized, /sandbox\.wompi\.co/u);
  });

  void test('uses exact-resource IAM and a disabled scheduler', () => {
    const template = stackTemplate();
    for (const policy of Object.values(resourcesOf(template, 'AWS::IAM::Policy'))) {
      const document = policy.Properties?.PolicyDocument as {
        readonly Statement: Array<Record<string, unknown>>;
      };
      for (const statement of document.Statement) {
        for (const resource of values(statement.Resource)) {
          assert.notEqual(resource, '*');
        }
      }
    }
    const schedule = Object.values(resourcesOf(template, 'AWS::Scheduler::Schedule'))[0];
    assert.equal(schedule?.Properties?.ScheduleExpression, 'rate(1 minute)');
    assert.equal(schedule?.Properties?.State, 'DISABLED');
  });
});
