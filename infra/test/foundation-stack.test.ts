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
    env: {
      account: '000000000000',
      region: 'us-east-1',
    },
  });
  return Template.fromStack(stack);
}

function resourcesOf(template: Template, type: string): Record<string, SynthesizedResource> {
  return template.findResources(type);
}

function values(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [value];
}

void describe('foundation stack', () => {
  void test('uses two bounded on-demand tables and one reconcile index', () => {
    const template = stackTemplate();
    const tables = Object.values(resourcesOf(template, 'AWS::DynamoDB::Table'));

    assert.equal(tables.length, 2);
    for (const table of tables) {
      assert.equal(table.Properties?.BillingMode, 'PAY_PER_REQUEST');
      assert.deepEqual(table.Properties?.SSESpecification, {
        SSEEnabled: true,
      });
      assert.ok(table.Properties?.OnDemandThroughput);
    }

    const indexedTables = tables.filter((table) =>
      Array.isArray(table.Properties?.GlobalSecondaryIndexes),
    );
    assert.equal(indexedTables.length, 1);
    const indexes = indexedTables[0]?.Properties?.GlobalSecondaryIndexes as Array<
      Record<string, unknown>
    >;
    assert.equal(indexes.length, 1);
    assert.equal(indexes[0]?.IndexName, 'GSI1-Reconcile');
    assert.equal(indexedTables[0]?.Properties?.TimeToLiveSpecification instanceof Object, true);
  });

  void test('fixes both Lambda functions to Node 24, arm64 and fake-only', () => {
    const template = stackTemplate();
    const functions = Object.values(resourcesOf(template, 'AWS::Lambda::Function'));

    assert.equal(functions.length, 2);
    for (const fn of functions) {
      assert.equal(fn.Properties?.Runtime, 'nodejs24.x');
      assert.deepEqual(fn.Properties?.Architectures, ['arm64']);
      const environment = fn.Properties?.Environment as {
        readonly Variables: Record<string, unknown>;
      };
      assert.equal(environment.Variables.PAYMENT_ADAPTER, 'fake');
      assert.equal(environment.Variables.PAYMENTS_ENABLED, 'false');
      assert.equal(environment.Variables.TOKENIZATION_MODE, 'disabled');
      assert.equal(environment.Variables.FOUNDATION_SYNTH_ONLY, 'true');
    }

    const concurrencies = functions.map((fn) => fn.Properties?.ReservedConcurrentExecutions).sort();
    assert.deepEqual(concurrencies, [1, 5]);
  });

  void test('retains logs for exactly seven days', () => {
    const template = stackTemplate();
    const groups = Object.values(resourcesOf(template, 'AWS::Logs::LogGroup'));

    assert.equal(groups.length, 2);
    for (const group of groups) {
      assert.equal(group.Properties?.RetentionInDays, 7);
    }
  });

  void test('keeps S3 private and exposes it only through CloudFront OAC', () => {
    const template = stackTemplate();
    const buckets = Object.values(resourcesOf(template, 'AWS::S3::Bucket'));

    assert.equal(buckets.length, 1);
    assert.deepEqual(buckets[0]?.Properties?.PublicAccessBlockConfiguration, {
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

    const distribution = Object.values(resourcesOf(template, 'AWS::CloudFront::Distribution'))[0];
    const distributionConfig = distribution?.Properties?.DistributionConfig as {
      readonly CacheBehaviors: Array<Record<string, unknown>>;
    };
    assert.deepEqual(
      distributionConfig.CacheBehaviors.map((behavior) => behavior.PathPattern).sort(),
      ['api/*', 'assets/*'],
    );

    const headerPolicies = Object.values(
      resourcesOf(template, 'AWS::CloudFront::ResponseHeadersPolicy'),
    );
    assert.equal(headerPolicies.length, 2);
    assert.ok(
      headerPolicies.some((policy) => JSON.stringify(policy.Properties).includes('Cache-Control')),
    );
  });

  void test('does not enable CORS, secrets or deployment identities', () => {
    const template = stackTemplate();
    const apis = Object.values(resourcesOf(template, 'AWS::ApiGatewayV2::Api'));

    assert.equal(apis.length, 1);
    assert.equal(Object.hasOwn(apis[0]?.Properties ?? {}, 'CorsConfiguration'), false);

    const serialized = JSON.stringify(template.toJSON()).toLowerCase();
    assert.equal(serialized.includes('secretsmanager:'), false);
    assert.equal(serialized.includes('aws::iam::oidcprovider'), false);
    assert.equal(serialized.includes('aws::budgets::budget'), false);
  });

  void test('uses exact-resource IAM and a disabled one-minute scheduler', () => {
    const template = stackTemplate();
    const policies = Object.values(resourcesOf(template, 'AWS::IAM::Policy'));

    assert.ok(policies.length >= 3);
    for (const policy of policies) {
      const document = policy.Properties?.PolicyDocument as {
        readonly Statement: Array<Record<string, unknown>>;
      };
      for (const statement of document.Statement) {
        for (const resource of values(statement.Resource)) {
          assert.notEqual(resource, '*', 'IAM Resource=* is not allowed in the foundation');
        }
      }
    }

    const schedules = Object.values(resourcesOf(template, 'AWS::Scheduler::Schedule'));
    assert.equal(schedules.length, 1);
    assert.equal(schedules[0]?.Properties?.ScheduleExpression, 'rate(1 minute)');
    assert.equal(schedules[0]?.Properties?.State, 'DISABLED');
  });
});
