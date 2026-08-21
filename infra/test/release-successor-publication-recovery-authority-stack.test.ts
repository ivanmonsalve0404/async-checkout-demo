/* global structuredClone */
import { strict as assert } from 'node:assert';
import { describe, test } from 'node:test';

import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { parseReleaseSuccessorPublicationRecoveryAuthorityConfig } from '../lib/release-successor-publication-recovery-authority-config';
import {
  ReleaseSuccessorPublicationRecoveryAuthorityStack,
  validateReleaseSuccessorPublicationRecoveryAuthorityTemplate,
} from '../lib/release-successor-publication-recovery-authority-stack';

const ACCOUNT = '123456789012';
const configuration = parseReleaseSuccessorPublicationRecoveryAuthorityConfig({
  accountId: ACCOUNT,
  region: 'us-east-1',
});

const synthesized = (): Record<string, unknown> => {
  const app = new App();
  const stack = new ReleaseSuccessorPublicationRecoveryAuthorityStack(
    app,
    'Stage7PublicationRecoveryAuthorityTest',
    {
      configuration,
      env: { account: configuration.accountId, region: configuration.region },
    },
  );
  return Template.fromStack(stack).toJSON();
};
const resources = (template: Record<string, unknown>): Record<string, Record<string, unknown>> =>
  template.Resources as Record<string, Record<string, unknown>>;
const onlyResource = (
  template: Record<string, unknown>,
  type: string,
): [string, Record<string, unknown>] => {
  const matches = Object.entries(resources(template)).filter(
    ([, resource]) => resource.Type === type,
  );
  assert.equal(matches.length, 1);
  const match = matches[0];
  if (match === undefined) assert.fail(`${type} missing`);
  return [match[0], match[1].Properties as Record<string, unknown>];
};
const policyDocuments = (
  template: Record<string, unknown>,
): { inline: Record<string, unknown>; boundary: Record<string, unknown> } => {
  const [, role] = onlyResource(template, 'AWS::IAM::Role');
  const [, boundary] = onlyResource(template, 'AWS::IAM::ManagedPolicy');
  const inline = (role.Policies as Array<Record<string, unknown>>)[0]?.PolicyDocument;
  if (inline === undefined) assert.fail('inline BASE missing');
  return {
    inline: inline as Record<string, unknown>,
    boundary: boundary.PolicyDocument as Record<string, unknown>,
  };
};

void describe('Stage 7 release-successor publication recovery IAM stack', () => {
  void test('synthesizes exactly one role, one identical BASE boundary and no session policy', () => {
    const template = synthesized();
    assert.equal(
      validateReleaseSuccessorPublicationRecoveryAuthorityTemplate(template, configuration),
      true,
    );
    assert.deepEqual(
      Object.values(resources(template))
        .map(({ Type }) => Type)
        .toSorted(),
      ['AWS::IAM::ManagedPolicy', 'AWS::IAM::Role'],
    );
    assert.deepEqual(Object.keys(template.Parameters as Record<string, unknown>), [
      'BootstrapVersion',
    ]);

    const [boundaryId] = onlyResource(template, 'AWS::IAM::ManagedPolicy');
    const [, role] = onlyResource(template, 'AWS::IAM::Role');
    assert.equal(role.RoleName, 'release-successor-publication-recovery');
    assert.equal(role.Path, '/checkout/');
    assert.deepEqual(role.PermissionsBoundary, { Ref: boundaryId });
    assert.equal(Object.hasOwn(role, 'ManagedPolicyArns'), false);
    assert.equal((role.Policies as unknown[]).length, 1);
    assert.deepEqual(policyDocuments(template).inline, policyDocuments(template).boundary);

    const trust = role.AssumeRolePolicyDocument as Record<string, unknown>;
    const statement = (trust.Statement as Array<Record<string, unknown>>)[0];
    const condition = statement?.Condition as Record<string, Record<string, unknown>>;
    assert.equal(
      condition.StringEquals?.['token.actions.githubusercontent.com:sub'],
      'repo:ivanmonsalve0404@192544565/async-checkout-demo@1335131225:environment:assessment-release-successor-publication-recovery',
    );
    assert.equal(
      condition.StringEquals?.['token.actions.githubusercontent.com:aud'],
      'sts.amazonaws.com',
    );
    assert.equal(JSON.stringify(template).includes('candidateSha'), false);
    assert.equal(JSON.stringify(template).includes('sourceRunId'), false);
  });

  void test('rejects a wildcard privilege even when inline BASE and boundary drift together', () => {
    const template = structuredClone(synthesized());
    const { inline, boundary } = policyDocuments(template);
    for (const document of [inline, boundary]) {
      (document.Statement as Array<Record<string, unknown>>).push({
        Sid: 'CanaryWildcard',
        Effect: 'Allow',
        Action: 'iam:*',
        Resource: '*',
      });
    }
    assert.throws(
      () => validateReleaseSuccessorPublicationRecoveryAuthorityTemplate(template, configuration),
      /E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_BOUNDARY_INVALID/u,
    );
  });

  void test('rejects trust widening away from the exact protected environment', () => {
    const template = structuredClone(synthesized());
    const [, role] = onlyResource(template, 'AWS::IAM::Role');
    const trust = role.AssumeRolePolicyDocument as Record<string, unknown>;
    const statement = (trust.Statement as Array<Record<string, unknown>>)[0];
    const condition = statement?.Condition as Record<string, Record<string, unknown>>;
    if (condition.StringEquals !== undefined) {
      condition.StringEquals['token.actions.githubusercontent.com:sub'] = 'repo:*';
    }
    assert.throws(
      () => validateReleaseSuccessorPublicationRecoveryAuthorityTemplate(template, configuration),
      /E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_ROLE_INVALID/u,
    );
  });

  void test('rejects an attached managed policy', () => {
    const template = structuredClone(synthesized());
    const [, role] = onlyResource(template, 'AWS::IAM::Role');
    role.ManagedPolicyArns = ['arn:aws:iam::aws:policy/ReadOnlyAccess'];
    assert.throws(
      () => validateReleaseSuccessorPublicationRecoveryAuthorityTemplate(template, configuration),
      /E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_ROLE_INVALID/u,
    );
  });

  void test('rejects boundary substitution and candidate-scoped session materialization', () => {
    const boundarySwap = structuredClone(synthesized());
    const [, swappedRole] = onlyResource(boundarySwap, 'AWS::IAM::Role');
    swappedRole.PermissionsBoundary = 'arn:aws:iam::aws:policy/ReadOnlyAccess';
    assert.throws(
      () =>
        validateReleaseSuccessorPublicationRecoveryAuthorityTemplate(boundarySwap, configuration),
      /E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_ROLE_INVALID/u,
    );

    const sessionPolicy = structuredClone(synthesized());
    const documents = policyDocuments(sessionPolicy);
    for (const document of [documents.inline, documents.boundary]) {
      const statement = (document.Statement as Array<Record<string, unknown>>).find(
        ({ Sid }) => Sid === 'ReadExactImmutableFence',
      );
      if (statement !== undefined) {
        statement.Resource = `arn:aws:ssm:us-east-1:${ACCOUNT}:parameter/checkout/stage7/release-fence/0123456789012345678901234567890123456789/123`;
      }
    }
    assert.throws(
      () =>
        validateReleaseSuccessorPublicationRecoveryAuthorityTemplate(sessionPolicy, configuration),
      /E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_BOUNDARY_INVALID/u,
    );
  });
});
