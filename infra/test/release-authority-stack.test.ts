/* global structuredClone */
import { strict as assert } from 'node:assert';
import { describe, test } from 'node:test';

import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { parseReleaseAuthorityConfig } from '../lib/release-authority-config';
import {
  ReleaseAuthorityStack,
  STAGE7_JOURNAL_OIDC_SUBJECTS,
  STAGE7_RECOVERY_OIDC_SUBJECT,
  validateReleaseAuthorityTemplate,
} from '../lib/release-authority-stack';

const ACCOUNT = '123456789012';
const configuration = parseReleaseAuthorityConfig({
  accountId: ACCOUNT,
  region: 'us-east-1',
  readRoleArn: `arn:aws:iam::${ACCOUNT}:role/checkout/read`,
});

const synthesized = (): Record<string, unknown> => {
  const app = new App();
  const stack = new ReleaseAuthorityStack(app, 'Stage7ReleaseAuthorityTest', {
    configuration,
    env: { account: configuration.accountId, region: configuration.region },
  });
  return Template.fromStack(stack).toJSON();
};
const resources = (template: Record<string, unknown>): Record<string, Record<string, unknown>> =>
  template.Resources as Record<string, Record<string, unknown>>;
const resourceBy = (
  template: Record<string, unknown>,
  type: string,
  key: string,
  value: string,
): Record<string, unknown> => {
  const found = Object.values(resources(template)).find(
    (resource) =>
      resource.Type === type &&
      (resource.Properties as Record<string, unknown> | undefined)?.[key] === value,
  );
  if (found === undefined) assert.fail(`${type} ${value} missing`);
  return found.Properties as Record<string, unknown>;
};

void describe('Stage 7 release auxiliary IAM authority stack', () => {
  void test('synthesizes only the two bounded roles, two boundaries and exact read audit policy', () => {
    const template = synthesized();
    assert.equal(validateReleaseAuthorityTemplate(template, configuration), true);
    const types = Object.values(resources(template)).map(({ Type }) => Type);
    assert.deepEqual(types.toSorted(), [
      'AWS::IAM::ManagedPolicy',
      'AWS::IAM::ManagedPolicy',
      'AWS::IAM::Role',
      'AWS::IAM::Role',
      'AWS::IAM::RolePolicy',
    ]);
    const journal = resourceBy(template, 'AWS::IAM::Role', 'RoleName', 'release-journal-cleanup');
    const recovery = resourceBy(
      template,
      'AWS::IAM::Role',
      'RoleName',
      'release-reconciliation-recovery',
    );
    const journalSubjects = (
      (
        (journal.AssumeRolePolicyDocument as Record<string, unknown>).Statement as Array<
          Record<string, unknown>
        >
      )[0]?.Condition as Record<string, Record<string, unknown>>
    ).StringEquals?.['token.actions.githubusercontent.com:sub'];
    const recoverySubject = (
      (
        (recovery.AssumeRolePolicyDocument as Record<string, unknown>).Statement as Array<
          Record<string, unknown>
        >
      )[0]?.Condition as Record<string, Record<string, unknown>>
    ).StringEquals?.['token.actions.githubusercontent.com:sub'];
    assert.deepEqual(STAGE7_JOURNAL_OIDC_SUBJECTS, [
      'repo:ivanmonsalve0404@192544565/async-checkout-demo@1335131225:environment:assessment-release',
      'repo:ivanmonsalve0404@192544565/async-checkout-demo@1335131225:environment:assessment-release-reconciliation-recovery',
      'repo:ivanmonsalve0404@192544565/async-checkout-demo@1335131225:environment:assessment-release-successor-post-success',
    ]);
    assert.equal(
      STAGE7_RECOVERY_OIDC_SUBJECT,
      'repo:ivanmonsalve0404@192544565/async-checkout-demo@1335131225:environment:assessment-release-reconciliation-recovery',
    );
    assert.deepEqual(journalSubjects, STAGE7_JOURNAL_OIDC_SUBJECTS);
    assert.equal(recoverySubject, STAGE7_RECOVERY_OIDC_SUBJECT);
    assert.equal(Object.hasOwn(journal, 'ManagedPolicyArns'), false);
    assert.equal(Object.hasOwn(recovery, 'ManagedPolicyArns'), false);
  });

  void test('rejects wildcard, foreign subject, attached policy and swapped boundary tampering', () => {
    const mutations: Array<(template: Record<string, unknown>) => void> = [
      (template) => {
        const journal = resourceBy(
          template,
          'AWS::IAM::Role',
          'RoleName',
          'release-journal-cleanup',
        );
        const trust = journal.AssumeRolePolicyDocument as Record<string, unknown>;
        const statement = (trust.Statement as Array<Record<string, unknown>>)[0];
        const condition = statement?.Condition as Record<string, Record<string, unknown>>;
        if (condition.StringEquals !== undefined) {
          condition.StringEquals['token.actions.githubusercontent.com:sub'] = 'repo:*';
        }
      },
      (template) => {
        const recovery = resourceBy(
          template,
          'AWS::IAM::Role',
          'RoleName',
          'release-reconciliation-recovery',
        );
        const trust = recovery.AssumeRolePolicyDocument as Record<string, unknown>;
        const statement = (trust.Statement as Array<Record<string, unknown>>)[0];
        const condition = statement?.Condition as Record<string, Record<string, unknown>>;
        if (condition.StringEquals !== undefined) {
          condition.StringEquals['token.actions.githubusercontent.com:sub'] =
            'repo:ivanmonsalve0404/async-checkout-demo:environment:other';
        }
      },
      (template) => {
        const journal = resourceBy(
          template,
          'AWS::IAM::Role',
          'RoleName',
          'release-journal-cleanup',
        );
        journal.ManagedPolicyArns = ['arn:aws:iam::aws:policy/AdministratorAccess'];
      },
      (template) => {
        const journal = resourceBy(
          template,
          'AWS::IAM::Role',
          'RoleName',
          'release-journal-cleanup',
        );
        journal.PermissionsBoundary = { Ref: 'RecoveryPermissionsBoundary' };
      },
    ];
    for (const mutate of mutations) {
      const template = structuredClone(synthesized());
      mutate(template);
      assert.throws(
        () => validateReleaseAuthorityTemplate(template, configuration),
        /E7_RELEASE_AUTHORITY_TEMPLATE_/u,
      );
    }
  });

  void test('rejects read-role PassRole, wildcard, sibling resources and missing exact reads', () => {
    const mutateRead = (
      mutate: (statements: Array<Record<string, unknown>>) => void,
    ): Record<string, unknown> => {
      const template = structuredClone(synthesized());
      const readPolicy = Object.values(resources(template)).find(
        ({ Type }) => Type === 'AWS::IAM::RolePolicy',
      );
      if (readPolicy === undefined) assert.fail('read role policy missing');
      const document = (readPolicy.Properties as Record<string, unknown>).PolicyDocument as Record<
        string,
        unknown
      >;
      mutate(document.Statement as Array<Record<string, unknown>>);
      return template;
    };
    const mutations = [
      mutateRead((statements) => {
        (statements[0]?.Action as string[]).push('iam:PassRole');
      }),
      mutateRead((statements) => {
        statements[0] = { ...statements[0], Resource: '*' };
      }),
      mutateRead((statements) => {
        statements[0] = {
          ...statements[0],
          Resource: [`arn:aws:iam::${ACCOUNT}:role/checkout/sibling`],
        };
      }),
      mutateRead((statements) => {
        statements[1] = {
          ...statements[1],
          Action: ['iam:GetPolicy'],
        };
      }),
    ];
    for (const template of mutations) {
      assert.throws(
        () => validateReleaseAuthorityTemplate(template, configuration),
        /READ_ROLE_POLICY_INVALID/u,
      );
    }
  });

  void test('rejects recovery BASE and boundary drift even when role and boundary drift together', () => {
    const template = structuredClone(synthesized());
    const recoveryRole = resourceBy(
      template,
      'AWS::IAM::Role',
      'RoleName',
      'release-reconciliation-recovery',
    );
    const recoveryBoundary = resourceBy(
      template,
      'AWS::IAM::ManagedPolicy',
      'ManagedPolicyName',
      'stage7-release-reconciliation-recovery-boundary',
    );
    const roleDocument = (recoveryRole.Policies as Array<Record<string, unknown>>)[0]
      ?.PolicyDocument as Record<string, unknown>;
    const boundaryDocument = recoveryBoundary.PolicyDocument as Record<string, unknown>;
    for (const document of [roleDocument, boundaryDocument]) {
      const statements = document.Statement as Array<Record<string, unknown>>;
      statements.push({
        Sid: 'UnexpectedPrivilege',
        Effect: 'Allow',
        Action: 'iam:PassRole',
        Resource: '*',
      });
    }
    assert.throws(
      () => validateReleaseAuthorityTemplate(template, configuration),
      /BOUNDARY_INVALID|ROLE_INVALID/u,
    );
  });
});
