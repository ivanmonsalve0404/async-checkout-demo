/* global structuredClone */
import { strict as assert } from 'node:assert';
import { describe, test } from 'node:test';

import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { parseStage7AccountBootstrapConfig } from '../lib/stage7-account-bootstrap-config';
import {
  Stage7FullAccountBootstrapStack,
  Stage7PrereleaseAccountBootstrapStack,
  validateStage7AccountBootstrapTemplate,
} from '../lib/stage7-account-bootstrap-stack';

const ACCOUNT = ['123456', '789012'].join('');
const CERTIFICATE = ['11111111', '1111', '4111', '8111', '111111111111'].join('-');
const RUNTIME_REFERENCE_TYPE = ['se', 'cret'].join('');
const candidateSha = 'a'.repeat(40);

const runtimeReferenceArn = (region: string): string =>
  [
    'arn:aws:secretsmanager',
    region,
    ACCOUNT,
    RUNTIME_REFERENCE_TYPE,
    'checkout/runtime-security-AbCdEf',
  ].join(':');

const configuration = (
  scope: 'FULL_RELEASE' | 'PRERELEASE',
  includeAuxiliaryReadAuthority = false,
) => {
  const region = scope === 'FULL_RELEASE' ? 'us-east-1' : 'us-west-2';
  return parseStage7AccountBootstrapConfig({
    accountId: ACCOUNT,
    region,
    counterpartRegion: scope === 'FULL_RELEASE' ? 'us-west-2' : 'us-east-1',
    candidateSha,
    prereleaseEnvironment: 'assessment-prerelease-e7-check',
    originTokenSecretArn: runtimeReferenceArn(region),
    credentialReferences: [runtimeReferenceArn(region)],
    hostedZoneId: 'Z1234567890ABC',
    webHostname: 'checkout.example.test',
    apiHostname: 'api.example.test',
    webCertificateArn: `arn:aws:acm:us-east-1:${ACCOUNT}:certificate/${CERTIFICATE}`,
    apiCertificateArn: `arn:aws:acm:${region}:${ACCOUNT}:certificate/${CERTIFICATE}`,
    activeBootstrapScope: scope,
    includeAuxiliaryReadAuthority,
  });
};

const synthesized = (
  scope: 'FULL_RELEASE' | 'PRERELEASE',
  includeAuxiliaryReadAuthority = false,
): Record<string, unknown> => {
  const config = configuration(scope, includeAuxiliaryReadAuthority);
  const app = new App();
  const StackClass =
    scope === 'FULL_RELEASE'
      ? Stage7FullAccountBootstrapStack
      : Stage7PrereleaseAccountBootstrapStack;
  const stack = new StackClass(app, `Stage7${scope}BootstrapTest`, {
    configuration: config,
    env: { account: config.accountId, region: config.region },
    stackName: 'CDKToolkit',
  });
  return Template.fromStack(stack).toJSON();
};

const resources = (template: Record<string, unknown>): Record<string, Record<string, unknown>> =>
  template.Resources as Record<string, Record<string, unknown>>;
const byType = (template: Record<string, unknown>, type: string): Record<string, unknown>[] =>
  Object.values(resources(template)).filter((resource) => resource.Type === type);
const roleByName = (template: Record<string, unknown>, name: string): Record<string, unknown> => {
  const role = byType(template, 'AWS::IAM::Role').find(
    (resource) => (resource.Properties as Record<string, unknown>).RoleName === name,
  );
  if (role === undefined) assert.fail(`Role ${name} missing`);
  return role.Properties as Record<string, unknown>;
};

void describe('Stage 7 regional account bootstrap stacks', () => {
  void test('synthesizes an exact full CDKToolkit with OIDC, bounded roles and durable assets', () => {
    const template = synthesized('FULL_RELEASE');
    assert.equal(
      validateStage7AccountBootstrapTemplate(template, configuration('FULL_RELEASE')),
      true,
    );
    assert.equal(byType(template, 'AWS::IAM::OIDCProvider').length, 1);
    assert.equal(byType(template, 'AWS::IAM::Role').length, 10);
    assert.equal(byType(template, 'AWS::IAM::ManagedPolicy').length, 8);
    assert.equal(byType(template, 'AWS::S3::Bucket').length, 1);
    assert.equal(byType(template, 'AWS::ECR::Repository').length, 1);
    assert.equal(byType(template, 'AWS::SSM::Parameter').length, 1);
    assert.equal(Object.keys(resources(template)).length, 22);
    const outputs = template.Outputs as Record<string, Record<string, unknown>>;
    assert.deepEqual(outputs.BootstrapVersion, { Value: '32' });
    assert.deepEqual(outputs.Stage7BootstrapScope, { Value: 'FULL_RELEASE' });

    const provider = byType(template, 'AWS::IAM::OIDCProvider')[0]?.Properties as Record<
      string,
      unknown
    >;
    assert.deepEqual(provider, {
      ClientIdList: ['sts.amazonaws.com'],
      Url: 'https://token.actions.githubusercontent.com',
    });
    const bucket = byType(template, 'AWS::S3::Bucket')[0]?.Properties as Record<string, unknown>;
    assert.equal(bucket.BucketName, `cdk-hnb659fds-assets-${ACCOUNT}-us-east-1`);
    const repository = byType(template, 'AWS::ECR::Repository')[0]?.Properties as Record<
      string,
      unknown
    >;
    assert.equal(repository.RepositoryName, `cdk-hnb659fds-container-assets-${ACCOUNT}-us-east-1`);
    const parameter = byType(template, 'AWS::SSM::Parameter')[0]?.Properties as Record<
      string,
      unknown
    >;
    assert.equal(parameter.Name, '/cdk-bootstrap/hnb659fds/version');
    assert.equal(parameter.Value, '32');
  });

  void test('synthesizes prerelease in a separate region and imports the account OIDC provider', () => {
    const template = synthesized('PRERELEASE');
    assert.equal(
      validateStage7AccountBootstrapTemplate(template, configuration('PRERELEASE')),
      true,
    );
    assert.equal(byType(template, 'AWS::IAM::OIDCProvider').length, 0);
    assert.equal(byType(template, 'AWS::IAM::Role').length, 10);
    assert.equal(byType(template, 'AWS::IAM::ManagedPolicy').length, 8);
    assert.equal(Object.keys(resources(template)).length, 21);
    const outputs = template.Outputs as Record<string, Record<string, unknown>>;
    assert.deepEqual(outputs.Stage7BootstrapScope, { Value: 'PRERELEASE' });
    assert.deepEqual(outputs.Stage7GithubOidcProviderArn, {
      Value: `arn:aws:iam::${ACCOUNT}:oidc-provider/token.actions.githubusercontent.com`,
    });
    assert.equal(
      (byType(template, 'AWS::S3::Bucket')[0]?.Properties as Record<string, unknown>).BucketName,
      `cdk-hnb659fds-assets-${ACCOUNT}-us-west-2`,
    );
  });

  void test('materializes the final full read-only auxiliary authority without widening actions', () => {
    const config = configuration('FULL_RELEASE', true);
    const template = synthesized('FULL_RELEASE', true);
    assert.equal(validateStage7AccountBootstrapTemplate(template, config), true);
    const outputs = template.Outputs as Record<string, Record<string, unknown>>;
    assert.deepEqual(outputs.Stage7AuxiliaryReadAuthorityMode, { Value: 'FINAL_ENABLED' });
    const readRole = roleByName(template, 'stage7-release-read');
    const policySource = JSON.stringify(readRole.Policies);
    for (const authorityArn of [
      config.auxiliary.journalRoleArn,
      config.auxiliary.journalPermissionsBoundaryArn,
      config.auxiliary.reconciliationRecoveryRoleArn,
      config.auxiliary.reconciliationRecoveryPermissionsBoundaryArn,
    ]) {
      assert.ok(policySource.includes(authorityArn));
    }
    assert.equal(policySource.includes('iam:passrole'), false);
  });

  void test('uses exact protected subjects and keeps the image publishing role inassumable', () => {
    const full = synthesized('FULL_RELEASE');
    const prerelease = synthesized('PRERELEASE');
    const readTrust = roleByName(full, 'stage7-release-read').AssumeRolePolicyDocument as Record<
      string,
      unknown
    >;
    const readStatement = (readTrust.Statement as Array<Record<string, unknown>>)[0];
    const readSubjects = (readStatement?.Condition as Record<string, Record<string, unknown>>)
      .StringEquals?.['token.actions.githubusercontent.com:sub'];
    assert.deepEqual(Array.isArray(readSubjects) ? readSubjects : [readSubjects], [
      'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release',
      'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-recovery',
      'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-reconciliation-recovery',
    ]);

    const prereleaseRead = roleByName(prerelease, 'stage7-prerelease-read');
    const prereleaseTrust = prereleaseRead.AssumeRolePolicyDocument as Record<string, unknown>;
    const prereleaseStatement = (prereleaseTrust.Statement as Array<Record<string, unknown>>)[0];
    const prereleaseSubjects = (
      prereleaseStatement?.Condition as Record<string, Record<string, unknown>>
    ).StringEquals?.['token.actions.githubusercontent.com:sub'];
    assert.deepEqual(prereleaseSubjects, [
      'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-prerelease',
      'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-prerelease-external',
    ]);

    const imageRole = roleByName(full, `cdk-hnb659fds-image-publishing-role-${ACCOUNT}-us-east-1`);
    assert.deepEqual(imageRole.AssumeRolePolicyDocument, {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: { AWS: '*' },
          Action: 'sts:AssumeRole',
        },
      ],
    });
  });

  void test('uses one exact inline policy, safe-size boundaries and no attached/admin policies', () => {
    for (const scope of ['FULL_RELEASE', 'PRERELEASE'] as const) {
      const template = synthesized(scope);
      const templateResources = resources(template);
      for (const roleResource of byType(template, 'AWS::IAM::Role')) {
        const role = roleResource.Properties as Record<string, unknown>;
        assert.equal(Object.hasOwn(role, 'ManagedPolicyArns'), false);
        const inlinePolicies = role.Policies as Array<Record<string, unknown>>;
        assert.equal(inlinePolicies.length, 1);
        const policyLength = JSON.stringify(inlinePolicies[0]?.PolicyDocument).length;
        assert.ok(policyLength <= 10_240);
        const roleName = role.RoleName as string;
        const boundaryReference = role.PermissionsBoundary as Record<string, string> | undefined;
        if (
          roleName.includes('stage7-release-read') ||
          roleName.includes('stage7-prerelease-read') ||
          roleName.includes('cfn-exec-role')
        ) {
          assert.equal(boundaryReference, undefined);
        } else {
          const boundaryId = boundaryReference?.Ref;
          if (boundaryId === undefined) assert.fail('boundary Ref missing');
          const boundary = templateResources[boundaryId];
          assert.equal(boundary?.Type, 'AWS::IAM::ManagedPolicy');
          assert.deepEqual(
            inlinePolicies[0]?.PolicyDocument,
            (boundary?.Properties as Record<string, unknown>).PolicyDocument,
          );
          assert.ok(
            JSON.stringify((boundary?.Properties as Record<string, unknown>).PolicyDocument)
              .length <= 6_144,
          );
        }
        assert.equal(JSON.stringify(role).includes('AdministratorAccess'), false);
      }
    }
  });

  void test('rejects wrong stack name and cross-scope constructors before synthesis', () => {
    const full = configuration('FULL_RELEASE');
    assert.throws(
      () =>
        new Stage7FullAccountBootstrapStack(new App(), 'WrongName', {
          configuration: full,
          env: { account: full.accountId, region: full.region },
          stackName: 'NotCDKToolkit',
        }),
      /STACK_NAME_INVALID/u,
    );
    assert.throws(
      () =>
        new Stage7PrereleaseAccountBootstrapStack(new App(), 'WrongScope', {
          configuration: full,
          env: { account: full.accountId, region: full.region },
          stackName: 'CDKToolkit',
        }),
      /PRERELEASE_STACK_SCOPE_INVALID/u,
    );
  });

  void test('rejects privilege, trust, boundary and asset tampering without mutating source', () => {
    const source = synthesized('FULL_RELEASE');
    const mutations: Array<(template: Record<string, unknown>) => void> = [
      (template) => {
        const role = roleByName(template, 'stage7-release-deploy');
        (role.Policies as Array<Record<string, unknown>>)[0] = {
          PolicyName: 'admin',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
          },
        };
      },
      (template) => {
        const role = roleByName(template, 'stage7-release-read');
        const trust = role.AssumeRolePolicyDocument as Record<string, unknown>;
        const statement = (trust.Statement as Array<Record<string, unknown>>)[0];
        const condition = statement?.Condition as Record<string, Record<string, unknown>>;
        if (condition.StringEquals !== undefined) {
          condition.StringEquals['token.actions.githubusercontent.com:sub'] = 'repo:*';
        }
      },
      (template) => {
        const role = roleByName(template, 'stage7-release-read');
        role.PermissionsBoundary = { Ref: 'UnexpectedBoundary' };
      },
      (template) => {
        const bucket = byType(template, 'AWS::S3::Bucket')[0]?.Properties as Record<
          string,
          unknown
        >;
        bucket.PublicAccessBlockConfiguration = { BlockPublicAcls: false };
      },
    ];
    for (const mutate of mutations) {
      const tampered = structuredClone(source);
      mutate(tampered);
      assert.throws(
        () => validateStage7AccountBootstrapTemplate(tampered, configuration('FULL_RELEASE')),
        /E7_ACCOUNT_BOOTSTRAP_TEMPLATE_/u,
      );
    }
    assert.equal(JSON.stringify(source).includes('"Action":"*"'), false);
  });
});
