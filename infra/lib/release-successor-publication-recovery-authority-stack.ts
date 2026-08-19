import { CfnOutput, Stack } from 'aws-cdk-lib';
import type { StackProps } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import type { Construct } from 'constructs';

// This frozen product module is the sole authority for trust and BASE policy bytes.
// @ts-expect-error The product contract is an ESM JavaScript module without declarations.
import * as recoveryContractModule from '../../scripts/stage7/release-successor-publication-recovery-contract.mjs';

import {
  STAGE7_PUBLICATION_RECOVERY_BOUNDARY_NAME,
  STAGE7_PUBLICATION_RECOVERY_ENVIRONMENT,
  STAGE7_PUBLICATION_RECOVERY_REPOSITORY,
  STAGE7_PUBLICATION_RECOVERY_ROLE_NAME,
  STAGE7_PUBLICATION_RECOVERY_ROLE_PATH,
} from './release-successor-publication-recovery-authority-config';
import type { ReleaseSuccessorPublicationRecoveryAuthorityConfig } from './release-successor-publication-recovery-authority-config';

interface IamStatement {
  readonly Sid?: string;
  readonly Effect: 'Allow' | 'Deny';
  readonly Action: string | readonly string[];
  readonly Resource: string | readonly string[];
  readonly Condition?: Readonly<Record<string, Readonly<Record<string, string>>>>;
}

interface IamPolicyDocument {
  readonly Version: '2012-10-17';
  readonly Statement: readonly IamStatement[];
}

interface IamTrustPolicyDocument {
  readonly Version: '2012-10-17';
  readonly Statement: readonly {
    readonly Sid: string;
    readonly Effect: 'Allow';
    readonly Principal: Readonly<{ Federated: string }>;
    readonly Action: 'sts:AssumeRoleWithWebIdentity';
    readonly Condition: Readonly<{
      StringEquals: Readonly<Record<string, string>>;
    }>;
  }[];
}

interface RecoveryContractApi {
  readonly RECOVERY_ENVIRONMENT: string;
  readonly RECOVERY_REPOSITORY: string;
  readonly RECOVERY_ROLE_INLINE_POLICY_NAME: string;
  readonly expectedRecoveryTrustPolicy: (input: {
    readonly awsAccountId: string;
  }) => IamTrustPolicyDocument;
  readonly expectedRecoveryBoundaryPolicy: (input: {
    readonly awsAccountId: string;
    readonly awsRegion: string;
    readonly recoveryRoleArn: string;
    readonly permissionsBoundaryArn: string;
  }) => IamPolicyDocument;
}

const recoveryContract = recoveryContractModule as unknown as RecoveryContractApi;
const fail = (code: string): never => {
  throw new Error(code);
};
const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map((entry) => canonical(entry)).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value)
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
};
const same = (left: unknown, right: unknown): boolean => canonical(left) === canonical(right);
const record = (value: unknown): Record<string, unknown> => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_INVALID');
  }
  return value as Record<string, unknown>;
};
const exactKeys = (value: unknown, keys: readonly string[]): boolean =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');

const authorityDocuments = (
  config: ReleaseSuccessorPublicationRecoveryAuthorityConfig,
): {
  readonly trustPolicy: IamTrustPolicyDocument;
  readonly basePolicy: IamPolicyDocument;
} => {
  if (
    recoveryContract.RECOVERY_REPOSITORY !== STAGE7_PUBLICATION_RECOVERY_REPOSITORY ||
    recoveryContract.RECOVERY_ENVIRONMENT !== STAGE7_PUBLICATION_RECOVERY_ENVIRONMENT ||
    recoveryContract.RECOVERY_ROLE_INLINE_POLICY_NAME.length === 0 ||
    config.repository !== recoveryContract.RECOVERY_REPOSITORY ||
    config.protectedEnvironment !== recoveryContract.RECOVERY_ENVIRONMENT
  ) {
    fail('E7_PUBLICATION_RECOVERY_IAC_PRODUCT_CONTRACT_MISMATCH');
  }
  return {
    trustPolicy: recoveryContract.expectedRecoveryTrustPolicy({
      awsAccountId: config.accountId,
    }),
    basePolicy: recoveryContract.expectedRecoveryBoundaryPolicy({
      awsAccountId: config.accountId,
      awsRegion: config.region,
      recoveryRoleArn: config.roleArn,
      permissionsBoundaryArn: config.permissionsBoundaryArn,
    }),
  };
};

export interface ReleaseSuccessorPublicationRecoveryAuthorityStackProps extends StackProps {
  readonly configuration: ReleaseSuccessorPublicationRecoveryAuthorityConfig;
}

export class ReleaseSuccessorPublicationRecoveryAuthorityStack extends Stack {
  public constructor(
    scope: Construct,
    id: string,
    props: ReleaseSuccessorPublicationRecoveryAuthorityStackProps,
  ) {
    super(scope, id, { ...props, analyticsReporting: false });
    const config = props.configuration;
    if (this.account !== config.accountId || this.region !== config.region) {
      fail('E7_PUBLICATION_RECOVERY_IAC_STACK_ENVIRONMENT_MISMATCH');
    }
    const { trustPolicy, basePolicy } = authorityDocuments(config);
    const boundary = new iam.CfnManagedPolicy(this, 'PermissionsBoundary', {
      description: 'Exact Stage 7 release-successor publication recovery BASE boundary',
      managedPolicyName: STAGE7_PUBLICATION_RECOVERY_BOUNDARY_NAME,
      policyDocument: basePolicy,
    });
    new iam.CfnRole(this, 'RecoveryRole', {
      assumeRolePolicyDocument: trustPolicy,
      description: 'Stage 7 protected release-successor publication recovery authority',
      maxSessionDuration: 3600,
      path: STAGE7_PUBLICATION_RECOVERY_ROLE_PATH,
      permissionsBoundary: boundary.ref,
      policies: [
        {
          policyName: recoveryContract.RECOVERY_ROLE_INLINE_POLICY_NAME,
          policyDocument: basePolicy,
        },
      ],
      roleName: STAGE7_PUBLICATION_RECOVERY_ROLE_NAME,
    });

    new CfnOutput(this, 'Stage7ReleaseSuccessorPublicationRecoveryRoleArn', {
      value: config.roleArn,
    });
    new CfnOutput(this, 'Stage7ReleaseSuccessorPublicationRecoveryPermissionsBoundaryArn', {
      value: config.permissionsBoundaryArn,
    });
  }
}

interface CloudFormationResource {
  readonly Type?: unknown;
  readonly Properties?: unknown;
}

const resourceEntries = (
  template: Record<string, unknown>,
): Array<[string, CloudFormationResource]> =>
  Object.entries(record(template.Resources)) as Array<[string, CloudFormationResource]>;

export const validateReleaseSuccessorPublicationRecoveryAuthorityTemplate = (
  source: unknown,
  config: ReleaseSuccessorPublicationRecoveryAuthorityConfig,
): true => {
  const template = record(source);
  const entries = resourceEntries(template);
  const parameters = Object.hasOwn(template, 'Parameters') ? record(template.Parameters) : {};
  const rules = Object.hasOwn(template, 'Rules') ? record(template.Rules) : {};
  const dynamicSessionMarkers = canonical({ parameters, rules });
  if (
    entries.length !== 2 ||
    entries.filter(([, resource]) => resource.Type === 'AWS::IAM::Role').length !== 1 ||
    entries.filter(([, resource]) => resource.Type === 'AWS::IAM::ManagedPolicy').length !== 1 ||
    entries.some(
      ([, resource]) =>
        !['AWS::IAM::Role', 'AWS::IAM::ManagedPolicy'].includes(String(resource.Type)),
    ) ||
    Object.keys(parameters).some((name) => name !== 'BootstrapVersion') ||
    Object.keys(rules).some((name) => name !== 'CheckBootstrapVersion') ||
    /candidateSha|candidate_sha|sourceRunId|source_run_id|SessionPolicy/iu.test(
      dynamicSessionMarkers,
    )
  ) {
    fail('E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_RESOURCE_SET_INVALID');
  }

  const { trustPolicy, basePolicy } = authorityDocuments(config);
  const boundaryEntry = entries.find(([, resource]) => resource.Type === 'AWS::IAM::ManagedPolicy');
  const roleEntry = entries.find(([, resource]) => resource.Type === 'AWS::IAM::Role');
  if (boundaryEntry === undefined || roleEntry === undefined) {
    throw new Error('E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_RESOURCE_SET_INVALID');
  }
  const [boundaryId, boundaryResource] = boundaryEntry;
  const boundary = record(boundaryResource.Properties);
  if (
    !exactKeys(boundary, ['Description', 'ManagedPolicyName', 'PolicyDocument']) ||
    boundary.ManagedPolicyName !== STAGE7_PUBLICATION_RECOVERY_BOUNDARY_NAME ||
    !same(boundary.PolicyDocument, basePolicy)
  ) {
    fail('E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_BOUNDARY_INVALID');
  }

  const role = record(roleEntry[1].Properties);
  const policies = role.Policies;
  if (
    !exactKeys(role, [
      'AssumeRolePolicyDocument',
      'Description',
      'MaxSessionDuration',
      'Path',
      'PermissionsBoundary',
      'Policies',
      'RoleName',
    ]) ||
    role.RoleName !== STAGE7_PUBLICATION_RECOVERY_ROLE_NAME ||
    role.Path !== STAGE7_PUBLICATION_RECOVERY_ROLE_PATH ||
    role.MaxSessionDuration !== 3600 ||
    !same(role.AssumeRolePolicyDocument, trustPolicy) ||
    !same(role.PermissionsBoundary, { Ref: boundaryId }) ||
    !Array.isArray(policies) ||
    policies.length !== 1
  ) {
    fail('E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_ROLE_INVALID');
  }
  const inlinePolicy = record((policies as unknown[])[0]);
  if (
    !exactKeys(inlinePolicy, ['PolicyDocument', 'PolicyName']) ||
    inlinePolicy.PolicyName !== recoveryContract.RECOVERY_ROLE_INLINE_POLICY_NAME ||
    !same(inlinePolicy.PolicyDocument, basePolicy) ||
    !same(inlinePolicy.PolicyDocument, boundary.PolicyDocument)
  ) {
    fail('E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_INLINE_POLICY_INVALID');
  }

  const outputs = record(template.Outputs);
  const expectedOutputs = {
    Stage7ReleaseSuccessorPublicationRecoveryRoleArn: { Value: config.roleArn },
    Stage7ReleaseSuccessorPublicationRecoveryPermissionsBoundaryArn: {
      Value: config.permissionsBoundaryArn,
    },
  };
  if (!same(outputs, expectedOutputs)) {
    fail('E7_PUBLICATION_RECOVERY_IAC_TEMPLATE_OUTPUT_SET_INVALID');
  }
  return true;
};
