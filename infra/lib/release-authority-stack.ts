import { CfnOutput, Stack } from 'aws-cdk-lib';
import type { StackProps } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import type { Construct } from 'constructs';

// These JavaScript modules are the frozen product contracts. Keeping the imports here makes
// synthesis fail closed if IaC drifts from the runtime authority validators.
// @ts-expect-error The product contract is an ESM JavaScript module without TypeScript declarations.
import * as recoveryContractModule from '../../scripts/stage7/release-reconciliation-recovery.mjs';
// @ts-expect-error The product contract is an ESM JavaScript module without TypeScript declarations.
import * as journalContractModule from '../../scripts/stage7/release-successor-iam-authority.mjs';

import {
  STAGE7_AUTHORITY_ROLE_PATH,
  STAGE7_GITHUB_OIDC_HOST,
  STAGE7_GITHUB_REPOSITORY,
  STAGE7_JOURNAL_BOUNDARY_NAME,
  STAGE7_JOURNAL_ROLE_NAME,
  STAGE7_RECOVERY_BOUNDARY_NAME,
  STAGE7_RECOVERY_ROLE_NAME,
} from './release-authority-config';
import type { ReleaseAuthorityConfig } from './release-authority-config';

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

interface IamTrustStatement {
  readonly Effect: 'Allow';
  readonly Principal: Readonly<{ Federated: string }>;
  readonly Action: 'sts:AssumeRoleWithWebIdentity';
  readonly Condition: Readonly<{
    StringEquals: Readonly<Record<string, string | readonly string[]>>;
  }>;
}

interface IamTrustPolicyDocument {
  readonly Version: '2012-10-17';
  readonly Statement: readonly IamTrustStatement[];
}

interface JournalContractCapture {
  readonly value: {
    readonly role: { readonly trustPolicy: IamTrustPolicyDocument };
    readonly inlinePolicies: readonly [{ readonly policyDocument: IamPolicyDocument }];
    readonly permissionsBoundary: { readonly policyDocument: IamPolicyDocument };
  };
}

interface JournalContractApi {
  readonly createReleaseJournalRoleEffectivePermissions: (input: {
    readonly expectedRoleArn: string;
    readonly expectedPermissionsBoundaryArn: string;
    readonly awsRegion: string;
    readonly rawSources: Readonly<Record<string, unknown>>;
  }) => JournalContractCapture;
}

interface RecoveryContractApi {
  readonly createReleaseReconciliationRecoveryTrustPolicy: (
    accountId: string,
  ) => IamTrustPolicyDocument;
  readonly createReleaseReconciliationRecoveryBasePolicy: (input: {
    readonly accountId: string;
    readonly awsRegion: string;
    readonly recoveryRoleArn: string;
    readonly permissionsBoundaryArn: string;
  }) => IamPolicyDocument;
}

const journalContract = journalContractModule as unknown as JournalContractApi;
const recoveryContract = recoveryContractModule as unknown as RecoveryContractApi;

const jsonBytes = (value: unknown): Buffer => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
const exactKeys = (value: unknown, keys: readonly string[]): boolean =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
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
const fail = (code: string): never => {
  throw new Error(code);
};

export const STAGE7_JOURNAL_OIDC_SUBJECTS = Object.freeze([
  `repo:${STAGE7_GITHUB_REPOSITORY}:environment:assessment-release`,
  `repo:${STAGE7_GITHUB_REPOSITORY}:environment:assessment-release-reconciliation-recovery`,
  `repo:${STAGE7_GITHUB_REPOSITORY}:environment:assessment-release-successor-post-success`,
]);
export const STAGE7_RECOVERY_OIDC_SUBJECT = `repo:${STAGE7_GITHUB_REPOSITORY}:environment:assessment-release-reconciliation-recovery`;

const journalTrustCandidate = (config: ReleaseAuthorityConfig): IamTrustPolicyDocument => ({
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Principal: { Federated: config.oidcProviderArn },
      Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: {
        StringEquals: {
          [`${STAGE7_GITHUB_OIDC_HOST}:aud`]: 'sts.amazonaws.com',
          [`${STAGE7_GITHUB_OIDC_HOST}:sub`]: STAGE7_JOURNAL_OIDC_SUBJECTS,
        },
      },
    },
  ],
});

const journalPolicyCandidate = (config: ReleaseAuthorityConfig): IamPolicyDocument => {
  const root = (name: string): string =>
    `arn:aws:ssm:${config.region}:${config.accountId}:parameter/checkout/stage7/${name}/*`;
  const finalization = root('release-finalization');
  const fence = root('release-fence');
  const rollback = root('rollback');
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AuditBoundary',
        Effect: 'Allow',
        Action: ['iam:GetPolicy', 'iam:GetPolicyVersion'],
        Resource: config.journalPermissionsBoundaryArn,
      },
      {
        Sid: 'AuditSelfRole',
        Effect: 'Allow',
        Action: [
          'iam:GetRole',
          'iam:GetRolePolicy',
          'iam:ListAttachedRolePolicies',
          'iam:ListRolePolicies',
        ],
        Resource: config.journalRoleArn,
      },
      {
        Sid: 'DeleteRollbackJournal',
        Effect: 'Allow',
        Action: 'ssm:DeleteParameter',
        Resource: rollback,
      },
      {
        Sid: 'ReadExactParameters',
        Effect: 'Allow',
        Action: 'ssm:GetParameter',
        Resource: [finalization, fence, rollback].toSorted(),
      },
      {
        Sid: 'ListRollbackJournal',
        Effect: 'Allow',
        Action: 'ssm:GetParametersByPath',
        Resource: rollback,
      },
      {
        Sid: 'WriteImmutableParameters',
        Effect: 'Allow',
        Action: 'ssm:PutParameter',
        Resource: [finalization, fence, rollback].toSorted(),
        Condition: { StringEquals: { 'ssm:Overwrite': 'false' } },
      },
      {
        Sid: 'ReadCallerIdentity',
        Effect: 'Allow',
        Action: 'sts:GetCallerIdentity',
        Resource: '*',
      },
    ],
  };
};

const validatedJournalAuthority = (
  config: ReleaseAuthorityConfig,
): {
  readonly trustPolicy: IamTrustPolicyDocument;
  readonly policyDocument: IamPolicyDocument;
} => {
  const trustPolicy = journalTrustCandidate(config);
  const policyDocument = journalPolicyCandidate(config);
  const roleName = config.journalRoleArn.split('/').at(-1) ?? '';
  const boundaryName = config.journalPermissionsBoundaryArn.split('/').at(-1) ?? '';
  const rawSources = {
    getRoleSource: jsonBytes({
      Role: {
        Path: STAGE7_AUTHORITY_ROLE_PATH,
        RoleName: roleName,
        RoleId: 'AROAOFFLINEAUTHORITY1',
        Arn: config.journalRoleArn,
        CreateDate: '2026-08-18T00:00:00.000Z',
        MaxSessionDuration: 3600,
        AssumeRolePolicyDocument: trustPolicy,
        PermissionsBoundary: {
          PermissionsBoundaryType: 'Policy',
          PermissionsBoundaryArn: config.journalPermissionsBoundaryArn,
        },
      },
    }),
    listRolePoliciesPages: [
      { requestToken: null, source: jsonBytes({ PolicyNames: ['stage7-release-journal'] }) },
    ],
    getRolePolicySources: [
      {
        policyName: 'stage7-release-journal',
        source: jsonBytes({
          RoleName: roleName,
          PolicyName: 'stage7-release-journal',
          PolicyDocument: policyDocument,
        }),
      },
    ],
    listAttachedRolePoliciesPages: [
      { requestToken: null, source: jsonBytes({ AttachedPolicies: [] }) },
    ],
    getPolicySources: [
      {
        policyArn: config.journalPermissionsBoundaryArn,
        source: jsonBytes({
          Policy: {
            PolicyName: boundaryName,
            Arn: config.journalPermissionsBoundaryArn,
            DefaultVersionId: 'v1',
          },
        }),
      },
    ],
    getPolicyVersionSources: [
      {
        policyArn: config.journalPermissionsBoundaryArn,
        source: jsonBytes({
          PolicyVersion: {
            Document: encodeURIComponent(JSON.stringify(policyDocument)),
            VersionId: 'v1',
            IsDefaultVersion: true,
          },
        }),
      },
    ],
  };
  const capture = journalContract.createReleaseJournalRoleEffectivePermissions({
    expectedRoleArn: config.journalRoleArn,
    expectedPermissionsBoundaryArn: config.journalPermissionsBoundaryArn,
    awsRegion: config.region,
    rawSources,
  });
  if (
    !same(capture.value.role.trustPolicy, trustPolicy) ||
    !same(
      capture.value.inlinePolicies[0].policyDocument,
      capture.value.permissionsBoundary.policyDocument,
    )
  ) {
    fail('E7_RELEASE_AUTHORITY_JOURNAL_PRODUCT_CONTRACT_MISMATCH');
  }
  return {
    trustPolicy: capture.value.role.trustPolicy,
    policyDocument: capture.value.inlinePolicies[0].policyDocument,
  };
};

const recoveryAuthority = (
  config: ReleaseAuthorityConfig,
): {
  readonly trustPolicy: IamTrustPolicyDocument;
  readonly policyDocument: IamPolicyDocument;
} => ({
  trustPolicy: recoveryContract.createReleaseReconciliationRecoveryTrustPolicy(config.accountId),
  policyDocument: recoveryContract.createReleaseReconciliationRecoveryBasePolicy({
    accountId: config.accountId,
    awsRegion: config.region,
    recoveryRoleArn: config.reconciliationRecoveryRoleArn,
    permissionsBoundaryArn: config.reconciliationRecoveryPermissionsBoundaryArn,
  }),
});

const readRolePolicy = (config: ReleaseAuthorityConfig): IamPolicyDocument => ({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'AuditExactStage7AuxiliaryRoles',
      Effect: 'Allow',
      Action: [
        'iam:GetRole',
        'iam:GetRolePolicy',
        'iam:ListAttachedRolePolicies',
        'iam:ListRolePolicies',
      ],
      Resource: [config.journalRoleArn, config.reconciliationRecoveryRoleArn].toSorted(),
    },
    {
      Sid: 'AuditExactStage7AuxiliaryBoundaries',
      Effect: 'Allow',
      Action: ['iam:GetPolicy', 'iam:GetPolicyVersion'],
      Resource: [
        config.journalPermissionsBoundaryArn,
        config.reconciliationRecoveryPermissionsBoundaryArn,
      ].toSorted(),
    },
  ],
});

export interface ReleaseAuthorityStackProps extends StackProps {
  readonly configuration: ReleaseAuthorityConfig;
}

export class ReleaseAuthorityStack extends Stack {
  public constructor(scope: Construct, id: string, props: ReleaseAuthorityStackProps) {
    super(scope, id, props);
    const config = props.configuration;
    if (this.account !== config.accountId || this.region !== config.region) {
      fail('E7_RELEASE_AUTHORITY_STACK_ENVIRONMENT_MISMATCH');
    }

    const journal = validatedJournalAuthority(config);
    const recovery = recoveryAuthority(config);
    const journalBoundary = new iam.CfnManagedPolicy(this, 'JournalPermissionsBoundary', {
      description: 'Exact Stage 7 release journal and successor finalization permissions boundary',
      managedPolicyName: STAGE7_JOURNAL_BOUNDARY_NAME,
      policyDocument: journal.policyDocument,
    });
    const recoveryBoundary = new iam.CfnManagedPolicy(this, 'RecoveryPermissionsBoundary', {
      description: 'Exact Stage 7 reconciliation recovery BASE permissions boundary',
      managedPolicyName: STAGE7_RECOVERY_BOUNDARY_NAME,
      policyDocument: recovery.policyDocument,
    });
    new iam.CfnRole(this, 'JournalRole', {
      assumeRolePolicyDocument: journal.trustPolicy,
      description: 'Stage 7 immutable reconciliation journal and post-success cleanup authority',
      maxSessionDuration: 3600,
      path: STAGE7_AUTHORITY_ROLE_PATH,
      permissionsBoundary: journalBoundary.ref,
      policies: [
        {
          policyName: 'stage7-release-journal',
          policyDocument: journal.policyDocument,
        },
      ],
      roleName: STAGE7_JOURNAL_ROLE_NAME,
    });
    new iam.CfnRole(this, 'RecoveryRole', {
      assumeRolePolicyDocument: recovery.trustPolicy,
      description: 'Stage 7 protected forward-only reconciliation recovery BASE authority',
      maxSessionDuration: 3600,
      path: STAGE7_AUTHORITY_ROLE_PATH,
      permissionsBoundary: recoveryBoundary.ref,
      policies: [
        {
          policyName: 'stage7-release-reconciliation-recovery',
          policyDocument: recovery.policyDocument,
        },
      ],
      roleName: STAGE7_RECOVERY_ROLE_NAME,
    });
    new iam.CfnRolePolicy(this, 'ReadRoleAuxiliaryAuthorityAudit', {
      policyDocument: readRolePolicy(config),
      policyName: 'stage7-read-exact-auxiliary-role-authorities',
      roleName: config.readRoleName,
    });

    new CfnOutput(this, 'Stage7ReleaseJournalCleanupRoleArn', {
      value: config.journalRoleArn,
    });
    new CfnOutput(this, 'Stage7ReleaseJournalCleanupPermissionsBoundaryArn', {
      value: config.journalPermissionsBoundaryArn,
    });
    new CfnOutput(this, 'Stage7ReleaseReconciliationRecoveryRoleArn', {
      value: config.reconciliationRecoveryRoleArn,
    });
    new CfnOutput(this, 'Stage7ReleaseReconciliationRecoveryPermissionsBoundaryArn', {
      value: config.reconciliationRecoveryPermissionsBoundaryArn,
    });
  }
}

interface CloudFormationResource {
  readonly Type?: unknown;
  readonly Properties?: unknown;
}

const record = (value: unknown): Record<string, unknown> => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('E7_RELEASE_AUTHORITY_TEMPLATE_INVALID');
  }
  return value as Record<string, unknown>;
};
const resourceEntries = (
  template: Record<string, unknown>,
): Array<[string, CloudFormationResource]> =>
  Object.entries(record(template.Resources)) as Array<[string, CloudFormationResource]>;
const oneBy = (
  entries: readonly [string, CloudFormationResource][],
  type: string,
  property: string,
  expected: string,
): [string, Record<string, unknown>] => {
  const matching = entries.filter(
    ([, resource]) => resource.Type === type && record(resource.Properties)[property] === expected,
  );
  if (matching.length !== 1) fail('E7_RELEASE_AUTHORITY_TEMPLATE_RESOURCE_SET_INVALID');
  return [matching[0]?.[0] ?? '', record(matching[0]?.[1].Properties)];
};

export const validateReleaseAuthorityTemplate = (
  source: unknown,
  config: ReleaseAuthorityConfig,
): true => {
  const template = record(source);
  const entries = resourceEntries(template);
  if (
    entries.length !== 5 ||
    entries.filter(([, resource]) => resource.Type === 'AWS::IAM::Role').length !== 2 ||
    entries.filter(([, resource]) => resource.Type === 'AWS::IAM::ManagedPolicy').length !== 2 ||
    entries.filter(([, resource]) => resource.Type === 'AWS::IAM::RolePolicy').length !== 1 ||
    entries.some(
      ([, resource]) =>
        !['AWS::IAM::Role', 'AWS::IAM::ManagedPolicy', 'AWS::IAM::RolePolicy'].includes(
          String(resource.Type),
        ),
    )
  ) {
    fail('E7_RELEASE_AUTHORITY_TEMPLATE_RESOURCE_SET_INVALID');
  }
  const journal = validatedJournalAuthority(config);
  const recovery = recoveryAuthority(config);
  const readPolicy = readRolePolicy(config);
  const [journalBoundaryId, journalBoundary] = oneBy(
    entries,
    'AWS::IAM::ManagedPolicy',
    'ManagedPolicyName',
    STAGE7_JOURNAL_BOUNDARY_NAME,
  );
  const [recoveryBoundaryId, recoveryBoundary] = oneBy(
    entries,
    'AWS::IAM::ManagedPolicy',
    'ManagedPolicyName',
    STAGE7_RECOVERY_BOUNDARY_NAME,
  );
  if (
    !exactKeys(journalBoundary, ['Description', 'ManagedPolicyName', 'PolicyDocument']) ||
    !same(journalBoundary.PolicyDocument, journal.policyDocument) ||
    !exactKeys(recoveryBoundary, ['Description', 'ManagedPolicyName', 'PolicyDocument']) ||
    !same(recoveryBoundary.PolicyDocument, recovery.policyDocument)
  ) {
    fail('E7_RELEASE_AUTHORITY_TEMPLATE_BOUNDARY_INVALID');
  }
  const [, journalRole] = oneBy(entries, 'AWS::IAM::Role', 'RoleName', STAGE7_JOURNAL_ROLE_NAME);
  const [, recoveryRole] = oneBy(entries, 'AWS::IAM::Role', 'RoleName', STAGE7_RECOVERY_ROLE_NAME);
  const validateRole = (
    role: Record<string, unknown>,
    expectedTrust: IamTrustPolicyDocument,
    expectedPolicy: IamPolicyDocument,
    expectedPolicyName: string,
    boundaryId: string,
  ): void => {
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
      role.Path !== STAGE7_AUTHORITY_ROLE_PATH ||
      role.MaxSessionDuration !== 3600 ||
      !same(role.AssumeRolePolicyDocument, expectedTrust) ||
      !same(role.PermissionsBoundary, { Ref: boundaryId }) ||
      !Array.isArray(policies) ||
      policies.length !== 1
    ) {
      fail('E7_RELEASE_AUTHORITY_TEMPLATE_ROLE_INVALID');
    }
    const policy = record((policies as unknown[])[0]);
    if (
      !exactKeys(policy, ['PolicyDocument', 'PolicyName']) ||
      policy.PolicyName !== expectedPolicyName ||
      !same(policy.PolicyDocument, expectedPolicy)
    ) {
      fail('E7_RELEASE_AUTHORITY_TEMPLATE_ROLE_INVALID');
    }
  };
  validateRole(
    journalRole,
    journal.trustPolicy,
    journal.policyDocument,
    'stage7-release-journal',
    journalBoundaryId,
  );
  validateRole(
    recoveryRole,
    recovery.trustPolicy,
    recovery.policyDocument,
    'stage7-release-reconciliation-recovery',
    recoveryBoundaryId,
  );
  const readPolicies = entries.filter(([, resource]) => resource.Type === 'AWS::IAM::RolePolicy');
  const readRolePolicyProperties = record(readPolicies[0]?.[1].Properties);
  if (
    !exactKeys(readRolePolicyProperties, ['PolicyDocument', 'PolicyName', 'RoleName']) ||
    readRolePolicyProperties.RoleName !== config.readRoleName ||
    readRolePolicyProperties.PolicyName !== 'stage7-read-exact-auxiliary-role-authorities' ||
    !same(readRolePolicyProperties.PolicyDocument, readPolicy) ||
    canonical(readRolePolicyProperties.PolicyDocument).includes('iam:PassRole') ||
    canonical(readRolePolicyProperties.PolicyDocument).includes('sts:AssumeRole') ||
    canonical(readRolePolicyProperties.PolicyDocument).includes('"Resource":"*"')
  ) {
    fail('E7_RELEASE_AUTHORITY_TEMPLATE_READ_ROLE_POLICY_INVALID');
  }
  const outputs = record(template.Outputs);
  const expectedOutputs = {
    Stage7ReleaseJournalCleanupRoleArn: { Value: config.journalRoleArn },
    Stage7ReleaseJournalCleanupPermissionsBoundaryArn: {
      Value: config.journalPermissionsBoundaryArn,
    },
    Stage7ReleaseReconciliationRecoveryRoleArn: {
      Value: config.reconciliationRecoveryRoleArn,
    },
    Stage7ReleaseReconciliationRecoveryPermissionsBoundaryArn: {
      Value: config.reconciliationRecoveryPermissionsBoundaryArn,
    },
  };
  if (!same(outputs, expectedOutputs)) {
    fail('E7_RELEASE_AUTHORITY_TEMPLATE_OUTPUT_SET_INVALID');
  }
  return true;
};
