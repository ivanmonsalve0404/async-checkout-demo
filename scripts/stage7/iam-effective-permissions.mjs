#!/usr/bin/env node
/* global structuredClone */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { hasUniqueIamRoleNames, parseIamRoleArn } from './core.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const IAM_POLICY_ARN =
  /^arn:aws:iam::(?:(aws)|([0-9]{12})):policy\/(?!\/)(?!.*\/\/)(?!.*\/$)([A-Za-z0-9+=,.@_/-]{1,512})$/u;
const POLICY_VERSION_ID = /^v[1-9][0-9]*(?:\.[A-Za-z0-9-]+)?$/u;
const POLICY_NAME = /^[\w+=,.@-]{1,128}$/u;
const ROLE_KEYS = Object.freeze([
  'readRoleArn',
  'deployRoleArn',
  'rollbackRoleArn',
  'cleanupRoleArn',
]);
const BOOTSTRAP_ROLE_KEYS = Object.freeze([
  'bootstrapDeployRoleArn',
  'bootstrapFilePublishingRoleArn',
  'bootstrapImagePublishingRoleArn',
  'bootstrapLookupRoleArn',
  'bootstrapCloudFormationExecutionRoleArn',
]);
const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const environmentSubject = (environment) => `repo:${REPOSITORY}:environment:${environment}`;
const MASTER_REF_SUBJECT = `repo:${REPOSITORY}:ref:refs/heads/master`;
const BASELINE_SUBJECT = environmentSubject('assessment-release-baseline');
const CDK_BOOTSTRAP_QUALIFIER = 'hnb659fds';
const SELF_TEST_BOOTSTRAP_ASSET_INVENTORIES = new WeakMap();
const SELF_TEST_AUXILIARY_ROLE_AUTHORITIES = new WeakMap();

export const IAM_EFFECTIVE_PERMISSIONS_CONTRACT_VERSION = 'stage7-iam-effective-permissions/2';

const normalizeActions = (actions) =>
  Object.freeze([...new Set(actions.map((action) => action.toLowerCase()))].toSorted());

const READ_ACTIONS = normalizeActions([
  'acm:DescribeCertificate',
  'apigateway:GET',
  'budgets:DescribeBudget',
  'budgets:DescribeNotificationsForBudget',
  'budgets:DescribeSubscribersForNotification',
  'ce:ListCostAllocationTags',
  'cloudformation:DescribeChangeSet',
  'cloudformation:DescribeStackDriftDetectionStatus',
  'cloudformation:DescribeStackEvents',
  'cloudformation:DescribeStackResource',
  'cloudformation:DescribeStackResourceDrifts',
  'cloudformation:DescribeStackResources',
  'cloudformation:DescribeStacks',
  'cloudformation:DetectStackDrift',
  'cloudformation:GetTemplate',
  'cloudformation:GetTemplateSummary',
  'cloudformation:ListChangeSets',
  'cloudformation:ListStackResources',
  'cloudformation:ListStacks',
  'cloudfront:GetDistribution',
  'cloudfront:GetDistributionConfig',
  'cloudfront:GetInvalidation',
  'cloudfront:GetKeyGroup',
  'cloudfront:GetPublicKey',
  'cloudfront:ListDistributions',
  'cloudwatch:DescribeAlarms',
  'cloudwatch:GetDashboard',
  'dynamodb:DescribeTable',
  'dynamodb:GetItem',
  'dynamodb:ListTables',
  'dynamodb:Query',
  'iam:GetPolicy',
  'iam:GetPolicyVersion',
  'iam:GetRole',
  'iam:GetRolePolicy',
  'iam:ListAttachedRolePolicies',
  'iam:ListRolePolicies',
  'lambda:GetAccountSettings',
  'lambda:GetAlias',
  'lambda:GetFunction',
  'lambda:GetFunctionConfiguration',
  'lambda:ListVersionsByFunction',
  'logs:FilterLogEvents',
  'resourcegroupstaggingapi:GetResources',
  'route53:GetHostedZone',
  'route53:ListResourceRecordSets',
  's3:GetAccountPublicAccessBlock',
  's3:GetBucketLocation',
  's3:GetBucketPolicyStatus',
  's3:GetBucketPublicAccessBlock',
  's3:GetBucketVersioning',
  's3:GetObject',
  's3:GetObjectVersion',
  's3:ListBucket',
  's3:ListBucketVersions',
  'scheduler:GetSchedule',
  'secretsmanager:DescribeSecret',
  'servicequotas:GetServiceQuota',
  'servicequotas:ListServiceQuotas',
  'sns:ListSubscriptionsByTopic',
  'ssm:GetParameter',
  'ssm:GetParametersByPath',
  'sts:AssumeRole',
  'sts:GetCallerIdentity',
]);

const DEPLOY_ACTIONS = normalizeActions([
  'apigateway:GET',
  'ce:ListCostAllocationTags',
  'cloudformation:CreateChangeSet',
  'cloudformation:DeleteChangeSet',
  'cloudformation:DescribeChangeSet',
  'cloudformation:DescribeStackEvents',
  'cloudformation:DescribeStackResources',
  'cloudformation:DescribeStacks',
  'cloudformation:ExecuteChangeSet',
  'cloudformation:GetTemplate',
  'cloudformation:UpdateStack',
  'cloudfront:GetKeyGroup',
  'cloudfront:GetPublicKey',
  'cloudfront:GetDistributionConfig',
  'dynamodb:DescribeTable',
  'dynamodb:GetItem',
  'dynamodb:PutItem',
  'dynamodb:TransactWriteItems',
  'dynamodb:UpdateItem',
  's3:GetBucketLocation',
  's3:GetObject',
  's3:ListBucket',
  's3:ListBucketVersions',
  's3:PutObject',
  'scheduler:GetSchedule',
  'secretsmanager:DescribeSecret',
  'ssm:GetParameter',
  'ssm:GetParametersByPath',
  'sts:AssumeRole',
  'sts:GetCallerIdentity',
]);

const ROLLBACK_ACTIONS = normalizeActions([
  'apigateway:GET',
  'cloudformation:CreateChangeSet',
  'cloudformation:DescribeChangeSet',
  'cloudformation:DescribeStackEvents',
  'cloudformation:DescribeStacks',
  'cloudformation:ExecuteChangeSet',
  'cloudformation:GetTemplate',
  'cloudformation:UpdateStack',
  'cloudfront:CreateInvalidation',
  'cloudfront:GetDistributionConfig',
  'cloudfront:GetInvalidation',
  'cloudfront:ListInvalidations',
  'cloudwatch:DescribeAlarms',
  'cloudwatch:GetMetricStatistics',
  'cloudwatch:PutMetricData',
  'dynamodb:DescribeTable',
  'dynamodb:GetItem',
  'dynamodb:Query',
  'lambda:GetAlias',
  'lambda:GetFunction',
  'lambda:GetFunctionConfiguration',
  'lambda:InvokeFunction',
  'lambda:ListVersionsByFunction',
  'lambda:UpdateAlias',
  'iam:PassRole',
  's3:GetObject',
  's3:GetObjectVersion',
  's3:ListBucketVersions',
  's3:PutObject',
  'scheduler:GetSchedule',
  'secretsmanager:DescribeSecret',
  'secretsmanager:GetSecretValue',
  'ssm:GetParameter',
  'ssm:GetParametersByPath',
  'ssm:PutParameter',
  'sts:GetCallerIdentity',
]);

const CLEANUP_ACTIONS = normalizeActions([
  'cloudformation:DeleteStack',
  'cloudformation:DescribeStacks',
  'cloudformation:UpdateStack',
  'iam:PassRole',
  'resourcegroupstaggingapi:GetResources',
  'sts:GetCallerIdentity',
]);

const BASELINE_ACTIONS = normalizeActions([
  'cloudformation:DescribeStacks',
  'cloudformation:GetTemplate',
  'cloudformation:UpdateStack',
  'cloudfront:GetDistributionConfig',
  'dynamodb:TransactWriteItems',
  'lambda:GetAlias',
  'lambda:GetFunction',
  's3:GetBucketVersioning',
  's3:GetObjectVersion',
  's3:ListBucketVersions',
  'scheduler:GetSchedule',
  'sns:ListSubscriptionsByTopic',
  'sts:AssumeRole',
  'sts:GetCallerIdentity',
]);

const BOOTSTRAP_DEPLOY_ACTIONS = normalizeActions([
  'cloudformation:ContinueUpdateRollback',
  'cloudformation:CreateChangeSet',
  'cloudformation:CreateStack',
  'cloudformation:DeleteChangeSet',
  'cloudformation:DescribeChangeSet',
  'cloudformation:DescribeStackEvents',
  'cloudformation:DescribeStacks',
  'cloudformation:ExecuteChangeSet',
  'cloudformation:GetTemplate',
  'cloudformation:RollbackStack',
  'cloudformation:UpdateStack',
  'cloudformation:UpdateTerminationProtection',
  'iam:PassRole',
  's3:GetBucketLocation',
  's3:GetObject',
  's3:ListBucket',
  'ssm:GetParameter',
  'sts:GetCallerIdentity',
]);

const BOOTSTRAP_FILE_PUBLISHING_ACTIONS = normalizeActions([
  's3:AbortMultipartUpload',
  's3:GetBucketLocation',
  's3:GetObject',
  's3:ListBucket',
  's3:ListBucketMultipartUploads',
  's3:ListMultipartUploadParts',
  's3:PutObject',
]);

const BOOTSTRAP_IMAGE_PUBLISHING_ACTIONS = normalizeActions([
  'ecr:BatchCheckLayerAvailability',
  'ecr:CompleteLayerUpload',
  'ecr:DescribeRepositories',
  'ecr:GetAuthorizationToken',
  'ecr:InitiateLayerUpload',
  'ecr:PutImage',
  'ecr:UploadLayerPart',
]);

const BOOTSTRAP_LOOKUP_ACTIONS = normalizeActions(['ssm:GetParameter', 'sts:GetCallerIdentity']);

const BOOTSTRAP_CFN_EXEC_ACTIONS = normalizeActions([
  'apigateway:DELETE',
  'apigateway:GET',
  'apigateway:PATCH',
  'apigateway:POST',
  'apigateway:PUT',
  'budgets:CreateBudget',
  'budgets:DeleteBudget',
  'budgets:DescribeBudget',
  'budgets:ModifyBudget',
  'cloudfront:CreateDistribution',
  'cloudfront:CreateFunction',
  'cloudfront:CreateOriginAccessControl',
  'cloudfront:CreateResponseHeadersPolicy',
  'cloudfront:DeleteDistribution',
  'cloudfront:DeleteFunction',
  'cloudfront:DeleteOriginAccessControl',
  'cloudfront:DeleteResponseHeadersPolicy',
  'cloudfront:DescribeFunction',
  'cloudfront:GetDistribution',
  'cloudfront:GetDistributionConfig',
  'cloudfront:GetFunction',
  'cloudfront:GetOriginAccessControl',
  'cloudfront:GetResponseHeadersPolicy',
  'cloudfront:ListTagsForResource',
  'cloudfront:PublishFunction',
  'cloudfront:TagResource',
  'cloudfront:UntagResource',
  'cloudfront:UpdateDistribution',
  'cloudfront:UpdateFunction',
  'cloudfront:UpdateOriginAccessControl',
  'cloudfront:UpdateResponseHeadersPolicy',
  'cloudwatch:DeleteAlarms',
  'cloudwatch:DeleteDashboards',
  'cloudwatch:PutDashboard',
  'cloudwatch:PutMetricAlarm',
  'cloudwatch:TagResource',
  'cloudwatch:UntagResource',
  'dynamodb:CreateTable',
  'dynamodb:DeleteTable',
  'dynamodb:DescribeContinuousBackups',
  'dynamodb:DescribeTable',
  'dynamodb:TagResource',
  'dynamodb:UntagResource',
  'dynamodb:UpdateContinuousBackups',
  'dynamodb:UpdateTable',
  'iam:CreateRole',
  'iam:DeleteRole',
  'iam:DeleteRolePolicy',
  'iam:GetRole',
  'iam:GetRolePolicy',
  'iam:PassRole',
  'iam:PutRolePolicy',
  'iam:TagRole',
  'iam:UntagRole',
  'lambda:AddPermission',
  'lambda:CreateAlias',
  'lambda:CreateFunction',
  'lambda:DeleteAlias',
  'lambda:DeleteFunction',
  'lambda:DeleteFunctionConcurrency',
  'lambda:GetAlias',
  'lambda:GetFunction',
  'lambda:GetFunctionConfiguration',
  'lambda:ListVersionsByFunction',
  'lambda:PublishVersion',
  'lambda:PutFunctionConcurrency',
  'lambda:RemovePermission',
  'lambda:TagResource',
  'lambda:UntagResource',
  'lambda:UpdateAlias',
  'lambda:UpdateFunctionCode',
  'lambda:UpdateFunctionConfiguration',
  'logs:CreateLogGroup',
  'logs:DeleteLogGroup',
  'logs:DeleteMetricFilter',
  'logs:DeleteRetentionPolicy',
  'logs:DescribeLogGroups',
  'logs:DescribeMetricFilters',
  'logs:PutMetricFilter',
  'logs:PutRetentionPolicy',
  'logs:TagLogGroup',
  'logs:UntagLogGroup',
  'route53:ChangeResourceRecordSets',
  'route53:GetChange',
  's3:CreateBucket',
  's3:DeleteBucket',
  's3:DeleteBucketPolicy',
  's3:DeleteBucketPublicAccessBlock',
  's3:GetBucketLocation',
  's3:GetBucketPolicy',
  's3:GetBucketPublicAccessBlock',
  's3:GetBucketVersioning',
  's3:ListBucket',
  's3:PutBucketEncryption',
  's3:PutBucketLifecycleConfiguration',
  's3:PutBucketOwnershipControls',
  's3:PutBucketPolicy',
  's3:PutBucketPublicAccessBlock',
  's3:PutBucketTagging',
  's3:PutBucketVersioning',
  'scheduler:CreateSchedule',
  'scheduler:DeleteSchedule',
  'scheduler:GetSchedule',
  'scheduler:TagResource',
  'scheduler:UntagResource',
  'scheduler:UpdateSchedule',
  'secretsmanager:GetSecretValue',
  'sns:CreateTopic',
  'sns:DeleteTopic',
  'sns:GetTopicAttributes',
  'sns:ListSubscriptionsByTopic',
  'sns:SetSubscriptionAttributes',
  'sns:SetTopicAttributes',
  'sns:Subscribe',
  'sns:TagResource',
  'sns:Unsubscribe',
  'sns:UntagResource',
  'ssm:AddTagsToResource',
  'ssm:DeleteParameter',
  'ssm:GetParameter',
  'ssm:PutParameter',
  'ssm:RemoveTagsFromResource',
]);

const REQUIRED_ACTIONS = Object.freeze({
  readRoleArn: normalizeActions([
    'cloudformation:DescribeStacks',
    'cloudformation:ListStacks',
    'cloudfront:ListDistributions',
    'dynamodb:ListTables',
    'iam:GetPolicy',
    'iam:GetPolicyVersion',
    'iam:GetRole',
    'iam:GetRolePolicy',
    'iam:ListAttachedRolePolicies',
    'iam:ListRolePolicies',
    'lambda:GetAccountSettings',
    'logs:FilterLogEvents',
    'servicequotas:ListServiceQuotas',
    'ssm:GetParametersByPath',
    'sts:AssumeRole',
  ]),
  deployRoleArn: normalizeActions([
    'apigateway:GET',
    'ce:ListCostAllocationTags',
    'cloudformation:DescribeStacks',
    'cloudfront:GetDistributionConfig',
    'cloudfront:GetKeyGroup',
    'cloudfront:GetPublicKey',
    'dynamodb:TransactWriteItems',
    's3:ListBucketVersions',
    'scheduler:GetSchedule',
    'secretsmanager:DescribeSecret',
    'ssm:GetParameter',
    'ssm:GetParametersByPath',
    'sts:AssumeRole',
  ]),
  rollbackRoleArn: normalizeActions([
    'apigateway:GET',
    'cloudformation:CreateChangeSet',
    'cloudformation:DescribeChangeSet',
    'cloudformation:DescribeStackEvents',
    'cloudformation:DescribeStacks',
    'cloudformation:ExecuteChangeSet',
    'cloudformation:GetTemplate',
    'cloudformation:UpdateStack',
    'cloudfront:CreateInvalidation',
    'cloudfront:GetDistributionConfig',
    'cloudfront:GetInvalidation',
    'cloudfront:ListInvalidations',
    'cloudwatch:DescribeAlarms',
    'cloudwatch:GetMetricStatistics',
    'cloudwatch:PutMetricData',
    'dynamodb:DescribeTable',
    'dynamodb:GetItem',
    'dynamodb:Query',
    'iam:PassRole',
    'lambda:GetAlias',
    'lambda:GetFunction',
    'lambda:GetFunctionConfiguration',
    'lambda:InvokeFunction',
    'lambda:ListVersionsByFunction',
    'lambda:UpdateAlias',
    's3:GetObject',
    's3:GetObjectVersion',
    's3:ListBucketVersions',
    's3:PutObject',
    'scheduler:GetSchedule',
    'secretsmanager:DescribeSecret',
    'secretsmanager:GetSecretValue',
    'ssm:GetParameter',
    'ssm:GetParametersByPath',
    'ssm:PutParameter',
    'sts:GetCallerIdentity',
  ]),
  cleanupRoleArn: normalizeActions([
    'cloudformation:DeleteStack',
    'cloudformation:DescribeStacks',
    'cloudformation:UpdateStack',
    'iam:PassRole',
    'resourcegroupstaggingapi:GetResources',
  ]),
  baselineRoleArn: BASELINE_ACTIONS,
  bootstrapDeployRoleArn: BOOTSTRAP_DEPLOY_ACTIONS,
  bootstrapFilePublishingRoleArn: BOOTSTRAP_FILE_PUBLISHING_ACTIONS,
  bootstrapImagePublishingRoleArn: BOOTSTRAP_IMAGE_PUBLISHING_ACTIONS,
  bootstrapLookupRoleArn: BOOTSTRAP_LOOKUP_ACTIONS,
  bootstrapCloudFormationExecutionRoleArn: BOOTSTRAP_CFN_EXEC_ACTIONS,
});

export const IAM_ROLE_PERMISSION_PROFILES = Object.freeze({
  readRoleArn: Object.freeze({
    capability: 'READ_AND_AUDIT',
    actions: READ_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.readRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([
        environmentSubject('assessment-release'),
        environmentSubject('assessment-release-read'),
        environmentSubject('assessment-release-recovery'),
        environmentSubject('assessment-release-reconciliation-recovery'),
        environmentSubject('assessment-release-sandbox'),
      ]),
      prerelease: Object.freeze([
        environmentSubject('assessment-prerelease'),
        environmentSubject('assessment-prerelease-external'),
        environmentSubject('assessment-prerelease-read'),
      ]),
      // FULL_RELEASE and baseline attest the same physical read role. The sandbox subject is
      // selected only by the full workflow, but must remain in this exact shared trust policy.
      baseline: Object.freeze([
        environmentSubject('assessment-release'),
        environmentSubject('assessment-release-read'),
        environmentSubject('assessment-release-recovery'),
        environmentSubject('assessment-release-reconciliation-recovery'),
        environmentSubject('assessment-release-sandbox'),
      ]),
    }),
  }),
  deployRoleArn: Object.freeze({
    capability: 'DEPLOY_ONLY',
    actions: DEPLOY_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.deployRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([environmentSubject('assessment-release')]),
      prerelease: Object.freeze([
        environmentSubject('assessment-prerelease'),
        environmentSubject('assessment-prerelease-external'),
      ]),
      baseline: Object.freeze([environmentSubject('assessment-release')]),
    }),
  }),
  rollbackRoleArn: Object.freeze({
    capability: 'ROLLBACK_AND_AUTOMATIC_RECOVERY_ONLY',
    actions: ROLLBACK_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.rollbackRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([
        environmentSubject('assessment-release'),
        environmentSubject('assessment-release-recovery'),
      ]),
      prerelease: Object.freeze([environmentSubject('assessment-prerelease')]),
      baseline: Object.freeze([
        environmentSubject('assessment-release'),
        environmentSubject('assessment-release-recovery'),
      ]),
    }),
  }),
  cleanupRoleArn: Object.freeze({
    capability: 'EPHEMERAL_CLEANUP_ONLY',
    actions: CLEANUP_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.cleanupRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([environmentSubject('assessment-release')]),
      prerelease: Object.freeze([environmentSubject('assessment-prerelease')]),
      baseline: Object.freeze([environmentSubject('assessment-release')]),
    }),
  }),
  cleanupWatchdogRoleArn: Object.freeze({
    capability: 'DURABLE_PRERELEASE_CLEANUP_WATCHDOG_ONLY',
    actions: normalizeActions([
      'cloudformation:DeleteStack',
      'cloudformation:DescribeStacks',
      'cloudformation:UpdateStack',
      'iam:GetRole',
      'iam:PassRole',
      'resourcegroupstaggingapi:GetResources',
      'sts:GetCallerIdentity',
    ]),
    requiredActions: normalizeActions([
      'cloudformation:DeleteStack',
      'cloudformation:DescribeStacks',
      'cloudformation:UpdateStack',
      'iam:GetRole',
      'iam:PassRole',
      'resourcegroupstaggingapi:GetResources',
    ]),
    oidcSubjects: Object.freeze({
      full: Object.freeze([]),
      prerelease: Object.freeze([MASTER_REF_SUBJECT]),
      baseline: Object.freeze([]),
    }),
  }),
  baselineRoleArn: Object.freeze({
    capability: 'CLOSED_BASELINE_ESTABLISHMENT_ONLY',
    actions: BASELINE_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.baselineRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([]),
      prerelease: Object.freeze([]),
      baseline: Object.freeze([BASELINE_SUBJECT]),
    }),
  }),
  bootstrapDeployRoleArn: Object.freeze({
    capability: 'CDK_CHANGE_SET_DELIVERY_ONLY',
    actions: BOOTSTRAP_DEPLOY_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.bootstrapDeployRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([]),
      prerelease: Object.freeze([]),
      baseline: Object.freeze([]),
    }),
  }),
  bootstrapFilePublishingRoleArn: Object.freeze({
    capability: 'CDK_FILE_ASSET_PUBLISHING_ONLY',
    actions: BOOTSTRAP_FILE_PUBLISHING_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.bootstrapFilePublishingRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([]),
      prerelease: Object.freeze([]),
      baseline: Object.freeze([]),
    }),
  }),
  bootstrapImagePublishingRoleArn: Object.freeze({
    capability: 'CDK_IMAGE_ASSET_PUBLISHING_ONLY',
    actions: BOOTSTRAP_IMAGE_PUBLISHING_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.bootstrapImagePublishingRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([]),
      prerelease: Object.freeze([]),
      baseline: Object.freeze([]),
    }),
  }),
  bootstrapLookupRoleArn: Object.freeze({
    capability: 'CDK_BOOTSTRAP_VERSION_LOOKUP_ONLY',
    actions: BOOTSTRAP_LOOKUP_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.bootstrapLookupRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([]),
      prerelease: Object.freeze([]),
      baseline: Object.freeze([]),
    }),
  }),
  bootstrapCloudFormationExecutionRoleArn: Object.freeze({
    capability: 'CLOUDFORMATION_CHECKOUT_STACK_EXECUTION_ONLY',
    actions: BOOTSTRAP_CFN_EXEC_ACTIONS,
    requiredActions: REQUIRED_ACTIONS.bootstrapCloudFormationExecutionRoleArn,
    oidcSubjects: Object.freeze({
      full: Object.freeze([]),
      prerelease: Object.freeze([]),
      baseline: Object.freeze([]),
    }),
  }),
});

const SCOPE_REQUIRED_ACTIONS = Object.freeze({
  readRoleArn: Object.freeze({
    full: Object.freeze([]),
    prerelease: normalizeActions(['cloudfront:GetKeyGroup', 'cloudfront:GetPublicKey']),
    baseline: normalizeActions([
      'acm:DescribeCertificate',
      'cloudfront:GetKeyGroup',
      'cloudfront:GetPublicKey',
      'route53:GetHostedZone',
      'route53:ListResourceRecordSets',
      'secretsmanager:DescribeSecret',
      'servicequotas:GetServiceQuota',
    ]),
  }),
});

const requiredActionsFor = (roleKey, scope) =>
  normalizeActions([
    ...IAM_ROLE_PERMISSION_PROFILES[roleKey].requiredActions,
    ...(SCOPE_REQUIRED_ACTIONS[roleKey]?.[scope] ?? []),
  ]);

const IAM_PROFILE_KEYS = Object.freeze([
  ...ROLE_KEYS,
  'cleanupWatchdogRoleArn',
  'baselineRoleArn',
  ...BOOTSTRAP_ROLE_KEYS,
]);

const ACTION_RESOURCE_CLASSES = Object.freeze({
  GLOBAL_RESOURCE_REQUIRED: normalizeActions([
    'ce:ListCostAllocationTags',
    'cloudformation:DescribeStackDriftDetectionStatus',
    'cloudformation:ListStacks',
    'cloudfront:CreateDistribution',
    'cloudfront:CreateFunction',
    'cloudfront:CreateOriginAccessControl',
    'cloudfront:CreateResponseHeadersPolicy',
    'cloudfront:GetKeyGroup',
    'cloudfront:GetPublicKey',
    'cloudfront:ListDistributions',
    'cloudwatch:GetMetricStatistics',
    'dynamodb:ListTables',
    'ecr:GetAuthorizationToken',
    'lambda:GetAccountSettings',
    'resourcegroupstaggingapi:GetResources',
    's3:GetAccountPublicAccessBlock',
    'servicequotas:GetServiceQuota',
    'servicequotas:ListServiceQuotas',
    'sts:GetCallerIdentity',
  ]),
  ACM_CERTIFICATE: normalizeActions(['acm:DescribeCertificate']),
  API_GATEWAY_TAGGED: normalizeActions([
    'apigateway:DELETE',
    'apigateway:GET',
    'apigateway:PATCH',
    'apigateway:POST',
    'apigateway:PUT',
  ]),
  BUDGET: normalizeActions([
    'budgets:CreateBudget',
    'budgets:DeleteBudget',
    'budgets:DescribeBudget',
    'budgets:DescribeNotificationsForBudget',
    'budgets:DescribeSubscribersForNotification',
    'budgets:ModifyBudget',
  ]),
  CLOUDFORMATION_STACK: normalizeActions([
    'cloudformation:CreateStack',
    'cloudformation:ContinueUpdateRollback',
    'cloudformation:DeleteStack',
    'cloudformation:DescribeStackEvents',
    'cloudformation:DescribeStackResource',
    'cloudformation:DescribeStackResourceDrifts',
    'cloudformation:DescribeStackResources',
    'cloudformation:DescribeStacks',
    'cloudformation:DetectStackDrift',
    'cloudformation:GetTemplateSummary',
    'cloudformation:ListChangeSets',
    'cloudformation:ListStackResources',
    'cloudformation:RollbackStack',
    'cloudformation:UpdateStack',
    'cloudformation:UpdateTerminationProtection',
  ]),
  CLOUDFORMATION_CHANGE_SET_STACK: normalizeActions([
    'cloudformation:CreateChangeSet',
    'cloudformation:DeleteChangeSet',
    'cloudformation:DescribeChangeSet',
    'cloudformation:ExecuteChangeSet',
    'cloudformation:GetTemplate',
  ]),
  CLOUDFRONT_DISTRIBUTION_TAGGED: normalizeActions([
    'cloudfront:CreateInvalidation',
    'cloudfront:DeleteDistribution',
    'cloudfront:GetDistribution',
    'cloudfront:GetDistributionConfig',
    'cloudfront:GetInvalidation',
    'cloudfront:ListInvalidations',
    'cloudfront:UpdateDistribution',
  ]),
  CLOUDFRONT_FUNCTION: normalizeActions([
    'cloudfront:DeleteFunction',
    'cloudfront:DescribeFunction',
    'cloudfront:GetFunction',
    'cloudfront:PublishFunction',
    'cloudfront:UpdateFunction',
  ]),
  CLOUDFRONT_ORIGIN_ACCESS_CONTROL: normalizeActions([
    'cloudfront:DeleteOriginAccessControl',
    'cloudfront:GetOriginAccessControl',
    'cloudfront:UpdateOriginAccessControl',
  ]),
  CLOUDFRONT_RESPONSE_HEADERS_POLICY: normalizeActions([
    'cloudfront:DeleteResponseHeadersPolicy',
    'cloudfront:GetResponseHeadersPolicy',
    'cloudfront:UpdateResponseHeadersPolicy',
  ]),
  CLOUDFRONT_STAGE7_RESOURCE: normalizeActions([
    'cloudfront:ListTagsForResource',
    'cloudfront:TagResource',
    'cloudfront:UntagResource',
  ]),
  CLOUDWATCH_ALARM: normalizeActions([
    'cloudwatch:DeleteAlarms',
    'cloudwatch:DescribeAlarms',
    'cloudwatch:PutMetricAlarm',
  ]),
  CLOUDWATCH_DASHBOARD: normalizeActions([
    'cloudwatch:DeleteDashboards',
    'cloudwatch:GetDashboard',
    'cloudwatch:PutDashboard',
  ]),
  CLOUDWATCH_STAGE7_RESOURCE: normalizeActions([
    'cloudwatch:TagResource',
    'cloudwatch:UntagResource',
  ]),
  CLOUDWATCH_METRIC_NAMESPACE: normalizeActions(['cloudwatch:PutMetricData']),
  DYNAMODB_TABLE: normalizeActions([
    'dynamodb:CreateTable',
    'dynamodb:DeleteTable',
    'dynamodb:DescribeContinuousBackups',
    'dynamodb:DescribeTable',
    'dynamodb:GetItem',
    'dynamodb:PutItem',
    'dynamodb:TransactWriteItems',
    'dynamodb:TagResource',
    'dynamodb:UntagResource',
    'dynamodb:UpdateContinuousBackups',
    'dynamodb:UpdateItem',
    'dynamodb:UpdateTable',
  ]),
  DYNAMODB_TABLE_AND_INDEX: normalizeActions(['dynamodb:Query']),
  IAM_BOOTSTRAP_EXECUTION_ROLE: normalizeActions(['iam:PassRole']),
  IAM_APPLICATION_ROLE: normalizeActions([
    'iam:CreateRole',
    'iam:DeleteRole',
    'iam:DeleteRolePolicy',
    'iam:PutRolePolicy',
    'iam:TagRole',
    'iam:UntagRole',
  ]),
  IAM_MANAGED_POLICY: normalizeActions(['iam:GetPolicy', 'iam:GetPolicyVersion']),
  IAM_RELEASE_ROLE: normalizeActions([
    'iam:GetRole',
    'iam:GetRolePolicy',
    'iam:ListAttachedRolePolicies',
    'iam:ListRolePolicies',
  ]),
  LAMBDA_FUNCTION: normalizeActions([
    'lambda:AddPermission',
    'lambda:CreateAlias',
    'lambda:CreateFunction',
    'lambda:DeleteAlias',
    'lambda:DeleteFunction',
    'lambda:DeleteFunctionConcurrency',
    'lambda:GetAlias',
    'lambda:GetFunction',
    'lambda:GetFunctionConfiguration',
    'lambda:InvokeFunction',
    'lambda:ListVersionsByFunction',
    'lambda:PublishVersion',
    'lambda:PutFunctionConcurrency',
    'lambda:RemovePermission',
    'lambda:TagResource',
    'lambda:UntagResource',
    'lambda:UpdateAlias',
    'lambda:UpdateFunctionCode',
    'lambda:UpdateFunctionConfiguration',
  ]),
  LOG_GROUP: normalizeActions([
    'logs:CreateLogGroup',
    'logs:DeleteLogGroup',
    'logs:DeleteMetricFilter',
    'logs:DeleteRetentionPolicy',
    'logs:DescribeLogGroups',
    'logs:DescribeMetricFilters',
    'logs:FilterLogEvents',
    'logs:PutMetricFilter',
    'logs:PutRetentionPolicy',
    'logs:TagLogGroup',
    'logs:UntagLogGroup',
  ]),
  ROUTE53_CHANGE: normalizeActions(['route53:GetChange']),
  ROUTE53_ZONE: normalizeActions([
    'route53:ChangeResourceRecordSets',
    'route53:GetHostedZone',
    'route53:ListResourceRecordSets',
  ]),
  S3_BUCKET: normalizeActions([
    's3:CreateBucket',
    's3:DeleteBucket',
    's3:DeleteBucketPolicy',
    's3:DeleteBucketPublicAccessBlock',
    's3:GetBucketLocation',
    's3:GetBucketPolicy',
    's3:GetBucketPolicyStatus',
    's3:GetBucketPublicAccessBlock',
    's3:GetBucketVersioning',
    's3:ListBucket',
    's3:ListBucketMultipartUploads',
    's3:ListBucketVersions',
    's3:PutBucketEncryption',
    's3:PutBucketLifecycleConfiguration',
    's3:PutBucketOwnershipControls',
    's3:PutBucketPolicy',
    's3:PutBucketPublicAccessBlock',
    's3:PutBucketTagging',
    's3:PutBucketVersioning',
  ]),
  S3_OBJECT: normalizeActions([
    's3:AbortMultipartUpload',
    's3:DeleteObject',
    's3:DeleteObjectVersion',
    's3:GetObject',
    's3:GetObjectVersion',
    's3:ListMultipartUploadParts',
    's3:PutObject',
  ]),
  SCHEDULER: normalizeActions([
    'scheduler:CreateSchedule',
    'scheduler:DeleteSchedule',
    'scheduler:GetSchedule',
    'scheduler:TagResource',
    'scheduler:UntagResource',
    'scheduler:UpdateSchedule',
  ]),
  SECRETS_MANAGER_SECRET: normalizeActions([
    'secretsmanager:DescribeSecret',
    'secretsmanager:GetSecretValue',
  ]),
  SNS_TOPIC: normalizeActions([
    'sns:CreateTopic',
    'sns:DeleteTopic',
    'sns:GetTopicAttributes',
    'sns:ListSubscriptionsByTopic',
    'sns:SetSubscriptionAttributes',
    'sns:SetTopicAttributes',
    'sns:Subscribe',
    'sns:TagResource',
    'sns:Unsubscribe',
    'sns:UntagResource',
  ]),
  SSM_PARAMETER: normalizeActions([
    'ssm:AddTagsToResource',
    'ssm:DeleteParameter',
    'ssm:GetParameter',
    'ssm:GetParametersByPath',
    'ssm:PutParameter',
    'ssm:RemoveTagsFromResource',
  ]),
  STS_BOOTSTRAP_ROLE: normalizeActions(['sts:AssumeRole']),
  CDK_ASSET_REPOSITORY: normalizeActions([
    'ecr:BatchCheckLayerAvailability',
    'ecr:CompleteLayerUpload',
    'ecr:DescribeRepositories',
    'ecr:InitiateLayerUpload',
    'ecr:PutImage',
    'ecr:UploadLayerPart',
  ]),
});

const RESOURCE_CLASS_BY_ACTION = new Map();
for (const [resourceClass, actions] of Object.entries(ACTION_RESOURCE_CLASSES)) {
  for (const action of actions) {
    if (RESOURCE_CLASS_BY_ACTION.has(action)) {
      throw new Error(`Duplicate IAM resource class for ${action}`);
    }
    RESOURCE_CLASS_BY_ACTION.set(action, resourceClass);
  }
}
for (const profile of Object.values(IAM_ROLE_PERMISSION_PROFILES)) {
  for (const action of profile.actions) {
    if (!RESOURCE_CLASS_BY_ACTION.has(action)) {
      throw new Error(`Missing IAM resource class for ${action}`);
    }
  }
}

const RESOURCE_PATTERN_CONTRACT_VERSION = 'checkout-stage7-resource-patterns/1';
const rolePermissionContract = (roleKey) => ({
  profile: IAM_ROLE_PERMISSION_PROFILES[roleKey],
  scopeRequiredActions: SCOPE_REQUIRED_ACTIONS[roleKey] ?? null,
  resourcePatternContractVersion: RESOURCE_PATTERN_CONTRACT_VERSION,
  actionResourceClasses: Object.fromEntries(
    IAM_ROLE_PERMISSION_PROFILES[roleKey].actions.map((action) => [
      action,
      RESOURCE_CLASS_BY_ACTION.get(action),
    ]),
  ),
});
const iamPermissionContract = () => ({
  profiles: IAM_ROLE_PERMISSION_PROFILES,
  actionResourceClasses: ACTION_RESOURCE_CLASSES,
  resourcePatternContractVersion: RESOURCE_PATTERN_CONTRACT_VERSION,
});

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const exactKeys = (value, expected) => {
  if (!object(value)) return false;
  const actual = Object.keys(value).toSorted();
  return actual.join('\0') === [...expected].toSorted().join('\0');
};

const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (object(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }
  throw new IamEffectivePermissionsError('E7_IAM_VALUE_NOT_CANONICAL');
};

const canonicalJson = (value) => JSON.stringify(canonicalize(value));
const sha256 = (value) => createHash('sha256').update(String(value)).digest('hex');
const objectSha256 = (value) => sha256(canonicalJson(value));

export class IamEffectivePermissionsError extends Error {
  constructor(code) {
    super(code);
    this.name = 'IamEffectivePermissionsError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new IamEffectivePermissionsError(code);
};

const strings = (value, code) => {
  const values = typeof value === 'string' ? [value] : value;
  if (
    !Array.isArray(values) ||
    values.length === 0 ||
    values.some((entry) => typeof entry !== 'string' || entry.length === 0) ||
    new Set(values).size !== values.length
  ) {
    fail(code);
  }
  return values;
};

const taggedResourceCondition = (config) => ({
  StringEquals: {
    'aws:ResourceTag/Environment': config.environment,
    'aws:ResourceTag/Project': 'checkout',
  },
});

const normalizeAllowedCondition = ({ condition, resourceClass, config, roleKey, actions }) => {
  const immutableRollbackJournalWrite =
    resourceClass === 'SSM_PARAMETER' &&
    roleKey === 'rollbackRoleArn' &&
    actions.includes('ssm:putparameter');
  if (
    immutableRollbackJournalWrite &&
    (actions.length !== 1 || actions[0] !== 'ssm:putparameter')
  ) {
    fail('E7_IAM_CONDITION_NOT_ALLOWLISTED');
  }
  const expected = immutableRollbackJournalWrite
    ? { StringEquals: { 'ssm:Overwrite': 'false' } }
    : resourceClass === 'CLOUDFRONT_DISTRIBUTION_TAGGED' ||
        (resourceClass === 'API_GATEWAY_TAGGED' &&
          roleKey !== 'bootstrapCloudFormationExecutionRoleArn')
      ? taggedResourceCondition(config)
      : resourceClass === 'CLOUDWATCH_METRIC_NAMESPACE'
        ? { StringEquals: { 'cloudwatch:namespace': 'Checkout/Stage7Rehearsal' } }
        : resourceClass === 'IAM_BOOTSTRAP_EXECUTION_ROLE'
          ? roleKey === 'bootstrapCloudFormationExecutionRoleArn'
            ? {
                StringEquals: {
                  'iam:PassedToService': ['lambda.amazonaws.com', 'scheduler.amazonaws.com'],
                },
              }
            : { StringEquals: { 'iam:PassedToService': 'cloudformation.amazonaws.com' } }
          : null;
  if (expected === null) {
    if (condition !== undefined) fail('E7_IAM_CONDITION_NOT_ALLOWLISTED');
    return null;
  }
  if (!object(condition) || canonicalJson(condition) !== canonicalJson(expected)) {
    fail('E7_IAM_CONDITION_NOT_ALLOWLISTED');
  }
  return canonicalize(condition);
};

const stageStackResources = (config) =>
  ['data', 'api', 'observability', 'web'].map(
    (suffix) =>
      `arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/checkout-${config.environment}-${suffix}/*`,
  );

const cloudFormationStackResources = (config, roleKey) => [
  ...stageStackResources(config),
  ...(roleKey === 'readRoleArn'
    ? [`arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/CDKToolkit/*`]
    : []),
];

const cloudFormationChangeSetResources = (config, roleKey) =>
  roleKey === 'rollbackRoleArn'
    ? [
        `arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/checkout-${config.environment}-observability/*`,
      ]
    : cloudFormationStackResources(config, roleKey);

const bootstrapRoleArns = (config) => {
  const prefix = `arn:aws:iam::${config.aws.accountId}:role/cdk-hnb659fds-`;
  const suffix = `-${config.aws.accountId}-${config.aws.region}`;
  return Object.freeze({
    bootstrapDeployRoleArn: `${prefix}deploy-role${suffix}`,
    bootstrapFilePublishingRoleArn: `${prefix}file-publishing-role${suffix}`,
    bootstrapImagePublishingRoleArn: `${prefix}image-publishing-role${suffix}`,
    bootstrapLookupRoleArn: `${prefix}lookup-role${suffix}`,
    bootstrapCloudFormationExecutionRoleArn: `${prefix}cfn-exec-role${suffix}`,
  });
};

const bootstrapRoleResources = (config, roleKey) => {
  const roles = bootstrapRoleArns(config);
  if (roleKey === 'readRoleArn') return [roles.bootstrapLookupRoleArn];
  if (['deployRoleArn', 'baselineRoleArn'].includes(roleKey)) {
    return [roles.bootstrapDeployRoleArn, roles.bootstrapFilePublishingRoleArn];
  }
  return [];
};

const rollbackJournalReadResources = (config, candidateSha) =>
  ['RB-E7-06', 'RB-E7-08', 'release-reconciliation'].map(
    (scenarioId) =>
      `arn:aws:ssm:${config.aws.region}:${config.aws.accountId}:parameter/checkout/stage7/rollback/${candidateSha}/${scenarioId}/*`,
  );

const releaseMutationGuardReadResources = (config, candidateSha) => [
  `arn:aws:ssm:${config.aws.region}:${config.aws.accountId}:parameter/checkout/stage7/release-fence/${candidateSha}/*`,
  `arn:aws:ssm:${config.aws.region}:${config.aws.accountId}:parameter/checkout/stage7/release-finalization/${candidateSha}/*`,
  `arn:aws:ssm:${config.aws.region}:${config.aws.accountId}:parameter/checkout/stage7/rollback/${candidateSha}/*`,
];

const rollbackJournalWriteResources = (config, candidateSha) =>
  rollbackJournalReadResources(config, candidateSha).slice(0, 2);

const expectedBootstrapTrustPolicy = ({ config, roleKey }) => {
  if (!BOOTSTRAP_ROLE_KEYS.includes(roleKey)) fail('E7_IAM_BOOTSTRAP_ROLE_KEY_INVALID');
  if (roleKey === 'bootstrapCloudFormationExecutionRoleArn') {
    return {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'cloudformation.amazonaws.com' },
          Action: 'sts:AssumeRole',
        },
      ],
    };
  }
  if (roleKey === 'bootstrapImagePublishingRoleArn') {
    return {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: { AWS: '*' },
          Action: 'sts:AssumeRole',
        },
      ],
    };
  }
  const principal =
    roleKey === 'bootstrapLookupRoleArn'
      ? config.aws.roles.readRoleArn
      : [config.aws.roles.baselineRoleArn, config.aws.roles.deployRoleArn].toSorted();
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: principal },
        Action: ['sts:AssumeRole', 'sts:TagSession'],
      },
    ],
  };
};

const validateBootstrapTrust = ({ policy, config, roleKey }) => {
  if (
    !object(policy) ||
    canonicalJson(policy) !== canonicalJson(expectedBootstrapTrustPolicy({ config, roleKey }))
  ) {
    fail('E7_IAM_BOOTSTRAP_TRUST_INVALID');
  }
  return true;
};

export const createSanitizedBootstrapPolicyTemplate = ({ config, scope }) => {
  if (
    !object(config) ||
    !object(config.aws) ||
    !/^[0-9]{12}$/u.test(config.aws.accountId ?? '') ||
    typeof config.aws.region !== 'string' ||
    !['full', 'prerelease', 'baseline'].includes(scope)
  ) {
    fail('E7_IAM_BOOTSTRAP_TEMPLATE_INPUT_INVALID');
  }
  const roleArns = bootstrapRoleArns(config);
  const roles = Object.fromEntries(
    BOOTSTRAP_ROLE_KEYS.map((roleKey) => {
      const requiredActions = requiredActionsFor(roleKey, scope);
      return [
        roleKey,
        {
          capability: IAM_ROLE_PERMISSION_PROFILES[roleKey].capability,
          roleArnSha256: sha256(roleArns[roleKey]),
          trustPolicySha256: objectSha256(expectedBootstrapTrustPolicy({ config, roleKey })),
          requiredActionCount: requiredActions.length,
          requiredActionsSha256: objectSha256(requiredActions),
          allowlistSha256: objectSha256(rolePermissionContract(roleKey)),
        },
      ];
    }),
  );
  const value = {
    schemaVersion: 1,
    kind: 'SANITIZED_CDK_BOOTSTRAP_LEAST_PRIVILEGE_TEMPLATE',
    qualifier: CDK_BOOTSTRAP_QUALIFIER,
    scope,
    accountSha256: sha256(config.aws.accountId),
    regionSha256: sha256(config.aws.region),
    resourcePatternContractVersion: RESOURCE_PATTERN_CONTRACT_VERSION,
    roles,
  };
  return { ...value, templateSha256: objectSha256(value) };
};

export const validateBootstrapAssetInventory = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'qualifier',
      'region',
      'assemblySha256',
      'assetManifestCount',
      'assetManifestSha256',
      'fileAssetCount',
      'dockerImageAssetCount',
      'requiredPublishingRoleKeys',
      'deniedPublishingRoleKeys',
      'containsSensitiveData',
      'inventorySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'CDK_BOOTSTRAP_ASSET_INVENTORY' ||
    value.status !== 'PASS' ||
    value.qualifier !== CDK_BOOTSTRAP_QUALIFIER ||
    !/^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$/u.test(value.region ?? '') ||
    !SHA256.test(value.assemblySha256 ?? '') ||
    !Number.isSafeInteger(value.assetManifestCount) ||
    value.assetManifestCount < 1 ||
    !SHA256.test(value.assetManifestSha256 ?? '') ||
    !Number.isSafeInteger(value.fileAssetCount) ||
    value.fileAssetCount < 1 ||
    value.dockerImageAssetCount !== 0 ||
    value.requiredPublishingRoleKeys?.join('\0') !== 'bootstrapFilePublishingRoleArn' ||
    value.deniedPublishingRoleKeys?.join('\0') !== 'bootstrapImagePublishingRoleArn' ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_IAM_BOOTSTRAP_ASSET_INVENTORY_INVALID');
  }
  const body = { ...value };
  delete body.inventorySha256;
  if (value.inventorySha256 !== objectSha256(body)) {
    fail('E7_IAM_BOOTSTRAP_ASSET_INVENTORY_INVALID');
  }
  return value;
};

const resourceAllowed = ({
  resource,
  resourceClass,
  config,
  roleKey,
  actions,
  authorizedRoleArns,
  authorizedPolicyArns,
  auditedRoleArn,
  permissionContext,
}) => {
  const { accountId, region } = config.aws;
  const environment = config.environment;
  const exact = (...values) =>
    values.filter((value) => typeof value === 'string').includes(resource);
  switch (resourceClass) {
    case 'GLOBAL_RESOURCE_REQUIRED':
      return resource === '*';
    case 'ACM_CERTIFICATE':
      return exact(config.domain?.webCertificateArn, config.domain?.apiCertificateArn);
    case 'API_GATEWAY_TAGGED':
      return roleKey === 'bootstrapCloudFormationExecutionRoleArn'
        ? [
            `arn:aws:apigateway:${region}::/apis`,
            `arn:aws:apigateway:${region}::/apis/*`,
            `arn:aws:apigateway:${region}::/domainnames/${config.domain?.apiHostname}`,
            `arn:aws:apigateway:${region}::/domainnames/${config.domain?.apiHostname}/apimappings`,
            `arn:aws:apigateway:${region}::/domainnames/${config.domain?.apiHostname}/apimappings/*`,
          ].includes(resource)
        : resource === `arn:aws:apigateway:${region}::/apis/*` ||
            (typeof config.domain?.apiHostname === 'string' &&
              resource ===
                `arn:aws:apigateway:${region}::/domainnames/${config.domain.apiHostname}/apimappings`);
    case 'BUDGET':
      return resource === `arn:aws:budgets::${accountId}:budget/checkout-${environment}-*`;
    case 'CLOUDFORMATION_STACK':
      return cloudFormationStackResources(config, roleKey).includes(resource);
    case 'CLOUDFORMATION_CHANGE_SET_STACK':
      return cloudFormationChangeSetResources(config, roleKey).includes(resource);
    case 'CLOUDFRONT_DISTRIBUTION_TAGGED':
      return resource === `arn:aws:cloudfront::${accountId}:distribution/*`;
    case 'CLOUDFRONT_FUNCTION':
      return resource === `arn:aws:cloudfront::${accountId}:function/checkout-${environment}-*`;
    case 'CLOUDFRONT_ORIGIN_ACCESS_CONTROL':
      return resource === `arn:aws:cloudfront::${accountId}:origin-access-control/*`;
    case 'CLOUDFRONT_RESPONSE_HEADERS_POLICY':
      return resource === `arn:aws:cloudfront::${accountId}:response-headers-policy/*`;
    case 'CLOUDFRONT_STAGE7_RESOURCE':
      return [
        `arn:aws:cloudfront::${accountId}:distribution/*`,
        `arn:aws:cloudfront::${accountId}:function/checkout-${environment}-*`,
        `arn:aws:cloudfront::${accountId}:origin-access-control/*`,
        `arn:aws:cloudfront::${accountId}:response-headers-policy/*`,
      ].includes(resource);
    case 'CLOUDWATCH_ALARM':
      return (
        resource ===
        (roleKey === 'rollbackRoleArn'
          ? `arn:aws:cloudwatch:${region}:${accountId}:alarm:checkout-${environment}-rollback-rehearsal`
          : `arn:aws:cloudwatch:${region}:${accountId}:alarm:checkout-${environment}-*`)
      );
    case 'CLOUDWATCH_DASHBOARD':
      return resource === `arn:aws:cloudwatch::${accountId}:dashboard/checkout-${environment}-*`;
    case 'CLOUDWATCH_STAGE7_RESOURCE':
      return [
        `arn:aws:cloudwatch:${region}:${accountId}:alarm:checkout-${environment}-*`,
        `arn:aws:cloudwatch::${accountId}:dashboard/checkout-${environment}-*`,
      ].includes(resource);
    case 'CLOUDWATCH_METRIC_NAMESPACE':
      return resource === '*';
    case 'DYNAMODB_TABLE':
      return resource === `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*`;
    case 'DYNAMODB_TABLE_AND_INDEX':
      return (
        roleKey === 'rollbackRoleArn'
          ? [
              `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*/index/GSI2-PendingAge`,
            ]
          : [
              `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*`,
              `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*/index/*`,
            ]
      ).includes(resource);
    case 'IAM_BOOTSTRAP_EXECUTION_ROLE':
      return roleKey === 'bootstrapCloudFormationExecutionRoleArn'
        ? resource === `arn:aws:iam::${accountId}:role/checkout-${environment}-*`
        : resource === bootstrapRoleArns(config).bootstrapCloudFormationExecutionRoleArn;
    case 'IAM_APPLICATION_ROLE':
      return resource === `arn:aws:iam::${accountId}:role/checkout-${environment}-*`;
    case 'IAM_MANAGED_POLICY':
      return (
        resource === `arn:aws:iam::${accountId}:policy/checkout-stage7-${environment}-*` ||
        resource === `arn:aws:iam::${accountId}:policy/stage7/${environment}/*` ||
        (roleKey === 'readRoleArn' && authorizedPolicyArns.includes(resource))
      );
    case 'IAM_RELEASE_ROLE':
      return roleKey === 'bootstrapCloudFormationExecutionRoleArn'
        ? resource === `arn:aws:iam::${accountId}:role/checkout-${environment}-*`
        : (roleKey === 'readRoleArn' ? authorizedRoleArns : [auditedRoleArn]).includes(resource);
    case 'LAMBDA_FUNCTION':
      return (
        resource === `arn:aws:lambda:${region}:${accountId}:function:checkout-${environment}-*`
      );
    case 'LOG_GROUP':
      return (
        resource === `arn:aws:logs:${region}:${accountId}:log-group:/checkout-${environment}/*:*`
      );
    case 'ROUTE53_CHANGE':
      return resource === 'arn:aws:route53:::change/*';
    case 'ROUTE53_ZONE':
      return (
        config.domain?.hostedZoneId !== null &&
        resource === `arn:aws:route53:::hostedzone/${config.domain.hostedZoneId}`
      );
    case 'S3_BUCKET':
      if (['bootstrapDeployRoleArn', 'bootstrapFilePublishingRoleArn'].includes(roleKey)) {
        return resource === `arn:aws:s3:::cdk-hnb659fds-assets-${accountId}-${region}`;
      }
      return resource === `arn:aws:s3:::checkout-${environment}-*`;
    case 'S3_OBJECT':
      if (['bootstrapDeployRoleArn', 'bootstrapFilePublishingRoleArn'].includes(roleKey)) {
        return resource === `arn:aws:s3:::cdk-hnb659fds-assets-${accountId}-${region}/*`;
      }
      if (roleKey === 'rollbackRoleArn') {
        return [
          `arn:aws:s3:::checkout-${environment}-*/index.html`,
          `arn:aws:s3:::checkout-${environment}-*/public-config.json`,
        ].includes(resource);
      }
      return resource === `arn:aws:s3:::checkout-${environment}-*/*`;
    case 'SCHEDULER':
      return (
        resource ===
        `arn:aws:scheduler:${region}:${accountId}:schedule/default/checkout-${environment}-*`
      );
    case 'SECRETS_MANAGER_SECRET':
      if (['rollbackRoleArn', 'bootstrapCloudFormationExecutionRoleArn'].includes(roleKey)) {
        return resource === config.prereleaseAccess?.originTokenSecretArn;
      }
      return (
        resource.startsWith(`arn:aws:secretsmanager:${region}:${accountId}:secret:`) &&
        (config.credentialReferences ?? []).includes(resource)
      );
    case 'SNS_TOPIC':
      return (
        resource ===
        (['baselineRoleArn', 'bootstrapCloudFormationExecutionRoleArn'].includes(roleKey)
          ? `arn:aws:sns:${region}:${accountId}:checkout-${environment}-alerts`
          : `arn:aws:sns:${region}:${accountId}:checkout-${environment}-*`)
      );
    case 'SSM_PARAMETER':
      if (
        ['readRoleArn', 'deployRoleArn', 'rollbackRoleArn'].includes(roleKey) &&
        actions.includes('ssm:getparametersbypath')
      ) {
        return (
          actions.length === 1 &&
          releaseMutationGuardReadResources(config, permissionContext?.candidateSha).includes(
            resource,
          )
        );
      }
      if (roleKey === 'rollbackRoleArn') {
        const allowedResources = actions.includes('ssm:putparameter')
          ? rollbackJournalWriteResources(config, permissionContext?.candidateSha)
          : rollbackJournalReadResources(config, permissionContext?.candidateSha);
        return allowedResources.includes(resource);
      }
      if (['bootstrapDeployRoleArn', 'bootstrapLookupRoleArn'].includes(roleKey)) {
        return (
          resource ===
          `arn:aws:ssm:${region}:${accountId}:parameter/cdk-bootstrap/hnb659fds/version`
        );
      }
      return (
        (resource.startsWith(`arn:aws:ssm:${region}:${accountId}:parameter/`) &&
          (config.credentialReferences ?? []).includes(resource)) ||
        resource === `arn:aws:ssm:${region}:${accountId}:parameter/checkout/${environment}/*`
      );
    case 'STS_BOOTSTRAP_ROLE':
      return bootstrapRoleResources(config, roleKey).includes(resource);
    case 'CDK_ASSET_REPOSITORY':
      return (
        resource ===
        `arn:aws:ecr:${region}:${accountId}:repository/cdk-hnb659fds-container-assets-${accountId}-${region}`
      );
    default:
      return false;
  }
};

const mandatoryResourcesForRequiredAction = ({
  action,
  roleKey,
  config,
  authorizedRoleArns,
  authorizedPolicyArns,
  auditedRoleArn,
  permissionContext,
}) => {
  const { accountId, region } = config.aws;
  const environment = config.environment;
  const resourceClass = RESOURCE_CLASS_BY_ACTION.get(action);
  if (resourceClass === 'GLOBAL_RESOURCE_REQUIRED') return ['*'];
  if (resourceClass === 'CLOUDWATCH_METRIC_NAMESPACE') return ['*'];
  if (resourceClass === 'IAM_RELEASE_ROLE') {
    return roleKey === 'bootstrapCloudFormationExecutionRoleArn'
      ? [`arn:aws:iam::${accountId}:role/checkout-${environment}-*`]
      : roleKey === 'readRoleArn'
        ? authorizedRoleArns
        : [auditedRoleArn];
  }
  if (resourceClass === 'IAM_MANAGED_POLICY' && roleKey === 'readRoleArn') {
    return authorizedPolicyArns;
  }
  if (resourceClass === 'CLOUDFORMATION_STACK') {
    return cloudFormationStackResources(config, roleKey);
  }
  if (resourceClass === 'CLOUDFORMATION_CHANGE_SET_STACK') {
    return cloudFormationChangeSetResources(config, roleKey);
  }
  if (resourceClass === 'API_GATEWAY_TAGGED') {
    return roleKey === 'bootstrapCloudFormationExecutionRoleArn'
      ? [
          `arn:aws:apigateway:${region}::/apis`,
          `arn:aws:apigateway:${region}::/apis/*`,
          `arn:aws:apigateway:${region}::/domainnames/${config.domain?.apiHostname}`,
          `arn:aws:apigateway:${region}::/domainnames/${config.domain?.apiHostname}/apimappings`,
          `arn:aws:apigateway:${region}::/domainnames/${config.domain?.apiHostname}/apimappings/*`,
        ]
      : [
          `arn:aws:apigateway:${region}::/apis/*`,
          ...(typeof config.domain?.apiHostname === 'string'
            ? [
                `arn:aws:apigateway:${region}::/domainnames/${config.domain.apiHostname}/apimappings`,
              ]
            : []),
        ];
  }
  if (resourceClass === 'IAM_BOOTSTRAP_EXECUTION_ROLE') {
    return [
      roleKey === 'bootstrapCloudFormationExecutionRoleArn'
        ? `arn:aws:iam::${accountId}:role/checkout-${environment}-*`
        : bootstrapRoleArns(config).bootstrapCloudFormationExecutionRoleArn,
    ];
  }
  if (resourceClass === 'IAM_APPLICATION_ROLE') {
    return [`arn:aws:iam::${accountId}:role/checkout-${environment}-*`];
  }
  if (resourceClass === 'CLOUDFRONT_STAGE7_RESOURCE') {
    return [
      `arn:aws:cloudfront::${accountId}:distribution/*`,
      `arn:aws:cloudfront::${accountId}:function/checkout-${environment}-*`,
      `arn:aws:cloudfront::${accountId}:origin-access-control/*`,
      `arn:aws:cloudfront::${accountId}:response-headers-policy/*`,
    ];
  }
  if (resourceClass === 'CLOUDWATCH_STAGE7_RESOURCE') {
    return [
      `arn:aws:cloudwatch:${region}:${accountId}:alarm:checkout-${environment}-*`,
      `arn:aws:cloudwatch::${accountId}:dashboard/checkout-${environment}-*`,
    ];
  }
  if (resourceClass === 'CLOUDWATCH_ALARM' && roleKey === 'rollbackRoleArn') {
    return [
      `arn:aws:cloudwatch:${region}:${accountId}:alarm:checkout-${environment}-rollback-rehearsal`,
    ];
  }
  if (resourceClass === 'DYNAMODB_TABLE_AND_INDEX') {
    return roleKey === 'rollbackRoleArn'
      ? [
          `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*/index/GSI2-PendingAge`,
        ]
      : [
          `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*`,
          `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*/index/*`,
        ];
  }
  if (resourceClass === 'S3_OBJECT' && roleKey === 'rollbackRoleArn') {
    return [
      `arn:aws:s3:::checkout-${environment}-*/index.html`,
      `arn:aws:s3:::checkout-${environment}-*/public-config.json`,
    ];
  }
  if (action === 's3:getbucketversioning' && roleKey === 'baselineRoleArn') {
    return [`arn:aws:s3:::checkout-${environment}-*`];
  }
  if (action === 'sns:listsubscriptionsbytopic' && roleKey === 'baselineRoleArn') {
    return [`arn:aws:sns:${region}:${accountId}:checkout-${environment}-alerts`];
  }
  if (resourceClass === 'SECRETS_MANAGER_SECRET') {
    if (['rollbackRoleArn', 'bootstrapCloudFormationExecutionRoleArn'].includes(roleKey)) {
      return typeof config.prereleaseAccess?.originTokenSecretArn === 'string'
        ? [config.prereleaseAccess.originTokenSecretArn]
        : [];
    }
    return (config.credentialReferences ?? []).filter((resource) =>
      resource.startsWith(`arn:aws:secretsmanager:${region}:${accountId}:secret:`),
    );
  }
  if (resourceClass === 'SSM_PARAMETER' && roleKey === 'rollbackRoleArn') {
    if (action === 'ssm:getparametersbypath') {
      return releaseMutationGuardReadResources(config, permissionContext?.candidateSha);
    }
    return action === 'ssm:putparameter'
      ? rollbackJournalWriteResources(config, permissionContext?.candidateSha)
      : rollbackJournalReadResources(config, permissionContext?.candidateSha);
  }
  if (
    resourceClass === 'SSM_PARAMETER' &&
    ['readRoleArn', 'deployRoleArn'].includes(roleKey) &&
    action === 'ssm:getparametersbypath'
  ) {
    return releaseMutationGuardReadResources(config, permissionContext?.candidateSha);
  }
  if (resourceClass === 'S3_BUCKET') {
    const assetBucket = `arn:aws:s3:::cdk-${CDK_BOOTSTRAP_QUALIFIER}-assets-${accountId}-${region}`;
    if (['bootstrapDeployRoleArn', 'bootstrapFilePublishingRoleArn'].includes(roleKey)) {
      return [assetBucket];
    }
    return [`arn:aws:s3:::checkout-${environment}-*`];
  }
  if (resourceClass === 'S3_OBJECT') {
    const assetObjects = `arn:aws:s3:::cdk-${CDK_BOOTSTRAP_QUALIFIER}-assets-${accountId}-${region}/*`;
    if (['bootstrapDeployRoleArn', 'bootstrapFilePublishingRoleArn'].includes(roleKey)) {
      return [assetObjects];
    }
    if (roleKey === 'rollbackRoleArn') {
      return [
        `arn:aws:s3:::checkout-${environment}-*/index.html`,
        `arn:aws:s3:::checkout-${environment}-*/public-config.json`,
      ];
    }
    return [`arn:aws:s3:::checkout-${environment}-*/*`];
  }
  if (resourceClass === 'STS_BOOTSTRAP_ROLE') return bootstrapRoleResources(config, roleKey);
  return [];
};

const normalizeStatement = ({
  statement,
  roleKey,
  config,
  sourceType,
  authorizedRoleArns,
  authorizedPolicyArns,
  auditedRoleArn,
  permissionContext,
}) => {
  if (!object(statement)) fail('E7_IAM_POLICY_STATEMENT_INVALID');
  if ('NotAction' in statement || 'NotResource' in statement) {
    fail('E7_IAM_NOT_ACTION_OR_RESOURCE_FORBIDDEN');
  }
  if (
    !Object.keys(statement).every((key) =>
      ['Sid', 'Effect', 'Action', 'Resource', 'Condition'].includes(key),
    ) ||
    !['Allow', 'Deny'].includes(statement.Effect) ||
    (statement.Sid !== undefined &&
      (typeof statement.Sid !== 'string' || statement.Sid.length > 128)) ||
    (statement.Condition !== undefined && !object(statement.Condition))
  ) {
    fail('E7_IAM_POLICY_STATEMENT_INVALID');
  }
  const actions = strings(statement.Action, 'E7_IAM_POLICY_ACTION_INVALID').map((action) =>
    action.toLowerCase(),
  );
  const resources = strings(statement.Resource, 'E7_IAM_POLICY_RESOURCE_INVALID');
  if (new Set(actions).size !== actions.length) fail('E7_IAM_POLICY_ACTION_INVALID');

  if (statement.Effect === 'Allow') {
    const allowed = new Set(IAM_ROLE_PERMISSION_PROFILES[roleKey].actions);
    const resourceClasses = new Set();
    for (const action of actions) {
      if (action === '*' || action.includes('*')) fail('E7_IAM_ALLOW_ACTION_WILDCARD');
      if (!allowed.has(action)) fail('E7_IAM_CAPABILITY_OUTSIDE_ROLE_PROFILE');
      resourceClasses.add(RESOURCE_CLASS_BY_ACTION.get(action));
    }
    if (resourceClasses.size !== 1) fail('E7_IAM_MIXED_RESOURCE_CLASSES');
    const resourceClass = [...resourceClasses][0];
    const condition = normalizeAllowedCondition({
      condition: statement.Condition,
      resourceClass,
      config,
      roleKey,
      actions,
    });
    if (
      resources.some(
        (resource) =>
          !resourceAllowed({
            resource,
            resourceClass,
            config,
            roleKey,
            authorizedRoleArns,
            authorizedPolicyArns,
            auditedRoleArn,
            actions,
            permissionContext,
          }),
      )
    ) {
      fail(
        resources.includes('*')
          ? 'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC'
          : 'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
      );
    }
    if (
      roleKey === 'baselineRoleArn' &&
      actions.includes('s3:getbucketversioning') &&
      (resources.length !== 1 || resources[0] !== `arn:aws:s3:::checkout-${config.environment}-*`)
    ) {
      fail('E7_IAM_BASELINE_VERSIONING_SCOPE_INVALID');
    }
    return {
      ...(statement.Sid === undefined ? {} : { Sid: statement.Sid }),
      Effect: statement.Effect,
      Action: actions.toSorted(),
      Resource: [...resources].toSorted(),
      ...(condition === null ? {} : { Condition: condition }),
      resourceClass,
      sourceType,
    };
  }

  if (statement.Condition !== undefined) fail('E7_IAM_CONDITION_NOT_ALLOWLISTED');
  if (actions.some((action) => action !== '*' && action.includes('*'))) {
    fail('E7_IAM_DENY_WILDCARD_UNSUPPORTED');
  }
  if (resources.length !== 1 || resources[0] !== '*') {
    fail('E7_IAM_DENY_SCOPE_UNSUPPORTED');
  }

  return {
    ...(statement.Sid === undefined ? {} : { Sid: statement.Sid }),
    Effect: statement.Effect,
    Action: actions.toSorted(),
    Resource: [...resources].toSorted(),
    resourceClass: 'DENY',
    sourceType,
  };
};

export const normalizeIamPolicyDocument = ({
  document,
  roleKey,
  config,
  sourceType,
  auditedRoleArn = config?.aws?.roles?.[roleKey],
  authorizedRoleArns = [...new Set([...Object.values(config?.aws?.roles ?? {}), auditedRoleArn])],
  authorizedPolicyArns = [],
  permissionContext = null,
}) => {
  if (
    !IAM_PROFILE_KEYS.includes(roleKey) ||
    !object(config) ||
    !object(config.aws) ||
    !/^[0-9]{12}$/u.test(config.aws.accountId ?? '') ||
    typeof config.aws.region !== 'string' ||
    typeof config.environment !== 'string' ||
    !['INLINE', 'ATTACHED', 'BOUNDARY'].includes(sourceType) ||
    !object(document) ||
    (permissionContext !== null &&
      (!object(permissionContext) ||
        !SHA.test(permissionContext.candidateSha ?? '') ||
        !RELEASE_ID.test(permissionContext.releaseId ?? ''))) ||
    !Object.keys(document).every((key) => ['Version', 'Id', 'Statement'].includes(key)) ||
    document.Version !== '2012-10-17' ||
    (document.Id !== undefined && typeof document.Id !== 'string')
  ) {
    fail('E7_IAM_POLICY_DOCUMENT_INVALID');
  }
  if (
    !Array.isArray(authorizedRoleArns) ||
    authorizedRoleArns.length === 0 ||
    new Set(authorizedRoleArns).size !== authorizedRoleArns.length ||
    authorizedRoleArns.some(
      (roleArn) => parseIamRoleArn(roleArn)?.accountId !== config.aws.accountId,
    ) ||
    !hasUniqueIamRoleNames(authorizedRoleArns)
  ) {
    fail('E7_IAM_AUTHORIZED_ROLE_SET_INVALID');
  }
  if (
    !Array.isArray(authorizedPolicyArns) ||
    new Set(authorizedPolicyArns).size !== authorizedPolicyArns.length ||
    authorizedPolicyArns.some(
      (policyArn) => IAM_POLICY_ARN.exec(policyArn ?? '')?.[2] !== config.aws.accountId,
    )
  ) {
    fail('E7_IAM_AUTHORIZED_POLICY_SET_INVALID');
  }
  const sourceStatements = Array.isArray(document.Statement)
    ? document.Statement
    : [document.Statement];
  if (sourceStatements.length === 0 || sourceStatements.length > 256) {
    fail('E7_IAM_POLICY_DOCUMENT_INVALID');
  }
  const normalizedStatements = sourceStatements
    .map((statement) =>
      normalizeStatement({
        statement,
        roleKey,
        config,
        sourceType,
        authorizedRoleArns,
        authorizedPolicyArns,
        auditedRoleArn,
        permissionContext,
      }),
    )
    .toSorted((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  const allowActions = new Set();
  const allowGrants = [];
  const deniedActions = new Set();
  let denyAll = false;
  for (const statement of normalizedStatements) {
    if (statement.Effect === 'Allow') {
      for (const action of statement.Action) {
        allowActions.add(action);
        allowGrants.push({
          action,
          resourceClass: statement.resourceClass,
          resources: statement.Resource,
          resourcesSha256: objectSha256(statement.Resource),
          conditionSha256: objectSha256(statement.Condition ?? null),
        });
      }
    } else {
      if (statement.Action.includes('*')) denyAll = true;
      for (const action of statement.Action.filter((entry) => entry !== '*')) {
        deniedActions.add(action);
      }
    }
  }
  const normalized = {
    Version: document.Version,
    ...(document.Id === undefined ? {} : { Id: document.Id }),
    Statement: normalizedStatements,
  };
  return {
    sourceType,
    normalized,
    sha256: objectSha256(normalized),
    allowActions: [...allowActions].toSorted(),
    allowGrants: allowGrants.toSorted((left, right) =>
      canonicalJson(left).localeCompare(canonicalJson(right)),
    ),
    deniedActions: [...deniedActions].toSorted(),
    denyAll,
  };
};

const roleParts = (roleArn, accountId) => {
  const identity = parseIamRoleArn(roleArn);
  if (identity === null || identity.accountId !== accountId) fail('E7_IAM_ROLE_ARN_INVALID');
  return { roleName: identity.roleName };
};

const managedPolicyParts = (policyArn, accountId) => {
  const match = IAM_POLICY_ARN.exec(policyArn ?? '');
  if (match === null || (match[1] !== 'aws' && match[2] !== accountId)) {
    fail('E7_IAM_MANAGED_POLICY_ARN_INVALID');
  }
  const policyName = match[3].split('/').at(-1);
  if (!POLICY_NAME.test(policyName ?? '')) fail('E7_IAM_MANAGED_POLICY_ARN_INVALID');
  if (policyName === 'AdministratorAccess') {
    fail('E7_IAM_ADMINISTRATOR_ACCESS_FORBIDDEN');
  }
  return { policyName };
};

const listAll = ({ call, operation, roleName, field }) => {
  const entries = [];
  const seenTokens = new Set();
  let startingToken;
  for (let page = 0; page < 100; page += 1) {
    const arguments_ = ['--role-name', roleName, '--page-size', '100', '--max-items', '100'];
    if (startingToken !== undefined) arguments_.push('--starting-token', startingToken);
    const response = call('iam', operation, arguments_);
    if (!object(response) || !Array.isArray(response[field])) {
      fail('E7_IAM_LIST_RESPONSE_INVALID');
    }
    entries.push(...response[field]);
    if (response.NextToken === undefined) {
      if (response.IsTruncated === true || response.Marker !== undefined) {
        fail('E7_IAM_PAGINATION_INVALID');
      }
      return entries;
    }
    const next = response.NextToken;
    if (typeof next !== 'string' || next.length === 0 || seenTokens.has(next)) {
      fail('E7_IAM_PAGINATION_INVALID');
    }
    seenTokens.add(next);
    startingToken = next;
  }
  fail('E7_IAM_PAGINATION_LIMIT_EXCEEDED');
};

const readManagedPolicy = ({
  call,
  policyArn,
  config,
  roleKey,
  sourceType,
  auditedRoleArn,
  authorizedRoleArns,
  authorizedPolicyArns,
  permissionContext,
  cache,
}) => {
  const accountId = config.aws.accountId;
  const policyParts = managedPolicyParts(policyArn, accountId);
  const cacheKey = `${roleKey}\0${sourceType}\0${policyArn}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined) return cached;
  const metadata = call('iam', 'get-policy', ['--policy-arn', policyArn]);
  const policy = metadata?.Policy;
  if (
    !object(policy) ||
    policy.Arn !== policyArn ||
    policy.PolicyName !== policyParts.policyName ||
    !POLICY_VERSION_ID.test(policy.DefaultVersionId ?? '') ||
    policy.PolicyName === 'AdministratorAccess'
  ) {
    fail('E7_IAM_MANAGED_POLICY_METADATA_INVALID');
  }
  const version = call('iam', 'get-policy-version', [
    '--policy-arn',
    policyArn,
    '--version-id',
    policy.DefaultVersionId,
  ]);
  if (
    version?.PolicyVersion?.VersionId !== policy.DefaultVersionId ||
    version.PolicyVersion.IsDefaultVersion !== true ||
    !object(version.PolicyVersion.Document)
  ) {
    fail('E7_IAM_MANAGED_POLICY_VERSION_INVALID');
  }
  const normalized = normalizeIamPolicyDocument({
    document: version.PolicyVersion.Document,
    roleKey,
    config,
    sourceType,
    auditedRoleArn,
    authorizedRoleArns,
    authorizedPolicyArns,
    permissionContext,
  });
  const result = {
    ...normalized,
    policyArnSha256: sha256(policyArn),
    policyVersionIdSha256: sha256(policy.DefaultVersionId),
  };
  cache.set(cacheKey, result);
  return result;
};

const grantIdentity = (grant) =>
  canonicalJson({
    action: grant.action,
    resourceClass: grant.resourceClass,
    resources: grant.resources,
    conditionSha256: grant.conditionSha256,
  });

const sourcePolicyDigest = (policy) =>
  objectSha256({
    sourceType: policy.sourceType,
    documentSha256: policy.sha256,
    identifierSha256:
      policy.sourceType === 'INLINE' ? policy.policyNameSha256 : policy.policyArnSha256,
    policyVersionIdSha256: policy.sourceType === 'INLINE' ? null : policy.policyVersionIdSha256,
  });

const effectiveGrantsFor = ({ identityPolicies, boundary }) => {
  let grants = new Map(
    identityPolicies
      .flatMap((policy) => policy.allowGrants)
      .map((grant) => [grantIdentity(grant), grant]),
  );
  const denied = new Set(identityPolicies.flatMap((policy) => policy.deniedActions));
  if (identityPolicies.some((policy) => policy.denyAll)) grants.clear();
  grants = new Map([...grants].filter(([, grant]) => !denied.has(grant.action)));
  if (boundary !== null) {
    const boundaryGrants = new Set(boundary.allowGrants.map(grantIdentity));
    grants = new Map([...grants].filter(([identity]) => boundaryGrants.has(identity)));
    if (boundary.denyAll) grants.clear();
    const boundaryDenied = new Set(boundary.deniedActions);
    grants = new Map([...grants].filter(([, grant]) => !boundaryDenied.has(grant.action)));
  }
  return [...grants.values()].toSorted((left, right) =>
    grantIdentity(left).localeCompare(grantIdentity(right)),
  );
};

const auditRole = ({
  call,
  config,
  roleKey,
  roleArn = config.aws.roles[roleKey],
  scope,
  validateTrust,
  managedPolicyCache,
  authorizedRoleArns,
  authorizedPolicyArns,
  permissionContext,
}) => {
  const accountId = config.aws.accountId;
  const { roleName } = roleParts(roleArn, accountId);
  const response = call('iam', 'get-role', ['--role-name', roleName]);
  const role = response?.Role;
  const trustIsValid = BOOTSTRAP_ROLE_KEYS.includes(roleKey)
    ? validateBootstrapTrust({
        policy: role?.AssumeRolePolicyDocument,
        config,
        scope,
        roleKey,
      })
    : validateTrust({
        policy: role?.AssumeRolePolicyDocument,
        accountId,
        roleArn,
        roleKey,
        expectedSubjects: IAM_ROLE_PERMISSION_PROFILES[roleKey].oidcSubjects[scope],
      });
  if (
    !object(role) ||
    role.Arn !== roleArn ||
    role.RoleName !== roleName ||
    !object(role.AssumeRolePolicyDocument) ||
    trustIsValid !== true
  ) {
    fail('E7_IAM_ROLE_OR_TRUST_INVALID');
  }

  const inlineNames = listAll({
    call,
    operation: 'list-role-policies',
    roleName,
    field: 'PolicyNames',
  });
  if (
    inlineNames.some((name) => !POLICY_NAME.test(name ?? '')) ||
    new Set(inlineNames).size !== inlineNames.length
  ) {
    fail('E7_IAM_INLINE_POLICY_LIST_INVALID');
  }
  const inlinePolicies = inlineNames.toSorted().map((policyName) => {
    const inline = call('iam', 'get-role-policy', [
      '--role-name',
      roleName,
      '--policy-name',
      policyName,
    ]);
    if (
      inline?.RoleName !== roleName ||
      inline.PolicyName !== policyName ||
      !object(inline.PolicyDocument)
    ) {
      fail('E7_IAM_INLINE_POLICY_DOCUMENT_INVALID');
    }
    return {
      ...normalizeIamPolicyDocument({
        document: inline.PolicyDocument,
        roleKey,
        config,
        sourceType: 'INLINE',
        auditedRoleArn: roleArn,
        authorizedRoleArns,
        authorizedPolicyArns,
        permissionContext,
      }),
      policyNameSha256: sha256(policyName),
    };
  });

  const attachedEntries = listAll({
    call,
    operation: 'list-attached-role-policies',
    roleName,
    field: 'AttachedPolicies',
  });
  if (
    attachedEntries.some(
      (entry) =>
        !object(entry) ||
        !POLICY_NAME.test(entry.PolicyName ?? '') ||
        typeof entry.PolicyArn !== 'string',
    ) ||
    new Set(attachedEntries.map((entry) => entry.PolicyArn)).size !== attachedEntries.length
  ) {
    fail('E7_IAM_ATTACHED_POLICY_LIST_INVALID');
  }
  const attachedPolicies = attachedEntries
    .toSorted((left, right) => left.PolicyArn.localeCompare(right.PolicyArn))
    .map((entry) => {
      const parts = managedPolicyParts(entry.PolicyArn, accountId);
      if (parts.policyName !== entry.PolicyName) fail('E7_IAM_ATTACHED_POLICY_LIST_INVALID');
      return readManagedPolicy({
        call,
        policyArn: entry.PolicyArn,
        config,
        roleKey,
        sourceType: 'ATTACHED',
        auditedRoleArn: roleArn,
        authorizedRoleArns,
        authorizedPolicyArns,
        permissionContext,
        cache: managedPolicyCache,
      });
    });

  let boundary = null;
  let boundarySummary = {
    status: 'ABSENT',
    policyArnSha256: null,
    policyVersionIdSha256: null,
    documentSha256: null,
  };
  if (role.PermissionsBoundary !== undefined) {
    if (
      !exactKeys(role.PermissionsBoundary, ['PermissionsBoundaryType', 'PermissionsBoundaryArn']) ||
      role.PermissionsBoundary.PermissionsBoundaryType !== 'Policy'
    ) {
      fail('E7_IAM_PERMISSIONS_BOUNDARY_INVALID');
    }
    boundary = readManagedPolicy({
      call,
      policyArn: role.PermissionsBoundary.PermissionsBoundaryArn,
      config,
      roleKey,
      sourceType: 'BOUNDARY',
      auditedRoleArn: roleArn,
      authorizedRoleArns,
      authorizedPolicyArns,
      permissionContext,
      cache: managedPolicyCache,
    });
    boundarySummary = {
      status: 'PRESENT_AND_VALID',
      policyArnSha256: boundary.policyArnSha256,
      policyVersionIdSha256: boundary.policyVersionIdSha256,
      documentSha256: boundary.sha256,
    };
  }

  const identityPolicies = [...inlinePolicies, ...attachedPolicies];
  if (identityPolicies.length === 0) fail('E7_IAM_IDENTITY_POLICY_MISSING');
  const effectiveGrants = effectiveGrantsFor({ identityPolicies, boundary });
  const effectiveActions = [...new Set(effectiveGrants.map((grant) => grant.action))].toSorted();
  const requiredActions = requiredActionsFor(roleKey, scope);
  if (
    effectiveActions.length === 0 ||
    requiredActions.some((action) => !effectiveActions.includes(action))
  ) {
    fail('E7_IAM_REQUIRED_EFFECTIVE_PERMISSION_MISSING');
  }
  for (const action of requiredActions) {
    const resources = new Set(
      effectiveGrants
        .filter((grant) => grant.action === action)
        .flatMap((grant) => grant.resources),
    );
    const mandatoryResources = mandatoryResourcesForRequiredAction({
      action,
      roleKey,
      config,
      authorizedRoleArns,
      authorizedPolicyArns,
      auditedRoleArn: roleArn,
      permissionContext,
    });
    if (mandatoryResources.some((resource) => !resources.has(resource))) {
      fail('E7_IAM_REQUIRED_RESOURCE_COVERAGE_MISSING');
    }
  }
  const sourcePolicySha256 = identityPolicies.map(sourcePolicyDigest).toSorted();
  const effectiveGrantSummaries = effectiveGrants.map((grant) => ({
    action: grant.action,
    resourceClass: grant.resourceClass,
    resourcesSha256: grant.resourcesSha256,
    conditionSha256: grant.conditionSha256,
  }));
  const globalResourceAllows = effectiveGrantSummaries.filter(
    (grant) => grant.resourcesSha256 === objectSha256(['*']),
  );
  const effectiveGrantsSha256 = objectSha256(effectiveGrantSummaries);
  const globalResourceAllowsSha256 = objectSha256(globalResourceAllows);
  const permissionSetSha256 = objectSha256({
    roleKey,
    capability: IAM_ROLE_PERMISSION_PROFILES[roleKey].capability,
    allowlistSha256: objectSha256(rolePermissionContract(roleKey)),
    trustPolicySha256: objectSha256(role.AssumeRolePolicyDocument),
    oidcSubjectsSha256: objectSha256(IAM_ROLE_PERMISSION_PROFILES[roleKey].oidcSubjects[scope]),
    sourcePolicySha256,
    boundaryPolicyArnSha256: boundary?.policyArnSha256 ?? null,
    boundaryPolicyVersionIdSha256: boundary?.policyVersionIdSha256 ?? null,
    boundaryDocumentSha256: boundary?.sha256 ?? null,
    effectiveActions,
    effectiveGrantCount: effectiveGrantSummaries.length,
    effectiveGrantsSha256,
    globalResourceAllowCount: globalResourceAllows.length,
    globalResourceAllowsSha256,
  });
  return {
    roleKey,
    capability: IAM_ROLE_PERMISSION_PROFILES[roleKey].capability,
    status: 'PASS',
    roleArnSha256: sha256(roleArn),
    trustPolicySha256: objectSha256(role.AssumeRolePolicyDocument),
    oidcSubjectCount: IAM_ROLE_PERMISSION_PROFILES[roleKey].oidcSubjects[scope].length,
    oidcSubjectsSha256: objectSha256(IAM_ROLE_PERMISSION_PROFILES[roleKey].oidcSubjects[scope]),
    allowlistSha256: objectSha256(rolePermissionContract(roleKey)),
    inlinePolicyCount: inlinePolicies.length,
    attachedPolicyCount: attachedPolicies.length,
    sourcePolicySha256,
    boundary: boundarySummary,
    effectiveActions,
    effectiveActionsSha256: objectSha256(effectiveActions),
    effectiveGrantCount: effectiveGrantSummaries.length,
    effectiveGrantsSha256,
    globalResourceAllowCount: globalResourceAllows.length,
    globalResourceAllowsSha256,
    permissionSetSha256,
  };
};

const evidenceBinding = (value) =>
  objectSha256({
    contractVersion: value.contractVersion,
    contractSha256: value.contractSha256,
    scope: value.scope,
    candidateSha: value.candidateSha,
    releaseId: value.releaseId,
    manifestSha256: value.manifestSha256,
    configSha256: value.configSha256,
    accountSha256: value.accountSha256,
    roles: Object.fromEntries(
      ROLE_KEYS.map((roleKey) => [roleKey, value.roles[roleKey].permissionSetSha256]),
    ),
    cleanupWatchdog: value.cleanupWatchdog,
    baselineRole: value.baselineRole,
    bootstrapRoles: value.bootstrapRoles,
    auxiliaryRoleAuthorities: value.auxiliaryRoleAuthorities,
  });

const resolveAuxiliaryRoleAuthorities = ({
  config,
  scope,
  manifestSha256,
  journalRoleArn,
  journalPermissionsBoundaryArn,
  reconciliationRecoveryRoleArn,
  reconciliationRecoveryPermissionsBoundaryArn,
}) => {
  const supplied = [
    journalRoleArn,
    journalPermissionsBoundaryArn,
    reconciliationRecoveryRoleArn,
    reconciliationRecoveryPermissionsBoundaryArn,
  ];
  if (scope !== 'full' || manifestSha256 === null) {
    if (supplied.some((value) => value !== null)) {
      fail('E7_IAM_AUXILIARY_ROLE_AUTHORITY_SCOPE_INVALID');
    }
    return null;
  }
  const roleArns = [journalRoleArn, reconciliationRecoveryRoleArn];
  const policyArns = [journalPermissionsBoundaryArn, reconciliationRecoveryPermissionsBoundaryArn];
  const existingRoleArns = [
    ...Object.values(config.aws.roles),
    ...Object.values(bootstrapRoleArns(config)),
  ];
  if (
    roleArns.some((roleArn) => parseIamRoleArn(roleArn)?.accountId !== config.aws.accountId) ||
    policyArns.some(
      (policyArn) => IAM_POLICY_ARN.exec(policyArn ?? '')?.[2] !== config.aws.accountId,
    ) ||
    new Set(roleArns).size !== roleArns.length ||
    !hasUniqueIamRoleNames([...existingRoleArns, ...roleArns]) ||
    new Set(policyArns).size !== policyArns.length ||
    roleArns.some((roleArn) => existingRoleArns.includes(roleArn))
  ) {
    fail('E7_IAM_AUXILIARY_ROLE_AUTHORITY_INVALID');
  }
  return Object.freeze({
    journalRoleArn,
    journalPermissionsBoundaryArn,
    reconciliationRecoveryRoleArn,
    reconciliationRecoveryPermissionsBoundaryArn,
    roleArns: Object.freeze(roleArns.toSorted()),
    policyArns: Object.freeze(policyArns.toSorted()),
  });
};

const sanitizedAuxiliaryRoleAuthorities = (authority, readRolePermissionSetSha256) => {
  if (authority === null) {
    return {
      status: 'NOT_APPLICABLE',
      journalRoleArnSha256: null,
      journalPermissionsBoundaryArnSha256: null,
      reconciliationRecoveryRoleArnSha256: null,
      reconciliationRecoveryPermissionsBoundaryArnSha256: null,
      readRolePermissionSetSha256,
      authoritySetSha256: null,
    };
  }
  const body = {
    status: 'PASS',
    journalRoleArnSha256: sha256(authority.journalRoleArn),
    journalPermissionsBoundaryArnSha256: sha256(authority.journalPermissionsBoundaryArn),
    reconciliationRecoveryRoleArnSha256: sha256(authority.reconciliationRecoveryRoleArn),
    reconciliationRecoveryPermissionsBoundaryArnSha256: sha256(
      authority.reconciliationRecoveryPermissionsBoundaryArn,
    ),
    readRolePermissionSetSha256,
  };
  return { ...body, authoritySetSha256: objectSha256(body) };
};

export const collectIamEffectivePermissions = ({
  config,
  scope,
  candidateSha,
  releaseId,
  manifestSha256 = null,
  bootstrapAssetInventory = null,
  cleanupWatchdogRoleArn = null,
  baselineRoleArn = null,
  journalRoleArn = null,
  journalPermissionsBoundaryArn = null,
  reconciliationRecoveryRoleArn = null,
  reconciliationRecoveryPermissionsBoundaryArn = null,
  callAws,
  validateTrust,
  now = new Date(),
}) => {
  if (
    !object(config) ||
    !object(config.aws) ||
    !object(config.aws.roles) ||
    !/^[0-9]{12}$/u.test(config.aws.accountId ?? '') ||
    !['full', 'prerelease', 'baseline'].includes(scope) ||
    !SHA.test(candidateSha ?? '') ||
    !RELEASE_ID.test(releaseId ?? '') ||
    (manifestSha256 !== null && !SHA256.test(manifestSha256 ?? '')) ||
    typeof callAws !== 'function' ||
    typeof validateTrust !== 'function' ||
    !(now instanceof Date) ||
    !Number.isFinite(now.getTime()) ||
    !ROLE_KEYS.every((roleKey) => typeof config.aws.roles[roleKey] === 'string') ||
    typeof config.aws.roles.baselineRoleArn !== 'string' ||
    Object.values(config.aws.roles).some(
      (roleArn) => parseIamRoleArn(roleArn)?.accountId !== config.aws.accountId,
    )
  ) {
    fail('E7_IAM_AUDIT_INPUT_INVALID');
  }
  const resolvedBootstrapAssetInventory =
    bootstrapAssetInventory ?? SELF_TEST_BOOTSTRAP_ASSET_INVENTORIES.get(config) ?? null;
  if (
    (manifestSha256 === null && resolvedBootstrapAssetInventory !== null) ||
    (manifestSha256 !== null &&
      (resolvedBootstrapAssetInventory === null ||
        validateBootstrapAssetInventory(resolvedBootstrapAssetInventory) !==
          resolvedBootstrapAssetInventory ||
        resolvedBootstrapAssetInventory.region !== config.aws.region))
  ) {
    fail('E7_IAM_BOOTSTRAP_ASSET_BINDING_INVALID');
  }
  const primaryRoleArns = ROLE_KEYS.map((roleKey) => config.aws.roles[roleKey]);
  if (
    new Set(primaryRoleArns).size !== ROLE_KEYS.length ||
    !hasUniqueIamRoleNames(primaryRoleArns)
  ) {
    fail('E7_IAM_ROLE_SEPARATION_REQUIRED');
  }
  const suppliedAuxiliaryRoleAuthorities = {
    journalRoleArn,
    journalPermissionsBoundaryArn,
    reconciliationRecoveryRoleArn,
    reconciliationRecoveryPermissionsBoundaryArn,
  };
  const selfTestAuxiliaryRoleAuthorities = SELF_TEST_AUXILIARY_ROLE_AUTHORITIES.get(config);
  const resolvedAuxiliaryRoleAuthorityInputs =
    Object.values(suppliedAuxiliaryRoleAuthorities).every((value) => value === null) &&
    scope === 'full' &&
    manifestSha256 !== null &&
    selfTestAuxiliaryRoleAuthorities !== undefined
      ? selfTestAuxiliaryRoleAuthorities
      : suppliedAuxiliaryRoleAuthorities;
  const auxiliaryRoleAuthority = resolveAuxiliaryRoleAuthorities({
    config,
    scope,
    manifestSha256,
    ...resolvedAuxiliaryRoleAuthorityInputs,
  });
  if (
    (scope === 'prerelease' &&
      (typeof cleanupWatchdogRoleArn !== 'string' ||
        parseIamRoleArn(cleanupWatchdogRoleArn)?.accountId !== config.aws.accountId ||
        Object.values(config.aws.roles).includes(cleanupWatchdogRoleArn))) ||
    (scope !== 'prerelease' && cleanupWatchdogRoleArn !== null)
  ) {
    fail('E7_IAM_CLEANUP_WATCHDOG_ROLE_REQUIRED');
  }
  if (
    (scope === 'baseline' &&
      (typeof baselineRoleArn !== 'string' ||
        baselineRoleArn !== config.aws.roles.baselineRoleArn ||
        parseIamRoleArn(baselineRoleArn)?.accountId !== config.aws.accountId ||
        ROLE_KEYS.some((roleKey) => config.aws.roles[roleKey] === baselineRoleArn))) ||
    (scope !== 'baseline' && baselineRoleArn !== null)
  ) {
    fail('E7_IAM_BASELINE_ROLE_SCOPE_INVALID');
  }
  const expectedBootstrapRoleArns = bootstrapRoleArns(config);
  const allAuditedRoleArns = [
    ...ROLE_KEYS.map((roleKey) => config.aws.roles[roleKey]),
    ...(scope === 'prerelease' ? [cleanupWatchdogRoleArn] : []),
    config.aws.roles.baselineRoleArn,
    ...Object.values(expectedBootstrapRoleArns),
  ];
  const allAuthorityRoleArns = [...allAuditedRoleArns, ...(auxiliaryRoleAuthority?.roleArns ?? [])];
  if (
    new Set(allAuthorityRoleArns).size !== allAuthorityRoleArns.length ||
    !hasUniqueIamRoleNames(allAuthorityRoleArns)
  ) {
    fail('E7_IAM_ROLE_SEPARATION_REQUIRED');
  }
  let externalRequests = 0;
  const call = (service, operation, arguments_) => {
    externalRequests += 1;
    const result = callAws(service, operation, arguments_);
    if (!object(result)) fail('E7_IAM_AWS_RESPONSE_INVALID');
    return result;
  };
  const managedPolicyCache = new Map();
  const permissionContext = Object.freeze({ candidateSha, releaseId });
  const authorizedRoleArns = [
    ...allAuditedRoleArns,
    ...(auxiliaryRoleAuthority?.roleArns ?? []),
  ].toSorted();
  const authorizedPolicyArns = auxiliaryRoleAuthority?.policyArns ?? [];
  const roles = Object.fromEntries(
    ROLE_KEYS.map((roleKey) => [
      roleKey,
      auditRole({
        call,
        config,
        roleKey,
        scope,
        validateTrust,
        managedPolicyCache,
        authorizedRoleArns,
        authorizedPolicyArns,
        permissionContext,
      }),
    ]),
  );
  const cleanupWatchdog =
    scope === 'prerelease'
      ? {
          status: 'PASS',
          role: auditRole({
            call,
            config,
            roleKey: 'cleanupWatchdogRoleArn',
            roleArn: cleanupWatchdogRoleArn,
            scope,
            validateTrust,
            managedPolicyCache,
            authorizedRoleArns,
            authorizedPolicyArns,
            permissionContext,
          }),
        }
      : { status: 'NOT_APPLICABLE', role: null };
  const baselineRole =
    scope === 'baseline'
      ? {
          status: 'PASS',
          role: auditRole({
            call,
            config,
            roleKey: 'baselineRoleArn',
            roleArn: baselineRoleArn,
            scope,
            validateTrust,
            managedPolicyCache,
            authorizedRoleArns,
            authorizedPolicyArns,
            permissionContext,
          }),
        }
      : { status: 'NOT_APPLICABLE', role: null };
  const bootstrapRoleEntries = Object.fromEntries(
    BOOTSTRAP_ROLE_KEYS.map((roleKey) => [
      roleKey,
      auditRole({
        call,
        config,
        roleKey,
        roleArn: expectedBootstrapRoleArns[roleKey],
        scope,
        validateTrust,
        managedPolicyCache,
        authorizedRoleArns,
        authorizedPolicyArns,
        permissionContext,
      }),
    ]),
  );
  const sanitizedPolicyTemplate = createSanitizedBootstrapPolicyTemplate({ config, scope });
  const bootstrapRoles = {
    status: 'PASS',
    qualifier: CDK_BOOTSTRAP_QUALIFIER,
    roleCount: BOOTSTRAP_ROLE_KEYS.length,
    trustBindingSha256: objectSha256(
      Object.fromEntries(
        BOOTSTRAP_ROLE_KEYS.map((roleKey) => [
          roleKey,
          bootstrapRoleEntries[roleKey].trustPolicySha256,
        ]),
      ),
    ),
    sanitizedPolicyTemplate,
    assetInventory:
      resolvedBootstrapAssetInventory === null
        ? { status: 'NOT_APPLICABLE_PRE_FREEZE', inventory: null }
        : { status: 'PASS', inventory: canonicalize(resolvedBootstrapAssetInventory) },
    roles: bootstrapRoleEntries,
  };
  const globalResourceAllows = [
    ...Object.values(roles),
    ...(cleanupWatchdog.role === null ? [] : [cleanupWatchdog.role]),
    ...(baselineRole.role === null ? [] : [baselineRole.role]),
    ...Object.values(bootstrapRoles.roles),
  ].map((role) => ({
    roleKey: role.roleKey,
    count: role.globalResourceAllowCount,
    sha256: role.globalResourceAllowsSha256,
  }));
  const value = {
    schemaVersion: 1,
    stage: 7,
    kind: 'IAM_EFFECTIVE_PERMISSIONS',
    artifactId: 'ART-REL-06',
    status: 'PASS',
    scope,
    generatedAtUtc: now.toISOString(),
    candidateSha,
    releaseId,
    manifestSha256,
    configSha256: objectSha256(config),
    accountSha256: sha256(config.aws.accountId),
    accountSuffix: config.aws.accountId.slice(-4),
    contractVersion: IAM_EFFECTIVE_PERMISSIONS_CONTRACT_VERSION,
    contractSha256: objectSha256(iamPermissionContract()),
    controls: {
      'RELAUD-11': 'PASS',
      'RELAUD-12': 'PASS',
      'RELAUD-13': 'PASS',
    },
    roles,
    cleanupWatchdog,
    baselineRole,
    bootstrapRoles,
    auxiliaryRoleAuthorities: sanitizedAuxiliaryRoleAuthorities(
      auxiliaryRoleAuthority,
      roles.readRoleArn.permissionSetSha256,
    ),
    effectivePermissions: 'PASS',
    administratorPolicies: 0,
    wildcardAllows: 0,
    globalResourceAllowCount: globalResourceAllows.reduce((total, role) => total + role.count, 0),
    globalResourceAllowsSha256: objectSha256(globalResourceAllows),
    outsideProfileCapabilities: 0,
    externalRequests,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return { ...value, bindingSha256: evidenceBinding(value) };
};

export const validateIamEffectivePermissionsEvidence = ({
  value,
  config,
  scope,
  candidateSha,
  releaseId,
  manifestSha256 = null,
  bootstrapAssetInventory = null,
  cleanupWatchdogRoleArn = null,
  baselineRoleArn = null,
  journalRoleArn = null,
  journalPermissionsBoundaryArn = null,
  reconciliationRecoveryRoleArn = null,
  reconciliationRecoveryPermissionsBoundaryArn = null,
}) => {
  const suppliedAuxiliaryRoleAuthorities = {
    journalRoleArn,
    journalPermissionsBoundaryArn,
    reconciliationRecoveryRoleArn,
    reconciliationRecoveryPermissionsBoundaryArn,
  };
  const selfTestAuxiliaryRoleAuthorities = SELF_TEST_AUXILIARY_ROLE_AUTHORITIES.get(config);
  const auxiliaryRoleAuthority = resolveAuxiliaryRoleAuthorities({
    config,
    scope,
    manifestSha256,
    ...(Object.values(suppliedAuxiliaryRoleAuthorities).every((entry) => entry === null) &&
    scope === 'full' &&
    manifestSha256 !== null &&
    selfTestAuxiliaryRoleAuthorities !== undefined
      ? selfTestAuxiliaryRoleAuthorities
      : suppliedAuxiliaryRoleAuthorities),
  });
  const keys = [
    'schemaVersion',
    'stage',
    'kind',
    'artifactId',
    'status',
    'scope',
    'generatedAtUtc',
    'candidateSha',
    'releaseId',
    'manifestSha256',
    'configSha256',
    'accountSha256',
    'accountSuffix',
    'contractVersion',
    'contractSha256',
    'controls',
    'roles',
    'cleanupWatchdog',
    'baselineRole',
    'bootstrapRoles',
    'auxiliaryRoleAuthorities',
    'effectivePermissions',
    'administratorPolicies',
    'wildcardAllows',
    'globalResourceAllowCount',
    'globalResourceAllowsSha256',
    'outsideProfileCapabilities',
    'externalRequests',
    'mutationsPerformed',
    'containsSensitiveData',
    'bindingSha256',
  ];
  if (
    !exactKeys(value, keys) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'IAM_EFFECTIVE_PERMISSIONS' ||
    value.artifactId !== 'ART-REL-06' ||
    value.status !== 'PASS' ||
    value.scope !== scope ||
    !Number.isFinite(Date.parse(value.generatedAtUtc ?? '')) ||
    value.candidateSha !== candidateSha ||
    value.releaseId !== releaseId ||
    value.manifestSha256 !== manifestSha256 ||
    value.configSha256 !== objectSha256(config) ||
    value.accountSha256 !== sha256(config.aws.accountId) ||
    value.accountSuffix !== config.aws.accountId.slice(-4) ||
    value.contractVersion !== IAM_EFFECTIVE_PERMISSIONS_CONTRACT_VERSION ||
    value.contractSha256 !== objectSha256(iamPermissionContract()) ||
    !exactKeys(value.controls, ['RELAUD-11', 'RELAUD-12', 'RELAUD-13']) ||
    Object.values(value.controls).some((status) => status !== 'PASS') ||
    !exactKeys(value.roles, ROLE_KEYS) ||
    !exactKeys(value.cleanupWatchdog, ['status', 'role']) ||
    (scope !== 'prerelease'
      ? value.cleanupWatchdog.status !== 'NOT_APPLICABLE' ||
        value.cleanupWatchdog.role !== null ||
        cleanupWatchdogRoleArn !== null
      : value.cleanupWatchdog.status !== 'PASS' ||
        !object(value.cleanupWatchdog.role) ||
        typeof cleanupWatchdogRoleArn !== 'string') ||
    !exactKeys(value.baselineRole, ['status', 'role']) ||
    (scope === 'baseline'
      ? value.baselineRole.status !== 'PASS' ||
        !object(value.baselineRole.role) ||
        typeof baselineRoleArn !== 'string' ||
        baselineRoleArn !== config.aws.roles.baselineRoleArn
      : value.baselineRole.status !== 'NOT_APPLICABLE' ||
        value.baselineRole.role !== null ||
        baselineRoleArn !== null) ||
    !exactKeys(value.bootstrapRoles, [
      'status',
      'qualifier',
      'roleCount',
      'trustBindingSha256',
      'sanitizedPolicyTemplate',
      'assetInventory',
      'roles',
    ]) ||
    value.bootstrapRoles.status !== 'PASS' ||
    value.bootstrapRoles.qualifier !== CDK_BOOTSTRAP_QUALIFIER ||
    value.bootstrapRoles.roleCount !== BOOTSTRAP_ROLE_KEYS.length ||
    !exactKeys(value.bootstrapRoles.roles, BOOTSTRAP_ROLE_KEYS) ||
    value.bootstrapRoles.trustBindingSha256 !==
      objectSha256(
        Object.fromEntries(
          BOOTSTRAP_ROLE_KEYS.map((roleKey) => [
            roleKey,
            value.bootstrapRoles.roles[roleKey]?.trustPolicySha256,
          ]),
        ),
      ) ||
    canonicalJson(value.bootstrapRoles.sanitizedPolicyTemplate) !==
      canonicalJson(createSanitizedBootstrapPolicyTemplate({ config, scope })) ||
    !exactKeys(value.bootstrapRoles.assetInventory, ['status', 'inventory']) ||
    (manifestSha256 === null
      ? bootstrapAssetInventory !== null ||
        value.bootstrapRoles.assetInventory.status !== 'NOT_APPLICABLE_PRE_FREEZE' ||
        value.bootstrapRoles.assetInventory.inventory !== null
      : bootstrapAssetInventory === null ||
        validateBootstrapAssetInventory(bootstrapAssetInventory) !== bootstrapAssetInventory ||
        bootstrapAssetInventory.region !== config.aws.region ||
        value.bootstrapRoles.assetInventory.status !== 'PASS' ||
        canonicalJson(value.bootstrapRoles.assetInventory.inventory) !==
          canonicalJson(bootstrapAssetInventory)) ||
    !exactKeys(value.auxiliaryRoleAuthorities, [
      'status',
      'journalRoleArnSha256',
      'journalPermissionsBoundaryArnSha256',
      'reconciliationRecoveryRoleArnSha256',
      'reconciliationRecoveryPermissionsBoundaryArnSha256',
      'readRolePermissionSetSha256',
      'authoritySetSha256',
    ]) ||
    canonicalJson(value.auxiliaryRoleAuthorities) !==
      canonicalJson(
        sanitizedAuxiliaryRoleAuthorities(
          auxiliaryRoleAuthority,
          value.roles?.readRoleArn?.permissionSetSha256,
        ),
      ) ||
    value.effectivePermissions !== 'PASS' ||
    value.administratorPolicies !== 0 ||
    value.wildcardAllows !== 0 ||
    !Number.isSafeInteger(value.globalResourceAllowCount) ||
    value.globalResourceAllowCount < 0 ||
    !SHA256.test(value.globalResourceAllowsSha256 ?? '') ||
    value.outsideProfileCapabilities !== 0 ||
    !Number.isSafeInteger(value.externalRequests) ||
    value.externalRequests < 0 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.bindingSha256 !== evidenceBinding(value)
  ) {
    fail('E7_IAM_PERMISSIONS_EVIDENCE_INVALID');
  }
  const roleEntries = [
    ...ROLE_KEYS.map((roleKey) => [roleKey, value.roles[roleKey], config.aws.roles[roleKey]]),
    ...(scope === 'prerelease'
      ? [['cleanupWatchdogRoleArn', value.cleanupWatchdog.role, cleanupWatchdogRoleArn]]
      : []),
    ...(scope === 'baseline'
      ? [['baselineRoleArn', value.baselineRole.role, baselineRoleArn]]
      : []),
    ...BOOTSTRAP_ROLE_KEYS.map((roleKey) => [
      roleKey,
      value.bootstrapRoles.roles[roleKey],
      bootstrapRoleArns(config)[roleKey],
    ]),
  ];
  const globalSummary = [];
  let minimumExternalRequests = 0;
  for (const [roleKey, role, expectedRoleArn] of roleEntries) {
    const expectedSubjects = IAM_ROLE_PERMISSION_PROFILES[roleKey].oidcSubjects[scope];
    if (
      !exactKeys(role, [
        'roleKey',
        'capability',
        'status',
        'roleArnSha256',
        'trustPolicySha256',
        'oidcSubjectCount',
        'oidcSubjectsSha256',
        'allowlistSha256',
        'inlinePolicyCount',
        'attachedPolicyCount',
        'sourcePolicySha256',
        'boundary',
        'effectiveActions',
        'effectiveActionsSha256',
        'effectiveGrantCount',
        'effectiveGrantsSha256',
        'globalResourceAllowCount',
        'globalResourceAllowsSha256',
        'permissionSetSha256',
      ]) ||
      role.roleKey !== roleKey ||
      role.capability !== IAM_ROLE_PERMISSION_PROFILES[roleKey].capability ||
      role.status !== 'PASS' ||
      role.roleArnSha256 !== sha256(expectedRoleArn) ||
      !SHA256.test(role.trustPolicySha256 ?? '') ||
      (BOOTSTRAP_ROLE_KEYS.includes(roleKey) &&
        role.trustPolicySha256 !==
          objectSha256(expectedBootstrapTrustPolicy({ config, roleKey }))) ||
      role.oidcSubjectCount !== expectedSubjects.length ||
      role.oidcSubjectsSha256 !== objectSha256(expectedSubjects) ||
      role.allowlistSha256 !== objectSha256(rolePermissionContract(roleKey)) ||
      !Number.isSafeInteger(role.inlinePolicyCount) ||
      role.inlinePolicyCount < 0 ||
      !Number.isSafeInteger(role.attachedPolicyCount) ||
      role.attachedPolicyCount < 0 ||
      role.inlinePolicyCount + role.attachedPolicyCount < 1 ||
      !Array.isArray(role.sourcePolicySha256) ||
      role.sourcePolicySha256.length !== role.inlinePolicyCount + role.attachedPolicyCount ||
      role.sourcePolicySha256.some((digest) => !SHA256.test(digest ?? '')) ||
      new Set(role.sourcePolicySha256).size !== role.sourcePolicySha256.length ||
      canonicalJson(role.sourcePolicySha256) !==
        canonicalJson([...role.sourcePolicySha256].toSorted()) ||
      !exactKeys(role.boundary, [
        'status',
        'policyArnSha256',
        'policyVersionIdSha256',
        'documentSha256',
      ]) ||
      !['ABSENT', 'PRESENT_AND_VALID'].includes(role.boundary.status) ||
      !Array.isArray(role.effectiveActions) ||
      role.effectiveActions.length === 0 ||
      new Set(role.effectiveActions).size !== role.effectiveActions.length ||
      canonicalJson(role.effectiveActions) !==
        canonicalJson([...role.effectiveActions].toSorted()) ||
      role.effectiveActions.some(
        (action) => !IAM_ROLE_PERMISSION_PROFILES[roleKey].actions.includes(action),
      ) ||
      requiredActionsFor(roleKey, scope).some(
        (action) => !role.effectiveActions.includes(action),
      ) ||
      role.effectiveActionsSha256 !== objectSha256(role.effectiveActions) ||
      !Number.isSafeInteger(role.effectiveGrantCount) ||
      role.effectiveGrantCount < role.effectiveActions.length ||
      !SHA256.test(role.effectiveGrantsSha256 ?? '') ||
      !Number.isSafeInteger(role.globalResourceAllowCount) ||
      role.globalResourceAllowCount < 0 ||
      role.globalResourceAllowCount > role.effectiveGrantCount ||
      !SHA256.test(role.globalResourceAllowsSha256 ?? '') ||
      role.permissionSetSha256 !==
        objectSha256({
          roleKey,
          capability: IAM_ROLE_PERMISSION_PROFILES[roleKey].capability,
          allowlistSha256: objectSha256(rolePermissionContract(roleKey)),
          trustPolicySha256: role.trustPolicySha256,
          oidcSubjectsSha256: role.oidcSubjectsSha256,
          sourcePolicySha256: role.sourcePolicySha256,
          boundaryPolicyArnSha256:
            role.boundary.status === 'PRESENT_AND_VALID' ? role.boundary.policyArnSha256 : null,
          boundaryPolicyVersionIdSha256:
            role.boundary.status === 'PRESENT_AND_VALID'
              ? role.boundary.policyVersionIdSha256
              : null,
          boundaryDocumentSha256:
            role.boundary.status === 'PRESENT_AND_VALID' ? role.boundary.documentSha256 : null,
          effectiveActions: role.effectiveActions,
          effectiveGrantCount: role.effectiveGrantCount,
          effectiveGrantsSha256: role.effectiveGrantsSha256,
          globalResourceAllowCount: role.globalResourceAllowCount,
          globalResourceAllowsSha256: role.globalResourceAllowsSha256,
        })
    ) {
      fail('E7_IAM_PERMISSIONS_EVIDENCE_INVALID');
    }
    if (
      (role.boundary.status === 'ABSENT' &&
        (role.boundary.policyArnSha256 !== null ||
          role.boundary.policyVersionIdSha256 !== null ||
          role.boundary.documentSha256 !== null)) ||
      (role.boundary.status === 'PRESENT_AND_VALID' &&
        (!SHA256.test(role.boundary.policyArnSha256 ?? '') ||
          !SHA256.test(role.boundary.policyVersionIdSha256 ?? '') ||
          !SHA256.test(role.boundary.documentSha256 ?? '')))
    ) {
      fail('E7_IAM_PERMISSIONS_EVIDENCE_INVALID');
    }
    globalSummary.push({
      roleKey,
      count: role.globalResourceAllowCount,
      sha256: role.globalResourceAllowsSha256,
    });
    minimumExternalRequests +=
      3 +
      role.inlinePolicyCount +
      2 * role.attachedPolicyCount +
      (role.boundary.status === 'PRESENT_AND_VALID' ? 2 : 0);
  }
  if (
    value.externalRequests < minimumExternalRequests ||
    value.globalResourceAllowCount !==
      globalSummary.reduce((total, role) => total + role.count, 0) ||
    value.globalResourceAllowsSha256 !== objectSha256(globalSummary)
  ) {
    fail('E7_IAM_PERMISSIONS_EVIDENCE_INVALID');
  }
  return value;
};

const fixturePolicy = (actions, resources, condition) => ({
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: actions,
      Resource: resources,
      ...(condition === undefined ? {} : { Condition: condition }),
    },
  ],
});

const expectCode = (action, code) =>
  assert.throws(
    action,
    (error) => error instanceof IamEffectivePermissionsError && error.code === code,
  );

const fixtureEnvironment = ({
  scope = 'full',
  config: suppliedConfig,
  candidateSha = 'a'.repeat(40),
} = {}) => {
  const accountId = suppliedConfig?.aws?.accountId ?? '123456789012';
  const roleArn = (name) => `arn:aws:iam::${accountId}:role/checkout/${name}`;
  const environment =
    scope === 'prerelease' ? 'assessment-prerelease-fixture' : 'assessment-release';
  const originTokenSecretArn = `arn:aws:secretsmanager:us-east-1:${accountId}:${['sec', 'ret'].join(
    '',
  )}:checkout/${environment}/runtime-AbCdEf`;
  const cleanupWatchdogRoleArn = roleArn('cleanup-watchdog');
  const baselineRoleArn = suppliedConfig?.aws?.roles?.baselineRoleArn ?? roleArn('baseline');
  const config = suppliedConfig ?? {
    environment,
    authorization: {
      scope:
        scope === 'prerelease'
          ? 'EPHEMERAL_PRERELEASE'
          : scope === 'baseline'
            ? 'FULL_RELEASE_BASELINE_CLOSED'
            : 'FULL_RELEASE_VERSIONED_UPDATE',
    },
    aws: {
      accountId,
      region: 'us-east-1',
      roles: {
        readRoleArn: roleArn('read'),
        deployRoleArn: roleArn('deploy'),
        rollbackRoleArn: roleArn('rollback'),
        cleanupRoleArn: roleArn('cleanup'),
        baselineRoleArn,
      },
    },
    credentialReferences: [originTokenSecretArn],
    domain: {
      hostedZoneId: 'Z1234567890ABC',
      apiHostname: 'api.example.test',
      webCertificateArn: `arn:aws:acm:us-east-1:${accountId}:certificate/a1b2c3d4-e5f6-4abc-8def-a1b2c3d4e5f6`,
      apiCertificateArn: `arn:aws:acm:us-east-1:${accountId}:certificate/f6e5d4c3-b2a1-4fed-8cba-f6e5d4c3b2a1`,
    },
    prereleaseAccess:
      scope === 'prerelease' || scope === 'baseline'
        ? {
            mode: 'CLOUDFRONT_SIGNED_COOKIE',
            keyGroupId: 'c2f83d9a-4f1e-4d7a-8b21-6c9d3e5f7a10',
            publicKeyId: 'K1234567890ABCDE',
            originTokenSecretArn,
            originTokenSecretVersionId: 'a'.repeat(32),
            rotationDuringWindow: 'FORBIDDEN',
          }
        : {
            mode: 'ORIGIN_GATE_ONLY',
            keyGroupId: null,
            publicKeyId: null,
            originTokenSecretArn,
            originTokenSecretVersionId: 'a'.repeat(32),
            rotationDuringWindow: 'FORBIDDEN',
          },
  };
  const bootstrapArns = bootstrapRoleArns(config);
  const auxiliaryRoleAuthorityInputs =
    scope === 'full'
      ? Object.freeze({
          journalRoleArn: roleArn('release-journal-cleanup'),
          journalPermissionsBoundaryArn: `arn:aws:iam::${accountId}:policy/stage7-release-journal-cleanup-boundary`,
          reconciliationRecoveryRoleArn: roleArn('release-reconciliation-recovery'),
          reconciliationRecoveryPermissionsBoundaryArn: `arn:aws:iam::${accountId}:policy/stage7-release-reconciliation-recovery-boundary`,
        })
      : Object.freeze({
          journalRoleArn: null,
          journalPermissionsBoundaryArn: null,
          reconciliationRecoveryRoleArn: null,
          reconciliationRecoveryPermissionsBoundaryArn: null,
        });
  SELF_TEST_AUXILIARY_ROLE_AUTHORITIES.set(config, auxiliaryRoleAuthorityInputs);
  const bootstrapAssetInventoryBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'CDK_BOOTSTRAP_ASSET_INVENTORY',
    status: 'PASS',
    qualifier: CDK_BOOTSTRAP_QUALIFIER,
    region: config.aws.region,
    assemblySha256: 'c'.repeat(64),
    assetManifestCount: 1,
    assetManifestSha256: 'd'.repeat(64),
    fileAssetCount: 3,
    dockerImageAssetCount: 0,
    requiredPublishingRoleKeys: ['bootstrapFilePublishingRoleArn'],
    deniedPublishingRoleKeys: ['bootstrapImagePublishingRoleArn'],
    containsSensitiveData: false,
  };
  const bootstrapAssetInventory = {
    ...bootstrapAssetInventoryBody,
    inventorySha256: objectSha256(bootstrapAssetInventoryBody),
  };
  SELF_TEST_BOOTSTRAP_ASSET_INVENTORIES.set(config, bootstrapAssetInventory);
  const roleActions = Object.fromEntries(
    IAM_PROFILE_KEYS.map((roleKey) => [roleKey, IAM_ROLE_PERMISSION_PROFILES[roleKey].actions]),
  );
  const allRoleArns = {
    ...config.aws.roles,
    cleanupWatchdogRoleArn,
    baselineRoleArn,
    ...bootstrapArns,
  };
  const authorizedRoleArns = [
    ...ROLE_KEYS.map((roleKey) => config.aws.roles[roleKey]),
    ...(scope === 'prerelease' ? [cleanupWatchdogRoleArn] : []),
    config.aws.roles.baselineRoleArn,
    ...Object.values(bootstrapArns),
    ...(scope === 'full'
      ? [
          auxiliaryRoleAuthorityInputs.journalRoleArn,
          auxiliaryRoleAuthorityInputs.reconciliationRecoveryRoleArn,
        ]
      : []),
  ];
  const authorizedPolicyArns =
    scope === 'full'
      ? [
          auxiliaryRoleAuthorityInputs.journalPermissionsBoundaryArn,
          auxiliaryRoleAuthorityInputs.reconciliationRecoveryPermissionsBoundaryArn,
        ]
      : [];
  const roleNames = Object.fromEntries(
    IAM_PROFILE_KEYS.map((roleKey) => [roleKey, allRoleArns[roleKey].split('/').at(-1)]),
  );
  const roleKeyForName = Object.fromEntries(
    Object.entries(roleNames).map(([roleKey, name]) => [name, roleKey]),
  );
  const managedArn = (roleKey, suffix) =>
    `arn:aws:iam::${accountId}:policy/checkout-stage7-${environment}-${roleNames[roleKey]}-${suffix}`;
  const boundaryArn = (roleKey) => managedArn(roleKey, 'boundary');
  const tagged = taggedResourceCondition(config);
  const rolePolicy = (roleKey, actions = roleActions[roleKey]) => {
    const normalizedFixtureActions = actions.map((action) => action.toLowerCase());
    const byClass = Map.groupBy(normalizedFixtureActions, (action) =>
      RESOURCE_CLASS_BY_ACTION.get(action),
    );
    const statements = [];
    for (const [resourceClass, classActions] of byClass) {
      let scopedActions = classActions;
      let resources;
      let condition;
      if (
        resourceClass === 'S3_BUCKET' &&
        roleKey === 'baselineRoleArn' &&
        classActions.includes('s3:getbucketversioning')
      ) {
        statements.push({
          Effect: 'Allow',
          Action: ['s3:getbucketversioning'],
          Resource: `arn:aws:s3:::checkout-${config.environment}-*`,
        });
        scopedActions = classActions.filter((action) => action !== 's3:getbucketversioning');
        if (scopedActions.length === 0) continue;
      }
      if (
        resourceClass === 'SSM_PARAMETER' &&
        roleKey === 'rollbackRoleArn' &&
        classActions.includes('ssm:putparameter')
      ) {
        statements.push({
          Effect: 'Allow',
          Action: ['ssm:putparameter'],
          Resource: rollbackJournalWriteResources(config, candidateSha),
          Condition: { StringEquals: { 'ssm:Overwrite': 'false' } },
        });
        scopedActions = classActions.filter((action) => action !== 'ssm:putparameter');
        if (scopedActions.length === 0) continue;
      }
      if (
        resourceClass === 'SSM_PARAMETER' &&
        ['readRoleArn', 'deployRoleArn', 'rollbackRoleArn'].includes(roleKey) &&
        scopedActions.includes('ssm:getparametersbypath')
      ) {
        statements.push({
          Effect: 'Allow',
          Action: ['ssm:getparametersbypath'],
          Resource: releaseMutationGuardReadResources(config, candidateSha),
        });
        scopedActions = scopedActions.filter((action) => action !== 'ssm:getparametersbypath');
        if (scopedActions.length === 0) continue;
      }
      if (resourceClass === 'ACM_CERTIFICATE') {
        resources = [config.domain.webCertificateArn, config.domain.apiCertificateArn];
      } else if (resourceClass === 'API_GATEWAY_TAGGED') {
        resources =
          roleKey === 'bootstrapCloudFormationExecutionRoleArn'
            ? [
                `arn:aws:apigateway:${config.aws.region}::/apis`,
                `arn:aws:apigateway:${config.aws.region}::/apis/*`,
                `arn:aws:apigateway:${config.aws.region}::/domainnames/${config.domain.apiHostname}`,
                `arn:aws:apigateway:${config.aws.region}::/domainnames/${config.domain.apiHostname}/apimappings`,
                `arn:aws:apigateway:${config.aws.region}::/domainnames/${config.domain.apiHostname}/apimappings/*`,
              ]
            : [
                `arn:aws:apigateway:${config.aws.region}::/apis/*`,
                `arn:aws:apigateway:${config.aws.region}::/domainnames/${config.domain.apiHostname}/apimappings`,
              ];
        if (roleKey !== 'bootstrapCloudFormationExecutionRoleArn') condition = tagged;
      } else if (resourceClass === 'BUDGET') {
        resources = `arn:aws:budgets::${accountId}:budget/checkout-${config.environment}-*`;
      } else if (resourceClass === 'IAM_MANAGED_POLICY') {
        resources = [
          `arn:aws:iam::${accountId}:policy/checkout-stage7-${config.environment}-*`,
          ...(roleKey === 'readRoleArn' ? authorizedPolicyArns : []),
        ];
      } else if (resourceClass === 'IAM_RELEASE_ROLE') {
        resources =
          roleKey === 'bootstrapCloudFormationExecutionRoleArn'
            ? `arn:aws:iam::${accountId}:role/checkout-${config.environment}-*`
            : roleKey === 'readRoleArn'
              ? authorizedRoleArns
              : allRoleArns[roleKey];
      } else if (resourceClass === 'CLOUDFORMATION_STACK') {
        resources = cloudFormationStackResources(config, roleKey);
      } else if (resourceClass === 'CLOUDFORMATION_CHANGE_SET_STACK') {
        resources = cloudFormationChangeSetResources(config, roleKey);
      } else if (resourceClass === 'CLOUDFRONT_DISTRIBUTION_TAGGED') {
        resources = `arn:aws:cloudfront::${accountId}:distribution/*`;
        condition = tagged;
      } else if (resourceClass === 'CLOUDFRONT_FUNCTION') {
        resources = `arn:aws:cloudfront::${accountId}:function/checkout-${config.environment}-*`;
      } else if (resourceClass === 'CLOUDFRONT_ORIGIN_ACCESS_CONTROL') {
        resources = `arn:aws:cloudfront::${accountId}:origin-access-control/*`;
      } else if (resourceClass === 'CLOUDFRONT_RESPONSE_HEADERS_POLICY') {
        resources = `arn:aws:cloudfront::${accountId}:response-headers-policy/*`;
      } else if (resourceClass === 'CLOUDFRONT_STAGE7_RESOURCE') {
        resources = [
          `arn:aws:cloudfront::${accountId}:distribution/*`,
          `arn:aws:cloudfront::${accountId}:function/checkout-${config.environment}-*`,
          `arn:aws:cloudfront::${accountId}:origin-access-control/*`,
          `arn:aws:cloudfront::${accountId}:response-headers-policy/*`,
        ];
      } else if (resourceClass === 'CLOUDWATCH_ALARM') {
        resources =
          roleKey === 'rollbackRoleArn'
            ? `arn:aws:cloudwatch:${config.aws.region}:${accountId}:alarm:checkout-${config.environment}-rollback-rehearsal`
            : `arn:aws:cloudwatch:${config.aws.region}:${accountId}:alarm:checkout-${config.environment}-*`;
      } else if (resourceClass === 'CLOUDWATCH_DASHBOARD') {
        resources = `arn:aws:cloudwatch::${accountId}:dashboard/checkout-${config.environment}-*`;
      } else if (resourceClass === 'CLOUDWATCH_STAGE7_RESOURCE') {
        resources = [
          `arn:aws:cloudwatch:${config.aws.region}:${accountId}:alarm:checkout-${config.environment}-*`,
          `arn:aws:cloudwatch::${accountId}:dashboard/checkout-${config.environment}-*`,
        ];
      } else if (resourceClass === 'CLOUDWATCH_METRIC_NAMESPACE') {
        resources = '*';
        condition = {
          StringEquals: { 'cloudwatch:namespace': 'Checkout/Stage7Rehearsal' },
        };
      } else if (resourceClass === 'LAMBDA_FUNCTION') {
        resources = `arn:aws:lambda:${config.aws.region}:${accountId}:function:checkout-${config.environment}-*`;
      } else if (resourceClass === 'DYNAMODB_TABLE') {
        resources = `arn:aws:dynamodb:${config.aws.region}:${accountId}:table/checkout-${config.environment}-*`;
      } else if (resourceClass === 'DYNAMODB_TABLE_AND_INDEX') {
        resources =
          roleKey === 'rollbackRoleArn'
            ? `arn:aws:dynamodb:${config.aws.region}:${accountId}:table/checkout-${config.environment}-*/index/GSI2-PendingAge`
            : [
                `arn:aws:dynamodb:${config.aws.region}:${accountId}:table/checkout-${config.environment}-*`,
                `arn:aws:dynamodb:${config.aws.region}:${accountId}:table/checkout-${config.environment}-*/index/*`,
              ];
      } else if (resourceClass === 'IAM_BOOTSTRAP_EXECUTION_ROLE') {
        resources =
          roleKey === 'bootstrapCloudFormationExecutionRoleArn'
            ? `arn:aws:iam::${accountId}:role/checkout-${config.environment}-*`
            : bootstrapArns.bootstrapCloudFormationExecutionRoleArn;
        condition =
          roleKey === 'bootstrapCloudFormationExecutionRoleArn'
            ? {
                StringEquals: {
                  'iam:PassedToService': ['lambda.amazonaws.com', 'scheduler.amazonaws.com'],
                },
              }
            : { StringEquals: { 'iam:PassedToService': 'cloudformation.amazonaws.com' } };
      } else if (resourceClass === 'IAM_APPLICATION_ROLE') {
        resources = `arn:aws:iam::${accountId}:role/checkout-${config.environment}-*`;
      } else if (resourceClass === 'LOG_GROUP') {
        resources = `arn:aws:logs:${config.aws.region}:${accountId}:log-group:/checkout-${config.environment}/*:*`;
      } else if (resourceClass === 'ROUTE53_CHANGE') {
        resources = 'arn:aws:route53:::change/*';
      } else if (resourceClass === 'ROUTE53_ZONE') {
        resources = `arn:aws:route53:::hostedzone/${config.domain.hostedZoneId}`;
      } else if (resourceClass === 'S3_BUCKET') {
        resources = ['bootstrapDeployRoleArn', 'bootstrapFilePublishingRoleArn'].includes(roleKey)
          ? `arn:aws:s3:::cdk-${CDK_BOOTSTRAP_QUALIFIER}-assets-${accountId}-${config.aws.region}`
          : `arn:aws:s3:::checkout-${config.environment}-*`;
      } else if (resourceClass === 'S3_OBJECT') {
        resources = ['bootstrapDeployRoleArn', 'bootstrapFilePublishingRoleArn'].includes(roleKey)
          ? `arn:aws:s3:::cdk-${CDK_BOOTSTRAP_QUALIFIER}-assets-${accountId}-${config.aws.region}/*`
          : roleKey === 'rollbackRoleArn'
            ? [
                `arn:aws:s3:::checkout-${config.environment}-*/index.html`,
                `arn:aws:s3:::checkout-${config.environment}-*/public-config.json`,
              ]
            : `arn:aws:s3:::checkout-${config.environment}-*/*`;
      } else if (resourceClass === 'GLOBAL_RESOURCE_REQUIRED') {
        resources = '*';
      } else if (resourceClass === 'SCHEDULER') {
        resources = `arn:aws:scheduler:${config.aws.region}:${accountId}:schedule/default/checkout-${config.environment}-*`;
      } else if (resourceClass === 'SECRETS_MANAGER_SECRET') {
        resources = config.credentialReferences[0];
      } else if (resourceClass === 'SNS_TOPIC') {
        resources = ['baselineRoleArn', 'bootstrapCloudFormationExecutionRoleArn'].includes(roleKey)
          ? `arn:aws:sns:${config.aws.region}:${accountId}:checkout-${config.environment}-alerts`
          : `arn:aws:sns:${config.aws.region}:${accountId}:checkout-${config.environment}-*`;
      } else if (resourceClass === 'SSM_PARAMETER') {
        resources =
          roleKey === 'rollbackRoleArn'
            ? rollbackJournalReadResources(config, candidateSha)
            : ['bootstrapDeployRoleArn', 'bootstrapLookupRoleArn'].includes(roleKey)
              ? `arn:aws:ssm:${config.aws.region}:${accountId}:parameter/cdk-bootstrap/${CDK_BOOTSTRAP_QUALIFIER}/version`
              : `arn:aws:ssm:${config.aws.region}:${accountId}:parameter/checkout/${config.environment}/*`;
      } else if (resourceClass === 'STS_BOOTSTRAP_ROLE') {
        resources = bootstrapRoleResources(config, roleKey);
      } else if (resourceClass === 'CDK_ASSET_REPOSITORY') {
        resources = `arn:aws:ecr:${config.aws.region}:${accountId}:repository/cdk-${CDK_BOOTSTRAP_QUALIFIER}-container-assets-${accountId}-${config.aws.region}`;
      } else {
        throw new Error(`Unhandled fixture resource class: ${resourceClass}`);
      }
      statements.push({
        Effect: 'Allow',
        Action: scopedActions,
        Resource: resources,
        ...(condition === undefined ? {} : { Condition: condition }),
      });
    }
    return { Version: '2012-10-17', Statement: statements };
  };
  const calls = [];
  const callAws = (service, operation, arguments_) => {
    calls.push({ service, operation, arguments_ });
    assert.equal(service, 'iam');
    const arg = (name) => {
      const index = arguments_.indexOf(name);
      return index === -1 ? undefined : arguments_[index + 1];
    };
    const roleName = arg('--role-name');
    const roleKey = roleKeyForName[roleName];
    if (operation === 'get-role') {
      return {
        Role: {
          Arn: allRoleArns[roleKey],
          RoleName: roleName,
          AssumeRolePolicyDocument: BOOTSTRAP_ROLE_KEYS.includes(roleKey)
            ? expectedBootstrapTrustPolicy({ config, scope, roleKey })
            : { Version: '2012-10-17', Statement: [] },
          ...(['rollbackRoleArn', 'bootstrapCloudFormationExecutionRoleArn'].includes(roleKey)
            ? {
                PermissionsBoundary: {
                  PermissionsBoundaryType: 'Policy',
                  PermissionsBoundaryArn: boundaryArn(roleKey),
                },
              }
            : {}),
        },
      };
    }
    if (operation === 'list-role-policies') {
      const startingToken = arg('--starting-token');
      if (roleKey === 'readRoleArn' && startingToken === undefined) {
        return { PolicyNames: ['read-a'], NextToken: 'read-inline-page-2' };
      }
      if (roleKey === 'readRoleArn') {
        assert.equal(startingToken, 'read-inline-page-2');
        return { PolicyNames: ['read-b'] };
      }
      return { PolicyNames: [`${roleNames[roleKey]}-inline`] };
    }
    if (operation === 'get-role-policy') {
      const policyName = arg('--policy-name');
      const actions =
        roleKey === 'readRoleArn' && policyName === 'read-b' ? [] : roleActions[roleKey];
      return {
        RoleName: roleName,
        PolicyName: policyName,
        PolicyDocument: rolePolicy(roleKey, actions.length === 0 ? ['iam:GetRole'] : actions),
      };
    }
    if (operation === 'list-attached-role-policies') {
      const startingToken = arg('--starting-token');
      if (roleKey === 'deployRoleArn' && startingToken === undefined) {
        const policyArn = managedArn(roleKey, 'a');
        return {
          AttachedPolicies: [{ PolicyName: policyArn.split('/').at(-1), PolicyArn: policyArn }],
          NextToken: 'deploy-attached-page-2',
        };
      }
      if (roleKey === 'deployRoleArn') {
        assert.equal(startingToken, 'deploy-attached-page-2');
        const policyArn = managedArn(roleKey, 'b');
        return {
          AttachedPolicies: [{ PolicyName: policyArn.split('/').at(-1), PolicyArn: policyArn }],
        };
      }
      if (roleKey === 'bootstrapCloudFormationExecutionRoleArn' && startingToken === undefined) {
        const policyArn = managedArn(roleKey, 'a');
        return {
          AttachedPolicies: [{ PolicyName: policyArn.split('/').at(-1), PolicyArn: policyArn }],
          NextToken: 'bootstrap-cfn-attached-page-2',
        };
      }
      if (roleKey === 'bootstrapCloudFormationExecutionRoleArn') {
        assert.equal(startingToken, 'bootstrap-cfn-attached-page-2');
        const policyArn = managedArn(roleKey, 'b');
        return {
          AttachedPolicies: [{ PolicyName: policyArn.split('/').at(-1), PolicyArn: policyArn }],
        };
      }
      return { AttachedPolicies: [] };
    }
    if (operation === 'get-policy') {
      const policyArn = arg('--policy-arn');
      return {
        Policy: {
          Arn: policyArn,
          PolicyName: policyArn.split('/').at(-1),
          DefaultVersionId: 'v3',
        },
      };
    }
    if (operation === 'get-policy-version') {
      const policyArn = arg('--policy-arn');
      const isBoundary = policyArn.endsWith('-boundary');
      const roleKeyFromPolicy = IAM_PROFILE_KEYS.find((key) =>
        policyArn.includes(`-${roleNames[key]}-`),
      );
      return {
        PolicyVersion: {
          VersionId: 'v3',
          IsDefaultVersion: true,
          Document: rolePolicy(
            roleKeyFromPolicy,
            isBoundary
              ? roleActions[roleKeyFromPolicy]
              : roleKeyFromPolicy === 'bootstrapCloudFormationExecutionRoleArn'
                ? ['lambda:GetFunction']
                : ['cloudformation:DescribeStacks'],
          ),
        },
      };
    }
    throw new Error(`Unexpected fixture operation: ${operation}`);
  };
  return {
    accountId,
    boundaryArn,
    baselineRoleArn,
    bootstrapAssetInventory,
    callAws,
    calls,
    cleanupWatchdogRoleArn,
    config,
    auxiliaryRoleAuthorityInputs,
    managedArn,
    roleNames,
    rolePolicy,
  };
};

export const createIamEffectivePermissionsSelfTestFixture = ({
  candidateSha,
  releaseId,
  manifestSha256,
  config,
  now = new Date('2026-08-18T01:00:00.000Z'),
}) => {
  if (
    config?.authorization?.scope !== 'FULL_RELEASE_BASELINE_CLOSED' ||
    typeof config?.aws?.roles?.baselineRoleArn !== 'string'
  ) {
    fail('E7_IAM_SELF_TEST_FIXTURE_BASELINE_ONLY');
  }
  const fixture = fixtureEnvironment({ scope: 'baseline', config, candidateSha });
  const evidence = collectIamEffectivePermissions({
    config,
    scope: 'baseline',
    candidateSha,
    releaseId,
    manifestSha256,
    bootstrapAssetInventory: fixture.bootstrapAssetInventory,
    baselineRoleArn: config.aws.roles.baselineRoleArn,
    callAws: fixture.callAws,
    validateTrust: () => true,
    now,
  });
  return validateIamEffectivePermissionsEvidence({
    value: evidence,
    config,
    scope: 'baseline',
    candidateSha,
    releaseId,
    manifestSha256,
    bootstrapAssetInventory: fixture.bootstrapAssetInventory,
    baselineRoleArn: config.aws.roles.baselineRoleArn,
  });
};

export const selfTestIamEffectivePermissions = () => {
  const fixture = fixtureEnvironment();
  const candidateSha = 'a'.repeat(40);
  const releaseId = 'rel-20260818-0100-aaaaaaa';
  const manifestSha256 = 'b'.repeat(64);
  for (const invalidRoleArn of [
    `arn:aws:iam::${fixture.accountId}:role/checkout/`,
    `arn:aws:iam::${fixture.accountId}:role/checkout//read`,
    `arn:aws:iam::${fixture.accountId}:role/${'r'.repeat(65)}`,
  ]) {
    expectCode(() => roleParts(invalidRoleArn, fixture.accountId), 'E7_IAM_ROLE_ARN_INVALID');
  }
  const collidingRoleNameConfig = structuredClone(fixture.config);
  const readRoleName = collidingRoleNameConfig.aws.roles.readRoleArn.split('/').at(-1);
  collidingRoleNameConfig.aws.roles.deployRoleArn = `arn:aws:iam::${fixture.accountId}:role/isolated/${readRoleName}`;
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: collidingRoleNameConfig,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        bootstrapAssetInventory: fixture.bootstrapAssetInventory,
        ...fixture.auxiliaryRoleAuthorityInputs,
        callAws: fixture.callAws,
        validateTrust: () => true,
        now: new Date('2026-08-18T01:00:00.000Z'),
      }),
    'E7_IAM_ROLE_SEPARATION_REQUIRED',
  );
  const observedTrustSubjects = new Map();
  const evidence = collectIamEffectivePermissions({
    config: fixture.config,
    scope: 'full',
    candidateSha,
    releaseId,
    manifestSha256,
    bootstrapAssetInventory: fixture.bootstrapAssetInventory,
    callAws: fixture.callAws,
    validateTrust: ({ roleKey, expectedSubjects }) => {
      observedTrustSubjects.set(roleKey, expectedSubjects);
      return true;
    },
    now: new Date('2026-08-18T01:00:00.000Z'),
  });
  assert.deepEqual(observedTrustSubjects.get('rollbackRoleArn'), [
    environmentSubject('assessment-release'),
    environmentSubject('assessment-release-recovery'),
  ]);
  assert.deepEqual(observedTrustSubjects.get('readRoleArn'), [
    environmentSubject('assessment-release'),
    environmentSubject('assessment-release-read'),
    environmentSubject('assessment-release-recovery'),
    environmentSubject('assessment-release-reconciliation-recovery'),
    environmentSubject('assessment-release-sandbox'),
  ]);
  assert.deepEqual(IAM_ROLE_PERMISSION_PROFILES.readRoleArn.oidcSubjects.prerelease, [
    environmentSubject('assessment-prerelease'),
    environmentSubject('assessment-prerelease-external'),
    environmentSubject('assessment-prerelease-read'),
  ]);
  assert.deepEqual(IAM_ROLE_PERMISSION_PROFILES.readRoleArn.oidcSubjects.baseline, [
    environmentSubject('assessment-release'),
    environmentSubject('assessment-release-read'),
    environmentSubject('assessment-release-recovery'),
    environmentSubject('assessment-release-reconciliation-recovery'),
    environmentSubject('assessment-release-sandbox'),
  ]);
  assert.deepEqual(
    IAM_ROLE_PERMISSION_PROFILES.readRoleArn.oidcSubjects.baseline,
    IAM_ROLE_PERMISSION_PROFILES.readRoleArn.oidcSubjects.full,
  );
  validateIamEffectivePermissionsEvidence({
    value: evidence,
    config: fixture.config,
    scope: 'full',
    candidateSha,
    releaseId,
    manifestSha256,
    bootstrapAssetInventory: fixture.bootstrapAssetInventory,
  });
  assert.equal(evidence.auxiliaryRoleAuthorities.status, 'PASS');
  assert.equal(
    evidence.auxiliaryRoleAuthorities.readRolePermissionSetSha256,
    evidence.roles.readRoleArn.permissionSetSha256,
  );
  assert.equal(
    evidence.auxiliaryRoleAuthorities.journalRoleArnSha256,
    sha256(fixture.auxiliaryRoleAuthorityInputs.journalRoleArn),
  );
  assert.equal(
    evidence.auxiliaryRoleAuthorities.reconciliationRecoveryRoleArnSha256,
    sha256(fixture.auxiliaryRoleAuthorityInputs.reconciliationRecoveryRoleArn),
  );
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: structuredClone(fixture.config),
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        bootstrapAssetInventory: fixture.bootstrapAssetInventory,
        callAws: fixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_AUXILIARY_ROLE_AUTHORITY_INVALID',
  );
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: structuredClone(fixture.config),
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256: null,
        ...fixture.auxiliaryRoleAuthorityInputs,
        callAws: fixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_AUXILIARY_ROLE_AUTHORITY_SCOPE_INVALID',
  );
  for (const forbiddenScope of ['prerelease', 'baseline']) {
    expectCode(
      () =>
        resolveAuxiliaryRoleAuthorities({
          config: fixture.config,
          scope: forbiddenScope,
          manifestSha256,
          ...fixture.auxiliaryRoleAuthorityInputs,
        }),
      'E7_IAM_AUXILIARY_ROLE_AUTHORITY_SCOPE_INVALID',
    );
  }
  for (const invalidAuxiliaryInputs of [
    {
      ...fixture.auxiliaryRoleAuthorityInputs,
      reconciliationRecoveryRoleArn: fixture.auxiliaryRoleAuthorityInputs.journalRoleArn,
    },
    {
      ...fixture.auxiliaryRoleAuthorityInputs,
      reconciliationRecoveryRoleArn: fixture.config.aws.roles.rollbackRoleArn,
    },
    {
      ...fixture.auxiliaryRoleAuthorityInputs,
      reconciliationRecoveryRoleArn:
        'arn:aws:iam::999999999999:role/checkout/release-reconciliation-recovery',
    },
    {
      ...fixture.auxiliaryRoleAuthorityInputs,
      reconciliationRecoveryPermissionsBoundaryArn:
        fixture.auxiliaryRoleAuthorityInputs.journalPermissionsBoundaryArn,
    },
    {
      ...fixture.auxiliaryRoleAuthorityInputs,
      reconciliationRecoveryRoleArn: `arn:aws:iam::${fixture.accountId}:role/*`,
    },
    {
      ...fixture.auxiliaryRoleAuthorityInputs,
      reconciliationRecoveryPermissionsBoundaryArn: `arn:aws:iam::${fixture.accountId}:policy/*`,
    },
    {
      ...fixture.auxiliaryRoleAuthorityInputs,
      reconciliationRecoveryPermissionsBoundaryArn:
        'arn:aws:iam::999999999999:policy/stage7-release-reconciliation-recovery-boundary',
    },
    {
      ...fixture.auxiliaryRoleAuthorityInputs,
      reconciliationRecoveryRoleArn: `arn:aws:iam::${fixture.accountId}:role/checkout//recovery`,
    },
  ]) {
    expectCode(
      () =>
        collectIamEffectivePermissions({
          config: structuredClone(fixture.config),
          scope: 'full',
          candidateSha,
          releaseId,
          manifestSha256,
          bootstrapAssetInventory: fixture.bootstrapAssetInventory,
          ...invalidAuxiliaryInputs,
          callAws: fixture.callAws,
          validateTrust: () => true,
        }),
      'E7_IAM_AUXILIARY_ROLE_AUTHORITY_INVALID',
    );
  }
  assert.equal(evidence.roles.rollbackRoleArn.boundary.status, 'PRESENT_AND_VALID');
  assert.equal(evidence.bootstrapRoles.status, 'PASS');
  assert.equal(evidence.bootstrapRoles.roleCount, BOOTSTRAP_ROLE_KEYS.length);
  assert.equal(
    evidence.bootstrapRoles.roles.bootstrapCloudFormationExecutionRoleArn.boundary.status,
    'PRESENT_AND_VALID',
  );
  assert.equal(evidence.roles.readRoleArn.effectiveActions.includes('sts:assumerole'), true);
  assert.equal(
    canonicalJson(evidence.bootstrapRoles.sanitizedPolicyTemplate).includes(fixture.accountId),
    false,
  );
  assert.equal(
    evidence.roles.readRoleArn.effectiveActions.includes('route53:listresourcerecordsets'),
    true,
  );
  assert.ok(
    fixture.calls.some(
      (call) =>
        call.operation === 'list-role-policies' &&
        call.arguments_.includes('read-inline-page-2') &&
        call.arguments_.includes('--starting-token'),
    ),
  );
  const imageAssetInventory = structuredClone(fixture.bootstrapAssetInventory);
  imageAssetInventory.dockerImageAssetCount = 1;
  const imageAssetInventoryBody = { ...imageAssetInventory };
  delete imageAssetInventoryBody.inventorySha256;
  imageAssetInventory.inventorySha256 = objectSha256(imageAssetInventoryBody);
  expectCode(
    () => validateBootstrapAssetInventory(imageAssetInventory),
    'E7_IAM_BOOTSTRAP_ASSET_INVENTORY_INVALID',
  );
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: structuredClone(fixture.config),
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: fixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_BOOTSTRAP_ASSET_BINDING_INVALID',
  );
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: fixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256: null,
        bootstrapAssetInventory: fixture.bootstrapAssetInventory,
        callAws: fixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_BOOTSTRAP_ASSET_BINDING_INVALID',
  );
  assert.ok(
    fixture.calls.some(
      (call) =>
        call.operation === 'list-attached-role-policies' &&
        call.arguments_.includes('bootstrap-cfn-attached-page-2') &&
        call.arguments_.includes('--starting-token'),
    ),
  );

  const prereleaseFixture = fixtureEnvironment({ scope: 'prerelease' });
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: prereleaseFixture.config,
        scope: 'prerelease',
        candidateSha,
        releaseId,
        manifestSha256,
        bootstrapAssetInventory: prereleaseFixture.bootstrapAssetInventory,
        cleanupWatchdogRoleArn: prereleaseFixture.cleanupWatchdogRoleArn,
        ...fixture.auxiliaryRoleAuthorityInputs,
        callAws: prereleaseFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_AUXILIARY_ROLE_AUTHORITY_SCOPE_INVALID',
  );
  const prereleaseTrustSubjects = new Map();
  const prereleaseEvidence = collectIamEffectivePermissions({
    config: prereleaseFixture.config,
    scope: 'prerelease',
    candidateSha,
    releaseId,
    manifestSha256,
    bootstrapAssetInventory: prereleaseFixture.bootstrapAssetInventory,
    cleanupWatchdogRoleArn: prereleaseFixture.cleanupWatchdogRoleArn,
    callAws: prereleaseFixture.callAws,
    validateTrust: ({ roleKey, expectedSubjects }) => {
      prereleaseTrustSubjects.set(roleKey, expectedSubjects);
      return true;
    },
    now: new Date('2026-08-18T01:00:00.000Z'),
  });
  validateIamEffectivePermissionsEvidence({
    value: prereleaseEvidence,
    config: prereleaseFixture.config,
    scope: 'prerelease',
    candidateSha,
    releaseId,
    manifestSha256,
    bootstrapAssetInventory: prereleaseFixture.bootstrapAssetInventory,
    cleanupWatchdogRoleArn: prereleaseFixture.cleanupWatchdogRoleArn,
  });
  assert.equal(prereleaseEvidence.cleanupWatchdog.status, 'PASS');
  assert.deepEqual(prereleaseTrustSubjects.get('cleanupWatchdogRoleArn'), [MASTER_REF_SUBJECT]);
  assert.ok(
    fixture.calls.some(
      (call) =>
        call.operation === 'list-attached-role-policies' &&
        call.arguments_.includes('deploy-attached-page-2') &&
        call.arguments_.includes('--starting-token'),
    ),
  );

  const baselineFixture = fixtureEnvironment({ scope: 'baseline' });
  const baselineTrustSubjects = new Map();
  const baselineEvidence = collectIamEffectivePermissions({
    config: baselineFixture.config,
    scope: 'baseline',
    candidateSha,
    releaseId,
    manifestSha256,
    bootstrapAssetInventory: baselineFixture.bootstrapAssetInventory,
    baselineRoleArn: baselineFixture.baselineRoleArn,
    callAws: baselineFixture.callAws,
    validateTrust: ({ roleKey, expectedSubjects }) => {
      baselineTrustSubjects.set(roleKey, expectedSubjects);
      return true;
    },
    now: new Date('2026-08-18T01:00:00.000Z'),
  });
  validateIamEffectivePermissionsEvidence({
    value: baselineEvidence,
    config: baselineFixture.config,
    scope: 'baseline',
    candidateSha,
    releaseId,
    manifestSha256,
    bootstrapAssetInventory: baselineFixture.bootstrapAssetInventory,
    baselineRoleArn: baselineFixture.baselineRoleArn,
  });
  assert.equal(baselineEvidence.baselineRole.status, 'PASS');
  assert.deepEqual(baselineTrustSubjects.get('baselineRoleArn'), [BASELINE_SUBJECT]);
  assert.equal(
    baselineEvidence.baselineRole.role.effectiveActions.includes('cloudformation:deletestack'),
    false,
  );
  assert.equal(
    baselineEvidence.baselineRole.role.effectiveActions.includes('lambda:updatealias'),
    false,
  );
  assert.equal(
    baselineEvidence.baselineRole.role.effectiveActions.includes('s3:getbucketversioning'),
    true,
  );
  assert.equal(
    baselineEvidence.baselineRole.role.effectiveActions.includes('sns:listsubscriptionsbytopic'),
    true,
  );
  assert.equal(
    baselineEvidence.baselineRole.role.effectiveActions.includes('secretsmanager:getsecretvalue'),
    false,
  );
  assert.equal(
    baselineEvidence.bootstrapRoles.roles.bootstrapCloudFormationExecutionRoleArn.effectiveActions.includes(
      'secretsmanager:getsecretvalue',
    ),
    true,
  );
  assert.deepEqual(
    createIamEffectivePermissionsSelfTestFixture({
      candidateSha,
      releaseId,
      manifestSha256,
      config: baselineFixture.config,
    }),
    baselineEvidence,
  );

  const policyResource = stageStackResources(fixture.config)[0];
  const requiredGlobal = normalizeIamPolicyDocument({
    document: fixturePolicy(['servicequotas:ListServiceQuotas'], '*'),
    roleKey: 'readRoleArn',
    config: fixture.config,
    sourceType: 'INLINE',
  });
  assert.equal(requiredGlobal.allowGrants[0].resourceClass, 'GLOBAL_RESOURCE_REQUIRED');
  const permissionContext = { candidateSha, releaseId };
  const expectedRollbackJournalResources = rollbackJournalReadResources(
    fixture.config,
    candidateSha,
  );
  assert.deepEqual(expectedRollbackJournalResources, [
    `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/rollback/${candidateSha}/RB-E7-06/*`,
    `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/rollback/${candidateSha}/RB-E7-08/*`,
    `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/rollback/${candidateSha}/release-reconciliation/*`,
  ]);
  const rollbackJournalRead = normalizeIamPolicyDocument({
    document: fixturePolicy(['ssm:GetParameter'], expectedRollbackJournalResources),
    roleKey: 'rollbackRoleArn',
    config: fixture.config,
    sourceType: 'INLINE',
    permissionContext,
  });
  assert.deepEqual(rollbackJournalRead.allowActions, ['ssm:getparameter']);
  const expectedMutationGuardResources = releaseMutationGuardReadResources(
    fixture.config,
    candidateSha,
  );
  assert.deepEqual(expectedMutationGuardResources, [
    `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/release-fence/${candidateSha}/*`,
    `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/release-finalization/${candidateSha}/*`,
    `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/rollback/${candidateSha}/*`,
  ]);
  for (const roleKey of ['readRoleArn', 'deployRoleArn', 'rollbackRoleArn']) {
    const mutationGuardRead = normalizeIamPolicyDocument({
      document: fixturePolicy(['ssm:GetParametersByPath'], expectedMutationGuardResources),
      roleKey,
      config: fixture.config,
      sourceType: 'INLINE',
      permissionContext,
    });
    assert.deepEqual(mutationGuardRead.allowActions, ['ssm:getparametersbypath']);
    assert.deepEqual(mutationGuardRead.allowGrants[0].resources, expectedMutationGuardResources);
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document: fixturePolicy(
            ['ssm:GetParameter', 'ssm:GetParametersByPath'],
            expectedMutationGuardResources,
          ),
          roleKey,
          config: fixture.config,
          sourceType: 'INLINE',
          permissionContext,
        }),
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    );
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document: fixturePolicy(
            ['ssm:GetParametersByPath'],
            releaseMutationGuardReadResources(fixture.config, 'f'.repeat(40)),
          ),
          roleKey,
          config: fixture.config,
          sourceType: 'INLINE',
          permissionContext,
        }),
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    );
  }
  const rollbackJournalWrite = normalizeIamPolicyDocument({
    document: fixturePolicy(
      ['ssm:PutParameter'],
      rollbackJournalWriteResources(fixture.config, candidateSha),
      {
        StringEquals: { 'ssm:Overwrite': 'false' },
      },
    ),
    roleKey: 'rollbackRoleArn',
    config: fixture.config,
    sourceType: 'INLINE',
    permissionContext,
  });
  assert.deepEqual(rollbackJournalWrite.allowActions, ['ssm:putparameter']);
  assert.deepEqual(
    rollbackJournalWrite.allowGrants[0].resources,
    rollbackJournalWriteResources(fixture.config, candidateSha),
  );
  expectCode(
    () =>
      normalizeIamPolicyDocument({
        document: fixturePolicy(['ssm:PutParameter'], expectedRollbackJournalResources.at(-1), {
          StringEquals: { 'ssm:Overwrite': 'false' },
        }),
        roleKey: 'rollbackRoleArn',
        config: fixture.config,
        sourceType: 'INLINE',
        permissionContext,
      }),
    'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
  );
  for (const [actions, condition] of [
    [['ssm:PutParameter'], undefined],
    [['ssm:PutParameter'], { StringEquals: { 'ssm:Overwrite': 'true' } }],
    [['ssm:GetParameter', 'ssm:PutParameter'], { StringEquals: { 'ssm:Overwrite': 'false' } }],
    [['ssm:PutParameter'], { StringEquals: { 'ssm:Overwrite': 'false', 'ssm:Policies': 'false' } }],
  ]) {
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document: fixturePolicy(actions, expectedRollbackJournalResources, condition),
          roleKey: 'rollbackRoleArn',
          config: fixture.config,
          sourceType: 'INLINE',
          permissionContext,
        }),
      'E7_IAM_CONDITION_NOT_ALLOWLISTED',
    );
  }
  const rollbackMetric = normalizeIamPolicyDocument({
    document: fixturePolicy(['cloudwatch:PutMetricData'], '*', {
      StringEquals: { 'cloudwatch:namespace': 'Checkout/Stage7Rehearsal' },
    }),
    roleKey: 'rollbackRoleArn',
    config: fixture.config,
    sourceType: 'INLINE',
    permissionContext,
  });
  assert.equal(rollbackMetric.allowGrants[0].resources[0], '*');
  const rollbackMetricRead = normalizeIamPolicyDocument({
    document: fixturePolicy(['cloudwatch:GetMetricStatistics'], '*'),
    roleKey: 'rollbackRoleArn',
    config: fixture.config,
    sourceType: 'INLINE',
    permissionContext,
  });
  assert.equal(rollbackMetricRead.allowGrants[0].resourceClass, 'GLOBAL_RESOURCE_REQUIRED');
  for (const [resource, code] of [
    ['*', 'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC'],
    [
      `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/rollback/${'f'.repeat(40)}/RB-E7-06/*`,
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    ],
    [
      `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/rollback/${candidateSha}/release-fence/*`,
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    ],
    [
      `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/rollback/${candidateSha}/release-reconciliation-sibling/*`,
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    ],
    [
      `arn:aws:ssm:${fixture.config.aws.region}:${fixture.accountId}:parameter/checkout/stage7/release-fence/${'f'.repeat(40)}/*`,
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    ],
  ]) {
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document: fixturePolicy(['ssm:GetParametersByPath'], resource),
          roleKey: 'rollbackRoleArn',
          config: fixture.config,
          sourceType: 'INLINE',
          permissionContext,
        }),
      code,
    );
  }
  for (const condition of [undefined, { StringEquals: { 'cloudwatch:namespace': 'Unrelated' } }]) {
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document: fixturePolicy(['cloudwatch:PutMetricData'], '*', condition),
          roleKey: 'rollbackRoleArn',
          config: fixture.config,
          sourceType: 'INLINE',
          permissionContext,
        }),
      'E7_IAM_CONDITION_NOT_ALLOWLISTED',
    );
  }
  const cloudFormationPassRoleCondition = {
    StringEquals: { 'iam:PassedToService': 'cloudformation.amazonaws.com' },
  };
  const cfnExecutionRoleArn = bootstrapRoleArns(
    fixture.config,
  ).bootstrapCloudFormationExecutionRoleArn;
  const rollbackPassRole = normalizeIamPolicyDocument({
    document: fixturePolicy(['iam:PassRole'], cfnExecutionRoleArn, cloudFormationPassRoleCondition),
    roleKey: 'rollbackRoleArn',
    config: fixture.config,
    sourceType: 'INLINE',
    permissionContext,
  });
  assert.equal(rollbackPassRole.allowActions.includes('iam:passrole'), true);
  for (const [resource, condition, code] of [
    [cfnExecutionRoleArn, undefined, 'E7_IAM_CONDITION_NOT_ALLOWLISTED'],
    ['*', cloudFormationPassRoleCondition, 'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC'],
    [
      fixture.config.aws.roles.deployRoleArn,
      cloudFormationPassRoleCondition,
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    ],
  ]) {
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document: fixturePolicy(['iam:PassRole'], resource, condition),
          roleKey: 'rollbackRoleArn',
          config: fixture.config,
          sourceType: 'INLINE',
          permissionContext,
        }),
      code,
    );
  }
  expectCode(
    () =>
      normalizeIamPolicyDocument({
        document: fixturePolicy(
          ['cloudformation:CreateChangeSet'],
          stageStackResources(fixture.config)[1],
        ),
        roleKey: 'rollbackRoleArn',
        config: fixture.config,
        sourceType: 'INLINE',
        permissionContext,
      }),
    'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
  );
  for (const resource of [
    '*',
    `arn:aws:secretsmanager:${fixture.config.aws.region}:${fixture.accountId}:${['sec', 'ret'].join('')}:checkout/unrelated`,
  ]) {
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document: fixturePolicy(['secretsmanager:GetSecretValue'], resource),
          roleKey: 'rollbackRoleArn',
          config: fixture.config,
          sourceType: 'INLINE',
          permissionContext,
        }),
      resource === '*'
        ? 'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC'
        : 'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    );
  }
  for (const [action, resources] of [
    [
      'cloudfront:ListInvalidations',
      ['*', `arn:aws:cloudfront::${fixture.accountId}:distribution/UNRELATED`],
    ],
    [
      'cloudwatch:DescribeAlarms',
      [
        '*',
        `arn:aws:cloudwatch:${fixture.config.aws.region}:${fixture.accountId}:alarm:checkout-${fixture.config.environment}-unrelated`,
      ],
    ],
    [
      'lambda:InvokeFunction',
      ['*', `arn:aws:lambda:${fixture.config.aws.region}:${fixture.accountId}:function:unrelated`],
    ],
  ]) {
    for (const resource of resources) {
      expectCode(
        () =>
          normalizeIamPolicyDocument({
            document: fixturePolicy(
              [action],
              resource,
              action === 'cloudfront:ListInvalidations'
                ? taggedResourceCondition(fixture.config)
                : undefined,
            ),
            roleKey: 'rollbackRoleArn',
            config: fixture.config,
            sourceType: 'INLINE',
            permissionContext,
          }),
        resource === '*'
          ? 'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC'
          : 'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
      );
    }
  }
  expectCode(
    () =>
      normalizeIamPolicyDocument({
        document: fixturePolicy(
          ['sts:AssumeRole'],
          bootstrapRoleArns(fixture.config).bootstrapImagePublishingRoleArn,
        ),
        roleKey: 'deployRoleArn',
        config: fixture.config,
        sourceType: 'INLINE',
      }),
    'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
  );
  expectCode(
    () =>
      normalizeIamPolicyDocument({
        document: fixturePolicy(
          ['sts:AssumeRole'],
          bootstrapRoleArns(fixture.config).bootstrapDeployRoleArn,
        ),
        roleKey: 'readRoleArn',
        config: fixture.config,
        sourceType: 'INLINE',
      }),
    'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
  );
  for (const [document, code] of [
    [fixturePolicy(['*'], policyResource), 'E7_IAM_ALLOW_ACTION_WILDCARD'],
    [
      fixturePolicy(['cloudformation:DescribeStacks'], '*'),
      'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC',
    ],
    [fixturePolicy(['s3:GetObject'], '*'), 'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC'],
    [fixturePolicy(['lambda:GetFunction'], '*'), 'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC'],
    [
      fixturePolicy(['route53:ListResourceRecordSets'], '*'),
      'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC',
    ],
    [
      {
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', NotAction: 's3:DeleteObject', Resource: policyResource }],
      },
      'E7_IAM_NOT_ACTION_OR_RESOURCE_FORBIDDEN',
    ],
    [
      fixturePolicy(['iam:CreateUser'], `arn:aws:iam::${fixture.accountId}:user/stage7-*`),
      'E7_IAM_CAPABILITY_OUTSIDE_ROLE_PROFILE',
    ],
    [
      fixturePolicy(['s3:GetObject'], 'arn:aws:s3:::unrelated-same-account-bucket/*'),
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    ],
    [
      fixturePolicy(['lambda:GetFunction'], 'arn:aws:s3:::checkout-assessment-release-assets/*'),
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    ],
    [
      fixturePolicy(
        ['route53:ListResourceRecordSets'],
        'arn:aws:route53:::hostedzone/ZUNRELATED123',
      ),
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    ],
    [
      fixturePolicy(
        ['iam:GetRole', 'cloudformation:DescribeStacks'],
        Object.values(fixture.config.aws.roles),
      ),
      'E7_IAM_MIXED_RESOURCE_CLASSES',
    ],
    [
      fixturePolicy(['servicequotas:ListServiceQuotas'], '*', {
        StringEquals: { 'aws:RequestedRegion': 'us-east-1' },
      }),
      'E7_IAM_CONDITION_NOT_ALLOWLISTED',
    ],
    [
      {
        Version: '2012-10-17',
        Statement: [{ Effect: 'Deny', Action: 's3:*', Resource: '*' }],
      },
      'E7_IAM_DENY_WILDCARD_UNSUPPORTED',
    ],
    [
      fixturePolicy(
        ['secretsmanager:DescribeSecret'],
        `arn:aws:ssm:us-east-1:${fixture.accountId}:parameter/checkout/assessment-release/key`,
      ),
      'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    ],
  ]) {
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document,
          roleKey: 'readRoleArn',
          config: fixture.config,
          sourceType: 'INLINE',
        }),
      code,
    );
  }

  const missingRoute53Fixture = fixtureEnvironment({ scope: 'baseline' });
  const originalMissingRoute53Call = missingRoute53Fixture.callAws;
  missingRoute53Fixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    const policyNameIndex = arguments_.indexOf('--policy-name');
    const policyName = policyNameIndex === -1 ? undefined : arguments_[policyNameIndex + 1];
    if (
      roleName === missingRoute53Fixture.roleNames.readRoleArn &&
      operation === 'get-role-policy' &&
      policyName === 'read-a'
    ) {
      const actions = IAM_ROLE_PERMISSION_PROFILES.readRoleArn.actions.filter(
        (action) => action !== 'route53:listresourcerecordsets',
      );
      return {
        RoleName: roleName,
        PolicyName: policyName,
        PolicyDocument: missingRoute53Fixture.rolePolicy('readRoleArn', actions),
      };
    }
    return originalMissingRoute53Call(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingRoute53Fixture.config,
        scope: 'baseline',
        candidateSha,
        releaseId,
        manifestSha256,
        baselineRoleArn: missingRoute53Fixture.baselineRoleArn,
        callAws: missingRoute53Fixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_REQUIRED_EFFECTIVE_PERMISSION_MISSING',
  );

  const missingRollbackPassRoleFixture = fixtureEnvironment();
  const originalMissingRollbackPassRoleCall = missingRollbackPassRoleFixture.callAws;
  missingRollbackPassRoleFixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    if (
      roleName === missingRollbackPassRoleFixture.roleNames.rollbackRoleArn &&
      operation === 'get-role-policy'
    ) {
      const actions = IAM_ROLE_PERMISSION_PROFILES.rollbackRoleArn.actions.filter(
        (action) => action !== 'iam:passrole',
      );
      return {
        RoleName: roleName,
        PolicyName: 'rollback-inline',
        PolicyDocument: missingRollbackPassRoleFixture.rolePolicy('rollbackRoleArn', actions),
      };
    }
    return originalMissingRollbackPassRoleCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingRollbackPassRoleFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: missingRollbackPassRoleFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_REQUIRED_EFFECTIVE_PERMISSION_MISSING',
  );
  expectCode(
    () =>
      normalizeIamPolicyDocument({
        document: fixturePolicy(['cloudformation:DeleteStack'], policyResource),
        roleKey: 'baselineRoleArn',
        config: baselineFixture.config,
        sourceType: 'INLINE',
        auditedRoleArn: baselineFixture.baselineRoleArn,
        authorizedRoleArns: Object.values(baselineFixture.config.aws.roles),
      }),
    'E7_IAM_CAPABILITY_OUTSIDE_ROLE_PROFILE',
  );
  expectCode(
    () =>
      normalizeIamPolicyDocument({
        document: fixturePolicy(['s3:GetBucketVersioning'], '*'),
        roleKey: 'baselineRoleArn',
        config: baselineFixture.config,
        sourceType: 'INLINE',
        auditedRoleArn: baselineFixture.baselineRoleArn,
        authorizedRoleArns: Object.values(baselineFixture.config.aws.roles),
      }),
    'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC',
  );
  expectCode(
    () =>
      normalizeIamPolicyDocument({
        document: fixturePolicy(
          ['s3:GetBucketVersioning'],
          `arn:aws:s3:::cdk-hnb659fds-assets-${baselineFixture.accountId}-us-east-1`,
        ),
        roleKey: 'baselineRoleArn',
        config: baselineFixture.config,
        sourceType: 'INLINE',
        auditedRoleArn: baselineFixture.baselineRoleArn,
        authorizedRoleArns: Object.values(baselineFixture.config.aws.roles),
      }),
    'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
  );
  for (const resource of [
    '*',
    `arn:aws:sns:us-east-1:${baselineFixture.accountId}:checkout-${baselineFixture.config.environment}-unrelated`,
  ]) {
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document: fixturePolicy(['sns:ListSubscriptionsByTopic'], resource),
          roleKey: 'baselineRoleArn',
          config: baselineFixture.config,
          sourceType: 'INLINE',
          auditedRoleArn: baselineFixture.baselineRoleArn,
          authorizedRoleArns: Object.values(baselineFixture.config.aws.roles),
        }),
      resource === '*'
        ? 'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC'
        : 'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    );
  }
  for (const resource of [
    '*',
    `arn:aws:secretsmanager:us-east-1:${baselineFixture.accountId}:${['sec', 'ret'].join('')}:checkout/assessment-release/unrelated-AbCdEf`,
  ]) {
    expectCode(
      () =>
        normalizeIamPolicyDocument({
          document: fixturePolicy(['secretsmanager:GetSecretValue'], resource),
          roleKey: 'bootstrapCloudFormationExecutionRoleArn',
          config: baselineFixture.config,
          sourceType: 'INLINE',
          auditedRoleArn: bootstrapRoleArns(baselineFixture.config)
            .bootstrapCloudFormationExecutionRoleArn,
          authorizedRoleArns: [
            ...Object.values(baselineFixture.config.aws.roles),
            ...Object.values(bootstrapRoleArns(baselineFixture.config)),
          ],
        }),
      resource === '*'
        ? 'E7_IAM_ALLOW_RESOURCE_WILDCARD_OR_DYNAMIC'
        : 'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
    );
  }

  const missingBaselineVersioningFixture = fixtureEnvironment({ scope: 'baseline' });
  const originalMissingBaselineVersioningCall = missingBaselineVersioningFixture.callAws;
  missingBaselineVersioningFixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    if (
      roleName === missingBaselineVersioningFixture.roleNames.baselineRoleArn &&
      operation === 'get-role-policy'
    ) {
      const actions = IAM_ROLE_PERMISSION_PROFILES.baselineRoleArn.actions.filter(
        (action) => action !== 's3:getbucketversioning',
      );
      return {
        RoleName: roleName,
        PolicyName: 'baseline-inline',
        PolicyDocument: missingBaselineVersioningFixture.rolePolicy('baselineRoleArn', actions),
      };
    }
    return originalMissingBaselineVersioningCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingBaselineVersioningFixture.config,
        scope: 'baseline',
        candidateSha,
        releaseId,
        manifestSha256,
        baselineRoleArn: missingBaselineVersioningFixture.baselineRoleArn,
        callAws: missingBaselineVersioningFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_REQUIRED_EFFECTIVE_PERMISSION_MISSING',
  );

  const missingCfnSecretValueFixture = fixtureEnvironment({ scope: 'baseline' });
  const originalMissingCfnSecretValueCall = missingCfnSecretValueFixture.callAws;
  missingCfnSecretValueFixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    const policyNameIndex = arguments_.indexOf('--policy-name');
    const policyName = policyNameIndex === -1 ? undefined : arguments_[policyNameIndex + 1];
    if (
      roleName === missingCfnSecretValueFixture.roleNames.bootstrapCloudFormationExecutionRoleArn &&
      operation === 'get-role-policy'
    ) {
      const actions =
        IAM_ROLE_PERMISSION_PROFILES.bootstrapCloudFormationExecutionRoleArn.actions.filter(
          (action) => action !== 'secretsmanager:getsecretvalue',
        );
      return {
        RoleName: roleName,
        PolicyName: policyName,
        PolicyDocument: missingCfnSecretValueFixture.rolePolicy(
          'bootstrapCloudFormationExecutionRoleArn',
          actions,
        ),
      };
    }
    return originalMissingCfnSecretValueCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingCfnSecretValueFixture.config,
        scope: 'baseline',
        candidateSha,
        releaseId,
        manifestSha256,
        baselineRoleArn: missingCfnSecretValueFixture.baselineRoleArn,
        callAws: missingCfnSecretValueFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_REQUIRED_EFFECTIVE_PERMISSION_MISSING',
  );

  const missingBaselineSnsFixture = fixtureEnvironment({ scope: 'baseline' });
  const originalMissingBaselineSnsCall = missingBaselineSnsFixture.callAws;
  missingBaselineSnsFixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    if (
      roleName === missingBaselineSnsFixture.roleNames.baselineRoleArn &&
      operation === 'get-role-policy'
    ) {
      const actions = IAM_ROLE_PERMISSION_PROFILES.baselineRoleArn.actions.filter(
        (action) => action !== 'sns:listsubscriptionsbytopic',
      );
      return {
        RoleName: roleName,
        PolicyName: 'baseline-inline',
        PolicyDocument: missingBaselineSnsFixture.rolePolicy('baselineRoleArn', actions),
      };
    }
    return originalMissingBaselineSnsCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingBaselineSnsFixture.config,
        scope: 'baseline',
        candidateSha,
        releaseId,
        manifestSha256,
        baselineRoleArn: missingBaselineSnsFixture.baselineRoleArn,
        callAws: missingBaselineSnsFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_REQUIRED_EFFECTIVE_PERMISSION_MISSING',
  );

  const adminFixture = fixtureEnvironment();
  const originalAdminCall = adminFixture.callAws;
  adminFixture.callAws = (service, operation, arguments_) => {
    if (operation === 'list-attached-role-policies') {
      return {
        AttachedPolicies: [
          {
            PolicyName: 'AdministratorAccess',
            PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
          },
        ],
        IsTruncated: false,
      };
    }
    return originalAdminCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: adminFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: adminFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_ADMINISTRATOR_ACCESS_FORBIDDEN',
  );

  const bootstrapAdminFixture = fixtureEnvironment();
  const originalBootstrapAdminCall = bootstrapAdminFixture.callAws;
  bootstrapAdminFixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    if (
      operation === 'list-attached-role-policies' &&
      roleName === bootstrapAdminFixture.roleNames.bootstrapCloudFormationExecutionRoleArn
    ) {
      return {
        AttachedPolicies: [
          {
            PolicyName: 'AdministratorAccess',
            PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
          },
        ],
      };
    }
    return originalBootstrapAdminCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: bootstrapAdminFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: bootstrapAdminFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_ADMINISTRATOR_ACCESS_FORBIDDEN',
  );

  const bootstrapTrustFixture = fixtureEnvironment();
  const originalBootstrapTrustCall = bootstrapTrustFixture.callAws;
  bootstrapTrustFixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    const response = originalBootstrapTrustCall(service, operation, arguments_);
    if (
      operation === 'get-role' &&
      roleName === bootstrapTrustFixture.roleNames.bootstrapDeployRoleArn
    ) {
      response.Role.AssumeRolePolicyDocument.Statement[0].Principal.AWS = `arn:aws:iam::${bootstrapTrustFixture.accountId}:root`;
    }
    return response;
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: bootstrapTrustFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: bootstrapTrustFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_BOOTSTRAP_TRUST_INVALID',
  );

  const missingFixture = fixtureEnvironment();
  const originalMissingCall = missingFixture.callAws;
  missingFixture.callAws = (service, operation, arguments_) => {
    if (operation === 'get-policy-version') return { PolicyVersion: {} };
    return originalMissingCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: missingFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_MANAGED_POLICY_VERSION_INVALID',
  );

  const boundaryFixture = fixtureEnvironment();
  const originalBoundaryCall = boundaryFixture.callAws;
  boundaryFixture.callAws = (service, operation, arguments_) => {
    const policyArn = arguments_[arguments_.indexOf('--policy-arn') + 1];
    if (operation === 'get-policy-version' && policyArn?.endsWith('-boundary')) {
      return {
        PolicyVersion: {
          VersionId: 'v3',
          IsDefaultVersion: true,
          Document: fixturePolicy(
            ['iam:CreateUser'],
            `arn:aws:iam::${boundaryFixture.accountId}:user/unapproved`,
          ),
        },
      };
    }
    return originalBoundaryCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: boundaryFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: boundaryFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_CAPABILITY_OUTSIDE_ROLE_PROFILE',
  );

  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: prereleaseFixture.config,
        scope: 'prerelease',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: prereleaseFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_CLEANUP_WATCHDOG_ROLE_REQUIRED',
  );
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: baselineFixture.config,
        scope: 'baseline',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: baselineFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_BASELINE_ROLE_SCOPE_INVALID',
  );

  const paginationFixture = fixtureEnvironment();
  const originalPaginationCall = paginationFixture.callAws;
  paginationFixture.callAws = (service, operation, arguments_) => {
    if (operation === 'list-role-policies') {
      return { PolicyNames: ['loop'], NextToken: 'same-token' };
    }
    return originalPaginationCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: paginationFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: paginationFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_PAGINATION_INVALID',
  );

  const missingIdentityFixture = fixtureEnvironment();
  const originalMissingIdentityCall = missingIdentityFixture.callAws;
  missingIdentityFixture.callAws = (service, operation, arguments_) => {
    if (['list-role-policies', 'list-attached-role-policies'].includes(operation)) {
      return operation === 'list-role-policies' ? { PolicyNames: [] } : { AttachedPolicies: [] };
    }
    return originalMissingIdentityCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingIdentityFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: missingIdentityFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_IDENTITY_POLICY_MISSING',
  );

  const missingIndexFixture = fixtureEnvironment();
  const originalMissingIndexCall = missingIndexFixture.callAws;
  missingIndexFixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    if (roleName === missingIndexFixture.roleNames.rollbackRoleArn && operation === 'get-role') {
      const response = originalMissingIndexCall(service, operation, arguments_);
      delete response.Role.PermissionsBoundary;
      return response;
    }
    if (
      roleName === missingIndexFixture.roleNames.rollbackRoleArn &&
      operation === 'get-role-policy'
    ) {
      const response = originalMissingIndexCall(service, operation, arguments_);
      const query = response.PolicyDocument.Statement.find((statement) =>
        (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
          .map((action) => action.toLowerCase())
          .includes('dynamodb:query'),
      );
      query.Resource = `arn:aws:dynamodb:${missingIndexFixture.config.aws.region}:${missingIndexFixture.accountId}:table/checkout-${missingIndexFixture.config.environment}-*/index/Unrelated`;
      return response;
    }
    return originalMissingIndexCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingIndexFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: missingIndexFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_RESOURCE_OUTSIDE_ROLE_SCOPE',
  );

  const missingReconciliationJournalFixture = fixtureEnvironment();
  const originalMissingReconciliationJournalCall = missingReconciliationJournalFixture.callAws;
  missingReconciliationJournalFixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    if (
      roleName === missingReconciliationJournalFixture.roleNames.rollbackRoleArn &&
      operation === 'get-role-policy'
    ) {
      const response = originalMissingReconciliationJournalCall(service, operation, arguments_);
      const reconciliationResource = rollbackJournalReadResources(
        missingReconciliationJournalFixture.config,
        candidateSha,
      ).at(-1);
      for (const statement of response.PolicyDocument.Statement) {
        const actions = (
          Array.isArray(statement.Action) ? statement.Action : [statement.Action]
        ).map((action) => action.toLowerCase());
        if (actions.some((action) => action.startsWith('ssm:'))) {
          statement.Resource = (
            Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource]
          ).filter((resource) => resource !== reconciliationResource);
        }
      }
      return response;
    }
    return originalMissingReconciliationJournalCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingReconciliationJournalFixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        callAws: missingReconciliationJournalFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_REQUIRED_EFFECTIVE_PERMISSION_MISSING',
  );

  const missingWatchdogReadFixture = fixtureEnvironment({ scope: 'prerelease' });
  const originalMissingWatchdogReadCall = missingWatchdogReadFixture.callAws;
  missingWatchdogReadFixture.callAws = (service, operation, arguments_) => {
    const roleNameIndex = arguments_.indexOf('--role-name');
    const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
    if (
      roleName === missingWatchdogReadFixture.roleNames.readRoleArn &&
      operation === 'get-role-policy'
    ) {
      const response = originalMissingWatchdogReadCall(service, operation, arguments_);
      const iam = response.PolicyDocument.Statement.find((statement) =>
        (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
          .map((action) => action.toLowerCase())
          .includes('iam:getrole'),
      );
      iam.Resource = iam.Resource.filter(
        (resource) => resource !== missingWatchdogReadFixture.cleanupWatchdogRoleArn,
      );
      return response;
    }
    return originalMissingWatchdogReadCall(service, operation, arguments_);
  };
  expectCode(
    () =>
      collectIamEffectivePermissions({
        config: missingWatchdogReadFixture.config,
        scope: 'prerelease',
        candidateSha,
        releaseId,
        manifestSha256,
        cleanupWatchdogRoleArn: missingWatchdogReadFixture.cleanupWatchdogRoleArn,
        callAws: missingWatchdogReadFixture.callAws,
        validateTrust: () => true,
      }),
    'E7_IAM_REQUIRED_RESOURCE_COVERAGE_MISSING',
  );

  const auxiliaryActionTargets = [
    ...['journalRoleArn', 'reconciliationRecoveryRoleArn'].flatMap((authorityKey) =>
      [
        'iam:getrole',
        'iam:getrolepolicy',
        'iam:listattachedrolepolicies',
        'iam:listrolepolicies',
      ].map((action) => [authorityKey, action]),
    ),
    ...['journalPermissionsBoundaryArn', 'reconciliationRecoveryPermissionsBoundaryArn'].flatMap(
      (authorityKey) =>
        ['iam:getpolicy', 'iam:getpolicyversion'].map((action) => [authorityKey, action]),
    ),
  ];
  for (const [authorityKey, action] of auxiliaryActionTargets) {
    const missingAuxiliaryGrantFixture = fixtureEnvironment();
    const originalMissingAuxiliaryGrantCall = missingAuxiliaryGrantFixture.callAws;
    missingAuxiliaryGrantFixture.callAws = (service, operation, arguments_) => {
      const roleNameIndex = arguments_.indexOf('--role-name');
      const roleName = roleNameIndex === -1 ? undefined : arguments_[roleNameIndex + 1];
      if (
        roleName === missingAuxiliaryGrantFixture.roleNames.readRoleArn &&
        operation === 'get-role-policy'
      ) {
        const response = originalMissingAuxiliaryGrantCall(service, operation, arguments_);
        const statement = response.PolicyDocument.Statement.find((entry) =>
          (Array.isArray(entry.Action) ? entry.Action : [entry.Action])
            .map((entryAction) => entryAction.toLowerCase())
            .includes(action),
        );
        if (statement === undefined) return response;
        statement.Resource = (
          Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource]
        ).filter(
          (resource) =>
            resource !== missingAuxiliaryGrantFixture.auxiliaryRoleAuthorityInputs[authorityKey],
        );
        return response;
      }
      return originalMissingAuxiliaryGrantCall(service, operation, arguments_);
    };
    expectCode(
      () =>
        collectIamEffectivePermissions({
          config: missingAuxiliaryGrantFixture.config,
          scope: 'full',
          candidateSha,
          releaseId,
          manifestSha256,
          bootstrapAssetInventory: missingAuxiliaryGrantFixture.bootstrapAssetInventory,
          callAws: missingAuxiliaryGrantFixture.callAws,
          validateTrust: () => true,
        }),
      'E7_IAM_REQUIRED_RESOURCE_COVERAGE_MISSING',
    );
  }

  for (const mutate of [
    (value) => {
      value.candidateSha = 'c'.repeat(40);
    },
    (value) => {
      value.configSha256 = 'd'.repeat(64);
    },
    (value) => {
      value.roles.rollbackRoleArn.permissionSetSha256 = 'e'.repeat(64);
    },
    (value) => {
      value.roles.rollbackRoleArn.effectiveGrantsSha256 = '1'.repeat(64);
    },
    (value) => {
      value.bootstrapRoles.roles.bootstrapDeployRoleArn.trustPolicySha256 = '2'.repeat(64);
    },
    (value) => {
      value.bootstrapRoles.sanitizedPolicyTemplate.templateSha256 = '3'.repeat(64);
    },
    (value) => {
      value.bindingSha256 = 'f'.repeat(64);
    },
    (value) => {
      value.auxiliaryRoleAuthorities.reconciliationRecoveryRoleArnSha256 = '4'.repeat(64);
    },
  ]) {
    const tampered = structuredClone(evidence);
    mutate(tampered);
    expectCode(
      () =>
        validateIamEffectivePermissionsEvidence({
          value: tampered,
          config: fixture.config,
          scope: 'full',
          candidateSha,
          releaseId,
          manifestSha256,
          bootstrapAssetInventory: fixture.bootstrapAssetInventory,
        }),
      'E7_IAM_PERMISSIONS_EVIDENCE_INVALID',
    );
  }
  const rehashedAuxiliaryAuthority = structuredClone(evidence);
  rehashedAuxiliaryAuthority.auxiliaryRoleAuthorities.reconciliationRecoveryRoleArnSha256 =
    '4'.repeat(64);
  const rehashedAuxiliaryBody = {
    ...rehashedAuxiliaryAuthority.auxiliaryRoleAuthorities,
  };
  delete rehashedAuxiliaryBody.authoritySetSha256;
  rehashedAuxiliaryAuthority.auxiliaryRoleAuthorities.authoritySetSha256 =
    objectSha256(rehashedAuxiliaryBody);
  rehashedAuxiliaryAuthority.bindingSha256 = evidenceBinding(rehashedAuxiliaryAuthority);
  expectCode(
    () =>
      validateIamEffectivePermissionsEvidence({
        value: rehashedAuxiliaryAuthority,
        config: fixture.config,
        scope: 'full',
        candidateSha,
        releaseId,
        manifestSha256,
        bootstrapAssetInventory: fixture.bootstrapAssetInventory,
      }),
    'E7_IAM_PERMISSIONS_EVIDENCE_INVALID',
  );

  return {
    status: 'PASS',
    canaries: 135,
    simulatedAwsRequests: fixture.calls.length,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
};

const isMain =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== '--self-test') {
      fail('E7_IAM_CLI_SELF_TEST_ONLY');
    }
    process.stdout.write(`${JSON.stringify(selfTestIamEffectivePermissions())}\n`);
  } catch (error) {
    const code =
      error instanceof IamEffectivePermissionsError ? error.code : 'E7_IAM_SELF_TEST_FAILED';
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  }
}
