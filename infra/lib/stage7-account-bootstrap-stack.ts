import { BootstraplessSynthesizer, CfnOutput, RemovalPolicy, Stack } from 'aws-cdk-lib';
import type { StackProps } from 'aws-cdk-lib';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import type { Construct } from 'constructs';

// This frozen product module is the authority for action profiles, required actions and
// policy normalization. Synthesis fails when the generated policies drift from it.
// @ts-expect-error The product contract is an ESM JavaScript module without declarations.
import * as iamContractModule from '../../scripts/stage7/iam-effective-permissions.mjs';

import {
  STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS,
  STAGE7_ACCOUNT_BOOTSTRAP_OIDC_HOST,
  STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS,
  STAGE7_ACCOUNT_BOOTSTRAP_REPOSITORY,
  STAGE7_ACCOUNT_BOOTSTRAP_ROLE_PATH,
} from './stage7-account-bootstrap-config';
import type {
  Stage7AccountBootstrapConfig,
  Stage7CdkRoleKey,
  Stage7PrimaryRoleKey,
  Stage7RoleSet,
} from './stage7-account-bootstrap-config';

type ContractScope = 'full' | 'prerelease' | 'baseline';
type PolicyRoleKey =
  Stage7PrimaryRoleKey | 'baselineRoleArn' | 'cleanupWatchdogRoleArn' | Stage7CdkRoleKey;

interface IamStatement {
  readonly Effect: 'Allow' | 'Deny';
  readonly Principal?: Readonly<Record<string, string | readonly string[]>>;
  readonly Action: string | readonly string[];
  readonly Resource?: string | readonly string[];
  readonly Condition?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
}

interface IamPolicyDocument {
  readonly Version: '2012-10-17';
  readonly Statement: readonly IamStatement[];
}

interface ContractRoleProfile {
  readonly actions: readonly string[];
  readonly requiredActions: readonly string[];
  readonly oidcSubjects: Readonly<Record<ContractScope, readonly string[]>>;
}

interface IamContractApi {
  readonly IAM_ROLE_PERMISSION_PROFILES: Readonly<Record<PolicyRoleKey, ContractRoleProfile>>;
  readonly normalizeIamPolicyDocument: (input: {
    readonly document: IamPolicyDocument;
    readonly roleKey: PolicyRoleKey;
    readonly config: unknown;
    readonly sourceType: 'INLINE';
    readonly auditedRoleArn: string;
    readonly authorizedRoleArns: readonly string[];
    readonly authorizedPolicyArns: readonly string[];
    readonly permissionContext: Readonly<{ candidateSha: string; releaseId: string }>;
  }) => Readonly<{ allowActions: readonly string[] }>;
}

const iamContract = iamContractModule as unknown as IamContractApi;
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
const uniqueSorted = (values: readonly string[]): string[] => [...new Set(values)].toSorted();

type ResourceClass =
  | 'GLOBAL_RESOURCE_REQUIRED'
  | 'ACM_CERTIFICATE'
  | 'API_GATEWAY_TAGGED'
  | 'BUDGET'
  | 'CLOUDFORMATION_STACK'
  | 'CLOUDFORMATION_CHANGE_SET_STACK'
  | 'CLOUDFRONT_DISTRIBUTION_TAGGED'
  | 'CLOUDFRONT_FUNCTION'
  | 'CLOUDFRONT_ORIGIN_ACCESS_CONTROL'
  | 'CLOUDFRONT_RESPONSE_HEADERS_POLICY'
  | 'CLOUDFRONT_STAGE7_RESOURCE'
  | 'CLOUDWATCH_ALARM'
  | 'CLOUDWATCH_DASHBOARD'
  | 'CLOUDWATCH_STAGE7_RESOURCE'
  | 'CLOUDWATCH_METRIC_NAMESPACE'
  | 'DYNAMODB_TABLE'
  | 'DYNAMODB_TABLE_AND_INDEX'
  | 'IAM_BOOTSTRAP_EXECUTION_ROLE'
  | 'IAM_APPLICATION_ROLE'
  | 'IAM_MANAGED_POLICY'
  | 'IAM_RELEASE_ROLE'
  | 'LAMBDA_FUNCTION'
  | 'LOG_GROUP'
  | 'ROUTE53_CHANGE'
  | 'ROUTE53_ZONE'
  | 'S3_BUCKET'
  | 'S3_OBJECT'
  | 'SCHEDULER'
  | 'SECRETS_MANAGER_SECRET'
  | 'SNS_TOPIC'
  | 'SSM_PARAMETER'
  | 'STS_BOOTSTRAP_ROLE'
  | 'CDK_ASSET_REPOSITORY';

const ACTION_RESOURCE_CLASSES: Readonly<Record<ResourceClass, readonly string[]>> = Object.freeze({
  GLOBAL_RESOURCE_REQUIRED: [
    'ce:listcostallocationtags',
    'cloudformation:describestackdriftdetectionstatus',
    'cloudformation:liststacks',
    'cloudfront:createdistribution',
    'cloudfront:createfunction',
    'cloudfront:createoriginaccesscontrol',
    'cloudfront:createresponseheaderspolicy',
    'cloudfront:getkeygroup',
    'cloudfront:getpublickey',
    'cloudfront:listdistributions',
    'cloudwatch:getmetricstatistics',
    'dynamodb:listtables',
    'ecr:getauthorizationtoken',
    'lambda:getaccountsettings',
    'resourcegroupstaggingapi:getresources',
    's3:getaccountpublicaccessblock',
    'servicequotas:getservicequota',
    'servicequotas:listservicequotas',
    'sts:getcalleridentity',
  ],
  ACM_CERTIFICATE: ['acm:describecertificate'],
  API_GATEWAY_TAGGED: [
    'apigateway:delete',
    'apigateway:get',
    'apigateway:patch',
    'apigateway:post',
    'apigateway:put',
  ],
  BUDGET: [
    'budgets:createbudget',
    'budgets:deletebudget',
    'budgets:describebudget',
    'budgets:describenotificationsforbudget',
    'budgets:describesubscribersfornotification',
    'budgets:modifybudget',
  ],
  CLOUDFORMATION_STACK: [
    'cloudformation:createstack',
    'cloudformation:continueupdaterollback',
    'cloudformation:deletestack',
    'cloudformation:describestackevents',
    'cloudformation:describestackresource',
    'cloudformation:describestackresourcedrifts',
    'cloudformation:describestackresources',
    'cloudformation:describestacks',
    'cloudformation:detectstackdrift',
    'cloudformation:gettemplatesummary',
    'cloudformation:listchangesets',
    'cloudformation:liststackresources',
    'cloudformation:rollbackstack',
    'cloudformation:updatestack',
    'cloudformation:updateterminationprotection',
  ],
  CLOUDFORMATION_CHANGE_SET_STACK: [
    'cloudformation:createchangeset',
    'cloudformation:deletechangeset',
    'cloudformation:describechangeset',
    'cloudformation:executechangeset',
    'cloudformation:gettemplate',
  ],
  CLOUDFRONT_DISTRIBUTION_TAGGED: [
    'cloudfront:createinvalidation',
    'cloudfront:deletedistribution',
    'cloudfront:getdistribution',
    'cloudfront:getdistributionconfig',
    'cloudfront:getinvalidation',
    'cloudfront:listinvalidations',
    'cloudfront:updatedistribution',
  ],
  CLOUDFRONT_FUNCTION: [
    'cloudfront:deletefunction',
    'cloudfront:describefunction',
    'cloudfront:getfunction',
    'cloudfront:publishfunction',
    'cloudfront:updatefunction',
  ],
  CLOUDFRONT_ORIGIN_ACCESS_CONTROL: [
    'cloudfront:deleteoriginaccesscontrol',
    'cloudfront:getoriginaccesscontrol',
    'cloudfront:updateoriginaccesscontrol',
  ],
  CLOUDFRONT_RESPONSE_HEADERS_POLICY: [
    'cloudfront:deleteresponseheaderspolicy',
    'cloudfront:getresponseheaderspolicy',
    'cloudfront:updateresponseheaderspolicy',
  ],
  CLOUDFRONT_STAGE7_RESOURCE: [
    'cloudfront:listtagsforresource',
    'cloudfront:tagresource',
    'cloudfront:untagresource',
  ],
  CLOUDWATCH_ALARM: [
    'cloudwatch:deletealarms',
    'cloudwatch:describealarms',
    'cloudwatch:putmetricalarm',
  ],
  CLOUDWATCH_DASHBOARD: [
    'cloudwatch:deletedashboards',
    'cloudwatch:getdashboard',
    'cloudwatch:putdashboard',
  ],
  CLOUDWATCH_STAGE7_RESOURCE: ['cloudwatch:tagresource', 'cloudwatch:untagresource'],
  CLOUDWATCH_METRIC_NAMESPACE: ['cloudwatch:putmetricdata'],
  DYNAMODB_TABLE: [
    'dynamodb:createtable',
    'dynamodb:deletetable',
    'dynamodb:describecontinuousbackups',
    'dynamodb:describetable',
    'dynamodb:getitem',
    'dynamodb:putitem',
    'dynamodb:transactwriteitems',
    'dynamodb:tagresource',
    'dynamodb:untagresource',
    'dynamodb:updatecontinuousbackups',
    'dynamodb:updateitem',
    'dynamodb:updatetable',
  ],
  DYNAMODB_TABLE_AND_INDEX: ['dynamodb:query'],
  IAM_BOOTSTRAP_EXECUTION_ROLE: ['iam:passrole'],
  IAM_APPLICATION_ROLE: [
    'iam:createrole',
    'iam:deleterole',
    'iam:deleterolepolicy',
    'iam:putrolepolicy',
    'iam:tagrole',
    'iam:untagrole',
  ],
  IAM_MANAGED_POLICY: ['iam:getpolicy', 'iam:getpolicyversion'],
  IAM_RELEASE_ROLE: [
    'iam:getrole',
    'iam:getrolepolicy',
    'iam:listattachedrolepolicies',
    'iam:listrolepolicies',
  ],
  LAMBDA_FUNCTION: [
    'lambda:addpermission',
    'lambda:createalias',
    'lambda:createfunction',
    'lambda:deletealias',
    'lambda:deletefunction',
    'lambda:deletefunctionconcurrency',
    'lambda:getalias',
    'lambda:getfunction',
    'lambda:getfunctionconfiguration',
    'lambda:invokefunction',
    'lambda:listversionsbyfunction',
    'lambda:publishversion',
    'lambda:putfunctionconcurrency',
    'lambda:removepermission',
    'lambda:tagresource',
    'lambda:untagresource',
    'lambda:updatealias',
    'lambda:updatefunctioncode',
    'lambda:updatefunctionconfiguration',
  ],
  LOG_GROUP: [
    'logs:createloggroup',
    'logs:deleteloggroup',
    'logs:deletemetricfilter',
    'logs:deleteretentionpolicy',
    'logs:describeloggroups',
    'logs:describemetricfilters',
    'logs:putmetricfilter',
    'logs:putretentionpolicy',
    'logs:tagloggroup',
    'logs:untagloggroup',
  ],
  ROUTE53_CHANGE: ['route53:getchange'],
  ROUTE53_ZONE: [
    'route53:changeresourcerecordsets',
    'route53:gethostedzone',
    'route53:listresourcerecordsets',
  ],
  S3_BUCKET: [
    's3:createbucket',
    's3:deletebucket',
    's3:deletebucketpolicy',
    's3:deletebucketpublicaccessblock',
    's3:getbucketlocation',
    's3:getbucketpolicy',
    's3:getbucketpolicystatus',
    's3:getbucketpublicaccessblock',
    's3:getbucketversioning',
    's3:listbucket',
    's3:listbucketmultipartuploads',
    's3:listbucketversions',
    's3:putbucketencryption',
    's3:putbucketlifecycleconfiguration',
    's3:putbucketownershipcontrols',
    's3:putbucketpolicy',
    's3:putbucketpublicaccessblock',
    's3:putbuckettagging',
    's3:putbucketversioning',
  ],
  S3_OBJECT: [
    's3:abortmultipartupload',
    's3:deleteobject',
    's3:deleteobjectversion',
    's3:getobject',
    's3:getobjectversion',
    's3:listmultipartuploadparts',
    's3:putobject',
  ],
  SCHEDULER: [
    'scheduler:createschedule',
    'scheduler:deleteschedule',
    'scheduler:getschedule',
    'scheduler:tagresource',
    'scheduler:untagresource',
    'scheduler:updateschedule',
  ],
  SECRETS_MANAGER_SECRET: ['secretsmanager:describesecret', 'secretsmanager:getsecretvalue'],
  SNS_TOPIC: [
    'sns:createtopic',
    'sns:deletetopic',
    'sns:gettopicattributes',
    'sns:listsubscriptionsbytopic',
    'sns:setsubscriptionattributes',
    'sns:settopicattributes',
    'sns:subscribe',
    'sns:tagresource',
    'sns:unsubscribe',
    'sns:untagresource',
  ],
  SSM_PARAMETER: [
    'ssm:addtagstoresource',
    'ssm:deleteparameter',
    'ssm:getparameter',
    'ssm:getparametersbypath',
    'ssm:putparameter',
    'ssm:removetagsfromresource',
  ],
  STS_BOOTSTRAP_ROLE: ['sts:assumerole'],
  CDK_ASSET_REPOSITORY: [
    'ecr:batchchecklayeravailability',
    'ecr:completelayerupload',
    'ecr:describerepositories',
    'ecr:initiatelayerupload',
    'ecr:putimage',
    'ecr:uploadlayerpart',
  ],
});

const resourceClassByAction = new Map<string, ResourceClass>();
for (const [resourceClass, actions] of Object.entries(ACTION_RESOURCE_CLASSES) as Array<
  [ResourceClass, readonly string[]]
>) {
  for (const action of actions) {
    if (resourceClassByAction.has(action)) fail('E7_ACCOUNT_BOOTSTRAP_ACTION_CLASS_DUPLICATE');
    resourceClassByAction.set(action, resourceClass);
  }
}
for (const profile of Object.values(iamContract.IAM_ROLE_PERMISSION_PROFILES)) {
  for (const action of profile.actions) {
    if (!resourceClassByAction.has(action)) {
      fail(`E7_ACCOUNT_BOOTSTRAP_ACTION_CLASS_MISSING_${action.toUpperCase()}`);
    }
  }
}

interface ProductPolicyConfig {
  readonly environment: string;
  readonly aws: Readonly<{
    accountId: string;
    region: string;
    roles: Stage7RoleSet;
  }>;
  readonly credentialReferences: readonly string[];
  readonly domain: Readonly<{
    hostedZoneId: string;
    apiHostname: string;
    webCertificateArn: string;
    apiCertificateArn: string;
  }>;
  readonly prereleaseAccess: Readonly<{
    originTokenSecretArn: string;
  }>;
}

interface PolicyAuthority {
  readonly productConfig: ProductPolicyConfig;
  readonly scope: ContractScope;
  readonly authorizedRoleArns: readonly string[];
  readonly authorizedPolicyArns: readonly string[];
  readonly auditedRoleArns: Readonly<Record<PolicyRoleKey, string>>;
}

const masterSubject = `repo:${STAGE7_ACCOUNT_BOOTSTRAP_REPOSITORY}:ref:refs/heads/master`;

const oidcTrust = (
  config: Stage7AccountBootstrapConfig,
  subjects: readonly string[],
): IamPolicyDocument => {
  if (subjects.length < 1 || new Set(subjects).size !== subjects.length) {
    fail('E7_ACCOUNT_BOOTSTRAP_OIDC_SUBJECT_SET_INVALID');
  }
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { Federated: config.oidcProviderArn },
        Action: 'sts:AssumeRoleWithWebIdentity',
        Condition: {
          StringEquals: {
            [`${STAGE7_ACCOUNT_BOOTSTRAP_OIDC_HOST}:aud`]: 'sts.amazonaws.com',
            [`${STAGE7_ACCOUNT_BOOTSTRAP_OIDC_HOST}:sub`]:
              subjects.length === 1 ? subjects[0] : [...subjects],
          },
        },
      },
    ],
  };
};

const cdkTrust = (roleKey: Stage7CdkRoleKey, authority: PolicyAuthority): IamPolicyDocument => {
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
  const roles = authority.productConfig.aws.roles;
  const principal =
    roleKey === 'bootstrapLookupRoleArn'
      ? roles.readRoleArn
      : [roles.baselineRoleArn, roles.deployRoleArn].toSorted();
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

const releaseMutationGuardReadResources = (
  config: ProductPolicyConfig,
  candidateSha: string,
): string[] =>
  ['release-fence', 'release-finalization', 'rollback'].map(
    (name) =>
      `arn:aws:ssm:${config.aws.region}:${config.aws.accountId}:parameter/checkout/stage7/${name}/${candidateSha}/*`,
  );

const rollbackJournalReadResources = (
  config: ProductPolicyConfig,
  candidateSha: string,
): string[] =>
  ['RB-E7-06', 'RB-E7-08', 'release-reconciliation'].map(
    (scenarioId) =>
      `arn:aws:ssm:${config.aws.region}:${config.aws.accountId}:parameter/checkout/stage7/rollback/${candidateSha}/${scenarioId}/*`,
  );

const stageStackResources = (config: ProductPolicyConfig): string[] =>
  ['data', 'api', 'observability', 'web'].map(
    (suffix) =>
      `arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/checkout-${config.environment}-${suffix}/*`,
  );

const cloudFormationStackResources = (
  config: ProductPolicyConfig,
  roleKey: PolicyRoleKey,
): string[] => [
  ...stageStackResources(config),
  ...(roleKey === 'readRoleArn'
    ? [`arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/CDKToolkit/*`]
    : []),
];

const cloudFormationChangeSetResources = (
  config: ProductPolicyConfig,
  roleKey: PolicyRoleKey,
): string[] =>
  roleKey === 'rollbackRoleArn'
    ? [
        `arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/checkout-${config.environment}-observability/*`,
      ]
    : cloudFormationStackResources(config, roleKey);

const taggedCondition = (config: ProductPolicyConfig) => ({
  StringEquals: {
    'aws:ResourceTag/Environment': config.environment,
    'aws:ResourceTag/Project': 'checkout',
  },
});

const resourcesForClass = (
  resourceClass: ResourceClass,
  roleKey: PolicyRoleKey,
  authority: PolicyAuthority,
  root: Stage7AccountBootstrapConfig,
): readonly string[] => {
  const config = authority.productConfig;
  const { accountId, region } = config.aws;
  const environment = config.environment;
  const bootstrap = root.bootstrap;
  switch (resourceClass) {
    case 'GLOBAL_RESOURCE_REQUIRED':
    case 'CLOUDWATCH_METRIC_NAMESPACE':
      return ['*'];
    case 'ACM_CERTIFICATE':
      return [config.domain.webCertificateArn, config.domain.apiCertificateArn];
    case 'API_GATEWAY_TAGGED':
      return roleKey === 'bootstrapCloudFormationExecutionRoleArn'
        ? [
            `arn:aws:apigateway:${region}::/apis`,
            `arn:aws:apigateway:${region}::/apis/*`,
            `arn:aws:apigateway:${region}::/domainnames/${config.domain.apiHostname}`,
            `arn:aws:apigateway:${region}::/domainnames/${config.domain.apiHostname}/apimappings`,
            `arn:aws:apigateway:${region}::/domainnames/${config.domain.apiHostname}/apimappings/*`,
          ]
        : [
            `arn:aws:apigateway:${region}::/apis/*`,
            `arn:aws:apigateway:${region}::/domainnames/${config.domain.apiHostname}/apimappings`,
          ];
    case 'BUDGET':
      return [`arn:aws:budgets::${accountId}:budget/checkout-${environment}-*`];
    case 'CLOUDFORMATION_STACK':
      return cloudFormationStackResources(config, roleKey);
    case 'CLOUDFORMATION_CHANGE_SET_STACK':
      return cloudFormationChangeSetResources(config, roleKey);
    case 'CLOUDFRONT_DISTRIBUTION_TAGGED':
      return [`arn:aws:cloudfront::${accountId}:distribution/*`];
    case 'CLOUDFRONT_FUNCTION':
      return [`arn:aws:cloudfront::${accountId}:function/checkout-${environment}-*`];
    case 'CLOUDFRONT_ORIGIN_ACCESS_CONTROL':
      return [`arn:aws:cloudfront::${accountId}:origin-access-control/*`];
    case 'CLOUDFRONT_RESPONSE_HEADERS_POLICY':
      return [`arn:aws:cloudfront::${accountId}:response-headers-policy/*`];
    case 'CLOUDFRONT_STAGE7_RESOURCE':
      return [
        `arn:aws:cloudfront::${accountId}:distribution/*`,
        `arn:aws:cloudfront::${accountId}:function/checkout-${environment}-*`,
        `arn:aws:cloudfront::${accountId}:origin-access-control/*`,
        `arn:aws:cloudfront::${accountId}:response-headers-policy/*`,
      ];
    case 'CLOUDWATCH_ALARM':
      return [
        roleKey === 'rollbackRoleArn'
          ? `arn:aws:cloudwatch:${region}:${accountId}:alarm:checkout-${environment}-rollback-rehearsal`
          : `arn:aws:cloudwatch:${region}:${accountId}:alarm:checkout-${environment}-*`,
      ];
    case 'CLOUDWATCH_DASHBOARD':
      return [`arn:aws:cloudwatch::${accountId}:dashboard/checkout-${environment}-*`];
    case 'CLOUDWATCH_STAGE7_RESOURCE':
      return [
        `arn:aws:cloudwatch:${region}:${accountId}:alarm:checkout-${environment}-*`,
        `arn:aws:cloudwatch::${accountId}:dashboard/checkout-${environment}-*`,
      ];
    case 'DYNAMODB_TABLE':
      return [`arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*`];
    case 'DYNAMODB_TABLE_AND_INDEX':
      return roleKey === 'rollbackRoleArn'
        ? [
            `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*/index/GSI2-PendingAge`,
          ]
        : [
            `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*`,
            `arn:aws:dynamodb:${region}:${accountId}:table/checkout-${environment}-*/index/*`,
          ];
    case 'IAM_BOOTSTRAP_EXECUTION_ROLE':
      return [
        roleKey === 'bootstrapCloudFormationExecutionRoleArn'
          ? `arn:aws:iam::${accountId}:role/checkout-${environment}-*`
          : bootstrap.roles.bootstrapCloudFormationExecutionRoleArn,
      ];
    case 'IAM_APPLICATION_ROLE':
      return [`arn:aws:iam::${accountId}:role/checkout-${environment}-*`];
    case 'IAM_MANAGED_POLICY':
      return [
        `arn:aws:iam::${accountId}:policy/checkout-stage7-${environment}-*`,
        ...(roleKey === 'readRoleArn' ? authority.authorizedPolicyArns : []),
      ];
    case 'IAM_RELEASE_ROLE':
      return roleKey === 'bootstrapCloudFormationExecutionRoleArn'
        ? [`arn:aws:iam::${accountId}:role/checkout-${environment}-*`]
        : roleKey === 'readRoleArn'
          ? authority.authorizedRoleArns
          : [authority.auditedRoleArns[roleKey]];
    case 'LAMBDA_FUNCTION':
      return [`arn:aws:lambda:${region}:${accountId}:function:checkout-${environment}-*`];
    case 'LOG_GROUP':
      return [`arn:aws:logs:${region}:${accountId}:log-group:/checkout-${environment}/*:*`];
    case 'ROUTE53_CHANGE':
      return ['arn:aws:route53:::change/*'];
    case 'ROUTE53_ZONE':
      return [`arn:aws:route53:::hostedzone/${config.domain.hostedZoneId}`];
    case 'S3_BUCKET':
      return ['bootstrapDeployRoleArn', 'bootstrapFilePublishingRoleArn'].includes(roleKey)
        ? [`arn:aws:s3:::${bootstrap.assetBucketName}`]
        : [`arn:aws:s3:::checkout-${environment}-*`];
    case 'S3_OBJECT':
      return ['bootstrapDeployRoleArn', 'bootstrapFilePublishingRoleArn'].includes(roleKey)
        ? [`arn:aws:s3:::${bootstrap.assetBucketName}/*`]
        : roleKey === 'rollbackRoleArn'
          ? [
              `arn:aws:s3:::checkout-${environment}-*/index.html`,
              `arn:aws:s3:::checkout-${environment}-*/public-config.json`,
            ]
          : [`arn:aws:s3:::checkout-${environment}-*/*`];
    case 'SCHEDULER':
      return [
        `arn:aws:scheduler:${region}:${accountId}:schedule/default/checkout-${environment}-*`,
      ];
    case 'SECRETS_MANAGER_SECRET':
      return ['rollbackRoleArn', 'bootstrapCloudFormationExecutionRoleArn'].includes(roleKey)
        ? [config.prereleaseAccess.originTokenSecretArn]
        : config.credentialReferences.filter((reference) =>
            reference.startsWith(`arn:aws:secretsmanager:${region}:${accountId}:secret:`),
          );
    case 'SNS_TOPIC':
      return [
        ['baselineRoleArn', 'bootstrapCloudFormationExecutionRoleArn'].includes(roleKey)
          ? `arn:aws:sns:${region}:${accountId}:checkout-${environment}-alerts`
          : `arn:aws:sns:${region}:${accountId}:checkout-${environment}-*`,
      ];
    case 'SSM_PARAMETER':
      if (['bootstrapDeployRoleArn', 'bootstrapLookupRoleArn'].includes(roleKey)) {
        return [
          `arn:aws:ssm:${region}:${accountId}:parameter/cdk-bootstrap/${bootstrap.qualifier}/version`,
        ];
      }
      if (roleKey === 'rollbackRoleArn') {
        return rollbackJournalReadResources(config, root.candidateSha);
      }
      return [
        `arn:aws:ssm:${region}:${accountId}:parameter/checkout/${environment}/*`,
        ...config.credentialReferences.filter((reference) =>
          reference.startsWith(`arn:aws:ssm:${region}:${accountId}:parameter/`),
        ),
      ];
    case 'STS_BOOTSTRAP_ROLE':
      if (roleKey === 'readRoleArn') return [bootstrap.roles.bootstrapLookupRoleArn];
      if (['deployRoleArn', 'baselineRoleArn'].includes(roleKey)) {
        return [
          bootstrap.roles.bootstrapDeployRoleArn,
          bootstrap.roles.bootstrapFilePublishingRoleArn,
        ];
      }
      return [];
    case 'CDK_ASSET_REPOSITORY':
      return [`arn:aws:ecr:${region}:${accountId}:repository/${bootstrap.imageRepositoryName}`];
  }
};

const conditionForClass = (
  resourceClass: ResourceClass,
  roleKey: PolicyRoleKey,
  authority: PolicyAuthority,
): Readonly<Record<string, Readonly<Record<string, unknown>>>> | undefined => {
  if (
    resourceClass === 'CLOUDFRONT_DISTRIBUTION_TAGGED' ||
    (resourceClass === 'API_GATEWAY_TAGGED' &&
      roleKey !== 'bootstrapCloudFormationExecutionRoleArn')
  ) {
    return taggedCondition(authority.productConfig);
  }
  if (resourceClass === 'CLOUDWATCH_METRIC_NAMESPACE') {
    return { StringEquals: { 'cloudwatch:namespace': 'Checkout/Stage7Rehearsal' } };
  }
  if (resourceClass === 'IAM_BOOTSTRAP_EXECUTION_ROLE') {
    return roleKey === 'bootstrapCloudFormationExecutionRoleArn'
      ? {
          StringEquals: {
            'iam:PassedToService': ['lambda.amazonaws.com', 'scheduler.amazonaws.com'],
          },
        }
      : { StringEquals: { 'iam:PassedToService': 'cloudformation.amazonaws.com' } };
  }
  return undefined;
};

const generatedPolicy = (
  roleKey: PolicyRoleKey,
  authority: PolicyAuthority,
  root: Stage7AccountBootstrapConfig,
): IamPolicyDocument => {
  const profile = iamContract.IAM_ROLE_PERMISSION_PROFILES[roleKey];
  if (profile === undefined) fail('E7_ACCOUNT_BOOTSTRAP_ROLE_PROFILE_MISSING');
  const actionsByClass = new Map<ResourceClass, string[]>();
  for (const action of profile.actions) {
    const resourceClass =
      resourceClassByAction.get(action) ?? fail('E7_ACCOUNT_BOOTSTRAP_ACTION_CLASS_MISSING');
    const current = actionsByClass.get(resourceClass) ?? [];
    current.push(action);
    actionsByClass.set(resourceClass, current);
  }
  const statements: IamStatement[] = [];
  for (const [resourceClass, originalActions] of actionsByClass) {
    let actions = [...originalActions].toSorted();
    if (
      resourceClass === 'SSM_PARAMETER' &&
      roleKey === 'rollbackRoleArn' &&
      actions.includes('ssm:putparameter')
    ) {
      statements.push({
        Effect: 'Allow',
        Action: 'ssm:putparameter',
        Resource: rollbackJournalReadResources(authority.productConfig, root.candidateSha).slice(
          0,
          2,
        ),
        Condition: { StringEquals: { 'ssm:Overwrite': 'false' } },
      });
      actions = actions.filter((action) => action !== 'ssm:putparameter');
    }
    if (
      resourceClass === 'SSM_PARAMETER' &&
      ['readRoleArn', 'deployRoleArn', 'rollbackRoleArn'].includes(roleKey) &&
      actions.includes('ssm:getparametersbypath')
    ) {
      statements.push({
        Effect: 'Allow',
        Action: 'ssm:getparametersbypath',
        Resource: releaseMutationGuardReadResources(authority.productConfig, root.candidateSha),
      });
      actions = actions.filter((action) => action !== 'ssm:getparametersbypath');
    }
    if (actions.length === 0) continue;
    const resources = uniqueSorted(resourcesForClass(resourceClass, roleKey, authority, root));
    if (resources.length === 0) {
      if (actions.some((action) => profile.requiredActions.includes(action))) {
        fail('E7_ACCOUNT_BOOTSTRAP_REQUIRED_RESOURCE_SET_EMPTY');
      }
      continue;
    }
    const condition = conditionForClass(resourceClass, roleKey, authority);
    statements.push({
      Effect: 'Allow',
      Action:
        actions.length === 1
          ? (actions[0] ?? fail('E7_ACCOUNT_BOOTSTRAP_ACTION_SET_EMPTY'))
          : actions,
      Resource: resources.length === 1 ? resources[0] : resources,
      ...(condition === undefined ? {} : { Condition: condition }),
    });
  }
  const policy: IamPolicyDocument = { Version: '2012-10-17', Statement: statements };
  const normalized = iamContract.normalizeIamPolicyDocument({
    document: policy,
    roleKey,
    config: authority.productConfig,
    sourceType: 'INLINE',
    auditedRoleArn: authority.auditedRoleArns[roleKey],
    authorizedRoleArns: authority.authorizedRoleArns,
    authorizedPolicyArns: authority.authorizedPolicyArns,
    permissionContext: {
      candidateSha: root.candidateSha,
      releaseId: `rel-20260819-0000-${root.candidateSha.slice(0, 7)}`,
    },
  });
  if (profile.requiredActions.some((action) => !normalized.allowActions.includes(action))) {
    fail('E7_ACCOUNT_BOOTSTRAP_REQUIRED_EFFECTIVE_PERMISSION_MISSING');
  }
  return policy;
};

const activeAuthority = (config: Stage7AccountBootstrapConfig): PolicyAuthority => {
  const full = config.activeBootstrapScope === 'FULL_RELEASE';
  const scope: ContractScope = full ? 'full' : 'prerelease';
  const roles = full ? config.roles.release : config.roles.prerelease;
  const environment = full ? 'assessment-release' : config.prereleaseEnvironment;
  const auxiliaryRoleArns =
    full && config.includeAuxiliaryReadAuthority
      ? [config.auxiliary.journalRoleArn, config.auxiliary.reconciliationRecoveryRoleArn]
      : [];
  const auxiliaryPolicyArns =
    full && config.includeAuxiliaryReadAuthority
      ? [
          config.auxiliary.journalPermissionsBoundaryArn,
          config.auxiliary.reconciliationRecoveryPermissionsBoundaryArn,
        ]
      : [];
  const auditedRoleArns = Object.freeze({
    ...roles,
    cleanupWatchdogRoleArn: config.roles.cleanupWatchdogRoleArn,
    ...config.bootstrap.roles,
  }) as Readonly<Record<PolicyRoleKey, string>>;
  const activeAdditionalRoles = full ? [] : [config.roles.cleanupWatchdogRoleArn];
  const authorizedRoleArns = uniqueSorted([
    ...STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS.map((key) => roles[key]),
    roles.baselineRoleArn,
    ...activeAdditionalRoles,
    ...Object.values(config.bootstrap.roles),
    ...auxiliaryRoleArns,
  ]);
  return {
    productConfig: Object.freeze({
      environment,
      aws: Object.freeze({
        accountId: config.accountId,
        region: config.region,
        roles,
      }),
      credentialReferences: config.credentialReferences,
      domain: Object.freeze({
        hostedZoneId: config.domain.hostedZoneId,
        apiHostname: config.domain.apiHostname,
        webCertificateArn: config.domain.webCertificateArn,
        apiCertificateArn: config.domain.apiCertificateArn,
      }),
      prereleaseAccess: Object.freeze({
        originTokenSecretArn: config.originTokenSecretArn,
      }),
    }),
    scope,
    authorizedRoleArns,
    authorizedPolicyArns: uniqueSorted(auxiliaryPolicyArns),
    auditedRoleArns,
  };
};

const validateSharedFullBaselineTrust = (): void => {
  for (const roleKey of STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS) {
    const profile = iamContract.IAM_ROLE_PERMISSION_PROFILES[roleKey];
    if (!same(profile.oidcSubjects.full, profile.oidcSubjects.baseline)) {
      fail('E7_ACCOUNT_BOOTSTRAP_FULL_BASELINE_TRUST_CONTRACT_MISMATCH');
    }
  }
};

interface CreatedRole {
  readonly role: iam.CfnRole;
  readonly boundary?: iam.CfnManagedPolicy;
  readonly trust: IamPolicyDocument;
  readonly policy: IamPolicyDocument;
  readonly roleName: string;
  readonly boundaryName: string;
}

const ROLE_KEYS_WITHOUT_BOUNDARY = new Set<PolicyRoleKey>([
  // Their exact contract policies are larger than IAM's 6,144-character managed-policy quota.
  // Both remain below the 10,240-character per-role inline-policy quota.
  'readRoleArn',
  'bootstrapCloudFormationExecutionRoleArn',
]);
const IAM_MANAGED_POLICY_CHARACTER_LIMIT = 6_144;
const IAM_ROLE_INLINE_POLICY_CHARACTER_LIMIT = 10_240;

export interface Stage7AccountBootstrapStackProps extends StackProps {
  readonly configuration: Stage7AccountBootstrapConfig;
}

export class Stage7AccountBootstrapStack extends Stack {
  public constructor(scope: Construct, id: string, props: Stage7AccountBootstrapStackProps) {
    super(scope, id, {
      ...props,
      analyticsReporting: false,
      synthesizer: props.synthesizer ?? new BootstraplessSynthesizer(),
    });
    const config = props.configuration;
    if (this.stackName !== 'CDKToolkit') {
      fail('E7_ACCOUNT_BOOTSTRAP_STACK_NAME_INVALID');
    }
    if (this.account !== config.accountId || this.region !== config.region) {
      fail('E7_ACCOUNT_BOOTSTRAP_STACK_ENVIRONMENT_MISMATCH');
    }
    if (config.activeBootstrapScope === 'FULL_RELEASE') validateSharedFullBaselineTrust();
    const authority = activeAuthority(config);
    const full = config.activeBootstrapScope === 'FULL_RELEASE';

    let oidcProvider: iam.CfnOIDCProvider | undefined;
    if (full) {
      oidcProvider = new iam.CfnOIDCProvider(this, 'GithubActionsOidcProvider', {
        clientIdList: ['sts.amazonaws.com'],
        url: `https://${STAGE7_ACCOUNT_BOOTSTRAP_OIDC_HOST}`,
      });
      oidcProvider.applyRemovalPolicy(RemovalPolicy.RETAIN);
    }

    const assetBucket = new s3.CfnBucket(this, 'BootstrapAssetBucket', {
      bucketEncryption: {
        serverSideEncryptionConfiguration: [
          { serverSideEncryptionByDefault: { sseAlgorithm: 'AES256' } },
        ],
      },
      bucketName: config.bootstrap.assetBucketName,
      ownershipControls: { rules: [{ objectOwnership: 'BucketOwnerEnforced' }] },
      publicAccessBlockConfiguration: {
        blockPublicAcls: true,
        blockPublicPolicy: true,
        ignorePublicAcls: true,
        restrictPublicBuckets: true,
      },
      versioningConfiguration: { status: 'Enabled' },
    });
    assetBucket.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const imageRepository = new ecr.CfnRepository(this, 'BootstrapImageRepository', {
      encryptionConfiguration: { encryptionType: 'AES256' },
      imageScanningConfiguration: { scanOnPush: true },
      imageTagMutability: 'IMMUTABLE',
      repositoryName: config.bootstrap.imageRepositoryName,
    });
    imageRepository.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const versionParameter = new ssm.CfnParameter(this, 'BootstrapVersionParameter', {
      description: 'Stage 7 contract-first CDK bootstrap template version',
      name: config.bootstrap.versionParameterName,
      type: 'String',
      value: String(config.bootstrap.version),
    });
    versionParameter.applyRemovalPolicy(RemovalPolicy.RETAIN);

    const created = new Map<PolicyRoleKey, CreatedRole>();
    const createRole = (
      logicalId: string,
      roleKey: PolicyRoleKey,
      roleArn: string,
      boundaryArn: string,
      trust: IamPolicyDocument,
      path: string | undefined,
    ): iam.CfnRole => {
      const roleName = roleArn.split('/').at(-1) ?? '';
      const boundaryName = boundaryArn.split('/').at(-1) ?? '';
      const policy = generatedPolicy(roleKey, authority, config);
      const policyCharacters = JSON.stringify(policy).length;
      if (policyCharacters > IAM_ROLE_INLINE_POLICY_CHARACTER_LIMIT) {
        fail('E7_ACCOUNT_BOOTSTRAP_INLINE_POLICY_QUOTA_EXCEEDED');
      }
      const boundary = ROLE_KEYS_WITHOUT_BOUNDARY.has(roleKey)
        ? undefined
        : new iam.CfnManagedPolicy(this, `${logicalId}Boundary`, {
            description: `Exact Stage 7 ${roleKey} permissions boundary`,
            managedPolicyName: boundaryName,
            policyDocument: policy,
          });
      if (boundary !== undefined && policyCharacters > IAM_MANAGED_POLICY_CHARACTER_LIMIT) {
        fail('E7_ACCOUNT_BOOTSTRAP_MANAGED_POLICY_QUOTA_EXCEEDED');
      }
      const role = new iam.CfnRole(this, logicalId, {
        assumeRolePolicyDocument: trust,
        description: `Stage 7 contract-first ${roleKey}`,
        maxSessionDuration: 3600,
        ...(path === undefined ? {} : { path }),
        ...(boundary === undefined ? {} : { permissionsBoundary: boundary.ref }),
        policies: [{ policyDocument: policy, policyName: `stage7-${roleKey}` }],
        roleName,
      });
      if (
        oidcProvider !== undefined &&
        !STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS.includes(roleKey as Stage7CdkRoleKey)
      ) {
        role.addResourceDependency(oidcProvider);
      }
      created.set(roleKey, {
        role,
        ...(boundary === undefined ? {} : { boundary }),
        trust,
        policy,
        roleName,
        boundaryName,
      });
      return role;
    };

    const activeRoles = full ? config.roles.release : config.roles.prerelease;
    const activeBoundaries = full ? config.boundaries.release : config.boundaries.prerelease;
    const primaryLogicalNames: Readonly<Record<Stage7PrimaryRoleKey, string>> = {
      readRoleArn: 'Stage7ReadRole',
      deployRoleArn: 'Stage7DeployRole',
      rollbackRoleArn: 'Stage7RollbackRole',
      cleanupRoleArn: 'Stage7CleanupRole',
    };
    for (const roleKey of STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS) {
      createRole(
        primaryLogicalNames[roleKey],
        roleKey,
        activeRoles[roleKey],
        activeBoundaries[roleKey],
        oidcTrust(
          config,
          iamContract.IAM_ROLE_PERMISSION_PROFILES[roleKey].oidcSubjects[authority.scope],
        ),
        STAGE7_ACCOUNT_BOOTSTRAP_ROLE_PATH,
      );
    }
    if (full) {
      createRole(
        'Stage7BaselineRole',
        'baselineRoleArn',
        activeRoles.baselineRoleArn,
        activeBoundaries.baselineRoleArn,
        oidcTrust(
          config,
          iamContract.IAM_ROLE_PERMISSION_PROFILES.baselineRoleArn.oidcSubjects.baseline,
        ),
        STAGE7_ACCOUNT_BOOTSTRAP_ROLE_PATH,
      );
    } else {
      const watchdogTrust = oidcTrust(
        config,
        iamContract.IAM_ROLE_PERMISSION_PROFILES.cleanupWatchdogRoleArn.oidcSubjects.prerelease,
      );
      if (
        !same(
          iamContract.IAM_ROLE_PERMISSION_PROFILES.cleanupWatchdogRoleArn.oidcSubjects.prerelease,
          [masterSubject],
        )
      ) {
        fail('E7_ACCOUNT_BOOTSTRAP_WATCHDOG_TRUST_CONTRACT_MISMATCH');
      }
      createRole(
        'Stage7PrereleaseCleanupWatchdogRole',
        'cleanupWatchdogRoleArn',
        config.roles.cleanupWatchdogRoleArn,
        config.boundaries.cleanupWatchdogRoleArn,
        watchdogTrust,
        STAGE7_ACCOUNT_BOOTSTRAP_ROLE_PATH,
      );
    }

    for (const roleKey of STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS) {
      createRole(
        `Stage7${roleKey.slice('bootstrap'.length)}`,
        roleKey,
        config.bootstrap.roles[roleKey],
        config.bootstrap.boundaries[roleKey],
        cdkTrust(roleKey, authority),
        undefined,
      );
    }
    const deployPrincipal = created.get('deployRoleArn')?.role;
    const readPrincipal = created.get('readRoleArn')?.role;
    const baselinePrincipal = full ? created.get('baselineRoleArn')?.role : undefined;
    for (const roleKey of ['bootstrapDeployRoleArn', 'bootstrapFilePublishingRoleArn'] as const) {
      const role = created.get(roleKey)?.role;
      if (role === undefined || deployPrincipal === undefined) {
        throw new Error('E7_ACCOUNT_BOOTSTRAP_ROLE_SET_INVALID');
      }
      role.addResourceDependency(deployPrincipal);
      if (baselinePrincipal !== undefined) role.addResourceDependency(baselinePrincipal);
    }
    const lookupRole = created.get('bootstrapLookupRoleArn')?.role;
    if (lookupRole === undefined || readPrincipal === undefined) {
      throw new Error('E7_ACCOUNT_BOOTSTRAP_ROLE_SET_INVALID');
    }
    lookupRole.addResourceDependency(readPrincipal);

    this.emitOutputs(config, activeRoles, activeBoundaries);
  }

  private emitOutputs(
    config: Stage7AccountBootstrapConfig,
    roles: Stage7RoleSet,
    boundaries: Readonly<Record<keyof Stage7RoleSet, string>>,
  ): void {
    new CfnOutput(this, 'BootstrapVersion', { value: String(config.bootstrap.version) });
    new CfnOutput(this, 'Stage7BootstrapScope', { value: config.activeBootstrapScope });
    new CfnOutput(this, 'Stage7GithubOidcProviderArn', { value: config.oidcProviderArn });
    new CfnOutput(this, 'Stage7AwsReadRoleArn', { value: roles.readRoleArn });
    new CfnOutput(this, 'Stage7AwsDeployRoleArn', { value: roles.deployRoleArn });
    new CfnOutput(this, 'Stage7AwsRollbackRoleArn', { value: roles.rollbackRoleArn });
    new CfnOutput(this, 'Stage7AwsCleanupRoleArn', { value: roles.cleanupRoleArn });
    new CfnOutput(this, 'Stage7AwsBaselineRoleArn', { value: roles.baselineRoleArn });
    const primaryBoundaryOutputNames: Readonly<Record<Stage7PrimaryRoleKey, string>> = {
      readRoleArn: 'Stage7AwsReadRolePermissionsBoundaryArn',
      deployRoleArn: 'Stage7AwsDeployRolePermissionsBoundaryArn',
      rollbackRoleArn: 'Stage7AwsRollbackRolePermissionsBoundaryArn',
      cleanupRoleArn: 'Stage7AwsCleanupRolePermissionsBoundaryArn',
    };
    for (const roleKey of STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS) {
      if (ROLE_KEYS_WITHOUT_BOUNDARY.has(roleKey)) continue;
      new CfnOutput(this, primaryBoundaryOutputNames[roleKey], {
        value: boundaries[roleKey],
      });
    }
    if (config.activeBootstrapScope === 'FULL_RELEASE') {
      new CfnOutput(this, 'Stage7AwsBaselineRolePermissionsBoundaryArn', {
        value: boundaries.baselineRoleArn,
      });
      new CfnOutput(this, 'Stage7AuxiliaryReadAuthorityMode', {
        value: config.includeAuxiliaryReadAuthority ? 'FINAL_ENABLED' : 'PREFREEZE_ONLY',
      });
    } else {
      new CfnOutput(this, 'Stage7PrereleaseCleanupWatchdogRoleArn', {
        value: config.roles.cleanupWatchdogRoleArn,
      });
      new CfnOutput(this, 'Stage7PrereleaseCleanupWatchdogPermissionsBoundaryArn', {
        value: config.boundaries.cleanupWatchdogRoleArn,
      });
    }
    const cdkRoleOutputNames: Readonly<Record<Stage7CdkRoleKey, string>> = {
      bootstrapDeployRoleArn: 'Stage7BootstrapDeployRoleArn',
      bootstrapFilePublishingRoleArn: 'Stage7BootstrapFilePublishingRoleArn',
      bootstrapImagePublishingRoleArn: 'Stage7BootstrapImagePublishingRoleArn',
      bootstrapLookupRoleArn: 'Stage7BootstrapLookupRoleArn',
      bootstrapCloudFormationExecutionRoleArn: 'Stage7BootstrapCloudFormationExecutionRoleArn',
    };
    for (const roleKey of STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS) {
      const outputName = cdkRoleOutputNames[roleKey];
      new CfnOutput(this, outputName, { value: config.bootstrap.roles[roleKey] });
      if (ROLE_KEYS_WITHOUT_BOUNDARY.has(roleKey)) continue;
      new CfnOutput(this, `${outputName.slice(0, -3)}PermissionsBoundaryArn`, {
        value: config.bootstrap.boundaries[roleKey],
      });
    }
    new CfnOutput(this, 'Stage7BootstrapAssetBucketName', {
      value: config.bootstrap.assetBucketName,
    });
    new CfnOutput(this, 'Stage7BootstrapImageRepositoryName', {
      value: config.bootstrap.imageRepositoryName,
    });
    new CfnOutput(this, 'Stage7BootstrapVersionParameterName', {
      value: config.bootstrap.versionParameterName,
    });
  }
}

export class Stage7FullAccountBootstrapStack extends Stage7AccountBootstrapStack {
  public constructor(scope: Construct, id: string, props: Stage7AccountBootstrapStackProps) {
    if (props.configuration.activeBootstrapScope !== 'FULL_RELEASE') {
      fail('E7_ACCOUNT_BOOTSTRAP_FULL_STACK_SCOPE_INVALID');
    }
    super(scope, id, props);
  }
}

export class Stage7PrereleaseAccountBootstrapStack extends Stage7AccountBootstrapStack {
  public constructor(scope: Construct, id: string, props: Stage7AccountBootstrapStackProps) {
    if (props.configuration.activeBootstrapScope !== 'PRERELEASE') {
      fail('E7_ACCOUNT_BOOTSTRAP_PRERELEASE_STACK_SCOPE_INVALID');
    }
    super(scope, id, props);
  }
}

interface CloudFormationResource {
  readonly Type?: unknown;
  readonly Properties?: unknown;
}

const record = (value: unknown): Record<string, unknown> => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_INVALID');
  }
  return value as Record<string, unknown>;
};

export const validateStage7AccountBootstrapTemplate = (
  source: unknown,
  config: Stage7AccountBootstrapConfig,
): true => {
  const template = record(source);
  const resourceMap = record(template.Resources);
  const entries = Object.entries(resourceMap) as Array<[string, CloudFormationResource]>;
  const full = config.activeBootstrapScope === 'FULL_RELEASE';
  const allowedTypes = new Set([
    'AWS::IAM::OIDCProvider',
    'AWS::IAM::Role',
    'AWS::IAM::ManagedPolicy',
    'AWS::S3::Bucket',
    'AWS::ECR::Repository',
    'AWS::SSM::Parameter',
  ]);
  if (
    entries.length !== (full ? 22 : 21) ||
    entries.some(([, resource]) => !allowedTypes.has(String(resource.Type))) ||
    entries.filter(([, resource]) => resource.Type === 'AWS::IAM::Role').length !== 10 ||
    entries.filter(([, resource]) => resource.Type === 'AWS::IAM::ManagedPolicy').length !== 8 ||
    entries.filter(([, resource]) => resource.Type === 'AWS::IAM::OIDCProvider').length !==
      (full ? 1 : 0) ||
    entries.filter(([, resource]) => resource.Type === 'AWS::S3::Bucket').length !== 1 ||
    entries.filter(([, resource]) => resource.Type === 'AWS::ECR::Repository').length !== 1 ||
    entries.filter(([, resource]) => resource.Type === 'AWS::SSM::Parameter').length !== 1
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_RESOURCE_SET_INVALID');
  }
  if (full) {
    const provider = entries.find(([, resource]) => resource.Type === 'AWS::IAM::OIDCProvider');
    if (
      provider === undefined ||
      !same(record(provider[1].Properties), {
        ClientIdList: ['sts.amazonaws.com'],
        Url: `https://${STAGE7_ACCOUNT_BOOTSTRAP_OIDC_HOST}`,
      })
    ) {
      fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_OIDC_INVALID');
    }
  }

  const oneBy = (
    type: string,
    property: string,
    expected: string,
  ): [string, Record<string, unknown>] => {
    const matches = entries.filter(
      ([, resource]) =>
        resource.Type === type && record(resource.Properties)[property] === expected,
    );
    if (matches.length !== 1) fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_RESOURCE_IDENTITY_INVALID');
    const match = matches[0] ?? fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_RESOURCE_IDENTITY_INVALID');
    return [match[0], record(match[1].Properties)];
  };

  const [, bucket] = oneBy('AWS::S3::Bucket', 'BucketName', config.bootstrap.assetBucketName);
  if (
    !same(bucket.PublicAccessBlockConfiguration, {
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    }) ||
    !same(bucket.OwnershipControls, { Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] }) ||
    !same(bucket.VersioningConfiguration, { Status: 'Enabled' })
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_ASSET_BUCKET_INVALID');
  }
  const [, repository] = oneBy(
    'AWS::ECR::Repository',
    'RepositoryName',
    config.bootstrap.imageRepositoryName,
  );
  if (
    !same(repository.EncryptionConfiguration, { EncryptionType: 'AES256' }) ||
    !same(repository.ImageScanningConfiguration, { ScanOnPush: true }) ||
    repository.ImageTagMutability !== 'IMMUTABLE'
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_IMAGE_REPOSITORY_INVALID');
  }
  const [, parameter] = oneBy('AWS::SSM::Parameter', 'Name', config.bootstrap.versionParameterName);
  if (parameter.Type !== 'String' || parameter.Value !== String(config.bootstrap.version)) {
    fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_VERSION_PARAMETER_INVALID');
  }

  const authority = activeAuthority(config);
  const activeRoles = full ? config.roles.release : config.roles.prerelease;
  const activeBoundaries = full ? config.boundaries.release : config.boundaries.prerelease;
  const specs: Array<{
    roleKey: PolicyRoleKey;
    roleArn: string;
    boundaryArn: string;
    trust: IamPolicyDocument;
    path?: string;
  }> = STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS.map((roleKey) => ({
    roleKey,
    roleArn: activeRoles[roleKey],
    boundaryArn: activeBoundaries[roleKey],
    trust: oidcTrust(
      config,
      iamContract.IAM_ROLE_PERMISSION_PROFILES[roleKey].oidcSubjects[authority.scope],
    ),
    path: STAGE7_ACCOUNT_BOOTSTRAP_ROLE_PATH,
  }));
  if (full) {
    specs.push({
      roleKey: 'baselineRoleArn',
      roleArn: activeRoles.baselineRoleArn,
      boundaryArn: activeBoundaries.baselineRoleArn,
      trust: oidcTrust(
        config,
        iamContract.IAM_ROLE_PERMISSION_PROFILES.baselineRoleArn.oidcSubjects.baseline,
      ),
      path: STAGE7_ACCOUNT_BOOTSTRAP_ROLE_PATH,
    });
  } else {
    specs.push({
      roleKey: 'cleanupWatchdogRoleArn',
      roleArn: config.roles.cleanupWatchdogRoleArn,
      boundaryArn: config.boundaries.cleanupWatchdogRoleArn,
      trust: oidcTrust(
        config,
        iamContract.IAM_ROLE_PERMISSION_PROFILES.cleanupWatchdogRoleArn.oidcSubjects.prerelease,
      ),
      path: STAGE7_ACCOUNT_BOOTSTRAP_ROLE_PATH,
    });
  }
  for (const roleKey of STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS) {
    specs.push({
      roleKey,
      roleArn: config.bootstrap.roles[roleKey],
      boundaryArn: config.bootstrap.boundaries[roleKey],
      trust: cdkTrust(roleKey, authority),
    });
  }

  for (const spec of specs) {
    const roleName = spec.roleArn.split('/').at(-1) ?? '';
    const boundaryName = spec.boundaryArn.split('/').at(-1) ?? '';
    const [, role] = oneBy('AWS::IAM::Role', 'RoleName', roleName);
    const expectedPolicy = generatedPolicy(spec.roleKey, authority, config);
    const policies = role.Policies;
    const boundaryExpected = !ROLE_KEYS_WITHOUT_BOUNDARY.has(spec.roleKey);
    const boundaryEntry = boundaryExpected
      ? oneBy('AWS::IAM::ManagedPolicy', 'ManagedPolicyName', boundaryName)
      : undefined;
    const boundaryId = boundaryEntry?.[0];
    const boundary = boundaryEntry?.[1];
    if (
      role.MaxSessionDuration !== 3600 ||
      (spec.path === undefined ? Object.hasOwn(role, 'Path') : role.Path !== spec.path) ||
      !same(role.AssumeRolePolicyDocument, spec.trust) ||
      (boundaryExpected
        ? !same(role.PermissionsBoundary, { Ref: boundaryId })
        : Object.hasOwn(role, 'PermissionsBoundary')) ||
      Object.hasOwn(role, 'ManagedPolicyArns') ||
      !Array.isArray(policies) ||
      policies.length !== 1 ||
      !same((policies[0] as Record<string, unknown>).PolicyDocument, expectedPolicy) ||
      (policies[0] as Record<string, unknown>).PolicyName !== `stage7-${spec.roleKey}` ||
      (boundaryExpected &&
        (boundary?.ManagedPolicyName !== boundaryName ||
          !same(boundary.PolicyDocument, expectedPolicy))) ||
      canonical({ role, boundary }).includes('AdministratorAccess') ||
      canonical({ role, boundary }).includes('"NotAction"') ||
      canonical({ role, boundary }).includes('"NotResource"') ||
      canonical({ role, boundary }).includes('"Action":"*"')
    ) {
      fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_ROLE_OR_BOUNDARY_INVALID');
    }
  }

  const outputs = record(template.Outputs);
  if (
    !same(outputs.BootstrapVersion, { Value: String(config.bootstrap.version) }) ||
    !same(outputs.Stage7BootstrapScope, { Value: config.activeBootstrapScope }) ||
    !same(outputs.Stage7GithubOidcProviderArn, { Value: config.oidcProviderArn }) ||
    !same(outputs.Stage7AwsReadRoleArn, { Value: activeRoles.readRoleArn }) ||
    !same(outputs.Stage7AwsDeployRoleArn, { Value: activeRoles.deployRoleArn }) ||
    !same(outputs.Stage7AwsRollbackRoleArn, { Value: activeRoles.rollbackRoleArn }) ||
    !same(outputs.Stage7AwsCleanupRoleArn, { Value: activeRoles.cleanupRoleArn }) ||
    !same(outputs.Stage7AwsBaselineRoleArn, { Value: activeRoles.baselineRoleArn })
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_TEMPLATE_OUTPUT_SET_INVALID');
  }
  return true;
};
