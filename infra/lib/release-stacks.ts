import { createHash } from 'node:crypto';

import {
  Aws,
  CfnCondition,
  CfnOutput,
  CfnParameter,
  Duration,
  Fn,
  RemovalPolicy,
  SecretValue,
  Stack,
  Tags,
  Token,
} from 'aws-cdk-lib';
import type { StackProps } from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as budgets from 'aws-cdk-lib/aws-budgets';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53Targets from 'aws-cdk-lib/aws-route53-targets';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import type { Construct } from 'constructs';

import type { ReleaseConfig } from './config';
import { inspectReleaseArtifact } from './release-artifact';

const RECONCILE_INDEX = 'GSI1-Reconcile';
const PENDING_AGE_INDEX = 'GSI2-PendingAge';
const RETENTION = logs.RetentionDays.ONE_WEEK;
const sha256 = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

export interface ReleaseStackProps extends StackProps {
  readonly configuration: ReleaseConfig;
}

abstract class ReleaseStack extends Stack {
  protected readonly configuration: ReleaseConfig;
  protected readonly resourcePrefix: string;

  protected constructor(scope: Construct, id: string, props: ReleaseStackProps) {
    super(scope, id, props);
    this.configuration = props.configuration;
    this.resourcePrefix = props.configuration.projectName + '-' + props.configuration.environment;
    this.applyReleaseTags();
    if (props.configuration.publicationMode === 'FULL_BASELINE_CLOSED') {
      const baselineConfigSha256 = props.configuration.baselineConfigSha256;
      if (baselineConfigSha256 === undefined) {
        throw new Error('FULL_BASELINE_CLOSED requires baselineConfigSha256');
      }
      this.releaseOutput(
        'BaselineConfigSha256',
        baselineConfigSha256,
        'Closed baseline config binding',
      );
    }
  }

  protected releaseOutput(id: string, value: string, description: string): void {
    new CfnOutput(this, id, { description, value });
  }

  protected get ephemeralPrerelease(): boolean {
    return this.configuration.environment.startsWith('assessment-prerelease-');
  }

  protected get restrictedViewerAccess(): boolean {
    return (
      this.ephemeralPrerelease || this.configuration.publicationMode === 'FULL_BASELINE_CLOSED'
    );
  }

  protected get originGateEnabled(): boolean {
    return this.configuration.runtimeSecretArn !== undefined;
  }

  protected get releaseRemovalPolicy(): RemovalPolicy {
    return this.ephemeralPrerelease ? RemovalPolicy.DESTROY : RemovalPolicy.RETAIN;
  }

  protected publicationControl(defaultState: 'DISABLED' | 'ENABLED'): Readonly<{
    condition: CfnCondition;
    parameter: CfnParameter;
  }> {
    const parameter = new CfnParameter(this, 'PublicationState', {
      allowedValues: ['DISABLED', 'ENABLED'],
      default: defaultState,
      description:
        'CloudFormation-managed publication state; changed only by audited activation/rollback',
      type: 'String',
    });
    const condition = new CfnCondition(this, 'PublicationEnabled', {
      expression: Fn.conditionEquals(parameter.valueAsString, 'ENABLED'),
    });
    return { condition, parameter };
  }

  private applyReleaseTags(): void {
    const config = this.configuration;
    for (const [key, value] of Object.entries({
      CandidateSha: config.candidateSha,
      CostCenter: 'technical-assessment',
      CleanupExpiresAtUtc: config.cleanupExpiresAtUtc,
      DataClass: 'synthetic-only',
      Environment: config.environment,
      ExpiresOn: config.expiresOn,
      ManagedBy: 'cdk',
      Owner: config.owner,
      PaymentMode: config.paymentAdapter,
      Project: config.projectName,
      ReleaseId: config.releaseId,
    })) {
      Tags.of(this).add(key, value);
    }
  }
}

export class ReleaseDataStack extends ReleaseStack {
  public readonly catalogTable: dynamodb.Table;
  public readonly checkoutTable: dynamodb.Table;

  public constructor(scope: Construct, id: string, props: ReleaseStackProps) {
    super(scope, id, props);
    const deletionProtection =
      this.configuration.paymentAdapter === 'sandbox' && !this.ephemeralPrerelease;
    const pitr = this.configuration.pointInTimeRecoveryEnabled;

    this.catalogTable = new dynamodb.Table(this, 'CatalogTable', {
      partitionKey: { name: 'PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'SK', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      deletionProtection,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: pitr },
      removalPolicy: this.releaseRemovalPolicy,
      tableName: this.resourcePrefix + '-catalog',
    });
    this.limitOnDemandThroughput(this.catalogTable, 50, 25);

    this.checkoutTable = new dynamodb.Table(this, 'CheckoutTable', {
      partitionKey: { name: 'PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'SK', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      deletionProtection,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: pitr },
      removalPolicy: this.releaseRemovalPolicy,
      tableName: this.resourcePrefix + '-checkout',
      timeToLiveAttribute: 'purgeAt',
    });
    this.checkoutTable.addGlobalSecondaryIndex({
      indexName: RECONCILE_INDEX,
      partitionKey: { name: 'GSI1PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'GSI1SK', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.INCLUDE,
      nonKeyAttributes: ['checkoutId', 'transactionId', 'dispatchPhase', 'paymentStatus'],
    });
    this.checkoutTable.addGlobalSecondaryIndex({
      indexName: PENDING_AGE_INDEX,
      partitionKey: { name: 'GSI2PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'GSI2SK', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.INCLUDE,
      nonKeyAttributes: ['acceptedAt', 'paymentStatus'],
    });
    this.limitOnDemandThroughput(this.checkoutTable, 50, 50);

    this.releaseOutput('CatalogTableName', this.catalogTable.tableName, 'Retained catalog table');
    this.releaseOutput(
      'CheckoutTableName',
      this.checkoutTable.tableName,
      'Retained checkout table',
    );
    this.releaseOutput(
      'PointInTimeRecoveryStatus',
      pitr ? 'ENABLED' : 'DISABLED_EXPLICIT',
      'DynamoDB recovery posture selected for this release',
    );
    this.releaseOutput('ReleaseId', this.configuration.releaseId, 'Immutable release identifier');
    this.releaseOutput('CandidateSha', this.configuration.candidateSha, 'Verified candidate SHA');
  }

  private limitOnDemandThroughput(
    table: dynamodb.Table,
    maxReadRequestUnits: number,
    maxWriteRequestUnits: number,
  ): void {
    const cfnTable = table.node.defaultChild as dynamodb.CfnTable;
    cfnTable.addPropertyOverride('OnDemandThroughput', {
      MaxReadRequestUnits: maxReadRequestUnits,
      MaxWriteRequestUnits: maxWriteRequestUnits,
    });
  }
}

export interface ReleaseApiStackProps extends ReleaseStackProps {
  readonly dataStack: ReleaseDataStack;
}

export class ReleaseApiStack extends ReleaseStack {
  public readonly apiAlias: lambda.Alias;
  public readonly apiFunction: lambda.Function;
  public readonly apiLogGroup: logs.LogGroup;
  public readonly apiOriginDomainName: string;
  public readonly httpApi: apigwv2.HttpApi;
  public readonly scheduleName: string;
  public readonly workerAlias: lambda.Alias;
  public readonly workerFunction: lambda.Function;
  public readonly workerLogGroup: logs.LogGroup;

  public constructor(scope: Construct, id: string, props: ReleaseApiStackProps) {
    super(scope, id, props);
    this.addStackDependency(props.dataStack);
    const config = this.configuration;
    const publication = this.publicationControl('DISABLED');
    const apiArtifact = inspectReleaseArtifact(config.apiArtifactPath, ['index.js'], 'api');
    const workerArtifact = inspectReleaseArtifact(
      config.workerArtifactPath,
      ['index.js'],
      'worker',
    );
    const publicOriginParameterName = '/' + this.resourcePrefix + '/public-origin';

    this.apiLogGroup = this.createLogGroup(
      'ApiLogGroup',
      '/' + this.resourcePrefix + '/lambda/api',
    );
    this.workerLogGroup = this.createLogGroup(
      'WorkerLogGroup',
      '/' + this.resourcePrefix + '/lambda/worker',
    );
    const accessLogGroup = this.createLogGroup(
      'ApiAccessLogGroup',
      '/' + this.resourcePrefix + '/apigateway/access',
    );
    const apiRole = this.createLambdaRole('ApiRole', this.apiLogGroup);
    const workerRole = this.createLambdaRole('WorkerRole', this.workerLogGroup);
    this.grantTableAccess(apiRole, workerRole, props.dataStack);
    const parameterArn = this.formatArn({
      service: 'ssm',
      resource: 'parameter',
      resourceName: publicOriginParameterName.slice(1),
    });
    this.addPolicy(apiRole, 'ReadPublicOriginConfiguration', ['ssm:GetParameter'], [parameterArn]);
    this.addPolicy(
      workerRole,
      'ReadPublicOriginConfiguration',
      ['ssm:GetParameter'],
      [parameterArn],
    );

    const runtimeSecret = this.runtimeSecret(apiRole, workerRole);
    const environment: Record<string, string> = {
      ALLOWED_ORIGIN_PARAMETER_NAME: publicOriginParameterName,
      APP_ENV: 'assessment',
      AUTO_SEED_CATALOG: 'false',
      AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
      CANDIDATE_SHA: config.candidateSha,
      CATALOG_TABLE_NAME: props.dataStack.catalogTable.tableName,
      CHECKOUT_TABLE_NAME: props.dataStack.checkoutTable.tableName,
      DATA_ADAPTER: 'dynamodb',
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
      FOUNDATION_SYNTH_ONLY: 'false',
      LOG_LEVEL: 'info',
      MAX_BODY_BYTES: '16384',
      PAYMENT_ADAPTER: config.paymentAdapter,
      PAYMENTS_ENABLED: String(config.paymentsEnabled),
      PRERELEASE_ACCESS_MODE: this.restrictedViewerAccess
        ? 'cloudfront_signed_cookie'
        : this.originGateEnabled
          ? 'origin_gate'
          : 'disabled',
      PUBLIC_ASSET_ORIGIN_PARAMETER_NAME: publicOriginParameterName,
      RELEASE_ID: config.releaseId,
      RUNTIME_SECRET_ARN: runtimeSecret.secretArn,
      ...(config.runtimeSecretVersionId === undefined
        ? {}
        : { RUNTIME_SECRET_VERSION_ID: config.runtimeSecretVersionId }),
      ...(config.sandboxAuthorizedUntilUtc === undefined
        ? {}
        : { SANDBOX_AUTHORIZED_UNTIL_UTC: config.sandboxAuthorizedUntilUtc }),
      TOKENIZATION_MODE: config.tokenizationMode,
    };
    this.apiFunction = new lambda.Function(this, 'ApiFunction', {
      architecture: lambda.Architecture.ARM_64,
      code: lambda.Code.fromAsset(apiArtifact.path),
      currentVersionOptions: { removalPolicy: this.releaseRemovalPolicy },
      description: config.releaseId + ' API release candidate',
      environment,
      handler: 'index.handler',
      logGroup: this.apiLogGroup,
      loggingFormat: lambda.LoggingFormat.JSON,
      memorySize: 512,
      reservedConcurrentExecutions: 5,
      role: apiRole,
      runtime: lambda.Runtime.NODEJS_24_X,
      timeout: Duration.seconds(10),
    });
    this.workerFunction = new lambda.Function(this, 'WorkerFunction', {
      architecture: lambda.Architecture.ARM_64,
      code: lambda.Code.fromAsset(workerArtifact.path),
      currentVersionOptions: { removalPolicy: this.releaseRemovalPolicy },
      description: config.releaseId + ' reconciliation worker release candidate',
      environment: {
        ...environment,
        RECONCILE_BATCH_SIZE: '10',
        RECONCILE_LEASE_SECONDS: '45',
      },
      handler: 'index.handler',
      logGroup: this.workerLogGroup,
      loggingFormat: lambda.LoggingFormat.JSON,
      memorySize: 512,
      reservedConcurrentExecutions: 1,
      role: workerRole,
      runtime: lambda.Runtime.NODEJS_24_X,
      timeout: Duration.seconds(30),
    });
    this.apiAlias = new lambda.Alias(this, 'ApiAlias', {
      aliasName: 'live',
      version: this.apiFunction.currentVersion,
    });
    this.workerAlias = new lambda.Alias(this, 'WorkerAlias', {
      aliasName: 'live',
      version: this.workerFunction.currentVersion,
    });

    const hostedZone =
      config.domain === undefined
        ? undefined
        : route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
            hostedZoneId: config.domain.hostedZoneId,
            zoneName: config.domain.hostedZoneName,
          });
    const apiCustomDomain =
      config.domain === undefined
        ? undefined
        : new apigwv2.DomainName(this, 'ApiCustomDomain', {
            certificate: acm.Certificate.fromCertificateArn(
              this,
              'ApiCertificate',
              config.domain.apiCertificateArn,
            ),
            domainName: config.domain.apiDomainName,
            endpointType: apigwv2.EndpointType.REGIONAL,
            securityPolicy: apigwv2.SecurityPolicy.TLS_1_2,
          });
    this.httpApi = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: this.resourcePrefix + '-api',
      createDefaultStage: true,
      description: 'Same-origin assessment release API',
      disableExecuteApiEndpoint: true,
    });
    const cfnApi = this.httpApi.node.defaultChild as apigwv2.CfnApi;
    cfnApi.addPropertyOverride(
      'DisableExecuteApiEndpoint',
      Fn.conditionIf(publication.condition.logicalId, apiCustomDomain !== undefined, true),
    );
    this.httpApi.addRoutes({
      integration: new integrations.HttpLambdaIntegration('ApiIntegration', this.apiAlias),
      methods: [apigwv2.HttpMethod.ANY],
      path: '/{proxy+}',
    });
    const stage = this.httpApi.defaultStage;
    if (stage === undefined) throw new Error('HTTP API default stage must exist');
    const cfnStage = stage.node.defaultChild as apigwv2.CfnStage;
    cfnStage.defaultRouteSettings = {
      detailedMetricsEnabled: true,
      throttlingBurstLimit: 10,
      throttlingRateLimit: 1,
    };
    cfnStage.accessLogSettings = {
      destinationArn: accessLogGroup.logGroupArn,
      format: JSON.stringify({
        integrationError: '$context.integrationErrorMessage',
        requestId: '$context.requestId',
        responseLatency: '$context.responseLatency',
        routeKey: '$context.routeKey',
        status: '$context.status',
      }),
    };
    if (apiCustomDomain !== undefined) {
      const mapping = new apigwv2.ApiMapping(this, 'ApiDefaultMapping', {
        api: this.httpApi,
        domainName: apiCustomDomain,
        stage,
      });
      const cfnMapping = mapping.node.defaultChild as apigwv2.CfnApiMapping;
      cfnMapping.cfnOptions.condition = publication.condition;
    }
    if (apiCustomDomain !== undefined && hostedZone !== undefined && config.domain !== undefined) {
      const target = route53.RecordTarget.fromAlias(
        new route53Targets.ApiGatewayv2DomainProperties(
          apiCustomDomain.regionalDomainName,
          apiCustomDomain.regionalHostedZoneId,
        ),
      );
      new route53.ARecord(this, 'ApiAliasA', {
        recordName: config.domain.apiDomainName,
        target,
        zone: hostedZone,
      });
      new route53.AaaaRecord(this, 'ApiAliasAAAA', {
        recordName: config.domain.apiDomainName,
        target,
        zone: hostedZone,
      });
    }
    this.apiOriginDomainName =
      config.domain?.apiDomainName ??
      this.httpApi.httpApiId + '.execute-api.' + this.region + '.' + Aws.URL_SUFFIX;

    this.scheduleName = this.resourcePrefix + '-reconcile';
    const schedulerRole = new iam.Role(this, 'SchedulerRole', {
      assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com'),
      description: 'Invokes only the reconciliation worker live alias',
    });
    this.addPolicy(
      schedulerRole,
      'InvokeWorkerAlias',
      ['lambda:InvokeFunction'],
      [this.workerAlias.functionArn],
    );
    const schedule = new scheduler.CfnSchedule(this, 'ReconcileSchedule', {
      description: 'Bounded reconciliation for ' + config.releaseId,
      flexibleTimeWindow: { mode: 'OFF' },
      name: this.scheduleName,
      scheduleExpression: 'rate(1 minute)',
      state: 'DISABLED',
      target: {
        arn: this.workerAlias.functionArn,
        input: JSON.stringify({ action: 'reconcile', mode: config.paymentAdapter }),
        retryPolicy: { maximumEventAgeInSeconds: 300, maximumRetryAttempts: 2 },
        roleArn: schedulerRole.roleArn,
      },
    });
    const schedulerMayRun =
      config.schedulerEnabled && config.publicationMode !== 'FULL_BASELINE_CLOSED';
    if (schedulerMayRun) {
      schedule.addPropertyOverride(
        'State',
        Fn.conditionIf(publication.condition.logicalId, 'ENABLED', 'DISABLED'),
      );
    }

    const publicationStatus = Token.asString(
      Fn.conditionIf(publication.condition.logicalId, 'ENABLED', 'DISABLED'),
    );

    this.releaseOutput('ApiOriginUrl', 'https://' + this.apiOriginDomainName, 'API HTTPS origin');
    this.releaseOutput(
      'ApiLogGroupName',
      this.apiLogGroup.logGroupName,
      'Exact API application log group for read-only release evidence',
    );
    this.releaseOutput('HttpApiId', this.httpApi.httpApiId, 'Exact HTTP API rollback target');
    this.releaseOutput(
      'ApiCustomDomainName',
      config.domain?.apiDomainName ?? 'NONE_MANAGED_PRERELEASE',
      'Custom-domain API mapping target; absent only in restricted prerelease',
    );
    this.releaseOutput(
      'ApiPublicationStatus',
      publicationStatus,
      'CloudFormation-managed API mapping and worker publication state',
    );
    this.releaseOutput('ApiAliasArn', this.apiAlias.functionArn, 'Rollback target for API alias');
    this.releaseOutput('ApiFunctionVersion', this.apiAlias.version.version, 'Pinned API version');
    this.releaseOutput(
      'WorkerAliasArn',
      this.workerAlias.functionArn,
      'Rollback target for worker',
    );
    this.releaseOutput(
      'WorkerLogGroupName',
      this.workerLogGroup.logGroupName,
      'Exact worker application log group for read-only release evidence',
    );
    this.releaseOutput(
      'WorkerFunctionVersion',
      this.workerAlias.version.version,
      'Pinned worker version',
    );
    this.releaseOutput('ScheduleName', this.scheduleName, 'Reconciliation scheduler name');
    this.releaseOutput(
      'SchedulerStatus',
      schedulerMayRun ? publicationStatus : 'DISABLED_EXPLICIT',
      'CloudFormation-managed reconciliation trigger posture',
    );
    this.releaseOutput('PublicOriginParameterName', publicOriginParameterName, 'Origin parameter');
    this.releaseOutput('ApiArtifactSha256', apiArtifact.sha256, 'API artifact directory SHA-256');
    this.releaseOutput('ApiArtifactBytes', String(apiArtifact.sizeBytes), 'API artifact bytes');
    this.releaseOutput(
      'WorkerArtifactSha256',
      workerArtifact.sha256,
      'Worker artifact directory SHA-256',
    );
    this.releaseOutput(
      'WorkerArtifactBytes',
      String(workerArtifact.sizeBytes),
      'Worker artifact bytes',
    );
    this.releaseOutput('ReleaseId', config.releaseId, 'Immutable release identifier');
    this.releaseOutput('CandidateSha', config.candidateSha, 'Verified candidate SHA');
    this.releaseOutput(
      'RollbackMechanism',
      'MOVE_LAMBDA_ALIASES_TO_RECORDED_PREVIOUS_VERSIONS',
      'API and worker rollback mechanism',
    );
  }

  private runtimeSecret(apiRole: iam.Role, workerRole: iam.Role): secretsmanager.ISecret {
    const config = this.configuration;
    if (config.paymentAdapter === 'sandbox' && config.runtimeSecretArn === undefined) {
      throw new Error('sandbox release requires an external runtime JSON secret ARN');
    }
    const generated = config.runtimeSecretArn === undefined;
    const secret = generated
      ? new secretsmanager.Secret(this, 'RuntimeSecret', {
          description: 'Generated fake-release runtime JSON; value never enters CloudFormation',
          generateSecretString: {
            excludePunctuation: true,
            generateStringKey: 'runtimeSecurityRootKey',
            passwordLength: 48,
            secretStringTemplate: '{}',
          },
          secretName: this.resourcePrefix + '/runtime',
        })
      : secretsmanager.Secret.fromSecretCompleteArn(this, 'RuntimeSecret', config.runtimeSecretArn);
    if (generated) secret.applyRemovalPolicy(this.releaseRemovalPolicy);
    secret.grantRead(apiRole);
    secret.grantRead(workerRole);
    return secret;
  }

  private createLogGroup(id: string, name: string): logs.LogGroup {
    return new logs.LogGroup(this, id, {
      logGroupName: name,
      removalPolicy: this.releaseRemovalPolicy,
      retention: RETENTION,
    });
  }

  private createLambdaRole(id: string, logGroup: logs.ILogGroup): iam.Role {
    const role = new iam.Role(this, id, {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    this.addPolicy(
      role,
      id + 'Logs',
      ['logs:CreateLogStream', 'logs:PutLogEvents'],
      [logGroup.logGroupArn + ':*'],
    );
    return role;
  }

  private grantTableAccess(apiRole: iam.Role, workerRole: iam.Role, data: ReleaseDataStack): void {
    const indexArns = [RECONCILE_INDEX, PENDING_AGE_INDEX].map(
      (index) => data.checkoutTable.tableArn + '/index/' + index,
    );
    this.addPolicy(
      apiRole,
      'ApiCatalogReads',
      ['dynamodb:GetItem', 'dynamodb:BatchGetItem', 'dynamodb:Query'],
      [data.catalogTable.tableArn],
    );
    this.addPolicy(
      apiRole,
      'ApiCheckoutReads',
      ['dynamodb:GetItem', 'dynamodb:Query'],
      [data.checkoutTable.tableArn, ...indexArns],
    );
    this.addPolicy(
      apiRole,
      'ApiTableWrites',
      ['dynamodb:UpdateItem', 'dynamodb:TransactWriteItems'],
      [data.catalogTable.tableArn, data.checkoutTable.tableArn],
    );
    this.addPolicy(
      workerRole,
      'WorkerCatalogReads',
      ['dynamodb:GetItem'],
      [data.catalogTable.tableArn],
    );
    this.addPolicy(
      workerRole,
      'WorkerCheckoutReads',
      ['dynamodb:GetItem', 'dynamodb:Query'],
      [data.checkoutTable.tableArn, ...indexArns],
    );
    this.addPolicy(
      workerRole,
      'WorkerTableWrites',
      ['dynamodb:UpdateItem', 'dynamodb:TransactWriteItems'],
      [data.catalogTable.tableArn, data.checkoutTable.tableArn],
    );
  }

  private addPolicy(role: iam.Role, sid: string, actions: string[], resources: string[]): void {
    role.addToPolicy(
      new iam.PolicyStatement({ actions, effect: iam.Effect.ALLOW, resources, sid }),
    );
  }
}

export interface ReleaseObservabilityStackProps extends ReleaseStackProps {
  readonly apiStack: ReleaseApiStack;
  readonly dataStack: ReleaseDataStack;
}

export class ReleaseObservabilityStack extends ReleaseStack {
  public readonly alertTopic: sns.Topic;

  public constructor(scope: Construct, id: string, props: ReleaseObservabilityStackProps) {
    super(scope, id, props);
    this.addStackDependency(props.apiStack);
    this.addStackDependency(props.dataStack);
    const config = this.configuration;
    const alertEmail = new CfnParameter(this, 'AlertEmail', {
      allowedPattern: '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$',
      description: 'Operator email; must confirm the SNS subscription after deployment',
      noEcho: true,
      type: 'String',
    });
    this.alertTopic = new sns.Topic(this, 'AlertTopic', {
      displayName: this.resourcePrefix + ' alerts',
      topicName: this.resourcePrefix + '-alerts',
    });
    this.alertTopic.addSubscription(
      new snsSubscriptions.EmailSubscription(alertEmail.valueAsString),
    );
    this.alertTopic.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: ['sns:Publish'],
        conditions: { StringEquals: { 'aws:SourceAccount': this.account } },
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('budgets.amazonaws.com')],
        resources: [this.alertTopic.topicArn],
        sid: 'AllowBudgetNotifications',
      }),
    );
    const alarmAction = new cloudwatchActions.SnsAction(this.alertTopic);
    const alarm = (id: string, metric: cloudwatch.IMetric, threshold: number): cloudwatch.Alarm => {
      const created = new cloudwatch.Alarm(this, id, {
        alarmDescription: config.releaseId + ' operational signal',
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric,
        threshold,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      created.addAlarmAction(alarmAction);
      return created;
    };

    const apiErrors = props.apiStack.apiFunction.metricErrors({
      period: Duration.minutes(5),
      statistic: 'sum',
    });
    const apiThrottles = props.apiStack.apiFunction.metricThrottles({
      period: Duration.minutes(5),
      statistic: 'sum',
    });
    const apiDuration = props.apiStack.apiFunction.metricDuration({
      period: Duration.minutes(5),
      statistic: 'p95',
    });
    const workerErrors = props.apiStack.workerFunction.metricErrors({
      period: Duration.minutes(5),
      statistic: 'sum',
    });
    const workerThrottles = props.apiStack.workerFunction.metricThrottles({
      period: Duration.minutes(5),
      statistic: 'sum',
    });
    const workerDuration = props.apiStack.workerFunction.metricDuration({
      period: Duration.minutes(5),
      statistic: 'p95',
    });
    const gatewayMetric = (name: string, statistic: string): cloudwatch.Metric =>
      new cloudwatch.Metric({
        dimensionsMap: { ApiId: props.apiStack.httpApi.httpApiId },
        metricName: name,
        namespace: 'AWS/ApiGateway',
        period: Duration.minutes(5),
        statistic,
      });
    const apiRequests = gatewayMetric('Count', 'sum');
    const apiClientErrors = gatewayMetric('4xx', 'sum');
    const apiGatewayErrors = gatewayMetric('5xx', 'sum');
    const apiGatewayLatency = gatewayMetric('Latency', 'p95');
    const dynamoThrottles = new cloudwatch.MathExpression({
      expression: 'catalog + checkout',
      period: Duration.minutes(5),
      usingMetrics: {
        catalog: new cloudwatch.Metric({
          dimensionsMap: { TableName: props.dataStack.catalogTable.tableName },
          metricName: 'ThrottledRequests',
          namespace: 'AWS/DynamoDB',
          statistic: 'sum',
        }),
        checkout: new cloudwatch.Metric({
          dimensionsMap: { TableName: props.dataStack.checkoutTable.tableName },
          metricName: 'ThrottledRequests',
          namespace: 'AWS/DynamoDB',
          statistic: 'sum',
        }),
      },
    });
    const schedulerErrors = new cloudwatch.Metric({
      dimensionsMap: { ScheduleGroup: 'default', ScheduleName: props.apiStack.scheduleName },
      metricName: 'TargetErrorCount',
      namespace: 'AWS/Scheduler',
      period: Duration.minutes(5),
      statistic: 'sum',
    });
    const recordedMetric = (
      id: string,
      sourceName: string,
      emittedName: string,
      logGroup: logs.ILogGroup = props.apiStack.apiLogGroup,
      statistic = 'sum',
    ): cloudwatch.Metric =>
      new logs.MetricFilter(this, id, {
        defaultValue: 0,
        filterPattern: logs.FilterPattern.all(
          logs.FilterPattern.stringValue('$.eventName', '=', 'metric.recorded'),
          logs.FilterPattern.stringValue('$.metricName', '=', sourceName),
        ),
        logGroup,
        metricName: emittedName,
        metricNamespace: this.resourcePrefix + '/Checkout',
        metricValue: '$.metricValue',
      }).metric({ period: Duration.minutes(5), statistic });
    const paymentAttempts = recordedMetric(
      'PaymentAttemptsMetric',
      'payment_attempts_total',
      'PaymentAttempts',
    );
    const paymentPending = recordedMetric(
      'PaymentPendingMetric',
      'payment_unknown_total',
      'PaymentPendingOrUnknown',
    );
    const paymentApproved = recordedMetric(
      'PaymentApprovedMetric',
      'payment_finalized_approved_total',
      'PaymentApproved',
    );
    const paymentDeclined = recordedMetric(
      'PaymentDeclinedMetric',
      'payment_finalized_declined_total',
      'PaymentDeclined',
    );
    const idempotencyReplays = recordedMetric(
      'IdempotencyReplaysMetric',
      'idempotency_replays_total',
      'IdempotencyReplays',
    );
    const deliveryEffects = recordedMetric(
      'DeliveryEffectsMetric',
      'reservations_committed_total',
      'DeliveryEffects',
    );
    const reconciliationRetries = recordedMetric(
      'ReconciliationRetriesMetric',
      'reconciliation_retries_total',
      'ReconciliationRetries',
      props.apiStack.workerLogGroup,
    );
    const providerErrors = recordedMetric(
      'ProviderErrorsMetric',
      'provider_external_errors_total',
      'ProviderErrors',
      props.apiStack.workerLogGroup,
    );
    const oldestPendingAge = recordedMetric(
      'OldestPendingAgeMetric',
      'oldest_pending_age_seconds',
      'OldestPendingAgeSeconds',
      props.apiStack.workerLogGroup,
      'maximum',
    );
    const inventoryConflicts = new logs.MetricFilter(this, 'InventoryConflictMetric', {
      defaultValue: 0,
      filterPattern: logs.FilterPattern.stringValue('$.eventName', '=', 'inventory.conflict'),
      logGroup: props.apiStack.apiLogGroup,
      metricName: 'InventoryConflicts',
      metricNamespace: this.resourcePrefix + '/Checkout',
      metricValue: '1',
    }).metric({ period: Duration.minutes(5), statistic: 'sum' });
    const reconcileFailures = new logs.MetricFilter(this, 'ReconcileFailureMetric', {
      defaultValue: 0,
      filterPattern: logs.FilterPattern.any(
        logs.FilterPattern.stringValue('$.eventName', '=', 'reconcile.exhausted'),
        logs.FilterPattern.stringValue('$.eventName', '=', 'provider.external_error'),
      ),
      logGroup: props.apiStack.workerLogGroup,
      metricName: 'ReconcileFailures',
      metricNamespace: this.resourcePrefix + '/Checkout',
      metricValue: '1',
    }).metric({ period: Duration.minutes(5), statistic: 'sum' });

    const alarms = [
      alarm('ApiErrorsAlarm', apiErrors, 1),
      alarm('ApiThrottlesAlarm', apiThrottles, 1),
      alarm('ApiDurationAlarm', apiDuration, 8000),
      alarm('WorkerErrorsAlarm', workerErrors, 1),
      alarm('WorkerThrottlesAlarm', workerThrottles, 1),
      alarm('WorkerDurationAlarm', workerDuration, 25_000),
      alarm('ApiGatewayErrorsAlarm', apiGatewayErrors, 1),
      alarm('ApiGatewayLatencyAlarm', apiGatewayLatency, 9000),
      alarm('DynamoThrottlesAlarm', dynamoThrottles, 1),
      alarm('SchedulerErrorsAlarm', schedulerErrors, 1),
      alarm('InventoryConflictsAlarm', inventoryConflicts, 1),
      alarm('ReconcileFailuresAlarm', reconcileFailures, 1),
      alarm('PendingOrUnknownAlarm', paymentPending, 1),
      alarm('OldestPendingAgeAlarm', oldestPendingAge, 600),
    ];
    const rollbackRehearsalAlarm = new cloudwatch.Alarm(this, 'RollbackRehearsalAlarm', {
      actionsEnabled: false,
      alarmDescription: config.releaseId + ' isolated rollback rehearsal signal',
      alarmName: this.resourcePrefix + '-rollback-rehearsal',
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 1,
      metric: new cloudwatch.Metric({
        dimensionsMap: {
          Environment: config.environment,
          ReleaseId: config.releaseId,
          Scenario: 'RB-E7-08',
        },
        metricName: 'RollbackRehearsalFailure',
        namespace: 'Checkout/Stage7Rehearsal',
        period: Duration.minutes(1),
        statistic: 'Maximum',
        unit: cloudwatch.Unit.COUNT,
      }),
      threshold: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    const dashboard = new cloudwatch.Dashboard(this, 'OperationsDashboard', {
      dashboardName: this.resourcePrefix + '-operations',
      defaultInterval: Duration.hours(6),
      widgets: [
        [
          new cloudwatch.GraphWidget({
            left: [apiErrors, apiThrottles, workerErrors, workerThrottles, schedulerErrors],
            title: 'Errors and throttles',
          }),
          new cloudwatch.GraphWidget({
            left: [apiDuration, workerDuration, apiGatewayLatency],
            title: 'Latency p95',
          }),
        ],
        [
          new cloudwatch.GraphWidget({
            left: [apiRequests, apiClientErrors, apiGatewayErrors],
            title: 'API traffic',
          }),
          new cloudwatch.GraphWidget({
            left: [paymentAttempts, paymentPending, paymentApproved, paymentDeclined],
            title: 'Payment outcomes',
          }),
        ],
        [
          new cloudwatch.GraphWidget({
            left: [
              dynamoThrottles,
              inventoryConflicts,
              reconcileFailures,
              reconciliationRetries,
              providerErrors,
              oldestPendingAge,
            ],
            title: 'Data integrity and reconciliation',
          }),
          new cloudwatch.GraphWidget({
            left: [deliveryEffects, idempotencyReplays],
            title: 'Idempotent business effects',
          }),
        ],
        [new cloudwatch.AlarmStatusWidget({ alarms, title: 'Release alarms' })],
      ],
    });

    const notification = (threshold: number, type: 'ACTUAL' | 'FORECASTED') => ({
      notification: {
        comparisonOperator: 'GREATER_THAN',
        notificationType: type,
        threshold,
        thresholdType: 'PERCENTAGE',
      },
      subscribers: [{ address: this.alertTopic.topicArn, subscriptionType: 'SNS' }],
    });
    const warningNotifications = config.budgetWarningUsd.map((amount) =>
      notification(Number(((amount / config.budgetMaxUsd) * 100).toFixed(2)), 'ACTUAL'),
    );
    new budgets.CfnBudget(this, 'ReleaseBudget', {
      budget: {
        budgetLimit: { amount: config.budgetMaxUsd, unit: 'USD' },
        budgetName:
          this.resourcePrefix + '-monthly-usd-' + config.budgetMaxUsd.toFixed(2).replace('.', '-'),
        budgetType: 'COST',
        costFilters: { TagKeyValue: ['user:Project$' + config.projectName] },
        timeUnit: 'MONTHLY',
      },
      notificationsWithSubscribers: [...warningNotifications, notification(100, 'FORECASTED')],
      resourceTags: [
        { key: 'CandidateSha', value: config.candidateSha },
        { key: 'Project', value: config.projectName },
        { key: 'ReleaseId', value: config.releaseId },
        { key: 'ExpiresOn', value: config.expiresOn },
        { key: 'CleanupExpiresAtUtc', value: config.cleanupExpiresAtUtc },
      ],
    });

    this.releaseOutput(
      'AlertTopicArn',
      this.alertTopic.topicArn,
      'Alarm and budget notification topic',
    );
    this.releaseOutput('DashboardName', dashboard.dashboardName, 'Operational dashboard name');
    this.releaseOutput(
      'RollbackRehearsalAlarmName',
      rollbackRehearsalAlarm.alarmName,
      'Dedicated actionless rollback rehearsal alarm name',
    );
    this.releaseOutput(
      'RollbackRehearsalAlarmArn',
      rollbackRehearsalAlarm.alarmArn,
      'Dedicated actionless rollback rehearsal alarm ARN',
    );
    this.releaseOutput(
      'BudgetContract',
      `${config.budgetMaxUsd.toFixed(2)}:${config.budgetWarningUsd
        .map((amount) => amount.toFixed(2))
        .join(',')}`,
      'Approved maximum and warning amounts in USD; no destination is exposed',
    );
    this.releaseOutput('ReleaseId', config.releaseId, 'Immutable release identifier');
    this.releaseOutput('CandidateSha', config.candidateSha, 'Verified candidate SHA');
  }
}

export interface ReleaseWebStackProps extends ReleaseStackProps {
  readonly apiStack: ReleaseApiStack;
  readonly observabilityStack: ReleaseObservabilityStack;
}

export class ReleaseWebStack extends ReleaseStack {
  public constructor(scope: Construct, id: string, props: ReleaseWebStackProps) {
    super(scope, id, props);
    this.addStackDependency(props.apiStack);
    this.addStackDependency(props.observabilityStack);
    const config = this.configuration;
    const publication = this.publicationControl('DISABLED');
    const webArtifact = inspectReleaseArtifact(config.webArtifactPath, ['index.html'], 'web');
    const bucket = new s3.Bucket(this, 'WebBucket', {
      autoDeleteObjects: this.ephemeralPrerelease,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      lifecycleRules: [
        {
          abortIncompleteMultipartUploadAfter: Duration.days(1),
          noncurrentVersionExpiration: Duration.days(30),
        },
      ],
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: this.releaseRemovalPolicy,
      versioned: true,
    });
    const securityHeaders = this.createHeadersPolicy(
      'SecurityHeaders',
      'public,max-age=31536000,immutable',
    );
    const documentHeaders = this.createHeadersPolicy('DocumentHeaders', 'no-store');
    const apiHeaders = this.createHeadersPolicy('ApiHeaders');
    const webOrigin = origins.S3BucketOrigin.withOriginAccessControl(bucket);
    if (
      this.restrictedViewerAccess &&
      (config.prereleaseKeyGroupId === undefined ||
        config.prereleasePublicKeyId === undefined ||
        config.runtimeSecretArn === undefined)
    ) {
      throw new Error('prerelease edge access configuration is incomplete');
    }
    const prereleaseKeyGroup =
      this.restrictedViewerAccess && config.prereleaseKeyGroupId !== undefined
        ? cloudfront.KeyGroup.fromKeyGroupId(
            this,
            'PrereleaseViewerKeyGroup',
            config.prereleaseKeyGroupId,
          )
        : undefined;
    const trustedKeyGroups = prereleaseKeyGroup === undefined ? undefined : [prereleaseKeyGroup];
    const prereleaseOriginHeaders =
      this.originGateEnabled &&
      config.runtimeSecretArn !== undefined &&
      config.runtimeSecretVersionId !== undefined
        ? {
            'x-stage7-origin-verify': SecretValue.secretsManager(config.runtimeSecretArn, {
              jsonField: 'prereleaseOriginToken',
              versionId: config.runtimeSecretVersionId,
            }).unsafeUnwrap(),
          }
        : undefined;
    const spaRewrite = new cloudfront.Function(this, 'SpaRewrite', {
      code: cloudfront.FunctionCode.fromInline(
        "function handler(event){var r=event.request;var p=r.uri.split('/').pop();" +
          "if(r.uri.endsWith('/')){r.uri+='index.html';}" +
          "else if(p.indexOf('.')===-1){r.uri='/index.html';}return r;}",
      ),
      comment: 'Maps extensionless client-side routes to the SPA shell',
      functionName: this.resourcePrefix + '-spa-rewrite',
    });
    const webCertificate =
      config.domain === undefined
        ? undefined
        : acm.Certificate.fromCertificateArn(
            this,
            'WebCertificate',
            config.domain.webCertificateArn,
          );
    const distribution = new cloudfront.Distribution(this, 'WebDistribution', {
      certificate: webCertificate,
      comment: this.resourcePrefix + ' private-origin SPA',
      defaultBehavior: {
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        compress: true,
        functionAssociations: [
          { eventType: cloudfront.FunctionEventType.VIEWER_REQUEST, function: spaRewrite },
        ],
        origin: webOrigin,
        responseHeadersPolicy: documentHeaders,
        trustedKeyGroups,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      defaultRootObject: 'index.html',
      domainNames: config.domain === undefined ? undefined : [config.domain.webDomainName],
      enabled: false,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      minimumProtocolVersion:
        webCertificate === undefined ? undefined : cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      additionalBehaviors: {
        'assets/*': {
          allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
          cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
          compress: true,
          origin: webOrigin,
          responseHeadersPolicy: securityHeaders,
          trustedKeyGroups,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        },
        'api/*': {
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          compress: true,
          origin: new origins.HttpOrigin(props.apiStack.apiOriginDomainName, {
            customHeaders: prereleaseOriginHeaders,
            originSslProtocols: [cloudfront.OriginSslPolicy.TLS_V1_2],
            protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
          }),
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
          responseHeadersPolicy: apiHeaders,
          trustedKeyGroups,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        },
      },
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
    });
    const cfnDistribution = distribution.node.defaultChild as cloudfront.CfnDistribution;
    cfnDistribution.addPropertyOverride(
      'DistributionConfig.Enabled',
      Fn.conditionIf(publication.condition.logicalId, true, false),
    );
    const publicationStatus = Token.asString(
      Fn.conditionIf(publication.condition.logicalId, 'ENABLED', 'DISABLED'),
    );
    const applicationUrl =
      config.domain === undefined
        ? 'https://' + distribution.distributionDomainName
        : 'https://' + config.domain.webDomainName;
    this.deployWebArtifact(webArtifact.path, bucket, distribution);
    const publicOriginParameterName = '/' + this.resourcePrefix + '/public-origin';
    new ssm.StringParameter(this, 'PublicOriginParameter', {
      description: 'Canonical same-origin URL consumed by API and worker at cold start',
      parameterName: publicOriginParameterName,
      simpleName: false,
      stringValue: applicationUrl,
    }).applyRemovalPolicy(this.releaseRemovalPolicy);

    if (config.domain !== undefined) {
      const zone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
        hostedZoneId: config.domain.hostedZoneId,
        zoneName: config.domain.hostedZoneName,
      });
      const target = route53.RecordTarget.fromAlias(
        new route53Targets.CloudFrontTarget(distribution),
      );
      new route53.ARecord(this, 'WebAliasA', {
        recordName: config.domain.webDomainName,
        target,
        zone,
      });
      new route53.AaaaRecord(this, 'WebAliasAAAA', {
        recordName: config.domain.webDomainName,
        target,
        zone,
      });
    }

    const cloudFrontMetric = (name: string): cloudwatch.Metric =>
      new cloudwatch.Metric({
        dimensionsMap: { DistributionId: distribution.distributionId, Region: 'Global' },
        metricName: name,
        namespace: 'AWS/CloudFront',
        period: Duration.minutes(5),
        statistic: 'average',
      });
    const cloudFrontClientErrors = cloudFrontMetric('4xxErrorRate');
    const cloudFrontErrors = cloudFrontMetric('5xxErrorRate');
    const cloudFrontAlarm = new cloudwatch.Alarm(this, 'CloudFrontErrorsAlarm', {
      alarmDescription: config.releaseId + ' edge failure signal',
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 1,
      metric: cloudFrontErrors,
      threshold: 5,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    cloudFrontAlarm.addAlarmAction(
      new cloudwatchActions.SnsAction(props.observabilityStack.alertTopic),
    );
    new cloudwatch.Dashboard(this, 'EdgeDashboard', {
      dashboardName: this.resourcePrefix + '-edge',
      defaultInterval: Duration.hours(6),
      widgets: [
        [
          new cloudwatch.GraphWidget({
            left: [cloudFrontClientErrors, cloudFrontErrors],
            title: 'CloudFront error rates',
          }),
          new cloudwatch.AlarmStatusWidget({
            alarms: [cloudFrontAlarm],
            title: 'Edge alarm',
          }),
        ],
      ],
    });

    this.releaseOutput('ApplicationUrl', applicationUrl, 'Canonical HTTPS application URL');
    this.releaseOutput('ApiUrl', applicationUrl + '/api', 'Same-origin API base URL');
    this.releaseOutput('ApiDocsUrl', applicationUrl + '/api/docs', 'Public API documentation URL');
    this.releaseOutput(
      'HealthUrl',
      applicationUrl + '/api/health/ready',
      'Application readiness URL',
    );
    this.releaseOutput('WebBucketName', bucket.bucketName, 'Private versioned web bucket');
    this.releaseOutput('DistributionId', distribution.distributionId, 'CloudFront distribution ID');
    this.releaseOutput(
      'WebPublicationStatus',
      publicationStatus,
      'CloudFormation-managed edge publication state',
    );
    this.releaseOutput('WebArtifactSha256', webArtifact.sha256, 'Web artifact directory SHA-256');
    this.releaseOutput('WebArtifactBytes', String(webArtifact.sizeBytes), 'Web artifact bytes');
    this.releaseOutput('PublicOriginParameterName', publicOriginParameterName, 'Origin parameter');
    this.releaseOutput(
      'PrereleaseAccessBindingSha256',
      config.runtimeSecretArn !== undefined && config.runtimeSecretVersionId !== undefined
        ? sha256(
            [
              this.restrictedViewerAccess ? 'CLOUDFRONT_SIGNED_COOKIE' : 'ORIGIN_GATE_ONLY',
              config.prereleaseKeyGroupId ?? 'NONE',
              config.prereleasePublicKeyId ?? 'NONE',
              config.runtimeSecretArn,
              config.runtimeSecretVersionId,
            ].join('\n'),
          )
        : 'NOT_APPLICABLE',
      'Hash binding the prerelease viewer signer, key group and origin-secret reference',
    );
    this.releaseOutput(
      'TlsBaselineStatus',
      config.domain === undefined
        ? 'BLOCKED_CUSTOM_DOMAIN_REQUIRED_PRERELEASE_ONLY'
        : 'TLS12_CUSTOM_DOMAIN_CONFIGURED',
      'Managed CloudFront domain does not satisfy the full TLS 1.2 gate',
    );
    this.releaseOutput(
      'ReleaseScope',
      config.paymentAdapter === 'sandbox'
        ? config.domain === undefined
          ? 'SANDBOX_NON_PUBLIC_PRERELEASE_ONLY'
          : 'SANDBOX_RELEASE_CANDIDATE'
        : 'NON_PUBLIC_FAKE_PRERELEASE_ONLY',
      'Authorized scope of this synthesized release',
    );
    this.releaseOutput(
      'RollbackMechanism',
      'RESTORE_RECORDED_S3_OBJECT_VERSION_AND_INVALIDATE_MUTABLE_PATHS_ONLY',
      'Frontend rollback mechanism',
    );
    this.releaseOutput('ReleaseId', config.releaseId, 'Immutable release identifier');
    this.releaseOutput('CandidateSha', config.candidateSha, 'Verified candidate SHA');
  }

  private createHeadersPolicy(id: string, cacheControl?: string): cloudfront.ResponseHeadersPolicy {
    const config = this.configuration;
    const sandboxConnect = config.paymentAdapter === 'sandbox' ? ' https://sandbox.wompi.co' : '';
    const csp =
      "default-src 'self'; connect-src 'self'" +
      sandboxConnect +
      "; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; " +
      "img-src 'self' data:; font-src 'self'; script-src 'self'; style-src 'self'";
    const customHeaders = [
      {
        header: 'Permissions-Policy',
        override: true,
        value: 'camera=(), geolocation=(), microphone=(), payment=()',
      },
    ];
    if (cacheControl !== undefined) {
      customHeaders.push({ header: 'Cache-Control', override: true, value: cacheControl });
    }
    if (config.domain === undefined) {
      customHeaders.push({
        header: 'X-Robots-Tag',
        override: true,
        value: 'noindex,nofollow,noarchive',
      });
    }
    return new cloudfront.ResponseHeadersPolicy(this, id, {
      customHeadersBehavior: { customHeaders },
      securityHeadersBehavior: {
        contentSecurityPolicy: { contentSecurityPolicy: csp, override: true },
        contentTypeOptions: { override: true },
        frameOptions: { frameOption: cloudfront.HeadersFrameOption.DENY, override: true },
        referrerPolicy: {
          referrerPolicy: cloudfront.HeadersReferrerPolicy.SAME_ORIGIN,
          override: true,
        },
        strictTransportSecurity: {
          accessControlMaxAge: Duration.days(365),
          includeSubdomains: config.domain !== undefined,
          override: true,
          preload: false,
        },
        xssProtection: { modeBlock: true, override: true, protection: true },
      },
    });
  }

  private deployWebArtifact(
    artifactPath: string,
    bucket: s3.IBucket,
    distribution: cloudfront.IDistribution,
  ): void {
    const logGroup = new logs.LogGroup(this, 'WebDeploymentLogGroup', {
      logGroupName: '/' + this.resourcePrefix + '/deployment/web',
      removalPolicy: this.releaseRemovalPolicy,
      retention: RETENTION,
    });
    const immutable = new s3deploy.BucketDeployment(this, 'DeployImmutableAssets', {
      cacheControl: [s3deploy.CacheControl.fromString('public,max-age=31536000,immutable')],
      destinationBucket: bucket,
      exclude: ['*'],
      include: ['assets/*'],
      logGroup,
      prune: false,
      retainOnDelete: !this.ephemeralPrerelease,
      sources: [s3deploy.Source.asset(artifactPath)],
    });
    const mutable = new s3deploy.BucketDeployment(this, 'DeployMutableDocuments', {
      cacheControl: [s3deploy.CacheControl.noStore()],
      destinationBucket: bucket,
      distribution,
      distributionPaths: ['/index.html', '/legal/*', '/product-placeholder.svg'],
      exclude: ['assets/*'],
      logGroup,
      prune: false,
      retainOnDelete: !this.ephemeralPrerelease,
      sources: [s3deploy.Source.asset(artifactPath)],
    });
    mutable.node.addDependency(immutable);
  }
}
