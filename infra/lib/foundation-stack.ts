import * as path from 'node:path';

import { Aws, CfnOutput, Duration, RemovalPolicy, Stack, Tags } from 'aws-cdk-lib';
import type { StackProps } from 'aws-cdk-lib';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import type { Construct } from 'constructs';

import type { FoundationConfig } from './config';

export interface FoundationStackProps extends StackProps {
  readonly configuration: FoundationConfig;
}

const RECONCILE_INDEX = 'GSI1-Reconcile';

export class FoundationStack extends Stack {
  public constructor(scope: Construct, id: string, props: FoundationStackProps) {
    super(scope, id, props);

    const config = props.configuration;
    const removalPolicy = RemovalPolicy.DESTROY;
    const resourcePrefix = config.projectName + '-' + config.environment;

    Tags.of(this).add('Project', config.projectName);
    Tags.of(this).add('Environment', config.environment);
    Tags.of(this).add('CostScope', 'technical-test');
    Tags.of(this).add('ManagedBy', 'cdk');
    Tags.of(this).add('PaymentMode', 'fake');

    const catalogTable = new dynamodb.Table(this, 'CatalogTable', {
      partitionKey: { name: 'PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'SK', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: false,
      },
      deletionProtection: false,
      removalPolicy,
    });
    this.limitOnDemandThroughput(catalogTable, 50, 25);

    const checkoutTable = new dynamodb.Table(this, 'CheckoutTable', {
      partitionKey: { name: 'PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'SK', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: false,
      },
      timeToLiveAttribute: 'purgeAt',
      deletionProtection: false,
      removalPolicy,
    });
    checkoutTable.addGlobalSecondaryIndex({
      indexName: RECONCILE_INDEX,
      partitionKey: {
        name: 'GSI1PK',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'GSI1SK',
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.INCLUDE,
      nonKeyAttributes: ['checkoutId', 'transactionId', 'dispatchPhase', 'paymentStatus'],
    });
    this.limitOnDemandThroughput(checkoutTable, 50, 50);

    const apiLogGroup = this.createLogGroup(
      'ApiLogGroup',
      '/' + resourcePrefix + '/lambda/api',
      removalPolicy,
    );
    const workerLogGroup = this.createLogGroup(
      'WorkerLogGroup',
      '/' + resourcePrefix + '/lambda/worker',
      removalPolicy,
    );

    const apiRole = this.createLambdaRole('ApiRole', apiLogGroup);
    const workerRole = this.createLambdaRole('WorkerRole', workerLogGroup);

    const checkoutIndexArn = checkoutTable.tableArn + '/index/' + RECONCILE_INDEX;
    this.addPolicy(
      apiRole,
      'ApiCatalogReads',
      ['dynamodb:GetItem', 'dynamodb:BatchGetItem', 'dynamodb:Query'],
      [catalogTable.tableArn],
    );
    this.addPolicy(
      apiRole,
      'ApiCheckoutReads',
      ['dynamodb:GetItem', 'dynamodb:Query'],
      [checkoutTable.tableArn, checkoutIndexArn],
    );
    this.addPolicy(
      apiRole,
      'ApiTableWrites',
      ['dynamodb:UpdateItem', 'dynamodb:TransactWriteItems'],
      [catalogTable.tableArn, checkoutTable.tableArn],
    );
    this.addPolicy(workerRole, 'WorkerCatalogReads', ['dynamodb:GetItem'], [catalogTable.tableArn]);
    this.addPolicy(
      workerRole,
      'WorkerCheckoutReads',
      ['dynamodb:GetItem', 'dynamodb:Query'],
      [checkoutTable.tableArn, checkoutIndexArn],
    );
    this.addPolicy(
      workerRole,
      'WorkerTableWrites',
      ['dynamodb:UpdateItem', 'dynamodb:TransactWriteItems'],
      [catalogTable.tableArn, checkoutTable.tableArn],
    );

    const placeholderCode = lambda.Code.fromAsset(
      path.join(__dirname, '..', 'assets', 'synth-placeholder'),
    );
    const safeEnvironment = {
      APP_ENV: config.environment,
      AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
      CATALOG_TABLE_NAME: catalogTable.tableName,
      CHECKOUT_TABLE_NAME: checkoutTable.tableName,
      FOUNDATION_SYNTH_ONLY: 'true',
      LOG_LEVEL: 'info',
      MAX_BODY_BYTES: '16384',
      PAYMENT_ADAPTER: config.paymentAdapter,
      PAYMENTS_ENABLED: String(config.paymentsEnabled),
      TOKENIZATION_MODE: config.tokenizationMode,
    };

    const apiFunction = new lambda.Function(this, 'ApiFunction', {
      architecture: lambda.Architecture.ARM_64,
      code: placeholderCode,
      description: 'Fake-only stage 4 API synthesis placeholder',
      environment: safeEnvironment,
      handler: 'index.apiHandler',
      logGroup: apiLogGroup,
      loggingFormat: lambda.LoggingFormat.JSON,
      memorySize: 512,
      reservedConcurrentExecutions: 5,
      role: apiRole,
      runtime: lambda.Runtime.NODEJS_24_X,
      timeout: Duration.seconds(10),
    });

    const workerFunction = new lambda.Function(this, 'WorkerFunction', {
      architecture: lambda.Architecture.ARM_64,
      code: placeholderCode,
      description: 'Fake-only stage 4 reconciliation synthesis placeholder',
      environment: {
        ...safeEnvironment,
        RECONCILE_BATCH_SIZE: '10',
        RECONCILE_LEASE_SECONDS: '45',
      },
      handler: 'index.workerHandler',
      logGroup: workerLogGroup,
      loggingFormat: lambda.LoggingFormat.JSON,
      memorySize: 512,
      reservedConcurrentExecutions: 1,
      role: workerRole,
      runtime: lambda.Runtime.NODEJS_24_X,
      timeout: Duration.seconds(50),
    });
    const workerAlias = new lambda.Alias(this, 'WorkerAlias', {
      aliasName: config.environment,
      version: workerFunction.currentVersion,
    });

    const httpApi = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: resourcePrefix + '-api',
      createDefaultStage: true,
      description: 'Same-origin fake-only HTTP API foundation',
    });
    httpApi.addRoutes({
      integration: new integrations.HttpLambdaIntegration('ApiIntegration', apiFunction),
      methods: [apigwv2.HttpMethod.ANY],
      path: '/{proxy+}',
    });

    const defaultStage = httpApi.defaultStage;
    if (!defaultStage) {
      throw new Error('HTTP API default stage must exist');
    }
    const cfnStage = defaultStage.node.defaultChild as apigwv2.CfnStage;
    cfnStage.defaultRouteSettings = {
      detailedMetricsEnabled: false,
      throttlingBurstLimit: 10,
      throttlingRateLimit: 5,
    };

    const schedulerRole = new iam.Role(this, 'SchedulerRole', {
      assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com'),
      description: 'Invokes only the fake-only reconciliation worker alias',
    });
    this.addPolicy(
      schedulerRole,
      'InvokeWorkerAlias',
      ['lambda:InvokeFunction'],
      [workerAlias.functionArn],
    );

    new scheduler.CfnSchedule(this, 'ReconcileSchedule', {
      description: 'Stage 4 fake reconciliation schedule; disabled until an authorized deploy',
      flexibleTimeWindow: { mode: 'OFF' },
      name: resourcePrefix + '-reconcile',
      scheduleExpression: 'rate(1 minute)',
      state: 'DISABLED',
      target: {
        arn: workerAlias.functionArn,
        input: JSON.stringify({
          action: 'reconcile',
          mode: 'fake',
        }),
        retryPolicy: {
          maximumEventAgeInSeconds: 300,
          maximumRetryAttempts: 2,
        },
        roleArn: schedulerRole.roleArn,
      },
    });

    const webBucket = new s3.Bucket(this, 'WebBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy,
      versioned: true,
    });

    const securityHeadersBehavior = {
      contentSecurityPolicy: {
        contentSecurityPolicy:
          "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'",
        override: true,
      },
      contentTypeOptions: { override: true },
      frameOptions: {
        frameOption: cloudfront.HeadersFrameOption.DENY,
        override: true,
      },
      referrerPolicy: {
        referrerPolicy: cloudfront.HeadersReferrerPolicy.SAME_ORIGIN,
        override: true,
      },
      strictTransportSecurity: {
        accessControlMaxAge: Duration.days(365),
        includeSubdomains: true,
        override: true,
        preload: true,
      },
      xssProtection: {
        modeBlock: true,
        override: true,
        protection: true,
      },
    };
    const securityHeaders = new cloudfront.ResponseHeadersPolicy(this, 'SecurityHeaders', {
      securityHeadersBehavior,
    });
    const documentHeaders = new cloudfront.ResponseHeadersPolicy(this, 'DocumentHeaders', {
      customHeadersBehavior: {
        customHeaders: [
          {
            header: 'Cache-Control',
            override: true,
            value: 'no-store',
          },
        ],
      },
      securityHeadersBehavior,
    });

    const apiDomain = httpApi.httpApiId + '.execute-api.' + this.region + '.' + Aws.URL_SUFFIX;
    const webOrigin = origins.S3BucketOrigin.withOriginAccessControl(webBucket);
    const distribution = new cloudfront.Distribution(this, 'WebDistribution', {
      comment: resourcePrefix + ' fake-only SPA',
      defaultBehavior: {
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        compress: true,
        origin: webOrigin,
        responseHeadersPolicy: documentHeaders,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      defaultRootObject: 'index.html',
      enabled: true,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      additionalBehaviors: {
        'assets/*': {
          allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
          cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
          compress: true,
          origin: webOrigin,
          responseHeadersPolicy: securityHeaders,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        },
        'api/*': {
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          compress: true,
          origin: new origins.HttpOrigin(apiDomain, {
            originSslProtocols: [cloudfront.OriginSslPolicy.TLS_V1_2],
            protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
          }),
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
          responseHeadersPolicy: documentHeaders,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        },
      },
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
    });

    new CfnOutput(this, 'ApplicationUrl', {
      description: 'Symbolic HTTPS entry point after an authorized deployment',
      value: 'https://' + distribution.distributionDomainName,
    });
  }

  private createLogGroup(
    id: string,
    logGroupName: string,
    removalPolicy: RemovalPolicy,
  ): logs.LogGroup {
    return new logs.LogGroup(this, id, {
      logGroupName,
      removalPolicy,
      retention: logs.RetentionDays.ONE_WEEK,
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

  private addPolicy(role: iam.Role, sid: string, actions: string[], resources: string[]): void {
    role.addToPolicy(
      new iam.PolicyStatement({
        actions,
        effect: iam.Effect.ALLOW,
        resources,
        sid,
      }),
    );
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
