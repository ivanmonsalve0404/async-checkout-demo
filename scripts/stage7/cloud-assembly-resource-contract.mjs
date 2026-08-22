const STACK_SUFFIXES = Object.freeze(['data', 'api', 'observability', 'web']);

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const sortedRecord = (value) =>
  Object.fromEntries(
    Object.entries(value).toSorted(([left], [right]) => left.localeCompare(right)),
  );

const stackSuffix = (artifactId) =>
  typeof artifactId === 'string'
    ? (STACK_SUFFIXES.find((value) => artifactId.endsWith(`-${value}`)) ?? null)
    : null;

const expectedCounts = ({ scope, domainMode }, suffix) => {
  const customDomain = domainMode === 'CUSTOM_AUTHORIZED';
  const prerelease = scope === 'prerelease';
  const expectedBySuffix = {
    data: {
      'AWS::DynamoDB::Table': 2,
    },
    api: {
      'AWS::ApiGatewayV2::Api': 1,
      ...(customDomain
        ? {
            'AWS::ApiGatewayV2::ApiMapping': 1,
            'AWS::ApiGatewayV2::DomainName': 1,
            'AWS::Route53::RecordSet': 2,
          }
        : {}),
      'AWS::ApiGatewayV2::Integration': 1,
      'AWS::ApiGatewayV2::Route': 1,
      'AWS::ApiGatewayV2::Stage': 1,
      'AWS::IAM::Policy': 3,
      'AWS::IAM::Role': 3,
      'AWS::Lambda::Alias': 2,
      'AWS::Lambda::Function': 2,
      'AWS::Lambda::Permission': 1,
      'AWS::Lambda::Version': 2,
      'AWS::Logs::LogGroup': 3,
      'AWS::Scheduler::Schedule': 1,
    },
    observability: {
      'AWS::Budgets::Budget': 1,
      'AWS::CloudWatch::Alarm': 15,
      'AWS::CloudWatch::Dashboard': 1,
      'AWS::Logs::MetricFilter': 11,
      'AWS::SNS::Subscription': 1,
      'AWS::SNS::Topic': 1,
      'AWS::SNS::TopicPolicy': 1,
    },
    web: {
      'AWS::CloudFront::Distribution': 1,
      'AWS::CloudFront::Function': 1,
      'AWS::CloudFront::OriginAccessControl': 1,
      'AWS::CloudFront::ResponseHeadersPolicy': 3,
      'AWS::CloudWatch::Alarm': 1,
      'AWS::CloudWatch::Dashboard': 1,
      'AWS::IAM::Policy': 1,
      'AWS::IAM::Role': prerelease ? 2 : 1,
      'AWS::Lambda::Function': prerelease ? 2 : 1,
      'AWS::Lambda::LayerVersion': 2,
      'AWS::Logs::LogGroup': 1,
      ...(customDomain ? { 'AWS::Route53::RecordSet': 2 } : {}),
      'AWS::S3::Bucket': 1,
      'AWS::S3::BucketPolicy': 1,
      'AWS::SSM::Parameter': 1,
      'Custom::CDKBucketDeployment': 2,
      ...(prerelease ? { 'Custom::S3AutoDeleteObjects': 1 } : {}),
    },
  };
  return expectedBySuffix[suffix];
};

export const cloudFormationResourceTypeCounts = (template) => {
  if (!object(template?.Resources)) return null;
  const counts = {};
  for (const resource of Object.values(template.Resources)) {
    if (!object(resource) || typeof resource.Type !== 'string' || resource.Type === '') return null;
    counts[resource.Type] = (counts[resource.Type] ?? 0) + 1;
  }
  return sortedRecord(counts);
};

export const inspectReleaseStackResourceAllowlist = ({
  artifactId,
  domainMode,
  scope,
  template,
}) => {
  const suffix = stackSuffix(artifactId);
  const actual = cloudFormationResourceTypeCounts(template);
  const expected =
    suffix === null ? null : sortedRecord(expectedCounts({ scope, domainMode }, suffix));
  return {
    actual,
    expected,
    suffix,
    valid:
      actual !== null && expected !== null && JSON.stringify(actual) === JSON.stringify(expected),
  };
};
