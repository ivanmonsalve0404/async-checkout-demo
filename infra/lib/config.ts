export interface FoundationConfig {
  readonly projectName: string;
  readonly environment: 'preview';
  readonly region: string;
  readonly paymentAdapter: 'fake';
  readonly paymentsEnabled: false;
  readonly tokenizationMode: 'disabled';
}

export interface RawFoundationConfig {
  readonly projectName?: unknown;
  readonly environment?: unknown;
  readonly region?: unknown;
  readonly paymentAdapter?: unknown;
  readonly paymentsEnabled?: unknown;
  readonly tokenizationMode?: unknown;
}

const PROJECT_NAME_PATTERN = /^[a-z][a-z0-9-]{1,30}[a-z0-9]$/;
const REGION_PATTERN = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;

function asBoolean(value: unknown, name: string): boolean {
  if (value === true || value === 'true') {
    return true;
  }
  if (value === false || value === 'false') {
    return false;
  }
  throw new Error(name + ' must be a boolean');
}

function asString(value: unknown, fallback: string, name: string): string {
  const resolved = value ?? fallback;
  if (typeof resolved !== 'string') {
    throw new Error(name + ' must be a string');
  }
  return resolved;
}

export function parseFoundationConfig(raw: RawFoundationConfig): FoundationConfig {
  const projectName = asString(raw.projectName, 'checkout', 'projectName');
  const environment = asString(raw.environment, 'preview', 'environment');
  const region = asString(raw.region, 'us-east-1', 'region');
  const paymentAdapter = asString(raw.paymentAdapter, 'fake', 'paymentAdapter');
  const paymentsEnabled = asBoolean(raw.paymentsEnabled ?? false, 'paymentsEnabled');
  const tokenizationMode = asString(raw.tokenizationMode, 'disabled', 'tokenizationMode');

  if (!PROJECT_NAME_PATTERN.test(projectName)) {
    throw new Error('projectName must be a lowercase, hyphenated slug');
  }
  if (environment !== 'preview') {
    throw new Error('Only the fake-only preview environment may be synthesized');
  }
  if (!REGION_PATTERN.test(region)) {
    throw new Error('region must be an AWS region identifier');
  }
  if (paymentAdapter !== 'fake') {
    throw new Error('Stage 4 only permits the fake payment adapter');
  }
  if (paymentsEnabled) {
    throw new Error('Stage 4 requires paymentsEnabled=false');
  }
  if (tokenizationMode !== 'disabled') {
    throw new Error('Stage 4 requires tokenizationMode=disabled');
  }

  return {
    projectName,
    environment: 'preview',
    region,
    paymentAdapter: 'fake',
    paymentsEnabled: false,
    tokenizationMode: 'disabled',
  };
}
