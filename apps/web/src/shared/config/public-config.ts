export interface PublicConfig {
  readonly apiBaseUrl: string;
  readonly productId: string;
}

export interface RuntimePublicConfigOptions {
  readonly attempts?: number;
  readonly timeoutMs?: number;
}

const productIdPattern = /^[A-Za-z0-9_-]{8,128}$/;
const apiBaseUrlPattern = /^\/api\/v1$/;
const defaultConfig = Object.freeze({ apiBaseUrl: '/api/v1', productId: 'product-demo-001' });
export const runtimePublicConfigAttempts = 2;
export const runtimePublicConfigTimeoutMs = 5_000;
let activeConfig: PublicConfig = defaultConfig;

class RuntimePublicConfigError extends Error {
  public constructor(
    message: 'Public configuration is invalid' | 'Public configuration is unavailable',
    public readonly retryable: boolean,
  ) {
    super(message);
    this.name = 'RuntimePublicConfigError';
  }
}

const invalidRuntimePublicConfig = (): RuntimePublicConfigError =>
  new RuntimePublicConfigError('Public configuration is invalid', false);

const unavailableRuntimePublicConfig = (): RuntimePublicConfigError =>
  new RuntimePublicConfigError('Public configuration is unavailable', true);

const parsePublicConfig = (value: unknown): PublicConfig => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalidRuntimePublicConfig();
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== 2 ||
    !Object.hasOwn(record, 'apiBaseUrl') ||
    !Object.hasOwn(record, 'productId') ||
    typeof record.apiBaseUrl !== 'string' ||
    !apiBaseUrlPattern.test(record.apiBaseUrl) ||
    typeof record.productId !== 'string' ||
    !productIdPattern.test(record.productId)
  ) {
    throw invalidRuntimePublicConfig();
  }
  return Object.freeze({ apiBaseUrl: record.apiBaseUrl, productId: record.productId });
};

export const readPublicConfig = (environment: Record<string, string | undefined>): PublicConfig => {
  const productId = environment.VITE_PRODUCT_ID ?? 'product-demo-001';
  if (!productIdPattern.test(productId)) {
    throw new Error('VITE_PRODUCT_ID must be an opaque public identifier');
  }
  return { apiBaseUrl: '/api/v1', productId };
};

const readRuntimePublicConfig = async (
  fetchImplementation: typeof fetch,
  timeoutMs: number,
): Promise<PublicConfig> => {
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImplementation('/public-config.json', {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      method: 'GET',
      redirect: 'error',
      signal: controller.signal,
    });
    if (
      response.status !== 200 ||
      response.headers.get('content-type')?.toLowerCase().includes('application/json') !== true
    ) {
      throw unavailableRuntimePublicConfig();
    }
    const source = await response.text();
    if (source.length === 0 || source.length > 4_096) {
      throw invalidRuntimePublicConfig();
    }
    let value: unknown;
    try {
      value = JSON.parse(source) as unknown;
    } catch {
      throw invalidRuntimePublicConfig();
    }
    return parsePublicConfig(value);
  } catch (error) {
    if (error instanceof RuntimePublicConfigError) {
      throw error;
    }
    throw unavailableRuntimePublicConfig();
  } finally {
    globalThis.clearTimeout(timeout);
  }
};

const positiveInteger = (value: number, maximum: number): boolean =>
  Number.isSafeInteger(value) && value >= 1 && value <= maximum;

export const loadRuntimePublicConfig = async (
  fetchImplementation: typeof fetch = globalThis.fetch,
  options: RuntimePublicConfigOptions = {},
): Promise<PublicConfig> => {
  const attempts = options.attempts ?? runtimePublicConfigAttempts;
  const timeoutMs = options.timeoutMs ?? runtimePublicConfigTimeoutMs;
  if (!positiveInteger(attempts, 3) || !positiveInteger(timeoutMs, 30_000)) {
    throw new Error('Public configuration loading options are invalid');
  }

  activeConfig = defaultConfig;
  let latestFailure = unavailableRuntimePublicConfig();
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      activeConfig = await readRuntimePublicConfig(fetchImplementation, timeoutMs);
      return activeConfig;
    } catch (error) {
      latestFailure =
        error instanceof RuntimePublicConfigError ? error : unavailableRuntimePublicConfig();
      if (!latestFailure.retryable) {
        throw latestFailure;
      }
    }
  }
  throw latestFailure;
};

export const getPublicConfig = (): PublicConfig => activeConfig;
