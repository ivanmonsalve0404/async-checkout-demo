export interface PublicConfig {
  readonly apiBaseUrl: string;
  readonly productId: string;
}

const productIdPattern = /^[A-Za-z0-9_-]{8,128}$/;
const apiBaseUrlPattern = /^\/api\/v1$/;
const defaultConfig = Object.freeze({ apiBaseUrl: '/api/v1', productId: 'product-demo-001' });
let activeConfig: PublicConfig = defaultConfig;

const parsePublicConfig = (value: unknown): PublicConfig => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Public configuration must be an object');
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
    throw new Error('Public configuration is invalid');
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

export const loadRuntimePublicConfig = async (
  fetchImplementation: typeof fetch = globalThis.fetch,
): Promise<PublicConfig> => {
  const response = await fetchImplementation('/public-config.json', {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
    method: 'GET',
    redirect: 'error',
  });
  if (
    response.status !== 200 ||
    response.headers.get('content-type')?.toLowerCase().includes('application/json') !== true
  ) {
    throw new Error('Public configuration is unavailable');
  }
  const source = await response.text();
  if (source.length === 0 || source.length > 4_096) {
    throw new Error('Public configuration is invalid');
  }
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error('Public configuration is invalid');
  }
  activeConfig = parsePublicConfig(value);
  return activeConfig;
};

export const getPublicConfig = (): PublicConfig => activeConfig;
