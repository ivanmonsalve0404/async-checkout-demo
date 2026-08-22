export interface PublicConfig {
  readonly apiBaseUrl: string;
  readonly productId: string;
  readonly releaseId: string;
}

const productIdPattern = /^[A-Za-z0-9_-]{8,128}$/;
const apiBaseUrlPattern = /^\/api\/v1$/;
const releaseIdPattern = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/;
const defaultConfig = Object.freeze({
  apiBaseUrl: '/api/v1',
  productId: 'product-demo-001',
  releaseId: 'rel-19700101-0000-0000000',
});
let activeConfig: PublicConfig = defaultConfig;

const parsePublicConfig = (value: unknown): PublicConfig => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Public configuration must be an object');
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== 3 ||
    !Object.hasOwn(record, 'apiBaseUrl') ||
    !Object.hasOwn(record, 'productId') ||
    !Object.hasOwn(record, 'releaseId') ||
    typeof record.apiBaseUrl !== 'string' ||
    !apiBaseUrlPattern.test(record.apiBaseUrl) ||
    typeof record.productId !== 'string' ||
    !productIdPattern.test(record.productId) ||
    typeof record.releaseId !== 'string' ||
    !releaseIdPattern.test(record.releaseId)
  ) {
    throw new Error('Public configuration is invalid');
  }
  return Object.freeze({
    apiBaseUrl: record.apiBaseUrl,
    productId: record.productId,
    releaseId: record.releaseId,
  });
};

export const readPublicConfig = (environment: Record<string, string | undefined>): PublicConfig => {
  const productId = environment.VITE_PRODUCT_ID ?? 'product-demo-001';
  const releaseId = environment.VITE_STAGE7_RELEASE_ID ?? defaultConfig.releaseId;
  if (!productIdPattern.test(productId)) {
    throw new Error('VITE_PRODUCT_ID must be an opaque public identifier');
  }
  if (!releaseIdPattern.test(releaseId)) {
    throw new Error('VITE_STAGE7_RELEASE_ID must be a public release identifier');
  }
  return { apiBaseUrl: '/api/v1', productId, releaseId };
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
