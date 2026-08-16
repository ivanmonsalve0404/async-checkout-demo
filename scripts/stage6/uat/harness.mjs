import { spawn } from 'node:child_process';
import { randomBytes, randomInt } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { expect } from '@playwright/test';

import { assertLoopbackUrl, workspaceRoot } from '../lib/evidence.mjs';

export const API_ORIGIN = 'http://127.0.0.1:3000';
export const PRODUCT_ID = 'product-demo-001';
export const PRODUCT_PATH = `/products/${PRODUCT_ID}`;
export const WEB_ORIGIN = 'http://127.0.0.1:4173';

const API_ENTRY = path.join(workspaceRoot, 'apps', 'api', 'dist', 'main.js');
const VITE_ENTRY = path.join(
  workspaceRoot,
  'apps',
  'web',
  'node_modules',
  'vite',
  'bin',
  'vite.js',
);
const NETWORK_GUARD = path.join(workspaceRoot, 'scripts', 'smoke', 'deny-external-network.cjs');
const EXTERNAL_NETWORK_MARKER = 'SMOKE_EXTERNAL_NETWORK_BLOCKED';
let observedApiBlockedMarkers = 0;
let observedBrowserBlockedRequests = 0;
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

assertLoopbackUrl(API_ORIGIN);
assertLoopbackUrl(WEB_ORIGIN);

export class UatFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export const check = (condition, code) => {
  if (!condition) throw new UatFailure(code);
};

export const createExternalNetworkAttemptCounter = () => {
  let count = 0;
  let carry = '';
  return {
    observe: (chunk) => {
      const combined = carry + String(chunk);
      count += combined.split(EXTERNAL_NETWORK_MARKER).length - 1;
      carry = combined.slice(-(EXTERNAL_NETWORK_MARKER.length - 1));
    },
    value: () => count,
  };
};

export const assertNoExternalNetworkAttempts = (count) => {
  check(Number.isSafeInteger(count) && count >= 0, 'UAT_EXTERNAL_NETWORK_COUNTER_INVALID');
  check(count === 0, 'UAT_EXTERNAL_NETWORK_ATTEMPT');
};

export const runExternalNetworkObservationCanary = () => {
  const counter = createExternalNetworkAttemptCounter();
  counter.observe('synthetic-prefix-SMOKE_EXTERNAL_');
  counter.observe('NETWORK_BLOCKED-synthetic-suffix');
  check(counter.value() === 1, 'UAT_EXTERNAL_NETWORK_CANARY_COUNT');
  let failureCode;
  try {
    assertNoExternalNetworkAttempts(counter.value());
  } catch (error) {
    failureCode = error instanceof UatFailure ? error.code : undefined;
  }
  check(failureCode === 'UAT_EXTERNAL_NETWORK_ATTEMPT', 'UAT_EXTERNAL_NETWORK_CANARY_FAIL_OPEN');
  return 'PASS';
};

export const observedExternalNetworkAttempts = () => ({
  apiBlockedMarkers: observedApiBlockedMarkers,
  browserBlockedRequests: observedBrowserBlockedRequests,
  total: observedApiBlockedMarkers + observedBrowserBlockedRequests,
});

export const loopbackFetch = (url, options = {}) => {
  assertLoopbackUrl(url);
  return fetch(url, { ...options, headers: { ...options.headers, Connection: 'close' } });
};

const start = (executable, arguments_, options) => {
  const child = spawn(executable, arguments_, {
    cwd: options.cwd ?? workspaceRoot,
    env: options.env ?? process.env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout?.on('data', options.onOutput ?? (() => undefined));
  child.stderr?.on('data', options.onOutput ?? (() => undefined));
  return child;
};

export const stop = async (child) => {
  if (child === undefined || child.exitCode !== null) return;
  child.kill();
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    sleep(3_000).then(() => child.kill('SIGKILL')),
  ]);
};

const waitFor = async (child, url, code) => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    check(child.exitCode === null, `${code}_EXITED`);
    try {
      const response = await loopbackFetch(url, { signal: AbortSignal.timeout(500) });
      if (response.status >= 100) return;
    } catch {
      // Bounded loopback startup polling.
    }
    await sleep(100);
  }
  throw new UatFailure(`${code}_NOT_READY`);
};

const baseApiEnvironment = {
  ALLOWED_ORIGIN: WEB_ORIGIN,
  API_PORT: '3000',
  APP_ENV: 'test',
  CHECKOUT_TTL_SECONDS: '1800',
  DATA_ADAPTER: 'memory',
  FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
  FAKE_RECONCILE_INTERVAL_MS: '60000',
  PAYMENT_ADAPTER: 'fake',
  PAYMENTS_ENABLED: 'false',
  PRODUCT_INITIAL_STOCK: '3',
  PUBLIC_ASSET_ORIGIN: WEB_ORIGIN,
  QUOTE_TTL_SECONDS: '900',
  TOKENIZATION_MODE: 'disabled',
};

export const withApi = async (overrides, run) => {
  check(existsSync(API_ENTRY), 'API_BUILD_MISSING');
  let output = '';
  const externalNetworkCounter = createExternalNetworkAttemptCounter();
  const child = start(process.execPath, [API_ENTRY], {
    env: {
      ...process.env,
      ...baseApiEnvironment,
      ...overrides,
      NODE_OPTIONS:
        `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(NETWORK_GUARD).href}`.trim(),
    },
    onOutput: (chunk) => {
      externalNetworkCounter.observe(chunk);
      output = `${output}${String(chunk)}`.slice(-200_000);
    },
  });
  try {
    await waitFor(child, `${API_ORIGIN}/api/health`, 'UAT_API');
    return await run({
      countLog: (name) => output.split(`"eventName":"${name}"`).length - 1,
      outputContains: (value) => output.includes(value),
    });
  } finally {
    await stop(child);
    const blockedMarkers = externalNetworkCounter.value();
    observedApiBlockedMarkers += blockedMarkers;
    assertNoExternalNetworkAttempts(blockedMarkers);
  }
};

export const withWebPreview = async (run) => {
  check(existsSync(VITE_ENTRY), 'WEB_PREVIEW_RUNTIME_MISSING');
  const child = start(process.execPath, [VITE_ENTRY, 'preview'], {
    cwd: path.join(workspaceRoot, 'apps', 'web'),
  });
  try {
    await waitFor(child, WEB_ORIGIN, 'UAT_WEB');
    return await run();
  } finally {
    await stop(child);
  }
};

const readResponse = async (response) => {
  const text = await response.text();
  let body = null;
  if (text.length > 0) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  return { status: response.status, headers: response.headers, body };
};

export class ApiSession {
  cookie;

  async request(method, pathname, options = {}) {
    check(pathname.startsWith('/api/'), 'NON_API_PATH_REJECTED');
    const response = await loopbackFetch(`${API_ORIGIN}${pathname}`, {
      method,
      headers: {
        Accept: 'application/json',
        ...(method === 'GET' ? {} : { 'Content-Type': 'application/json', Origin: WEB_ORIGIN }),
        ...(this.cookie === undefined ? {} : { Cookie: this.cookie }),
        ...options.headers,
      },
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      signal: AbortSignal.timeout(options.timeoutMs ?? 5_000),
    });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie !== null) this.cookie = setCookie.split(';')[0];
    return readResponse(response);
  }
}

export const expectStatus = (response, status, code) => {
  check(response.status === status, `${code}_HTTP_${response.status}`);
  return response.body;
};

export const prepareReady = async (session) => {
  const createdResponse = await session.request('POST', '/api/v1/checkouts', {
    body: { productId: PRODUCT_ID },
  });
  const created = expectStatus(createdResponse, 201, 'CREATE_CHECKOUT');
  const customerResponse = await session.request(
    'PUT',
    `/api/v1/checkouts/${created.checkoutId}/customer`,
    {
      headers: { 'If-Match': createdResponse.headers.get('etag') },
      body: {
        fullName: 'Persona Sintetica',
        email: 'uat@example.invalid',
        phone: '+573001112233',
      },
    },
  );
  expectStatus(customerResponse, 200, 'SAVE_CUSTOMER');
  const deliveryResponse = await session.request(
    'PUT',
    `/api/v1/checkouts/${created.checkoutId}/delivery-details`,
    {
      headers: { 'If-Match': customerResponse.headers.get('etag') },
      body: {
        addressLine1: 'Calle Sintetica 1',
        city: 'Bogota',
        region: 'Cundinamarca',
        postalCode: '110111',
      },
    },
  );
  expectStatus(deliveryResponse, 200, 'SAVE_DELIVERY');
  const configurationResponse = await session.request('GET', '/api/v1/payment-configuration');
  const configuration = expectStatus(configurationResponse, 200, 'PAYMENT_CONFIGURATION');
  const terms = configuration.acceptanceContracts.find(({ type }) => type === 'TERMS');
  const personal = configuration.acceptanceContracts.find(({ type }) => type === 'PERSONAL_DATA');
  check(terms !== undefined && personal !== undefined, 'ACCEPTANCE_CONTRACTS_MISSING');
  return {
    checkoutId: created.checkoutId,
    quote: created.quote,
    etag: deliveryResponse.headers.get('etag'),
    body: {
      quoteId: created.quote.quoteId,
      paymentMethodToken: `tok_fake_${randomBytes(12).toString('hex')}`,
      installments: 1,
      acceptances: {
        termsAcceptanceToken: terms.acceptanceToken,
        personalDataAcceptanceToken: personal.acceptanceToken,
      },
    },
  };
};

export const getStock = async (session) => {
  const response = await session.request('GET', `/api/v1/stock/${PRODUCT_ID}`);
  return expectStatus(response, 200, 'GET_STOCK');
};

export const getTransaction = (session, transactionId) =>
  session.request('GET', `/api/v1/transactions/${transactionId}`);

export const waitForTransaction = async (session, transactionId, predicate) => {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await getTransaction(session, transactionId);
    if (response.status === 200 && predicate(response.body)) return response.body;
    await sleep(25);
  }
  throw new UatFailure('TRANSACTION_TIMEOUT');
};

const isLoopback = (candidate) => {
  const url = new URL(candidate);
  return (
    (url.protocol !== 'http:' && url.protocol !== 'https:') ||
    url.hostname === '127.0.0.1' ||
    url.hostname === 'localhost'
  );
};

export const installCapabilityBridge = async (page, options = {}) => {
  let capability = options.initialCapability;
  let externalRequests = 0;
  let lifecycleCancellations = 0;
  const handler = async (route) => {
    try {
      if (!isLoopback(route.request().url())) {
        externalRequests += 1;
        observedBrowserBlockedRequests += 1;
        await route.abort('blockedbyclient');
        return;
      }
      if (!new URL(route.request().url()).pathname.startsWith('/api/')) {
        await route.continue();
        return;
      }
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      let postDataJson;
      try {
        postDataJson = request.postDataJSON();
      } catch {
        postDataJson = undefined;
      }
      const requestOverride = await options.requestOverride?.({
        method: request.method(),
        pathname,
        postDataJson,
      });
      const response = await route.fetch({
        headers:
          capability === undefined
            ? request.headers()
            : { ...request.headers(), cookie: capability },
        ...requestOverride,
      });
      const setCookie = response.headers()['set-cookie'];
      if (setCookie !== undefined) capability = setCookie.split(';')[0];
      if (options.responsePolicy !== undefined) {
        const body = await response.body();
        let responseJson;
        try {
          responseJson = JSON.parse(body.toString('utf8'));
        } catch {
          responseJson = undefined;
        }
        const policy = await options.responsePolicy({
          method: request.method(),
          pathname,
          status: response.status(),
          responseJson,
        });
        if (policy === 'ABORT_AFTER_COMMIT') {
          await route.abort('failed');
          return;
        }
        await route.fulfill({ response, body });
        return;
      }
      await route.fulfill({ response });
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      if (
        /fetch response has been disposed|target (?:page|context|browser).*closed|route is already handled|request context disposed/iu.test(
          message,
        )
      ) {
        lifecycleCancellations += 1;
        return;
      }
      throw error;
    }
  };
  await page.route('**/*', handler);
  return {
    externalRequests: () => externalRequests,
    lifecycleCancellations: () => lifecycleCancellations,
    capability: () => capability,
    dispose: () => page.unrouteAll({ behavior: 'wait' }),
  };
};

const syntheticCard = () => {
  const digits = Array.from(randomBytes(14), (value) => value % 10);
  const prefix = `4${digits.join('')}`;
  const luhn = (candidate) => {
    let sum = 0;
    let twice = false;
    for (let index = candidate.length - 1; index >= 0; index -= 1) {
      const value = Number(candidate[index]) * (twice ? 2 : 1);
      sum += value > 9 ? value - 9 : value;
      twice = !twice;
    }
    return sum % 10 === 0;
  };
  const number = Array.from({ length: 10 }, (_, value) => `${prefix}${value}`).find(luhn);
  check(number !== undefined, 'CARD_FIXTURE_FAILED');
  return {
    number,
    expiry: `12/${String((new Date().getFullYear() + 1) % 100).padStart(2, '0')}`,
    securityCode: String(randomInt(0, 1_000)).padStart(3, '0'),
    holderName: 'Persona Sintetica',
  };
};

export const fillCard = async (page, { tokenize = true } = {}) => {
  const card = syntheticCard();
  await page.getByLabel('Número de tarjeta').fill(card.number);
  await page.getByLabel('Vencimiento').fill(card.expiry);
  await page.getByLabel('Código de seguridad').fill(card.securityCode);
  await page.getByLabel('Nombre en la tarjeta').fill(card.holderName);
  if (tokenize) {
    await page.getByTestId('payment-tokenize').click();
    await expect(page.getByTestId('checkout-step-customer')).toBeVisible({ timeout: 5_000 });
  }
  return card;
};

export const fillCustomerDelivery = async (page) => {
  await page.getByLabel('Nombre completo').fill('Persona Sintetica');
  await page.getByLabel('Correo electrónico').fill('uat@example.invalid');
  await page.getByLabel('Teléfono').fill('+573001112233');
  await page.getByLabel('Dirección', { exact: true }).fill('Calle Sintetica 1');
  await page.getByLabel('Ciudad').fill('Bogota');
  await page.getByLabel('Departamento o región').fill('Cundinamarca');
  await page.getByLabel('Código postal (opcional)').fill('110111');
};

export const openPayment = async (page) => {
  await page.goto(`${WEB_ORIGIN}${PRODUCT_PATH}`);
  await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
  await page.getByTestId('product-checkout-cta').click();
  await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
};

export const reachReview = async (page) => {
  await openPayment(page);
  await fillCard(page);
  await fillCustomerDelivery(page);
  await page.getByTestId('customer-delivery-save').click();
  await expect(page.getByTestId('checkout-step-acceptances')).toBeVisible({ timeout: 5_000 });
  await page.getByLabel(/términos y condiciones/iu).check();
  await page.getByLabel(/tratamiento de mis datos personales/iu).check();
  await page.getByTestId('acceptances-continue').click();
  await expect(page.getByTestId('checkout-step-review')).toBeVisible({ timeout: 5_000 });
};

export const readProgress = (page) =>
  page.evaluate(() => {
    const raw = globalThis.localStorage.getItem('checkout.progress.ids.v1');
    return raw === null ? {} : JSON.parse(raw);
  });

export const countRequests = (page, method, suffix) => {
  let count = 0;
  page.on('request', (request) => {
    if (request.method() === method && new URL(request.url()).pathname.endsWith(suffix)) count += 1;
  });
  return () => count;
};

export const browserJson = async (page, pathname, expectedStatus) => {
  const result = await page.evaluate(async (path_) => {
    const response = await fetch(path_, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(5_000),
    });
    return { status: response.status, body: await response.json() };
  }, pathname);
  check(result.status === expectedStatus, `BROWSER_HTTP_${result.status}`);
  return result.body;
};

export const browserProgressContainsForbiddenData = (page) =>
  page.evaluate(() => {
    const sensitiveAliases = [
      'accesskey',
      'accesstoken',
      'apikey',
      'authorization',
      'bearer',
      'cardholder',
      'cardnumber',
      'clientsecret',
      'credential',
      'cvc',
      'cvv',
      'expiry',
      'hmackey',
      'pan',
      'password',
      'paymentmethodtoken',
      'privatekey',
      'rootkey',
      'securitycode',
      'secret',
      'sessiontoken',
      'token',
    ];
    const maxNestedDepth = 8;
    const keyIsSensitive = (value) => {
      const normalized = value
        .normalize('NFKC')
        .replaceAll(/[^a-z0-9]/giu, '')
        .toLowerCase();
      return sensitiveAliases.some((alias) => normalized.includes(alias));
    };
    const parseNested = (value) => {
      if (typeof value !== 'string') return undefined;
      const trimmed = value.trim();
      if (trimmed[0] !== '"' && trimmed[0] !== '{' && trimmed[0] !== '[') return undefined;
      try {
        const parsed = JSON.parse(trimmed);
        return parsed === value ? undefined : parsed;
      } catch {
        return undefined;
      }
    };
    const containsSensitiveKey = (value, depth = 0) => {
      if (depth > maxNestedDepth) return true;
      if (Array.isArray(value)) {
        return value.some((nested) => containsSensitiveKey(nested, depth + 1));
      }
      if (value !== null && typeof value === 'object') {
        return Object.entries(value).some(
          ([key, nested]) => keyIsSensitive(key) || containsSensitiveKey(nested, depth + 1),
        );
      }
      const nested = parseNested(value);
      return nested === undefined ? false : containsSensitiveKey(nested, depth + 1);
    };
    const values = Object.values(globalThis.localStorage);
    return values.some((raw) => {
      const parsed = parseNested(raw);
      return parsed === undefined ? raw.length > 0 : containsSensitiveKey(parsed, 1);
    });
  });

export const waitForUiState = async (page, testId) => {
  const target = page.getByTestId(testId);
  for (let attempt = 0; attempt < 12; attempt += 1) {
    if (await target.isVisible()) return;
    const refresh = page.getByRole('button', {
      name: /^Consultar estado(?: manualmente)?$/u,
    });
    if ((await refresh.isVisible()) && (await refresh.isEnabled())) await refresh.click();
    await page.waitForTimeout(250);
  }
  throw new UatFailure(`UI_STATE_TIMEOUT_${testId.toUpperCase().replaceAll('-', '_')}`);
};

export const exactBrowserTargets = async () => {
  const { chromium, firefox, webkit } = await import('@playwright/test');
  return [
    { id: 'chromium', browserType: chromium },
    { id: 'firefox', browserType: firefox },
    { id: 'webkit', browserType: webkit },
  ];
};

export const submitPrepared = (session, ready, overrides = {}) =>
  session.request('POST', `/api/v1/checkouts/${ready.checkoutId}/transactions`, {
    headers: {
      'Idempotency-Key': overrides.idempotencyKey ?? `idem-${randomBytes(12).toString('hex')}`,
      'If-Match': ready.etag,
    },
    body: overrides.body ?? ready.body,
  });

const harnessExecutedDirectly =
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (harnessExecutedDirectly && process.argv.includes('--network-canary-self-test')) {
  process.stdout.write(
    'stage-6 UAT external-network observation canary: ' +
      runExternalNetworkObservationCanary() +
      '\n',
  );
}
