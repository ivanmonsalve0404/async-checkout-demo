#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createHash, randomBytes, randomInt } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { chromium, expect } from '@playwright/test';

import {
  serializeSanitizedEvidence,
  writeSanitizedJsonAtomic,
} from '../stage6/lib/artifact-sanitizer.mjs';

const ROOT = process.cwd();
const LOOPBACK_HOST = '127.0.0.1';
let apiOrigin;
let webOrigin;
const PRODUCT_ID = 'product-demo-001';
const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const EVIDENCE_PATH = path.join(
  ROOT,
  'output',
  'evidence',
  'runtime',
  'stage-5-smoke-results.json',
);
const TRACKED_EVIDENCE_PATH = path.join(
  ROOT,
  'output',
  'evidence',
  'stage-5',
  'smoke-results.json',
);
const API_NETWORK_GUARD_PATH = path.join(ROOT, 'scripts', 'smoke', 'deny-external-network.cjs');
const PRODUCT_PATH = `/products/${PRODUCT_ID}`;
const processes = new Set();
const SMOKE_IDS = [
  'SMK-E5-04',
  'SMK-E5-01',
  'SMK-E5-02',
  'SMK-E5-03',
  'SMK-E5-05',
  'SMK-E5-06',
  'SMK-E5-07',
  'SMK-E5-08',
  'SMK-E5-09',
  'SMK-E5-10',
  'SMK-E5-11',
  'SMK-E5-12',
];
let sharedBrowser;

class SmokeFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const check = (condition, code) => {
  if (!condition) throw new SmokeFailure(code);
};

const closeServer = (server) =>
  new Promise((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });

const listenOnLoopback = (server, port) =>
  new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: LOOPBACK_HOST, port }, () => resolve());
  });

const isUsablePort = (value) =>
  typeof value === 'number' && Number.isInteger(value) && value >= 1024 && value <= 65_535;

const configuredPort = (name) => {
  const value = process.env[name];
  if (value === undefined) return undefined;
  const port = Number(value);
  check(isUsablePort(port) && String(port) === value, `${name}_INVALID`);
  return port;
};

const isLoopbackPortAvailable = async (port) => {
  const server = createServer();
  try {
    await listenOnLoopback(server, port);
    return true;
  } catch {
    return false;
  } finally {
    if (server.listening) await closeServer(server);
  }
};

const allocateLoopbackPort = async () => {
  const server = createServer();
  try {
    await listenOnLoopback(server, 0);
    const address = server.address();
    check(
      typeof address === 'object' && address !== null && isUsablePort(address.port),
      'SMOKE_PORT_ALLOCATION_FAILED',
    );
    return address.port;
  } finally {
    if (server.listening) await closeServer(server);
  }
};

const allocateDistinctLoopbackPort = async (excluded) => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const port = await allocateLoopbackPort();
    if (!excluded.has(port)) return port;
  }
  throw new SmokeFailure('SMOKE_PORT_ALLOCATION_COLLISION');
};

const configureOrigins = async () => {
  const configuredApiPort = configuredPort('SMOKE_API_PORT');
  const configuredWebPort = configuredPort('SMOKE_WEB_PORT');
  const apiPort = configuredApiPort ?? (await allocateDistinctLoopbackPort(new Set()));
  const webPort = configuredWebPort ?? (await allocateDistinctLoopbackPort(new Set([apiPort])));
  check(apiPort !== webPort, 'SMOKE_PORTS_MUST_DIFFER');
  if (configuredApiPort !== undefined) {
    check(await isLoopbackPortAvailable(apiPort), 'SMOKE_API_PORT_IN_USE');
  }
  if (configuredWebPort !== undefined) {
    check(await isLoopbackPortAvailable(webPort), 'SMOKE_WEB_PORT_IN_USE');
  }
  apiOrigin = `http://${LOOPBACK_HOST}:${apiPort}`;
  webOrigin = `http://${LOOPBACK_HOST}:${webPort}`;
  return { apiPort, webPort };
};

const runPortAllocationSelfTest = async () => {
  const blocker = createServer();
  await listenOnLoopback(blocker, 0);
  const address = blocker.address();
  check(
    typeof address === 'object' && address !== null && isUsablePort(address.port),
    'SMOKE_PORT_SELF_TEST_SETUP_FAILED',
  );
  const originalApiPort = process.env.SMOKE_API_PORT;
  try {
    process.env.SMOKE_API_PORT = String(address.port);
    let failure;
    try {
      await configureOrigins();
    } catch (error) {
      failure = error;
    }
    check(
      failure instanceof SmokeFailure && failure.code === 'SMOKE_API_PORT_IN_USE',
      'SMOKE_PORT_COLLISION_CANARY_FAILED',
    );
  } finally {
    if (originalApiPort === undefined) {
      delete process.env.SMOKE_API_PORT;
    } else {
      process.env.SMOKE_API_PORT = originalApiPort;
    }
    await closeServer(blocker);
  }
  process.stdout.write('SMOKE_PORT_ALLOCATION_SELF_TEST PASS\n');
};

const within = async (promise, timeoutMs, code) => {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new SmokeFailure(code)), timeoutMs);
  });
  try {
    return await Promise.race([promise, deadline]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
};

const localUrl = (pathname) => {
  check(pathname.startsWith('/api/'), 'NON_API_PATH_REJECTED');
  return `${webOrigin}${pathname}`;
};

const isLoopback = (candidate) => {
  const url = new URL(candidate);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return true;
  return url.hostname === '127.0.0.1' || url.hostname === 'localhost';
};

const start = (executable, arguments_, environment = {}, cwd = ROOT, onStderr) => {
  const child = spawn(executable, arguments_, {
    cwd,
    env: { ...process.env, ...environment },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout?.resume();
  if (onStderr === undefined) {
    child.stderr?.resume();
  } else {
    child.stderr?.on('data', onStderr);
  }
  processes.add(child);
  return child;
};

const stop = async (child) => {
  if (child === undefined) return;
  processes.delete(child);
  if (child.exitCode !== null) return;
  child.kill();
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve();
    }, 3_000);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
  });
};

const stopAll = async () => {
  await Promise.all([...processes].map(stop));
};
const smokeScriptSha256 = async () =>
  createHash('sha256')
    .update(await readFile(process.argv[1]))
    .digest('hex');

const evidenceBase = async (results) => {
  const packageManifest = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8'));
  return {
    schemaVersion: 4,
    environment: 'local-memory-fake-only',
    networkPolicy: 'loopback-only-enforced',
    apiNetworkGuard: 'node-connect-guard',
    browserExternalRequests: results.reduce(
      (total, result) => total + (result.browserExternalRequests ?? 0),
      0,
    ),
    apiExternalRequestsBlocked: results.reduce(
      (total, result) => total + (result.apiExternalRequestsBlocked ?? 0),
      0,
    ),
    networkGuardCanaries: results.every((result) => result.networkGuardCanaries === 'PASS')
      ? 'PASS'
      : 'FAIL',
    providerExternalSmoke: 'NOT_RUN_AUTH_REQUIRED',
    screenshots: 0,
    traces: 0,
    node: process.version,
    packageManager: packageManifest.packageManager,
    smokeScriptSha256: await smokeScriptSha256(),
    exitCode: results.some((result) => result.status !== 'PASS') ? 1 : 0,
    passed: results.filter((result) => result.status === 'PASS').length,
    total: results.length,
  };
};

const writeEvidence = async (results, { closeout = false } = {}) => {
  const base = await evidenceBase(results);
  const runtimeEvidence = {
    ...base,
    executedAt: new Date().toISOString(),
    results,
  };
  await writeSanitizedJsonAtomic(EVIDENCE_PATH, 'stage-5-smoke-results.json', runtimeEvidence);
  if (!closeout) return;

  const ids = results.map(({ id }) => id);
  const exactMatrix =
    ids.length === SMOKE_IDS.length &&
    new Set(ids).size === SMOKE_IDS.length &&
    SMOKE_IDS.every((id) => ids.includes(id));
  check(exactMatrix, 'SMOKE_MATRIX_INCOMPLETE');
  check(base.exitCode === 0, 'SMOKE_MATRIX_FAILED');

  const trackedEvidence = {
    ...base,
    results: results.map((result) => ({ ...result, durationMs: undefined })),
  };
  const serialized = serializeSanitizedEvidence('smoke-results.json', trackedEvidence);
  if (process.argv.includes('--promote')) {
    await writeSanitizedJsonAtomic(TRACKED_EVIDENCE_PATH, 'smoke-results.json', trackedEvidence);
    return;
  }
  let current;
  try {
    current = await readFile(TRACKED_EVIDENCE_PATH, 'utf8');
  } catch {
    throw new SmokeFailure('TRACKED_EVIDENCE_MISSING');
  }
  check(current === serialized, 'TRACKED_EVIDENCE_DRIFT');
};

const waitFor = async (name, child, url, attempts = 100) => {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (child.exitCode !== null) throw new SmokeFailure(`${name.toUpperCase()}_EXITED`);
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) {
        await new Promise((resolve) => setTimeout(resolve, 25));
        if (child.exitCode !== null) throw new SmokeFailure(`${name.toUpperCase()}_EXITED`);
        return;
      }
    } catch {
      // Bounded local startup polling only.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new SmokeFailure(`${name.toUpperCase()}_NOT_READY`);
};

const guardedNodeOptions = () =>
  `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(API_NETWORK_GUARD_PATH).href}`.trim();
const apiEnvironment = (overrides) => ({
  ALLOWED_ORIGIN: webOrigin,
  API_PORT: new URL(apiOrigin).port,
  APP_ENV: 'test',
  CHECKOUT_TTL_SECONDS: '1800',
  DATA_ADAPTER: 'memory',
  FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
  FAKE_RECONCILE_INTERVAL_MS: '10',
  PAYMENT_ADAPTER: 'fake',
  PAYMENTS_ENABLED: 'false',
  NODE_OPTIONS: guardedNodeOptions(),
  PRODUCT_INITIAL_STOCK: '3',
  PUBLIC_ASSET_ORIGIN: webOrigin,
  QUOTE_TTL_SECONDS: '900',
  TOKENIZATION_MODE: 'disabled',
  ...overrides,
});

const captureCapability = (headers, current) => {
  const setCookie = headers['set-cookie'];
  if (setCookie === undefined) return current;
  const capability = /^__Secure-checkout_cap=[^;]+/.exec(setCookie)?.[0];
  check(capability !== undefined, 'CAPABILITY_COOKIE_MALFORMED');
  return capability;
};

const createApiSession = (context, inheritedCapability = () => undefined) => {
  let capability;
  return {
    async request(method, pathname, options = {}) {
      const requestCapability = capability ?? inheritedCapability();
      const response = await context.request.fetch(localUrl(pathname), {
        method,
        timeout: 5_000,
        ...(options.data === undefined ? {} : { data: options.data }),
        headers: {
          Accept: 'application/json',
          Origin: webOrigin,
          'Sec-Fetch-Site': 'same-origin',
          ...(requestCapability === undefined ? {} : { Cookie: requestCapability }),
          ...options.headers,
        },
      });
      capability = captureCapability(response.headers(), capability);
      return response;
    },
  };
};

const responseJson = async (response, expectedStatus, code) => {
  const statuses = Array.isArray(expectedStatus) ? expectedStatus : [expectedStatus];
  check(statuses.includes(response.status()), `${code}_HTTP_STATUS`);
  try {
    return await response.json();
  } catch {
    throw new SmokeFailure(`${code}_INVALID_JSON`);
  }
};

const apiJson = async (session, method, pathname, expectedStatus, options, code) =>
  responseJson(await session.request(method, pathname, options), expectedStatus, code);

const installCapabilityBridge = async (page) => {
  let capability;
  await page.route('**/api/**', async (route) => {
    check(isLoopback(route.request().url()), 'EXTERNAL_API_ROUTE_REJECTED');
    const response = await route.fetch({
      timeout: 5_000,
      headers:
        capability === undefined
          ? route.request().headers()
          : { ...route.request().headers(), cookie: capability },
    });
    capability = captureCapability(response.headers(), capability);
    const requestUrl = new URL(route.request().url());
    if (route.request().method() === 'POST' && requestUrl.pathname === '/api/v1/checkouts') {
      check(capability !== undefined, 'CAPABILITY_COOKIE_MISSING');
    }
    await route.fulfill({ response });
  });
  return () => capability;
};

const browserJson = async (page, pathname, expectedStatus, code) => {
  check(pathname.startsWith('/api/'), 'NON_API_PATH_REJECTED');
  const result = await page.evaluate(async (localPathname) => {
    const response = await fetch(localPathname, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(5_000),
    });
    let body = null;
    try {
      body = await response.json();
    } catch {
      // The outer assertion reports only a sanitized failure code.
    }
    return { status: response.status, body };
  }, pathname);
  check(result.status === expectedStatus, `${code}_HTTP_STATUS`);
  check(result.body !== null, `${code}_INVALID_JSON`);
  return result.body;
};

const randomLetters = (length) =>
  Array.from(randomBytes(length), (value) => String.fromCharCode(65 + (value % 26))).join('');

const passesLuhn = (candidate) => {
  let sum = 0;
  let doubleDigit = false;
  for (let index = candidate.length - 1; index >= 0; index -= 1) {
    const value = Number(candidate[index]) * (doubleDigit ? 2 : 1);
    sum += value > 9 ? value - 9 : value;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
};

const syntheticCard = () => {
  const prefix = `4${Array.from(randomBytes(14), (value) => value % 10).join('')}`;
  const number = Array.from({ length: 10 }, (_, digit) => `${prefix}${digit}`).find(passesLuhn);
  check(number !== undefined, 'CARD_FIXTURE_GENERATION_FAILED');
  const expiryYear = String((new Date().getFullYear() + 1) % 100).padStart(2, '0');
  return {
    number,
    expiry: `12/${expiryYear}`,
    securityCode: String(randomInt(0, 1_000)).padStart(3, '0'),
    holderName: `Persona ${randomLetters(8)}`,
  };
};

const syntheticCustomerDelivery = () => {
  const nonce = randomBytes(7).toString('hex');
  return {
    customer: {
      fullName: `Persona ${randomLetters(8)}`,
      email: `smoke-${nonce}@example.invalid`,
      phone: `+57${String(3_000_000_000 + randomInt(0, 100_000_000))}`,
    },
    delivery: {
      addressLine1: `Calle ${randomInt(1, 100)} Numero ${randomInt(1, 1_000)}`,
      city: 'Ciudad Prueba',
      region: 'Region Prueba',
      postalCode: String(randomInt(100_000, 1_000_000)),
    },
  };
};

const opaque = (prefix, bytes = 18) => `${prefix}_${randomBytes(bytes).toString('base64url')}`;
const etag = (version) => `"checkout-v${version}"`;

const prepareReadyCheckout = async (session) => {
  const created = await apiJson(
    session,
    'POST',
    '/api/v1/checkouts',
    201,
    { data: { productId: PRODUCT_ID } },
    'CREATE_CHECKOUT',
  );
  const fixture = syntheticCustomerDelivery();
  const customer = await apiJson(
    session,
    'PUT',
    `/api/v1/checkouts/${created.checkoutId}/customer`,
    200,
    { data: fixture.customer, headers: { 'If-Match': etag(created.version) } },
    'SAVE_CUSTOMER',
  );
  const delivery = await apiJson(
    session,
    'PUT',
    `/api/v1/checkouts/${created.checkoutId}/delivery-details`,
    200,
    { data: fixture.delivery, headers: { 'If-Match': etag(customer.version) } },
    'SAVE_DELIVERY',
  );
  const configuration = await apiJson(
    session,
    'GET',
    '/api/v1/payment-configuration',
    200,
    {},
    'PAYMENT_CONFIGURATION',
  );
  check(configuration.captureVariant === 'FAKE_CONTRACT', 'FAKE_CAPTURE_NOT_ACTIVE');
  const terms = configuration.acceptanceContracts.find((contract) => contract.type === 'TERMS');
  const personalData = configuration.acceptanceContracts.find(
    (contract) => contract.type === 'PERSONAL_DATA',
  );
  check(terms !== undefined && personalData !== undefined, 'ACCEPTANCE_CONTRACTS_MISSING');
  return {
    checkoutId: created.checkoutId,
    version: delivery.version,
    body: {
      quoteId: created.quote.quoteId,
      paymentMethodToken: opaque('tok_fake'),
      installments: 1,
      acceptances: {
        termsAcceptanceToken: terms.acceptanceToken,
        personalDataAcceptanceToken: personalData.acceptanceToken,
      },
    },
  };
};

const submitPrepared = (session, prepared, idempotencyKey = opaque('idem')) => ({
  idempotencyKey,
  response: session.request('POST', `/api/v1/checkouts/${prepared.checkoutId}/transactions`, {
    data: prepared.body,
    headers: {
      'Idempotency-Key': idempotencyKey,
      'If-Match': etag(prepared.version),
    },
  }),
});

const getTransaction = (session, transactionId) =>
  apiJson(session, 'GET', `/api/v1/transactions/${transactionId}`, 200, {}, 'GET_TRANSACTION');

const waitForTransaction = async (session, transactionId, predicate, code, timeoutMs = 8_000) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const transaction = await getTransaction(session, transactionId);
    if (predicate(transaction)) return transaction;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new SmokeFailure(code);
};

const getStock = (session) =>
  apiJson(session, 'GET', `/api/v1/stock/${PRODUCT_ID}`, 200, {}, 'GET_STOCK');

const fillCard = async (page) => {
  const card = syntheticCard();
  await page.getByLabel('Número de tarjeta').fill(card.number);
  await page.getByLabel('Vencimiento').fill(card.expiry);
  await page.getByLabel('Código de seguridad').fill(card.securityCode);
  await page.getByLabel('Nombre en la tarjeta').fill(card.holderName);
  await page.getByTestId('payment-tokenize').click();
  await expect(page.getByTestId('checkout-step-customer')).toBeVisible({ timeout: 5_000 });
};

const fillCustomerDelivery = async (page, fixture) => {
  await page.getByLabel('Nombre completo').fill(fixture.customer.fullName);
  await page.getByLabel('Correo electrónico').fill(fixture.customer.email);
  await page.getByLabel('Teléfono').fill(fixture.customer.phone);
  await page.getByLabel('Dirección', { exact: true }).fill(fixture.delivery.addressLine1);
  await page.getByLabel('Ciudad').fill(fixture.delivery.city);
  await page.getByLabel('Departamento o región').fill(fixture.delivery.region);
  await page.getByLabel('Código postal (opcional)').fill(fixture.delivery.postalCode);
};

const openCheckoutAtCustomer = async (page) => {
  await page.goto(`${webOrigin}${PRODUCT_PATH}`);
  await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
  await page.getByTestId('product-checkout-cta').click();
  await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
  await fillCard(page);
};

const reachReview = async (page) => {
  await openCheckoutAtCustomer(page);
  const fixture = syntheticCustomerDelivery();
  await fillCustomerDelivery(page, fixture);
  await page.getByTestId('customer-delivery-save').click();
  await expect(page.getByTestId('checkout-step-acceptances')).toBeVisible({ timeout: 5_000 });
  await page.getByLabel(/términos y condiciones/i).check();
  await page.getByLabel(/tratamiento de mis datos personales/i).check();
  await page.getByTestId('acceptances-continue').click();
  await expect(page.getByTestId('checkout-step-review')).toBeVisible({ timeout: 5_000 });
  return fixture;
};

const readProgress = async (page) =>
  page.evaluate(() => {
    const raw = globalThis.localStorage.getItem('checkout.progress.ids.v1');
    if (raw === null) return {};
    const parsed = JSON.parse(raw);
    return {
      checkoutId: typeof parsed.checkoutId === 'string' ? parsed.checkoutId : undefined,
      transactionId: typeof parsed.transactionId === 'string' ? parsed.transactionId : undefined,
    };
  });

const browserTransaction = async (page) => {
  const progress = await readProgress(page);
  check(progress.transactionId !== undefined, 'TRANSACTION_ID_NOT_RECOVERED');
  return browserJson(
    page,
    `/api/v1/transactions/${progress.transactionId}`,
    200,
    'BROWSER_TRANSACTION',
  );
};

const submitUiAndWait = async (page, testId) => {
  await page.getByTestId('checkout-submit').click();
  await expect(page.getByTestId(testId)).toBeVisible({ timeout: 8_000 });
  return browserTransaction(page);
};

const assertFailedPayment = async (page, expectedStatus, testId) => {
  const transaction = await submitUiAndWait(page, testId);
  check(transaction.paymentStatus === expectedStatus, 'FAILED_PAYMENT_STATUS_MISMATCH');
  check(transaction.reservationStatus === 'RELEASED', 'FAILED_RESERVATION_NOT_RELEASED');
  check(transaction.deliveryId === undefined, 'FAILED_PAYMENT_CREATED_DELIVERY');
  const stock = await browserJson(page, `/api/v1/stock/${PRODUCT_ID}`, 200, 'FAILED_STOCK');
  check(stock.available === 1, 'FAILED_PAYMENT_CHANGED_STOCK');
};

const countRequests = (page, method, suffix) => {
  let count = 0;
  page.on('request', (request) => {
    if (request.method() === method && new URL(request.url()).pathname.endsWith(suffix)) count += 1;
  });
  return () => count;
};

const installBrowserNetworkGuard = async (context) => {
  let blocked = 0;
  await context.route('**/*', async (route) => {
    if (isLoopback(route.request().url())) {
      await route.continue();
      return;
    }
    blocked += 1;
    await route.abort('blockedbyclient');
  });
  return () => blocked;
};

const assertBrowserNetworkGuard = async (browser) => {
  const context = await browser.newContext();
  try {
    const blockedRequests = await installBrowserNetworkGuard(context);
    const page = await context.newPage();
    const rejected = await page.evaluate(async () => {
      try {
        await fetch('https://example.invalid/smoke-network-canary');
        return false;
      } catch {
        return true;
      }
    });
    check(rejected && blockedRequests() === 1, 'BROWSER_NETWORK_GUARD_CANARY_FAILED');
  } finally {
    await context.close();
  }
};

const assertApiNetworkGuard = async () => {
  let blockedMarkers = 0;
  const child = start(
    process.execPath,
    ['-e', ''],
    {
      NODE_OPTIONS: guardedNodeOptions(),
      SMOKE_NETWORK_GUARD_CANARY: '1',
    },
    ROOT,
    (chunk) => {
      blockedMarkers += String(chunk).match(/SMOKE_EXTERNAL_NETWORK_BLOCKED/g)?.length ?? 0;
    },
  );
  const exitCode = await within(
    new Promise((resolve) => child.once('exit', (code) => resolve(code ?? 1))),
    5_000,
    'API_NETWORK_GUARD_CANARY_TIMEOUT',
  );
  processes.delete(child);
  check(exitCode === 0 && blockedMarkers === 1, 'API_NETWORK_GUARD_CANARY_FAILED');
};

const run = async () => {
  const { webPort } = await configureOrigins();
  const web = start(
    process.execPath,
    [
      path.join(ROOT, 'apps', 'web', 'node_modules', 'vite', 'bin', 'vite.js'),
      'preview',
      '--host',
      LOOPBACK_HOST,
      '--port',
      String(webPort),
      '--strictPort',
    ],
    { SMOKE_API_PROXY_TARGET: apiOrigin },
    path.join(ROOT, 'apps', 'web'),
  );
  await waitFor('web', web, webOrigin);

  const executablePath =
    process.env.SMOKE_BROWSER_EXECUTABLE ??
    (process.platform === 'win32' && existsSync(EDGE_PATH) ? EDGE_PATH : undefined);
  sharedBrowser = await within(
    chromium.launch({
      headless: true,
      ...(executablePath === undefined ? {} : { executablePath }),
    }),
    10_000,
    'BROWSER_START_TIMEOUT',
  );
  await assertApiNetworkGuard();
  await assertBrowserNetworkGuard(sharedBrowser);
  const results = [];

  const scenario = async (id, title, environment, execute) => {
    if (process.env.SMOKE_ONLY !== undefined && process.env.SMOKE_ONLY !== id) return;
    const startedAt = Date.now();
    let api;
    let context;
    let browserExternalRequests = () => 0;
    let apiExternalRequestsBlocked = 0;
    let checkpoint = 'SETUP';
    try {
      api = start(
        process.execPath,
        [path.join(ROOT, 'apps', 'api', 'dist', 'main.js')],
        apiEnvironment(environment),
        ROOT,
        (chunk) => {
          apiExternalRequestsBlocked +=
            String(chunk).match(/SMOKE_EXTERNAL_NETWORK_BLOCKED/g)?.length ?? 0;
        },
      );
      await waitFor(`api-${id}`, api, `${apiOrigin}/api/health`);
      context = await sharedBrowser.newContext({ viewport: { width: 390, height: 844 } });
      browserExternalRequests = await installBrowserNetworkGuard(context);
      const page = await context.newPage();
      page.setDefaultTimeout(5_000);
      page.setDefaultNavigationTimeout(5_000);
      const browserCapability = await installCapabilityBridge(page);
      await within(
        execute({
          browser: sharedBrowser,
          context,
          page,
          session: createApiSession(context, browserCapability),
          mark(value) {
            checkpoint = value;
          },
        }),
        60_000,
        'SCENARIO_TIMEOUT',
      );
      check(browserExternalRequests() === 0, 'EXTERNAL_NETWORK_REQUEST_DETECTED');
      check(apiExternalRequestsBlocked === 0, 'API_EXTERNAL_NETWORK_REQUEST_BLOCKED');
      results.push({
        id,
        title,
        status: 'PASS',
        durationMs: Date.now() - startedAt,
        browserExternalRequests: browserExternalRequests(),
        apiExternalRequestsBlocked,
        networkGuardCanaries: 'PASS',
      });
      process.stdout.write(`${id} PASS — ${title}\n`);
    } catch (error) {
      const rawFailureCode =
        error instanceof SmokeFailure ? error.code : 'UNEXPECTED_ASSERTION_FAILURE';
      const failureCode =
        rawFailureCode === 'SCENARIO_TIMEOUT' || rawFailureCode === 'UNEXPECTED_ASSERTION_FAILURE'
          ? `${rawFailureCode}_${checkpoint}`
          : rawFailureCode;
      results.push({
        id,
        title,
        status: 'FAIL',
        durationMs: Date.now() - startedAt,
        browserExternalRequests: browserExternalRequests(),
        apiExternalRequestsBlocked,
        networkGuardCanaries: 'PASS',
        failureCode,
      });
      process.stderr.write(`${id} FAIL — ${title}: ${failureCode}\n`);
    } finally {
      if (context !== undefined) {
        await within(context.close(), 3_000, 'CONTEXT_CLOSE_TIMEOUT').catch(() => undefined);
      }
      await stop(api);
    }
  };

  await scenario(
    'SMK-E5-04',
    'pending → volver al producto → recuperar el mismo intento',
    {
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
      FAKE_RECONCILE_INTERVAL_MS: '500',
      PRODUCT_INITIAL_STOCK: '1',
    },
    async ({ page, mark }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      mark('REVIEW');
      await reachReview(page);
      mark('SUBMIT');
      const first = await submitUiAndWait(page, 'transaction-pending');
      check(first.paymentStatus === 'PENDING', 'PENDING_STATUS_MISSING');
      check(first.reservationStatus === 'ACTIVE', 'PENDING_RESERVATION_NOT_ACTIVE');
      mark('READ_PROGRESS');
      const before = await readProgress(page);
      mark('RETURN_TO_PRODUCT');
      await page.getByTestId('return-product').click();
      mark('WAIT_PRODUCT_ROUTE');
      await expect(page).toHaveURL(`${webOrigin}/products/${PRODUCT_ID}`);
      mark('REOPEN');
      await page.getByTestId('product-checkout-cta').click();
      mark('WAIT_STATUS_ROUTE');
      await expect(page).toHaveURL(`${webOrigin}/products/${PRODUCT_ID}/checkout/status`);
      mark('WAIT_PENDING_VISIBLE');
      const pendingRecovered = await page
        .getByTestId('transaction-pending')
        .waitFor({ state: 'visible', timeout: 15_000 })
        .then(
          () => true,
          () => false,
        );
      check(pendingRecovered, 'PENDING_RECOVERY_NOT_VISIBLE');
      mark('READ_RECOVERED_PROGRESS');
      const after = await readProgress(page);
      check(before.checkoutId === after.checkoutId, 'PENDING_RECOVERY_CHANGED_CHECKOUT');
      check(before.transactionId === after.transactionId, 'PENDING_RECOVERY_CHANGED_TRANSACTION');
      mark('CHECK_SINGLE_SUBMISSION');
      check(transactionPosts() === 1, 'PENDING_RECOVERY_DUPLICATED_SUBMISSION');
      mark('READ_HELD_STOCK');
      const stockResponse = await fetch(`${apiOrigin}/api/v1/stock/${PRODUCT_ID}`, {
        headers: { Accept: 'application/json', Origin: webOrigin },
        signal: AbortSignal.timeout(5_000),
      });
      check(stockResponse.status === 200, 'PENDING_STOCK_HTTP_STATUS');
      const stock = await stockResponse.json().catch(() => undefined);
      check(
        stock !== null &&
          typeof stock === 'object' &&
          'available' in stock &&
          Number.isSafeInteger(stock.available),
        'PENDING_STOCK_SCHEMA_INVALID',
      );
      check(stock.available === 0, 'PENDING_RESERVATION_NOT_HELD');
      mark('DONE');
    },
  );
  await scenario(
    'SMK-E5-01',
    'producto → checkout → aprobado → stock actualizado',
    { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01', PRODUCT_INITIAL_STOCK: '3' },
    async ({ page }) => {
      await reachReview(page);
      const transaction = await submitUiAndWait(page, 'transaction-approved');
      check(transaction.paymentStatus === 'APPROVED', 'APPROVED_STATUS_MISSING');
      check(transaction.reservationStatus === 'CONSUMED', 'APPROVED_STOCK_NOT_CONSUMED');
      check(transaction.deliveryId !== undefined, 'APPROVED_DELIVERY_MISSING');
      const delivery = await browserJson(
        page,
        `/api/v1/deliveries/${transaction.deliveryId}`,
        200,
        'APPROVED_DELIVERY',
      );
      check(delivery.transactionId === transaction.transactionId, 'APPROVED_DELIVERY_MISMATCH');
      await page.getByTestId('return-product').click();
      await expect(page.getByText('2 unidades disponibles')).toBeVisible({ timeout: 5_000 });
    },
  );

  await scenario(
    'SMK-E5-02',
    'declinado → reserva liberada → sin entrega',
    { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-02', PRODUCT_INITIAL_STOCK: '1' },
    async ({ page }) => {
      await reachReview(page);
      await assertFailedPayment(page, 'DECLINED', 'transaction-declined');
    },
  );

  await scenario(
    'SMK-E5-03',
    'error final → reserva liberada → sin entrega',
    { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-03', PRODUCT_INITIAL_STOCK: '1' },
    async ({ page }) => {
      await reachReview(page);
      await assertFailedPayment(page, 'ERROR', 'transaction-error');
    },
  );

  await scenario(
    'SMK-E5-05',
    'refresh en datos de entrega',
    { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04', PRODUCT_INITIAL_STOCK: '1' },
    async ({ page }) => {
      await openCheckoutAtCustomer(page);
      const fixture = syntheticCustomerDelivery();
      await fillCustomerDelivery(page, fixture);
      await page.getByTestId('customer-delivery-save').click();
      await expect(page.getByTestId('checkout-step-acceptances')).toBeVisible({ timeout: 5_000 });
      const before = await readProgress(page);
      await page.reload();
      await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
      await fillCard(page);
      check(
        (await page.getByLabel('Nombre completo').inputValue()) === fixture.customer.fullName,
        'CUSTOMER_NOT_RECOVERED',
      );
      check(
        (await page.getByLabel('Correo electrónico').inputValue()) === fixture.customer.email,
        'CUSTOMER_EMAIL_NOT_RECOVERED',
      );
      check(
        (await page.getByLabel('Dirección', { exact: true }).inputValue()) ===
          fixture.delivery.addressLine1,
        'DELIVERY_NOT_RECOVERED',
      );
      const after = await readProgress(page);
      check(before.checkoutId === after.checkoutId, 'DELIVERY_REFRESH_CHANGED_CHECKOUT');
    },
  );

  await scenario(
    'SMK-E5-06',
    'refresh durante pago pendiente',
    { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04', PRODUCT_INITIAL_STOCK: '1' },
    async ({ page, session, mark }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      mark('REVIEW');
      await reachReview(page);
      mark('SUBMIT');
      await submitUiAndWait(page, 'transaction-pending');
      mark('READ_BEFORE_REFRESH');
      const before = await readProgress(page);
      mark('RELOAD');
      await page.reload();
      mark('WAIT_RECOVERED_STATUS');
      await expect(page.getByTestId('transaction-pending')).toBeVisible({ timeout: 5_000 });
      check(before.transactionId !== undefined, 'PENDING_REFRESH_ID_MISSING');
      check(transactionPosts() === 1, 'PENDING_REFRESH_DUPLICATED_SUBMISSION');
      mark('READ_CANONICAL_TRANSACTION');
      const transaction = await getTransaction(session, before.transactionId);
      check(transaction.paymentStatus === 'PENDING', 'PENDING_REFRESH_STATUS_CHANGED');
      check(transaction.reservationStatus === 'ACTIVE', 'PENDING_REFRESH_RELEASED_RESERVATION');
      mark('DONE');
    },
  );

  await scenario(
    'SMK-E5-07',
    'doble clic → una transacción lógica',
    { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04', PRODUCT_INITIAL_STOCK: '1' },
    async ({ page, session, mark }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      mark('REVIEW');
      await reachReview(page);
      const before = await readProgress(page);
      check(before.checkoutId !== undefined, 'DOUBLE_SUBMIT_CHECKOUT_ID_MISSING');
      const prepared = { checkoutId: before.checkoutId };
      const acceptedResponse = page.waitForResponse(
        (response) =>
          response.request().method() === 'POST' &&
          new URL(response.url()).pathname.endsWith('/transactions'),
      );

      mark('DOUBLE_CLICK');
      await page.getByTestId('checkout-submit').dblclick();
      const accepted = await responseJson(await acceptedResponse, 202, 'DOUBLE_SUBMIT_UI_RESPONSE');
      await expect(page.getByTestId('transaction-pending')).toBeVisible({ timeout: 8_000 });

      const after = await readProgress(page);
      check(transactionPosts() === 1, 'DOUBLE_SUBMIT_SENT_MULTIPLE_POSTS');
      check(after.transactionId === accepted.transactionId, 'DOUBLE_SUBMIT_PROGRESS_ID_MISMATCH');
      const transaction = await browserTransaction(page);
      check(
        transaction.transactionId === accepted.transactionId,
        'DOUBLE_SUBMIT_CANONICAL_ID_MISMATCH',
      );
      check(transaction.reservationStatus === 'ACTIVE', 'DOUBLE_SUBMIT_RESERVATION_INVALID');
      const checkout = await apiJson(
        session,
        'GET',
        `/api/v1/checkouts/${prepared.checkoutId}`,
        200,
        {},
        'DOUBLE_SUBMIT_CHECKOUT',
      );
      check(
        checkout.activeTransactionId === accepted.transactionId,
        'DOUBLE_SUBMIT_ACTIVE_ID_MISMATCH',
      );
      const stock = await getStock(session);
      check(stock.available === 0, 'DOUBLE_SUBMIT_RESERVED_MORE_THAN_ONCE');
      mark('DONE');
    },
  );

  await scenario(
    'SMK-E5-08',
    'dos requests concurrentes contra último stock',
    { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01', PRODUCT_INITIAL_STOCK: '1' },
    async ({ browser, session }) => {
      const secondContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
      try {
        const secondSession = createApiSession(secondContext);
        const [firstPrepared, secondPrepared] = await Promise.all([
          prepareReadyCheckout(session),
          prepareReadyCheckout(secondSession),
        ]);
        const [firstResponse, secondResponse] = await Promise.all([
          submitPrepared(session, firstPrepared).response,
          submitPrepared(secondSession, secondPrepared).response,
        ]);
        const outcomes = [
          { session, prepared: firstPrepared, response: firstResponse },
          { session: secondSession, prepared: secondPrepared, response: secondResponse },
        ];
        const accepted = outcomes.filter(({ response }) => response.status() === 202);
        const rejected = outcomes.filter(({ response }) => response.status() === 409);
        check(accepted.length === 1 && rejected.length === 1, 'LAST_STOCK_NOT_EXCLUSIVE');
        const winner = accepted[0];
        const loser = rejected[0];
        const acceptedBody = await responseJson(winner.response, 202, 'LAST_STOCK_WINNER');
        const problem = await responseJson(loser.response, 409, 'LAST_STOCK_LOSER');
        check(problem.code === 'OUT_OF_STOCK', 'LAST_STOCK_WRONG_CONFLICT');
        const final = await waitForTransaction(
          winner.session,
          acceptedBody.transactionId,
          (transaction) => transaction.paymentStatus === 'APPROVED',
          'LAST_STOCK_WINNER_NOT_APPROVED',
        );
        check(final.reservationStatus === 'CONSUMED', 'LAST_STOCK_WINNER_NOT_CONSUMED');
        const losingCheckout = await apiJson(
          loser.session,
          'GET',
          `/api/v1/checkouts/${loser.prepared.checkoutId}`,
          200,
          {},
          'LAST_STOCK_LOSER_CHECKOUT',
        );
        check(
          losingCheckout.status === 'READY' && losingCheckout.activeTransactionId === null,
          'LAST_STOCK_LOSER_MUTATED',
        );
        const stock = await getStock(winner.session);
        check(stock.available === 0, 'LAST_STOCK_BECAME_INVALID');
      } finally {
        await secondContext.close();
      }
    },
  );

  await scenario(
    'SMK-E5-09',
    'quote vencido/reprecio',
    {
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
      PRODUCT_INITIAL_STOCK: '1',
      QUOTE_TTL_SECONDS: '0',
    },
    async ({ page }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      const checkoutPosts = countRequests(page, 'POST', '/checkouts');
      await reachReview(page);
      await expect(page.getByTestId('smk-e5-09-quote-stale')).toBeVisible({ timeout: 5_000 });
      const before = await readProgress(page);
      await page.getByRole('button', { name: 'Actualizar total' }).click();
      await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
      await page.getByTestId('product-checkout-cta').click();
      await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
      const after = await readProgress(page);
      check(before.checkoutId !== after.checkoutId, 'REPRICE_REUSED_EXPIRED_CHECKOUT');
      check(checkoutPosts() === 2, 'REPRICE_DID_NOT_CREATE_NEW_QUOTE');
      check(transactionPosts() === 0, 'EXPIRED_QUOTE_SUBMITTED_PAYMENT');
      const stock = await browserJson(page, `/api/v1/stock/${PRODUCT_ID}`, 200, 'REPRICE_STOCK');
      check(stock.available === 1, 'REPRICE_CHANGED_STOCK');
    },
  );

  await scenario(
    'SMK-E5-10',
    'sesión expirada',
    {
      CHECKOUT_TTL_SECONDS: '0',
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
      PRODUCT_INITIAL_STOCK: '1',
    },
    async ({ page }) => {
      const transactionPosts = countRequests(page, 'POST', '/transactions');
      await page.goto(`${webOrigin}${PRODUCT_PATH}`);
      await page.getByTestId('product-checkout-cta').click();
      await expect(page.getByTestId('checkout-expired')).toBeVisible({ timeout: 5_000 });
      check(transactionPosts() === 0, 'EXPIRED_SESSION_SUBMITTED_PAYMENT');
      const progress = await readProgress(page);
      check(progress.checkoutId === undefined, 'EXPIRED_SESSION_WAS_PERSISTED');
      const stock = await browserJson(page, `/api/v1/stock/${PRODUCT_ID}`, 200, 'EXPIRED_STOCK');
      check(stock.available === 1, 'EXPIRED_SESSION_CHANGED_STOCK');
    },
  );

  await scenario(
    'SMK-E5-11',
    'respuesta externa divergente bloqueada',
    { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-08', PRODUCT_INITIAL_STOCK: '1' },
    async ({ page }) => {
      await reachReview(page);
      const transaction = await submitUiAndWait(page, 'transaction-unknown');
      check(transaction.paymentStatus === 'PENDING', 'DIVERGENT_RESULT_BECAME_FINAL');
      check(transaction.dispatchPhase === 'UNKNOWN', 'DIVERGENT_RESULT_NOT_QUARANTINED');
      check(transaction.reservationStatus === 'ACTIVE', 'DIVERGENT_RESULT_RELEASED_RESERVATION');
      check(transaction.deliveryId === undefined, 'DIVERGENT_RESULT_CREATED_DELIVERY');
      const stock = await browserJson(page, `/api/v1/stock/${PRODUCT_ID}`, 200, 'DIVERGENT_STOCK');
      check(stock.available === 0, 'DIVERGENT_RESULT_DID_NOT_HOLD_RESERVATION');
    },
  );

  await scenario(
    'SMK-E5-12',
    'replay de finalización sin efectos duplicados',
    { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-10', PRODUCT_INITIAL_STOCK: '2' },
    async ({ session }) => {
      const prepared = await prepareReadyCheckout(session);
      const idempotencyKey = opaque('idem');
      const firstResponse = await submitPrepared(session, prepared, idempotencyKey).response;
      const firstBody = await responseJson(firstResponse, 202, 'FINAL_REPLAY_FIRST');
      const finalized = await waitForTransaction(
        session,
        firstBody.transactionId,
        (transaction) => transaction.paymentStatus === 'APPROVED',
        'FINAL_REPLAY_NOT_APPROVED',
      );
      check(finalized.deliveryId !== undefined, 'FINAL_REPLAY_DELIVERY_MISSING');
      const firstStock = await getStock(session);
      const firstDelivery = await apiJson(
        session,
        'GET',
        `/api/v1/deliveries/${finalized.deliveryId}`,
        200,
        {},
        'FINAL_REPLAY_FIRST_DELIVERY',
      );
      const replayResponse = await submitPrepared(session, prepared, idempotencyKey).response;
      const replayBody = await responseJson(replayResponse, 202, 'FINAL_REPLAY_RESPONSE');
      check(
        replayBody.transactionId === firstBody.transactionId,
        'FINAL_REPLAY_CREATED_NEW_TRANSACTION',
      );
      const replayed = await getTransaction(session, firstBody.transactionId);
      const secondStock = await getStock(session);
      const secondDelivery = await apiJson(
        session,
        'GET',
        `/api/v1/deliveries/${finalized.deliveryId}`,
        200,
        {},
        'FINAL_REPLAY_SECOND_DELIVERY',
      );
      check(firstStock.available === 1 && secondStock.available === 1, 'FINAL_REPLAY_DOUBLE_STOCK');
      check(replayed.reservationStatus === 'CONSUMED', 'FINAL_REPLAY_RESERVATION_CHANGED');
      check(replayed.updatedAt === finalized.updatedAt, 'FINAL_REPLAY_MUTATED_FINAL_STATE');
      check(
        firstDelivery.deliveryId === secondDelivery.deliveryId &&
          firstDelivery.createdAt === secondDelivery.createdAt,
        'FINAL_REPLAY_DUPLICATED_DELIVERY',
      );
    },
  );

  await writeEvidence(results);
  if (results.some((result) => result.status !== 'PASS')) process.exitCode = 1;
};

const runWorker = async (id) => {
  const child = start(process.execPath, [process.argv[1]], {
    SMOKE_ONLY: id,
    SMOKE_WORKER: '1',
  });
  let exitCode;
  try {
    exitCode = await within(
      new Promise((resolve) => {
        child.once('exit', (code) => resolve(code ?? 1));
      }),
      90_000,
      `${id}_WORKER_TIMEOUT`,
    );
  } catch {
    await stop(child);
    return {
      id,
      title: id,
      status: 'FAIL',
      durationMs: 90_000,
      failureCode: 'WORKER_TIMEOUT',
    };
  } finally {
    processes.delete(child);
  }

  try {
    const evidence = JSON.parse(await readFile(EVIDENCE_PATH, 'utf8'));
    const result = Array.isArray(evidence.results)
      ? evidence.results.find((candidate) => candidate?.id === id)
      : undefined;
    if (result !== undefined) {
      return exitCode === 0 || result.status === 'FAIL'
        ? result
        : { ...result, status: 'FAIL', failureCode: 'WORKER_EXITED' };
    }
  } catch {
    // A missing or malformed worker artifact becomes a sanitized failure below.
  }

  return {
    id,
    title: id,
    status: 'FAIL',
    durationMs: 0,
    failureCode: 'WORKER_EVIDENCE_MISSING',
  };
};

const runIsolatedMatrix = async () => {
  const results = [];
  for (const id of SMOKE_IDS) {
    const result = await runWorker(id);
    results.push(result);
    const output = result.status === 'PASS' ? process.stdout : process.stderr;
    output.write(`${id} ${result.status} — ${result.title}\n`);
  }
  results.sort((left, right) => left.id.localeCompare(right.id));
  await writeEvidence(results, { closeout: true });
  if (results.some((result) => result.status !== 'PASS')) process.exitCode = 1;
};

try {
  if (process.argv.includes('--self-test')) {
    await runPortAllocationSelfTest();
  } else if (process.env.SMOKE_WORKER === '1' || process.env.SMOKE_ONLY !== undefined) {
    await run();
  } else {
    await runIsolatedMatrix();
  }
} finally {
  if (sharedBrowser !== undefined) {
    await within(sharedBrowser.close(), 5_000, 'BROWSER_CLOSE_TIMEOUT').catch(() => undefined);
  }
  await stopAll();
}
