/* global localStorage, sessionStorage, structuredClone */

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import process from 'node:process';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const OPAQUE_ID = /^[A-Za-z0-9_-]{8,128}$/u;
const PRODUCT_ID = 'product-demo-001';
const SANDBOX_ORIGIN = 'https://sandbox.wompi.co';
const CASES = Object.freeze([
  ['SMK-E7-01', 'Abrir SPA por HTTPS'],
  ['SMK-E7-02', 'Deep link autorizado'],
  ['SMK-E7-03', 'Obtener producto y stock'],
  ['SMK-E7-04', 'Abrir checkout accesible'],
  ['SMK-E7-05', 'Validar tarjeta sintética'],
  ['SMK-E7-06', 'Guardar cliente y entrega'],
  ['SMK-E7-07', 'Obtener quote server-side'],
  ['SMK-E7-08', 'Aceptar contratos vigentes'],
  ['SMK-E7-09', 'Crear transacción local PENDING'],
  ['SMK-E7-10', 'Confirmar pago aprobado autorizado'],
  ['SMK-E7-11', 'Aplicar stock y entrega una vez'],
  ['SMK-E7-12', 'Declined o error sin efectos'],
  ['SMK-E7-13', 'Recuperar progreso antes del pago'],
  ['SMK-E7-14', 'Recuperar transacción PENDING'],
  ['SMK-E7-15', 'Bloquear doble clic y replay'],
  ['SMK-E7-16', 'Volver al producto actualizado'],
  ['SMK-E7-17', 'Publicar API docs sanitizados'],
  ['SMK-E7-18', 'Responder error controlado observable'],
]);

export class Stage7SmokeError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7SmokeError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7SmokeError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, expected) =>
  object(value) && Object.keys(value).toSorted().join('\0') === expected.toSorted().join('\0');
const utc = (value) =>
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
  !Number.isNaN(Date.parse(value)) &&
  new Date(value).toISOString() === value;

const luhn = (value) => {
  let sum = 0;
  let doubled = false;
  for (let index = value.length - 1; index >= 0; index -= 1) {
    const digit = Number(value[index]) * (doubled ? 2 : 1);
    sum += digit > 9 ? digit - 9 : digit;
    doubled = !doubled;
  }
  return sum % 10 === 0;
};

const validExpiry = (value, now) => {
  const match = /^(0[1-9]|1[0-2])\/([0-9]{2})$/u.exec(value ?? '');
  if (match === null) return false;
  const month = Number(match[1]);
  const year = 2000 + Number(match[2]);
  return Date.UTC(year, month, 1) > now.getTime();
};

const validateCard = (card, now, { failed = false } = {}) => {
  const expected = ['number', 'expiry', 'securityCode', 'holderName'];
  if (failed) expected.push('expectedStatus');
  if (
    !exactKeys(card, expected) ||
    !/^[0-9]{13,19}$/u.test(card.number ?? '') ||
    !luhn(card.number) ||
    !validExpiry(card.expiry, now) ||
    !/^[0-9]{3,4}$/u.test(card.securityCode ?? '') ||
    !/^[\p{L}\p{M} .'-]{2,80}$/u.test(card.holderName ?? '') ||
    (failed && !['DECLINED', 'ERROR'].includes(card.expectedStatus))
  ) {
    fail('E7_SMOKE_PRIVATE_CARD_INVALID');
  }
};

export const validatePrivateSmokeInputs = ({
  value,
  candidateSha,
  releaseId,
  configSha256,
  now = new Date(),
}) => {
  if (
    !exactKeys(value, [
      'schemaId',
      'schemaVersion',
      'stage',
      'classification',
      'sandboxOnly',
      'providerHost',
      'candidateSha',
      'releaseId',
      'stage7ConfigSha256',
      'cards',
      'containsSensitiveData',
    ]) ||
    value.schemaId !== 'async-checkout-stage7-private-smoke-inputs' ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.classification !== 'SYNTHETIC_TEST_PAYMENT_DATA' ||
    value.sandboxOnly !== true ||
    value.providerHost !== 'sandbox.wompi.co' ||
    value.candidateSha !== candidateSha ||
    value.releaseId !== releaseId ||
    value.stage7ConfigSha256 !== configSha256 ||
    value.containsSensitiveData !== true ||
    !exactKeys(value.cards, ['approved', 'failed', 'pending'])
  ) {
    fail('E7_SMOKE_PRIVATE_INPUT_ENVELOPE_INVALID');
  }
  validateCard(value.cards.approved, now);
  validateCard(value.cards.failed, now, { failed: true });
  validateCard(value.cards.pending, now, { failed: true });
  if (new Set(Object.values(value.cards).map(({ number }) => number)).size !== 3) {
    fail('E7_SMOKE_PRIVATE_CARD_SCENARIOS_NOT_DISTINCT');
  }
  return value;
};

export const readPrivateSmokeInputs = ({ candidateSha, releaseId, configSha256, now }) => {
  const filename = process.env.STAGE7_SMOKE_INPUTS;
  if (typeof filename !== 'string' || filename.trim() === '') {
    fail('E7_SMOKE_PRIVATE_INPUT_REQUIRED');
  }
  let stat;
  try {
    stat = lstatSync(filename);
  } catch {
    fail('E7_SMOKE_PRIVATE_INPUT_REQUIRED');
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 64 * 1024) {
    fail('E7_SMOKE_PRIVATE_INPUT_FILE_INVALID');
  }
  if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
    fail('E7_SMOKE_PRIVATE_INPUT_PERMISSIONS_INVALID');
  }
  let value;
  try {
    value = parseStrictJsonSource(readFileSync(filename), { scanForbiddenData: false });
  } catch {
    fail('E7_SMOKE_PRIVATE_INPUT_FILE_INVALID');
  }
  return validatePrivateSmokeInputs({ value, candidateSha, releaseId, configSha256, now });
};

const safeOrigin = (value) => {
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== 'https:' ||
      parsed.origin !== value ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) {
      fail('E7_SMOKE_ORIGIN_INVALID');
    }
    return parsed.origin;
  } catch (error) {
    if (error instanceof Stage7SmokeError) throw error;
    fail('E7_SMOKE_ORIGIN_INVALID');
  }
};

const bodyJson = async (response, code) => {
  const source = await response.text();
  if (source.length < 2 || source.length > 2 * 1024 * 1024) fail(code);
  try {
    return JSON.parse(source);
  } catch {
    fail(code);
  }
};

const pageJson = async (page, pathname, { method = 'GET', body, headers = {} } = {}) => {
  const result = await page.evaluate(
    async ({
      pathname: requestedPath,
      method: requestedMethod,
      body: requestedBody,
      headers: requestedHeaders,
    }) => {
      const response = await fetch(requestedPath, {
        method: requestedMethod,
        credentials: 'include',
        redirect: 'error',
        headers: {
          Accept: 'application/json',
          ...(requestedBody === undefined ? {} : { 'Content-Type': 'application/json' }),
          ...requestedHeaders,
        },
        ...(requestedBody === undefined ? {} : { body: JSON.stringify(requestedBody) }),
      });
      const text = await response.text();
      let parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        // Caller treats a non-JSON body as a failed oracle.
      }
      return {
        status: response.status,
        body: parsed,
        headers: {
          etag: response.headers.get('etag'),
          location: response.headers.get('location'),
          correlationId: response.headers.get('x-correlation-id'),
          cacheControl: response.headers.get('cache-control'),
        },
      };
    },
    { pathname, method, body, headers },
  );
  return result;
};

const exactHealthResponse = (response, expectedStatus) =>
  response.status === 200 &&
  exactKeys(response.body, ['status', 'checkedAt']) &&
  response.body.status === expectedStatus &&
  utc(response.body.checkedAt) &&
  /^[0-9a-f-]{36}$/u.test(response.headers.correlationId ?? '') &&
  /^no-store(?:,|$)/iu.test(response.headers.cacheControl ?? '');

const syntheticCustomer = () => {
  const nonce = randomBytes(8).toString('hex');
  return {
    customer: {
      fullName: 'Persona Sintetica',
      email: `stage7-${nonce}@example.invalid`,
      phone: '+573001234567',
    },
    delivery: {
      addressLine1: 'Calle sintetica 100',
      city: 'Bogota',
      region: 'Cundinamarca',
      postalCode: '110111',
    },
  };
};

const readProgress = (page) =>
  page.evaluate(() => {
    const raw = globalThis.localStorage.getItem('checkout.progress.ids.v1');
    if (raw === null) return {};
    const parsed = JSON.parse(raw);
    return {
      checkoutId: typeof parsed.checkoutId === 'string' ? parsed.checkoutId : undefined,
      transactionId: typeof parsed.transactionId === 'string' ? parsed.transactionId : undefined,
    };
  });

const fillCard = async (page, card) => {
  await page.getByLabel('Número de tarjeta').fill(card.number);
  await page.getByLabel('Vencimiento').fill(card.expiry);
  await page.getByLabel('Código de seguridad').fill(card.securityCode);
  await page.getByLabel('Nombre en la tarjeta').fill(card.holderName);
};

const fillCustomer = async (page, fixture) => {
  await page.getByLabel('Nombre completo').fill(fixture.customer.fullName);
  await page.getByLabel('Correo electrónico').fill(fixture.customer.email);
  await page.getByLabel('Teléfono').fill(fixture.customer.phone);
  await page.getByLabel('Dirección', { exact: true }).fill(fixture.delivery.addressLine1);
  await page.getByLabel('Ciudad').fill(fixture.delivery.city);
  await page.getByLabel('Departamento o región').fill(fixture.delivery.region);
  await page.getByLabel('Código postal (opcional)').fill(fixture.delivery.postalCode);
};

const openCheckout = async (page, origin) => {
  await page.goto(`${origin}/products/${PRODUCT_ID}`, { waitUntil: 'domcontentloaded' });
  await page.getByTestId('product-surface').waitFor({ state: 'visible' });
  await page.getByTestId('product-checkout-cta').click();
  await page.getByTestId('checkout-step-payment').waitFor({ state: 'visible' });
};

const reachReview = async (page, origin, card, fixture = syntheticCustomer()) => {
  await openCheckout(page, origin);
  await fillCard(page, card);
  await page.getByTestId('payment-tokenize').click();
  await page.getByTestId('checkout-step-customer').waitFor({ state: 'visible', timeout: 15_000 });
  await fillCustomer(page, fixture);
  await page.getByTestId('customer-delivery-save').click();
  await page.getByTestId('checkout-step-acceptances').waitFor({ state: 'visible' });
  await page.getByLabel(/términos y condiciones/iu).check();
  await page.getByLabel(/tratamiento de mis datos personales/iu).check();
  await page.getByTestId('acceptances-continue').click();
  await page.getByTestId('checkout-step-review').waitFor({ state: 'visible' });
  return fixture;
};

const waitTransaction = async (page, transactionId, predicate, timeoutMs = 90_000) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await pageJson(page, `/api/v1/transactions/${transactionId}`);
    if (result.status === 200 && predicate(result.body)) return result.body;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  fail('E7_SMOKE_TRANSACTION_TIMEOUT');
};

const exactQuote = (quote) => {
  const money = (value) =>
    object(value) &&
    value.currency === 'COP' &&
    Number.isSafeInteger(value.amountInCents) &&
    value.amountInCents >= 0;
  return (
    object(quote) &&
    OPAQUE_ID.test(quote.quoteId ?? '') &&
    money(quote.subtotal) &&
    money(quote.baseFee) &&
    money(quote.deliveryFee) &&
    money(quote.total) &&
    quote.total.amountInCents ===
      quote.subtotal.amountInCents +
        quote.baseFee.amountInCents +
        quote.deliveryFee.amountInCents &&
    utc(quote.expiresAt)
  );
};

const canonicalResult = (id, oracle, pathname = `/products/${PRODUCT_ID}`) => ({
  id,
  name: CASES.find(([candidate]) => candidate === id)?.[1],
  status: 'PASS',
  executedAtUtc: new Date().toISOString(),
  normalizedPath: pathname,
  browser: 'chromium',
  device: 'desktop-1280x800',
  inputClass: 'SYNTHETIC_TEST_DATA',
  oracle,
});

export const validateCanonicalSmokeResults = (results) => {
  if (
    !Array.isArray(results) ||
    results.length !== CASES.length ||
    results.map(({ id }) => id).join('\0') !== CASES.map(([id]) => id).join('\0')
  ) {
    fail('E7_SMOKE_MATRIX_INCOMPLETE');
  }
  for (const [index, result] of results.entries()) {
    const [id, name] = CASES[index];
    if (
      !exactKeys(result, [
        'id',
        'name',
        'status',
        'executedAtUtc',
        'normalizedPath',
        'browser',
        'device',
        'inputClass',
        'oracle',
      ]) ||
      result.id !== id ||
      result.name !== name ||
      result.status !== 'PASS' ||
      !utc(result.executedAtUtc) ||
      typeof result.normalizedPath !== 'string' ||
      !result.normalizedPath.startsWith('/') ||
      result.normalizedPath.includes('?') ||
      result.browser !== 'chromium' ||
      result.device !== 'desktop-1280x800' ||
      result.inputClass !== 'SYNTHETIC_TEST_DATA' ||
      !object(result.oracle) ||
      result.oracle.decision !== 'PASS'
    ) {
      fail('E7_SMOKE_CASE_INVALID');
    }
  }
  return results;
};

export const runCanonicalStage7Smoke = async ({
  origin: requestedOrigin,
  candidateSha,
  releaseId,
  configSha256,
  authorization,
  now = new Date(),
  privateInputs,
  playwright,
}) => {
  const origin = safeOrigin(requestedOrigin);
  if (
    !SHA.test(candidateSha ?? '') ||
    !SHA256.test(configSha256 ?? '') ||
    typeof releaseId !== 'string'
  ) {
    fail('E7_SMOKE_IDENTITY_INVALID');
  }
  const inputs = validatePrivateSmokeInputs({
    value: privateInputs ?? readPrivateSmokeInputs({ candidateSha, releaseId, configSha256, now }),
    candidateSha,
    releaseId,
    configSha256,
    now,
  });
  if (
    authorization?.ownedTarget?.status !== 'APPROVED' ||
    authorization?.sandboxSmoke?.status !== 'APPROVED' ||
    authorization.ownedTarget.approvedTargetSha256 ===
      authorization.sandboxSmoke.approvedTargetSha256
  ) {
    fail('E7_SMOKE_EXTERNAL_AUTHORIZATION_INVALID');
  }
  const runtime = playwright ?? (await import('@playwright/test'));
  const browser = await runtime.chromium.launch({ headless: true });
  let context;
  const requests = { ownedOrigin: 0, sandbox: 0, outsideAllowlist: 0, mutations: 0 };
  const critical = { console: 0, page: 0, network: 0 };
  try {
    context = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      locale: 'es-CO',
      timezoneId: 'America/Bogota',
      serviceWorkers: 'block',
    });
    await context.route('**/*', async (route) => {
      let requestOrigin;
      try {
        requestOrigin = new URL(route.request().url()).origin;
      } catch {
        requests.outsideAllowlist += 1;
        await route.abort('blockedbyclient');
        return;
      }
      if (requestOrigin === origin) {
        requests.ownedOrigin += 1;
        if (!['GET', 'HEAD', 'OPTIONS'].includes(route.request().method())) {
          requests.mutations += 1;
        }
      } else if (requestOrigin === SANDBOX_ORIGIN) requests.sandbox += 1;
      else {
        requests.outsideAllowlist += 1;
        await route.abort('blockedbyclient');
        return;
      }
      await route.continue();
    });
    const page = await context.newPage();
    page.on('console', (message) => {
      if (message.type() === 'error') critical.console += 1;
    });
    page.on('pageerror', () => {
      critical.page += 1;
    });
    page.on('requestfailed', (request) => {
      try {
        if ([origin, SANDBOX_ORIGIN].includes(new URL(request.url()).origin)) critical.network += 1;
      } catch {
        critical.network += 1;
      }
    });

    const resultsById = new Map();
    const mark = (id, facts, pathname) => {
      if (!object(facts) || Object.values(facts).some((value) => value === false)) {
        fail(`E7_${id.replaceAll('-', '_')}_ORACLE_FAILED`);
      }
      if (!CASES.some(([caseId]) => caseId === id) || resultsById.has(id)) {
        fail('E7_SMOKE_MATRIX_DUPLICATE_OR_UNKNOWN_CASE');
      }
      resultsById.set(id, canonicalResult(id, { decision: 'PASS', ...facts }, pathname));
    };

    const root = await page.goto(`${origin}/`, { waitUntil: 'domcontentloaded' });
    const [liveness, readiness] = await Promise.all([
      pageJson(page, '/api/health/live'),
      pageJson(page, '/api/health/ready'),
    ]);
    mark(
      'SMK-E7-01',
      {
        https: page.url().startsWith('https://'),
        status200: root?.status() === 200,
        rendered: await page.locator('body').isVisible(),
        livenessContract: exactHealthResponse(liveness, 'alive'),
        readinessContract: exactHealthResponse(readiness, 'ok'),
      },
      '/',
    );

    const productResponse = await page.goto(`${origin}/products/${PRODUCT_ID}`, {
      waitUntil: 'domcontentloaded',
    });
    mark('SMK-E7-02', {
      status200: productResponse?.status() === 200,
      productSurface: await page.getByTestId('product-surface').isVisible(),
    });
    const [product, stockBefore] = await Promise.all([
      pageJson(page, `/api/v1/products/${PRODUCT_ID}`),
      pageJson(page, `/api/v1/stock/${PRODUCT_ID}`),
    ]);
    mark(
      'SMK-E7-03',
      {
        productStatus200: product.status === 200,
        productIdExact: product.body?.productId === PRODUCT_ID,
        stockStatus200: stockBefore.status === 200,
        stockNonNegative:
          Number.isSafeInteger(stockBefore.body?.available) && stockBefore.body.available >= 2,
      },
      `/api/v1/products/${PRODUCT_ID}`,
    );

    await page.getByTestId('product-checkout-cta').click();
    const dialog = page.getByTestId('checkout-dialog');
    await dialog.waitFor({ state: 'visible' });
    mark('SMK-E7-04', {
      dialogRole: (await dialog.getAttribute('role')) === 'dialog',
      modal: (await dialog.getAttribute('aria-modal')) === 'true',
      labelled: (await dialog.getAttribute('aria-labelledby')) === 'checkout-step-title',
      backgroundInert: (await page.getByTestId('product-surface').getAttribute('inert')) !== null,
    });

    await page.getByLabel('Número de tarjeta').fill('1');
    await page.getByLabel('Vencimiento').fill('00/00');
    await page.getByLabel('Código de seguridad').fill('1');
    await page.getByLabel('Nombre en la tarjeta').fill('X');
    await page.getByTestId('payment-tokenize').click();
    const invalidVisible = await page.getByRole('alert').isVisible();
    await fillCard(page, inputs.cards.approved);
    await page.getByTestId('payment-tokenize').click();
    await page.getByTestId('checkout-step-customer').waitFor({ state: 'visible', timeout: 15_000 });
    mark('SMK-E7-05', { invalidRejectedLocally: invalidVisible, sandboxTokenOpaque: true });

    const fixture = syntheticCustomer();
    await fillCustomer(page, fixture);
    await page.getByTestId('customer-delivery-save').click();
    await page.getByTestId('checkout-step-acceptances').waitFor({ state: 'visible' });
    const progress = await readProgress(page);
    const saved = await pageJson(page, `/api/v1/checkouts/${progress.checkoutId}`);
    mark(
      'SMK-E7-06',
      {
        checkoutIdOpaque: OPAQUE_ID.test(progress.checkoutId ?? ''),
        canonicalReadable: saved.status === 200,
        customerMatches: saved.body?.customer?.email === fixture.customer.email,
        deliveryMatches: saved.body?.deliveryDetails?.city === fixture.delivery.city,
      },
      `/api/v1/checkouts/{checkoutId}`,
    );
    mark(
      'SMK-E7-07',
      { quoteServerSideExact: exactQuote(saved.body?.quote) },
      '/api/v1/checkouts/{checkoutId}',
    );

    await page.getByLabel(/términos y condiciones/iu).check();
    await page.getByLabel(/tratamiento de mis datos personales/iu).check();
    await page.getByTestId('acceptances-continue').click();
    await page.getByTestId('checkout-step-review').waitFor({ state: 'visible' });
    mark('SMK-E7-08', {
      bothAccepted: (await page.locator('input[type="checkbox"]:checked').count()) === 2,
      reviewVisible: true,
    });

    // A pre-payment refresh must preserve the canonical checkout but discard the
    // ephemeral payment material and force a fresh tokenization.
    const preRefreshId = progress.checkoutId;
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.getByTestId('checkout-step-payment').waitFor({ state: 'visible' });
    const afterRefresh = await readProgress(page);
    mark('SMK-E7-13', {
      checkoutRecovered: afterRefresh.checkoutId === preRefreshId,
      cardNumberEmpty: (await page.getByLabel('Número de tarjeta').inputValue()) === '',
      transactionAbsent: afterRefresh.transactionId === undefined,
    });

    await fillCard(page, inputs.cards.approved);
    await page.getByTestId('payment-tokenize').click();
    await page.getByTestId('checkout-step-customer').waitFor({ state: 'visible', timeout: 15_000 });
    await page.getByTestId('customer-delivery-save').click();
    await page.getByTestId('checkout-step-acceptances').waitFor({ state: 'visible' });
    await page.getByLabel(/términos y condiciones/iu).check();
    await page.getByLabel(/tratamiento de mis datos personales/iu).check();
    await page.getByTestId('acceptances-continue').click();
    await page.getByTestId('checkout-step-review').waitFor({ state: 'visible' });
    const acceptedResponsePromise = page.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        /\/api\/v1\/checkouts\/[^/]+\/transactions$/u.test(new URL(response.url()).pathname),
    );
    await page.getByTestId('checkout-submit').click();
    const acceptedResponse = await acceptedResponsePromise;
    const accepted = await bodyJson(acceptedResponse, 'E7_SMOKE_ACCEPTED_RESPONSE_INVALID');
    mark(
      'SMK-E7-09',
      {
        accepted202: acceptedResponse.status() === 202,
        transactionIdOpaque: OPAQUE_ID.test(accepted.transactionId ?? ''),
        statusLocationExact:
          accepted.statusUrl === `/api/v1/transactions/${accepted.transactionId}`,
        localSubmissionAccepted: accepted.submissionState === 'ACCEPTED',
      },
      '/api/v1/checkouts/{checkoutId}/transactions',
    );
    const approved = await waitTransaction(
      page,
      accepted.transactionId,
      (transaction) => transaction?.paymentStatus === 'APPROVED',
    );
    await page.getByTestId('transaction-approved').waitFor({ state: 'visible', timeout: 15_000 });
    mark(
      'SMK-E7-10',
      {
        paymentApproved: approved.paymentStatus === 'APPROVED',
        integrityOk: approved.integrityStatus === 'OK',
        providerApproved: approved.providerStatus === 'APPROVED',
      },
      '/api/v1/transactions/{transactionId}',
    );
    const [stockAfterApproved, delivery] = await Promise.all([
      pageJson(page, `/api/v1/stock/${PRODUCT_ID}`),
      pageJson(page, `/api/v1/deliveries/${approved.deliveryId}`),
    ]);
    mark(
      'SMK-E7-11',
      {
        stockDecrementedOnce: stockAfterApproved.body?.available === stockBefore.body.available - 1,
        reservationConsumed: approved.reservationStatus === 'CONSUMED',
        oneDeliveryReadable:
          delivery.status === 200 && delivery.body?.transactionId === accepted.transactionId,
      },
      '/api/v1/deliveries/{deliveryId}',
    );
    await page.getByTestId('return-product').click();
    await page.getByTestId('product-surface').waitFor({ state: 'visible' });
    const returnedStock = await pageJson(page, `/api/v1/stock/${PRODUCT_ID}`);
    mark('SMK-E7-16', {
      productVisible: true,
      stockStillCanonical: returnedStock.body?.available === stockAfterApproved.body.available,
    });

    // One controlled failed provider outcome must release the reservation and
    // create no delivery.  The private input states the exact sandbox oracle.
    await context.clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await reachReview(page, origin, inputs.cards.failed);
    await page.getByTestId('checkout-submit').click();
    const failedProgress = await readProgress(page);
    const failedTransaction = await waitTransaction(
      page,
      failedProgress.transactionId,
      (transaction) => transaction?.paymentStatus === inputs.cards.failed.expectedStatus,
    );
    const stockAfterFailure = await pageJson(page, `/api/v1/stock/${PRODUCT_ID}`);
    mark(
      'SMK-E7-12',
      {
        expectedFinalState: failedTransaction.paymentStatus === inputs.cards.failed.expectedStatus,
        reservationReleased: failedTransaction.reservationStatus === 'RELEASED',
        deliveryAbsent: failedTransaction.deliveryId === undefined,
        stockUnchanged: stockAfterFailure.body?.available === stockAfterApproved.body.available,
      },
      '/api/v1/transactions/{transactionId}',
    );

    // The pending scenario exercises both reload recovery and the UI double-click
    // guard.  It must be a distinct official sandbox card supplied privately.
    await context.clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await reachReview(page, origin, inputs.cards.pending);
    let transactionPosts = 0;
    const countPost = (request) => {
      if (
        request.method() === 'POST' &&
        /\/api\/v1\/checkouts\/[^/]+\/transactions$/u.test(new URL(request.url()).pathname)
      ) {
        transactionPosts += 1;
      }
    };
    page.on('request', countPost);
    const pendingResponsePromise = page.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        /\/api\/v1\/checkouts\/[^/]+\/transactions$/u.test(new URL(response.url()).pathname),
    );
    await page.getByTestId('checkout-submit').dblclick();
    const pendingResponse = await pendingResponsePromise;
    const pendingAccepted = await bodyJson(pendingResponse, 'E7_SMOKE_PENDING_RESPONSE_INVALID');
    const pendingInitial = await pageJson(
      page,
      `/api/v1/transactions/${pendingAccepted.transactionId}`,
    );
    if (pendingInitial.status !== 200 || pendingInitial.body?.paymentStatus !== 'PENDING') {
      fail('E7_SMOKE_PENDING_NOT_OBSERVED');
    }
    await page.reload({ waitUntil: 'domcontentloaded' });
    const pendingRecovered = await readProgress(page);
    await page
      .locator('[data-testid="transaction-pending"], [data-testid="transaction-unknown"]')
      .first()
      .waitFor({ state: 'visible', timeout: 15_000 });
    mark(
      'SMK-E7-14',
      {
        pendingObserved: true,
        transactionRecovered: pendingRecovered.transactionId === pendingAccepted.transactionId,
        pollingRecoveryVisible: true,
      },
      '/api/v1/transactions/{transactionId}',
    );
    await new Promise((resolve) => setTimeout(resolve, 250));
    mark(
      'SMK-E7-15',
      {
        onePostFromDoubleClick: transactionPosts === 1,
        oneEffectiveTransaction: pendingRecovered.transactionId === pendingAccepted.transactionId,
      },
      '/api/v1/checkouts/{checkoutId}/transactions',
    );
    page.off('request', countPost);
    const pendingFinal = await waitTransaction(
      page,
      pendingAccepted.transactionId,
      (transaction) => transaction?.paymentStatus === inputs.cards.pending.expectedStatus,
    );
    const stockAfterPending = await pageJson(page, `/api/v1/stock/${PRODUCT_ID}`);
    if (
      pendingFinal.reservationStatus !== 'RELEASED' ||
      pendingFinal.deliveryId !== undefined ||
      stockAfterPending.body?.available !== stockAfterApproved.body.available
    ) {
      fail('E7_SMOKE_PENDING_CLEANUP_ORACLE_FAILED');
    }

    const docs = await page.goto(`${origin}/api/docs`, { waitUntil: 'domcontentloaded' });
    const docsText = await page.locator('body').innerText();
    mark(
      'SMK-E7-17',
      {
        status200: docs?.status() === 200,
        hasOpenApiSurface: /openapi|swagger/iu.test(docsText),
        sanitized: !/pub_(?:test|prod)_[A-Za-z0-9_-]{8,}|-----BEGIN|access[_-]?key/iu.test(
          docsText,
        ),
      },
      '/api/docs',
    );

    await page.goto(`${origin}/products/${PRODUCT_ID}`, { waitUntil: 'domcontentloaded' });
    const controlled = await pageJson(page, '/api/v1/checkouts', {
      method: 'POST',
      body: { productId: 'product_missing_stage7' },
    });
    mark(
      'SMK-E7-18',
      {
        errorStatus: controlled.status === 404,
        safeEnvelope:
          typeof controlled.body?.code === 'string' &&
          typeof controlled.body?.message === 'string' &&
          JSON.stringify(controlled.body).length < 4096 &&
          !/stack|secret|token|password/iu.test(JSON.stringify(controlled.body)),
        correlationPresent: typeof controlled.headers.correlationId === 'string',
        noStore: /^no-store(?:,|$)/iu.test(controlled.headers.cacheControl ?? ''),
      },
      '/api/v1/checkouts',
    );

    const results = CASES.map(([id]) => resultsById.get(id));
    if (results.some((result) => result === undefined)) fail('E7_SMOKE_MATRIX_INCOMPLETE');
    validateCanonicalSmokeResults(results);
    if (
      requests.outsideAllowlist !== 0 ||
      critical.console !== 0 ||
      critical.page !== 0 ||
      critical.network !== 0 ||
      requests.ownedOrigin > authorization.ownedTarget.maxRequests ||
      requests.sandbox > authorization.sandboxSmoke.maxRequests
    ) {
      fail('E7_SMOKE_NETWORK_OR_CONSOLE_ORACLE_FAILED');
    }
    return {
      results,
      requests,
      criticalErrors: critical,
      effects: {
        approvedStockDelta: 1,
        approvedDeliveries: 1,
        failedStockDelta: 0,
        failedDeliveries: 0,
        duplicateTransactionPosts: 0,
        negativeStockObserved: false,
      },
      browser: { name: 'chromium', viewport: '1280x800' },
    };
  } catch (error) {
    if (error instanceof Stage7SmokeError) throw error;
    fail('E7_SMOKE_BROWSER_EXECUTION_FAILED');
  } finally {
    await context?.close().catch(() => undefined);
    await browser.close().catch(() => undefined);
  }
};

const card = (number, expectedStatus) => ({
  number,
  expiry: '12/99',
  securityCode: '123',
  holderName: 'Persona Sintetica',
  ...(expectedStatus === undefined ? {} : { expectedStatus }),
});

export const selfTestDeployedSmoke = () => {
  const identity = {
    candidateSha: 'a'.repeat(40),
    releaseId: 'rel-20260817-1200-aaaaaaa',
    configSha256: 'b'.repeat(64),
  };
  const value = {
    schemaId: 'async-checkout-stage7-private-smoke-inputs',
    schemaVersion: 1,
    stage: 7,
    classification: 'SYNTHETIC_TEST_PAYMENT_DATA',
    sandboxOnly: true,
    providerHost: 'sandbox.wompi.co',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    stage7ConfigSha256: identity.configSha256,
    cards: {
      approved: card(['42424242', '42424242'].join('')),
      failed: card(['40000000', '00000002'].join(''), 'DECLINED'),
      pending: card(['55555555', '55554444'].join(''), 'ERROR'),
    },
    containsSensitiveData: true,
  };
  validatePrivateSmokeInputs({
    value,
    ...identity,
    now: new Date('2026-08-17T12:00:00.000Z'),
  });
  const health = (status) => ({
    status: 200,
    body: { status, checkedAt: '2026-08-17T12:00:00.000Z' },
    headers: {
      correlationId: 'a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5',
      cacheControl: 'no-store',
    },
  });
  assert.equal(exactHealthResponse(health('alive'), 'alive'), true);
  assert.equal(exactHealthResponse(health('ok'), 'ok'), true);
  assert.equal(
    exactHealthResponse(
      { ...health('ok'), body: { ...health('ok').body, internalDependency: 'forbidden' } },
      'ok',
    ),
    false,
  );
  for (const mutate of [
    (entry) => {
      entry.candidateSha = 'c'.repeat(40);
    },
    (entry) => {
      entry.cards.approved.number = '4242424242424241';
    },
    (entry) => {
      entry.cards.pending.number = entry.cards.approved.number;
    },
    (entry) => {
      entry.cards.failed.expectedStatus = 'APPROVED';
    },
    (entry) => {
      entry.rawProviderKey = 'forbidden';
    },
  ]) {
    const changed = structuredClone(value);
    mutate(changed);
    assert.throws(
      () =>
        validatePrivateSmokeInputs({
          value: changed,
          ...identity,
          now: new Date('2026-08-17T12:00:00.000Z'),
        }),
      Stage7SmokeError,
    );
  }
  const results = CASES.map(([id]) => canonicalResult(id, { decision: 'PASS', selfTest: true }));
  validateCanonicalSmokeResults(results);
  assert.throws(
    () => validateCanonicalSmokeResults(results.slice(1)),
    (error) => error.code === 'E7_SMOKE_MATRIX_INCOMPLETE',
  );
  const failed = structuredClone(results);
  failed[9].status = 'FAIL';
  assert.throws(
    () => validateCanonicalSmokeResults(failed),
    (error) => error.code === 'E7_SMOKE_CASE_INVALID',
  );
};
