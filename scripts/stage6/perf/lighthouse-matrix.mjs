import { createServer } from 'node:http';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  PRODUCT_ID,
  PRODUCT_PATH,
  ROOT,
  Stage6CheckError,
  WEB_ORIGIN,
  check,
} from '../compat/harness.mjs';

const requireFromRoot = createRequire(path.join(ROOT, 'package.json'));
const CONFIG_PATH = path.join(ROOT, 'scripts', 'stage6', 'perf', 'lighthouse.mobile.json');
const REQUIRED_RUNS = 3;
const REPEAT_WARMUP_RUNS = 1;
const FINAL_CHECKOUT_ID = 'checkout_e6_local_001';
const REVIEW_CHECKOUT_ID = 'checkout_e6_review_001';
const TRANSACTION_ID = 'transaction_e6_local_001';
const FINAL_PATH = `${PRODUCT_PATH}/checkout/status`;

const product = {
  productId: PRODUCT_ID,
  sku: 'SKU_DEMO_001',
  name: 'Morral urbano de demostración',
  description: 'Producto sintético para la verificación local de etapa 6.',
  imageUrl: `${WEB_ORIGIN}/product-placeholder.svg`,
  unitPrice: { amountInCents: 2_500_000, currency: 'COP' },
  available: 3,
};

const quote = {
  quoteId: 'quote_e6_local_001',
  version: 1,
  productId: PRODUCT_ID,
  quantity: 1,
  subtotal: product.unitPrice,
  baseFee: { amountInCents: 125_000, currency: 'COP' },
  deliveryFee: { amountInCents: 75_000, currency: 'COP' },
  total: { amountInCents: 2_700_000, currency: 'COP' },
  expiresAt: '2099-01-01T00:00:00.000Z',
};

const newReviewCheckout = () => ({
  checkoutId: REVIEW_CHECKOUT_ID,
  status: 'DRAFT',
  version: 1,
  product,
  quote,
  customer: null,
  deliveryDetails: null,
  activeTransactionId: null,
  expiresAt: '2099-01-01T00:00:00.000Z',
});

const finalCheckout = {
  checkoutId: FINAL_CHECKOUT_ID,
  status: 'PAID',
  version: 4,
  product,
  quote,
  customer: null,
  deliveryDetails: null,
  activeTransactionId: TRANSACTION_ID,
  expiresAt: '2099-01-01T00:00:00.000Z',
};

const transaction = {
  transactionId: TRANSACTION_ID,
  checkoutId: FINAL_CHECKOUT_ID,
  checkoutStatus: 'PAID',
  paymentStatus: 'APPROVED',
  dispatchPhase: 'ACKNOWLEDGED',
  providerStatus: 'APPROVED',
  reservationStatus: 'CONSUMED',
  integrityStatus: 'OK',
  deliveryId: 'delivery_e6_local_001',
  statusUrl: `/api/v1/transactions/${TRANSACTION_ID}`,
  allowedActions: ['QUERY', 'RETURN_TO_PRODUCT'],
  acceptedAt: '2026-08-16T00:00:00.000Z',
  updatedAt: '2026-08-16T00:00:01.000Z',
};

const paymentConfiguration = {
  captureVariant: 'FAKE_CONTRACT',
  sandboxPublicKey: ['synthetic', 'local', 'material'].join('-'),
  allowedInstallments: [1, 3, 6],
  acceptanceContracts: [
    {
      type: 'TERMS',
      permalink: `${WEB_ORIGIN}/legal/terms-v1.html`,
      version: 'terms-v1',
      acceptanceToken: ['terms', 'e6', 'synthetic', 'material'].join('-'),
    },
    {
      type: 'PERSONAL_DATA',
      permalink: `${WEB_ORIGIN}/legal/personal-data-v1.html`,
      version: 'personal-data-v1',
      acceptanceToken: ['personal-data', 'e6', 'synthetic', 'material'].join('-'),
    },
  ],
  expiresAt: '2099-01-01T00:00:00.000Z',
};

const emptyCounts = () => ({
  product: 0,
  checkoutCreated: 0,
  reviewCheckout: 0,
  finalCheckout: 0,
  customerSaved: 0,
  deliverySaved: 0,
  paymentConfiguration: 0,
  transaction: 0,
  unknownApi: 0,
});

const sendJson = (response, body, status = 200) => {
  response.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
  });
  response.end(JSON.stringify(body));
};

const readJsonBody = async (request) => {
  let body = '';
  for await (const chunk of request) {
    body += chunk.toString();
    check(body.length <= 32_768, 'LIGHTHOUSE_SYNTHETIC_REQUEST_TOO_LARGE');
  }
  return JSON.parse(body);
};

const withSyntheticApi = async (run) => {
  const counts = emptyCounts();
  let reviewCheckout = newReviewCheckout();
  const server = createServer(async (request, response) => {
    try {
      const pathname = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
      const key = `${request.method ?? 'GET'} ${pathname}`;
      if (key === `GET /api/v1/products/${PRODUCT_ID}`) {
        counts.product += 1;
        sendJson(response, product);
      } else if (key === 'POST /api/v1/checkouts') {
        counts.checkoutCreated += 1;
        reviewCheckout = newReviewCheckout();
        sendJson(
          response,
          {
            checkoutId: REVIEW_CHECKOUT_ID,
            status: 'DRAFT',
            version: 1,
            quote,
            expiresAt: reviewCheckout.expiresAt,
          },
          201,
        );
      } else if (key === `GET /api/v1/checkouts/${REVIEW_CHECKOUT_ID}`) {
        counts.reviewCheckout += 1;
        sendJson(response, reviewCheckout);
      } else if (key === `GET /api/v1/checkouts/${FINAL_CHECKOUT_ID}`) {
        counts.finalCheckout += 1;
        sendJson(response, finalCheckout);
      } else if (key === `PUT /api/v1/checkouts/${REVIEW_CHECKOUT_ID}/customer`) {
        counts.customerSaved += 1;
        const body = await readJsonBody(request);
        const customer = {
          customerId: 'customer_e6_local_001',
          checkoutId: REVIEW_CHECKOUT_ID,
          version: reviewCheckout.version + 1,
          fullName: body.fullName,
          email: body.email,
          phone: body.phone,
        };
        reviewCheckout = { ...reviewCheckout, customer, version: customer.version };
        sendJson(response, customer);
      } else if (key === `PUT /api/v1/checkouts/${REVIEW_CHECKOUT_ID}/delivery-details`) {
        counts.deliverySaved += 1;
        const body = await readJsonBody(request);
        const deliveryDetails = {
          checkoutId: REVIEW_CHECKOUT_ID,
          version: reviewCheckout.version + 1,
          ...body,
        };
        reviewCheckout = {
          ...reviewCheckout,
          deliveryDetails,
          version: deliveryDetails.version,
        };
        sendJson(response, deliveryDetails);
      } else if (key === 'GET /api/v1/payment-configuration') {
        counts.paymentConfiguration += 1;
        sendJson(response, paymentConfiguration);
      } else if (key === `GET /api/v1/transactions/${TRANSACTION_ID}`) {
        counts.transaction += 1;
        sendJson(response, transaction);
      } else {
        counts.unknownApi += 1;
        sendJson(response, { code: 'E6_SYNTHETIC_ROUTE_MISSING' }, 501);
      }
    } catch {
      sendJson(response, { code: 'E6_SYNTHETIC_API_ERROR' }, 500);
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(3000, '127.0.0.1', resolve);
  }).catch(() => {
    throw new Stage6CheckError('LIGHTHOUSE_SYNTHETIC_API_START_FAILED');
  });

  try {
    return await run(() => ({ ...counts }));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
};

const isExternalRequest = (candidate) => {
  try {
    const parsed = new URL(candidate);
    return (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      parsed.hostname !== '127.0.0.1' &&
      parsed.hostname !== 'localhost'
    );
  } catch {
    return false;
  }
};

const browserVersionFrom = (value) =>
  /(?:Edg|Chrome)\/([0-9.]+)/.exec(value ?? '')?.[1] ?? 'UNKNOWN';

const numericAudit = (lhr, id, failureCode) => {
  const value = lhr.audits[id]?.numericValue;
  check(Number.isFinite(value), failureCode);
  return value;
};

const categoryScore = (lhr, id, failureCode) => {
  const value = lhr.categories[id]?.score;
  check(Number.isFinite(value), failureCode);
  return value;
};

const navigationSnapshot = (lhr, expectedUrl, budgets) => {
  const requests = lhr.audits['network-requests']?.details?.items ?? [];
  const resources = { javascriptBytes: 0, cssBytes: 0, imageBytes: 0, fontBytes: 0 };
  for (const request of requests) {
    const bytes = Number.isFinite(request.transferSize) ? request.transferSize : 0;
    const resourceType = String(request.resourceType ?? '').toLowerCase();
    if (resourceType === 'script') resources.javascriptBytes += bytes;
    else if (resourceType === 'stylesheet') resources.cssBytes += bytes;
    else if (resourceType === 'image') resources.imageBytes += bytes;
    else if (resourceType === 'font') resources.fontBytes += bytes;
  }

  const expected = new URL(expectedUrl);
  const actual = new URL(lhr.finalUrl);
  check(
    actual.origin === expected.origin && actual.pathname === expected.pathname,
    'LIGHTHOUSE_URL_MISMATCH',
  );
  const metrics = {
    lcpMs: numericAudit(lhr, 'largest-contentful-paint', 'LIGHTHOUSE_LCP_MISSING'),
    cls: numericAudit(lhr, 'cumulative-layout-shift', 'LIGHTHOUSE_CLS_MISSING'),
    tbtMs: numericAudit(lhr, 'total-blocking-time', 'LIGHTHOUSE_TBT_MISSING'),
    fcpMs: numericAudit(lhr, 'first-contentful-paint', 'LIGHTHOUSE_FCP_MISSING'),
    speedIndexMs: numericAudit(lhr, 'speed-index', 'LIGHTHOUSE_SPEED_INDEX_MISSING'),
    transferredBytes: numericAudit(lhr, 'total-byte-weight', 'LIGHTHOUSE_TRANSFER_SIZE_MISSING'),
    ...resources,
    requestCount: requests.length,
    performanceScore: categoryScore(lhr, 'performance', 'LIGHTHOUSE_PERFORMANCE_SCORE_MISSING'),
    accessibilityScore: categoryScore(
      lhr,
      'accessibility',
      'LIGHTHOUSE_ACCESSIBILITY_SCORE_MISSING',
    ),
    bestPracticesScore: categoryScore(
      lhr,
      'best-practices',
      'LIGHTHOUSE_BEST_PRACTICES_SCORE_MISSING',
    ),
    externalRequestCount: requests.filter(({ url }) => isExternalRequest(url)).length,
  };
  check(metrics.lcpMs < budgets.lcpMsMaximumExclusive, 'LIGHTHOUSE_LCP_BUDGET_EXCEEDED');
  check(metrics.cls < budgets.clsMaximumExclusive, 'LIGHTHOUSE_CLS_BUDGET_EXCEEDED');
  check(metrics.externalRequestCount === 0, 'LIGHTHOUSE_EXTERNAL_REQUEST_DETECTED');
  return {
    metrics,
    lighthouseVersion: lhr.lighthouseVersion,
    browserVersion: browserVersionFrom(lhr.userAgent),
  };
};

const rounded = (value) => Number(value.toFixed(3));

const distribution = (samples, unit, source) => {
  const roundedSamples = samples.map(rounded);
  const values = [...roundedSamples].sort((left, right) => left - right);
  check(values.length === REQUIRED_RUNS, 'LIGHTHOUSE_MEASURED_RUN_COUNT_MISMATCH');
  const minimum = values[0];
  const maximum = values.at(-1);
  return {
    unit,
    source,
    median: values[Math.floor(values.length / 2)],
    dispersion: {
      method: 'range',
      minimum,
      maximum,
      value: rounded(maximum - minimum),
    },
    samples: roundedSamples,
  };
};

const NAVIGATION_METRICS = {
  lcpMs: 'ms',
  cls: 'score',
  tbtMs: 'ms',
  fcpMs: 'ms',
  speedIndexMs: 'ms',
  transferredBytes: 'bytes',
  javascriptBytes: 'bytes',
  cssBytes: 'bytes',
  imageBytes: 'bytes',
  fontBytes: 'bytes',
  requestCount: 'count',
  performanceScore: 'ratio',
  accessibilityScore: 'ratio',
  bestPracticesScore: 'ratio',
  externalRequestCount: 'count',
};

const summarizeNavigation = (snapshots) =>
  Object.fromEntries(
    Object.entries(NAVIGATION_METRICS).map(([name, unit]) => [
      name,
      distribution(
        snapshots.map(({ metrics }) => metrics[name]),
        unit,
        'LIGHTHOUSE_NAVIGATION',
      ),
    ]),
  );

const versionsFrom = (snapshots, key) => [...new Set(snapshots.map((snapshot) => snapshot[key]))];

const cleanupDirectory = (directory) =>
  rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });

const preparePage = async (page) => {
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1, isMobile: true });
  page.setDefaultTimeout(15_000);
};

const withProfileBrowser = async ({ config, executablePath, puppeteer }, workingDirectory, run) => {
  const browser = await puppeteer.launch({
    executablePath,
    headless: true,
    userDataDir: path.join(workingDirectory, '.lighthouse-profile'),
    args: config.browserArguments,
  });
  try {
    const page = await browser.newPage();
    await preparePage(page);
    return await run(browser, page);
  } finally {
    await browser.close().catch(() => undefined);
  }
};

const withBrowser = async (options, run) => {
  const workingDirectory = path.join(options.parentDirectory, options.id);
  await mkdir(workingDirectory, { recursive: true });
  try {
    return await withProfileBrowser(options, workingDirectory, run);
  } finally {
    await cleanupDirectory(workingDirectory);
  }
};

const installFinalRecoveryFixture = async (page) => {
  const name = 'checkout.progress.ids.v1';
  const expected = JSON.stringify({ checkoutId: FINAL_CHECKOUT_ID, transactionId: TRANSACTION_ID });
  await page.evaluateOnNewDocument(
    ({ origin, name: storageName, expected: storageValue }) => {
      if (globalThis.location.origin !== origin) return;
      globalThis.localStorage.setItem(storageName, storageValue);
    },
    { origin: WEB_ORIGIN, name, expected },
  );
  return { name, expected };
};

const navigate = async ({ config, lighthouse, page, url, disableStorageReset }) => {
  let observedExternalRequests = 0;
  const observe = (request) => {
    if (isExternalRequest(request.url())) observedExternalRequests += 1;
  };
  page.on('request', observe);
  try {
    const result = await lighthouse.navigation(page, url, {
      flags: { ...config.settings, disableStorageReset },
    });
    check(result?.lhr !== undefined, 'LIGHTHOUSE_NAVIGATION_RESULT_MISSING');
    check(observedExternalRequests === 0, 'LIGHTHOUSE_EXTERNAL_REQUEST_OBSERVED');
    return navigationSnapshot(result.lhr, url, config.budgets);
  } finally {
    page.off('request', observe);
  }
};

const navigateWithRecoveryFixture = async (page, options, disableStorageReset) => {
  const fixture = await installFinalRecoveryFixture(page);
  const snapshot = await navigate({ ...options, page, disableStorageReset });
  const actual = await page.evaluate(({ name }) => globalThis.localStorage.getItem(name), {
    name: fixture.name,
  });
  check(actual === fixture.expected, 'LIGHTHOUSE_FINAL_STATE_FIXTURE_NOT_STORED');
  return snapshot;
};

const collectFirstVisits = async (options) => {
  const snapshots = [];
  for (let index = 0; index < REQUIRED_RUNS; index += 1) {
    snapshots.push(
      await withBrowser(
        { ...options, id: `${options.id}-first-${index + 1}` },
        async (_browser, page) => {
          if (options.preserveRecoveryIds) {
            return navigateWithRecoveryFixture(page, options, false);
          }
          return navigate({
            ...options,
            page,
            disableStorageReset: false,
          });
        },
      ),
    );
  }
  return {
    status: 'PASS',
    visit: 'first',
    measuredRuns: snapshots.length,
    warmupRuns: 0,
    isolation: 'FRESH_BROWSER_PROFILE_PER_RUN',
    lighthouseVersions: versionsFrom(snapshots, 'lighthouseVersion'),
    browserVersions: versionsFrom(snapshots, 'browserVersion'),
    metrics: summarizeNavigation(snapshots),
  };
};

const collectRepeatVisits = async (options) => {
  const workingDirectory = path.join(options.parentDirectory, `${options.id}-repeat`);
  await mkdir(workingDirectory, { recursive: true });
  try {
    await withProfileBrowser(options, workingDirectory, async (_browser, page) => {
      if (options.preserveRecoveryIds) {
        return navigateWithRecoveryFixture(page, options, false);
      }
      return navigate({
        ...options,
        page,
        disableStorageReset: false,
      });
    });
    const snapshots = [];
    for (let index = 0; index < REQUIRED_RUNS; index += 1) {
      snapshots.push(
        await withProfileBrowser(options, workingDirectory, async (_browser, page) => {
          if (options.preserveRecoveryIds) {
            return navigateWithRecoveryFixture(page, options, true);
          }
          return navigate({ ...options, page, disableStorageReset: true });
        }),
      );
    }
    return {
      status: 'PASS',
      visit: 'repeat',
      measuredRuns: snapshots.length,
      warmupRuns: REPEAT_WARMUP_RUNS,
      isolation: 'ONE_WARMUP_THEN_THREE_FRESH_BROWSERS_WITH_SHARED_PERSISTED_PROFILE',
      lighthouseVersions: versionsFrom(snapshots, 'lighthouseVersion'),
      browserVersions: versionsFrom(snapshots, 'browserVersion'),
      metrics: summarizeNavigation(snapshots),
    };
  } finally {
    await cleanupDirectory(workingDirectory);
  }
};

const validSyntheticCardNumber = () => {
  const passesLuhn = (candidate) => {
    let sum = 0;
    let double = false;
    for (let index = candidate.length - 1; index >= 0; index -= 1) {
      let digit = Number(candidate[index]);
      if (double) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      double = !double;
    }
    return sum % 10 === 0;
  };
  const prefix = `4${'0'.repeat(14)}`;
  const value = Array.from({ length: 10 }, (_, digit) => `${prefix}${digit}`).find(passesLuhn);
  check(value !== undefined, 'LIGHTHOUSE_SYNTHETIC_CARD_GENERATION_FAILED');
  return value;
};

const type = async (page, selector, value) => {
  await page.waitForSelector(selector, { visible: true });
  await page.type(selector, value);
};

const driveToReview = async (page) => {
  await page.goto(`${WEB_ORIGIN}${PRODUCT_PATH}`, { waitUntil: 'networkidle0', timeout: 45_000 });
  await page.waitForSelector('[data-testid="product-surface"]', { visible: true });
  await page.click('[data-testid="product-checkout-cta"]');
  await page.waitForSelector('[data-testid="checkout-step-payment"]', { visible: true });
  await type(page, '[name="payment-number"]', validSyntheticCardNumber());
  await type(page, '[name="payment-expiry"]', ['12', '99'].join(''));
  await type(page, '[name="payment-security-code"]', [8, 7, 3].join(''));
  await type(page, '[name="payment-holder"]', 'Persona Sintética');
  await page.click('[data-testid="payment-tokenize"]');
  await page.waitForSelector('[data-testid="checkout-step-customer"]', { visible: true });
  await type(page, '[name="fullName"]', 'Persona Sintética');
  await type(page, '[name="email"]', 'persona@example.test');
  await type(page, '[name="phone"]', '+573000000000');
  await type(page, '[name="addressLine1"]', 'Calle sintética 123');
  await type(page, '[name="city"]', 'Bogotá');
  await type(page, '[name="region"]', 'Cundinamarca');
  await page.click('[data-testid="customer-delivery-save"]');
  await page.waitForSelector('[data-testid="checkout-step-acceptances"]', { visible: true });
  const acceptances = await page.$$(
    '[data-testid="checkout-step-acceptances"] input[type="checkbox"]',
  );
  check(acceptances.length === 2, 'LIGHTHOUSE_ACCEPTANCE_CONTROLS_MISSING');
  for (const acceptance of acceptances) await acceptance.click();
};

const resourceTimingSnapshot = async (page) => {
  const timing = await page.evaluate(() => {
    const navigation = globalThis.performance.getEntriesByType('navigation')[0];
    return {
      navigationTransferSize: Number.isFinite(navigation?.transferSize)
        ? navigation.transferSize
        : 0,
      resources: globalThis.performance.getEntriesByType('resource').map((entry) => ({
        name: entry.name,
        initiatorType: entry.initiatorType,
        transferSize: Number.isFinite(entry.transferSize) ? entry.transferSize : 0,
      })),
    };
  });
  const result = {
    transferredBytes: timing.navigationTransferSize,
    javascriptBytes: 0,
    cssBytes: 0,
    imageBytes: 0,
    fontBytes: 0,
    requestCount: timing.resources.length + 1,
    externalRequestCount: 0,
  };
  for (const resource of timing.resources) {
    result.transferredBytes += resource.transferSize;
    let pathname = '';
    try {
      pathname = new URL(resource.name).pathname.toLowerCase();
    } catch {
      // Non-URL performance entries do not contribute to typed resource totals.
    }
    const kind = resource.initiatorType.toLowerCase();
    if (kind === 'script' || pathname.endsWith('.js')) {
      result.javascriptBytes += resource.transferSize;
    } else if (kind === 'css' || kind === 'link' || pathname.endsWith('.css')) {
      result.cssBytes += resource.transferSize;
    } else if (kind === 'img' || /\.(?:avif|gif|jpe?g|png|svg|webp)$/.test(pathname)) {
      result.imageBytes += resource.transferSize;
    } else if (/\.(?:eot|otf|ttf|woff2?)$/.test(pathname)) {
      result.fontBytes += resource.transferSize;
    }
    if (isExternalRequest(resource.name)) result.externalRequestCount += 1;
  }
  return result;
};

const runSummaryFlow = async ({ config, lighthouse, parentDirectory, ...browserOptions }) => {
  const runNumber = browserOptions.runNumber;
  return withBrowser(
    {
      config,
      executablePath: browserOptions.executablePath,
      parentDirectory,
      puppeteer: browserOptions.puppeteer,
      id: `summary-flow-${runNumber}`,
    },
    async (browser, page) => {
      let externalRequestCount = 0;
      page.on('request', (request) => {
        if (isExternalRequest(request.url())) externalRequestCount += 1;
      });
      await driveToReview(page);
      const { onlyCategories: _onlyCategories, ...flowSettings } = config.settings;
      void _onlyCategories;
      const flow = await lighthouse.startFlow(page, {
        name: `checkout-summary-run-${runNumber}`,
        flags: flowSettings,
      });
      await flow.startTimespan({
        name: 'summary-transition',
        onlyCategories: ['performance', 'best-practices'],
      });
      await page.click('[data-testid="acceptances-continue"]');
      await page.waitForSelector('[data-testid="checkout-step-review"]', { visible: true });
      await flow.endTimespan();
      await flow.startTimespan({
        name: 'summary-stable-observation',
        onlyCategories: ['performance', 'best-practices'],
      });
      await new Promise((resolve) => setTimeout(resolve, 500));
      await flow.endTimespan();
      await flow.snapshot({
        name: 'summary-stable',
        onlyCategories: ['accessibility', 'best-practices'],
      });
      const result = await flow.createFlowResult();
      const transition = result.steps.find(({ name }) => name === 'summary-transition')?.lhr;
      const stableObservation = result.steps.find(
        ({ name }) => name === 'summary-stable-observation',
      )?.lhr;
      const snapshot = result.steps.find(({ name }) => name === 'summary-stable')?.lhr;
      check(transition !== undefined, 'LIGHTHOUSE_SUMMARY_TRANSITION_MISSING');
      check(stableObservation !== undefined, 'LIGHTHOUSE_SUMMARY_STABLE_OBSERVATION_MISSING');
      check(snapshot !== undefined, 'LIGHTHOUSE_SUMMARY_SNAPSHOT_MISSING');
      const resources = await resourceTimingSnapshot(page);
      const metrics = {
        transitionCls: numericAudit(
          transition,
          'cumulative-layout-shift',
          'LIGHTHOUSE_SUMMARY_TRANSITION_CLS_MISSING',
        ),
        cls: numericAudit(
          stableObservation,
          'cumulative-layout-shift',
          'LIGHTHOUSE_SUMMARY_STABLE_CLS_MISSING',
        ),
        tbtMs: numericAudit(transition, 'total-blocking-time', 'LIGHTHOUSE_SUMMARY_TBT_MISSING'),
        ...resources,
        performanceScore: categoryScore(
          transition,
          'performance',
          'LIGHTHOUSE_SUMMARY_PERFORMANCE_SCORE_MISSING',
        ),
        accessibilityScore: categoryScore(
          snapshot,
          'accessibility',
          'LIGHTHOUSE_SUMMARY_ACCESSIBILITY_SCORE_MISSING',
        ),
        bestPracticesScore: categoryScore(
          snapshot,
          'best-practices',
          'LIGHTHOUSE_SUMMARY_BEST_PRACTICES_SCORE_MISSING',
        ),
      };
      check(
        metrics.cls < config.budgets.clsMaximumExclusive,
        'LIGHTHOUSE_SUMMARY_CLS_BUDGET_EXCEEDED',
      );
      check(
        metrics.externalRequestCount === 0 && externalRequestCount === 0,
        'LIGHTHOUSE_SUMMARY_EXTERNAL_REQUEST_DETECTED',
      );
      return {
        metrics,
        lighthouseVersions: [
          transition.lighthouseVersion,
          stableObservation.lighthouseVersion,
          snapshot.lighthouseVersion,
        ],
        browserVersion: browserVersionFrom(await browser.version()),
      };
    },
  );
};

const SUMMARY_METRICS = {
  transitionCls: ['score', 'LIGHTHOUSE_USER_FLOW_TRANSITION_DIAGNOSTIC'],
  cls: ['score', 'LIGHTHOUSE_USER_FLOW_STABLE_OBSERVATION'],
  tbtMs: ['ms', 'LIGHTHOUSE_USER_FLOW_TRANSITION'],
  transferredBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  javascriptBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  cssBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  imageBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  fontBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  requestCount: ['count', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  performanceScore: ['ratio', 'LIGHTHOUSE_USER_FLOW_TRANSITION'],
  accessibilityScore: ['ratio', 'LIGHTHOUSE_USER_FLOW_SNAPSHOT'],
  bestPracticesScore: ['ratio', 'LIGHTHOUSE_USER_FLOW_SNAPSHOT'],
  externalRequestCount: ['count', 'BROWSER_RESOURCE_TIMING_AND_REQUEST_OBSERVER'],
};

const collectSummary = async (options) => {
  const snapshots = [];
  for (let runNumber = 1; runNumber <= REQUIRED_RUNS; runNumber += 1) {
    snapshots.push(await runSummaryFlow({ ...options, runNumber }));
  }
  return {
    status: 'PASS',
    route: `${PRODUCT_PATH}/checkout`,
    mode: 'LIGHTHOUSE_USER_FLOW_TWO_TIMESPANS_PLUS_SNAPSHOT',
    measuredRuns: snapshots.length,
    firstVisit: {
      applicable: true,
      measuredRuns: snapshots.length,
      isolation: 'FRESH_REAL_CHECKOUT_JOURNEY_AND_BROWSER_PROFILE_PER_RUN',
    },
    repeatVisit: {
      applicable: false,
      reason: 'REVIEW_USES_INTENTIONALLY_EPHEMERAL_IN_MEMORY_PAYMENT_SELECTION',
    },
    unavailableNavigationMetrics: {
      lcpMs: 'NOT_AVAILABLE_FOR_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
      fcpMs: 'NOT_AVAILABLE_FOR_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
      speedIndexMs: 'NOT_AVAILABLE_FOR_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
    },
    lighthouseVersions: [
      ...new Set(snapshots.flatMap(({ lighthouseVersions }) => lighthouseVersions)),
    ],
    browserVersions: [...new Set(snapshots.map(({ browserVersion }) => browserVersion))],
    metrics: Object.fromEntries(
      Object.entries(SUMMARY_METRICS).map(([name, [unit, source]]) => [
        name,
        distribution(
          snapshots.map(({ metrics }) => metrics[name]),
          unit,
          source,
        ),
      ]),
    ),
    rawArtifacts: 'IN_MEMORY_ONLY_NOT_PERSISTED',
  };
};

const validateVersionedConfig = (config, installedVersion) => {
  check(config?.schemaVersion === 1, 'LIGHTHOUSE_CONFIG_SCHEMA_INVALID');
  check(config?.tool?.version === installedVersion, 'LIGHTHOUSE_CONFIG_VERSION_MISMATCH');
  check(config?.runsPerApplicableVisit === REQUIRED_RUNS, 'LIGHTHOUSE_CONFIG_RUN_COUNT_INVALID');
  check(config?.settings?.formFactor === 'mobile', 'LIGHTHOUSE_CONFIG_FORM_FACTOR_INVALID');
  check(config?.settings?.screenEmulation?.width === 390, 'LIGHTHOUSE_CONFIG_WIDTH_INVALID');
  check(config?.settings?.screenEmulation?.height === 844, 'LIGHTHOUSE_CONFIG_HEIGHT_INVALID');
  check(
    ['performance', 'accessibility', 'best-practices'].every((category) =>
      config?.settings?.onlyCategories?.includes(category),
    ),
    'LIGHTHOUSE_CONFIG_CATEGORIES_INVALID',
  );
  check(config?.budgets?.lcpMsMaximumExclusive === 2_500, 'LIGHTHOUSE_CONFIG_LCP_BUDGET_INVALID');
  check(config?.budgets?.clsMaximumExclusive === 0.1, 'LIGHTHOUSE_CONFIG_CLS_BUDGET_INVALID');
};

export const runLighthouseAudit = async (executablePath) => {
  let lighthouse;
  let lighthouseVersion;
  let puppeteer;
  let puppeteerVersion;
  try {
    const lighthouseEntry = requireFromRoot.resolve('lighthouse/core/index.js');
    const lighthouseManifestPath = requireFromRoot.resolve('lighthouse/package.json');
    lighthouseVersion = JSON.parse(await readFile(lighthouseManifestPath, 'utf8')).version;
    const requireFromLighthouse = createRequire(lighthouseManifestPath);
    puppeteer = requireFromLighthouse('puppeteer-core');
    const puppeteerManifestPath = requireFromLighthouse.resolve('puppeteer-core/package.json');
    puppeteerVersion = JSON.parse(await readFile(puppeteerManifestPath, 'utf8')).version;
    lighthouse = await import(pathToFileURL(lighthouseEntry).href);
  } catch {
    return { status: 'NOT_RUN_ENV_REQUIRED', reason: 'LIGHTHOUSE_USER_FLOW_RUNTIME_MISSING' };
  }

  const config = JSON.parse(await readFile(CONFIG_PATH, 'utf8'));
  validateVersionedConfig(config, lighthouseVersion);
  const parentDirectory = await mkdtemp(path.join(tmpdir(), 'checkout-e6-lighthouse-'));
  try {
    return await withSyntheticApi(async (apiCounts) => {
      const shared = { config, executablePath, lighthouse, parentDirectory, puppeteer };
      const productFirst = await collectFirstVisits({
        ...shared,
        id: 'product',
        url: `${WEB_ORIGIN}${PRODUCT_PATH}`,
        preserveRecoveryIds: false,
      });
      const productRepeat = await collectRepeatVisits({
        ...shared,
        id: 'product',
        url: `${WEB_ORIGIN}${PRODUCT_PATH}`,
        preserveRecoveryIds: false,
      });
      const summary = await collectSummary(shared);
      const finalFirst = await collectFirstVisits({
        ...shared,
        id: 'final',
        url: `${WEB_ORIGIN}${FINAL_PATH}`,
        preserveRecoveryIds: true,
      });
      const finalRepeat = await collectRepeatVisits({
        ...shared,
        id: 'final',
        url: `${WEB_ORIGIN}${FINAL_PATH}`,
        preserveRecoveryIds: true,
      });
      const counts = apiCounts();
      check(counts.product >= 17, 'LIGHTHOUSE_PRODUCT_API_NOT_EXERCISED');
      check(counts.checkoutCreated >= REQUIRED_RUNS, 'LIGHTHOUSE_SUMMARY_CREATE_NOT_EXERCISED');
      check(counts.customerSaved >= REQUIRED_RUNS, 'LIGHTHOUSE_SUMMARY_CUSTOMER_NOT_EXERCISED');
      check(counts.deliverySaved >= REQUIRED_RUNS, 'LIGHTHOUSE_SUMMARY_DELIVERY_NOT_EXERCISED');
      check(counts.finalCheckout >= 7, 'LIGHTHOUSE_FINAL_CHECKOUT_NOT_EXERCISED');
      check(counts.transaction >= 7, 'LIGHTHOUSE_FINAL_TRANSACTION_NOT_EXERCISED');
      check(counts.unknownApi === 0, 'LIGHTHOUSE_UNDECLARED_SYNTHETIC_API_REQUEST');

      return {
        status: 'PASS',
        tool: {
          name: 'Lighthouse + Lighthouse User Flows + Puppeteer',
          version: `${lighthouseVersion} + ${puppeteerVersion}`,
        },
        config: {
          path: 'scripts/stage6/perf/lighthouse.mobile.json',
          formFactor: 'mobile',
          viewport: '390x844',
          categories: config.settings.onlyCategories,
          requiredMeasuredRunsPerApplicableVisit: REQUIRED_RUNS,
        },
        assertions: {
          status: 'PASS',
          engine: 'EXCLUSIVE_LOCAL_ASSERTIONS_OVER_LIGHTHOUSE_RESULTS',
          lcpMsMaximumExclusive: config.budgets.lcpMsMaximumExclusive,
          clsMaximumExclusive: config.budgets.clsMaximumExclusive,
          summaryLcp: 'NOT_APPLICABLE_TO_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
        },
        views: {
          product: {
            status: 'PASS',
            route: PRODUCT_PATH,
            firstVisit: productFirst,
            repeatVisit: productRepeat,
          },
          summary,
          final: {
            status: 'PASS',
            route: FINAL_PATH,
            fixture: 'CANONICAL_RECOVERY_IDS_INJECTED_BEFORE_DOCUMENT_LOOPBACK_ONLY',
            firstVisit: finalFirst,
            repeatVisit: finalRepeat,
          },
        },
        runAccounting: {
          navigationAudits: 14,
          measuredNavigationRuns: 12,
          navigationWarmupRuns: 2,
          summaryUserFlowRuns: REQUIRED_RUNS,
          summaryFlowSteps: REQUIRED_RUNS * 3,
        },
        apiRequestCounts: counts,
        secondaryMetricPolicy:
          'THIS_STAGE_6_RESULT_FREEZES_THE_LOCAL_BASELINE; CHANGES_OVER_10_PERCENT_REQUIRE_JUSTIFICATION',
        fieldMetrics: 'NOT_RUN_FIELD_REQUIRED',
        externalNetworkPolicy: 'DENY_LOOPBACK_ONLY',
        rawArtifacts: 'IN_MEMORY_ONLY_NOT_PERSISTED',
      };
    });
  } finally {
    await cleanupDirectory(parentDirectory);
  }
};
