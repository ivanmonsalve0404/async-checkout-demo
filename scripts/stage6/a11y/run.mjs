#!/usr/bin/env node
/* global document, HTMLElement, matchMedia */
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { expect } from '@playwright/test';
import {
  PRODUCT_ID,
  PRODUCT_PATH,
  ROOT,
  Stage6CheckError,
  WEB_ORIGIN,
  check,
  detectBrowserTargets,
  shouldBuild,
  withLocalPreview,
} from '../compat/harness.mjs';
import { evidenceBase, writeEvidence } from '../compat/evidence.mjs';
import {
  ManualEvidenceError,
  axeIncompleteInventory,
  loadManualEvidence,
  manualEvidencePath,
  selfTestManualEvidence,
  selfTestManualEvidenceLoader,
} from './manual-evidence.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const requireFromWeb = createRequire(path.join(ROOT, 'apps', 'web', 'package.json'));
const CHECKOUT_ID = 'checkout_e6_a11y_001';
const TRANSACTION_ID = 'transaction_e6_a11y_001';
const SYNTHETIC_PAYMENT_NUMBER = ['4111', '1111', '1111', '1111'].join('');
const SYNTHETIC_PAYMENT_SECURITY_CODE = ['8', '7', '3'].join('');
const STATUS_PATH = `${PRODUCT_PATH}/checkout/status`;
const REQUIRED_SURFACES = [
  'product',
  'checkout-payment',
  'payment-validation',
  'checkout-customer',
  'customer-validation',
  'checkout-acceptances',
  'acceptances-validation',
  'checkout-summary',
  'transaction-pending',
  'transaction-unknown',
  'transaction-approved',
  'transaction-declined',
  'transaction-error',
  'transaction-network-error',
];

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
  quoteId: 'quote_e6_a11y_001',
  version: 1,
  productId: PRODUCT_ID,
  quantity: 1,
  subtotal: product.unitPrice,
  baseFee: { amountInCents: 125_000, currency: 'COP' },
  deliveryFee: { amountInCents: 75_000, currency: 'COP' },
  total: { amountInCents: 2_700_000, currency: 'COP' },
  expiresAt: '2099-01-01T00:00:00.000Z',
};
const paymentConfiguration = {
  captureVariant: 'FAKE_CONTRACT',
  sandboxPublicKey: ['synthetic', 'a11y', 'material'].join('-'),
  allowedInstallments: [1, 3, 6],
  acceptanceContracts: [
    {
      type: 'TERMS',
      permalink: `${WEB_ORIGIN}/legal/terms-v1.html`,
      version: 'terms-v1',
      acceptanceToken: ['terms', 'a11y', 'synthetic', 'material'].join('-'),
    },
    {
      type: 'PERSONAL_DATA',
      permalink: `${WEB_ORIGIN}/legal/personal-data-v1.html`,
      version: 'personal-data-v1',
      acceptanceToken: ['personal-data', 'a11y', 'synthetic', 'material'].join('-'),
    },
  ],
  expiresAt: '2099-01-01T00:00:00.000Z',
};

const newCheckout = () => ({
  checkoutId: CHECKOUT_ID,
  status: 'DRAFT',
  version: 1,
  product,
  quote,
  customer: null,
  deliveryDetails: null,
  activeTransactionId: null,
  expiresAt: '2099-01-01T00:00:00.000Z',
});

const resolveAxe = async () => {
  try {
    const sourcePath = createRequire(requireFromWeb.resolve('jest-axe')).resolve(
      'axe-core/axe.min.js',
    );
    const manifest = JSON.parse(
      await readFile(path.join(path.dirname(sourcePath), 'package.json'), 'utf8'),
    );
    return { sourcePath, version: manifest.version };
  } catch {
    return undefined;
  }
};

const isLoopback = (candidate) => {
  const url = new URL(candidate);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return true;
  return url.hostname === '127.0.0.1' || url.hostname === 'localhost';
};

const fulfillJson = (route, body, status = 200) =>
  route.fulfill({
    status,
    contentType: 'application/json',
    headers: { 'cache-control': 'no-store' },
    body: JSON.stringify(body),
  });

const transactionFixture = (presentation) => {
  const acceptedAt = new Date().toISOString();
  const common = {
    transactionId: TRANSACTION_ID,
    checkoutId: CHECKOUT_ID,
    statusUrl: `/api/v1/transactions/${TRANSACTION_ID}`,
    acceptedAt,
    updatedAt: acceptedAt,
    integrityStatus: 'OK',
  };
  if (presentation === 'approved') {
    return {
      ...common,
      checkoutStatus: 'PAID',
      paymentStatus: 'APPROVED',
      dispatchPhase: 'ACKNOWLEDGED',
      providerStatus: 'APPROVED',
      reservationStatus: 'CONSUMED',
      deliveryId: 'delivery_e6_a11y_001',
      allowedActions: ['QUERY', 'RETURN_TO_PRODUCT'],
    };
  }
  if (presentation === 'declined') {
    return {
      ...common,
      checkoutStatus: 'PAYMENT_FAILED',
      paymentStatus: 'DECLINED',
      dispatchPhase: 'ACKNOWLEDGED',
      providerStatus: 'DECLINED',
      reservationStatus: 'RELEASED',
      allowedActions: ['QUERY', 'RETURN_TO_PRODUCT', 'START_NEW_CHECKOUT'],
    };
  }
  if (presentation === 'error') {
    return {
      ...common,
      checkoutStatus: 'PAYMENT_FAILED',
      paymentStatus: 'ERROR',
      dispatchPhase: 'NOT_SENT_FAILED',
      providerStatus: 'ERROR',
      reservationStatus: 'RELEASED',
      recoveryCode: 'INTERNAL_ERROR',
      allowedActions: ['QUERY', 'RETURN_TO_PRODUCT', 'START_NEW_CHECKOUT', 'CONTACT_SUPPORT'],
    };
  }
  return {
    ...common,
    checkoutStatus: 'PAYMENT_PENDING',
    paymentStatus: 'PENDING',
    dispatchPhase: presentation === 'unknown' ? 'UNKNOWN' : 'ACKNOWLEDGED',
    providerStatus: presentation === 'unknown' ? null : 'PENDING',
    reservationStatus: 'ACTIVE',
    ...(presentation === 'unknown' ? { recoveryCode: 'PROVIDER_OUTCOME_UNKNOWN' } : {}),
    allowedActions: ['QUERY', 'WAIT', 'RETURN_TO_PRODUCT'],
    retryAfterSeconds: 2,
  };
};

const installA11yNetwork = async (context) => {
  let checkout = newCheckout();
  let transactionPresentation = 'pending';
  let transactionNetworkError = false;
  let blockedExternalRequests = 0;
  let unknownApiRequests = 0;
  let apiRequests = 0;

  await context.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (!isLoopback(url.href)) {
      blockedExternalRequests += 1;
      await route.abort('blockedbyclient');
      return;
    }
    if (!url.pathname.startsWith('/api/v1/')) {
      await route.continue();
      return;
    }
    apiRequests += 1;
    const key = `${request.method()} ${url.pathname}`;
    try {
      if (key === `GET /api/v1/products/${PRODUCT_ID}`) {
        await fulfillJson(route, product);
      } else if (key === 'POST /api/v1/checkouts') {
        checkout = newCheckout();
        await fulfillJson(
          route,
          {
            checkoutId: CHECKOUT_ID,
            status: 'DRAFT',
            version: 1,
            quote,
            expiresAt: checkout.expiresAt,
          },
          201,
        );
      } else if (key === `GET /api/v1/checkouts/${CHECKOUT_ID}`) {
        await fulfillJson(route, checkout);
      } else if (key === `PUT /api/v1/checkouts/${CHECKOUT_ID}/customer`) {
        const body = request.postDataJSON();
        const customer = {
          customerId: 'customer_e6_a11y_001',
          checkoutId: CHECKOUT_ID,
          version: checkout.version + 1,
          fullName: body.fullName,
          email: body.email,
          phone: body.phone,
        };
        checkout = { ...checkout, customer, version: customer.version };
        await fulfillJson(route, customer);
      } else if (key === `PUT /api/v1/checkouts/${CHECKOUT_ID}/delivery-details`) {
        const body = request.postDataJSON();
        const deliveryDetails = {
          checkoutId: CHECKOUT_ID,
          version: checkout.version + 1,
          ...body,
        };
        checkout = {
          ...checkout,
          status: 'READY',
          deliveryDetails,
          version: deliveryDetails.version,
        };
        await fulfillJson(route, deliveryDetails);
      } else if (key === 'GET /api/v1/payment-configuration') {
        await fulfillJson(route, paymentConfiguration);
      } else if (key === `POST /api/v1/checkouts/${CHECKOUT_ID}/transactions`) {
        checkout = {
          ...checkout,
          status: 'PAYMENT_PENDING',
          version: checkout.version + 1,
          activeTransactionId: TRANSACTION_ID,
        };
        transactionPresentation = 'pending';
        transactionNetworkError = false;
        await fulfillJson(
          route,
          {
            transactionId: TRANSACTION_ID,
            statusUrl: `/api/v1/transactions/${TRANSACTION_ID}`,
            submissionState: 'ACCEPTED',
            acceptedAt: new Date().toISOString(),
          },
          202,
        );
      } else if (key === `GET /api/v1/transactions/${TRANSACTION_ID}`) {
        if (transactionNetworkError) await fulfillJson(route, { code: 'SYNTHETIC_ERROR' }, 503);
        else await fulfillJson(route, transactionFixture(transactionPresentation));
      } else {
        unknownApiRequests += 1;
        await fulfillJson(route, { code: 'E6_A11Y_ROUTE_MISSING' }, 501);
      }
    } catch {
      await fulfillJson(route, { code: 'E6_A11Y_FIXTURE_ERROR' }, 500);
    }
  });

  return {
    counts: () => ({ blockedExternalRequests, unknownApiRequests, apiRequests }),
    setTransactionPresentation: (value) => {
      transactionNetworkError = value === 'network-error';
      if (!transactionNetworkError) transactionPresentation = value;
    },
  };
};

const scanSurface = async (page, id, selector, requiredStateSelector = selector) => {
  check(REQUIRED_SURFACES.includes(id), 'A11Y_SURFACE_NOT_IN_INVENTORY');
  check((await page.locator(requiredStateSelector).count()) === 1, `A11Y_SURFACE_${id}_MISSING`);
  const result = await page.evaluate(
    async ({ contextSelector }) => {
      const root = document.querySelector(contextSelector);
      if (!(root instanceof HTMLElement)) return { missing: true };
      const ids = [...document.querySelectorAll('[id]')].map((element) => element.id);
      const duplicateIds = [...new Set(ids.filter((value, index) => ids.indexOf(value) !== index))];
      const axeResult = await globalThis.axe.run(root, {
        runOnly: {
          type: 'tag',
          values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'],
        },
      });
      const summarize = (findings) =>
        findings.map(({ id: ruleId, impact, nodes }) => ({
          id: ruleId,
          impact,
          nodeCount: nodes.length,
        }));
      return {
        missing: false,
        domIdCount: ids.length,
        duplicateIds,
        violations: summarize(axeResult.violations),
        incomplete: summarize(axeResult.incomplete),
      };
    },
    { contextSelector: selector },
  );
  check(!result.missing, `A11Y_SURFACE_${id}_MISSING`);
  check(result.duplicateIds.length === 0, `A11Y_SURFACE_${id}_DUPLICATE_DOM_IDS`);
  check(
    !result.violations.some(({ impact }) => impact === 'critical' || impact === 'serious'),
    `A11Y_SURFACE_${id}_HIGH_IMPACT_VIOLATION`,
  );
  check(result.violations.length === 0, `A11Y_SURFACE_${id}_UNTRIAGED_VIOLATION`);
  return {
    surface: id,
    status: 'PASS',
    domIdsUnique: true,
    domIdCount: result.domIdCount,
    violations: result.violations,
    incomplete: result.incomplete,
  };
};

const focusCycleCheck = async (page) => {
  const selector =
    'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  const prepared = await page.evaluate((candidate) => {
    const dialog = document.querySelector('[data-testid="checkout-dialog"]');
    if (!(dialog instanceof HTMLElement)) return false;
    const focusable = [...dialog.querySelectorAll(candidate)].filter(
      (element) => element instanceof HTMLElement,
    );
    const first = focusable[0];
    const last = focusable.at(-1);
    if (!(first instanceof HTMLElement) || !(last instanceof HTMLElement)) return false;
    first.dataset.stage6First = 'true';
    last.dataset.stage6Last = 'true';
    last.focus();
    return true;
  }, selector);
  check(prepared, 'FOCUSABLE_BOUNDARIES_MISSING');
  await page.keyboard.press('Tab');
  check(
    await page.evaluate(() => document.activeElement?.getAttribute('data-stage6-first') === 'true'),
    'FORWARD_FOCUS_CYCLE_FAILED',
  );
  await page.keyboard.press('Shift+Tab');
  check(
    await page.evaluate(() => document.activeElement?.getAttribute('data-stage6-last') === 'true'),
    'BACKWARD_FOCUS_CYCLE_FAILED',
  );
};

const activate = async (page, locator, key = 'Enter') => {
  await locator.focus();
  await expect(locator).toBeFocused({ timeout: 5_000 });
  await page.keyboard.press(key);
};

const expectHeadingFocus = async (page) => {
  const heading = page.locator('#checkout-step-title');
  await expect(heading).toBeVisible({ timeout: 5_000 });
  await expect(heading).toBeFocused({ timeout: 5_000 });
};

const runAutomated = async (target, axe) => {
  let browser;
  let context;
  let network;
  const axeScans = [];
  const startedAt = Date.now();
  try {
    browser = await target.launch();
    context = await browser.newContext({
      viewport: { width: 390, height: 844 },
      locale: 'es-CO',
      colorScheme: 'light',
      reducedMotion: 'reduce',
    });
    network = await installA11yNetwork(context);
    await context.addInitScript({ path: axe.sourcePath });
    const page = await context.newPage();

    await page.goto(`${WEB_ORIGIN}${PRODUCT_PATH}`, { waitUntil: 'networkidle' });
    await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
    axeScans.push(await scanSurface(page, 'product', '[data-testid="product-surface"]'));
    check(
      await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
      'REDUCED_MOTION_EMULATION_FAILED',
    );

    await activate(page, page.getByTestId('product-checkout-cta'));
    await expect(page.getByTestId('checkout-step-payment')).toBeVisible({ timeout: 5_000 });
    await expectHeadingFocus(page);
    check(
      await page
        .getByTestId('product-surface')
        .evaluate((element) => element.hasAttribute('inert')),
      'BACKGROUND_NOT_INERT',
    );
    axeScans.push(await scanSurface(page, 'checkout-payment', '[data-testid="checkout-dialog"]'));
    await focusCycleCheck(page);

    await activate(page, page.getByTestId('payment-tokenize'));
    await expect(page.locator('[data-testid="checkout-step-payment"] .error-summary')).toBeFocused({
      timeout: 5_000,
    });
    axeScans.push(
      await scanSurface(
        page,
        'payment-validation',
        '[data-testid="checkout-step-payment"]',
        '[data-testid="checkout-step-payment"] .error-summary',
      ),
    );

    await page.locator('[name="payment-number"]').fill(SYNTHETIC_PAYMENT_NUMBER);
    await page.locator('[name="payment-expiry"]').fill('12/99');
    await page.locator('[name="payment-security-code"]').fill(SYNTHETIC_PAYMENT_SECURITY_CODE);
    await page.locator('[name="payment-holder"]').fill('Persona Sintética');
    await activate(page, page.getByTestId('payment-tokenize'));
    await expect(page.getByTestId('checkout-step-customer')).toBeVisible({ timeout: 5_000 });
    await expectHeadingFocus(page);
    axeScans.push(
      await scanSurface(page, 'checkout-customer', '[data-testid="checkout-step-customer"]'),
    );

    await activate(page, page.getByTestId('customer-delivery-save'));
    await expect(page.locator('[data-testid="checkout-step-customer"] .error-summary')).toBeFocused(
      {
        timeout: 5_000,
      },
    );
    axeScans.push(
      await scanSurface(
        page,
        'customer-validation',
        '[data-testid="checkout-step-customer"]',
        '[data-testid="checkout-step-customer"] .error-summary',
      ),
    );

    await page.locator('[name="fullName"]').fill('Persona Sintética');
    await page.locator('[name="email"]').fill('persona@example.test');
    await page.locator('[name="phone"]').fill('+573000000000');
    await page.locator('[name="addressLine1"]').fill('Calle sintética 123');
    await page.locator('[name="city"]').fill('Bogotá');
    await page.locator('[name="region"]').fill('Cundinamarca');
    await activate(page, page.getByTestId('customer-delivery-save'));
    await expect(page.getByTestId('checkout-step-acceptances')).toBeVisible({ timeout: 5_000 });
    await expectHeadingFocus(page);
    axeScans.push(
      await scanSurface(page, 'checkout-acceptances', '[data-testid="checkout-step-acceptances"]'),
    );

    await activate(page, page.getByTestId('acceptances-continue'));
    await expect(
      page.locator('[data-testid="checkout-step-acceptances"] .error-summary'),
    ).toBeFocused({ timeout: 5_000 });
    axeScans.push(
      await scanSurface(
        page,
        'acceptances-validation',
        '[data-testid="checkout-step-acceptances"]',
        '[data-testid="checkout-step-acceptances"] .error-summary',
      ),
    );

    const acceptances = page.locator(
      '[data-testid="checkout-step-acceptances"] input[type="checkbox"]',
    );
    check((await acceptances.count()) === 2, 'A11Y_ACCEPTANCE_CONTROLS_MISSING');
    for (let index = 0; index < 2; index += 1) {
      const acceptance = acceptances.nth(index);
      await activate(page, acceptance, 'Space');
      await expect(acceptance).toBeChecked();
    }
    await activate(page, page.getByTestId('acceptances-continue'));
    await expect(page.getByTestId('checkout-step-review')).toBeVisible({ timeout: 5_000 });
    await expectHeadingFocus(page);
    axeScans.push(
      await scanSurface(page, 'checkout-summary', '[data-testid="checkout-step-review"]'),
    );

    await activate(page, page.getByTestId('checkout-submit'));
    await expect(page).toHaveURL(`${WEB_ORIGIN}${STATUS_PATH}`, { timeout: 5_000 });
    await expect(page.getByTestId('transaction-pending')).toBeVisible({ timeout: 5_000 });
    await expectHeadingFocus(page);
    axeScans.push(
      await scanSurface(page, 'transaction-pending', '[data-testid="transaction-pending"]'),
    );

    for (const presentation of ['unknown', 'approved', 'declined', 'error', 'network-error']) {
      network.setTransactionPresentation(presentation);
      await page.reload({ waitUntil: 'networkidle' });
      const surface = `transaction-${presentation}`;
      await expect(page.getByTestId(surface)).toBeVisible({ timeout: 5_000 });
      await expectHeadingFocus(page);
      axeScans.push(await scanSurface(page, surface, `[data-testid="${surface}"]`));
    }

    check(axeScans.length === REQUIRED_SURFACES.length, 'A11Y_SURFACE_COUNT_MISMATCH');
    check(
      new Set(axeScans.map(({ surface }) => surface)).size === REQUIRED_SURFACES.length,
      'A11Y_SURFACE_IDS_NOT_UNIQUE',
    );
    check(
      REQUIRED_SURFACES.every((id) => axeScans.some(({ surface }) => surface === id)),
      'A11Y_REQUIRED_SURFACE_MISSING',
    );

    await page.keyboard.press('Escape');
    try {
      await expect(page.getByTestId('checkout-dialog')).toHaveCount(0, { timeout: 5_000 });
    } catch {
      throw new Stage6CheckError('ESCAPE_DID_NOT_CLOSE_DIALOG');
    }
    try {
      await expect(page.getByTestId('product-checkout-cta')).toBeFocused({
        timeout: 5_000,
      });
    } catch {
      throw new Stage6CheckError('ESCAPE_DID_NOT_RESTORE_OPENER_FOCUS');
    }

    const counts = network.counts();
    check(counts.blockedExternalRequests === 0, 'EXTERNAL_REQUEST_ATTEMPTED');
    check(counts.unknownApiRequests === 0, 'UNDECLARED_SYNTHETIC_API_REQUEST');
    return {
      status: 'PASS',
      durationMs: Date.now() - startedAt,
      runtime: target.runtime,
      browserVersion: browser.version(),
      viewport: '390x844',
      requiredSurfaces: REQUIRED_SURFACES,
      surfaceCoverage: `${axeScans.length}/${REQUIRED_SURFACES.length}`,
      axeScans,
      axeIncompleteCount: axeScans.reduce((total, surface) => total + surface.incomplete.length, 0),
      keyboardDialogContract: 'PASS',
      keyboardFocusContract: 'PASS',
      keyboardFocusCoverage: [
        'dialog-forward-and-backward-focus-cycle',
        'step-heading-focus-on-transition',
        'validation-summary-focus',
        'pending-and-final-state-focus',
        'escape-close-and-opener-focus-return',
      ],
      reducedMotionEmulation: 'PASS',
      ...counts,
    };
  } catch (error) {
    return {
      status: 'FAIL',
      durationMs: Date.now() - startedAt,
      failureCode: error instanceof Stage6CheckError ? error.code : 'A11Y_ASSERTION_FAILED',
      requiredSurfaces: REQUIRED_SURFACES,
      surfacesCompleted: axeScans.map(({ surface }) => surface),
      axeScans,
      ...(network?.counts() ?? {}),
    };
  } finally {
    await context?.close().catch(() => undefined);
    await browser?.close().catch(() => undefined);
  }
};

const missingManualEvidence = (requiredAxeIncompleteReviews) => ({
  status: 'NOT_RUN_MANUAL_REQUIRED',
  reason: 'MANUAL_EVIDENCE_NOT_PROVIDED',
  acceptedChannels: ['--manual-evidence <json>', 'STAGE6_A11Y_MANUAL_EVIDENCE=<json>'],
  requiredAxeIncompleteReviews,
  containsSensitiveData: false,
});

const manualAssessments = (manual) => {
  const status = (key) =>
    manual.source === 'EXTERNAL_VERSIONED_JSON'
      ? manual.assessments[key]
      : 'NOT_RUN_MANUAL_REQUIRED';
  return [
    { scope: 'screen-reader-announcements', status: status('screenReader') },
    { scope: 'zoom-200-percent-and-reflow', status: status('zoom200Reflow') },
    { scope: 'forced-colors-visual-review', status: status('forcedColors') },
    { scope: 'axe-incomplete-review', status: status('axeIncompleteReview') },
    { scope: 'hosted-component-semantics', status: 'NOT_RUN_AUTH_REQUIRED' },
  ];
};

const run = async () => {
  selfTestManualEvidence();
  let configuredManualPath;
  let manualConfigurationError;
  try {
    configuredManualPath = manualEvidencePath();
  } catch (error) {
    manualConfigurationError = error;
  }

  const axe = await resolveAxe();
  const chromiumTarget = detectBrowserTargets().find(({ id }) => id === 'chromium');
  let automated;
  if (axe === undefined) {
    automated = { status: 'NOT_RUN_ENV_REQUIRED', reason: 'AXE_CORE_MISSING' };
  } else if (chromiumTarget?.launch === undefined) {
    automated = { status: 'NOT_RUN_ENV_REQUIRED', reason: 'CHROMIUM_RUNTIME_MISSING' };
  } else {
    automated = await withLocalPreview(() => runAutomated(chromiumTarget, axe), {
      build: shouldBuild(),
    });
  }

  const base = await evidenceBase({
    command: 'node scripts/stage6/a11y/run.mjs',
    scriptPath: SCRIPT_PATH,
    tool: {
      name: 'axe-core + @playwright/test',
      version: `${axe?.version ?? 'MISSING'} + 1.62.1`,
    },
  });
  const requiredAxeIncompleteReviews = axeIncompleteInventory(automated.axeScans);
  let manual = missingManualEvidence(requiredAxeIncompleteReviews);
  if (manualConfigurationError instanceof ManualEvidenceError) {
    manual = {
      status: 'FAIL',
      failureCode: manualConfigurationError.code,
      containsSensitiveData: false,
    };
  } else if (configuredManualPath !== undefined) {
    try {
      manual = await loadManualEvidence({
        sourcePath: configuredManualPath,
        commitSha: base.commitSha,
        ingestedByRunId: base.runId,
        axeIncompleteInventory: requiredAxeIncompleteReviews,
      });
    } catch (error) {
      manual = {
        status: 'FAIL',
        failureCode:
          error instanceof ManualEvidenceError ? error.code : 'MANUAL_EVIDENCE_INGESTION_FAILED',
        containsSensitiveData: false,
      };
    }
  }

  const status =
    automated.status === 'FAIL' || manual.status === 'FAIL'
      ? 'FAIL'
      : automated.status === 'NOT_RUN_ENV_REQUIRED'
        ? 'NOT_RUN_ENV_REQUIRED'
        : manual.status === 'PASS'
          ? 'PASS'
          : 'PARTIAL_NOT_RUN_MANUAL_REQUIRED';
  const report = {
    ...base,
    status,
    baseline: 'WCAG 2.2 AA; APG dialog contract',
    automated,
    existingUnitAxeCoverage: [
      'apps/web/src/features/product/components/product-view.spec.tsx',
      'apps/web/src/features/checkout/components/card-step.spec.tsx',
    ],
    manualEvidence: manual,
    manualAssessments: manualAssessments(manual),
    declaration: 'NO_WCAG_CONFORMANCE_CLAIM',
  };

  await writeEvidence('accessibility', report);
  if (status === 'FAIL') process.exitCode = 1;
  else if (status === 'NOT_RUN_ENV_REQUIRED') process.exitCode = 2;
};

if (process.argv.includes('--self-test')) {
  selfTestManualEvidence();
  await selfTestManualEvidenceLoader();
  process.stdout.write('stage-6 a11y manual evidence self-test: PASS\n');
} else {
  await run();
}
