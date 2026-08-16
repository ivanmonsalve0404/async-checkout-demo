#!/usr/bin/env node
/* global document, HTMLElement */
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { expect } from '@playwright/test';
import {
  PRODUCT_PATH,
  Stage6CheckError,
  VIEWPORTS,
  WEB_ORIGIN,
  check,
  createSyntheticPage,
  detectBrowserTargets,
  shouldBuild,
  withLocalPreview,
} from './harness.mjs';
import { evidenceBase, writeEvidence } from './evidence.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const SYNTHETIC_NUMBER_INPUT = ['4111', '1111', '1111', '1111'].join('');
const SYNTHETIC_CODE_INPUT = ['8', '7', '3'].join('');
const REQUIRED_JOURNEY_STATES = [
  'product',
  'capture-payment',
  'capture-validation',
  'summary',
  'pending',
  'unknown',
  'approved',
  'failed-declined',
];

const inspectLayout = (page) =>
  page.evaluate(() => {
    const root = document.documentElement;
    const cta = document.querySelector('[data-testid="product-checkout-cta"]');
    if (!(cta instanceof HTMLElement)) return { ready: false };
    const ctaRect = cta.getBoundingClientRect();
    return {
      ready: true,
      documentClientWidth: root.clientWidth,
      documentScrollWidth: root.scrollWidth,
      ctaWidth: ctaRect.width,
      ctaHeight: ctaRect.height,
    };
  });

const inspectDialog = (page) =>
  page.evaluate(() => {
    const root = document.documentElement;
    const dialog = document.querySelector('[data-testid="checkout-dialog"]');
    const body = document.querySelector('.dialog-body');
    if (!(dialog instanceof HTMLElement) || !(body instanceof HTMLElement)) {
      return { ready: false };
    }
    const rectangle = dialog.getBoundingClientRect();
    return {
      ready: true,
      documentClientWidth: root.clientWidth,
      documentScrollWidth: root.scrollWidth,
      bodyClientWidth: body.clientWidth,
      bodyScrollWidth: body.scrollWidth,
      x: rectangle.x,
      y: rectangle.y,
      right: rectangle.right,
      bottom: rectangle.bottom,
    };
  });

const runViewport = async (browser, viewport) => {
  const startedAt = Date.now();
  const { context, page, network } = await createSyntheticPage(browser, viewport);
  try {
    await page.goto(`${WEB_ORIGIN}${PRODUCT_PATH}`, { waitUntil: 'networkidle' });
    await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });

    const product = await inspectLayout(page);
    check(product.ready, 'PRODUCT_LAYOUT_NOT_READY');
    check(
      product.documentScrollWidth <= product.documentClientWidth + 1,
      'PRODUCT_HORIZONTAL_OVERFLOW',
    );
    check(product.ctaWidth >= 44 && product.ctaHeight >= 44, 'CTA_TARGET_BELOW_44_PX');

    await page.getByTestId('product-checkout-cta').click();
    await expect(page.getByTestId('checkout-dialog')).toBeVisible({ timeout: 5_000 });
    await expect(page.getByLabel('Número de tarjeta')).toBeVisible({ timeout: 5_000 });

    const dialog = await inspectDialog(page);
    check(dialog.ready, 'DIALOG_LAYOUT_NOT_READY');
    check(
      dialog.documentScrollWidth <= dialog.documentClientWidth + 1,
      'DIALOG_DOCUMENT_HORIZONTAL_OVERFLOW',
    );
    check(dialog.bodyScrollWidth <= dialog.bodyClientWidth + 1, 'DIALOG_BODY_HORIZONTAL_OVERFLOW');
    check(dialog.x >= -1 && dialog.right <= viewport.width + 1, 'DIALOG_CLIPPED_HORIZONTALLY');
    check(dialog.y >= -1 && dialog.bottom <= viewport.height + 1, 'DIALOG_CLIPPED_VERTICALLY');

    const counts = network.counts();
    check(counts.blockedExternalRequests === 0, 'EXTERNAL_REQUEST_ATTEMPTED');
    check(counts.unknownApiRequests === 0, 'UNDECLARED_SYNTHETIC_API_REQUEST');
    return {
      id: viewport.id,
      viewport: `${viewport.width}x${viewport.height}`,
      status: 'PASS',
      durationMs: Date.now() - startedAt,
      horizontalOverflowPx: Math.max(
        0,
        product.documentScrollWidth - product.documentClientWidth,
        dialog.documentScrollWidth - dialog.documentClientWidth,
        dialog.bodyScrollWidth - dialog.bodyClientWidth,
      ),
      minimumMeasuredTargetPx: Math.min(product.ctaWidth, product.ctaHeight),
      ...counts,
    };
  } catch (error) {
    return {
      id: viewport.id,
      viewport: `${viewport.width}x${viewport.height}`,
      status: 'FAIL',
      durationMs: Date.now() - startedAt,
      failureCode: error instanceof Stage6CheckError ? error.code : 'BROWSER_ASSERTION_FAILED',
      ...network.counts(),
    };
  } finally {
    await context.close();
  }
};

const observeJourneyState = async (page, observed, id, selector) => {
  check(REQUIRED_JOURNEY_STATES.includes(id), 'JOURNEY_STATE_NOT_REQUIRED');
  check(!observed.some(({ id: value }) => value === id), 'JOURNEY_STATE_DUPLICATED');
  const surface = page.locator(selector);
  try {
    await expect(surface).toBeVisible({ timeout: 5_000 });
  } catch {
    throw new Stage6CheckError(`JOURNEY_STATE_${id}_MISSING`);
  }
  check((await surface.count()) === 1, `JOURNEY_STATE_${id}_NOT_UNIQUE`);
  const layout = await surface.evaluate((element) => {
    const root = document.documentElement;
    const body = document.querySelector('.dialog-body');
    return {
      hasText: element.textContent?.trim().length > 0,
      documentOverflowPx: Math.max(0, root.scrollWidth - root.clientWidth),
      dialogBodyOverflowPx:
        body instanceof HTMLElement ? Math.max(0, body.scrollWidth - body.clientWidth) : 0,
    };
  });
  check(layout.hasText, `JOURNEY_STATE_${id}_EMPTY`);
  check(layout.documentOverflowPx <= 1, `JOURNEY_STATE_${id}_DOCUMENT_OVERFLOW`);
  check(layout.dialogBodyOverflowPx <= 1, `JOURNEY_STATE_${id}_DIALOG_OVERFLOW`);
  observed.push({ id, status: 'PASS', ...layout });
};

const runJourney = async (browser) => {
  const startedAt = Date.now();
  const observed = [];
  let pageErrors = 0;
  const { context, page, network } = await createSyntheticPage(browser, {
    width: 390,
    height: 844,
  });
  page.on('pageerror', () => {
    pageErrors += 1;
  });
  try {
    await page.goto(`${WEB_ORIGIN}${PRODUCT_PATH}`, { waitUntil: 'networkidle' });
    await observeJourneyState(page, observed, 'product', '[data-testid="product-surface"]');

    await page.getByTestId('product-checkout-cta').click();
    await observeJourneyState(
      page,
      observed,
      'capture-payment',
      '[data-testid="checkout-step-payment"]',
    );
    await page.getByTestId('payment-tokenize').click();
    await observeJourneyState(
      page,
      observed,
      'capture-validation',
      '[data-testid="checkout-step-payment"] .error-summary',
    );

    await page.locator('[name="payment-number"]').fill(SYNTHETIC_NUMBER_INPUT);
    await page.locator('[name="payment-expiry"]').fill('12/99');
    await page.locator('[name="payment-security-code"]').fill(SYNTHETIC_CODE_INPUT);
    await page.locator('[name="payment-holder"]').fill('Persona Sintética');
    await page.getByTestId('payment-tokenize').click();
    await expect(page.getByTestId('checkout-step-customer')).toBeVisible({ timeout: 5_000 });
    await page.locator('[name="fullName"]').fill('Persona Sintética');
    await page.locator('[name="email"]').fill('persona@example.test');
    await page.locator('[name="phone"]').fill('+573000000000');
    await page.locator('[name="addressLine1"]').fill('Calle sintética 123');
    await page.locator('[name="city"]').fill('Bogotá');
    await page.locator('[name="region"]').fill('Cundinamarca');
    await page.getByTestId('customer-delivery-save').click();
    await expect(page.getByTestId('checkout-step-acceptances')).toBeVisible({ timeout: 5_000 });
    const acceptances = page.locator(
      '[data-testid="checkout-step-acceptances"] input[type="checkbox"]',
    );
    check((await acceptances.count()) === 2, 'JOURNEY_ACCEPTANCE_CONTROLS_MISSING');
    for (let index = 0; index < 2; index += 1) await acceptances.nth(index).check();
    await page.getByTestId('acceptances-continue').click();
    await observeJourneyState(page, observed, 'summary', '[data-testid="checkout-step-review"]');

    await page.getByTestId('checkout-submit').click();
    await observeJourneyState(page, observed, 'pending', '[data-testid="transaction-pending"]');
    for (const [fixture, id] of [
      ['unknown', 'unknown'],
      ['approved', 'approved'],
      ['declined', 'failed-declined'],
    ]) {
      network.setTransactionPresentation(fixture);
      await page.reload({ waitUntil: 'networkidle' });
      await observeJourneyState(page, observed, id, `[data-testid="transaction-${fixture}"]`);
    }

    const observedIds = observed.map(({ id }) => id);
    const complete =
      observedIds.length === REQUIRED_JOURNEY_STATES.length &&
      REQUIRED_JOURNEY_STATES.every((id) => observedIds.includes(id));
    check(complete, 'JOURNEY_INVENTORY_INCOMPLETE');
    check(pageErrors === 0, 'JOURNEY_UNHANDLED_PAGE_ERROR');
    const counts = network.counts();
    check(counts.blockedExternalRequests === 0, 'EXTERNAL_REQUEST_ATTEMPTED');
    check(counts.unknownApiRequests === 0, 'UNDECLARED_SYNTHETIC_API_REQUEST');
    return {
      status: 'PASS',
      durationMs: Date.now() - startedAt,
      viewport: '390x844',
      inventory: {
        required: REQUIRED_JOURNEY_STATES,
        observed: observedIds,
        complete,
      },
      states: observed,
      pageErrors,
      ...counts,
    };
  } catch (error) {
    const observedIds = observed.map(({ id }) => id);
    return {
      status: 'FAIL',
      durationMs: Date.now() - startedAt,
      failureCode: error instanceof Stage6CheckError ? error.code : 'JOURNEY_ASSERTION_FAILED',
      viewport: '390x844',
      inventory: {
        required: REQUIRED_JOURNEY_STATES,
        observed: observedIds,
        complete: false,
      },
      states: observed,
      pageErrors,
      ...network.counts(),
    };
  } finally {
    await context.close();
  }
};

const unavailableJourney = (target) => ({
  status: target.status,
  reason: target.reason,
  inventory: { required: REQUIRED_JOURNEY_STATES, observed: [], complete: false },
  states: [],
});

const targetResult = async (target) => {
  if (target.launch === undefined) {
    return {
      id: target.id,
      status: target.status,
      reason: target.reason,
      viewports: [],
      journey: unavailableJourney(target),
    };
  }

  let browser;
  try {
    browser = await target.launch();
    const viewports = [];
    for (const viewport of VIEWPORTS) viewports.push(await runViewport(browser, viewport));
    const journey = await runJourney(browser);
    return {
      id: target.id,
      runtime: target.runtime,
      browserVersion: browser.version(),
      status:
        viewports.every(({ status }) => status === 'PASS') && journey.status === 'PASS'
          ? 'PASS'
          : 'FAIL',
      viewports,
      journey,
    };
  } catch {
    return {
      id: target.id,
      runtime: target.runtime,
      status: 'FAIL',
      reason: 'BROWSER_LAUNCH_OR_SUITE_FAILED',
      viewports: [],
      journey: {
        status: 'FAIL',
        reason: 'BROWSER_LAUNCH_OR_SUITE_FAILED',
        inventory: { required: REQUIRED_JOURNEY_STATES, observed: [], complete: false },
        states: [],
      },
    };
  } finally {
    await browser?.close().catch(() => undefined);
  }
};

const targets = detectBrowserTargets();
const results = await withLocalPreview(
  async () => {
    const matrix = [];
    for (const target of targets) matrix.push(await targetResult(target));
    return matrix;
  },
  { build: shouldBuild() },
);

const failed = results.some(({ status }) => status === 'FAIL');
const unavailable = results.some(({ status }) => status === 'NOT_RUN_ENV_REQUIRED');
const status = failed ? 'FAIL' : unavailable ? 'PARTIAL_NOT_RUN_ENV_REQUIRED' : 'PASS';
const report = {
  ...(await evidenceBase({
    command: 'node scripts/stage6/compat/run.mjs',
    scriptPath: SCRIPT_PATH,
    tool: { name: '@playwright/test', version: '1.61.1' },
  })),
  status,
  requiredEngines: ['chromium', 'firefox', 'webkit'],
  requiredViewports: VIEWPORTS.map(({ id, width, height }) => ({ id, width, height })),
  requiredJourneyStates: REQUIRED_JOURNEY_STATES,
  results,
  summary: {
    enginesPassed: results.filter(({ status: value }) => value === 'PASS').length,
    enginesRequired: 3,
    responsiveCasesPassed: results
      .flatMap(({ viewports }) => viewports)
      .filter(({ status: value }) => value === 'PASS').length,
    responsiveCasesExecuted: results.flatMap(({ viewports }) => viewports).length,
    journeyInventoriesComplete: results.filter(({ journey }) => journey.inventory.complete).length,
    journeyInventoriesRequired: 3,
    journeyStatesPassed: results.flatMap(({ journey }) => journey.states).length,
    journeyStatesRequired: REQUIRED_JOURNEY_STATES.length * 3,
  },
};

await writeEvidence('compatibility', report);
if (failed) process.exitCode = 1;
else if (unavailable && !process.argv.includes('--allow-partial')) process.exitCode = 2;
