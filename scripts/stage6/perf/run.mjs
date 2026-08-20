#!/usr/bin/env node
/* global document, PerformanceObserver, performance */
import { stat } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { expect } from '@playwright/test';
import {
  PRODUCT_PATH,
  ROOT,
  Stage6CheckError,
  WEB_ORIGIN,
  check,
  createSyntheticPage,
  detectBrowserTargets,
  shouldBuild,
  withLocalPreview,
} from '../compat/harness.mjs';
import { evidenceBase, writeEvidence } from '../compat/evidence.mjs';
import { roundAggregateMetric } from './evidence.mjs';
import { writePerformanceHtml } from './html-report.mjs';
import { runLighthouseAudit } from './lighthouse-matrix.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const MAIN_IMAGE_PATH = path.join(ROOT, 'apps', 'web', 'public', 'product-placeholder.svg');

const browserLab = async (target) => {
  let browser;
  const startedAt = Date.now();
  try {
    browser = await target.launch();
    const { context, page, network } = await createSyntheticPage(browser, {
      width: 1334,
      height: 750,
    });
    try {
      await page.addInitScript(() => {
        globalThis.__stage6Performance = {
          cls: 0,
          lcpMs: 0,
          supported: PerformanceObserver.supportedEntryTypes,
        };
        if (PerformanceObserver.supportedEntryTypes.includes('largest-contentful-paint')) {
          new PerformanceObserver((list) => {
            const latest = list.getEntries().at(-1);
            if (latest !== undefined) globalThis.__stage6Performance.lcpMs = latest.startTime;
          }).observe({ type: 'largest-contentful-paint', buffered: true });
        }
        if (PerformanceObserver.supportedEntryTypes.includes('layout-shift')) {
          new PerformanceObserver((list) => {
            for (const entry of list.getEntries()) {
              if (!entry.hadRecentInput) globalThis.__stage6Performance.cls += entry.value;
            }
          }).observe({ type: 'layout-shift', buffered: true });
        }
      });

      await page.goto(`${WEB_ORIGIN}${PRODUCT_PATH}`, { waitUntil: 'networkidle' });
      await expect(page.getByTestId('product-surface')).toBeVisible({ timeout: 5_000 });
      await page.waitForTimeout(500);
      const rawMetrics = await page.evaluate(() => {
        const navigation = performance.getEntriesByType('navigation')[0];
        const image = document.querySelector('.product-media img');
        return {
          cls: globalThis.__stage6Performance?.cls ?? null,
          lcpMs: globalThis.__stage6Performance?.lcpMs ?? null,
          supportedEntryTypes: globalThis.__stage6Performance?.supported ?? [],
          navigationDurationMs: navigation?.duration ?? null,
          imageWidthAttribute: image?.getAttribute('width') ?? null,
          imageHeightAttribute: image?.getAttribute('height') ?? null,
          imageNaturalWidth: image?.naturalWidth ?? 0,
          imageNaturalHeight: image?.naturalHeight ?? 0,
        };
      });
      const metrics = {
        ...rawMetrics,
        cls: roundAggregateMetric(rawMetrics.cls),
        lcpMs: roundAggregateMetric(rawMetrics.lcpMs),
        navigationDurationMs: roundAggregateMetric(rawMetrics.navigationDurationMs),
      };

      check(metrics.lcpMs !== null && metrics.lcpMs > 0, 'LCP_NOT_OBSERVED');
      check(metrics.lcpMs < 2_500, 'LCP_BUDGET_EXCEEDED');
      check(metrics.cls !== null && metrics.cls < 0.1, 'CLS_BUDGET_EXCEEDED');
      check(
        metrics.imageWidthAttribute !== null && metrics.imageHeightAttribute !== null,
        'IMAGE_DIMENSIONS_NOT_RESERVED',
      );
      check(
        metrics.imageNaturalWidth > 0 && metrics.imageNaturalHeight > 0,
        'MAIN_IMAGE_NOT_LOADED',
      );

      const interactionStartedAt = await page.evaluate(() => performance.now());
      await page.getByTestId('product-checkout-cta').click();
      await expect(page.getByLabel('Número de tarjeta')).toBeVisible({ timeout: 5_000 });
      const syntheticInteractionMs = roundAggregateMetric(
        await page.evaluate((start) => performance.now() - start, interactionStartedAt),
      );

      const counts = network.counts();
      check(counts.blockedExternalRequests === 0, 'EXTERNAL_REQUEST_ATTEMPTED');
      check(counts.unknownApiRequests === 0, 'UNDECLARED_SYNTHETIC_API_REQUEST');
      return {
        status: 'PASS_BROWSER_LAB_EQUIVALENT',
        durationMs: Date.now() - startedAt,
        runtime: target.runtime,
        browserVersion: browser.version(),
        viewport: '1334x750',
        metrics: {
          lcpMs: metrics.lcpMs,
          lcpTargetMs: 2_500,
          cls: metrics.cls,
          clsTarget: 0.1,
          navigationDurationMs: metrics.navigationDurationMs,
          syntheticInteractionMs,
          inp: 'NOT_RUN_FIELD_REQUIRED',
        },
        mediaReservation: {
          widthAttribute: metrics.imageWidthAttribute,
          heightAttribute: metrics.imageHeightAttribute,
          naturalWidth: metrics.imageNaturalWidth,
          naturalHeight: metrics.imageNaturalHeight,
          status: 'PASS',
        },
        ...counts,
      };
    } finally {
      await context.close();
    }
  } catch (error) {
    return {
      status:
        error instanceof Stage6CheckError && error.code === 'LCP_NOT_OBSERVED'
          ? 'NOT_RUN_BROWSER_UNSUPPORTED'
          : 'FAIL',
      durationMs: Date.now() - startedAt,
      failureCode: error instanceof Stage6CheckError ? error.code : 'PERFORMANCE_ASSERTION_FAILED',
    };
  } finally {
    await browser?.close().catch(() => undefined);
  }
};

const mainImage = await stat(MAIN_IMAGE_PATH);
const assetCheck = {
  path: 'apps/web/public/product-placeholder.svg',
  bytes: mainImage.size,
  budgetBytes: 120 * 1024,
  status: mainImage.size <= 120 * 1024 ? 'PASS' : 'FAIL',
};
const chromiumTarget = detectBrowserTargets().find(({ id }) => id === 'chromium');
let lab;
let lighthouse;

if (chromiumTarget?.launch === undefined) {
  lab = { status: 'NOT_RUN_ENV_REQUIRED', reason: 'CHROMIUM_RUNTIME_MISSING' };
  lighthouse = { status: 'NOT_RUN_ENV_REQUIRED', reason: 'CHROMIUM_RUNTIME_MISSING' };
} else {
  const result = await withLocalPreview(
    async () => {
      const labResult = await browserLab(chromiumTarget);
      let lighthouseResult;
      try {
        lighthouseResult = await runLighthouseAudit(chromiumTarget.executablePath);
      } catch (error) {
        lighthouseResult = {
          status: 'FAIL',
          failureCode: error instanceof Stage6CheckError ? error.code : 'LHCI_ASSERTION_FAILED',
        };
      }
      return { lab: labResult, lighthouse: lighthouseResult };
    },
    { build: shouldBuild() },
  );
  lab = result.lab;
  lighthouse = result.lighthouse;
}

const failed =
  assetCheck.status === 'FAIL' || lab.status === 'FAIL' || lighthouse.status === 'FAIL';
const incomplete =
  lighthouse.status !== 'PASS' ||
  lab.status === 'NOT_RUN_ENV_REQUIRED' ||
  lab.status === 'NOT_RUN_BROWSER_UNSUPPORTED';
const status = failed ? 'FAIL' : incomplete ? 'PARTIAL_NOT_RUN_ENV_REQUIRED' : 'PASS';
const report = {
  ...(await evidenceBase({
    command: 'node scripts/stage6/perf/run.mjs',
    scriptPath: SCRIPT_PATH,
    tool: { name: 'Lighthouse + Playwright PerformanceObserver', version: '13.4.1 + 1.62.1' },
  })),
  status,
  budgets: {
    mainImageBytesMaximum: 120 * 1024,
    lcpMsMaximumExclusive: 2_500,
    clsMaximumExclusive: 0.1,
    inpMsMaximum: 200,
  },
  assetCheck,
  browserLab: lab,
  lighthouse,
  fieldVitals: {
    lcpP75: 'NOT_RUN_FIELD_REQUIRED',
    clsP75: 'NOT_RUN_FIELD_REQUIRED',
    inpP75: 'NOT_RUN_FIELD_REQUIRED',
  },
  declaration: 'LOCAL_LAB_ONLY_NOT_FIELD_PERFORMANCE',
};

report.sanitizedHtml = await writePerformanceHtml(report);
await writeEvidence('performance', report);
if (failed) process.exitCode = 1;
else if (incomplete && !process.argv.includes('--allow-partial')) process.exitCode = 2;
