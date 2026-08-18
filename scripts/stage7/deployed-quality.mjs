/* global document, matchMedia, structuredClone */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const PRODUCT_PATH = '/products/product-demo-001';
const ENGINES = ['chromium', 'firefox', 'webkit'];
const VIEWPORT = Object.freeze({ width: 390, height: 844 });
const BUDGETS = Object.freeze({
  lcpMsMaximumExclusive: 2_500,
  clsMaximumExclusive: 0.1,
  performanceScoreMinimum: 0.8,
  accessibilityScoreMinimum: 1,
  bestPracticesScoreMinimum: 0.9,
  totalByteWeightMaximum: 1_500_000,
});
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, expected) =>
  object(value) && Object.keys(value).sort().join('\0') === [...expected].sort().join('\0');

export class Stage7QualityError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7QualityError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7QualityError(code);
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
      fail('E7_QUALITY_ORIGIN_INVALID');
    }
    return parsed.origin;
  } catch (error) {
    if (error instanceof Stage7QualityError) throw error;
    fail('E7_QUALITY_ORIGIN_INVALID');
  }
};

const requestDestination = (url, origin) => {
  try {
    const parsed = new URL(url);
    if (['data:', 'blob:', 'about:'].includes(parsed.protocol)) return 'INTERNAL';
    return parsed.origin === origin ? 'OWNED' : 'OUTSIDE';
  } catch {
    return 'OUTSIDE';
  }
};

const resolveAxe = (workspaceRoot) => {
  try {
    const requireFromWeb = createRequire(path.join(workspaceRoot, 'apps/web/package.json'));
    const axePath = createRequire(requireFromWeb.resolve('jest-axe')).resolve(
      'axe-core/axe.min.js',
    );
    const axePackage = createRequire(axePath).resolve('axe-core/package.json');
    return {
      source: readFileSync(axePath, 'utf8'),
      version: JSON.parse(readFileSync(axePackage, 'utf8')).version,
    };
  } catch {
    fail('E7_QUALITY_AXE_RUNTIME_MISSING');
  }
};

const keyboardFocusesCta = async (page) => {
  await page.evaluate(() => {
    document.body.setAttribute('tabindex', '-1');
    document.body.focus();
  });
  for (let index = 0; index < 20; index += 1) {
    await page.keyboard.press('Tab');
    const focused = await page.evaluate(
      () => document.activeElement?.getAttribute('data-testid') ?? '',
    );
    if (focused === 'product-checkout-cta') return true;
  }
  return false;
};

const focalDomFacts = (page) =>
  page.evaluate(() => {
    const ids = [...document.querySelectorAll('[id]')].map((node) => node.id);
    const cta = document.querySelector('[data-testid="product-checkout-cta"]');
    const rect = cta?.getBoundingClientRect();
    const assistivePrice = [...document.querySelectorAll('.visually-hidden')].some((node) =>
      /precio.+pesos colombianos/iu.test(node.textContent ?? ''),
    );
    return {
      duplicateIds: ids.length - new Set(ids).size,
      horizontalOverflow:
        document.documentElement.scrollWidth > document.documentElement.clientWidth,
      ctaWidth: rect?.width ?? 0,
      ctaHeight: rect?.height ?? 0,
      headingCount: document.querySelectorAll('h1').length,
      mainCount: document.querySelectorAll('main').length,
      assistivePrice,
      reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
    };
  });

const runBrowserFocal = async ({ browserType, engine, origin, axe }) => {
  const browser = await browserType.launch({ headless: true });
  const counts = { owned: 0, outside: 0, mutations: 0 };
  const critical = { console: 0, page: 0, network: 0 };
  let context;
  try {
    context = await browser.newContext({
      viewport: VIEWPORT,
      locale: 'es-CO',
      timezoneId: 'America/Bogota',
      reducedMotion: 'reduce',
      serviceWorkers: 'block',
    });
    await context.route('**/*', async (route) => {
      const destination = requestDestination(route.request().url(), origin);
      const method = route.request().method();
      if (destination === 'INTERNAL') {
        await route.continue();
        return;
      }
      if (destination !== 'OWNED' || !SAFE_METHODS.has(method)) {
        if (destination !== 'OWNED') counts.outside += 1;
        else counts.mutations += 1;
        await route.abort('blockedbyclient');
        return;
      }
      counts.owned += 1;
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
      if (requestDestination(request.url(), origin) === 'OWNED') critical.network += 1;
    });
    const response = await page.goto(`${origin}${PRODUCT_PATH}`, {
      waitUntil: 'networkidle',
      timeout: 45_000,
    });
    await page.getByTestId('product-surface').waitFor({ state: 'visible' });
    const facts = await focalDomFacts(page);
    const keyboardCta = await keyboardFocusesCta(page);
    if (
      response?.status() !== 200 ||
      facts.duplicateIds !== 0 ||
      facts.horizontalOverflow ||
      facts.ctaWidth < 48 ||
      facts.ctaHeight < 48 ||
      facts.headingCount !== 1 ||
      facts.mainCount !== 1 ||
      !facts.assistivePrice ||
      !facts.reducedMotion ||
      !keyboardCta ||
      counts.outside !== 0 ||
      counts.mutations !== 0 ||
      Object.values(critical).some((value) => value !== 0)
    ) {
      fail(`E7_QUALITY_${engine.toUpperCase()}_FOCAL_FAILED`);
    }
    let accessibility;
    if (engine === 'chromium') {
      await page.addScriptTag({ content: axe.source });
      const axeResult = await page.evaluate(async () =>
        globalThis.axe.run(document, {
          runOnly: {
            type: 'tag',
            values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'],
          },
          resultTypes: ['violations', 'incomplete', 'passes'],
        }),
      );
      if (
        !Array.isArray(axeResult?.violations) ||
        !Array.isArray(axeResult?.incomplete) ||
        !Array.isArray(axeResult?.passes) ||
        axeResult.violations.length !== 0 ||
        axeResult.incomplete.length !== 0 ||
        axeResult.passes.length < 1
      ) {
        fail('E7_QUALITY_ACCESSIBILITY_FAILED');
      }
      accessibility = {
        status: 'PASS',
        tool: { name: 'axe-core', version: axe.version },
        surface: PRODUCT_PATH,
        violations: 0,
        incomplete: 0,
        passes: axeResult.passes.length,
        duplicateIds: 0,
        keyboardCta: 'PASS',
        reducedMotion: 'PASS',
        assistivePriceCop: 'PASS',
      };
    }
    return {
      browser: {
        engine,
        version: browser.version(),
        status: 'PASS',
        viewport: `${VIEWPORT.width}x${VIEWPORT.height}`,
        product: 'PASS',
        keyboard: 'PASS',
        responsive: 'PASS',
        targetSize: 'PASS',
      },
      accessibility,
      requests: counts.owned,
    };
  } finally {
    await context?.close().catch(() => undefined);
    await browser.close().catch(() => undefined);
  }
};

const lighthouseRuntime = async (workspaceRoot) => {
  try {
    const requireFromRoot = createRequire(path.join(workspaceRoot, 'package.json'));
    const lighthouseEntry = requireFromRoot.resolve('lighthouse/core/index.js');
    const lighthousePackage = requireFromRoot.resolve('lighthouse/package.json');
    const manifest = JSON.parse(readFileSync(lighthousePackage, 'utf8'));
    if (manifest.version !== '13.4.1') fail('E7_QUALITY_LIGHTHOUSE_VERSION_INVALID');
    const requireFromLighthouse = createRequire(lighthousePackage);
    return {
      lighthouse: await import(pathToFileURL(lighthouseEntry).href),
      puppeteer: requireFromLighthouse('puppeteer-core'),
      version: manifest.version,
    };
  } catch (error) {
    if (error instanceof Stage7QualityError) throw error;
    fail('E7_QUALITY_LIGHTHOUSE_RUNTIME_MISSING');
  }
};

const runLighthouse = async ({ origin, workspaceRoot, executablePath }) => {
  const runtime = await lighthouseRuntime(workspaceRoot);
  const runs = [];
  let requests = 0;
  let outside = 0;
  let mutations = 0;
  for (let index = 0; index < 3; index += 1) {
    const browser = await runtime.puppeteer.launch({
      executablePath,
      headless: true,
      args: [
        '--disable-gpu',
        '--disable-background-networking',
        '--no-first-run',
        ...(process.platform === 'linux' && process.env.CI === 'true' ? ['--no-sandbox'] : []),
      ],
    });
    try {
      const page = await browser.newPage();
      await page.setViewport({ ...VIEWPORT, deviceScaleFactor: 1, isMobile: true });
      await page.setRequestInterception(true);
      page.on('request', (request) => {
        const destination = requestDestination(request.url(), origin);
        if (destination === 'INTERNAL') {
          void request.continue();
          return;
        }
        if (destination !== 'OWNED' || !SAFE_METHODS.has(request.method())) {
          if (destination !== 'OWNED') outside += 1;
          else mutations += 1;
          void request.abort('blockedbyclient');
          return;
        }
        requests += 1;
        void request.continue();
      });
      const result = await runtime.lighthouse.navigation(page, `${origin}${PRODUCT_PATH}`, {
        flags: {
          onlyCategories: ['performance', 'accessibility', 'best-practices'],
          formFactor: 'mobile',
          screenEmulation: {
            mobile: true,
            ...VIEWPORT,
            deviceScaleFactor: 1,
            disabled: false,
          },
          throttlingMethod: 'simulate',
          locale: 'es',
          maxWaitForLoad: 45_000,
          disableStorageReset: false,
        },
      });
      const lhr = result?.lhr;
      const snapshot = {
        run: index + 1,
        performanceScore: lhr?.categories?.performance?.score ?? -1,
        accessibilityScore: lhr?.categories?.accessibility?.score ?? -1,
        bestPracticesScore: lhr?.categories?.['best-practices']?.score ?? -1,
        lcpMs: lhr?.audits?.['largest-contentful-paint']?.numericValue ?? Number.POSITIVE_INFINITY,
        cls: lhr?.audits?.['cumulative-layout-shift']?.numericValue ?? Number.POSITIVE_INFINITY,
        totalByteWeight:
          lhr?.audits?.['total-byte-weight']?.numericValue ?? Number.POSITIVE_INFINITY,
        https: lhr?.audits?.['is-on-https']?.score ?? 0,
        // Lighthouse's is-on-https audit also rejects active mixed-content
        // subresources; retain the conclusion separately for the E7 contract.
        mixedContent: lhr?.audits?.['is-on-https']?.score ?? 0,
      };
      if (
        new URL(lhr?.finalUrl ?? 'https://invalid.example').origin !== origin ||
        snapshot.performanceScore < BUDGETS.performanceScoreMinimum ||
        snapshot.accessibilityScore < BUDGETS.accessibilityScoreMinimum ||
        snapshot.bestPracticesScore < BUDGETS.bestPracticesScoreMinimum ||
        snapshot.lcpMs >= BUDGETS.lcpMsMaximumExclusive ||
        snapshot.cls >= BUDGETS.clsMaximumExclusive ||
        snapshot.totalByteWeight > BUDGETS.totalByteWeightMaximum ||
        snapshot.https !== 1 ||
        snapshot.mixedContent !== 1
      ) {
        fail('E7_QUALITY_LIGHTHOUSE_BUDGET_FAILED');
      }
      runs.push(snapshot);
    } finally {
      await browser.close().catch(() => undefined);
    }
  }
  if (outside !== 0 || mutations !== 0) fail('E7_QUALITY_LIGHTHOUSE_REQUEST_SCOPE_FAILED');
  return {
    status: 'PASS',
    tool: { name: 'lighthouse', version: runtime.version },
    surface: PRODUCT_PATH,
    formFactor: 'mobile-390x844',
    measuredRuns: 3,
    budgets: BUDGETS,
    runs,
    fieldTelemetry: 'NOT_AVAILABLE_LAB_ONLY',
    rawHtmlPersisted: false,
    requests,
  };
};

export const validateQualityPayload = (payload) => {
  if (
    !exactKeys(payload, [
      'crossBrowser',
      'accessibility',
      'lighthouse',
      'requests',
      'criticalErrors',
    ]) ||
    !Array.isArray(payload.crossBrowser) ||
    payload.crossBrowser.length !== 3 ||
    payload.crossBrowser.some(
      (entry, index) =>
        entry?.engine !== ENGINES[index] ||
        entry.status !== 'PASS' ||
        entry.viewport !== '390x844' ||
        !/^\d+(?:\.\d+){1,3}$/u.test(entry.version ?? ''),
    ) ||
    payload.accessibility?.status !== 'PASS' ||
    payload.accessibility?.violations !== 0 ||
    payload.accessibility?.incomplete !== 0 ||
    payload.lighthouse?.status !== 'PASS' ||
    payload.lighthouse?.measuredRuns !== 3 ||
    !Array.isArray(payload.lighthouse.runs) ||
    payload.lighthouse.runs.length !== 3 ||
    payload.lighthouse.rawHtmlPersisted !== false ||
    payload.lighthouse.fieldTelemetry !== 'NOT_AVAILABLE_LAB_ONLY' ||
    payload.requests?.outsideAllowlist !== 0 ||
    payload.requests?.mutations !== 0 ||
    !Number.isSafeInteger(payload.requests?.ownedOrigin) ||
    payload.requests.ownedOrigin < 1 ||
    Object.values(payload.criticalErrors ?? {}).some((value) => value !== 0)
  ) {
    fail('E7_QUALITY_PAYLOAD_INVALID');
  }
  for (const run of payload.lighthouse.runs) {
    if (
      run.performanceScore < BUDGETS.performanceScoreMinimum ||
      run.accessibilityScore < BUDGETS.accessibilityScoreMinimum ||
      run.bestPracticesScore < BUDGETS.bestPracticesScoreMinimum ||
      run.lcpMs >= BUDGETS.lcpMsMaximumExclusive ||
      run.cls >= BUDGETS.clsMaximumExclusive ||
      run.totalByteWeight > BUDGETS.totalByteWeightMaximum ||
      run.https !== 1 ||
      run.mixedContent !== 1
    ) {
      fail('E7_QUALITY_PAYLOAD_INVALID');
    }
  }
  return payload;
};

export const runDeployedQuality = async ({
  origin: requestedOrigin,
  authorization,
  workspaceRoot,
}) => {
  const origin = safeOrigin(requestedOrigin);
  if (
    authorization?.ownedTarget?.status !== 'APPROVED' ||
    !Number.isSafeInteger(authorization.ownedTarget.maxRequests) ||
    authorization.ownedTarget.maxRequests < 1
  ) {
    fail('E7_QUALITY_AUTHORIZATION_INVALID');
  }
  const playwright = await import('@playwright/test');
  const axe = resolveAxe(workspaceRoot);
  const crossBrowser = [];
  let accessibility;
  let browserRequests = 0;
  for (const engine of ENGINES) {
    const result = await runBrowserFocal({
      browserType: playwright[engine],
      engine,
      origin,
      axe,
    });
    crossBrowser.push(result.browser);
    browserRequests += result.requests;
    if (result.accessibility !== undefined) accessibility = result.accessibility;
  }
  const lighthouse = await runLighthouse({
    origin,
    workspaceRoot,
    executablePath: playwright.chromium.executablePath(),
  });
  const ownedOrigin = browserRequests + lighthouse.requests;
  if (ownedOrigin > authorization.ownedTarget.maxRequests) {
    fail('E7_QUALITY_AUTHORIZATION_REQUEST_LIMIT_EXCEEDED');
  }
  return validateQualityPayload({
    crossBrowser,
    accessibility,
    lighthouse,
    requests: { ownedOrigin, outsideAllowlist: 0, mutations: 0 },
    criticalErrors: { console: 0, page: 0, network: 0 },
  });
};

const qualityFixture = () => ({
  crossBrowser: ENGINES.map((engine) => ({
    engine,
    version: '1.2.3',
    status: 'PASS',
    viewport: '390x844',
    product: 'PASS',
    keyboard: 'PASS',
    responsive: 'PASS',
    targetSize: 'PASS',
  })),
  accessibility: {
    status: 'PASS',
    tool: { name: 'axe-core', version: '4.12.1' },
    surface: PRODUCT_PATH,
    violations: 0,
    incomplete: 0,
    passes: 10,
    duplicateIds: 0,
    keyboardCta: 'PASS',
    reducedMotion: 'PASS',
    assistivePriceCop: 'PASS',
  },
  lighthouse: {
    status: 'PASS',
    tool: { name: 'lighthouse', version: '13.4.1' },
    surface: PRODUCT_PATH,
    formFactor: 'mobile-390x844',
    measuredRuns: 3,
    budgets: BUDGETS,
    runs: Array.from({ length: 3 }, (_, index) => ({
      run: index + 1,
      performanceScore: 0.9,
      accessibilityScore: 1,
      bestPracticesScore: 1,
      lcpMs: 1_000,
      cls: 0.01,
      totalByteWeight: 500_000,
      https: 1,
      mixedContent: 1,
    })),
    fieldTelemetry: 'NOT_AVAILABLE_LAB_ONLY',
    rawHtmlPersisted: false,
    requests: 12,
  },
  requests: { ownedOrigin: 24, outsideAllowlist: 0, mutations: 0 },
  criticalErrors: { console: 0, page: 0, network: 0 },
});

export const selfTestDeployedQuality = () => {
  validateQualityPayload(qualityFixture());
  for (const mutate of [
    (value) => {
      value.crossBrowser.pop();
    },
    (value) => {
      value.accessibility.violations = 1;
    },
    (value) => {
      value.lighthouse.runs[1].lcpMs = 2_500;
    },
    (value) => {
      value.requests.mutations = 1;
    },
    (value) => {
      value.lighthouse.measuredRuns = 2;
    },
  ]) {
    const value = structuredClone(qualityFixture());
    mutate(value);
    assert.throws(() => validateQualityPayload(value), Stage7QualityError);
  }
  assert.equal(requestDestination('https://owned.example/path', 'https://owned.example'), 'OWNED');
  assert.equal(requestDestination('https://outside.example/', 'https://owned.example'), 'OUTSIDE');
  assert.throws(
    () => safeOrigin('http://owned.example'),
    (error) => error.code === 'E7_QUALITY_ORIGIN_INVALID',
  );
};
