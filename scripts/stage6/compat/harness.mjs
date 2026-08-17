#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { chromium, firefox, webkit } from '@playwright/test';
import { stage6Environment } from '../lib/evidence.mjs';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const WEB_PORT = 4176;
export const WEB_ORIGIN = `http://127.0.0.1:${WEB_PORT}`;
export const PRODUCT_ID = 'product-demo-001';
export const PRODUCT_PATH = `/products/${PRODUCT_ID}`;
export const CHECKOUT_ID = 'checkout_e6_local_001';
export const TRANSACTION_ID = 'transaction_e6_local_001';

export const VIEWPORTS = [
  { id: 'UXVP-01', width: 320, height: 568 },
  { id: 'UXVP-02', width: 375, height: 667 },
  { id: 'UXVP-03', width: 390, height: 844 },
  { id: 'UXVP-04', width: 667, height: 375 },
  { id: 'UXVP-05', width: 768, height: 1024 },
  { id: 'UXVP-06', width: 1334, height: 750 },
  { id: 'UXVP-07', width: 1440, height: 900 },
];

const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const CHROME_PATHS = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
];
const VITE_PATH = path.join(ROOT, 'apps', 'web', 'node_modules', 'vite', 'bin', 'vite.js');

export class Stage6CheckError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export const check = (condition, code) => {
  if (!condition) throw new Stage6CheckError(code);
};

const firstExisting = (paths) => paths.find((candidate) => existsSync(candidate));

export const detectBrowserTargets = () => {
  const bundledChromium = chromium.executablePath();
  const bundledFirefox = firefox.executablePath();
  const bundledWebkit = webkit.executablePath();
  const systemChromium = firstExisting([EDGE_PATH, ...CHROME_PATHS]);

  return [
    existsSync(bundledChromium)
      ? {
          id: 'chromium',
          runtime: 'playwright-chromium',
          executablePath: bundledChromium,
          launch: () => chromium.launch({ headless: true }),
        }
      : systemChromium === undefined
        ? {
            id: 'chromium',
            status: 'NOT_RUN_ENV_REQUIRED',
            reason: 'PLAYWRIGHT_CHROMIUM_OR_SYSTEM_CHROMIUM_MISSING',
          }
        : {
            id: 'chromium',
            runtime: systemChromium === EDGE_PATH ? 'system-edge-chromium' : 'system-chrome',
            executablePath: systemChromium,
            launch: () => chromium.launch({ headless: true, executablePath: systemChromium }),
          },
    existsSync(bundledFirefox)
      ? {
          id: 'firefox',
          runtime: 'playwright-firefox',
          executablePath: bundledFirefox,
          launch: () => firefox.launch({ headless: true }),
        }
      : {
          id: 'firefox',
          status: 'NOT_RUN_ENV_REQUIRED',
          reason: 'PLAYWRIGHT_FIREFOX_MISSING',
        },
    existsSync(bundledWebkit)
      ? {
          id: 'webkit',
          runtime: 'playwright-webkit',
          executablePath: bundledWebkit,
          launch: () => webkit.launch({ headless: true }),
        }
      : {
          id: 'webkit',
          status: 'NOT_RUN_ENV_REQUIRED',
          reason: 'PLAYWRIGHT_WEBKIT_MISSING',
        },
  ];
};

const runCommand = (executable, arguments_, code) => {
  const windows = process.platform === 'win32';
  const result = spawnSync(
    windows ? (process.env.ComSpec ?? 'cmd.exe') : executable,
    windows ? ['/d', '/s', '/c', executable, ...arguments_] : arguments_,
    {
      cwd: ROOT,
      env: process.env,
      encoding: 'utf8',
      windowsHide: true,
    },
  );
  check(result.error === undefined && result.status === 0, code);
};

export const buildWeb = () => {
  const pnpm = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';
  runCommand(pnpm, ['--filter', '@checkout/contracts', 'build'], 'CONTRACTS_BUILD_FAILED');
  runCommand(pnpm, ['--filter', '@checkout/web', 'build'], 'WEB_BUILD_FAILED');
};

const startPreview = () => {
  check(existsSync(VITE_PATH), 'VITE_RUNTIME_MISSING');
  const child = spawn(
    process.execPath,
    [VITE_PATH, 'preview', '--host', '127.0.0.1', '--port', String(WEB_PORT), '--strictPort'],
    {
      cwd: path.join(ROOT, 'apps', 'web'),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    },
  );
  child.stdout?.resume();
  child.stderr?.resume();
  return child;
};

const waitForPreview = async (child) => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    check(child.exitCode === null, 'WEB_PREVIEW_EXITED');
    try {
      const response = await fetch(WEB_ORIGIN, { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch {
      // Bounded loopback-only startup polling.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Stage6CheckError('WEB_PREVIEW_NOT_READY');
};

const stopPreview = async (child) => {
  if (child.exitCode !== null) return;
  child.kill();
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 3_000)),
  ]);
  if (child.exitCode === null) child.kill('SIGKILL');
};

export const withLocalPreview = async (run, { build = true } = {}) => {
  if (build) buildWeb();
  const preview = startPreview();
  try {
    await waitForPreview(preview);
    return await run();
  } finally {
    await stopPreview(preview);
  }
};

const fixture = () => {
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
  return {
    product,
    checkoutCreated: {
      checkoutId: CHECKOUT_ID,
      status: 'DRAFT',
      version: 1,
      quote,
      expiresAt: '2099-01-01T00:00:00.000Z',
    },
    checkout: {
      checkoutId: CHECKOUT_ID,
      status: 'DRAFT',
      version: 1,
      product,
      quote,
      customer: null,
      deliveryDetails: null,
      activeTransactionId: null,
      expiresAt: '2099-01-01T00:00:00.000Z',
    },
    paymentConfiguration: {
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
    },
  };
};

const transactionFixture = (presentation) => {
  const timestamp = new Date().toISOString();
  const common = {
    transactionId: TRANSACTION_ID,
    checkoutId: CHECKOUT_ID,
    statusUrl: `/api/v1/transactions/${TRANSACTION_ID}`,
    acceptedAt: timestamp,
    updatedAt: timestamp,
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
      deliveryId: 'delivery_e6_local_001',
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

export const installSyntheticNetwork = async (context) => {
  let blockedExternalRequests = 0;
  let unknownApiRequests = 0;
  let apiRequests = 0;
  const data = fixture();
  let checkout = { ...data.checkout };
  let transactionPresentation = 'pending';

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
        await fulfillJson(route, data.product);
      } else if (key === 'POST /api/v1/checkouts') {
        checkout = { ...data.checkout };
        await fulfillJson(route, data.checkoutCreated, 201);
      } else if (key === `GET /api/v1/checkouts/${CHECKOUT_ID}`) {
        await fulfillJson(route, checkout);
      } else if (key === `PUT /api/v1/checkouts/${CHECKOUT_ID}/customer`) {
        const body = request.postDataJSON();
        const customer = {
          customerId: 'customer_e6_local_001',
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
        await fulfillJson(route, data.paymentConfiguration);
      } else if (key === `POST /api/v1/checkouts/${CHECKOUT_ID}/transactions`) {
        checkout = {
          ...checkout,
          status: 'PAYMENT_PENDING',
          version: checkout.version + 1,
          activeTransactionId: TRANSACTION_ID,
        };
        transactionPresentation = 'pending';
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
        await fulfillJson(route, transactionFixture(transactionPresentation));
      } else {
        unknownApiRequests += 1;
        await fulfillJson(route, { code: 'E6_SYNTHETIC_ROUTE_MISSING' }, 501);
      }
    } catch {
      await fulfillJson(route, { code: 'E6_SYNTHETIC_FIXTURE_ERROR' }, 500);
    }
  });

  return {
    counts: () => ({ blockedExternalRequests, unknownApiRequests, apiRequests }),
    setTransactionPresentation: (value) => {
      check(
        ['pending', 'unknown', 'approved', 'declined'].includes(value),
        'INVALID_TRANSACTION_FIXTURE',
      );
      transactionPresentation = value;
    },
  };
};
export const createSyntheticPage = async (browser, viewport, options = {}) => {
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    locale: 'es-CO',
    colorScheme: 'light',
    reducedMotion: options.reducedMotion ?? 'no-preference',
  });
  const network = await installSyntheticNetwork(context);
  const page = await context.newPage();
  return { context, page, network };
};

const commandOutput = (executable, arguments_) => {
  const result = spawnSync(executable, arguments_, {
    cwd: ROOT,
    encoding: 'utf8',
    windowsHide: true,
  });
  return result.status === 0 ? result.stdout.trim() : 'UNKNOWN';
};

export const reportMetadata = async (scriptPath) => ({
  schemaVersion: 1,
  commitSha: commandOutput('git', ['rev-parse', 'HEAD']),
  branch: commandOutput('git', ['branch', '--show-current']),
  executedAtUtc: new Date().toISOString(),
  environment: stage6Environment(),
  executionScope: 'LOCAL_SYNTHETIC_LOOPBACK_ONLY',
  nodeVersion: process.version,
  playwrightVersion: JSON.parse(
    await readFile(path.join(ROOT, 'node_modules', '@playwright', 'test', 'package.json'), 'utf8'),
  ).version,
  scriptSha256: createHash('sha256')
    .update(await readFile(scriptPath))
    .digest('hex'),
  externalNetworkPolicy: 'DENY',
  syntheticDataOnly: true,
});

export const outputPathFromArgs = () => {
  const index = process.argv.indexOf('--output');
  return index === -1 ? undefined : process.argv[index + 1];
};

export const writeReport = async (report) => {
  const outputPath = outputPathFromArgs();
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  if (outputPath === undefined) {
    process.stdout.write(serialized);
    return;
  }
  const absolute = path.resolve(ROOT, outputPath);
  await mkdir(path.dirname(absolute), { recursive: true });
  await writeFile(absolute, serialized, 'utf8');
  process.stdout.write(`${absolute}\n`);
};

export const shouldBuild = () => !process.argv.includes('--skip-build');
