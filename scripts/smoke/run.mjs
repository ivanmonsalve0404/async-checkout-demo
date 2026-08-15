#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { chromium, expect } from '@playwright/test';

const ROOT = process.cwd();
const API_ORIGIN = 'http://127.0.0.1:3000';
const WEB_ORIGIN = 'http://127.0.0.1:4173';
const PRODUCT_ID = 'product-demo-001';
const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const EVIDENCE_PATH = path.join(ROOT, 'output', 'evidence', 'stage-4', 'smoke-results.json');

const processes = [];
const output = new Map();

const start = (name, executable, arguments_, environment = {}, cwd = ROOT) => {
  const child = spawn(executable, arguments_, {
    cwd,
    env: { ...process.env, ...environment },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const chunks = [];
  child.stdout?.on('data', (chunk) => chunks.push(String(chunk)));
  child.stderr?.on('data', (chunk) => chunks.push(String(chunk)));
  output.set(name, chunks);
  processes.push(child);
  return child;
};

const stopProcesses = async () => {
  for (const child of processes.reverse()) {
    if (child.exitCode === null) child.kill();
  }
  await Promise.all(
    processes.map(
      (child) =>
        new Promise((resolve) => {
          if (child.exitCode !== null) return resolve();
          const timer = setTimeout(() => {
            child.kill('SIGKILL');
            resolve();
          }, 3_000);
          child.once('exit', () => {
            clearTimeout(timer);
            resolve();
          });
        }),
    ),
  );
};

const waitFor = async (url, attempts = 80) => {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
    } catch {
      // The bounded retry is only for local process startup.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  const details = [...output.entries()]
    .map(([name, chunks]) => `${name}: ${chunks.join('').slice(-1_500)}`)
    .join('\n');
  throw new Error(`Local service did not become ready: ${url}\n${details}`);
};

const product = (available) => ({
  productId: PRODUCT_ID,
  sku: 'SKU_DEMO_001',
  name: 'Morral urbano de demostración',
  description: 'Producto sintético para el smoke local.',
  imageUrl: `${WEB_ORIGIN}/product-placeholder.svg`,
  unitPrice: { amountInCents: 2_500_000, currency: 'COP' },
  available,
});

const productProblem = {
  type: 'https://example.invalid/problems/product-not-found',
  title: 'Producto no encontrado',
  status: 404,
  detail: 'El producto solicitado no existe.',
  instance: '/api/v1/products/product-missing-001',
  code: 'PRODUCT_NOT_FOUND',
  correlationId: 'corr_smoke_synthetic',
};

const main = async () => {
  start('api', process.execPath, [path.join(ROOT, 'apps', 'api', 'dist', 'main.js')], {
    ALLOWED_ORIGIN: WEB_ORIGIN,
    API_PORT: '3000',
    APP_ENV: 'test',
    DATA_ADAPTER: 'memory',
    PAYMENT_ADAPTER: 'fake',
    PAYMENTS_ENABLED: 'false',
    PUBLIC_ASSET_ORIGIN: WEB_ORIGIN,
    TOKENIZATION_MODE: 'disabled',
  });
  start(
    'web',
    process.execPath,
    [path.join(ROOT, 'apps', 'web', 'node_modules', 'vite', 'bin', 'vite.js'), 'preview'],
    {},
    path.join(ROOT, 'apps', 'web'),
  );

  await waitFor(`${API_ORIGIN}/api/health`);
  await waitFor(WEB_ORIGIN);

  const executablePath =
    process.env.SMOKE_BROWSER_EXECUTABLE ??
    (process.platform === 'win32' && existsSync(EDGE_PATH) ? EDGE_PATH : undefined);
  const browser = await chromium.launch({
    headless: true,
    ...(executablePath === undefined ? {} : { executablePath }),
  });
  const results = [];

  const scenario = async (id, title, execute) => {
    const startedAt = Date.now();
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const page = await context.newPage();
    const externalRequests = [];
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (
        (url.protocol === 'http:' || url.protocol === 'https:') &&
        url.hostname !== '127.0.0.1' &&
        url.hostname !== 'localhost'
      ) {
        externalRequests.push(`${request.method()} ${url.origin}`);
      }
    });
    try {
      await execute(page);
      assert.deepEqual(externalRequests, [], 'the smoke journey must not contact external origins');
      results.push({ id, title, status: 'PASS', durationMs: Date.now() - startedAt });
      process.stdout.write(`${id} PASS — ${title}\n`);
    } catch (error) {
      const message = error instanceof Error ? error.message.split('\n')[0] : 'unknown failure';
      results.push({ id, title, status: 'FAIL', durationMs: Date.now() - startedAt, message });
      process.stderr.write(`${id} FAIL — ${title}: ${message}\n`);
    } finally {
      await context.close();
    }
  };

  await scenario('SMK-01', 'producto disponible desde API local real', async (page) => {
    await page.goto(`${WEB_ORIGIN}/products/${PRODUCT_ID}`);
    await expect(
      page.getByRole('heading', { name: 'Morral urbano de demostración' }),
    ).toBeVisible();
    await expect(page.getByText('3 unidades disponibles')).toBeVisible();
    await expect(page.getByLabel(/Precio/)).toContainText(/25\.000/);
  });

  await scenario('SMK-02', 'producto sin stock bloquea continuación', async (page) => {
    await page.route('**/api/v1/products/*', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(product(0)),
      }),
    );
    await page.goto(`${WEB_ORIGIN}/products/${PRODUCT_ID}`);
    await expect(page.getByText('Agotado por ahora')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sin disponibilidad' })).toBeDisabled();
  });

  await scenario('SMK-03', 'producto inexistente muestra 404 seguro', async (page) => {
    await page.route('**/api/v1/products/*', (route) =>
      route.fulfill({
        status: 404,
        contentType: 'application/problem+json',
        body: JSON.stringify(productProblem),
      }),
    );
    await page.goto(`${WEB_ORIGIN}/products/product-missing-001`);
    await expect(page.getByRole('heading', { name: 'Producto no disponible' })).toBeVisible();
  });

  await scenario('SMK-04', 'fallo temporal permite reintento controlado', async (page) => {
    let attempts = 0;
    await page.route('**/api/v1/products/*', async (route) => {
      attempts += 1;
      if (attempts === 1) return route.abort('connectionfailed');
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(product(3)),
      });
    });
    await page.goto(`${WEB_ORIGIN}/products/${PRODUCT_ID}`);
    await expect(
      page.getByRole('heading', { name: 'No pudimos cargar el producto' }),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Reintentar' }).click();
    await expect(
      page.getByRole('heading', { name: 'Morral urbano de demostración' }),
    ).toBeVisible();
    assert.equal(attempts, 2);
  });

  await scenario('SMK-05', 'refresh restaura producto desde estado canónico', async (page) => {
    await page.goto(`${WEB_ORIGIN}/products/${PRODUCT_ID}`);
    await expect(page.getByText('3 unidades disponibles')).toBeVisible();
    await page.reload();
    await expect(page.getByText('3 unidades disponibles')).toBeVisible();
  });

  await scenario('SMK-06', 'respuesta inválida cae en estado seguro', async (page) => {
    await page.route('**/api/v1/products/*', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ unsafe: 'shape' }),
      }),
    );
    await page.goto(`${WEB_ORIGIN}/products/${PRODUCT_ID}`);
    await expect(page.getByRole('heading', { name: 'Ocurrió un problema' })).toBeVisible();
  });

  await browser.close();
  await mkdir(path.dirname(EVIDENCE_PATH), { recursive: true });
  await writeFile(
    EVIDENCE_PATH,
    `${JSON.stringify(
      {
        schemaVersion: 1,
        executedAt: new Date().toISOString(),
        environment: 'local-fake-only',
        providerRequests: 0,
        passed: results.filter((result) => result.status === 'PASS').length,
        total: results.length,
        results,
      },
      null,
      2,
    )}\n`,
    'utf8',
  );
  if (results.some((result) => result.status !== 'PASS')) process.exitCode = 1;
};

try {
  await main();
} finally {
  await stopProcesses();
}
