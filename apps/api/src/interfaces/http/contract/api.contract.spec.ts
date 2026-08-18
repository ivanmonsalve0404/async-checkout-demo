import type { INestApplication } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import request from 'supertest';
import { createApplication } from '../../../bootstrap';

describe('API contract walking skeleton', () => {
  let application: INestApplication;
  const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);

  beforeAll(async () => {
    Object.assign(process.env, {
      APP_ENV: 'test',
      DATA_ADAPTER: 'memory',
      PAYMENT_ADAPTER: 'fake',
      PAYMENTS_ENABLED: 'false',
      TOKENIZATION_MODE: 'disabled',
      PRODUCT_SEED_ID: 'product-demo-001',
      PUBLIC_ASSET_ORIGIN: 'http://localhost:5173',
    });
    application = await createApplication();
    await application.init();
  });

  afterAll(async () => {
    await application.close();
    write.mockRestore();
  });

  it('serves health without exposing configuration', async () => {
    const response = await request(application.getHttpServer())
      .get('/api/health')
      .set('x-correlation-id', 'correlation-health-01')
      .expect(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['x-correlation-id']).toMatch(/^[0-9a-f-]{36}$/);
    expect(response.headers['x-correlation-id']).not.toBe('correlation-health-01');
    expect(Object.keys(response.body).sort()).toEqual(['checkedAt', 'status']);
    expect(response.body).toMatchObject({ status: 'ok' });
  });

  it('crosses controller, use case, port, adapter and presenter', async () => {
    const response = await request(application.getHttpServer())
      .get('/api/v1/products/product-demo-001')
      .expect(200);
    expect(response.headers['cache-control']).toBe('no-cache');
    expect(Object.keys(response.body).sort()).toEqual([
      'available',
      'description',
      'imageUrl',
      'name',
      'productId',
      'sku',
      'unitPrice',
    ]);
    expect(response.body).toMatchObject({
      productId: 'product-demo-001',
      unitPrice: { amountInCents: 2_500_000, currency: 'COP' },
      available: 3,
    });
  });

  it.each(['/api/v1/products/missing-product', '/api/v1/products/bad%2Fid'])(
    'returns the canonical safe problem for %s',
    async (path) => {
      const response = await request(application.getHttpServer()).get(path).expect(404);
      expect(response.headers['content-type']).toContain('application/problem+json');
      expect(response.body).toMatchObject({
        status: 404,
        code: 'PRODUCT_NOT_FOUND',
        retryable: false,
      });
      expect(response.body).not.toHaveProperty('stack');
    },
  );

  it('serves only sanitized local documentation', async () => {
    const contract = readFileSync(
      resolve(__dirname, '../../../../../..', 'output/architecture/openapi.yaml'),
      'utf8',
    );
    const response = await request(application.getHttpServer()).get('/api/docs').expect(200);
    expect(response.headers).toMatchObject({
      'cache-control': 'public, max-age=300',
      'content-disposition': 'inline; filename="openapi.yaml"',
      'content-type': 'application/yaml; charset=utf-8',
      'x-content-type-options': 'nosniff',
    });
    expect(createHash('sha256').update(response.text).digest('hex')).toBe(
      createHash('sha256').update(contract).digest('hex'),
    );
    expect(response.text).toContain('openapi: 3.1.2');
    expect(response.text).not.toMatch(/(?:sk|prv|pub)_(?:live|prod)_[A-Za-z0-9_-]+/);
    expect(response.text).not.toContain('https://production.wompi.co');
  });
});
