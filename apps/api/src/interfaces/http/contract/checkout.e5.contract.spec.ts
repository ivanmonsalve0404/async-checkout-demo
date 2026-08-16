import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createApplication } from '../../../bootstrap';

const ORIGIN = 'http://localhost:5173';
const PRODUCT_ID = 'product-demo-001';

const cookiePair = (headers: Record<string, unknown>): string => {
  const value = headers['set-cookie'];
  const first = Array.isArray(value) ? value[0] : value;
  if (typeof first !== 'string') throw new Error('Set-Cookie was not returned');
  return first.split(';')[0] as string;
};

describe('E5 HTTP contract', () => {
  let application: INestApplication;
  let write: jest.SpyInstance;

  beforeAll(async () => {
    process.env.APP_ENV = 'test';
    process.env.DATA_ADAPTER = 'memory';
    process.env.FAKE_PAYMENT_SCENARIO = 'FAKE-E5-09';
    process.env.FAKE_RECONCILE_INTERVAL_MS = '60000';
    process.env.PRODUCT_INITIAL_STOCK = '3';
    write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    application = await createApplication();
    await application.init();
  });

  afterAll(async () => {
    await application.close();
    write.mockRestore();
    delete process.env.APP_ENV;
    delete process.env.DATA_ADAPTER;
    delete process.env.FAKE_PAYMENT_SCENARIO;
    delete process.env.FAKE_RECONCILE_INTERVAL_MS;
    delete process.env.PRODUCT_INITIAL_STOCK;
  });

  it('serves API-01/03 and the complete capability checkout without PAN/CVC', async () => {
    const catalog = await request(application.getHttpServer()).get('/api/v1/products').expect(200);
    expect(catalog.headers['cache-control']).toBe('no-cache');
    expect(catalog.body).toMatchObject({
      count: 1,
      items: [{ productId: PRODUCT_ID, available: 3 }],
    });
    expect(catalog.body.items[0]).not.toHaveProperty('onHand');
    expect(catalog.body.items[0]).not.toHaveProperty('reserved');

    const stock = await request(application.getHttpServer())
      .get(`/api/v1/stock/${PRODUCT_ID}`)
      .expect(200);
    expect(stock.headers['cache-control']).toBe('no-cache');
    expect(stock.body).toEqual({
      productId: PRODUCT_ID,
      available: 3,
      asOf: '2026-01-01T00:00:00.000Z',
    });

    const created = await request(application.getHttpServer())
      .post('/api/v1/checkouts')
      .set('Origin', ORIGIN)
      .send({ productId: PRODUCT_ID })
      .expect(201);
    expect(created.headers.location).toBe(`/api/v1/checkouts/${created.body.checkoutId}`);
    expect(created.headers.etag).toBe('"checkout-v1"');
    const setCookie = (created.headers['set-cookie'] as unknown as string[])[0] as string;
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('Secure');
    expect(setCookie).toContain('SameSite=Strict');
    expect(setCookie).toContain('Path=/api/v1');
    const cookie = cookiePair(created.headers);

    await request(application.getHttpServer())
      .get(`/api/v1/checkouts/${created.body.checkoutId}`)
      .set('Cookie', '__Secure-checkout_cap=wrong.value')
      .expect(404);
    await request(application.getHttpServer())
      .get(`/api/v1/checkouts/${created.body.checkoutId}`)
      .set('Cookie', '__Secure-checkout_cap=%E0%A4%A')
      .expect(404);

    const customer = await request(application.getHttpServer())
      .put(`/api/v1/checkouts/${created.body.checkoutId}/customer`)
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .set('If-Match', created.headers.etag as string)
      .send({ fullName: 'Ada Lovelace', email: 'ADA@example.invalid', phone: '+573001234567' })
      .expect(200);
    expect(customer.headers.etag).toBe('"checkout-v2"');
    expect(customer.body).toMatchObject({ email: 'ada@example.invalid', version: 2 });

    const staleCustomer = await request(application.getHttpServer())
      .put(`/api/v1/checkouts/${created.body.checkoutId}/customer`)
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .set('If-Match', '"checkout-v1"')
      .send({ fullName: 'Ada Lovelace', email: 'ada@example.invalid', phone: '+573001234567' })
      .expect(412);
    expect(staleCustomer.headers.etag).toBe('"checkout-v2"');

    const delivery = await request(application.getHttpServer())
      .put(`/api/v1/checkouts/${created.body.checkoutId}/delivery-details`)
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .set('If-Match', customer.headers.etag as string)
      .send({
        addressLine1: 'Calle 100 # 10-20',
        addressLine2: 'Apto 302',
        city: 'Bogota',
        region: 'Cundinamarca',
        postalCode: '110111',
        deliveryInstructions: 'Porteria',
      })
      .expect(200);
    expect(delivery.headers.etag).toBe('"checkout-v3"');

    const configuration = await request(application.getHttpServer())
      .get('/api/v1/payment-configuration')
      .expect(200);
    expect(configuration.body).toMatchObject({
      captureVariant: 'FAKE_CONTRACT',
      allowedInstallments: [1, 2, 3],
    });
    expect(configuration.body.acceptanceContracts).toHaveLength(2);

    const payment = {
      quoteId: created.body.quote.quoteId,
      paymentMethodToken: 'tok_fake_synthetic_http',
      installments: 1,
      acceptances: {
        termsAcceptanceToken: configuration.body.acceptanceContracts[0].acceptanceToken,
        personalDataAcceptanceToken: configuration.body.acceptanceContracts[1].acceptanceToken,
      },
    };
    await request(application.getHttpServer())
      .post(`/api/v1/checkouts/${created.body.checkoutId}/transactions`)
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .set('If-Match', delivery.headers.etag as string)
      .set('Idempotency-Key', 'idem-http-invalid-001')
      .send({ ...payment, pan: ['4242', '4242', '4242', '4242'].join(''), cvc: '123' })
      .expect(422);

    const submitted = await request(application.getHttpServer())
      .post(`/api/v1/checkouts/${created.body.checkoutId}/transactions`)
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .set('If-Match', delivery.headers.etag as string)
      .set('Idempotency-Key', 'idem-http-valid-0001')
      .send(payment)
      .expect(202);
    expect(submitted.headers.location).toBe(submitted.body.statusUrl);

    const transaction = await request(application.getHttpServer())
      .get(submitted.body.statusUrl)
      .set('Cookie', cookie)
      .expect(200);
    expect(transaction.body).toMatchObject({
      paymentStatus: 'APPROVED',
      reservationStatus: 'CONSUMED',
      integrityStatus: 'OK',
    });
    expect(transaction.body).not.toHaveProperty('providerId');
    expect(transaction.body).not.toHaveProperty('providerReference');

    const refreshedCatalog = await request(application.getHttpServer())
      .get('/api/v1/products')
      .expect(200);
    expect(refreshedCatalog.headers['cache-control']).toBe('no-cache');
    expect(refreshedCatalog.body.items[0]).toMatchObject({
      productId: PRODUCT_ID,
      available: 2,
    });

    const assignedDelivery = await request(application.getHttpServer())
      .get(`/api/v1/deliveries/${transaction.body.deliveryId}`)
      .set('Cookie', cookie)
      .expect(200);
    expect(assignedDelivery.body).toMatchObject({
      transactionId: submitted.body.transactionId,
      status: 'CREATED',
    });

    const recovered = await request(application.getHttpServer())
      .get(`/api/v1/checkouts/${created.body.checkoutId}`)
      .set('Cookie', cookie)
      .expect(200);
    expect(recovered.body.status).toBe('PAID');
    expect(recovered.body).not.toHaveProperty('capabilityHash');
  });

  it('returns safe problems for forbidden origin, malformed JSON, and missing stock', async () => {
    await request(application.getHttpServer())
      .post('/api/v1/checkouts')
      .send({ productId: PRODUCT_ID })
      .expect(403)
      .expect(({ body }) => expect(body.code).toBe('ORIGIN_FORBIDDEN'));
    await request(application.getHttpServer())
      .get('/api/v1/products')
      .set('Origin', 'https://hostile.invalid')
      .expect(403)
      .expect('Cache-Control', 'no-store')
      .expect(({ body }) => expect(body.code).toBe('ORIGIN_FORBIDDEN'));

    await request(application.getHttpServer())
      .post('/api/v1/checkouts')
      .set('Origin', ORIGIN)
      .set('Content-Type', 'application/json')
      .send('{"productId":')
      .expect(400)
      .expect('Cache-Control', 'no-store')
      .expect(({ body }) => expect(body.code).toBe('REQUEST_MALFORMED'));

    await request(application.getHttpServer())
      .post('/api/v1/checkouts')
      .set('Origin', ORIGIN)
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`productId=${PRODUCT_ID}`)
      .expect(415)
      .expect('Cache-Control', 'no-store')
      .expect('Content-Type', /application\/problem\+json/)
      .expect(({ body }) => expect(body.code).toBe('REQUEST_MALFORMED'));

    await request(application.getHttpServer())
      .post('/api/v1/checkouts')
      .set('Origin', ORIGIN)
      .set('Content-Type', 'application/json')
      .send({ productId: 'x'.repeat(17_000) })
      .expect(413)
      .expect('Cache-Control', 'no-store')
      .expect('Content-Type', /application\/problem\+json/)
      .expect(({ body }) => expect(body.code).toBe('REQUEST_MALFORMED'));

    await request(application.getHttpServer())
      .get('/api/v1/stock/missing-product')
      .expect(404)
      .expect(({ body }) => expect(body.code).toBe('PRODUCT_NOT_FOUND'));
  });
});

describe('E5 HTTP recovery headers', () => {
  let application: INestApplication;
  let write: jest.SpyInstance;

  beforeAll(async () => {
    process.env.APP_ENV = 'test';
    process.env.DATA_ADAPTER = 'memory';
    process.env.FAKE_PAYMENT_SCENARIO = 'FAKE-E5-04';
    process.env.FAKE_RECONCILE_INTERVAL_MS = '60000';
    process.env.PRODUCT_INITIAL_STOCK = '1';
    write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    application = await createApplication();
    await application.init();
  });

  afterAll(async () => {
    await application.close();
    write.mockRestore();
    delete process.env.APP_ENV;
    delete process.env.DATA_ADAPTER;
    delete process.env.FAKE_PAYMENT_SCENARIO;
    delete process.env.FAKE_RECONCILE_INTERVAL_MS;
    delete process.env.PRODUCT_INITIAL_STOCK;
  });

  it('returns the canonical Location when another payment key targets an active attempt', async () => {
    const created = await request(application.getHttpServer())
      .post('/api/v1/checkouts')
      .set('Origin', ORIGIN)
      .send({ productId: PRODUCT_ID })
      .expect(201);
    const cookie = cookiePair(created.headers);
    const customer = await request(application.getHttpServer())
      .put(`/api/v1/checkouts/${created.body.checkoutId}/customer`)
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .set('If-Match', created.headers.etag as string)
      .send({ fullName: 'Grace Hopper', email: 'grace@example.invalid', phone: '+573001112233' })
      .expect(200);
    const delivery = await request(application.getHttpServer())
      .put(`/api/v1/checkouts/${created.body.checkoutId}/delivery-details`)
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .set('If-Match', customer.headers.etag as string)
      .send({ addressLine1: 'Calle 10 # 20-30', city: 'Bogota', region: 'Cundinamarca' })
      .expect(200);
    const configuration = await request(application.getHttpServer())
      .get('/api/v1/payment-configuration')
      .expect(200);
    const payment = {
      quoteId: created.body.quote.quoteId,
      paymentMethodToken: 'tok_fake_recovery001',
      installments: 1,
      acceptances: {
        termsAcceptanceToken: configuration.body.acceptanceContracts[0].acceptanceToken,
        personalDataAcceptanceToken: configuration.body.acceptanceContracts[1].acceptanceToken,
      },
    };
    const first = await request(application.getHttpServer())
      .post(`/api/v1/checkouts/${created.body.checkoutId}/transactions`)
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .set('If-Match', delivery.headers.etag as string)
      .set('Idempotency-Key', 'idem-recovery-first-001')
      .send(payment)
      .expect(202);
    const current = await request(application.getHttpServer())
      .get(`/api/v1/checkouts/${created.body.checkoutId}`)
      .set('Cookie', cookie)
      .expect(200);
    const conflict = await request(application.getHttpServer())
      .post(`/api/v1/checkouts/${created.body.checkoutId}/transactions`)
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .set('If-Match', current.headers.etag as string)
      .set('Idempotency-Key', 'idem-recovery-second-001')
      .send(payment)
      .expect(409);
    expect(conflict.body.code).toBe('PAYMENT_ALREADY_IN_PROGRESS');
    expect(conflict.headers.location).toBe(first.body.statusUrl);
  });
});

describe('E5 HTTP rate limit', () => {
  let application: INestApplication;
  let write: jest.SpyInstance;

  beforeAll(async () => {
    process.env.APP_ENV = 'test';
    process.env.DATA_ADAPTER = 'memory';
    process.env.FAKE_PAYMENT_SCENARIO = 'FAKE-E5-04';
    process.env.FAKE_RECONCILE_INTERVAL_MS = '60000';
    write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    application = await createApplication();
    await application.init();
  });

  afterAll(async () => {
    await application.close();
    write.mockRestore();
  });

  it('limits the third payment POST and emits Retry-After without reaching the application', async () => {
    const paymentPath = '/api/v1/checkouts/checkout-rate-001/transactions';
    const body = {
      quoteId: 'quote_rate_001',
      paymentMethodToken: 'tok_fake_ratecheck001',
      installments: 1,
      acceptances: {
        termsAcceptanceToken: 'A'.repeat(32) + '.' + 'B'.repeat(43),
        personalDataAcceptanceToken: 'C'.repeat(32) + '.' + 'D'.repeat(43),
      },
    };
    for (let index = 0; index < 2; index += 1) {
      const attempted = await request(application.getHttpServer())
        .post(paymentPath)
        .set('Origin', ORIGIN)
        .set('Cookie', '__Secure-checkout_cap=rate.check')
        .set('If-Match', '"checkout-v1"')
        .set('Idempotency-Key', 'idem-rate-payment-001')
        .send(body);
      expect(attempted.status).not.toBe(429);
      expect(attempted.headers['x-ratelimit-limit']).toBe('2');
    }
    const limited = await request(application.getHttpServer())
      .post(paymentPath)
      .set('Origin', ORIGIN)
      .set('Cookie', '__Secure-checkout_cap=rate.rotated')
      .set('If-Match', '"checkout-v1"')
      .set('Idempotency-Key', 'idem-rate-payment-001')
      .send(body)
      .expect(429);
    expect(limited.headers['x-ratelimit-limit']).toBe('2');
    expect(limited.headers['x-ratelimit-remaining']).toBe('0');
    expect(limited.headers['retry-after']).toBe('30');
    expect(limited.body.code).toBe('RATE_LIMITED');
  });

  it('allows a burst of 10 and returns 429 + Retry-After for the 11th command', async () => {
    for (let index = 0; index < 10; index += 1) {
      const response = await request(application.getHttpServer())
        .post('/api/v1/checkouts')
        .set('Origin', ORIGIN)
        .send({ productId: PRODUCT_ID })
        .expect(201);
      expect(response.headers['x-ratelimit-limit']).toBe('10');
    }
    const limited = await request(application.getHttpServer())
      .post('/api/v1/checkouts')
      .set('Origin', ORIGIN)
      .send({ productId: PRODUCT_ID })
      .expect(429);
    expect(limited.headers['retry-after']).toBe('6');
    expect(limited.headers['x-ratelimit-remaining']).toBe('0');
    expect(limited.body.code).toBe('RATE_LIMITED');
  });
});
