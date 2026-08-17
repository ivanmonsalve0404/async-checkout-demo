import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { createApplication } from '../../../bootstrap';

describe('E6 initially unavailable product fixture', () => {
  let application: INestApplication;
  let write: jest.SpyInstance;

  beforeAll(async () => {
    process.env.APP_ENV = 'test';
    process.env.DATA_ADAPTER = 'memory';
    process.env.PRODUCT_INITIAL_STOCK = '0';
    write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    application = await createApplication();
    await application.init();
  });

  afterAll(async () => {
    await application.close();
    write.mockRestore();
    delete process.env.APP_ENV;
    delete process.env.DATA_ADAPTER;
    delete process.env.PRODUCT_INITIAL_STOCK;
  });

  it('[E2E-E6-23] rejects checkout when the product starts without stock', async () => {
    await request(application.getHttpServer())
      .post('/api/v1/checkouts')
      .set('Origin', 'http://localhost:5173')
      .send({ productId: 'product-demo-001' })
      .expect(409)
      .expect(({ body }) => expect(body).toMatchObject({ code: 'OUT_OF_STOCK' }));
  });
});
