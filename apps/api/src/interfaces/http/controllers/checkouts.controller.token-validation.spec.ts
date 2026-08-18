import 'reflect-metadata';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { APP_CONFIG, type AppConfig } from '../../../infrastructure/configuration/app-config';
import { CheckoutService } from '../../../application/use-cases/checkout-service';
import { ok } from '../../../application/result/result';
import { CheckoutsController } from './checkouts.controller';

type TokenConfiguration = Pick<AppConfig, 'paymentAdapter' | 'paymentsEnabled'>;

const acceptedSubmission = {
  transactionId: 'transaction_token_validation_001',
  statusUrl: '/api/v1/transactions/transaction_token_validation_001',
  submissionState: 'ACCEPTED' as const,
  acceptedAt: '2026-08-17T00:00:00.000Z',
};

const paymentBody = (
  paymentMethodToken: string,
  extra: Readonly<Record<string, unknown>> = {},
): Readonly<Record<string, unknown>> => ({
  quoteId: 'quote_token_validation_001',
  paymentMethodToken,
  installments: 1,
  acceptances: {
    termsAcceptanceToken: 'A'.repeat(32) + '.' + 'B'.repeat(43),
    personalDataAcceptanceToken: 'C'.repeat(32) + '.' + 'D'.repeat(43),
  },
  ...extra,
});

const createTokenValidationApplication = async (
  configuration: TokenConfiguration,
): Promise<Readonly<{ application: INestApplication; submitPayment: jest.Mock }>> => {
  const submitPayment = jest.fn().mockResolvedValue(ok(acceptedSubmission));
  const module = await Test.createTestingModule({
    controllers: [CheckoutsController],
    providers: [
      { provide: CheckoutService, useValue: { submitPayment } },
      { provide: APP_CONFIG, useValue: configuration },
    ],
  }).compile();
  const application = module.createNestApplication();
  await application.init();
  return { application, submitPayment };
};

const submit = (application: INestApplication, body: Readonly<Record<string, unknown>>) =>
  request(application.getHttpServer())
    .post('/api/v1/checkouts/checkout_token_validation_001/transactions')
    .set('If-Match', '"checkout-v3"')
    .set('Idempotency-Key', 'idem-token-validation-001')
    .send(body);

describe('CheckoutsController token validation', () => {
  it.each([
    [
      'fake adapter',
      { paymentAdapter: 'fake', paymentsEnabled: false } satisfies TokenConfiguration,
      'tok_fake_synthetic123',
    ],
    [
      'authorized sandbox adapter',
      { paymentAdapter: 'sandbox', paymentsEnabled: true } satisfies TokenConfiguration,
      'tok_test_provideropaque123',
    ],
  ])('accepts the opaque token format for the %s', async (_name, configuration, token) => {
    const { application, submitPayment } = await createTokenValidationApplication(configuration);
    try {
      const response = await submit(application, paymentBody(token)).expect(202);

      expect(response.headers.location).toBe(acceptedSubmission.statusUrl);
      expect(submitPayment).toHaveBeenCalledWith(
        'checkout_token_validation_001',
        null,
        '"checkout-v3"',
        'idem-token-validation-001',
        expect.objectContaining({ paymentMethodToken: token }),
      );
    } finally {
      await application.close();
    }
  });

  it.each([
    [
      'fake adapter',
      { paymentAdapter: 'fake', paymentsEnabled: false } satisfies TokenConfiguration,
      'tok_test_provideropaque123',
    ],
    [
      'authorized sandbox adapter',
      { paymentAdapter: 'sandbox', paymentsEnabled: true } satisfies TokenConfiguration,
      'tok_fake_synthetic123',
    ],
  ])('rejects the other token family for the %s', async (_name, configuration, token) => {
    const { application, submitPayment } = await createTokenValidationApplication(configuration);
    try {
      await submit(application, paymentBody(token)).expect(422);
      expect(submitPayment).not.toHaveBeenCalled();
    } finally {
      await application.close();
    }
  });

  it.each([
    [
      'fake adapter',
      { paymentAdapter: 'fake', paymentsEnabled: false } satisfies TokenConfiguration,
      'tok_fake_synthetic123',
    ],
    [
      'authorized sandbox adapter',
      { paymentAdapter: 'sandbox', paymentsEnabled: true } satisfies TokenConfiguration,
      'tok_test_provideropaque123',
    ],
  ])(
    'rejects a PAN or CVC field before the service for the %s',
    async (_name, configuration, token) => {
      const { application, submitPayment } = await createTokenValidationApplication(configuration);
      try {
        await submit(
          application,
          paymentBody(token, {
            pan: ['4242', '4242', '4242', '4242'].join(''),
            cvc: '123',
          }),
        ).expect(422);
        expect(submitPayment).not.toHaveBeenCalled();
      } finally {
        await application.close();
      }
    },
  );
});
