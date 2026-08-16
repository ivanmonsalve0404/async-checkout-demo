import type { ZodType } from 'zod';
import type { Response } from 'express';
import { err, ok } from '../../application/result/result';
import type { CheckoutApplicationError } from '../../application/use-cases/checkout-service';
import type { Checkout } from '../../domain/checkout/checkout';
import {
  capabilityCookie,
  capabilityFrom,
  createCheckoutSchema,
  customerSchema,
  parseBody,
  paymentSubmissionSchema,
  setCheckoutHeaders,
  unwrap,
} from './checkout-http';
import { ProblemException } from './problems/problem';
import type { RequestWithCorrelation } from './request-context';

const request = (cookie?: string): RequestWithCorrelation =>
  ({
    correlationId: 'corr-001',
    originalUrl: '/api/v1/checkouts/checkout-001/transactions',
    headers: cookie === undefined ? {} : { cookie },
  }) as RequestWithCorrelation;

const validPayment = {
  quoteId: 'quote_0001',
  paymentMethodToken: 'tok_fake_synthetic123',
  installments: 1,
  acceptances: {
    termsAcceptanceToken: 'A'.repeat(32) + '.' + 'B'.repeat(43),
    personalDataAcceptanceToken: 'C'.repeat(32) + '.' + 'D'.repeat(43),
  },
};

describe('checkout HTTP boundary helpers', () => {
  it('parses strict public bodies and trims customer text', () => {
    expect(parseBody(createCheckoutSchema, { productId: 'product_001' }, request())).toEqual({
      productId: 'product_001',
    });
    expect(
      parseBody(
        customerSchema,
        {
          fullName: '  Ada Lovelace  ',
          email: 'ada@example.invalid',
          phone: '+573001234567',
        },
        request(),
      ),
    ).toMatchObject({ fullName: 'Ada Lovelace' });
    expect(parseBody(paymentSubmissionSchema, validPayment, request())).toEqual(validPayment);
  });

  it.each([
    [{ productId: 'short' }, createCheckoutSchema],
    [
      {
        ...validPayment,
        pan: ['4242', '4242', '4242', '4242'].join(''),
        cvc: '123',
      },
      paymentSubmissionSchema,
    ],
    [
      { ...validPayment, paymentMethodToken: ['4242', '4242', '4242', '4242'].join('') },
      paymentSubmissionSchema,
    ],
    [{ ...validPayment, paymentMethodToken: ['1', '2', '3'].join('') }, paymentSubmissionSchema],
  ])('rejects invalid or forbidden body %# as FIELD_INVALID', (body, schema) => {
    try {
      parseBody(schema as ZodType<unknown>, body, request());
      throw new Error('expected validation failure');
    } catch (error) {
      expect(error).toBeInstanceOf(ProblemException);
      const problem = (error as ProblemException).getResponse();
      expect(problem).toMatchObject({
        code: 'FIELD_INVALID',
        status: 422,
        correlationId: 'corr-001',
      });
    }
  });

  it('unwraps successful application results', () => {
    expect(unwrap(ok({ value: 42 }), request())).toEqual({ value: 42 });
  });

  it.each([
    ['PRODUCT_NOT_FOUND', 404],
    ['CHECKOUT_NOT_FOUND_OR_FORBIDDEN', 404],
    ['CHECKOUT_EXPIRED', 410],
    ['PRECONDITION_FAILED', 412],
    ['FIELD_INVALID', 422],
    ['OUT_OF_STOCK', 409],
    ['QUOTE_STALE', 409],
    ['IDEMPOTENCY_CONFLICT', 409],
    ['PAYMENT_ALREADY_IN_PROGRESS', 409],
    ['STATE_TRANSITION_CONFLICT', 409],
    ['PROVIDER_AUTH_OR_CONFIG_INVALID', 503],
    ['INTERNAL_ERROR', 500],
  ] as const)('maps application error %s to HTTP %s', (code, status) => {
    const result = err({ code } satisfies CheckoutApplicationError);
    try {
      unwrap(result, request());
      throw new Error('expected application error');
    } catch (error) {
      expect(error).toBeInstanceOf(ProblemException);
      expect((error as ProblemException).getStatus()).toBe(status);
      expect((error as ProblemException).getResponse()).toMatchObject({ code, status });
    }
  });

  it('reads only the scoped capability cookie and treats malformed encoding as absent', () => {
    expect(capabilityFrom(request())).toBeNull();
    expect(capabilityFrom(request('theme=dark; other=value'))).toBeNull();
    expect(capabilityFrom(request('checkout_capability=legacy.value'))).toBeNull();
    expect(
      capabilityFrom(request('theme=dark; __Secure-checkout_cap=checkout-001.cap%3Dvalue')),
    ).toBe('checkout-001.cap=value');
    expect(capabilityFrom(request('__Secure-checkout_cap=%E0%A4%A'))).toBeNull();
  });

  it('emits secure cookie and no-store optimistic-concurrency headers', () => {
    expect(capabilityCookie('checkout-001.cap=value')).toBe(
      '__Secure-checkout_cap=checkout-001.cap%3Dvalue; Path=/api/v1; HttpOnly; Secure; SameSite=Strict; Max-Age=86400',
    );
    const setHeader = jest.fn();
    setCheckoutHeaders({ setHeader } as unknown as Response, { version: 7 } as Checkout);
    expect(setHeader.mock.calls).toEqual([
      ['ETag', '"checkout-v7"'],
      ['Cache-Control', 'no-store'],
    ]);
  });
});
