import { capabilityFrom, parseBody, paymentSubmissionSchema } from '../checkout-http';
import { ProblemException } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';

const request = (cookie?: string): RequestWithCorrelation =>
  ({
    correlationId: 'correlation-e6-boundary',
    originalUrl: '/api/v1/checkouts/redacted/transactions',
    headers: cookie === undefined ? {} : { cookie },
  }) as RequestWithCorrelation;

const payment = {
  quoteId: 'quote_synthetic_e6',
  paymentMethodToken: 'tok_fake_synthetic_e6',
  installments: 1,
  acceptances: {
    termsAcceptanceToken: `${'A'.repeat(32)}.${'B'.repeat(43)}`,
    personalDataAcceptanceToken: `${'C'.repeat(32)}.${'D'.repeat(43)}`,
  },
};

describe('E6 negative HTTP boundaries', () => {
  it('[E2E-E6-13] rejects a client-supplied total instead of trusting it', () => {
    expect(() => parseBody(paymentSubmissionSchema, { ...payment, total: 1 }, request())).toThrow(
      ProblemException,
    );
  });

  it('[E2E-E6-15] accepts only the scoped, well-encoded capability cookie', () => {
    expect(capabilityFrom(request('unrelated=value'))).toBeNull();
    expect(capabilityFrom(request('__Secure-checkout_cap=%E0%A4%A'))).toBeNull();
  });

  it('[E2E-E6-22] returns a safe problem without echoing rejected fields', () => {
    try {
      parseBody(paymentSubmissionSchema, { ...payment, forbiddenField: 'rejected' }, request());
      throw new Error('expected validation failure');
    } catch (error) {
      expect(error).toBeInstanceOf(ProblemException);
      expect(JSON.stringify((error as ProblemException).getResponse())).not.toContain('rejected');
    }
  });
});
