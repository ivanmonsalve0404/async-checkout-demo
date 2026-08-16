import {
  PaymentCommandError,
  buildPaymentCommandRequest,
  submitPayment,
  type SubmitPaymentInput,
} from './submit-payment';

const input: SubmitPaymentInput = {
  checkoutId: 'checkout_123456',
  version: 3,
  idempotencyKey: 'idem_1234567890123456',
  body: {
    quoteId: 'quote_12345678',
    paymentMethodToken: 'opaque-method-synthetic',
    installments: 1,
    acceptances: {
      termsAcceptanceToken: 'terms-synthetic',
      personalDataAcceptanceToken: 'privacy-synthetic',
    },
  },
};

describe('payment command boundary', () => {
  it('builds the exact idempotent OAS request without card fields', () => {
    const command = buildPaymentCommandRequest(input);
    expect(command.url).toBe('/api/v1/checkouts/checkout_123456/transactions');
    expect(command.init).toMatchObject({
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'If-Match': '"checkout-v3"',
        'Idempotency-Key': input.idempotencyKey,
      },
    });
    if (typeof command.init.body !== 'string') {
      throw new Error('Expected a JSON request body');
    }
    const body = command.init.body;
    expect(body).not.toMatch(/number|securityCode|expiry|holderName|pan|cvc/i);
    expect(JSON.parse(body)).toEqual(input.body);
  });

  it('parses the stable 202 response', async () => {
    const request = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        transactionId: 'transaction_123456',
        statusUrl: '/api/v1/transactions/transaction_123456',
        submissionState: 'ACCEPTED',
        acceptedAt: '2026-01-01T00:00:00Z',
      }),
    });
    await expect(submitPayment(input, request)).resolves.toMatchObject({
      transactionId: 'transaction_123456',
    });
    expect(request).toHaveBeenCalledTimes(1);
  });

  it.each([
    [409, 'QUOTE_STALE'],
    [412, 'PRECONDITION_FAILED'],
  ] as const)('parses allowlisted RFC 9457 code %s', async (status, code) => {
    const rejected = jest.fn().mockResolvedValue({
      ok: false,
      status,
      json: async () => ({
        type: 'https://example.test/problems/payment',
        title: 'Synthetic problem',
        status,
        code,
      }),
    });

    await expect(submitPayment(input, rejected)).rejects.toEqual(
      new PaymentCommandError(status, code),
    );
  });

  it('fails closed for an unrecognised problem code and rejects success response drift', async () => {
    const rejected = jest.fn().mockResolvedValue({
      ok: false,
      status: 409,
      json: async () => ({ code: 'NOT_AN_ALLOWLISTED_CODE' }),
    });
    await expect(submitPayment(input, rejected)).rejects.toEqual(new PaymentCommandError(409));

    const malformed = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ transactionId: 'raw' }),
    });
    await expect(submitPayment(input, malformed)).rejects.toThrow();
  });
});
