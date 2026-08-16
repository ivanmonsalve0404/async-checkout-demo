import type { components } from '@checkout/contracts';
import { z } from 'zod';
import { checkoutEtag } from '../api/checkout-api';

export type PaymentSubmissionRequest = components['schemas']['PaymentSubmissionRequest'];
export type PaymentSubmissionResponse = components['schemas']['PaymentSubmissionResponse'];
export type PaymentProblemCode =
  | 'QUOTE_STALE'
  | 'OUT_OF_STOCK'
  | 'IDEMPOTENCY_CONFLICT'
  | 'PAYMENT_ALREADY_IN_PROGRESS'
  | 'PRECONDITION_FAILED'
  | 'CHECKOUT_EXPIRED'
  | 'PAYMENT_TOKEN_REJECTED';

export interface SubmitPaymentInput {
  readonly checkoutId: string;
  readonly version: number;
  readonly idempotencyKey: string;
  readonly body: PaymentSubmissionRequest;
}

export class PaymentCommandError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: PaymentProblemCode | undefined = undefined,
  ) {
    super('PAYMENT_COMMAND_FAILED');
    this.name = 'PaymentCommandError';
  }
}

const responseSchema = z
  .object({
    transactionId: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/),
    statusUrl: z.string().regex(/^\/api\/v1\/transactions\/[A-Za-z0-9_-]+$/),
    submissionState: z.literal('ACCEPTED'),
    acceptedAt: z.string().min(1),
  })
  .strict();

const problemSchema = z
  .object({
    code: z
      .enum([
        'QUOTE_STALE',
        'OUT_OF_STOCK',
        'IDEMPOTENCY_CONFLICT',
        'PAYMENT_ALREADY_IN_PROGRESS',
        'PRECONDITION_FAILED',
        'CHECKOUT_EXPIRED',
        'PAYMENT_TOKEN_REJECTED',
      ])
      .optional(),
  })
  .passthrough();

export const buildPaymentCommandRequest = (
  input: SubmitPaymentInput,
): { readonly url: string; readonly init: RequestInit } => ({
  url: '/api/v1/checkouts/' + encodeURIComponent(input.checkoutId) + '/transactions',
  init: {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'If-Match': checkoutEtag(input.version),
      'Idempotency-Key': input.idempotencyKey,
    },
    body: JSON.stringify(input.body),
  },
});

export const submitPayment = async (
  input: SubmitPaymentInput,
  request: typeof fetch = fetch,
): Promise<PaymentSubmissionResponse> => {
  const command = buildPaymentCommandRequest(input);
  const response = await request(command.url, command.init);
  if (!response.ok) {
    let code: PaymentProblemCode | undefined;
    try {
      const problem: unknown = await response.json();
      code = problemSchema.parse(problem).code;
    } catch {
      code = undefined;
    }
    throw new PaymentCommandError(response.status, code);
  }
  const value: unknown = await response.json();
  return responseSchema.parse(value);
};
