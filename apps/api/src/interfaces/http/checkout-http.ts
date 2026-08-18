import type { Response } from 'express';
import { z } from 'zod';
import type {
  CheckoutApplicationError,
  SubmitPaymentInput,
} from '../../application/use-cases/checkout-service';
import type { Result } from '../../application/result/result';
import type { Checkout, DeliveryDetails } from '../../domain/checkout/checkout';
import { createProblem, ProblemException } from './problems/problem';
import type { RequestWithCorrelation } from './request-context';

const opaqueId = z.string().regex(/^[A-Za-z0-9_-]{8,128}$/);
const fakePaymentToken = z.string().regex(/^tok_fake_[A-Za-z0-9_-]{8,128}$/);
const sandboxPaymentToken = z.string().regex(/^tok_(?!fake_)[A-Za-z0-9_-]{8,256}$/u);
const acceptanceToken = z.string().regex(/^[A-Za-z0-9_-]{32,512}\.[A-Za-z0-9_-]{43}$/);
export const CAPABILITY_COOKIE_NAME = '__Secure-checkout_cap';
const CAPABILITY_MAX_AGE_SECONDS = 86_400;

export type PaymentTokenValidationMode = 'FAKE' | 'AUTHORIZED_SANDBOX' | 'DISABLED';

export const createCheckoutSchema = z.object({ productId: opaqueId }).strict();
export const customerSchema = z
  .object({
    fullName: z.string().trim().min(2).max(120),
    email: z.email().max(254),
    phone: z.string().regex(/^\+?[0-9]{8,15}$/),
  })
  .strict();
export const deliveryDetailsSchema = z
  .object({
    addressLine1: z.string().trim().min(5).max(160),
    addressLine2: z.string().trim().max(160).optional(),
    city: z.string().trim().min(2).max(80),
    region: z.string().trim().min(2).max(80),
    postalCode: z
      .string()
      .regex(/^[A-Za-z0-9 -]{3,12}$/)
      .optional(),
    deliveryInstructions: z.string().trim().max(250).optional(),
  })
  .strict();
const paymentTokenSchemaFor = (mode: PaymentTokenValidationMode): z.ZodType<string> => {
  if (mode === 'FAKE') return fakePaymentToken;
  if (mode === 'AUTHORIZED_SANDBOX') return sandboxPaymentToken;
  return z.string().refine(() => false, 'Payment submission is disabled');
};

export const paymentSubmissionSchemaFor = (
  mode: PaymentTokenValidationMode,
): z.ZodType<SubmitPaymentInput> =>
  z
    .object({
      quoteId: opaqueId,
      paymentMethodToken: paymentTokenSchemaFor(mode),
      installments: z.number().int().min(1).max(36),
      acceptances: z
        .object({
          termsAcceptanceToken: acceptanceToken,
          personalDataAcceptanceToken: acceptanceToken,
        })
        .strict(),
    })
    .strict();

export const paymentSubmissionSchema = paymentSubmissionSchemaFor('FAKE');
export const parseBody = <T>(
  schema: z.ZodType<T>,
  body: unknown,
  request: RequestWithCorrelation,
): T => {
  const parsed = schema.safeParse(body);
  if (parsed.success) return parsed.data;
  throw new ProblemException(
    createProblem('FIELD_INVALID', 422, request.correlationId, request.originalUrl),
  );
};

const applicationStatus: Readonly<Record<CheckoutApplicationError['code'], number>> = {
  PRODUCT_NOT_FOUND: 404,
  CHECKOUT_NOT_FOUND_OR_FORBIDDEN: 404,
  CHECKOUT_EXPIRED: 410,
  PRECONDITION_FAILED: 412,
  FIELD_INVALID: 422,
  OUT_OF_STOCK: 409,
  QUOTE_STALE: 409,
  IDEMPOTENCY_CONFLICT: 409,
  PAYMENT_ALREADY_IN_PROGRESS: 409,
  STATE_TRANSITION_CONFLICT: 409,
  PROVIDER_AUTH_OR_CONFIG_INVALID: 503,
  INTERNAL_ERROR: 500,
};

export const unwrap = <T>(
  result: Result<T, CheckoutApplicationError>,
  request: RequestWithCorrelation,
): T => {
  if (result.ok) return result.value;
  throw new ProblemException(
    createProblem(
      result.error.code,
      applicationStatus[result.error.code],
      request.correlationId,
      request.originalUrl,
    ),
  );
};

export const capabilityFrom = (request: RequestWithCorrelation): string | null => {
  const cookieHeader = request.headers.cookie;
  if (cookieHeader === undefined) return null;
  for (const part of cookieHeader.split(';')) {
    const [name, ...value] = part.trim().split('=');
    if (name === CAPABILITY_COOKIE_NAME) {
      try {
        return decodeURIComponent(value.join('='));
      } catch {
        return null;
      }
    }
  }
  return null;
};

export const setCheckoutHeaders = (response: Response, checkout: Checkout): void => {
  response.setHeader('ETag', `"checkout-v${checkout.version}"`);
  response.setHeader('Cache-Control', 'no-store');
};

export const capabilityCookie = (raw: string): string =>
  `${CAPABILITY_COOKIE_NAME}=${encodeURIComponent(raw)}; Path=/api/v1; HttpOnly; Secure; SameSite=Strict; Max-Age=${CAPABILITY_MAX_AGE_SECONDS}`;

export type DeliveryInput = Omit<DeliveryDetails, 'checkoutId' | 'version'>;
