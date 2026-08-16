import type { components } from '@checkout/contracts';
import { z } from 'zod';
import { baseApi } from '../../../app/api/base-api';

export type CheckoutCreatedResponse = components['schemas']['CheckoutCreatedResponse'];
export type CheckoutResponse = components['schemas']['CheckoutResponse'];
export type CustomerRequest = components['schemas']['ReplaceCustomerRequest'];
export type DeliveryRequest = components['schemas']['ReplaceDeliveryDetailsRequest'];
export type PaymentConfigurationResponse = components['schemas']['PaymentConfigurationResponse'];
export type TransactionResponse = components['schemas']['TransactionResponse'];

const opaqueId = z.string().regex(/^[A-Za-z0-9_-]{8,128}$/);
const dateTime = z.string().datetime({ offset: true });
const money = z
  .object({
    amountInCents: z.number().int().min(0).max(999_999_999_999),
    currency: z.literal('COP'),
  })
  .strict();
const product = z
  .object({
    productId: opaqueId,
    sku: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[A-Za-z0-9_-]+$/),
    name: z.string().min(1).max(120),
    description: z.string().min(1).max(1_000),
    imageUrl: z.string().url().max(2_048),
    unitPrice: money,
    available: z.number().int().min(0).max(999_999),
  })
  .strict();
const quote = z
  .object({
    quoteId: opaqueId,
    version: z.number().int().positive(),
    productId: opaqueId,
    quantity: z.literal(1),
    subtotal: money,
    baseFee: money,
    deliveryFee: money,
    total: money,
    expiresAt: dateTime,
  })
  .strict();
const customer = z
  .object({
    customerId: opaqueId,
    checkoutId: opaqueId,
    version: z.number().int().positive(),
    fullName: z.string().min(2).max(120),
    email: z.string().email().max(254),
    phone: z.string().regex(/^\+?[0-9]{8,15}$/),
  })
  .strict();
const delivery = z
  .object({
    checkoutId: opaqueId,
    version: z.number().int().positive(),
    addressLine1: z.string().min(5).max(160),
    addressLine2: z.string().max(160).optional(),
    city: z.string().min(2).max(80),
    region: z.string().min(2).max(80),
    postalCode: z.string().min(3).max(12).optional(),
    deliveryInstructions: z.string().max(250).optional(),
  })
  .strict();

const checkoutCreated = z
  .object({
    checkoutId: opaqueId,
    status: z.literal('DRAFT'),
    version: z.number().int().positive(),
    quote,
    expiresAt: dateTime,
  })
  .strict();

const checkout = z
  .object({
    checkoutId: opaqueId,
    status: z.enum(['DRAFT', 'READY', 'PAYMENT_PENDING', 'PAID', 'PAYMENT_FAILED', 'EXPIRED']),
    version: z.number().int().positive(),
    product,
    quote,
    customer: customer.nullable().optional(),
    deliveryDetails: delivery.nullable().optional(),
    activeTransactionId: opaqueId.nullable().optional(),
    expiresAt: dateTime,
  })
  .strict();

const acceptanceContract = z
  .object({
    type: z.enum(['TERMS', 'PERSONAL_DATA']),
    permalink: z.string().url().max(2_048),
    version: z.string().min(1).max(128),
    acceptanceToken: z.string().min(1).max(4_096),
  })
  .strict();
const paymentConfiguration = z
  .object({
    captureVariant: z.enum(['DIRECT_JWE', 'HOSTED_COMPONENT', 'FAKE_CONTRACT']),
    sandboxPublicKey: z.string().min(1).max(4_096),
    allowedInstallments: z
      .array(z.number().int().min(1).max(36))
      .min(1)
      .max(36)
      .refine((installments) => new Set(installments).size === installments.length),
    acceptanceContracts: z
      .array(acceptanceContract)
      .length(2)
      .refine(
        (contracts) =>
          contracts.some(({ type }) => type === 'TERMS') &&
          contracts.some(({ type }) => type === 'PERSONAL_DATA'),
        'Both acceptance contracts are required',
      ),
    expiresAt: dateTime,
  })
  .strict();

const transaction = z
  .object({
    transactionId: opaqueId,
    checkoutId: opaqueId,
    checkoutStatus: z.enum([
      'DRAFT',
      'READY',
      'PAYMENT_PENDING',
      'PAID',
      'PAYMENT_FAILED',
      'EXPIRED',
    ]),
    paymentStatus: z.enum(['PENDING', 'APPROVED', 'DECLINED', 'VOIDED', 'ERROR']),
    dispatchPhase: z.enum(['NOT_SENT', 'SENDING', 'ACKNOWLEDGED', 'UNKNOWN', 'NOT_SENT_FAILED']),
    providerStatus: z.enum(['PENDING', 'APPROVED', 'DECLINED', 'VOIDED', 'ERROR']).nullable(),
    reservationStatus: z.enum(['ACTIVE', 'CONSUMED', 'RELEASED']),
    integrityStatus: z.enum(['OK', 'APPROVED_INVENTORY_CONFLICT', 'FINAL_STATE_CONFLICT']),
    recoveryCode: z
      .enum([
        'PAYMENT_TOKEN_REJECTED',
        'PROVIDER_NOT_SENT',
        'PROVIDER_OUTCOME_UNKNOWN',
        'STATE_TRANSITION_CONFLICT',
        'RATE_LIMITED',
        'INTERNAL_ERROR',
      ])
      .optional(),
    deliveryId: opaqueId.optional(),
    statusUrl: z.string().regex(/^\/api\/v1\/transactions\/[A-Za-z0-9_-]+$/),
    allowedActions: z
      .array(
        z.enum(['QUERY', 'WAIT', 'RETURN_TO_PRODUCT', 'START_NEW_CHECKOUT', 'CONTACT_SUPPORT']),
      )
      .min(1)
      .max(5)
      .refine((actions) => new Set(actions).size === actions.length),
    retryAfterSeconds: z.number().int().min(1).max(300).optional(),
    acceptedAt: dateTime,
    updatedAt: dateTime,
  })
  .strict();

export const parseCheckoutCreated = (value: unknown): CheckoutCreatedResponse =>
  checkoutCreated.parse(value);
export const parseCheckout = (value: unknown): CheckoutResponse =>
  checkout.parse(value) as CheckoutResponse;
export const parsePaymentConfiguration = (value: unknown): PaymentConfigurationResponse =>
  paymentConfiguration.parse(value);
export const parseTransaction = (value: unknown): TransactionResponse =>
  transaction.parse(value) as TransactionResponse;

export const checkoutEtag = (version: number): string => '"checkout-v' + String(version) + '"';

export const checkoutApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    createCheckout: builder.mutation<CheckoutCreatedResponse, string>({
      query: (productId) => ({
        url: '/checkouts',
        method: 'POST',
        body: { productId },
      }),
      transformResponse: parseCheckoutCreated,
      invalidatesTags: (_result, _error, productId) => [{ type: 'Product', id: productId }],
    }),
    getCheckout: builder.query<CheckoutResponse, string>({
      query: (checkoutId) => '/checkouts/' + encodeURIComponent(checkoutId),
      transformResponse: parseCheckout,
      providesTags: (_result, _error, checkoutId) => [{ type: 'Checkout', id: checkoutId }],
    }),
    replaceCustomer: builder.mutation<
      components['schemas']['CustomerResponse'],
      { readonly checkoutId: string; readonly version: number; readonly body: CustomerRequest }
    >({
      query: ({ checkoutId, version, body }) => ({
        url: '/checkouts/' + encodeURIComponent(checkoutId) + '/customer',
        method: 'PUT',
        headers: { 'If-Match': checkoutEtag(version) },
        body,
      }),
      transformResponse: (value: unknown) => customer.parse(value),
      invalidatesTags: (_result, _error, { checkoutId }) => [{ type: 'Checkout', id: checkoutId }],
    }),
    replaceDelivery: builder.mutation<
      components['schemas']['DeliveryDetailsResponse'],
      { readonly checkoutId: string; readonly version: number; readonly body: DeliveryRequest }
    >({
      query: ({ checkoutId, version, body }) => ({
        url: '/checkouts/' + encodeURIComponent(checkoutId) + '/delivery-details',
        method: 'PUT',
        headers: { 'If-Match': checkoutEtag(version) },
        body,
      }),
      transformResponse: (value: unknown) =>
        delivery.parse(value) as components['schemas']['DeliveryDetailsResponse'],
      invalidatesTags: (_result, _error, { checkoutId }) => [{ type: 'Checkout', id: checkoutId }],
    }),
    getPaymentConfiguration: builder.query<PaymentConfigurationResponse, void>({
      query: () => '/payment-configuration',
      transformResponse: parsePaymentConfiguration,
      keepUnusedDataFor: 0,
    }),
    getTransaction: builder.query<TransactionResponse, string>({
      query: (transactionId) => '/transactions/' + encodeURIComponent(transactionId),
      transformResponse: parseTransaction,
      providesTags: (_result, _error, transactionId) => [
        { type: 'Transaction', id: transactionId },
      ],
    }),
  }),
});

export const {
  useCreateCheckoutMutation,
  useGetCheckoutQuery,
  useGetPaymentConfigurationQuery,
  useGetTransactionQuery,
  useReplaceCustomerMutation,
  useReplaceDeliveryMutation,
} = checkoutApi;
