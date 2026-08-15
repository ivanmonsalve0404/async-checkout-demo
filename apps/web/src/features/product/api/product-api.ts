import type { components } from '@checkout/contracts';
import { z } from 'zod';
import { baseApi } from '../../../app/api/base-api';

export type ProductResponse = components['schemas']['ProductResponse'];

const productResponseSchema = z
  .object({
    productId: z.string().min(8).max(128),
    sku: z.string().min(1).max(128),
    name: z.string().min(1).max(200),
    description: z.string().min(1).max(2_000),
    imageUrl: z.string().url(),
    unitPrice: z
      .object({
        amountInCents: z.number().int().nonnegative(),
        currency: z.literal('COP'),
      })
      .strict(),
    available: z.number().int().min(0).max(999_999),
  })
  .strict();

export const parseProductResponse = (value: unknown): ProductResponse =>
  productResponseSchema.parse(value);

export const buildProductRequest = (productId: string) => ({
  url: `/products/${encodeURIComponent(productId)}`,
  method: 'GET' as const,
});

export const productApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    getProduct: builder.query<ProductResponse, string>({
      query: buildProductRequest,
      transformResponse: parseProductResponse,
    }),
  }),
});

export const { useGetProductQuery } = productApi;
