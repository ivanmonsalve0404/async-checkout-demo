import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { getPublicConfig } from '../../shared/config/public-config';

export const baseApi = createApi({
  reducerPath: 'api',
  baseQuery: fetchBaseQuery({ baseUrl: getPublicConfig().apiBaseUrl, credentials: 'same-origin' }),
  tagTypes: ['Product', 'Checkout', 'Transaction'],
  endpoints: () => ({}),
});
