import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';

export const baseApi = createApi({
  reducerPath: 'api',
  baseQuery: fetchBaseQuery({ baseUrl: '/api/v1', credentials: 'same-origin' }),
  tagTypes: ['Product', 'Checkout', 'Transaction'],
  endpoints: () => ({}),
});
