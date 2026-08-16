const mockEndpointDefinitions: Record<string, Record<string, unknown>> = {};

jest.mock('../../../app/api/base-api', () => ({
  baseApi: {
    injectEndpoints: ({
      endpoints,
    }: {
      readonly endpoints: (builder: unknown) => Record<string, Record<string, unknown>>;
    }) => {
      const identity = <Value>(definition: Value): Value => definition;
      Object.assign(mockEndpointDefinitions, endpoints({ mutation: identity, query: identity }));
      return {
        useCreateCheckoutMutation: jest.fn(),
        useGetCheckoutQuery: jest.fn(),
        useGetPaymentConfigurationQuery: jest.fn(),
        useGetTransactionQuery: jest.fn(),
        useReplaceCustomerMutation: jest.fn(),
        useReplaceDeliveryMutation: jest.fn(),
      };
    },
  },
}));

import './checkout-api';

const invoke = (endpoint: string, callback: string, ...args: readonly unknown[]): unknown => {
  const value = mockEndpointDefinitions[endpoint]?.[callback];
  if (typeof value !== 'function') throw new Error(`Missing ${endpoint}.${callback}`);
  return value(...args);
};

describe('checkout API endpoint definitions', () => {
  it('builds encoded checkout commands and their cache invalidations', () => {
    expect(invoke('createCheckout', 'query', 'product / demo')).toEqual({
      url: '/checkouts',
      method: 'POST',
      body: { productId: 'product / demo' },
    });
    expect(
      invoke('createCheckout', 'invalidatesTags', undefined, undefined, 'product_demo'),
    ).toEqual([{ type: 'Product', id: 'product_demo' }]);
    expect(invoke('getCheckout', 'query', 'checkout / demo')).toBe(
      '/checkouts/checkout%20%2F%20demo',
    );
    expect(invoke('getCheckout', 'providesTags', undefined, undefined, 'checkout_demo')).toEqual([
      { type: 'Checkout', id: 'checkout_demo' },
    ]);

    const customer = {
      customerId: 'customer_123456',
      checkoutId: 'checkout_123456',
      version: 4,
      fullName: 'Persona Sintética',
      email: 'persona@example.test',
      phone: '+573000000000',
    };
    expect(
      invoke('replaceCustomer', 'query', {
        checkoutId: 'checkout / demo',
        version: 3,
        body: customer,
      }),
    ).toMatchObject({
      url: '/checkouts/checkout%20%2F%20demo/customer',
      method: 'PUT',
      headers: { 'If-Match': '"checkout-v3"' },
    });
    expect(invoke('replaceCustomer', 'transformResponse', customer)).toEqual(customer);
    expect(
      invoke('replaceCustomer', 'invalidatesTags', undefined, undefined, {
        checkoutId: 'checkout_demo',
      }),
    ).toEqual([{ type: 'Checkout', id: 'checkout_demo' }]);
  });

  it('builds delivery, configuration, and transaction boundaries', () => {
    const delivery = {
      checkoutId: 'checkout_123456',
      version: 5,
      addressLine1: 'Calle sintética 123',
      city: 'Bogotá',
      region: 'Cundinamarca',
    };
    expect(
      invoke('replaceDelivery', 'query', {
        checkoutId: 'checkout / demo',
        version: 4,
        body: delivery,
      }),
    ).toMatchObject({
      url: '/checkouts/checkout%20%2F%20demo/delivery-details',
      method: 'PUT',
      headers: { 'If-Match': '"checkout-v4"' },
    });
    expect(invoke('replaceDelivery', 'transformResponse', delivery)).toEqual(delivery);
    expect(
      invoke('replaceDelivery', 'invalidatesTags', undefined, undefined, {
        checkoutId: 'checkout_demo',
      }),
    ).toEqual([{ type: 'Checkout', id: 'checkout_demo' }]);
    expect(invoke('getPaymentConfiguration', 'query')).toBe('/payment-configuration');
    expect(invoke('getTransaction', 'query', 'transaction / demo')).toBe(
      '/transactions/transaction%20%2F%20demo',
    );
    expect(
      invoke('getTransaction', 'providesTags', undefined, undefined, 'transaction_demo'),
    ).toEqual([{ type: 'Transaction', id: 'transaction_demo' }]);
  });
});
