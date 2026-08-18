import { getPublicConfig, loadRuntimePublicConfig, readPublicConfig } from './public-config';

describe('public frontend configuration', () => {
  it('uses the documented public default and accepts an override', () => {
    expect(readPublicConfig({}).productId).toBe('product-demo-001');
    expect(readPublicConfig({ VITE_PRODUCT_ID: 'product-other-001' }).productId).toBe(
      'product-other-001',
    );
  });

  it('rejects malformed public identifiers', () => {
    expect(() => readPublicConfig({ VITE_PRODUCT_ID: 'bad/id' })).toThrow();
  });

  it('loads one exact same-origin runtime document before application modules start', async () => {
    const request = jest.fn().mockResolvedValue({
      status: 200,
      headers: { get: () => 'application/json; charset=utf-8' },
      text: async () => JSON.stringify({ apiBaseUrl: '/api/v1', productId: 'product-runtime-001' }),
    });
    await expect(loadRuntimePublicConfig(request as unknown as typeof fetch)).resolves.toEqual({
      apiBaseUrl: '/api/v1',
      productId: 'product-runtime-001',
    });
    expect(request).toHaveBeenCalledWith(
      '/public-config.json',
      expect.objectContaining({ credentials: 'same-origin', method: 'GET', redirect: 'error' }),
    );
    expect(getPublicConfig().productId).toBe('product-runtime-001');
  });

  it('fails closed for missing, cross-origin, or extended runtime configuration', async () => {
    const response = (value: unknown) =>
      ({
        status: 200,
        headers: { get: () => 'application/json' },
        text: async () => JSON.stringify(value),
      }) as unknown as Response;
    for (const value of [
      { productId: 'product-runtime-001' },
      { apiBaseUrl: 'https://example.invalid/api/v1', productId: 'product-runtime-001' },
      { apiBaseUrl: '/api/v1', productId: 'product-runtime-001', extra: true },
    ]) {
      await expect(
        loadRuntimePublicConfig(jest.fn().mockResolvedValue(response(value))),
      ).rejects.toThrow('Public configuration is invalid');
    }
  });
});
