export interface PublicConfig {
  readonly productId: string;
}

const productIdPattern = /^[A-Za-z0-9_-]{8,128}$/;

export const readPublicConfig = (environment: Record<string, string | undefined>): PublicConfig => {
  const productId = environment.VITE_PRODUCT_ID ?? 'product-demo-001';
  if (!productIdPattern.test(productId)) {
    throw new Error('VITE_PRODUCT_ID must be an opaque public identifier');
  }
  return { productId };
};
