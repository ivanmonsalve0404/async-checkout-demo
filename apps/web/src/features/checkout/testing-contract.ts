export const checkoutRoutes = {
  product: (productId: string): string => '/products/' + encodeURIComponent(productId),
  capture: (productId: string): string =>
    '/products/' + encodeURIComponent(productId) + '/checkout',
  status: (productId: string): string =>
    '/products/' + encodeURIComponent(productId) + '/checkout/status',
} as const;

export const checkoutTestIds = {
  product: 'product-surface',
  productAction: 'product-checkout-cta',
  dialog: 'checkout-dialog',
  payment: 'checkout-step-payment',
  customer: 'checkout-step-customer',
  acceptances: 'checkout-step-acceptances',
  review: 'checkout-step-review',
  status: 'checkout-step-status',
  submit: 'checkout-submit',
  approved: 'transaction-approved',
  declined: 'transaction-declined',
  error: 'transaction-error',
  pending: 'transaction-pending',
  unknown: 'transaction-unknown',
  conflict: 'transaction-conflict',
  expired: 'checkout-expired',
  returnProduct: 'return-product',
} as const;
