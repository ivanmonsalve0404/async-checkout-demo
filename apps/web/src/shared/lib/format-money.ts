export const formatMoney = (amountInCents: number, currency: 'COP'): string =>
  new Intl.NumberFormat('es-CO', {
    style: 'currency',
    currency,
    maximumFractionDigits: 0,
  }).format(amountInCents / 100);
