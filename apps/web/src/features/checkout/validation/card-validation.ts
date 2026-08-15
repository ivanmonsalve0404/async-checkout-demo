export type CardBrand = 'VISA' | 'MASTERCARD';

export interface CardInput {
  readonly number: string;
  readonly expiry: string;
  readonly securityCode: string;
  readonly holderName: string;
}

export interface CardValidationErrors {
  readonly number?: string;
  readonly expiry?: string;
  readonly securityCode?: string;
  readonly holderName?: string;
}

export const digitsOnly = (value: string): string => value.replace(/\D/g, '');

export const detectCardBrand = (value: string): CardBrand | undefined => {
  const digits = digitsOnly(value);
  if (digits.startsWith('4')) {
    return 'VISA';
  }
  const prefix2 = Number(digits.slice(0, 2));
  const prefix4 = Number(digits.slice(0, 4));
  if ((prefix2 >= 51 && prefix2 <= 55) || (prefix4 >= 2221 && prefix4 <= 2720)) {
    return 'MASTERCARD';
  }
  return undefined;
};

export const passesLuhn = (value: string): boolean => {
  const digits = digitsOnly(value);
  if (digits.length < 12) {
    return false;
  }
  let sum = 0;
  let doubleDigit = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    const digit = Number(digits[index]);
    const candidate = doubleDigit ? digit * 2 : digit;
    sum += candidate > 9 ? candidate - 9 : candidate;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
};

export const isFutureExpiry = (value: string, now = new Date()): boolean => {
  const match = /^(\d{2})\/(\d{2})$/.exec(value.trim());
  if (match === null) {
    return false;
  }
  const month = Number(match[1]);
  const year = 2000 + Number(match[2]);
  return (
    month >= 1 &&
    month <= 12 &&
    (year > now.getFullYear() || (year === now.getFullYear() && month >= now.getMonth() + 1))
  );
};

export const validateCard = (
  input: CardInput,
  now = new Date(),
): { readonly brand?: CardBrand; readonly errors: CardValidationErrors } => {
  const number = digitsOnly(input.number);
  const brand = detectCardBrand(number);
  const errors: {
    number?: string;
    expiry?: string;
    securityCode?: string;
    holderName?: string;
  } = {};

  if (brand === undefined || number.length !== 16 || !passesLuhn(number)) {
    errors.number = 'Revisa el número de tarjeta. Aceptamos Visa y Mastercard.';
  }
  if (!isFutureExpiry(input.expiry, now)) {
    errors.expiry = 'Usa una fecha vigente en formato MM/AA.';
  }
  if (!/^\d{3}$/.test(digitsOnly(input.securityCode))) {
    errors.securityCode = 'Ingresa los 3 dígitos del código de seguridad.';
  }
  const holderName = input.holderName.trim();
  if (holderName.length < 2 || holderName.length > 120) {
    errors.holderName = 'Ingresa el nombre que aparece en la tarjeta.';
  }

  return brand === undefined ? { errors } : { brand, errors };
};

export const hasCardErrors = (errors: CardValidationErrors): boolean =>
  Object.values(errors).some(Boolean);
