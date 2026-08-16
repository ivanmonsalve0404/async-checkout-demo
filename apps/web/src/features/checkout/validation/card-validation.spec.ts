import {
  detectCardBrand,
  digitsOnly,
  hasCardErrors,
  isFutureExpiry,
  passesLuhn,
  validateCard,
} from './card-validation';

const luhnNumber = (prefix: string): string => {
  for (let check = 0; check <= 9; check += 1) {
    const candidate = prefix + String(check);
    if (passesLuhn(candidate)) {
      return candidate;
    }
  }
  throw new Error('fixture');
};

describe('card validation', () => {
  it('normalizes digits and detects Visa and Mastercard ranges', () => {
    expect(digitsOnly('4 2-abc')).toBe('42');
    expect(detectCardBrand('4')).toBe('VISA');
    expect(detectCardBrand('55')).toBe('MASTERCARD');
    expect(detectCardBrand('2221')).toBe('MASTERCARD');
    expect(detectCardBrand('2720')).toBe('MASTERCARD');
    expect(detectCardBrand('30')).toBeUndefined();
  });

  it('applies Luhn without accepting short or altered values', () => {
    const valid = luhnNumber('4' + '0'.repeat(14));
    expect(passesLuhn(valid)).toBe(true);
    expect(passesLuhn(valid.slice(0, -1) + (valid.endsWith('9') ? '0' : '9'))).toBe(false);
    expect(passesLuhn('123')).toBe(false);
  });

  it('requires a future, real expiration month', () => {
    const now = new Date('2030-06-15T00:00:00Z');
    expect(isFutureExpiry('06/30', now)).toBe(true);
    expect(isFutureExpiry('05/30', now)).toBe(false);
    expect(isFutureExpiry('13/30', now)).toBe(false);
    expect(isFutureExpiry('bad', now)).toBe(false);
  });

  it('returns field-safe errors and the accepted brand', () => {
    const valid = validateCard(
      {
        number: luhnNumber('4' + '0'.repeat(14)),
        expiry: '12/99',
        securityCode: '123',
        holderName: 'Persona Sintética',
      },
      new Date('2030-01-01T00:00:00Z'),
    );
    expect(valid.brand).toBe('VISA');
    expect(hasCardErrors(valid.errors)).toBe(false);

    const invalid = validateCard(
      { number: '1', expiry: '00/00', securityCode: '1', holderName: '' },
      new Date('2030-01-01T00:00:00Z'),
    );
    expect(invalid.brand).toBeUndefined();
    expect(Object.keys(invalid.errors)).toEqual(['number', 'expiry', 'securityCode', 'holderName']);
    expect(hasCardErrors(invalid.errors)).toBe(true);
  });
});
