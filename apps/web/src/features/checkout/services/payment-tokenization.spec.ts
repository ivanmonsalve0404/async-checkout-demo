import {
  FakeCardTokenizationAdapter,
  SandboxCardTokenizationAdapter,
  TokenizationError,
  selectTokenizationAdapter,
} from './payment-tokenization';
import { passesLuhn, type CardInput } from '../validation/card-validation';

const validNumber = (): string => {
  const prefix = '4' + '0'.repeat(14);
  return Array.from({ length: 10 }, (_, value) => prefix + String(value)).find(passesLuhn) ?? '';
};

const validCard: CardInput = {
  number: validNumber(),
  expiry: '12/99',
  securityCode: '123',
  holderName: 'Persona Sintética',
};

describe('payment tokenization boundary', () => {
  it('returns only an opaque token for a valid fake card', async () => {
    const adapter = new FakeCardTokenizationAdapter(() => 'tok_fake_synthetic123');
    await expect(adapter.tokenize(validCard)).resolves.toBe('tok_fake_synthetic123');
    expect(adapter.mode).toBe('FAKE');
  });

  it('rejects invalid input and malformed fake output', async () => {
    await expect(
      new FakeCardTokenizationAdapter().tokenize({ ...validCard, number: '1' }),
    ).rejects.toMatchObject({ code: 'CARD_INVALID' });
    await expect(
      new FakeCardTokenizationAdapter(() => 'bad').tokenize(validCard),
    ).rejects.toMatchObject({ code: 'TOKENIZATION_FAILED' });
  });

  it('keeps real capture ready but fail-closed', async () => {
    const direct = selectTokenizationAdapter('DIRECT_JWE');
    expect(direct).toBeInstanceOf(SandboxCardTokenizationAdapter);
    await expect(direct.tokenize(validCard)).rejects.toEqual(
      new TokenizationError('SANDBOX_DISABLED'),
    );
    expect(selectTokenizationAdapter('HOSTED_COMPONENT').mode).toBe('SANDBOX_READY_DISABLED');
    expect(selectTokenizationAdapter('FAKE_CONTRACT')).toBeInstanceOf(FakeCardTokenizationAdapter);
  });
});
