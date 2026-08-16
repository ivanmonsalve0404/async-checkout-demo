import type { components } from '@checkout/contracts';
import { hasCardErrors, validateCard, type CardInput } from '../validation/card-validation';

type CaptureVariant = components['schemas']['PaymentConfigurationResponse']['captureVariant'];

export interface PaymentTokenizationAdapter {
  readonly mode: 'FAKE' | 'SANDBOX_READY_DISABLED';
  tokenize(input: CardInput): Promise<string>;
}

export class TokenizationError extends Error {
  public constructor(
    public readonly code: 'CARD_INVALID' | 'SANDBOX_DISABLED' | 'TOKENIZATION_FAILED',
  ) {
    super(code);
    this.name = 'TokenizationError';
  }
}

const opaqueToken = (): string => {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return 'tok_fake_' + Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
};

export class FakeCardTokenizationAdapter implements PaymentTokenizationAdapter {
  public readonly mode = 'FAKE' as const;

  public constructor(private readonly createToken: () => string = opaqueToken) {}

  public async tokenize(input: CardInput): Promise<string> {
    if (hasCardErrors(validateCard(input).errors)) {
      throw new TokenizationError('CARD_INVALID');
    }
    const token = this.createToken();
    if (!/^tok_fake_[A-Za-z0-9_-]{8,128}$/.test(token)) {
      throw new TokenizationError('TOKENIZATION_FAILED');
    }
    return Promise.resolve(token);
  }
}

export class SandboxCardTokenizationAdapter implements PaymentTokenizationAdapter {
  public readonly mode = 'SANDBOX_READY_DISABLED' as const;

  public tokenize(): Promise<never> {
    return Promise.reject(new TokenizationError('SANDBOX_DISABLED'));
  }
}

export const selectTokenizationAdapter = (
  captureVariant: CaptureVariant,
): PaymentTokenizationAdapter =>
  captureVariant === 'FAKE_CONTRACT'
    ? new FakeCardTokenizationAdapter()
    : new SandboxCardTokenizationAdapter();
