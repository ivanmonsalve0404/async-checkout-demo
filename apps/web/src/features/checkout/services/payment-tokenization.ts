import type { components } from '@checkout/contracts';
import { hasCardErrors, validateCard, type CardInput } from '../validation/card-validation';

type CaptureVariant = components['schemas']['PaymentConfigurationResponse']['captureVariant'];

export interface PaymentTokenizationAdapter {
  readonly mode: 'FAKE' | 'SANDBOX' | 'SANDBOX_READY_DISABLED';
  tokenize(input: CardInput): Promise<string>;
}

export const WOMPI_SANDBOX_ORIGIN = 'https://sandbox.wompi.co' as const;
export const WOMPI_CARD_TOKENIZATION_RESOURCE = '/v1/tokens/cards' as const;

export interface SandboxTokenizationRequest {
  readonly method: 'POST';
  readonly origin: typeof WOMPI_SANDBOX_ORIGIN;
  readonly resource: typeof WOMPI_CARD_TOKENIZATION_RESOURCE;
  readonly redirect: 'error';
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Readonly<{ payload: string }>;
  readonly timeoutMs: number;
}

export interface SandboxTokenizationResponse {
  readonly status: number;
  readonly contentType: string | null;
  readonly body: unknown;
}

export type SandboxTokenizationTransport = (
  request: SandboxTokenizationRequest,
) => Promise<SandboxTokenizationResponse>;

export type SandboxCardEncryptor = (input: Readonly<CardInput>) => Promise<string>;

export type SandboxCardTokenizationOptions =
  | Readonly<{ enabled?: false }>
  | Readonly<{
      enabled: true;
      environment: 'sandbox';
      origin: typeof WOMPI_SANDBOX_ORIGIN;
      publicKey: string;
      encrypt: SandboxCardEncryptor;
      transport: SandboxTokenizationTransport;
      timeoutMs?: number;
    }>;

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
  public readonly mode: 'SANDBOX' | 'SANDBOX_READY_DISABLED';
  private readonly options: SandboxCardTokenizationOptions;

  public constructor(options: SandboxCardTokenizationOptions = { enabled: false }) {
    this.options = options;
    this.mode = readySandboxOptions(options) === null ? 'SANDBOX_READY_DISABLED' : 'SANDBOX';
  }

  public async tokenize(input: CardInput): Promise<string> {
    const options = readySandboxOptions(this.options);
    if (options === null) throw new TokenizationError('SANDBOX_DISABLED');
    if (hasCardErrors(validateCard(input).errors)) throw new TokenizationError('CARD_INVALID');

    try {
      const payload = await options.encrypt({ ...input });
      if (!isCompactJwe(payload)) throw new TokenizationError('TOKENIZATION_FAILED');
      const response = await options.transport({
        method: 'POST',
        origin: WOMPI_SANDBOX_ORIGIN,
        resource: WOMPI_CARD_TOKENIZATION_RESOURCE,
        redirect: 'error',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${options.publicKey}`,
          'Content-Type': 'application/json',
        },
        body: { payload },
        timeoutMs: options.timeoutMs,
      });
      if (
        response.status < 200 ||
        response.status >= 300 ||
        response.contentType?.toLowerCase().includes('application/json') !== true
      ) {
        throw new TokenizationError('TOKENIZATION_FAILED');
      }
      const token = sandboxToken(response.body);
      if (token === null) throw new TokenizationError('TOKENIZATION_FAILED');
      return token;
    } catch (error: unknown) {
      if (error instanceof TokenizationError) throw error;
      throw new TokenizationError('TOKENIZATION_FAILED');
    }
  }
}

type ReadySandboxOptions = Readonly<{
  publicKey: string;
  encrypt: SandboxCardEncryptor;
  transport: SandboxTokenizationTransport;
  timeoutMs: number;
}>;

const readySandboxOptions = (
  options: SandboxCardTokenizationOptions,
): ReadySandboxOptions | null => {
  if (
    options.enabled !== true ||
    options.environment !== 'sandbox' ||
    options.origin !== WOMPI_SANDBOX_ORIGIN ||
    !/^pub_test_[A-Za-z0-9_-]{8,128}$/u.test(options.publicKey) ||
    typeof options.encrypt !== 'function' ||
    typeof options.transport !== 'function'
  ) {
    return null;
  }
  const timeoutMs = options.timeoutMs ?? 8_000;
  return Number.isSafeInteger(timeoutMs) && timeoutMs >= 100 && timeoutMs <= 10_000
    ? {
        publicKey: options.publicKey,
        encrypt: options.encrypt,
        transport: options.transport,
        timeoutMs,
      }
    : null;
};

const isCompactJwe = (candidate: string): boolean =>
  candidate.length >= 64 &&
  candidate.length <= 16_384 &&
  candidate.split('.').length === 5 &&
  candidate.split('.').every((part) => /^[A-Za-z0-9_-]+$/u.test(part));

const sandboxToken = (body: unknown): string | null => {
  if (typeof body !== 'object' || body === null) return null;
  const data = (body as Readonly<Record<string, unknown>>).data;
  if (typeof data !== 'object' || data === null) return null;
  const token = (data as Readonly<Record<string, unknown>>).id;
  return typeof token === 'string' && /^tok_[A-Za-z0-9_-]{8,256}$/u.test(token) ? token : null;
};

export const selectTokenizationAdapter = (
  captureVariant: CaptureVariant,
): PaymentTokenizationAdapter =>
  captureVariant === 'FAKE_CONTRACT'
    ? new FakeCardTokenizationAdapter()
    : new SandboxCardTokenizationAdapter();
