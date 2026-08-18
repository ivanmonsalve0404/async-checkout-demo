import type { components } from '@checkout/contracts';
import { hasCardErrors, validateCard, type CardInput } from '../validation/card-validation';

type CaptureVariant = components['schemas']['PaymentConfigurationResponse']['captureVariant'];

export interface PaymentTokenizationAdapter {
  readonly mode: 'FAKE' | 'SANDBOX' | 'SANDBOX_READY_DISABLED';
  tokenize(input: CardInput): Promise<string>;
}

export const WOMPI_SANDBOX_ORIGIN = 'https://sandbox.wompi.co' as const;
export const WOMPI_TOKENIZATION_KEY_RESOURCE = '/v1/tokens/keys/tokenization' as const;
export const WOMPI_CARD_TOKENIZATION_RESOURCE = '/v1/tokens/cards' as const;

type FetchImplementation = typeof fetch;
type CryptoImplementation = Pick<Crypto, 'getRandomValues' | 'subtle'>;

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
      expiresAtUtc: string;
      now?: () => number;
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
  expiresAtUtc: string;
  now: () => number;
  encrypt: SandboxCardEncryptor;
  transport: SandboxTokenizationTransport;
  timeoutMs: number;
}>;

const canonicalUtcMillis = (value: string): number | null => {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) return null;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
    ? milliseconds
    : null;
};

const readySandboxOptions = (
  options: SandboxCardTokenizationOptions,
): ReadySandboxOptions | null => {
  const expiresAt = options.enabled === true ? canonicalUtcMillis(options.expiresAtUtc) : null;
  if (
    options.enabled !== true ||
    options.environment !== 'sandbox' ||
    options.origin !== WOMPI_SANDBOX_ORIGIN ||
    !/^pub_test_[A-Za-z0-9_-]{8,128}$/u.test(options.publicKey) ||
    expiresAt === null ||
    (options.now ?? Date.now)() >= expiresAt ||
    typeof options.encrypt !== 'function' ||
    typeof options.transport !== 'function'
  ) {
    return null;
  }
  const timeoutMs = options.timeoutMs ?? 8_000;
  return Number.isSafeInteger(timeoutMs) && timeoutMs >= 100 && timeoutMs <= 10_000
    ? {
        publicKey: options.publicKey,
        expiresAtUtc: options.expiresAtUtc,
        now: options.now ?? Date.now,
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
  return typeof token === 'string' && /^tok_(?!fake_)[A-Za-z0-9_-]{8,256}$/u.test(token)
    ? token
    : null;
};

const base64Url = (bytes: Uint8Array): string => {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
};

const ownedBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
};

const decodePem = (value: string): Uint8Array => {
  const encoded = value
    .replace(/-----BEGIN PUBLIC KEY-----/gu, '')
    .replace(/-----END PUBLIC KEY-----/gu, '')
    .replace(/\s/gu, '');
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded)) throw new TokenizationError('TOKENIZATION_FAILED');
  try {
    const binary = atob(encoded);
    const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (decoded.length < 128 || decoded.length > 8_192) {
      throw new TokenizationError('TOKENIZATION_FAILED');
    }
    return decoded;
  } catch (error: unknown) {
    if (error instanceof TokenizationError) throw error;
    throw new TokenizationError('TOKENIZATION_FAILED');
  }
};

const jsonResponse = async (response: Response): Promise<unknown> => {
  const contentType = response.headers.get('content-type');
  if (
    response.status < 200 ||
    response.status >= 300 ||
    contentType?.toLowerCase().includes('application/json') !== true
  ) {
    throw new TokenizationError('TOKENIZATION_FAILED');
  }
  const text = await response.text();
  if (text.length === 0 || text.length > 32_768) {
    throw new TokenizationError('TOKENIZATION_FAILED');
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new TokenizationError('TOKENIZATION_FAILED');
  }
};

const fetchWithTimeout = async (
  fetchImplementation: FetchImplementation,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> => {
  const controller = new AbortController();
  const timer = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImplementation(url, { ...init, signal: controller.signal });
  } finally {
    globalThis.clearTimeout(timer);
  }
};

const tokenizationPublicKey = (body: unknown): string => {
  if (typeof body !== 'object' || body === null) throw new TokenizationError('TOKENIZATION_FAILED');
  const data = (body as Readonly<Record<string, unknown>>).data;
  if (typeof data !== 'object' || data === null) throw new TokenizationError('TOKENIZATION_FAILED');
  const publicKey = (data as Readonly<Record<string, unknown>>).publicKey;
  if (
    typeof publicKey !== 'string' ||
    publicKey.length > 8_192 ||
    !publicKey.includes('BEGIN PUBLIC KEY')
  ) {
    throw new TokenizationError('TOKENIZATION_FAILED');
  }
  return publicKey;
};

const browserJweEncryptor =
  (
    publicKey: string,
    fetchImplementation: FetchImplementation,
    cryptoImplementation: CryptoImplementation,
    timeoutMs: number,
    assertAuthorized: () => void,
  ): SandboxCardEncryptor =>
  async (input): Promise<string> => {
    assertAuthorized();
    const keyResponse = await fetchWithTimeout(
      fetchImplementation,
      WOMPI_SANDBOX_ORIGIN + WOMPI_TOKENIZATION_KEY_RESOURCE,
      {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: { Accept: 'application/json', Authorization: `Bearer ${publicKey}` },
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      },
      timeoutMs,
    );
    const publicKeyPem = tokenizationPublicKey(await jsonResponse(keyResponse));
    const expiry = /^(\d{2})\/(\d{2})$/u.exec(input.expiry.trim());
    if (expiry === null) throw new TokenizationError('CARD_INVALID');
    const expiryMonth = expiry[1];
    const expiryYear = expiry[2];
    if (expiryMonth === undefined || expiryYear === undefined) {
      throw new TokenizationError('CARD_INVALID');
    }

    try {
      const rsaKey = await cryptoImplementation.subtle.importKey(
        'spki',
        ownedBuffer(decodePem(publicKeyPem)),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt'],
      );
      const headerBytes = new TextEncoder().encode(
        JSON.stringify({ alg: 'RSA-OAEP-256', enc: 'A256GCM' }),
      );
      const protectedHeader = base64Url(headerBytes);
      const cek = cryptoImplementation.getRandomValues(new Uint8Array(32));
      const iv = cryptoImplementation.getRandomValues(new Uint8Array(12));
      const aesKey = await cryptoImplementation.subtle.importKey(
        'raw',
        ownedBuffer(cek),
        'AES-GCM',
        false,
        ['encrypt'],
      );
      const plaintext = new TextEncoder().encode(
        JSON.stringify({
          number: input.number.replace(/\D/gu, ''),
          cvc: input.securityCode.replace(/\D/gu, ''),
          exp_month: expiryMonth,
          exp_year: expiryYear,
          card_holder: input.holderName.trim(),
        }),
      );
      const encryptedKey = new Uint8Array(
        await cryptoImplementation.subtle.encrypt({ name: 'RSA-OAEP' }, rsaKey, ownedBuffer(cek)),
      );
      const ciphertextAndTag = new Uint8Array(
        await cryptoImplementation.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: ownedBuffer(iv),
            additionalData: ownedBuffer(new TextEncoder().encode(protectedHeader)),
            tagLength: 128,
          },
          aesKey,
          ownedBuffer(plaintext),
        ),
      );
      if (ciphertextAndTag.length <= 16) throw new TokenizationError('TOKENIZATION_FAILED');
      return [
        protectedHeader,
        base64Url(encryptedKey),
        base64Url(iv),
        base64Url(ciphertextAndTag.subarray(0, -16)),
        base64Url(ciphertextAndTag.subarray(-16)),
      ].join('.');
    } catch (error: unknown) {
      if (error instanceof TokenizationError) throw error;
      throw new TokenizationError('TOKENIZATION_FAILED');
    }
  };

export const createBrowserSandboxTokenizationAdapter = (
  publicKey: string,
  expiresAtUtc: string,
  dependencies: Readonly<{
    fetchImplementation?: FetchImplementation;
    cryptoImplementation?: CryptoImplementation;
    timeoutMs?: number;
    now?: () => number;
  }> = {},
): PaymentTokenizationAdapter => {
  const fetchImplementation = dependencies.fetchImplementation ?? globalThis.fetch;
  const cryptoImplementation = dependencies.cryptoImplementation ?? globalThis.crypto;
  const timeoutMs = dependencies.timeoutMs ?? 8_000;
  const now = dependencies.now ?? Date.now;
  const assertAuthorized = (): void => {
    const expiry = Date.parse(expiresAtUtc);
    if (!Number.isFinite(expiry) || now() >= expiry) {
      throw new TokenizationError('SANDBOX_DISABLED');
    }
  };
  if (
    !/^pub_test_[A-Za-z0-9_-]{8,128}$/u.test(publicKey) ||
    typeof fetchImplementation !== 'function' ||
    cryptoImplementation?.subtle === undefined
  ) {
    return new SandboxCardTokenizationAdapter();
  }
  const transport: SandboxTokenizationTransport = async (request) => {
    assertAuthorized();
    if (
      request.method !== 'POST' ||
      request.origin !== WOMPI_SANDBOX_ORIGIN ||
      request.resource !== WOMPI_CARD_TOKENIZATION_RESOURCE ||
      request.redirect !== 'error'
    ) {
      throw new TokenizationError('TOKENIZATION_FAILED');
    }
    const response = await fetchWithTimeout(
      fetchImplementation,
      request.origin + request.resource,
      {
        method: request.method,
        body: JSON.stringify(request.body),
        cache: 'no-store',
        credentials: 'omit',
        headers: request.headers,
        redirect: request.redirect,
        referrerPolicy: 'no-referrer',
      },
      request.timeoutMs,
    );
    return {
      status: response.status,
      contentType: response.headers.get('content-type'),
      body: await jsonResponse(response),
    };
  };
  return new SandboxCardTokenizationAdapter({
    enabled: true,
    environment: 'sandbox',
    origin: WOMPI_SANDBOX_ORIGIN,
    publicKey,
    expiresAtUtc,
    now,
    encrypt: browserJweEncryptor(
      publicKey,
      fetchImplementation,
      cryptoImplementation,
      timeoutMs,
      assertAuthorized,
    ),
    transport,
    timeoutMs,
  });
};

export const selectTokenizationAdapter = (
  captureVariant: CaptureVariant,
  sandboxPublicKey?: string,
  expiresAtUtc?: string,
): PaymentTokenizationAdapter =>
  captureVariant === 'FAKE_CONTRACT'
    ? new FakeCardTokenizationAdapter()
    : captureVariant === 'DIRECT_JWE' &&
        sandboxPublicKey !== undefined &&
        expiresAtUtc !== undefined
      ? createBrowserSandboxTokenizationAdapter(sandboxPublicKey, expiresAtUtc)
      : new SandboxCardTokenizationAdapter();
