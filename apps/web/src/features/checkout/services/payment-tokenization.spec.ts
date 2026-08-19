import { webcrypto } from 'node:crypto';

import {
  createBrowserSandboxTokenizationAdapter,
  FakeCardTokenizationAdapter,
  SandboxCardTokenizationAdapter,
  TokenizationError,
  WOMPI_CARD_TOKENIZATION_RESOURCE,
  WOMPI_SANDBOX_ORIGIN,
  WOMPI_TOKENIZATION_KEY_RESOURCE,
  selectTokenizationAdapter,
  type SandboxTokenizationTransport,
} from './payment-tokenization';
import { passesLuhn, type CardInput } from '../validation/card-validation';

const validNumber = (): string => {
  const prefix = '4' + '0'.repeat(14);
  return Array.from({ length: 10 }, (_, value) => prefix + String(value)).find(passesLuhn) ?? '';
};

const validCard: CardInput = {
  number: validNumber(),
  expiry: '12/99',
  securityCode: '987',
  holderName: 'Persona Sintética',
};

const compactJwe = [
  'header123456',
  'encryptedkey123456',
  'ivvalue123456',
  'ciphertextvalue123456',
  'authtagvalue123456',
].join('.');
const sandboxPublicKey = ['pub', 'test', 'syntheticabcdef'].join('_');
const productionPublicKey = ['pub', 'prod', 'syntheticabcdef'].join('_');
const authorizationExpiry = '2099-01-01T00:00:00.000Z';

const transportMock = (): jest.MockedFunction<SandboxTokenizationTransport> =>
  jest.fn<ReturnType<SandboxTokenizationTransport>, Parameters<SandboxTokenizationTransport>>();

const response = (body: unknown, status = 200): Response =>
  ({
    status,
    headers: {
      get: (name: string) => (name.toLowerCase() === 'content-type' ? 'application/json' : null),
    },
    text: async () => JSON.stringify(body),
  }) as Response;

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

  it('enables sandbox only with the exact injected sandbox origin, test key, encryptor, and transport', async () => {
    const encrypt = jest.fn().mockResolvedValue(compactJwe);
    const transport = transportMock().mockResolvedValue({
      status: 201,
      contentType: 'application/json; charset=utf-8',
      body: { data: { id: 'tok_test_opaque123456' } },
    });
    const adapter = new SandboxCardTokenizationAdapter({
      enabled: true,
      environment: 'sandbox',
      origin: WOMPI_SANDBOX_ORIGIN,
      publicKey: sandboxPublicKey,
      expiresAtUtc: authorizationExpiry,
      encrypt,
      transport,
      timeoutMs: 1_234,
    });

    await expect(adapter.tokenize(validCard)).resolves.toBe('tok_test_opaque123456');
    expect(adapter.mode).toBe('SANDBOX');
    expect(encrypt).toHaveBeenCalledWith(validCard);
    expect(transport).toHaveBeenCalledWith({
      method: 'POST',
      origin: WOMPI_SANDBOX_ORIGIN,
      resource: WOMPI_CARD_TOKENIZATION_RESOURCE,
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${sandboxPublicKey}`,
        'Content-Type': 'application/json',
      },
      body: { payload: compactJwe },
      timeoutMs: 1_234,
    });
    const serializedRequest = JSON.stringify(transport.mock.calls[0]?.[0]);
    expect(serializedRequest).not.toContain(validCard.number);
    expect(serializedRequest).not.toContain(validCard.securityCode);
    expect(serializedRequest).not.toContain(validCard.expiry);
    expect(serializedRequest).not.toContain(validCard.holderName);
  });

  it('builds a browser JWE and sends only the encrypted payload to the sandbox allowlist', async () => {
    const pair = await webcrypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt'],
    );
    const spki = Buffer.from(await webcrypto.subtle.exportKey('spki', pair.publicKey));
    const publicKeyPem = [
      '-----BEGIN PUBLIC KEY-----',
      spki
        .toString('base64')
        .match(/.{1,64}/gu)
        ?.join('\n') ?? '',
      '-----END PUBLIC KEY-----',
    ].join('\n');
    const fetchImplementation = jest
      .fn()
      .mockResolvedValueOnce(response({ data: { publicKey: publicKeyPem } }))
      .mockResolvedValueOnce(response({ data: { id: 'tok_test_browseropaque123' } }, 201));
    const adapter = createBrowserSandboxTokenizationAdapter(sandboxPublicKey, authorizationExpiry, {
      fetchImplementation: fetchImplementation as unknown as typeof fetch,
      cryptoImplementation: webcrypto as unknown as Crypto,
      timeoutMs: 1_000,
    });

    await expect(adapter.tokenize(validCard)).resolves.toBe('tok_test_browseropaque123');
    expect(adapter.mode).toBe('SANDBOX');
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    expect(fetchImplementation.mock.calls[0]?.[0]).toBe(
      WOMPI_SANDBOX_ORIGIN + WOMPI_TOKENIZATION_KEY_RESOURCE,
    );
    expect(fetchImplementation.mock.calls[0]?.[1]).toMatchObject({
      method: 'GET',
      credentials: 'omit',
      redirect: 'error',
      headers: { Authorization: `Bearer ${sandboxPublicKey}` },
    });
    expect(fetchImplementation.mock.calls[1]?.[0]).toBe(
      WOMPI_SANDBOX_ORIGIN + WOMPI_CARD_TOKENIZATION_RESOURCE,
    );
    const tokenRequest = fetchImplementation.mock.calls[1]?.[1] as RequestInit;
    expect(typeof tokenRequest.body).toBe('string');
    const tokenBody = JSON.parse(tokenRequest.body as string) as Readonly<{ payload: string }>;
    expect(tokenRequest).toMatchObject({ method: 'POST', credentials: 'omit', redirect: 'error' });
    expect(tokenBody.payload.split('.')).toHaveLength(5);
    expect(JSON.stringify(tokenRequest)).not.toContain(validCard.number);
    expect(JSON.stringify(tokenRequest)).not.toContain(validCard.securityCode);
    expect(JSON.stringify(tokenRequest)).not.toContain(validCard.expiry);
    expect(JSON.stringify(tokenRequest)).not.toContain(validCard.holderName);
  });

  it('fails closed with zero transport for disabled or invalid injected options', async () => {
    const disabled = new SandboxCardTokenizationAdapter({ enabled: false });
    await expect(disabled.tokenize(validCard)).rejects.toMatchObject({ code: 'SANDBOX_DISABLED' });

    const encrypt = jest.fn().mockResolvedValue(compactJwe);
    const transport = transportMock();
    const productionKey = new SandboxCardTokenizationAdapter({
      enabled: true,
      environment: 'sandbox',
      origin: WOMPI_SANDBOX_ORIGIN,
      publicKey: productionPublicKey,
      expiresAtUtc: authorizationExpiry,
      encrypt,
      transport,
    });
    await expect(productionKey.tokenize(validCard)).rejects.toMatchObject({
      code: 'SANDBOX_DISABLED',
    });
    const wrongOrigin = new SandboxCardTokenizationAdapter({
      enabled: true,
      environment: 'sandbox',
      origin: 'https://production.wompi.co' as typeof WOMPI_SANDBOX_ORIGIN,
      publicKey: sandboxPublicKey,
      expiresAtUtc: authorizationExpiry,
      encrypt,
      transport,
    });
    await expect(wrongOrigin.tokenize(validCard)).rejects.toMatchObject({
      code: 'SANDBOX_DISABLED',
    });
    const impossibleDate = new SandboxCardTokenizationAdapter({
      enabled: true,
      environment: 'sandbox',
      origin: WOMPI_SANDBOX_ORIGIN,
      publicKey: sandboxPublicKey,
      expiresAtUtc: '2099-02-31T00:00:00.000Z',
      encrypt,
      transport,
    });
    await expect(impossibleDate.tokenize(validCard)).rejects.toMatchObject({
      code: 'SANDBOX_DISABLED',
    });
    expect(disabled.mode).toBe('SANDBOX_READY_DISABLED');
    expect(productionKey.mode).toBe('SANDBOX_READY_DISABLED');
    expect(wrongOrigin.mode).toBe('SANDBOX_READY_DISABLED');
    expect(impossibleDate.mode).toBe('SANDBOX_READY_DISABLED');
    expect(encrypt).not.toHaveBeenCalled();
    expect(transport).not.toHaveBeenCalled();
  });

  it('rejects invalid cards, malformed JWE, failed responses, and malformed tokens safely', async () => {
    const transport = transportMock();
    const create = (encrypt: () => Promise<string>) =>
      new SandboxCardTokenizationAdapter({
        enabled: true,
        environment: 'sandbox',
        origin: WOMPI_SANDBOX_ORIGIN,
        publicKey: sandboxPublicKey,
        expiresAtUtc: authorizationExpiry,
        encrypt,
        transport,
      });

    await expect(create(jest.fn()).tokenize({ ...validCard, number: '1' })).rejects.toMatchObject({
      code: 'CARD_INVALID',
    });
    expect(transport).not.toHaveBeenCalled();
    await expect(
      create(jest.fn().mockResolvedValue('not-jwe')).tokenize(validCard),
    ).rejects.toEqual(new TokenizationError('TOKENIZATION_FAILED'));
    expect(transport).not.toHaveBeenCalled();

    transport.mockResolvedValueOnce({ status: 302, contentType: 'text/html', body: 'redirect' });
    await expect(
      create(jest.fn().mockResolvedValue(compactJwe)).tokenize(validCard),
    ).rejects.toEqual(new TokenizationError('TOKENIZATION_FAILED'));
    transport.mockResolvedValueOnce({
      status: 201,
      contentType: 'application/json',
      body: { data: { id: validCard.number } },
    });
    const failure = create(jest.fn().mockResolvedValue(compactJwe)).tokenize(validCard);
    await expect(failure).rejects.toEqual(new TokenizationError('TOKENIZATION_FAILED'));
    await expect(failure).rejects.not.toThrow(validCard.number);
  });

  it('blocks browser encryption and transport at the exact authorization expiry', async () => {
    const encrypt = jest.fn().mockResolvedValue(compactJwe);
    const transport = transportMock();
    const adapter = new SandboxCardTokenizationAdapter({
      enabled: true,
      environment: 'sandbox',
      origin: WOMPI_SANDBOX_ORIGIN,
      publicKey: sandboxPublicKey,
      expiresAtUtc: '2026-08-17T12:00:00.000Z',
      now: () => Date.parse('2026-08-17T12:00:00.000Z'),
      encrypt,
      transport,
    });
    await expect(adapter.tokenize(validCard)).rejects.toEqual(
      new TokenizationError('SANDBOX_DISABLED'),
    );
    expect(encrypt).not.toHaveBeenCalled();
    expect(transport).not.toHaveBeenCalled();
  });
});
