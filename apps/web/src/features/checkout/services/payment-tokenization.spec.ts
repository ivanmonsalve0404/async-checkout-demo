import {
  FakeCardTokenizationAdapter,
  SandboxCardTokenizationAdapter,
  TokenizationError,
  WOMPI_CARD_TOKENIZATION_RESOURCE,
  WOMPI_SANDBOX_ORIGIN,
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

const transportMock = (): jest.MockedFunction<SandboxTokenizationTransport> =>
  jest.fn<ReturnType<SandboxTokenizationTransport>, Parameters<SandboxTokenizationTransport>>();

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
      encrypt,
      transport,
    });
    await expect(wrongOrigin.tokenize(validCard)).rejects.toMatchObject({
      code: 'SANDBOX_DISABLED',
    });
    expect(disabled.mode).toBe('SANDBOX_READY_DISABLED');
    expect(productionKey.mode).toBe('SANDBOX_READY_DISABLED');
    expect(wrongOrigin.mode).toBe('SANDBOX_READY_DISABLED');
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
});
