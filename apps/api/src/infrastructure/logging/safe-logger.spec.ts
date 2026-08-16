import { redactLogRecord, SafeLogger } from './safe-logger';

describe('safe logging', () => {
  it('redacts nested sensitive keys and arrays', () => {
    expect(
      redactLogRecord({
        authorization: 'value',
        nested: { cardToken: 'value' },
        runtimeSecurityRootKey: 'synthetic-root-key',
        privateKey: 'value',
        publicKey: 'synthetic-public-key',
        values: [{ address: 'value' }],
      }),
    ).toEqual({
      authorization: '[REDACTED]',
      nested: { cardToken: '[REDACTED]' },
      runtimeSecurityRootKey: '[REDACTED]',
      privateKey: '[REDACTED]',
      publicKey: 'synthetic-public-key',
      values: [{ address: '[REDACTED]' }],
    });
  });

  it('writes one structured allowlisted line and drops unknown PII fields', () => {
    const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    new SafeLogger('api', 'test', '1').info('test.event', {
      correlationId: 'correlation-01',
      email: 'private@example.invalid',
      phone: 'private-phone',
      fullName: 'Private Name',
    });
    expect(write).toHaveBeenCalledTimes(1);
    const entry = JSON.parse(String(write.mock.calls[0]?.[0])) as Record<string, unknown>;
    expect(entry).toMatchObject({ eventName: 'test.event', correlationId: 'correlation-01' });
    expect(entry).not.toHaveProperty('email');
    expect(entry).not.toHaveProperty('phone');
    expect(entry).not.toHaveProperty('fullName');
  });
});
