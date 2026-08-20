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

  it('emits only the sanitized provider egress schema', () => {
    const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    new SafeLogger('api', 'assessment', '1').info('provider.sandbox.egress.attempted', {
      schemaVersion: 1,
      candidateSha: 'a'.repeat(40),
      releaseId: 'rel-20260819-1200-aaaaaaa',
      providerHostSha256: 'b'.repeat(64),
      operation: 'TRANSACTION_CREATE',
      method: 'POST',
      correlationSha256: 'c'.repeat(64),
      containsSensitiveData: false,
      providerReference: 'reference_must-not-be-logged',
      providerId: 'provider-must-not-be-logged',
      body: { token: 'must-not-be-logged' },
    });
    const entry = JSON.parse(String(write.mock.calls[0]?.[0])) as Record<string, unknown>;
    expect(entry).toMatchObject({
      eventName: 'provider.sandbox.egress.attempted',
      candidateSha: 'a'.repeat(40),
      operation: 'TRANSACTION_CREATE',
      method: 'POST',
      correlationSha256: 'c'.repeat(64),
      containsSensitiveData: false,
    });
    expect(entry).not.toHaveProperty('providerReference');
    expect(entry).not.toHaveProperty('providerId');
    expect(entry).not.toHaveProperty('body');
  });
});
