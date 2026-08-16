import { SystemRuntimeSecurity } from './system-runtime-security';

const now = new Date('2026-08-15T12:00:00.000Z');
const rootKey = Buffer.alloc(32, 7).toString('base64url');

describe('SystemRuntimeSecurity', () => {
  it('keeps persisted hashes and acceptance tokens valid across instances with one root key', () => {
    const first = new SystemRuntimeSecurity(() => now, rootKey);
    const restarted = new SystemRuntimeSecurity(() => now, rootKey);
    const capability = first.newCapability('checkout_001');
    const acceptance = first.issueAcceptanceToken(
      'TERMS',
      'terms-v1',
      new Date(now.getTime() + 1_000),
    );

    expect(restarted.hashCapability(capability.raw)).toBe(capability.hash);
    expect(restarted.hashIdempotency('checkout_001', 'request_001')).toBe(
      first.hashIdempotency('checkout_001', 'request_001'),
    );
    expect(restarted.semanticHash('payload')).toBe(first.semanticHash('payload'));
    expect(restarted.verifyAcceptanceToken(acceptance, 'TERMS', now)).toEqual({
      ok: true,
      value: { version: 'terms-v1' },
    });
  });

  it('uses independent ephemeral roots when no stable key is configured', () => {
    const first = new SystemRuntimeSecurity(() => now);
    const second = new SystemRuntimeSecurity(() => now);
    expect(first.hashCapability('same-value')).not.toBe(second.hashCapability('same-value'));
  });

  it('generates opaque identifiers and compares only valid equal-length digests', () => {
    const runtime = new SystemRuntimeSecurity(() => now, Buffer.alloc(32, 9));
    const identifier = runtime.newOpaqueId('transaction');
    const digest = runtime.hashCapability('capability');
    expect(runtime.now()).toBe(now);
    expect(identifier).toMatch(/^transaction_[A-Za-z0-9_-]{24}$/);
    expect(runtime.hashesMatch(digest, digest)).toBe(true);
    expect(runtime.hashesMatch(digest, 'short')).toBe(false);
    expect(runtime.hashesMatch('malformed', digest)).toBe(false);
  });

  it.each([
    '',
    'not+base64url',
    'A'.repeat(45),
    Buffer.alloc(31).toString('base64url'),
    Buffer.alloc(97).toString('base64url'),
  ])('rejects invalid string root key %#', (candidate) => {
    expect(() => new SystemRuntimeSecurity(() => now, candidate)).toThrow();
  });

  it.each([Buffer.alloc(31), Buffer.alloc(97)])(
    'rejects invalid binary root key %#',
    (candidate) => {
      expect(() => new SystemRuntimeSecurity(() => now, candidate)).toThrow();
    },
  );

  it('rejects tampered, expired, wrong-type and malformed acceptance tokens', () => {
    const runtime = new SystemRuntimeSecurity(() => now, rootKey);
    const valid = runtime.issueAcceptanceToken(
      'PERSONAL_DATA',
      'personal-v1',
      new Date(now.getTime() + 1_000),
    );
    const [payload, signature] = valid.split('.') as [string, string];
    const invalid = { ok: false, error: { code: 'ACCEPTANCE_INVALID' } };

    expect(runtime.verifyAcceptanceToken(valid, 'TERMS', now)).toEqual(invalid);
    expect(
      runtime.verifyAcceptanceToken(
        runtime.issueAcceptanceToken('TERMS', 'terms-v1', now),
        'TERMS',
        now,
      ),
    ).toEqual(invalid);
    expect(runtime.verifyAcceptanceToken(`${payload}.${signature}x`, 'PERSONAL_DATA', now)).toEqual(
      invalid,
    );
    expect(
      runtime.verifyAcceptanceToken(`${payload}.${signature}.extra`, 'PERSONAL_DATA', now),
    ).toEqual(invalid);
    expect(runtime.verifyAcceptanceToken('not-json.' + signature, 'PERSONAL_DATA', now)).toEqual(
      invalid,
    );
  });
});
