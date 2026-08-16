import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import type { AcceptanceType, RuntimeSecurity } from '../../application/ports/runtime-security';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';

interface AcceptancePayload {
  readonly type: AcceptanceType;
  readonly version: string;
  readonly expiresAt: number;
}

const digest = (key: Buffer, value: string): string =>
  createHmac('sha256', key).update(value, 'utf8').digest('base64url');

const decodeRootKey = (value: string): Buffer => {
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(value)) {
    throw new Error('Runtime security root key must be unpadded base64url');
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) {
    throw new Error('Runtime security root key must be canonical base64url');
  }
  return decoded;
};

const deriveKey = (rootKey: Buffer, domain: string): Buffer =>
  Buffer.from(hkdfSync('sha256', rootKey, 'async-checkout/runtime/v1', domain, 32));

export class SystemRuntimeSecurity implements RuntimeSecurity {
  private readonly capabilityKey: Buffer;
  private readonly idempotencyKey: Buffer;
  private readonly semanticKey: Buffer;
  private readonly acceptanceKey: Buffer;

  public constructor(
    private readonly clock: () => Date = () => new Date(),
    rootKey: string | Buffer = randomBytes(32),
  ) {
    const root = typeof rootKey === 'string' ? decodeRootKey(rootKey) : Buffer.from(rootKey);
    if (root.length < 32 || root.length > 96) {
      throw new Error('Runtime security root key must contain between 32 and 96 bytes');
    }
    this.capabilityKey = deriveKey(root, 'capability');
    this.idempotencyKey = deriveKey(root, 'idempotency');
    this.semanticKey = deriveKey(root, 'semantic');
    this.acceptanceKey = deriveKey(root, 'acceptance');
  }

  public now(): Date {
    return this.clock();
  }

  public newOpaqueId(prefix: string): string {
    return `${prefix}_${randomBytes(18).toString('base64url')}`;
  }

  public newCapability(checkoutId: string): Readonly<{ raw: string; hash: string }> {
    const raw = `${checkoutId}.${randomBytes(32).toString('base64url')}`;
    return { raw, hash: this.hashCapability(raw) };
  }

  public hashCapability(raw: string): string {
    return digest(this.capabilityKey, `capability|${raw}`);
  }

  public hashesMatch(left: string, right: string): boolean {
    if (!/^[A-Za-z0-9_-]{43}$/.test(left) || !/^[A-Za-z0-9_-]{43}$/.test(right)) {
      return false;
    }
    const leftBuffer = Buffer.from(left, 'base64url');
    const rightBuffer = Buffer.from(right, 'base64url');
    return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
  }

  public hashIdempotency(checkoutId: string, rawKey: string): string {
    return digest(this.idempotencyKey, `submit-payment|${checkoutId}|${rawKey}`);
  }

  public semanticHash(value: string): string {
    return digest(this.semanticKey, `semantic-v1|${value}`);
  }

  public issueAcceptanceToken(type: AcceptanceType, version: string, expiresAt: Date): string {
    const payload = Buffer.from(
      JSON.stringify({ type, version, expiresAt: expiresAt.getTime() } satisfies AcceptancePayload),
    ).toString('base64url');
    return `${payload}.${digest(this.acceptanceKey, payload)}`;
  }

  public verifyAcceptanceToken(
    token: string,
    expectedType: AcceptanceType,
    now: Date,
  ): Result<Readonly<{ version: string }>, Readonly<{ code: 'ACCEPTANCE_INVALID' }>> {
    try {
      const [payload, signature, extra] = token.split('.');
      if (
        payload === undefined ||
        signature === undefined ||
        extra !== undefined ||
        !this.hashesMatch(digest(this.acceptanceKey, payload), signature)
      ) {
        return err({ code: 'ACCEPTANCE_INVALID' });
      }
      const parsed = JSON.parse(
        Buffer.from(payload, 'base64url').toString('utf8'),
      ) as Partial<AcceptancePayload>;
      return parsed.type === expectedType &&
        typeof parsed.version === 'string' &&
        typeof parsed.expiresAt === 'number' &&
        parsed.expiresAt > now.getTime()
        ? ok({ version: parsed.version })
        : err({ code: 'ACCEPTANCE_INVALID' });
    } catch {
      return err({ code: 'ACCEPTANCE_INVALID' });
    }
  }
}
