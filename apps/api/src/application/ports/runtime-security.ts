import type { Result } from '../result/result';

export type AcceptanceType = 'TERMS' | 'PERSONAL_DATA';

export interface RuntimeSecurity {
  now(): Date;
  newOpaqueId(prefix: string): string;
  newCapability(checkoutId: string): Readonly<{ raw: string; hash: string }>;
  hashCapability(raw: string): string;
  hashesMatch(left: string, right: string): boolean;
  hashIdempotency(checkoutId: string, rawKey: string): string;
  semanticHash(value: string): string;
  issueAcceptanceToken(type: AcceptanceType, version: string, expiresAt: Date): string;
  verifyAcceptanceToken(
    token: string,
    expectedType: AcceptanceType,
    now: Date,
  ): Result<Readonly<{ version: string }>, Readonly<{ code: 'ACCEPTANCE_INVALID' }>>;
}

export const RUNTIME_SECURITY = Symbol('RUNTIME_SECURITY');
