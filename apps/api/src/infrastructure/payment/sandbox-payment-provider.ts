import { createHash } from 'node:crypto';
import {
  isProviderAcceptanceJwtUsable,
  isWompiProviderPermalink,
} from '../configuration/runtime-secrets';
import type { MerchantContractSet } from '../../application/ports/merchant-contract';
import type {
  PaymentProvider,
  ProviderCreateOutcome,
  ProviderError,
  ProviderObservation,
  ProviderPaymentCommand,
  ProviderStatus,
} from '../../application/ports/payment-provider';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';

export interface SandboxTransportRequest {
  readonly method: 'GET' | 'POST';
  readonly resource: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: unknown;
  readonly timeoutMs: number;
  readonly correlationReference: string;
}

export interface SandboxTransportResponse {
  readonly status: number;
  readonly contentType: string | null;
  readonly body: unknown;
}

export type SandboxTransport = (
  request: SandboxTransportRequest,
) => Promise<SandboxTransportResponse>;

export interface SandboxProviderAcceptanceSnapshot {
  readonly contracts: MerchantContractSet;
  readonly providerAcceptances: Readonly<{
    terms: string;
    personalData: string;
  }>;
}

export type SandboxAcceptanceReader = (
  correlationReference: string,
) => Promise<SandboxProviderAcceptanceSnapshot>;

export interface SandboxPaymentProviderOptions {
  readonly enabled: boolean;
  readonly privateKey?: string;
  readonly publicKey?: string;
  readonly integritySecret?: string;
  readonly transport?: SandboxTransport;
  readonly acceptanceReader?: SandboxAcceptanceReader;
  readonly expectedContracts?: MerchantContractSet;
  readonly quoteTtlSeconds?: number;
  readonly authorizedUntilUtc?: string;
  readonly now?: () => Date;
  readonly timeoutMs?: number;
}

interface ReadySandboxPaymentProviderOptions {
  readonly privateKey: string;
  readonly publicKey: string;
  readonly integritySecret: string;
  readonly transport: SandboxTransport;
  readonly acceptanceReader: SandboxAcceptanceReader;
  readonly expectedContracts: MerchantContractSet;
  readonly quoteTtlSeconds: number;
  readonly authorizedUntilUtc: string;
  readonly now: () => Date;
}

const providerStatuses = new Set<ProviderStatus>([
  'PENDING',
  'APPROVED',
  'DECLINED',
  'VOIDED',
  'ERROR',
  'UNKNOWN_EXTERNAL',
]);

const canonicalUtcMillis = (value: string | undefined): number | null => {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    return null;
  }
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
    ? milliseconds
    : null;
};

const validContract = (value: unknown, type: 'TERMS' | 'PERSONAL_DATA'): boolean => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Readonly<Record<string, unknown>>;
  return (
    record.type === type &&
    isWompiProviderPermalink(record.permalink) &&
    typeof record.version === 'string' &&
    record.version.length > 0
  );
};

const validContractSet = (value: unknown): value is MerchantContractSet =>
  Array.isArray(value) &&
  value.length === 2 &&
  validContract(value[0] as unknown, 'TERMS') &&
  validContract(value[1] as unknown, 'PERSONAL_DATA');

const sameContractSet = (left: MerchantContractSet, right: MerchantContractSet): boolean =>
  left[0].type === right[0].type &&
  left[0].permalink === right[0].permalink &&
  left[0].version === right[0].version &&
  left[1].type === right[1].type &&
  left[1].permalink === right[1].permalink &&
  left[1].version === right[1].version;

export const signSandboxIntegrity = (
  reference: string,
  amountInCents: number,
  currency: string,
  secret: string,
): string =>
  createHash('sha256').update(`${reference}${amountInCents}${currency}${secret}`).digest('hex');

export const redactSandboxDiagnostic = (candidate: unknown): unknown => {
  if (Array.isArray(candidate)) return candidate.map(redactSandboxDiagnostic);
  if (typeof candidate !== 'object' || candidate === null) return candidate;
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(candidate)) {
    result[key] =
      /authorization|token|acceptance|secret|signature|pan|cvc|card|(?:api|private|root|hmac).*key/i.test(
        key,
      )
        ? '[REDACTED]'
        : redactSandboxDiagnostic(value);
  }
  return result;
};

export class SandboxPaymentProvider implements PaymentProvider {
  private readonly timeoutMs: number;

  public constructor(private readonly options: SandboxPaymentProviderOptions) {
    this.timeoutMs = options.timeoutMs ?? 8_000;
  }

  public getPublicConfiguration(): Result<
    Readonly<{
      mode: 'sandbox';
      captureVariant: 'DIRECT_JWE';
      publicKey: string;
      installments: readonly number[];
    }>,
    ProviderError
  > {
    const options = this.readyOptions();
    if (options === null) return err({ code: 'ENVIRONMENT_DISABLED' });
    return ok({
      mode: 'sandbox',
      captureVariant: 'DIRECT_JWE',
      publicKey: options.publicKey,
      installments: [1, 2, 3],
      authorizedUntilUtc: options.authorizedUntilUtc,
    });
  }

  public async createOnce(
    command: ProviderPaymentCommand,
  ): Promise<Result<ProviderCreateOutcome, ProviderError>> {
    const options = this.readyOptions();
    if (options === null) return err({ code: 'ENVIRONMENT_DISABLED' });
    let snapshot: SandboxProviderAcceptanceSnapshot;
    try {
      snapshot = await options.acceptanceReader(command.reference);
      const currentTime = options.now();
      if (
        !validContractSet(snapshot.contracts) ||
        !sameContractSet(options.expectedContracts, snapshot.contracts) ||
        !isProviderAcceptanceJwtUsable(
          snapshot.providerAcceptances.terms,
          currentTime,
          options.quoteTtlSeconds,
        ) ||
        !isProviderAcceptanceJwtUsable(
          snapshot.providerAcceptances.personalData,
          currentTime,
          options.quoteTtlSeconds,
        )
      ) {
        return ok({ kind: 'PROVEN_NOT_SENT' });
      }
    } catch {
      return ok({ kind: 'PROVEN_NOT_SENT' });
    }
    const request: SandboxTransportRequest = {
      method: 'POST',
      resource: '/v1/transactions',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${options.privateKey}`,
        'Content-Type': 'application/json',
      },
      timeoutMs: this.timeoutMs,
      correlationReference: command.reference,
      body: {
        acceptance_token: snapshot.providerAcceptances.terms,
        accept_personal_auth: snapshot.providerAcceptances.personalData,
        amount_in_cents: command.amountInCents,
        currency: command.currency,
        customer_email: command.customerEmail,
        payment_method: {
          type: 'CARD',
          token: command.paymentMethodHandle.value,
          installments: command.installments,
        },
        reference: command.reference,
        signature: signSandboxIntegrity(
          command.reference,
          command.amountInCents,
          command.currency,
          options.integritySecret,
        ),
      },
    };
    let response: SandboxTransportResponse;
    try {
      // A payment POST is intentionally attempted exactly once. The caller reconciles uncertainty.
      response = await options.transport(request);
    } catch {
      return ok({ kind: 'OUTCOME_UNKNOWN' });
    }
    if (response.status < 200 || response.status >= 300) {
      return ok({ kind: 'OUTCOME_UNKNOWN' });
    }
    if (!this.isJson(response.contentType)) {
      return ok({ kind: 'PROTOCOL_VIOLATION_AFTER_POSSIBLE_SEND' });
    }
    const observation = normalizeObservation(response.body);
    if (observation === null || observation.status === 'UNKNOWN_EXTERNAL') {
      return ok({ kind: 'PROTOCOL_VIOLATION_AFTER_POSSIBLE_SEND' });
    }
    return ok({
      kind: 'ACKNOWLEDGED',
      ...observation,
      status: observation.status,
    });
  }

  public getByReference(reference: string): Promise<Result<ProviderObservation, ProviderError>> {
    void reference;
    return Promise.resolve(err({ code: 'REFERENCE_LOOKUP_UNSUPPORTED' }));
  }

  public async getById(
    providerId: string,
    expectedReference?: string,
  ): Promise<Result<ProviderObservation, ProviderError>> {
    const options = this.readyOptions();
    if (options === null) return err({ code: 'ENVIRONMENT_DISABLED' });
    if (typeof expectedReference !== 'string' || expectedReference.length === 0) {
      return err({ code: 'PROVIDER_PROTOCOL_ERROR' });
    }
    let response: SandboxTransportResponse;
    try {
      response = await options.transport({
        method: 'GET',
        resource: `/v1/transactions/${encodeURIComponent(providerId)}`,
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${options.publicKey}`,
        },
        timeoutMs: this.timeoutMs,
        correlationReference: expectedReference,
      });
    } catch (error: unknown) {
      return err({ code: isTimeoutError(error) ? 'PROVIDER_TIMEOUT' : 'PROVIDER_UNAVAILABLE' });
    }
    if (response.status < 200 || response.status >= 300) {
      if (response.status === 429) return err({ code: 'PROVIDER_RATE_LIMITED' });
      return err({ code: 'PROVIDER_UNAVAILABLE' });
    }
    if (!this.isJson(response.contentType)) return err({ code: 'PROVIDER_PROTOCOL_ERROR' });
    const observation = normalizeObservation(response.body);
    return observation === null ? err({ code: 'PROVIDER_PROTOCOL_ERROR' }) : ok(observation);
  }

  public verifyAndNormalizeEvent(
    eventName: string,
  ): Result<Readonly<{ eventName: string }>, ProviderError> {
    void eventName;
    // API-11 remains deferred until an isolated sandbox webhook secret exists.
    return err({ code: 'ENVIRONMENT_DISABLED' });
  }

  private readyOptions(): ReadySandboxPaymentProviderOptions | null {
    const {
      privateKey,
      publicKey,
      integritySecret,
      transport,
      acceptanceReader,
      expectedContracts,
      quoteTtlSeconds,
      authorizedUntilUtc,
    } = this.options;
    const authorizedUntil = canonicalUtcMillis(authorizedUntilUtc);
    const currentTime = (this.options.now ?? (() => new Date()))();
    const now = currentTime.getTime();
    if (
      this.options.enabled &&
      authorizedUntil !== null &&
      now < authorizedUntil &&
      typeof publicKey === 'string' &&
      publicKey.length > 0 &&
      typeof privateKey === 'string' &&
      privateKey.length > 0 &&
      typeof integritySecret === 'string' &&
      integritySecret.length > 0 &&
      typeof transport === 'function' &&
      typeof acceptanceReader === 'function' &&
      validContractSet(expectedContracts) &&
      Number.isSafeInteger(quoteTtlSeconds) &&
      (quoteTtlSeconds as number) > 0
    ) {
      return {
        privateKey,
        publicKey,
        integritySecret,
        transport,
        acceptanceReader,
        expectedContracts,
        quoteTtlSeconds: quoteTtlSeconds as number,
        authorizedUntilUtc: authorizedUntilUtc as string,
        now: this.options.now ?? (() => new Date()),
      };
    }
    return null;
  }

  private isJson(contentType: string | null): boolean {
    return contentType?.toLowerCase().includes('application/json') === true;
  }
}

const isTimeoutError = (error: unknown): boolean => {
  if (typeof error !== 'object' || error === null) return false;
  const candidate = error as Readonly<{ name?: unknown; code?: unknown }>;
  return (
    candidate.name === 'AbortError' ||
    candidate.name === 'TimeoutError' ||
    candidate.code === 'ETIMEDOUT'
  );
};

const normalizeObservation = (body: unknown): ProviderObservation | null => {
  if (typeof body !== 'object' || body === null) return null;
  const envelope = body as Record<string, unknown>;
  const value =
    typeof envelope.data === 'object' && envelope.data !== null
      ? (envelope.data as Record<string, unknown>)
      : envelope;
  const providerId = value.id ?? value.providerId;
  const reference = value.reference;
  const amountInCents = value.amount_in_cents ?? value.amountInCents;
  const currency = value.currency;
  const status = value.status;
  if (
    typeof providerId !== 'string' ||
    providerId.length === 0 ||
    typeof reference !== 'string' ||
    reference.length === 0 ||
    !Number.isSafeInteger(amountInCents) ||
    (amountInCents as number) < 0 ||
    typeof currency !== 'string' ||
    typeof status !== 'string' ||
    !providerStatuses.has(status as ProviderStatus)
  ) {
    return null;
  }
  return {
    providerId,
    reference,
    amountInCents: amountInCents as number,
    currency,
    status: status as ProviderStatus,
  };
};
