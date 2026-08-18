import type { CatalogRepository } from '../ports/catalog-repository';
import type {
  CheckoutRepository,
  CheckoutRepositoryError,
  ReconciliationCheck,
} from '../ports/checkout-repository';
import type {
  MerchantContractPort,
  MerchantContractSet,
  PersonalDataMerchantContract,
  TermsMerchantContract,
} from '../ports/merchant-contract';
import type {
  PaymentProvider,
  ProviderCreateOutcome,
  ProviderObservation,
} from '../ports/payment-provider';
import type { RuntimeSecurity } from '../ports/runtime-security';
import {
  NOOP_OBSERVABILITY,
  type MetricName,
  type ObservabilityPort,
} from '../ports/observability';
import type { Result } from '../result/result';
import { err, ok } from '../result/result';
import type { ProductAvailability } from '../../domain/catalog/product';
import {
  allowedActionsFor,
  etagFor,
  type Checkout,
  type AcceptanceEvidence,
  type Customer,
  type Delivery,
  type DeliveryDetails,
  type PaymentSubmission,
  type Quote,
  type Transaction,
} from '../../domain/checkout/checkout';

export type CheckoutApplicationError = Readonly<{
  code:
    | 'PRODUCT_NOT_FOUND'
    | 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN'
    | 'CHECKOUT_EXPIRED'
    | 'PRECONDITION_FAILED'
    | 'FIELD_INVALID'
    | 'OUT_OF_STOCK'
    | 'QUOTE_STALE'
    | 'IDEMPOTENCY_CONFLICT'
    | 'PAYMENT_ALREADY_IN_PROGRESS'
    | 'STATE_TRANSITION_CONFLICT'
    | 'PROVIDER_AUTH_OR_CONFIG_INVALID'
    | 'INTERNAL_ERROR';
}>;

export interface PaymentConfiguration {
  readonly captureVariant: 'FAKE_CONTRACT' | 'DIRECT_JWE' | 'HOSTED_COMPONENT';
  readonly sandboxPublicKey: string;
  readonly allowedInstallments: readonly number[];
  readonly acceptanceContracts: readonly [
    Readonly<{
      type: 'TERMS';
      permalink: string;
      version: string;
      acceptanceToken: string;
    }>,
    Readonly<{
      type: 'PERSONAL_DATA';
      permalink: string;
      version: string;
      acceptanceToken: string;
    }>,
  ];
  readonly expiresAt: string;
}

export interface CheckoutView {
  readonly checkout: Checkout;
  readonly product: ProductAvailability;
}

export interface TransactionView {
  readonly transaction: Transaction;
  readonly checkout: Checkout;
  readonly allowedActions: ReturnType<typeof allowedActionsFor>;
}

export interface SubmitPaymentInput {
  readonly quoteId: string;
  readonly paymentMethodToken: string;
  readonly installments: number;
  readonly acceptances: Readonly<{
    termsAcceptanceToken: string;
    personalDataAcceptanceToken: string;
  }>;
}

export interface ReconciliationBackoffPolicy {
  readonly delaysMs: readonly [number, ...number[]];
  readonly recurringDelayMs: number;
  readonly jitterRatio: number;
}

export const PRODUCTION_RECONCILIATION_BACKOFF_POLICY: ReconciliationBackoffPolicy = Object.freeze({
  delaysMs: [60_000, 120_000, 300_000, 600_000, 900_000] as const,
  recurringDelayMs: 3_600_000,
  jitterRatio: 0.2,
});

export const LOCAL_FAKE_RECONCILIATION_BACKOFF_POLICY: ReconciliationBackoffPolicy = Object.freeze({
  delaysMs: [250, 500, 1_000, 2_000, 3_000] as const,
  recurringDelayMs: 5_000,
  jitterRatio: 0,
});
const RECONCILIATION_LEASE_MS = 45_000;
const RECONCILIATION_BATCH_SIZE = 10;
const PROVIDER_READ_LIMIT = 2;
const BASE_FEE_IN_CENTS = 200_000;
const DELIVERY_FEE_IN_CENTS = 500_000;

export class CheckoutService {
  public constructor(
    private readonly catalog: CatalogRepository,
    private readonly repository: CheckoutRepository,
    private readonly paymentProvider: PaymentProvider,
    private readonly runtime: RuntimeSecurity,
    private readonly merchantContracts: MerchantContractPort,
    private readonly quoteTtlSeconds = 900,
    private readonly checkoutTtlSeconds = 1800,
    private readonly observability: ObservabilityPort = NOOP_OBSERVABILITY,
    private readonly random: () => number = () => Math.random(),
    private readonly backoffPolicy = PRODUCTION_RECONCILIATION_BACKOFF_POLICY,
  ) {}

  public async createCheckout(
    productId: string,
  ): Promise<
    Result<Readonly<{ checkout: Checkout; rawCapability: string }>, CheckoutApplicationError>
  > {
    const productResult = await this.catalog.findById(productId);
    if (!productResult.ok) return err({ code: 'INTERNAL_ERROR' });
    const product = productResult.value;
    if (product === null || !product.active) return err({ code: 'PRODUCT_NOT_FOUND' });
    if (product.available < 1) {
      this.observability.event('inventory.conflict');
      this.observability.increment('inventory_conflicts_total');
      return err({ code: 'OUT_OF_STOCK' });
    }

    const now = this.runtime.now();
    const checkoutId = this.runtime.newOpaqueId('checkout');
    const capability = this.runtime.newCapability(checkoutId);
    const quote = this.createQuote(product, now);
    const checkout: Checkout = {
      checkoutId,
      status: 'DRAFT',
      version: 1,
      capabilityHash: capability.hash,
      productId,
      quote,
      expiresAt: new Date(now.getTime() + this.checkoutTtlSeconds * 1000).toISOString(),
    };
    const created = await this.repository.create(checkout);
    if (!created.ok) return err({ code: 'INTERNAL_ERROR' });
    this.observability.event('checkout.created', { toState: created.value.status });
    this.observability.event('checkout.quoted');
    this.observability.increment('checkout_sessions_total');
    this.observability.increment('checkout_quotes_total');
    return ok({ checkout: created.value, rawCapability: capability.raw });
  }

  public async getCheckout(
    checkoutId: string,
    rawCapability: string | null,
  ): Promise<Result<CheckoutView, CheckoutApplicationError>> {
    const authorized = await this.authorize(checkoutId, rawCapability);
    if (!authorized.ok) return authorized;
    const product = await this.catalog.findById(authorized.value.productId);
    return product.ok && product.value !== null
      ? ok({ checkout: authorized.value, product: product.value })
      : err({ code: 'INTERNAL_ERROR' });
  }

  public async replaceCustomer(
    checkoutId: string,
    rawCapability: string | null,
    ifMatch: string | undefined,
    input: Readonly<{ fullName: string; email: string; phone: string }>,
  ): Promise<Result<Checkout, CheckoutApplicationError>> {
    const authorized = await this.authorize(checkoutId, rawCapability);
    if (!authorized.ok) return authorized;
    const expectedVersion = this.expectedVersion(ifMatch);
    if (!expectedVersion.ok) return expectedVersion;
    const customer: Omit<Customer, 'version'> = {
      customerId: this.runtime.newOpaqueId('customer'),
      checkoutId,
      fullName: input.fullName.trim(),
      email: input.email.trim().toLowerCase(),
      phone: input.phone,
    };
    return this.mapRepository(
      await this.repository.replaceCustomer(
        checkoutId,
        authorized.value.capabilityHash,
        expectedVersion.value,
        customer,
      ),
    );
  }

  public async replaceDeliveryDetails(
    checkoutId: string,
    rawCapability: string | null,
    ifMatch: string | undefined,
    input: Omit<DeliveryDetails, 'checkoutId' | 'version'>,
  ): Promise<Result<Checkout, CheckoutApplicationError>> {
    const authorized = await this.authorize(checkoutId, rawCapability);
    if (!authorized.ok) return authorized;
    const expectedVersion = this.expectedVersion(ifMatch);
    if (!expectedVersion.ok) return expectedVersion;
    return this.mapRepository(
      await this.repository.replaceDeliveryDetails(
        checkoutId,
        authorized.value.capabilityHash,
        expectedVersion.value,
        { ...input, checkoutId },
      ),
    );
  }

  public getPaymentConfiguration(): Result<PaymentConfiguration, CheckoutApplicationError> {
    const configuration = this.paymentProvider.getPublicConfiguration();
    if (!configuration.ok) return err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' });
    const contracts = this.currentMerchantContracts();
    if (!contracts.ok) return contracts;
    const [terms, personalData] = contracts.value;
    const now = this.runtime.now();
    const providerExpiry = Date.parse(configuration.value.authorizedUntilUtc ?? '');
    const expiresAt = new Date(
      Math.min(
        now.getTime() + 15 * 60 * 1000,
        Number.isFinite(providerExpiry) ? providerExpiry : Number.POSITIVE_INFINITY,
      ),
    );
    if (expiresAt.getTime() <= now.getTime()) {
      return err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' });
    }
    return ok({
      captureVariant: configuration.value.captureVariant,
      sandboxPublicKey: configuration.value.publicKey,
      allowedInstallments: configuration.value.installments,
      acceptanceContracts: [
        {
          ...terms,
          acceptanceToken: this.runtime.issueAcceptanceToken(terms.type, terms.version, expiresAt),
        },
        {
          ...personalData,
          acceptanceToken: this.runtime.issueAcceptanceToken(
            personalData.type,
            personalData.version,
            expiresAt,
          ),
        },
      ],
      expiresAt: expiresAt.toISOString(),
    });
  }

  public async submitPayment(
    checkoutId: string,
    rawCapability: string | null,
    ifMatch: string | undefined,
    rawIdempotencyKey: string | undefined,
    input: SubmitPaymentInput,
  ): Promise<Result<PaymentSubmission, CheckoutApplicationError>> {
    const authorized = await this.authorize(checkoutId, rawCapability);
    if (!authorized.ok) return authorized;
    const expectedVersion = this.expectedVersion(ifMatch);
    if (!expectedVersion.ok) return expectedVersion;
    if (rawIdempotencyKey === undefined || !/^[A-Za-z0-9._~-]{16,128}$/.test(rawIdempotencyKey)) {
      return err({ code: 'FIELD_INVALID' });
    }
    const now = this.runtime.now();
    const contracts = this.currentMerchantContracts();
    if (!contracts.ok) return contracts;
    const contractEvidence = this.acceptanceContractEvidence(contracts.value);
    const keyHash = this.runtime.hashIdempotency(checkoutId, rawIdempotencyKey);
    const semanticHash = this.semanticRequestHash(
      authorized.value,
      expectedVersion.value,
      input,
      contractEvidence,
    );
    const replay = await this.repository.findIdempotency({
      checkoutId,
      keyHash,
      semanticHash,
    });
    if (!replay.ok) {
      if (replay.error.code === 'IDEMPOTENCY_CONFLICT') this.recordIdempotencyConflict();
      return this.mapRepository(replay);
    }
    if (replay.value !== null) {
      this.recordIdempotencyReplay();
      const replayValidation = this.validateDispatchableReplay(
        replay.value.transaction,
        input,
        contracts.value,
      );
      if (!replayValidation.ok) {
        if (replayValidation.error.code === 'IDEMPOTENCY_CONFLICT')
          this.recordIdempotencyConflict();
        return err(replayValidation.error);
      }
      const dispatched = await this.dispatchIfLeader(
        replay.value.transaction,
        input,
        authorized.value.customer?.email ?? '',
      );
      if (!dispatched.ok) return ok(replay.value.submission);
      return ok(replay.value.submission);
    }
    if (authorized.value.status !== 'READY' && authorized.value.activeTransactionId === undefined) {
      return err({ code: 'STATE_TRANSITION_CONFLICT' });
    }
    if (input.quoteId !== authorized.value.quote.quoteId) return err({ code: 'QUOTE_STALE' });
    if (new Date(authorized.value.quote.expiresAt).getTime() <= now.getTime()) {
      this.observability.event('checkout.quote_expired');
      this.observability.increment('checkout_quotes_expired_total');
      return err({ code: 'QUOTE_STALE' });
    }
    const currentProduct = await this.catalog.findById(authorized.value.productId);
    if (!currentProduct.ok) return err({ code: 'INTERNAL_ERROR' });
    if (
      currentProduct.value === null ||
      !currentProduct.value.active ||
      currentProduct.value.unitPrice.amountInCents !==
        authorized.value.quote.subtotal.amountInCents ||
      currentProduct.value.unitPrice.currency !== authorized.value.quote.subtotal.currency
    ) {
      return err({ code: 'QUOTE_STALE' });
    }
    const configuration = this.paymentProvider.getPublicConfiguration();
    if (!configuration.ok) return err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' });
    if (!configuration.value.installments.includes(input.installments)) {
      return err({ code: 'FIELD_INVALID' });
    }
    const accepted = this.validateAcceptances(input, contracts.value, now);
    if (!accepted.ok) return err(accepted.error);
    const transactionId = this.runtime.newOpaqueId('transaction');
    const acceptedAt = now.toISOString();
    const submission: PaymentSubmission = {
      transactionId,
      statusUrl: `/api/v1/transactions/${transactionId}`,
      submissionState: 'ACCEPTED',
      acceptedAt,
    };
    const transaction: Transaction = {
      transactionId,
      checkoutId,
      providerReference: `reference_${transactionId}`,
      paymentStatus: 'PENDING',
      dispatchPhase: 'NOT_SENT',
      providerStatus: null,
      reservationStatus: 'ACTIVE',
      integrityStatus: 'OK',
      acceptanceEvidence: accepted.value,
      acceptedAt,
      updatedAt: acceptedAt,
      attempts: 0,
      // A durable NOT_SENT record is recoverable only after the inline dispatcher
      // has had a bounded grace period to claim it. The due worker then proves
      // that no dispatch leader existed before releasing the reservation.
      nextCheckAt: new Date(now.getTime() + RECONCILIATION_LEASE_MS).toISOString(),
      amountInCents: authorized.value.quote.total.amountInCents,
      currency: 'COP',
      effectsApplied: false,
    };
    const prepared = await this.repository.preparePayment({
      checkoutId,
      capabilityHash: authorized.value.capabilityHash,
      expectedVersion: expectedVersion.value,
      keyHash,
      semanticHash,
      transaction,
      submission,
    });
    if (!prepared.ok) {
      if (prepared.error.code === 'IDEMPOTENCY_CONFLICT') this.recordIdempotencyConflict();
      if (prepared.error.code === 'OUT_OF_STOCK') {
        this.observability.event('inventory.conflict');
        this.observability.increment('inventory_conflicts_total');
      }
      return this.mapRepository(prepared);
    }
    if (prepared.value.kind === 'REPLAY') {
      this.recordIdempotencyReplay();
      const replayValidation = this.validateDispatchableReplay(
        prepared.value.transaction,
        input,
        contracts.value,
      );
      if (!replayValidation.ok) {
        if (replayValidation.error.code === 'IDEMPOTENCY_CONFLICT')
          this.recordIdempotencyConflict();
        return err(replayValidation.error);
      }
    } else {
      this.observability.event('payment.reserved', { toState: 'ACTIVE' });
      this.observability.increment('reservations_total');
      this.observability.increment('reservations_created_total');
    }
    const dispatched = await this.dispatchIfLeader(
      prepared.value.transaction,
      input,
      authorized.value.customer?.email ?? '',
    );
    if (!dispatched.ok) return ok(prepared.value.submission);
    return ok(prepared.value.submission);
  }

  public async getTransaction(
    transactionId: string,
    rawCapability: string | null,
  ): Promise<Result<TransactionView, CheckoutApplicationError>> {
    const found = await this.repository.findTransaction(transactionId);
    if (!found.ok || found.value === null) return err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' });
    const checkout = await this.authorize(found.value.checkoutId, rawCapability);
    return checkout.ok
      ? ok({
          transaction: found.value,
          checkout: checkout.value,
          allowedActions: allowedActionsFor(found.value),
        })
      : checkout;
  }

  public async getDelivery(
    deliveryId: string,
    rawCapability: string | null,
  ): Promise<Result<Delivery, CheckoutApplicationError>> {
    const found = await this.repository.findDelivery(deliveryId);
    if (!found.ok || found.value === null) return err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' });
    const checkout = await this.authorize(found.value.checkoutId, rawCapability);
    return checkout.ok ? ok(found.value) : checkout;
  }

  public async reconcileDue(): Promise<Result<number, CheckoutApplicationError>> {
    const claimedAt = this.runtime.now();
    const due = await this.repository.claimDue(
      claimedAt.toISOString(),
      new Date(claimedAt.getTime() + RECONCILIATION_LEASE_MS).toISOString(),
      RECONCILIATION_BATCH_SIZE,
    );
    if (!due.ok) return err({ code: 'INTERNAL_ERROR' });

    const oldestPendingAgeSeconds = due.value.reduce((oldest, transaction) => {
      const acceptedAt = Date.parse(transaction.acceptedAt);
      if (!Number.isFinite(acceptedAt)) return oldest;
      return Math.max(oldest, Math.floor((claimedAt.getTime() - acceptedAt) / 1000));
    }, 0);
    this.observability.observe('oldest_pending_age_seconds', oldestPendingAgeSeconds);

    let processed = 0;
    let providerReads = 0;
    for (const transaction of due.value) {
      this.observability.event('reconcile.claimed', {
        dispatchPhase: transaction.dispatchPhase,
        retryCount: transaction.attempts,
      });
      const attempts = transaction.attempts + 1;
      if (transaction.providerId === undefined) {
        if (transaction.dispatchPhase === 'NOT_SENT_FAILED') {
          const finalized = await this.finalizeAndObserve(
            transaction,
            'ERROR',
            null,
            'PROVIDER_NOT_SENT',
            this.runtime.now().toISOString(),
          );
          if (!finalized.ok) return finalized;
        } else {
          const checkedAt = this.runtime.now();
          const marked = await this.markUnknown(
            transaction,
            checkedAt,
            attempts,
            'REFERENCE_LOOKUP_UNSUPPORTED',
          );
          if (!marked.ok) return marked;
        }
        processed += 1;
        continue;
      }
      if (providerReads >= PROVIDER_READ_LIMIT) continue;

      providerReads += 1;
      const providerReadStartedAt = this.runtime.now().getTime();
      const observation = await this.paymentProvider.getById(transaction.providerId);
      this.observeDuration('provider_query_latency_ms', providerReadStartedAt);
      if (!observation.ok) {
        const checkedAt = this.runtime.now();
        const marked = await this.markUnknown(
          transaction,
          checkedAt,
          attempts,
          observation.error.code,
        );
        if (!marked.ok) return marked;
      } else {
        const applied = await this.applyProviderObservation(
          transaction,
          observation.value,
          attempts,
        );
        if (!applied.ok) return applied;
      }
      processed += 1;
    }
    return ok(processed);
  }

  private semanticRequestHash(
    checkout: Checkout,
    expectedVersion: number,
    input: SubmitPaymentInput,
    contractEvidence: Omit<AcceptanceEvidence, 'acceptedAt'>,
  ): string {
    return this.runtime.semanticHash(
      JSON.stringify({
        operation: 'submit-payment-v2',
        checkoutId: checkout.checkoutId,
        expectedVersion,
        quoteId: input.quoteId,
        amountInCents: checkout.quote.total.amountInCents,
        currency: checkout.quote.total.currency,
        productId: checkout.productId,
        customerVersion: checkout.customer?.version,
        deliveryVersion: checkout.deliveryDetails?.version,
        installments: input.installments,
        acceptanceContracts: contractEvidence,
      }),
    );
  }

  private acceptanceContractEvidence(
    contracts: MerchantContractSet,
  ): Omit<AcceptanceEvidence, 'acceptedAt'> {
    const [terms, personalData] = contracts;
    return {
      termsVersion: terms.version,
      termsContractHash: this.runtime.semanticHash(
        JSON.stringify({
          type: terms.type,
          version: terms.version,
          permalink: terms.permalink,
        }),
      ),
      personalDataVersion: personalData.version,
      personalDataContractHash: this.runtime.semanticHash(
        JSON.stringify({
          type: personalData.type,
          version: personalData.version,
          permalink: personalData.permalink,
        }),
      ),
    };
  }

  private validateAcceptances(
    input: SubmitPaymentInput,
    contracts: MerchantContractSet,
    now: Date,
  ): Result<AcceptanceEvidence, CheckoutApplicationError> {
    const terms = this.runtime.verifyAcceptanceToken(
      input.acceptances.termsAcceptanceToken,
      'TERMS',
      now,
    );
    const personalData = this.runtime.verifyAcceptanceToken(
      input.acceptances.personalDataAcceptanceToken,
      'PERSONAL_DATA',
      now,
    );
    if (
      !terms.ok ||
      !personalData.ok ||
      terms.value.version !== contracts[0].version ||
      personalData.value.version !== contracts[1].version
    ) {
      return err({ code: 'FIELD_INVALID' });
    }
    return ok({
      ...this.acceptanceContractEvidence(contracts),
      acceptedAt: now.toISOString(),
    });
  }

  private validateDispatchableReplay(
    transaction: Transaction,
    input: SubmitPaymentInput,
    contracts: MerchantContractSet,
  ): Result<void, CheckoutApplicationError> {
    if (!this.replayCanDispatch(transaction)) return ok(undefined);
    const accepted = this.validateAcceptances(input, contracts, this.runtime.now());
    if (!accepted.ok) return err(accepted.error);
    return this.acceptanceContractsMatch(transaction, accepted.value)
      ? ok(undefined)
      : err({ code: 'IDEMPOTENCY_CONFLICT' });
  }

  private replayCanDispatch(transaction: Transaction): boolean {
    return (
      transaction.paymentStatus === 'PENDING' &&
      (transaction.dispatchPhase === 'NOT_SENT' || transaction.dispatchPhase === 'NOT_SENT_FAILED')
    );
  }

  private acceptanceContractsMatch(
    transaction: Transaction,
    evidence: AcceptanceEvidence,
  ): boolean {
    const stored = transaction.acceptanceEvidence;
    return (
      stored.termsVersion === evidence.termsVersion &&
      stored.termsContractHash === evidence.termsContractHash &&
      stored.personalDataVersion === evidence.personalDataVersion &&
      stored.personalDataContractHash === evidence.personalDataContractHash
    );
  }
  private async dispatchIfLeader(
    transaction: Transaction,
    input: SubmitPaymentInput,
    customerEmail: string,
  ): Promise<Result<void, CheckoutApplicationError>> {
    const claimedAt = this.runtime.now();
    const claim = await this.repository.claimDispatch(
      transaction.transactionId,
      claimedAt.toISOString(),
      new Date(claimedAt.getTime() + RECONCILIATION_LEASE_MS).toISOString(),
    );
    if (!claim.ok) return err({ code: 'INTERNAL_ERROR' });
    if (claim.value.kind === 'NOT_LEADER') {
      this.recordDeduplication();
      return ok(undefined);
    }

    this.observability.event('payment.dispatch_claimed', {
      fromState: transaction.dispatchPhase,
      toState: claim.value.transaction.dispatchPhase,
    });
    this.observability.increment('payment_attempts_total');
    const providerStartedAt = this.runtime.now().getTime();
    const outcome = await this.paymentProvider.createOnce({
      reference: transaction.providerReference,
      amountInCents: transaction.amountInCents,
      currency: 'COP',
      customerEmail,
      installments: input.installments,
      paymentMethodHandle: { kind: 'OPAQUE_TOKEN', value: input.paymentMethodToken },
      acceptances: input.acceptances,
    });
    this.observeDuration('payment_start_latency_ms', providerStartedAt);
    if (!outcome.ok) {
      return this.markUnknown(
        claim.value.transaction,
        this.runtime.now(),
        transaction.attempts,
        outcome.error.code,
      );
    }
    return this.applyCreateOutcome(claim.value.transaction, outcome.value);
  }

  private async applyCreateOutcome(
    transaction: Transaction,
    outcome: ProviderCreateOutcome,
  ): Promise<Result<void, CheckoutApplicationError>> {
    const checkedAt = this.runtime.now();
    if (outcome.kind === 'ACKNOWLEDGED') {
      return this.applyProviderObservation(
        transaction,
        {
          providerId: outcome.providerId,
          reference: outcome.reference,
          amountInCents: outcome.amountInCents,
          currency: outcome.currency,
          status: outcome.status,
        },
        transaction.attempts,
      );
    }
    if (outcome.kind === 'PROVEN_NOT_SENT') {
      return this.finalizeAndObserve(
        transaction,
        'ERROR',
        null,
        'PROVIDER_NOT_SENT',
        checkedAt.toISOString(),
      );
    }
    if (outcome.kind === 'DEFINITIVE_REJECTION') {
      return this.finalizeAndObserve(
        transaction,
        'ERROR',
        'ERROR',
        'PAYMENT_TOKEN_REJECTED',
        checkedAt.toISOString(),
      );
    }
    return this.markUnknown(transaction, checkedAt, transaction.attempts, outcome.kind);
  }

  private async applyProviderObservation(
    transaction: Transaction,
    observation: ProviderObservation,
    attempts: number,
  ): Promise<Result<void, CheckoutApplicationError>> {
    const checkedAt = this.runtime.now();
    const now = checkedAt.toISOString();
    if (
      observation.reference !== transaction.providerReference ||
      observation.amountInCents !== transaction.amountInCents ||
      observation.currency !== transaction.currency ||
      (transaction.providerId !== undefined && transaction.providerId !== observation.providerId) ||
      observation.status === 'UNKNOWN_EXTERNAL'
    ) {
      return this.markUnknown(transaction, checkedAt, attempts, 'PROVIDER_PROTOCOL_ERROR');
    }
    const check = this.reconciliationCheck(checkedAt, attempts);
    const acknowledged = await this.repository.acknowledgeProvider(
      transaction.transactionId,
      observation.providerId,
      observation.status,
      now,
      check,
    );
    if (!acknowledged.ok) {
      return this.markUnknown(transaction, checkedAt, attempts, 'STATE_TRANSITION_CONFLICT');
    }
    if (observation.status !== 'PENDING') {
      return this.finalizeAndObserve(
        acknowledged.value,
        observation.status,
        observation.status,
        undefined,
        now,
      );
    }
    if (attempts > 0) this.recordRetry(attempts);
    return ok(undefined);
  }

  private async markUnknown(
    transaction: Transaction,
    checkedAt: Date,
    attempts: number,
    errorCode: string,
  ): Promise<Result<void, CheckoutApplicationError>> {
    const marked = await this.repository.markUnknown(
      transaction.transactionId,
      checkedAt.toISOString(),
      this.reconciliationCheck(checkedAt, attempts),
    );
    if (!marked.ok) return err(this.mapRepositoryError(marked.error));
    this.observability.event('payment.outcome_unknown', {
      dispatchPhase: marked.value.dispatchPhase,
      errorCode,
      retryCount: attempts,
    });
    this.observability.increment('payment_unknown_total');
    this.recordRetry(attempts);
    this.recordExternalError(errorCode);
    return ok(undefined);
  }

  private async finalizeAndObserve(
    transaction: Transaction,
    status: Exclude<Transaction['paymentStatus'], 'PENDING'>,
    providerStatus: Transaction['providerStatus'],
    recoveryCode: Transaction['recoveryCode'],
    updatedAt: string,
  ): Promise<Result<void, CheckoutApplicationError>> {
    const duplicate = transaction.effectsApplied || transaction.paymentStatus !== 'PENDING';
    const finalized = await this.repository.finalize(
      transaction.transactionId,
      status,
      providerStatus,
      recoveryCode,
      updatedAt,
    );
    if (!finalized.ok) return err(this.mapRepositoryError(finalized.error));
    if (duplicate) {
      this.observability.increment('duplicate_finalizations_avoided_total');
      this.recordDeduplication();
      return ok(undefined);
    }
    this.observability.event('payment.finalized', {
      fromState: transaction.paymentStatus,
      toState: finalized.value.paymentStatus,
      dispatchPhase: finalized.value.dispatchPhase,
      providerStatus: finalized.value.providerStatus,
    });
    this.observability.increment('payment_finalized_total');
    switch (finalized.value.paymentStatus) {
      case 'APPROVED':
        this.observability.increment('payment_finalized_approved_total');
        break;
      case 'DECLINED':
        this.observability.increment('payment_finalized_declined_total');
        break;
      case 'VOIDED':
        this.observability.increment('payment_finalized_voided_total');
        break;
      case 'ERROR':
        this.observability.increment('payment_finalized_error_total');
        break;
    }
    if (finalized.value.reservationStatus === 'CONSUMED') {
      this.observability.event('reservation.committed', {
        fromState: 'ACTIVE',
        toState: 'CONSUMED',
      });
      this.observability.increment('reservations_committed_total');
    } else if (finalized.value.reservationStatus === 'RELEASED') {
      this.observability.event('reservation.released', {
        fromState: 'ACTIVE',
        toState: 'RELEASED',
      });
      this.observability.increment('reservations_released_total');
    }
    return ok(undefined);
  }

  private reconciliationCheck(checkedAt: Date, attempts: number): ReconciliationCheck {
    return {
      attempts,
      lastCheckedAt: checkedAt.toISOString(),
      nextCheckAt: this.nextCheckAt(checkedAt, attempts),
    };
  }

  private recordRetry(attempts: number): void {
    this.observability.event(
      attempts > this.backoffPolicy.delaysMs.length
        ? 'reconcile.exhausted'
        : 'reconcile.retry_scheduled',
      { retryCount: attempts },
    );
    this.observability.increment('reconciliation_retries_total');
  }

  private recordIdempotencyReplay(): void {
    this.observability.event('payment.idempotency_replayed');
    this.observability.increment('idempotency_replays_total');
  }
  private observeDuration(name: MetricName, startedAt: number): void {
    const durationMs = Math.max(0, this.runtime.now().getTime() - startedAt);
    this.observability.observe(name, durationMs);
  }

  private recordIdempotencyConflict(): void {
    this.observability.event('payment.idempotency_conflict');
    this.observability.increment('idempotency_conflicts_total');
  }

  private recordExternalError(errorCode: string): void {
    let categoryMetric: MetricName;
    switch (errorCode) {
      case 'PROVIDER_RATE_LIMITED':
        categoryMetric = 'provider_rate_limited_total';
        break;
      case 'PROVIDER_TIMEOUT':
        categoryMetric = 'provider_timeouts_total';
        break;
      case 'PROVIDER_UNAVAILABLE':
      case 'FAKE_SCRIPT_EXHAUSTED':
        categoryMetric = 'provider_unavailable_total';
        break;
      case 'PROVIDER_PROTOCOL_ERROR':
      case 'PROTOCOL_VIOLATION_AFTER_POSSIBLE_SEND':
        categoryMetric = 'provider_protocol_errors_total';
        break;
      case 'OUTCOME_UNKNOWN':
        categoryMetric = 'provider_unknown_outcomes_total';
        break;
      default:
        return;
    }
    this.observability.event('provider.external_error', { errorCode });
    this.observability.increment('provider_external_errors_total');
    this.observability.increment(categoryMetric);
  }

  private recordDeduplication(): void {
    this.observability.event('reconcile.deduplicated');
    this.observability.increment('deduplicated_operations_total');
  }

  private currentMerchantContracts(): Result<MerchantContractSet, CheckoutApplicationError> {
    const current = this.merchantContracts.getCurrentContracts();
    if (!current.ok) return err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' });
    const terms = current.value.find(
      (contract): contract is TermsMerchantContract => contract.type === 'TERMS',
    );
    const personalData = current.value.find(
      (contract): contract is PersonalDataMerchantContract => contract.type === 'PERSONAL_DATA',
    );
    if (
      current.value.length !== 2 ||
      terms === undefined ||
      personalData === undefined ||
      terms.version.trim().length === 0 ||
      personalData.version.trim().length === 0
    ) {
      return err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' });
    }
    try {
      const links = [new URL(terms.permalink), new URL(personalData.permalink)];
      if (links.some(({ protocol }) => protocol !== 'http:' && protocol !== 'https:')) {
        return err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' });
      }
    } catch {
      return err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' });
    }
    return ok([terms, personalData]);
  }

  private async authorize(
    checkoutId: string,
    rawCapability: string | null,
  ): Promise<Result<Checkout, CheckoutApplicationError>> {
    if (rawCapability === null || !rawCapability.startsWith(`${checkoutId}.`)) {
      return err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' });
    }
    const found = await this.repository.findCheckout(checkoutId);
    if (!found.ok || found.value === null) return err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' });
    const candidateHash = this.runtime.hashCapability(rawCapability);
    if (!this.runtime.hashesMatch(found.value.capabilityHash, candidateHash)) {
      return err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' });
    }
    if (
      found.value.activeTransactionId === undefined &&
      new Date(found.value.expiresAt).getTime() <= this.runtime.now().getTime()
    ) {
      return err({ code: 'CHECKOUT_EXPIRED' });
    }
    return ok(found.value);
  }

  private expectedVersion(ifMatch: string | undefined): Result<number, CheckoutApplicationError> {
    const match = ifMatch?.match(/^"checkout-v([1-9][0-9]*)"$/);
    const version = match?.[1] === undefined ? Number.NaN : Number(match[1]);
    return Number.isSafeInteger(version) ? ok(version) : err({ code: 'PRECONDITION_FAILED' });
  }

  private nextCheckAt(from: Date, attempts: number): string {
    const baseDelay =
      this.backoffPolicy.delaysMs[Math.max(attempts, 1) - 1] ?? this.backoffPolicy.recurringDelayMs;
    const jitterRatio = Math.min(Math.max(this.backoffPolicy.jitterRatio, 0), 1);
    const candidate = this.random();
    const boundedRandom = Number.isFinite(candidate) ? Math.min(Math.max(candidate, 0), 1) : 0.5;
    const jitteredDelay = Math.round(
      baseDelay * (1 - jitterRatio + boundedRandom * jitterRatio * 2),
    );
    return new Date(from.getTime() + jitteredDelay).toISOString();
  }

  private createQuote(product: ProductAvailability, now: Date): Quote {
    const subtotal = product.unitPrice.amountInCents;
    const total = subtotal + BASE_FEE_IN_CENTS + DELIVERY_FEE_IN_CENTS;
    if (!Number.isSafeInteger(total)) throw new Error('Money overflow');
    return {
      quoteId: this.runtime.newOpaqueId('quote'),
      version: 1,
      productId: product.productId,
      quantity: 1,
      subtotal: { amountInCents: subtotal, currency: 'COP' },
      baseFee: { amountInCents: BASE_FEE_IN_CENTS, currency: 'COP' },
      deliveryFee: { amountInCents: DELIVERY_FEE_IN_CENTS, currency: 'COP' },
      total: { amountInCents: total, currency: 'COP' },
      expiresAt: new Date(now.getTime() + this.quoteTtlSeconds * 1000).toISOString(),
    };
  }

  private mapRepositoryError(error: CheckoutRepositoryError): CheckoutApplicationError {
    const mapping: Record<CheckoutRepositoryError['code'], CheckoutApplicationError['code']> = {
      CHECKOUT_NOT_FOUND: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN',
      VERSION_MISMATCH: 'PRECONDITION_FAILED',
      IDEMPOTENCY_CONFLICT: 'IDEMPOTENCY_CONFLICT',
      PAYMENT_ALREADY_IN_PROGRESS: 'PAYMENT_ALREADY_IN_PROGRESS',
      OUT_OF_STOCK: 'OUT_OF_STOCK',
      FINAL_STATE_CONFLICT: 'STATE_TRANSITION_CONFLICT',
      APPROVED_INVENTORY_CONFLICT: 'STATE_TRANSITION_CONFLICT',
      REPOSITORY_UNAVAILABLE: 'INTERNAL_ERROR',
    };
    return { code: mapping[error.code] };
  }

  private mapRepositoryMutation<T>(
    result: Result<T, CheckoutRepositoryError>,
  ): Result<void, CheckoutApplicationError> {
    return result.ok ? ok(undefined) : err(this.mapRepositoryError(result.error));
  }

  private mapRepository<T>(
    result: Result<T, CheckoutRepositoryError>,
  ): Result<T, CheckoutApplicationError> {
    return result.ok ? result : err(this.mapRepositoryError(result.error));
  }
}

export const checkoutEtag = (checkout: Checkout): string => etagFor(checkout.version);
