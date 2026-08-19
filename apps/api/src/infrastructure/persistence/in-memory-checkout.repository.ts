import type { CatalogRepository } from '../../application/ports/catalog-repository';
import type {
  CheckoutRepository,
  CheckoutRepositoryError,
  PreparedPayment,
  ReconciliationCheck,
} from '../../application/ports/checkout-repository';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';
import {
  checkoutStatusForPayment,
  isTerminalPayment,
  type Checkout,
  type Customer,
  type Delivery,
  type DeliveryDetails,
  type PaymentStatus,
  type PaymentSubmission,
  type ProviderStatus,
  type Transaction,
} from '../../domain/checkout/checkout';

interface IdempotencyRecord {
  readonly checkoutId: string;
  readonly keyHash: string;
  readonly semanticHash: string;
  readonly transactionId: string;
  readonly submission: PaymentSubmission;
}

type DispatchClaim = Readonly<{ kind: 'CLAIMED' | 'NOT_LEADER'; transaction: Transaction }>;

const clone = <T>(value: T): T => structuredClone(value);

export class InMemoryCheckoutRepository implements CheckoutRepository {
  private readonly checkouts = new Map<string, Checkout>();
  private readonly transactions = new Map<string, Transaction>();
  private readonly deliveries = new Map<string, Delivery>();
  private readonly idempotency = new Map<string, IdempotencyRecord>();
  private readonly webhookEvents = new Set<string>();
  private mutationTail: Promise<void> = Promise.resolve();

  public constructor(private readonly catalog: CatalogRepository) {}

  public create(checkout: Checkout): Promise<Result<Checkout, CheckoutRepositoryError>> {
    return this.serialized<Result<Checkout, CheckoutRepositoryError>>(() => {
      if (this.checkouts.has(checkout.checkoutId)) {
        return Promise.resolve(err({ code: 'REPOSITORY_UNAVAILABLE' }));
      }
      this.checkouts.set(checkout.checkoutId, clone(checkout));
      return Promise.resolve(ok(clone(checkout)));
    });
  }

  public findCheckout(
    checkoutId: string,
  ): Promise<Result<Checkout | null, CheckoutRepositoryError>> {
    const checkout = this.checkouts.get(checkoutId);
    return Promise.resolve(ok(checkout === undefined ? null : clone(checkout)));
  }

  public replaceCustomer(
    checkoutId: string,
    capabilityHash: string,
    expectedVersion: number,
    customer: Omit<Customer, 'version'>,
  ): Promise<Result<Checkout, CheckoutRepositoryError>> {
    return this.serialized<Result<Checkout, CheckoutRepositoryError>>(() => {
      const checkout = this.authorized(checkoutId, capabilityHash);
      if (!checkout.ok) return Promise.resolve(checkout);
      if (checkout.value.version !== expectedVersion) {
        return Promise.resolve(err({ code: 'VERSION_MISMATCH' }));
      }
      if (checkout.value.activeTransactionId !== undefined) {
        return Promise.resolve(err({ code: 'PAYMENT_ALREADY_IN_PROGRESS' }));
      }
      const version = checkout.value.version + 1;
      const updated: Checkout = {
        ...checkout.value,
        version,
        status: checkout.value.deliveryDetails === undefined ? 'DRAFT' : 'READY',
        customer: { ...customer, version },
      };
      this.checkouts.set(checkoutId, updated);
      return Promise.resolve(ok(clone(updated)));
    });
  }

  public replaceDeliveryDetails(
    checkoutId: string,
    capabilityHash: string,
    expectedVersion: number,
    details: Omit<DeliveryDetails, 'version'>,
  ): Promise<Result<Checkout, CheckoutRepositoryError>> {
    return this.serialized<Result<Checkout, CheckoutRepositoryError>>(() => {
      const checkout = this.authorized(checkoutId, capabilityHash);
      if (!checkout.ok) return Promise.resolve(checkout);
      if (checkout.value.version !== expectedVersion) {
        return Promise.resolve(err({ code: 'VERSION_MISMATCH' }));
      }
      if (checkout.value.activeTransactionId !== undefined) {
        return Promise.resolve(err({ code: 'PAYMENT_ALREADY_IN_PROGRESS' }));
      }
      const version = checkout.value.version + 1;
      const updated: Checkout = {
        ...checkout.value,
        version,
        status: checkout.value.customer === undefined ? 'DRAFT' : 'READY',
        deliveryDetails: { ...details, version },
      };
      this.checkouts.set(checkoutId, updated);
      return Promise.resolve(ok(clone(updated)));
    });
  }

  public findIdempotency(
    input: Readonly<{ checkoutId: string; keyHash: string; semanticHash: string }>,
  ): Promise<Result<PreparedPayment | null, CheckoutRepositoryError>> {
    const recordKey = `${input.checkoutId}|${input.keyHash}`;
    const existing = this.idempotency.get(recordKey);
    if (existing === undefined) return Promise.resolve(ok(null));
    if (existing.semanticHash !== input.semanticHash) {
      return Promise.resolve(err({ code: 'IDEMPOTENCY_CONFLICT' }));
    }
    const transaction = this.transactions.get(existing.transactionId);
    const checkout = this.checkouts.get(input.checkoutId);
    if (transaction === undefined || checkout === undefined) {
      return Promise.resolve(err({ code: 'REPOSITORY_UNAVAILABLE' }));
    }
    return Promise.resolve(
      ok({
        kind: 'REPLAY',
        checkout: clone(checkout),
        transaction: clone(transaction),
        submission: clone(existing.submission),
      }),
    );
  }

  public preparePayment(
    input: Readonly<{
      checkoutId: string;
      capabilityHash: string;
      expectedVersion: number;
      keyHash: string;
      semanticHash: string;
      transaction: Transaction;
      submission: PaymentSubmission;
    }>,
  ): Promise<Result<PreparedPayment, CheckoutRepositoryError>> {
    return this.serialized<Result<PreparedPayment, CheckoutRepositoryError>>(async () => {
      const checkout = this.authorized(input.checkoutId, input.capabilityHash);
      if (!checkout.ok) return checkout;
      const recordKey = `${input.checkoutId}|${input.keyHash}`;
      const existing = this.idempotency.get(recordKey);
      if (existing !== undefined) {
        if (existing.semanticHash !== input.semanticHash) {
          return err({ code: 'IDEMPOTENCY_CONFLICT' });
        }
        const transaction = this.transactions.get(existing.transactionId);
        if (transaction === undefined) return err({ code: 'REPOSITORY_UNAVAILABLE' });
        return ok({
          kind: 'REPLAY',
          checkout: clone(checkout.value),
          transaction: clone(transaction),
          submission: clone(existing.submission),
        });
      }
      if (checkout.value.version !== input.expectedVersion) {
        return err({ code: 'VERSION_MISMATCH' });
      }
      if (checkout.value.activeTransactionId !== undefined) {
        return err({ code: 'PAYMENT_ALREADY_IN_PROGRESS' });
      }
      const reserved = await this.catalog.reserve(
        checkout.value.productId,
        1,
        input.transaction.acceptedAt,
      );
      if (!reserved.ok) {
        return err({
          code: reserved.error.code === 'OUT_OF_STOCK' ? 'OUT_OF_STOCK' : 'REPOSITORY_UNAVAILABLE',
        });
      }
      const updatedCheckout: Checkout = {
        ...checkout.value,
        status: 'PAYMENT_PENDING',
        version: checkout.value.version + 1,
        activeTransactionId: input.transaction.transactionId,
      };
      this.checkouts.set(input.checkoutId, updatedCheckout);
      this.transactions.set(input.transaction.transactionId, clone(input.transaction));
      this.idempotency.set(recordKey, {
        checkoutId: input.checkoutId,
        keyHash: input.keyHash,
        semanticHash: input.semanticHash,
        transactionId: input.transaction.transactionId,
        submission: clone(input.submission),
      });
      return ok({
        kind: 'CREATED',
        checkout: clone(updatedCheckout),
        transaction: clone(input.transaction),
        submission: clone(input.submission),
      });
    });
  }

  public claimDispatch(
    transactionId: string,
    updatedAt: string,
    leaseUntil: string,
  ): Promise<Result<DispatchClaim, CheckoutRepositoryError>> {
    return this.serialized<Result<DispatchClaim, CheckoutRepositoryError>>(() => {
      const transaction = this.transactions.get(transactionId);
      if (transaction === undefined) return Promise.resolve(err({ code: 'CHECKOUT_NOT_FOUND' }));
      if (transaction.dispatchPhase !== 'NOT_SENT') {
        return Promise.resolve(ok({ kind: 'NOT_LEADER', transaction: clone(transaction) }));
      }
      const sending: Transaction = {
        ...transaction,
        dispatchPhase: 'SENDING',
        nextCheckAt: leaseUntil,
        updatedAt,
      };
      this.transactions.set(transactionId, sending);
      return Promise.resolve(ok({ kind: 'CLAIMED', transaction: clone(sending) }));
    });
  }

  public acknowledgeProvider(
    transactionId: string,
    providerId: string,
    providerStatus: Exclude<ProviderStatus, null>,
    updatedAt: string,
    check: ReconciliationCheck,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    return this.serialized<Result<Transaction, CheckoutRepositoryError>>(() => {
      const transaction = this.transactions.get(transactionId);
      if (transaction === undefined) return Promise.resolve(err({ code: 'CHECKOUT_NOT_FOUND' }));
      const providerConflict = [...this.transactions.values()].some(
        (candidate) =>
          candidate.transactionId !== transactionId && candidate.providerId === providerId,
      );
      if (
        providerConflict ||
        (transaction.providerId !== undefined && transaction.providerId !== providerId) ||
        (isTerminalPayment(transaction.paymentStatus) && transaction.providerId === undefined)
      ) {
        return Promise.resolve(err({ code: 'FINAL_STATE_CONFLICT' }));
      }
      if (isTerminalPayment(transaction.paymentStatus)) {
        return Promise.resolve(ok(clone(transaction)));
      }
      return Promise.resolve(
        this.storeTransaction({
          ...transaction,
          providerId,
          providerStatus,
          dispatchPhase: 'ACKNOWLEDGED',
          ...(providerStatus === 'PENDING' ? { nextCheckAt: check.nextCheckAt } : {}),
          attempts: check.attempts,
          lastCheckedAt: check.lastCheckedAt,
          updatedAt,
        }),
      );
    });
  }

  public markUnknown(
    transactionId: string,
    updatedAt: string,
    check: ReconciliationCheck,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    return this.serialized<Result<Transaction, CheckoutRepositoryError>>(() => {
      const transaction = this.transactions.get(transactionId);
      if (transaction === undefined) return Promise.resolve(err({ code: 'CHECKOUT_NOT_FOUND' }));
      if (isTerminalPayment(transaction.paymentStatus))
        return Promise.resolve(ok(clone(transaction)));
      return Promise.resolve(
        this.storeTransaction({
          ...transaction,
          dispatchPhase: 'UNKNOWN',
          recoveryCode: 'PROVIDER_OUTCOME_UNKNOWN',
          attempts: check.attempts,
          lastCheckedAt: check.lastCheckedAt,
          nextCheckAt: check.nextCheckAt,
          updatedAt,
        }),
      );
    });
  }

  public finalize(
    transactionId: string,
    status: Exclude<PaymentStatus, 'PENDING'>,
    providerStatus: ProviderStatus,
    recoveryCode: Transaction['recoveryCode'],
    updatedAt: string,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    return this.serialized<Result<Transaction, CheckoutRepositoryError>>(async () => {
      const transaction = this.transactions.get(transactionId);
      if (transaction === undefined) return err({ code: 'CHECKOUT_NOT_FOUND' });
      if (isTerminalPayment(transaction.paymentStatus)) {
        if (transaction.paymentStatus === status) return ok(clone(transaction));
        return this.storeTransaction({
          ...transaction,
          integrityStatus: 'FINAL_STATE_CONFLICT',
          updatedAt,
        });
      }
      if (
        recoveryCode === 'PROVIDER_NOT_SENT' &&
        (status !== 'ERROR' ||
          providerStatus !== null ||
          transaction.providerId !== undefined ||
          (transaction.dispatchPhase !== 'SENDING' &&
            transaction.dispatchPhase !== 'NOT_SENT_FAILED'))
      ) {
        return err({ code: 'FINAL_STATE_CONFLICT' });
      }
      if (
        recoveryCode === undefined &&
        (providerStatus === null ||
          providerStatus !== status ||
          transaction.providerStatus !== providerStatus ||
          transaction.providerId === undefined ||
          transaction.dispatchPhase !== 'ACKNOWLEDGED')
      ) {
        return err({ code: 'FINAL_STATE_CONFLICT' });
      }
      const checkout = this.checkouts.get(transaction.checkoutId);
      if (checkout === undefined) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      if (status === 'APPROVED') {
        if (transaction.reservationStatus !== 'ACTIVE') {
          return this.approvedInventoryConflict(transaction, checkout, providerStatus, updatedAt);
        }
        const details = checkout.deliveryDetails;
        if (details === undefined) return err({ code: 'REPOSITORY_UNAVAILABLE' });
        const consumed = await this.catalog.consume(checkout.productId, 1, updatedAt);
        if (!consumed.ok) {
          return this.approvedInventoryConflict(transaction, checkout, providerStatus, updatedAt);
        }
        const deliveryId = `delivery_${transaction.transactionId}`;
        const { checkoutId: ignoredCheckout, version: ignoredVersion, ...destination } = details;
        void ignoredCheckout;
        void ignoredVersion;
        if (!this.deliveries.has(deliveryId)) {
          this.deliveries.set(deliveryId, {
            deliveryId,
            checkoutId: checkout.checkoutId,
            transactionId,
            status: 'CREATED',
            destination,
            createdAt: updatedAt,
            updatedAt,
          });
        }
        const finalized: Transaction = {
          ...transaction,
          paymentStatus: 'APPROVED',
          providerStatus,
          dispatchPhase: 'ACKNOWLEDGED',
          reservationStatus: 'CONSUMED',
          integrityStatus: 'OK',
          deliveryId,
          effectsApplied: true,
          updatedAt,
        };
        this.transactions.set(transactionId, finalized);
        this.checkouts.set(checkout.checkoutId, { ...checkout, status: 'PAID' });
        return ok(clone(finalized));
      }
      if (transaction.reservationStatus === 'ACTIVE') {
        const released = await this.catalog.release(checkout.productId, 1, updatedAt);
        if (!released.ok) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      }
      const finalized: Transaction = {
        ...transaction,
        paymentStatus: status,
        providerStatus,
        dispatchPhase: recoveryCode === 'PROVIDER_NOT_SENT' ? 'NOT_SENT_FAILED' : 'ACKNOWLEDGED',
        reservationStatus: 'RELEASED',
        integrityStatus: 'OK',
        ...(recoveryCode === undefined ? {} : { recoveryCode }),
        effectsApplied: true,
        updatedAt,
      };
      this.transactions.set(transactionId, finalized);
      this.checkouts.set(checkout.checkoutId, {
        ...checkout,
        status: checkoutStatusForPayment(status),
      });
      return ok(clone(finalized));
    });
  }

  public findTransaction(
    transactionId: string,
  ): Promise<Result<Transaction | null, CheckoutRepositoryError>> {
    const transaction = this.transactions.get(transactionId);
    return Promise.resolve(ok(transaction === undefined ? null : clone(transaction)));
  }

  public findTransactionByProviderId(
    providerId: string,
  ): Promise<Result<Transaction | null, CheckoutRepositoryError>> {
    // ponytail: bounded in-memory scan; Dynamo uses the approved unique lock lookup.
    const transaction = [...this.transactions.values()].find(
      (candidate) => candidate.providerId === providerId,
    );
    return Promise.resolve(ok(transaction === undefined ? null : clone(transaction)));
  }

  public recordWebhook(
    eventHash: string,
  ): Promise<Result<'NEW' | 'DUPLICATE', CheckoutRepositoryError>> {
    return this.serialized<Result<'NEW' | 'DUPLICATE', CheckoutRepositoryError>>(() => {
      if (this.webhookEvents.has(eventHash)) return Promise.resolve(ok('DUPLICATE'));
      this.webhookEvents.add(eventHash);
      return Promise.resolve(ok('NEW'));
    });
  }

  public findOldestPendingAcceptedAt(): Promise<Result<string | null, CheckoutRepositoryError>> {
    let oldest: string | null = null;
    for (const transaction of this.transactions.values()) {
      if (transaction.paymentStatus !== 'PENDING') continue;
      if (!Number.isFinite(Date.parse(transaction.acceptedAt))) {
        return Promise.resolve(err({ code: 'REPOSITORY_UNAVAILABLE' }));
      }
      if (oldest === null || transaction.acceptedAt < oldest) oldest = transaction.acceptedAt;
    }
    return Promise.resolve(ok(oldest));
  }

  public claimDue(
    now: string,
    leaseUntil: string,
    limit: number,
  ): Promise<Result<readonly Transaction[], CheckoutRepositoryError>> {
    return this.serialized<Result<readonly Transaction[], CheckoutRepositoryError>>(() => {
      const due = [...this.transactions.values()]
        .filter(
          (transaction) =>
            transaction.paymentStatus === 'PENDING' &&
            (transaction.dispatchPhase === 'NOT_SENT' ||
              transaction.dispatchPhase === 'NOT_SENT_FAILED' ||
              transaction.dispatchPhase === 'SENDING' ||
              transaction.dispatchPhase === 'ACKNOWLEDGED' ||
              transaction.dispatchPhase === 'UNKNOWN') &&
            transaction.nextCheckAt !== undefined &&
            transaction.nextCheckAt <= now,
        )
        .slice(0, Math.min(Math.max(limit, 1), 100));
      const claimed = due.map((transaction) => {
        const updated: Transaction = {
          ...transaction,
          ...(transaction.dispatchPhase === 'NOT_SENT' ? { dispatchPhase: 'NOT_SENT_FAILED' } : {}),
          nextCheckAt: leaseUntil,
        };
        this.transactions.set(transaction.transactionId, updated);
        return updated;
      });
      return Promise.resolve(ok(clone(claimed)));
    });
  }

  public findDelivery(
    deliveryId: string,
  ): Promise<Result<Delivery | null, CheckoutRepositoryError>> {
    const delivery = this.deliveries.get(deliveryId);
    return Promise.resolve(ok(delivery === undefined ? null : clone(delivery)));
  }

  private authorized(
    checkoutId: string,
    capabilityHash: string,
  ): Result<Checkout, CheckoutRepositoryError> {
    const checkout = this.checkouts.get(checkoutId);
    return checkout !== undefined && checkout.capabilityHash === capabilityHash
      ? ok(checkout)
      : err({ code: 'CHECKOUT_NOT_FOUND' });
  }

  private storeTransaction(transaction: Transaction): Result<Transaction, CheckoutRepositoryError> {
    this.transactions.set(transaction.transactionId, transaction);
    return ok(clone(transaction));
  }

  private approvedInventoryConflict(
    transaction: Transaction,
    checkout: Checkout,
    providerStatus: ProviderStatus,
    updatedAt: string,
  ): Result<Transaction, CheckoutRepositoryError> {
    const conflicted: Transaction = {
      ...transaction,
      paymentStatus: 'APPROVED',
      providerStatus,
      dispatchPhase: 'ACKNOWLEDGED',
      integrityStatus: 'APPROVED_INVENTORY_CONFLICT',
      recoveryCode: 'STATE_TRANSITION_CONFLICT',
      updatedAt,
    };
    this.transactions.set(transaction.transactionId, conflicted);
    this.checkouts.set(checkout.checkoutId, { ...checkout, status: 'PAID' });
    return ok(clone(conflicted));
  }

  private serialized<T>(action: () => Promise<T>): Promise<T> {
    // ponytail: one process-wide queue is correct for the demo; replace with DynamoDB conditions at scale.
    const result = this.mutationTail.then(action, action);
    this.mutationTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}
