import type { CatalogRepository } from '../ports/catalog-repository';
import type { CheckoutRepository } from '../ports/checkout-repository';
import type { MerchantContractPort, MerchantContractSet } from '../ports/merchant-contract';
import type {
  PaymentProvider,
  ProviderCreateOutcome,
  ProviderError,
  ProviderObservation,
} from '../ports/payment-provider';
import type { Result } from '../result/result';
import { err, ok } from '../result/result';
import type { Checkout, Transaction } from '../../domain/checkout/checkout';
import { FakeMerchantContractAdapter } from '../../infrastructure/payment/fake-merchant-contract.adapter';
import { FakeObservability } from '../../infrastructure/observability/observability.adapter';
import {
  E5ScriptedPaymentProvider,
  type E5PaymentScenario,
} from '../../infrastructure/payment/e5-scripted-payment-provider';
import { InMemoryCatalogRepository } from '../../infrastructure/persistence/in-memory-catalog.repository';
import { InMemoryCheckoutRepository } from '../../infrastructure/persistence/in-memory-checkout.repository';
import { createProductSeed } from '../../infrastructure/persistence/product-seed';
import { SystemRuntimeSecurity } from '../../infrastructure/security/system-runtime-security';
import {
  CheckoutService,
  LOCAL_FAKE_RECONCILIATION_BACKOFF_POLICY,
  PRODUCTION_RECONCILIATION_BACKOFF_POLICY,
  type PaymentConfiguration,
  type ReconciliationBackoffPolicy,
  type SubmitPaymentInput,
} from './checkout-service';

const PRODUCT_ID = 'product-demo-001';
const IDEMPOTENCY_KEY = 'idem-key-00000001';

const valueOf = <T, E>(result: Result<T, E>): T => {
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result.value;
};

class MutableCatalog implements CatalogRepository {
  public priceDelta = 0;

  public constructor(private readonly inner: InMemoryCatalogRepository) {}

  public async findById(productId: string) {
    const found = await this.inner.findById(productId);
    if (!found.ok || found.value === null || this.priceDelta === 0) return found;
    return ok({
      ...found.value,
      unitPrice: {
        ...found.value.unitPrice,
        amountInCents: found.value.unitPrice.amountInCents + this.priceDelta,
      },
    });
  }

  public async listActive(limit: number) {
    return this.inner.listActive(limit);
  }

  public async seedIfAbsent(product: Parameters<CatalogRepository['seedIfAbsent']>[0]) {
    return this.inner.seedIfAbsent(product);
  }

  public async reserve(productId: string, quantity: 1, updatedAt: string) {
    return this.inner.reserve(productId, quantity, updatedAt);
  }

  public async consume(productId: string, quantity: 1, updatedAt: string) {
    return this.inner.consume(productId, quantity, updatedAt);
  }

  public async release(productId: string, quantity: 1, updatedAt: string) {
    return this.inner.release(productId, quantity, updatedAt);
  }

  public isReady(): Promise<boolean> {
    return this.inner.isReady();
  }
}

class StaticOutcomeProvider implements PaymentProvider {
  public createCalls = 0;

  public constructor(
    private readonly outcome: ProviderCreateOutcome,
    private readonly configurationEnabled = true,
  ) {}

  public getPublicConfiguration() {
    return this.configurationEnabled
      ? ok({
          mode: 'fake' as const,
          captureVariant: 'FAKE_CONTRACT' as const,
          publicKey: 'FAKE_CONTRACT_NO_CARD_DATA',
          installments: [1, 2, 3] as const,
        })
      : err({ code: 'ENVIRONMENT_DISABLED' as const });
  }

  public createOnce(): Promise<Result<ProviderCreateOutcome, ProviderError>> {
    this.createCalls += 1;
    return Promise.resolve(ok(this.outcome));
  }

  public getById(): Promise<Result<ProviderObservation, ProviderError>> {
    return Promise.resolve(err({ code: 'FAKE_SCRIPT_EXHAUSTED' }));
  }
  public getByReference(): Promise<Result<ProviderObservation, ProviderError>> {
    return this.getById();
  }

  public verifyAndNormalizeEvent(eventName: string) {
    return ok({ eventName });
  }
}
class TransportErrorProvider extends StaticOutcomeProvider {
  public constructor() {
    super({ kind: 'OUTCOME_UNKNOWN' });
  }

  public override createOnce(): Promise<Result<ProviderCreateOutcome, ProviderError>> {
    this.createCalls += 1;
    return Promise.resolve(err({ code: 'PROVIDER_UNAVAILABLE' }));
  }
}

interface Harness {
  readonly catalog: MutableCatalog;
  readonly innerCatalog: InMemoryCatalogRepository;
  readonly repository: InMemoryCheckoutRepository;
  readonly runtime: SystemRuntimeSecurity;
  readonly provider: PaymentProvider;
  readonly merchantContracts: MerchantContractPort;
  readonly observability: FakeObservability;
  readonly service: CheckoutService;
  readonly advance: (milliseconds: number) => void;
}

const harness = (
  options: Readonly<{
    scenario?: E5PaymentScenario;
    stock?: number;
    active?: boolean;
    quoteTtlSeconds?: number;
    checkoutTtlSeconds?: number;
    provider?: PaymentProvider;
    merchantContracts?: MerchantContractPort;
    observability?: FakeObservability;
    random?: () => number;
    backoffPolicy?: ReconciliationBackoffPolicy;
  }> = {},
): Harness => {
  let milliseconds = Date.parse('2026-08-15T12:00:00.000Z');
  const seed = {
    ...createProductSeed(PRODUCT_ID, 'http://localhost:5173', options.stock ?? 3),
    active: options.active ?? true,
  };
  const innerCatalog = new InMemoryCatalogRepository([seed]);
  const catalog = new MutableCatalog(innerCatalog);
  const repository = new InMemoryCheckoutRepository(catalog);
  const runtime = new SystemRuntimeSecurity(() => new Date(milliseconds));
  const provider =
    options.provider ??
    new E5ScriptedPaymentProvider(options.scenario ?? 'FAKE-E5-01', {
      now: () => milliseconds,
    });
  const merchantContracts =
    options.merchantContracts ?? new FakeMerchantContractAdapter('http://localhost:5173');
  const observability = options.observability ?? new FakeObservability();
  const service = new CheckoutService(
    catalog,
    repository,
    provider,
    runtime,
    merchantContracts,
    options.quoteTtlSeconds ?? 900,
    options.checkoutTtlSeconds ?? 1800,
    observability,
    options.random ?? (() => 0.5),
    options.backoffPolicy ?? PRODUCTION_RECONCILIATION_BACKOFF_POLICY,
  );
  return {
    catalog,
    innerCatalog,
    repository,
    runtime,
    provider,
    merchantContracts,
    service,
    observability,
    advance: (delta) => {
      milliseconds += delta;
    },
  };
};

interface ReadyCheckout {
  readonly checkout: Checkout;
  readonly capability: string;
  readonly input: SubmitPaymentInput;
}

const readyCheckout = async (service: CheckoutService): Promise<ReadyCheckout> => {
  const created = valueOf(await service.createCheckout(PRODUCT_ID));
  const customer = valueOf(
    await service.replaceCustomer(
      created.checkout.checkoutId,
      created.rawCapability,
      '"checkout-v1"',
      { fullName: 'Ada Lovelace', email: 'ada@example.invalid', phone: '+573001234567' },
    ),
  );
  const checkout = valueOf(
    await service.replaceDeliveryDetails(
      created.checkout.checkoutId,
      created.rawCapability,
      `"checkout-v${customer.version}"`,
      {
        addressLine1: 'Calle 100 # 10-20',
        city: 'Bogota',
        region: 'Cundinamarca',
        postalCode: '110111',
      },
    ),
  );
  const configuration: PaymentConfiguration = valueOf(service.getPaymentConfiguration());
  return {
    checkout,
    capability: created.rawCapability,
    input: {
      quoteId: checkout.quote.quoteId,
      paymentMethodToken: 'tok_synthetic_001',
      installments: 1,
      acceptances: {
        termsAcceptanceToken: configuration.acceptanceContracts[0].acceptanceToken,
        personalDataAcceptanceToken: configuration.acceptanceContracts[1].acceptanceToken,
      },
    },
  };
};

const submit = (
  service: CheckoutService,
  ready: ReadyCheckout,
  input: SubmitPaymentInput = ready.input,
  key = IDEMPOTENCY_KEY,
) =>
  service.submitPayment(
    ready.checkout.checkoutId,
    ready.capability,
    `"checkout-v${ready.checkout.version}"`,
    key,
    input,
  );

describe('CheckoutService vertical payment flow', () => {
  it('uses the merchant contract port and fails closed unless both local v1 contracts exist', () => {
    const configuration = valueOf(harness().service.getPaymentConfiguration());
    expect(
      configuration.acceptanceContracts.map(({ acceptanceToken: ignoredToken, ...contract }) => {
        void ignoredToken;
        return contract;
      }),
    ).toEqual([
      {
        type: 'TERMS',
        permalink: 'http://localhost:5173/legal/terms-v1.html',
        version: 'terms-v1',
      },
      {
        type: 'PERSONAL_DATA',
        permalink: 'http://localhost:5173/legal/personal-data-v1.html',
        version: 'personal-data-v1',
      },
    ]);

    const incomplete = new FakeMerchantContractAdapter('http://localhost:5173', [
      {
        type: 'TERMS',
        permalink: 'http://localhost:5173/legal/terms-v1.html',
        version: 'terms-v1',
      },
    ]);
    expect(harness({ merchantContracts: incomplete }).service.getPaymentConfiguration()).toEqual(
      err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' }),
    );
  });

  it('completes APPROVED, consumes the reservation, and creates one delivery', async () => {
    const context = harness({ scenario: 'FAKE-E5-01' });
    const ready = await readyCheckout(context.service);
    expect(ready.checkout.status).toBe('READY');
    const submission = valueOf(await submit(context.service, ready));
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(1);

    const pending = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    );
    expect(pending.transaction).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'ACKNOWLEDGED',
      providerStatus: 'PENDING',
      reservationStatus: 'ACTIVE',
    });
    expect(pending.transaction.acceptanceEvidence).toEqual({
      termsVersion: 'terms-v1',
      termsContractHash: expect.stringMatching(/^[A-Za-z0-9_-]{32,}$/u),
      personalDataVersion: 'personal-data-v1',
      personalDataContractHash: expect.stringMatching(/^[A-Za-z0-9_-]{32,}$/u),
      acceptedAt: submission.acceptedAt,
    });
    const persisted = JSON.stringify(pending.transaction);
    expect(persisted).not.toContain(ready.input.acceptances.termsAcceptanceToken);
    expect(persisted).not.toContain(ready.input.acceptances.personalDataAcceptanceToken);

    expect(valueOf(await context.innerCatalog.findById(PRODUCT_ID))).toMatchObject({
      onHand: 3,
      reserved: 1,
      available: 2,
    });

    context.advance(60_000);
    expect(valueOf(await context.service.reconcileDue())).toBe(1);
    expect(context.observability.values('oldest_pending_age_seconds')).toEqual([60]);
    const approved = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    );
    expect(approved.transaction).toMatchObject({
      paymentStatus: 'APPROVED',
      reservationStatus: 'CONSUMED',
      integrityStatus: 'OK',
      effectsApplied: true,
    });
    expect(approved.allowedActions).not.toContain('START_NEW_CHECKOUT');
    expect(valueOf(await context.innerCatalog.findById(PRODUCT_ID))).toMatchObject({
      onHand: 2,
      reserved: 0,
      available: 2,
    });
    const deliveryId = approved.transaction.deliveryId as string;
    const delivery = valueOf(await context.service.getDelivery(deliveryId, ready.capability));
    expect(delivery).toMatchObject({ transactionId: submission.transactionId, status: 'CREATED' });
    expect(valueOf(await context.service.reconcileDue())).toBe(0);
    expect(context.observability.values('oldest_pending_age_seconds')).toEqual([60, 0]);
    const repeated = valueOf(
      await context.repository.finalize(
        submission.transactionId,
        'APPROVED',
        'APPROVED',
        undefined,
        context.runtime.now().toISOString(),
      ),
    );
    expect(repeated.deliveryId).toBe(deliveryId);
    expect(
      valueOf(await context.service.getCheckout(ready.checkout.checkoutId, ready.capability))
        .checkout.status,
    ).toBe('PAID');
  });

  it.each([
    ['FAKE-E5-02', 'DECLINED'],
    ['FAKE-E5-03', 'ERROR'],
  ] as const)(
    'releases inventory for %s -> %s and requires a new checkout',
    async (scenario, status) => {
      const context = harness({ scenario });
      const ready = await readyCheckout(context.service);
      const submission = valueOf(await submit(context.service, ready));
      context.advance(60_000);
      valueOf(await context.service.reconcileDue());
      const failed = valueOf(
        await context.service.getTransaction(submission.transactionId, ready.capability),
      );
      expect(failed.transaction).toMatchObject({
        paymentStatus: status,
        reservationStatus: 'RELEASED',
      });
      const finalMetric =
        status === 'DECLINED'
          ? 'payment_finalized_declined_total'
          : 'payment_finalized_error_total';
      expect(context.observability.count(finalMetric)).toBe(1);
      expect(context.observability.count('reservations_released_total')).toBe(1);
      expect(context.observability.events.map(({ name }) => name)).toContain(
        'reservation.released',
      );

      expect(failed.transaction.deliveryId).toBeUndefined();
      expect(valueOf(await context.innerCatalog.findById(PRODUCT_ID))).toMatchObject({
        onHand: 3,
        reserved: 0,
        available: 3,
      });
      expect(await context.service.getDelivery('delivery_missing', ready.capability)).toEqual(
        err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }),
      );
      expect(
        await context.service.submitPayment(
          ready.checkout.checkoutId,
          ready.capability,
          '"checkout-v4"',
          'different-key-00001',
          ready.input,
        ),
      ).toEqual(err({ code: 'PAYMENT_ALREADY_IN_PROGRESS' }));
    },
  );

  it('uses claim/lease so two workers query a sustained PENDING only once', async () => {
    const context = harness({ scenario: 'FAKE-E5-04' });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    expect(valueOf(await context.service.reconcileDue())).toBe(0);
    context.advance(60_000);
    const results = await Promise.all([
      context.service.reconcileDue(),
      context.service.reconcileDue(),
    ]);
    expect(results.map(valueOf).reduce((sum, value) => sum + value, 0)).toBe(1);
    const transaction = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(transaction).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'ACKNOWLEDGED',
      providerStatus: 'PENDING',
      reservationStatus: 'ACTIVE',
    });
    expect(valueOf(await context.service.reconcileDue())).toBe(0);
  });

  it('persists deterministic 1/2/5/10/15 minute then hourly reconciliation backoff', async () => {
    const context = harness({ scenario: 'FAKE-E5-04', random: () => 0.5 });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    const initial = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(initial).toMatchObject({
      attempts: 0,
      lastCheckedAt: submission.acceptedAt,
    });
    expect(Date.parse(initial.nextCheckAt ?? '') - Date.parse(submission.acceptedAt)).toBe(60_000);

    const delays = [60_000, 120_000, 300_000, 600_000, 900_000, 3_600_000, 3_600_000];
    let advanceToDue = 60_000;
    for (const [index, expectedDelay] of delays.entries()) {
      context.advance(advanceToDue);
      const checkedAt = context.runtime.now().toISOString();
      expect(valueOf(await context.service.reconcileDue())).toBe(1);
      const transaction = valueOf(
        await context.service.getTransaction(submission.transactionId, ready.capability),
      ).transaction;
      expect(transaction).toMatchObject({
        attempts: index + 1,
        lastCheckedAt: checkedAt,
        paymentStatus: 'PENDING',
        reservationStatus: 'ACTIVE',
      });
      expect(Date.parse(transaction.nextCheckAt ?? '') - Date.parse(checkedAt)).toBe(expectedDelay);
      advanceToDue = expectedDelay;
    }
  });
  it('uses the deterministic 250ms local fake schedule without changing production backoff', async () => {
    expect(PRODUCTION_RECONCILIATION_BACKOFF_POLICY).toEqual({
      delaysMs: [60_000, 120_000, 300_000, 600_000, 900_000],
      recurringDelayMs: 3_600_000,
      jitterRatio: 0.2,
    });
    const context = harness({
      scenario: 'FAKE-E5-01',
      random: () => 0,
      backoffPolicy: LOCAL_FAKE_RECONCILIATION_BACKOFF_POLICY,
    });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    const pending = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(Date.parse(pending.nextCheckAt ?? '') - Date.parse(submission.acceptedAt)).toBe(250);

    context.advance(249);
    expect(valueOf(await context.service.reconcileDue())).toBe(0);
    context.advance(1);
    expect(valueOf(await context.service.reconcileDue())).toBe(1);
    expect(
      valueOf(await context.service.getTransaction(submission.transactionId, ready.capability))
        .transaction.paymentStatus,
    ).toBe('APPROVED');
  });

  it.each([
    [0, 48_000],
    [1, 72_000],
  ] as const)(
    'applies deterministic bounded jitter for random=%s',
    async (random, expectedDelay) => {
      const context = harness({ scenario: 'FAKE-E5-04', random: () => random });
      const ready = await readyCheckout(context.service);
      const submission = valueOf(await submit(context.service, ready));
      const transaction = valueOf(
        await context.service.getTransaction(submission.transactionId, ready.capability),
      ).transaction;
      expect(Date.parse(transaction.nextCheckAt ?? '') - Date.parse(submission.acceptedAt)).toBe(
        expectedDelay,
      );
    },
  );

  it('claims batches of ten for 45 seconds while two workers perform at most two provider GETs', async () => {
    const context = harness({ scenario: 'FAKE-E5-04', stock: 10 });
    const ready: ReadyCheckout[] = [];
    const transactionIds: string[] = [];
    for (let index = 0; index < 10; index += 1) {
      const candidate = await readyCheckout(context.service);
      ready.push(candidate);
      const submission = valueOf(
        await submit(
          context.service,
          candidate,
          candidate.input,
          `idem-key-batch-${String(index).padStart(4, '0')}`,
        ),
      );
      transactionIds.push(submission.transactionId);
    }
    const claimDue = jest.spyOn(context.repository, 'claimDue');

    context.advance(60_000);
    const results = await Promise.all([
      context.service.reconcileDue(),
      context.service.reconcileDue(),
    ]);

    expect(results.map(valueOf).reduce((sum, value) => sum + value, 0)).toBe(2);
    expect(claimDue).toHaveBeenCalledWith(
      '2026-08-15T12:01:00.000Z',
      '2026-08-15T12:01:45.000Z',
      10,
    );
    expect((context.provider as E5ScriptedPaymentProvider).readCalls).toBe(2);

    const transactions: Transaction[] = [];
    for (const [index, transactionId] of transactionIds.entries()) {
      const candidate = ready[index];
      if (candidate === undefined) throw new Error('Missing ready checkout fixture');
      transactions.push(
        valueOf(await context.service.getTransaction(transactionId, candidate.capability))
          .transaction,
      );
    }
    expect(transactions.filter(({ attempts }) => attempts === 1)).toHaveLength(2);
    expect(transactions.filter(({ attempts }) => attempts === 0)).toHaveLength(8);
    expect(transactions.every(({ attempts }) => attempts <= 1)).toBe(true);
  });

  it('keeps the last PENDING provider status when a query becomes unknown', async () => {
    const context = harness({ scenario: 'FAKE-E5-06' });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    context.advance(60_000);
    const results = await Promise.all([
      context.service.reconcileDue(),
      context.service.reconcileDue(),
    ]);
    expect(results.map(valueOf).reduce((sum, value) => sum + value, 0)).toBe(1);
    expect(
      valueOf(await context.service.getTransaction(submission.transactionId, ready.capability))
        .transaction,
    ).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      providerStatus: 'PENDING',
      reservationStatus: 'ACTIVE',
    });
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(1);
  });

  it('keeps 429 and 5xx provider reads PENDING/UNKNOWN with the reservation intact', async () => {
    const provider = new E5ScriptedPaymentProvider('FAKE-E5-04');
    const getById = jest
      .spyOn(provider, 'getById')
      .mockResolvedValueOnce(err<ProviderError>({ code: 'PROVIDER_RATE_LIMITED' }))
      .mockResolvedValueOnce(err<ProviderError>({ code: 'PROVIDER_UNAVAILABLE' }));
    const context = harness({ provider, random: () => 0.5 });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));

    context.advance(60_000);
    expect(valueOf(await context.service.reconcileDue())).toBe(1);
    expect(
      valueOf(await context.service.getTransaction(submission.transactionId, ready.capability))
        .transaction,
    ).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      providerStatus: 'PENDING',
      reservationStatus: 'ACTIVE',
      effectsApplied: false,
      attempts: 1,
      lastCheckedAt: '2026-08-15T12:01:00.000Z',
      nextCheckAt: '2026-08-15T12:02:00.000Z',
    });

    context.advance(60_000);
    expect(valueOf(await context.service.reconcileDue())).toBe(1);
    const pending = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(pending).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      providerStatus: 'PENDING',
      reservationStatus: 'ACTIVE',
      effectsApplied: false,
      attempts: 2,
      lastCheckedAt: '2026-08-15T12:02:00.000Z',
      nextCheckAt: '2026-08-15T12:04:00.000Z',
    });
    expect(pending.deliveryId).toBeUndefined();
    expect(getById).toHaveBeenCalledTimes(2);
    expect(context.observability.count('payment_unknown_total')).toBe(2);
    expect(context.observability.count('reconciliation_retries_total')).toBe(2);
    expect(context.observability.count('provider_external_errors_total')).toBe(2);
    expect(context.observability.count('provider_rate_limited_total')).toBe(1);
    expect(context.observability.count('provider_unavailable_total')).toBe(1);
    expect(context.observability.values('provider_query_latency_ms')).toEqual([0, 0]);

    expect(
      context.observability.events
        .filter(({ name }) => name === 'payment.outcome_unknown')
        .map(({ fields }) => fields.errorCode),
    ).toEqual(['PROVIDER_RATE_LIMITED', 'PROVIDER_UNAVAILABLE']);
  });
  it('classifies provider timeouts while preserving PENDING and the active reservation', async () => {
    const provider = new E5ScriptedPaymentProvider('FAKE-E5-04');
    jest
      .spyOn(provider, 'getById')
      .mockResolvedValueOnce(err<ProviderError>({ code: 'PROVIDER_TIMEOUT' }));
    const context = harness({ provider, random: () => 0.5 });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));

    context.advance(60_000);
    expect(valueOf(await context.service.reconcileDue())).toBe(1);
    expect(
      valueOf(await context.service.getTransaction(submission.transactionId, ready.capability))
        .transaction,
    ).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      reservationStatus: 'ACTIVE',
      attempts: 1,
    });
    expect(context.observability.count('provider_timeouts_total')).toBe(1);
    expect(context.observability.count('provider_external_errors_total')).toBe(1);
    expect(context.observability.count('reconciliation_retries_total')).toBe(1);
    expect(context.observability.values('provider_query_latency_ms')).toEqual([0]);
    expect(context.observability.events).toContainEqual({
      name: 'provider.external_error',
      fields: { errorCode: 'PROVIDER_TIMEOUT' },
    });
  });

  it('emits allowlisted session, quote, attempt, final, idempotency, reservation, stock and dedupe signals', async () => {
    const context = harness({ scenario: 'FAKE-E5-01' });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    expect(valueOf(await submit(context.service, ready)).transactionId).toBe(
      submission.transactionId,
    );
    context.advance(60_000);
    expect(valueOf(await context.service.reconcileDue())).toBe(1);

    expect(context.observability.count('checkout_sessions_total')).toBe(1);
    expect(context.observability.count('checkout_quotes_total')).toBe(1);
    expect(context.observability.count('payment_attempts_total')).toBe(1);
    expect(context.observability.count('payment_finalized_total')).toBe(1);
    expect(context.observability.count('idempotency_replays_total')).toBe(1);
    expect(context.observability.count('reservations_total')).toBe(1);
    expect(context.observability.count('deduplicated_operations_total')).toBe(1);
    expect(context.observability.count('payment_finalized_approved_total')).toBe(1);
    expect(context.observability.count('reservations_created_total')).toBe(1);
    expect(context.observability.count('reservations_committed_total')).toBe(1);
    expect(context.observability.values('payment_start_latency_ms')).toEqual([0]);
    expect(context.observability.values('provider_query_latency_ms')).toEqual([0]);

    expect(context.observability.events.map(({ name }) => name)).toEqual(
      expect.arrayContaining([
        'checkout.created',
        'checkout.quoted',
        'payment.reserved',
        'payment.dispatch_claimed',
        'payment.idempotency_replayed',
        'reconcile.deduplicated',
        'reconcile.claimed',
        'payment.finalized',
        'reservation.committed',
      ]),
    );
    const telemetry = JSON.stringify(context.observability);
    expect(telemetry).not.toContain('Ada Lovelace');
    expect(telemetry).not.toContain('ada@example.invalid');
    expect(telemetry).not.toContain('tok_synthetic_001');
    expect(telemetry).not.toContain('Calle 100');

    const stockConflict = harness({ stock: 0 });
    await expect(stockConflict.service.createCheckout(PRODUCT_ID)).resolves.toEqual(
      err({ code: 'OUT_OF_STOCK' }),
    );
    expect(stockConflict.observability.count('inventory_conflicts_total')).toBe(1);
    expect(stockConflict.observability.events).toContainEqual({
      name: 'inventory.conflict',
      fields: {},
    });
  });

  it('quarantines divergent provider correlation without inventory or delivery effects', async () => {
    const context = harness({ scenario: 'FAKE-E5-08' });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    const transaction = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(transaction).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      providerStatus: null,
      reservationStatus: 'ACTIVE',
    });
    expect(transaction.deliveryId).toBeUndefined();
    context.advance(60_000);
    expect(valueOf(await context.service.reconcileDue())).toBe(1);
    expect(
      valueOf(await context.service.getTransaction(submission.transactionId, ready.capability))
        .transaction,
    ).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      reservationStatus: 'ACTIVE',
      effectsApplied: false,
    });
  });

  it('replays after TTL/config/price drift, excludes token C3, and conflicts on semantic changes', async () => {
    const context = harness({ scenario: 'FAKE-E5-04' });
    const ready = await readyCheckout(context.service);
    const first = valueOf(await submit(context.service, ready));
    context.advance(3_600_000);
    context.catalog.priceDelta = 123;
    const retokenized = { ...ready.input, paymentMethodToken: 'tok_synthetic_002' };
    const replay = valueOf(await submit(context.service, ready, retokenized));
    expect(replay).toEqual(first);
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(1);
    expect(await submit(context.service, ready, { ...retokenized, installments: 2 })).toEqual(
      err({ code: 'IDEMPOTENCY_CONFLICT' }),
    );
    expect(
      await submit(context.service, ready, { ...retokenized, quoteId: 'quote_changed_001' }),
    ).toEqual(err({ code: 'IDEMPOTENCY_CONFLICT' }));
    expect(context.observability.count('idempotency_conflicts_total')).toBe(2);
  });

  it.each([
    ['NOT_SENT', false],
    ['NOT_SENT_FAILED', true],
  ] as const)(
    'rejects expired acceptance tokens before a replay can dispatch from %s',
    async (dispatchPhase, claimAsNotSentFailed) => {
      const context = harness({ scenario: 'FAKE-E5-04' });
      jest
        .spyOn(context.repository, 'claimDispatch')
        .mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' }));
      const ready = await readyCheckout(context.service);
      const submission = valueOf(await submit(context.service, ready));
      expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(0);

      if (claimAsNotSentFailed) {
        context.advance(45_000);
        const claimedAt = context.runtime.now();
        const claimed = valueOf(
          await context.repository.claimDue(
            claimedAt.toISOString(),
            new Date(claimedAt.getTime() + 45_000).toISOString(),
            10,
          ),
        );
        expect(claimed).toHaveLength(1);
        context.advance(855_000);
      } else {
        context.advance(900_000);
      }

      await expect(submit(context.service, ready)).resolves.toEqual(err({ code: 'FIELD_INVALID' }));
      expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(0);
      expect(
        valueOf(await context.service.getTransaction(submission.transactionId, ready.capability))
          .transaction,
      ).toMatchObject({
        paymentStatus: 'PENDING',
        dispatchPhase,
        reservationStatus: 'ACTIVE',
      });
    },
  );

  it('conflicts before dispatch when the current contract permalink rotates under the same key', async () => {
    let currentContracts: MerchantContractSet = [
      {
        type: 'TERMS',
        permalink: 'http://localhost:5173/legal/terms-v1.html',
        version: 'terms-v1',
      },
      {
        type: 'PERSONAL_DATA',
        permalink: 'http://localhost:5173/legal/personal-data-v1.html',
        version: 'personal-data-v1',
      },
    ];
    const merchantContracts: MerchantContractPort = {
      getCurrentContracts: () => ok(currentContracts),
    };
    const context = harness({ scenario: 'FAKE-E5-04', merchantContracts });
    jest
      .spyOn(context.repository, 'claimDispatch')
      .mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' }));
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    const persisted = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(persisted.acceptanceEvidence.termsContractHash).toMatch(/^[A-Za-z0-9_-]{32,}$/u);
    expect(JSON.stringify(persisted.acceptanceEvidence)).not.toContain('/legal/');

    currentContracts = [
      {
        ...currentContracts[0],
        permalink: 'http://localhost:5173/legal/terms-v1-rotated.html',
      },
      currentContracts[1],
    ];
    await expect(submit(context.service, ready)).resolves.toEqual(
      err({ code: 'IDEMPOTENCY_CONFLICT' }),
    );
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(0);
    expect(context.observability.count('idempotency_conflicts_total')).toBe(1);
    expect(context.observability.events).toContainEqual({
      name: 'payment.idempotency_conflict',
      fields: {},
    });
  });
  it('recovers a crash after prepare: two concurrent replays elect one POST leader', async () => {
    const context = harness({ scenario: 'FAKE-E5-04' });
    let failFirstClaim = true;
    const repository = new Proxy(context.repository, {
      get(target, property) {
        if (property === 'claimDispatch') {
          return async (...args: Parameters<CheckoutRepository['claimDispatch']>) => {
            if (failFirstClaim) {
              failFirstClaim = false;
              return err({ code: 'REPOSITORY_UNAVAILABLE' as const });
            }
            return target.claimDispatch(...args);
          };
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) as CheckoutRepository;
    const service = new CheckoutService(
      context.catalog,
      repository,
      context.provider,
      context.runtime,
      context.merchantContracts,
    );
    const ready = await readyCheckout(service);
    const first = valueOf(await submit(service, ready));
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(0);
    const replays = await Promise.all([submit(service, ready), submit(service, ready)]);
    expect(replays.every((result) => result.ok)).toBe(true);
    expect(replays.map(valueOf).map(({ transactionId }) => transactionId)).toEqual([
      first.transactionId,
      first.transactionId,
    ]);
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(1);
  });

  it('recovers NOT_SENT autonomously after a crash without calling the provider', async () => {
    const context = harness({ scenario: 'FAKE-E5-04' });
    jest
      .spyOn(context.repository, 'claimDispatch')
      .mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' }));
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(0);

    context.advance(45_000);
    expect(valueOf(await context.service.reconcileDue())).toBe(1);
    const recovered = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(recovered).toMatchObject({
      paymentStatus: 'ERROR',
      dispatchPhase: 'NOT_SENT_FAILED',
      providerStatus: null,
      reservationStatus: 'RELEASED',
      recoveryCode: 'PROVIDER_NOT_SENT',
      effectsApplied: true,
    });
    expect(recovered.deliveryId).toBeUndefined();
    expect(valueOf(await context.innerCatalog.findById(PRODUCT_ID))).toMatchObject({
      onHand: 3,
      reserved: 0,
      available: 3,
    });
  });

  it('turns an expired SENDING lease into UNKNOWN and never repeats POST', async () => {
    const context = harness({ scenario: 'FAKE-E5-04' });
    let returnErrorAfterClaim = true;
    const repository = new Proxy(context.repository, {
      get(target, property) {
        if (property === 'claimDispatch') {
          return async (...args: Parameters<CheckoutRepository['claimDispatch']>) => {
            const claimed = await target.claimDispatch(...args);
            if (returnErrorAfterClaim) {
              returnErrorAfterClaim = false;
              return err({ code: 'REPOSITORY_UNAVAILABLE' as const });
            }
            return claimed;
          };
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) as CheckoutRepository;
    const service = new CheckoutService(
      context.catalog,
      repository,
      context.provider,
      context.runtime,
      context.merchantContracts,
    );
    const ready = await readyCheckout(service);
    expect((await submit(service, ready)).ok).toBe(true);
    context.advance(45_000);
    expect(valueOf(await service.reconcileDue())).toBe(1);
    const replay = valueOf(await submit(service, ready));
    const transaction = valueOf(
      await service.getTransaction(replay.transactionId, ready.capability),
    ).transaction;
    expect(transaction.dispatchPhase).toBe('UNKNOWN');
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(0);
  });

  it('keeps an unknown POST reserved when no provider ID permits safe lookup', async () => {
    const context = harness({ scenario: 'FAKE-E5-05' });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    const unknown = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(unknown).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      providerStatus: null,
      reservationStatus: 'ACTIVE',
    });
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(1);

    context.advance(60_000);
    expect(valueOf(await context.service.reconcileDue())).toBe(1);
    const stillUnknown = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(stillUnknown).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      reservationStatus: 'ACTIVE',
      attempts: 1,
      lastCheckedAt: '2026-08-15T12:01:00.000Z',
      nextCheckAt: '2026-08-15T12:02:00.000Z',
      effectsApplied: false,
    });
    expect(stillUnknown.deliveryId).toBeUndefined();
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(1);
    expect((context.provider as E5ScriptedPaymentProvider).readCalls).toBe(0);
  });

  it('keeps 202 and quarantines an acknowledge conflict after one provider POST', async () => {
    const context = harness({ scenario: 'FAKE-E5-09' });
    const acknowledge = jest
      .spyOn(context.repository, 'acknowledgeProvider')
      .mockResolvedValueOnce(err({ code: 'FINAL_STATE_CONFLICT' }));
    const finalize = jest.spyOn(context.repository, 'finalize');
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));

    expect(acknowledge).toHaveBeenCalledTimes(1);
    expect(finalize).not.toHaveBeenCalled();
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(1);
    const quarantined = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(quarantined).toMatchObject({
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      providerStatus: null,
      reservationStatus: 'ACTIVE',
      recoveryCode: 'PROVIDER_OUTCOME_UNKNOWN',
      effectsApplied: false,
    });
    expect(quarantined.deliveryId).toBeUndefined();
    expect(valueOf(await context.innerCatalog.findById(PRODUCT_ID))).toMatchObject({
      onHand: 3,
      reserved: 1,
      available: 2,
    });
    expect(valueOf(await submit(context.service, ready))).toEqual(submission);
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(1);
  });

  it.each([
    [{ kind: 'PROVEN_NOT_SENT' } as const, 'PROVIDER_NOT_SENT', 'NOT_SENT_FAILED'],
    [{ kind: 'DEFINITIVE_REJECTION' } as const, 'PAYMENT_TOKEN_REJECTED', 'ACKNOWLEDGED'],
  ])('releases safely for explicit provider outcome %#', async (outcome, recoveryCode, phase) => {
    const provider = new StaticOutcomeProvider(outcome);
    const context = harness({ provider });
    const ready = await readyCheckout(context.service);
    const submission = valueOf(await submit(context.service, ready));
    const transaction = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    ).transaction;
    expect(transaction).toMatchObject({
      paymentStatus: 'ERROR',
      reservationStatus: 'RELEASED',
      recoveryCode,
      dispatchPhase: phase,
    });
  });

  it('keeps invalid state, forged capability, provider error and ambiguity fail-closed', async () => {
    const draftContext = harness();
    const created = valueOf(await draftContext.service.createCheckout(PRODUCT_ID));
    const configuration = valueOf(draftContext.service.getPaymentConfiguration());
    const draftInput: SubmitPaymentInput = {
      quoteId: created.checkout.quote.quoteId,
      paymentMethodToken: 'tok_synthetic_draft',
      installments: 1,
      acceptances: {
        termsAcceptanceToken: configuration.acceptanceContracts[0].acceptanceToken,
        personalDataAcceptanceToken: configuration.acceptanceContracts[1].acceptanceToken,
      },
    };
    expect(
      await draftContext.service.submitPayment(
        created.checkout.checkoutId,
        created.rawCapability,
        '"checkout-v1"',
        'idem-draft-0000001',
        draftInput,
      ),
    ).toEqual(err({ code: 'STATE_TRANSITION_CONFLICT' }));
    expect(
      await draftContext.service.getCheckout(
        created.checkout.checkoutId,
        created.checkout.checkoutId + '.forged-capability',
      ),
    ).toEqual(err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }));

    const providerErrorContext = harness({ provider: new TransportErrorProvider() });
    const providerErrorReady = await readyCheckout(providerErrorContext.service);
    const providerErrorSubmission = valueOf(
      await submit(providerErrorContext.service, providerErrorReady),
    );
    expect(
      valueOf(
        await providerErrorContext.service.getTransaction(
          providerErrorSubmission.transactionId,
          providerErrorReady.capability,
        ),
      ).transaction,
    ).toMatchObject({ paymentStatus: 'PENDING', dispatchPhase: 'UNKNOWN' });

    const ambiguousContext = harness({
      provider: new StaticOutcomeProvider({ kind: 'OUTCOME_UNKNOWN' }),
    });
    const ambiguousReady = await readyCheckout(ambiguousContext.service);
    const ambiguousSubmission = valueOf(await submit(ambiguousContext.service, ambiguousReady));
    expect(
      valueOf(
        await ambiguousContext.service.getTransaction(
          ambiguousSubmission.transactionId,
          ambiguousReady.capability,
        ),
      ).transaction,
    ).toMatchObject({ paymentStatus: 'PENDING', dispatchPhase: 'UNKNOWN' });

    const configContext = harness();
    const configReady = await readyCheckout(configContext.service);
    const disabledService = new CheckoutService(
      configContext.catalog,
      configContext.repository,
      new StaticOutcomeProvider({ kind: 'OUTCOME_UNKNOWN' }, false),
      configContext.runtime,
      configContext.merchantContracts,
    );
    expect(await submit(disabledService, configReady)).toEqual(
      err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' }),
    );
  });

  it('fails validation and authorization before effects', async () => {
    expect(await harness({ stock: 0 }).service.createCheckout(PRODUCT_ID)).toEqual(
      err({ code: 'OUT_OF_STOCK' }),
    );
    expect(await harness({ active: false }).service.createCheckout(PRODUCT_ID)).toEqual(
      err({ code: 'PRODUCT_NOT_FOUND' }),
    );
    expect(await harness().service.createCheckout('missing-product')).toEqual(
      err({ code: 'PRODUCT_NOT_FOUND' }),
    );

    const context = harness();
    const created = valueOf(await context.service.createCheckout(PRODUCT_ID));
    expect(
      await context.service.getCheckout(created.checkout.checkoutId, 'wrong.capability'),
    ).toEqual(err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }));
    expect(
      await context.service.replaceCustomer(
        created.checkout.checkoutId,
        created.rawCapability,
        'bad-etag',
        { fullName: 'Ada', email: 'ada@example.invalid', phone: '+573001234567' },
      ),
    ).toEqual(err({ code: 'PRECONDITION_FAILED' }));
    const ready = await readyCheckout(context.service);
    expect(await submit(context.service, ready, ready.input, 'short')).toEqual(
      err({ code: 'FIELD_INVALID' }),
    );
    expect(await submit(context.service, ready, { ...ready.input, installments: 36 })).toEqual(
      err({ code: 'FIELD_INVALID' }),
    );
    expect(
      await submit(context.service, ready, {
        ...ready.input,
        acceptances: { ...ready.input.acceptances, termsAcceptanceToken: 'tampered' },
      }),
    ).toEqual(err({ code: 'FIELD_INVALID' }));
    context.catalog.priceDelta = 1;
    expect(await submit(context.service, ready)).toEqual(err({ code: 'QUOTE_STALE' }));
  });

  it('expires checkout and quote deterministically without sleeps and fails payment config closed', async () => {
    const expiredCheckout = harness({ checkoutTtlSeconds: 0 });
    const created = valueOf(await expiredCheckout.service.createCheckout(PRODUCT_ID));
    expect(
      await expiredCheckout.service.getCheckout(created.checkout.checkoutId, created.rawCapability),
    ).toEqual(err({ code: 'CHECKOUT_EXPIRED' }));

    const expiredQuote = harness({ quoteTtlSeconds: 0 });
    const ready = await readyCheckout(expiredQuote.service);
    expect(await submit(expiredQuote.service, ready)).toEqual(err({ code: 'QUOTE_STALE' }));
    expect(expiredQuote.observability.count('checkout_quotes_expired_total')).toBe(1);
    expect(expiredQuote.observability.events).toContainEqual({
      name: 'checkout.quote_expired',
      fields: {},
    });

    const disabled = new StaticOutcomeProvider({ kind: 'OUTCOME_UNKNOWN' }, false);
    const disabledContext = harness({ provider: disabled });
    expect(disabledContext.service.getPaymentConfiguration()).toEqual(
      err({ code: 'PROVIDER_AUTH_OR_CONFIG_INVALID' }),
    );
  });

  it('rejects unauthorized commands and invalid optimistic preconditions before mutation', async () => {
    const context = harness();
    const created = valueOf(await context.service.createCheckout(PRODUCT_ID));
    const customer = {
      fullName: 'Ada Lovelace',
      email: 'ada@example.invalid',
      phone: '+573001234567',
    };
    const delivery = { addressLine1: 'Calle 1', city: 'Bogota', region: 'Cundinamarca' };

    await expect(
      context.service.replaceCustomer(created.checkout.checkoutId, null, '"checkout-v1"', customer),
    ).resolves.toEqual(err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }));
    await expect(
      context.service.replaceDeliveryDetails(
        created.checkout.checkoutId,
        null,
        '"checkout-v1"',
        delivery,
      ),
    ).resolves.toEqual(err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }));

    const ready = await readyCheckout(context.service);
    await expect(
      context.service.submitPayment(
        ready.checkout.checkoutId,
        null,
        '"checkout-v3"',
        IDEMPOTENCY_KEY,
        ready.input,
      ),
    ).resolves.toEqual(err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }));
    await expect(
      context.service.replaceDeliveryDetails(
        ready.checkout.checkoutId,
        ready.capability,
        'bad-etag',
        delivery,
      ),
    ).resolves.toEqual(err({ code: 'PRECONDITION_FAILED' }));
    await expect(
      context.service.submitPayment(
        ready.checkout.checkoutId,
        ready.capability,
        'bad-etag',
        IDEMPOTENCY_KEY,
        ready.input,
      ),
    ).resolves.toEqual(err({ code: 'PRECONDITION_FAILED' }));
    await expect(
      context.service.getCheckout('checkout_missing', 'checkout_missing.capability'),
    ).resolves.toEqual(err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }));
  });

  it('maps catalog and repository failures and hides related resources from other capabilities', async () => {
    const context = harness();
    const unavailableCatalog = {
      findById: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' as const })),
    } as unknown as CatalogRepository;
    const unavailableCatalogService = new CheckoutService(
      unavailableCatalog,
      context.repository,
      context.provider,
      context.runtime,
      context.merchantContracts,
    );
    await expect(unavailableCatalogService.createCheckout(PRODUCT_ID)).resolves.toEqual(
      err({ code: 'INTERNAL_ERROR' }),
    );

    const createFailureRepository = {
      create: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' as const })),
    } as unknown as CheckoutRepository;
    const createFailureService = new CheckoutService(
      context.catalog,
      createFailureRepository,
      context.provider,
      context.runtime,
      context.merchantContracts,
    );
    await expect(createFailureService.createCheckout(PRODUCT_ID)).resolves.toEqual(
      err({ code: 'INTERNAL_ERROR' }),
    );

    const ready = await readyCheckout(context.service);
    await expect(
      unavailableCatalogService.getCheckout(ready.checkout.checkoutId, ready.capability),
    ).resolves.toEqual(err({ code: 'INTERNAL_ERROR' }));
    await expect(
      unavailableCatalogService.submitPayment(
        ready.checkout.checkoutId,
        ready.capability,
        '"checkout-v3"',
        IDEMPOTENCY_KEY,
        ready.input,
      ),
    ).resolves.toEqual(err({ code: 'INTERNAL_ERROR' }));

    const repositoryFailure = {
      findTransaction: jest
        .fn()
        .mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' as const })),
      claimDue: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' as const })),
    } as unknown as CheckoutRepository;
    const repositoryFailureService = new CheckoutService(
      context.catalog,
      repositoryFailure,
      context.provider,
      context.runtime,
      context.merchantContracts,
    );
    await expect(
      repositoryFailureService.getTransaction('transaction_missing', null),
    ).resolves.toEqual(err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }));
    await expect(repositoryFailureService.reconcileDue()).resolves.toEqual(
      err({ code: 'INTERNAL_ERROR' }),
    );

    const submission = valueOf(await submit(context.service, ready));
    await expect(context.service.getTransaction(submission.transactionId, null)).resolves.toEqual(
      err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }),
    );
    context.advance(60_000);
    valueOf(await context.service.reconcileDue());
    const approved = valueOf(
      await context.service.getTransaction(submission.transactionId, ready.capability),
    );
    if (approved.transaction.deliveryId === undefined) throw new Error('Delivery was not created');
    await expect(
      context.service.getDelivery(approved.transaction.deliveryId, null),
    ).resolves.toEqual(err({ code: 'CHECKOUT_NOT_FOUND_OR_FORBIDDEN' }));
  });

  it('preserves one unit under concurrent checkout submissions', async () => {
    const context = harness({ scenario: 'FAKE-E5-04', stock: 1 });
    const first = await readyCheckout(context.service);
    const second = await readyCheckout(context.service);
    const results = await Promise.all([
      submit(context.service, first, first.input, 'idem-concurrent-0001'),
      submit(context.service, second, second.input, 'idem-concurrent-0002'),
    ]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.filter((result) => !result.ok)).toEqual([err({ code: 'OUT_OF_STOCK' })]);
    expect((context.provider as E5ScriptedPaymentProvider).createCalls).toBe(1);
  });

  it('keeps approved inventory safe when delivery data is absent and records terminal conflict', async () => {
    const context = harness();
    const created = valueOf(await context.service.createCheckout(PRODUCT_ID));
    const acceptedAt = context.runtime.now().toISOString();
    const transaction: Transaction = {
      transactionId: 'transaction_direct_001',
      checkoutId: created.checkout.checkoutId,
      providerReference: 'reference_direct_001',
      paymentStatus: 'PENDING',
      dispatchPhase: 'NOT_SENT',
      providerStatus: null,
      reservationStatus: 'ACTIVE',
      integrityStatus: 'OK',
      acceptanceEvidence: {
        termsVersion: 'terms-v1',
        termsContractHash: 'terms-contract-hash-synthetic',
        personalDataVersion: 'personal-data-v1',
        personalDataContractHash: 'personal-data-contract-hash-synthetic',
        acceptedAt,
      },
      acceptedAt,
      updatedAt: acceptedAt,
      nextCheckAt: acceptedAt,
      attempts: 0,
      amountInCents: created.checkout.quote.total.amountInCents,
      currency: 'COP',
      effectsApplied: false,
    };
    valueOf(
      await context.repository.preparePayment({
        checkoutId: created.checkout.checkoutId,
        capabilityHash: created.checkout.capabilityHash,
        expectedVersion: 1,
        keyHash: 'key-direct',
        semanticHash: 'semantic-direct',
        transaction,
        submission: {
          transactionId: transaction.transactionId,
          statusUrl: `/api/v1/transactions/${transaction.transactionId}`,
          submissionState: 'ACCEPTED',
          acceptedAt,
        },
      }),
    );
    valueOf(
      await context.repository.claimDispatch(transaction.transactionId, acceptedAt, acceptedAt),
    );
    valueOf(
      await context.repository.acknowledgeProvider(
        transaction.transactionId,
        'provider-direct-001',
        'APPROVED',
        acceptedAt,
        {
          attempts: 1,
          lastCheckedAt: acceptedAt,
          nextCheckAt: acceptedAt,
        },
      ),
    );
    expect(
      await context.repository.finalize(
        transaction.transactionId,
        'APPROVED',
        'APPROVED',
        undefined,
        acceptedAt,
      ),
    ).toEqual(err({ code: 'REPOSITORY_UNAVAILABLE' }));
    expect(valueOf(await context.innerCatalog.findById(PRODUCT_ID))).toMatchObject({
      onHand: 3,
      reserved: 1,
      available: 2,
    });
  });
});
