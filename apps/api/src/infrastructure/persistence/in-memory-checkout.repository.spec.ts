import type { CatalogRepository } from '../../application/ports/catalog-repository';
import type { Result } from '../../application/result/result';
import { err } from '../../application/result/result';
import type { Checkout, PaymentSubmission, Transaction } from '../../domain/checkout/checkout';
import { InMemoryCatalogRepository } from './in-memory-catalog.repository';
import { InMemoryCheckoutRepository } from './in-memory-checkout.repository';
import { createProductSeed } from './product-seed';

const now = '2026-01-01T00:00:00.000Z';
const later = '2026-01-01T00:00:01.000Z';
const lease = '2026-01-01T00:00:05.000Z';
const product = createProductSeed('product-demo-001', 'http://localhost:5173', 4);
const reconciliationCheck = (nextCheckAt = lease, attempts = 1) => ({
  attempts,
  lastCheckedAt: nextCheckAt,
  nextCheckAt,
});

const checkout = (id = 'checkout-001', overrides: Partial<Checkout> = {}): Checkout => ({
  checkoutId: id,
  status: 'READY',
  version: 3,
  capabilityHash: `cap-${id}`,
  productId: product.productId,
  quote: {
    quoteId: `quote-${id}`,
    version: 1,
    productId: product.productId,
    quantity: 1,
    subtotal: product.unitPrice,
    baseFee: { amountInCents: 200_000, currency: 'COP' },
    deliveryFee: { amountInCents: 500_000, currency: 'COP' },
    total: { amountInCents: 3_200_000, currency: 'COP' },
    expiresAt: '2026-01-01T00:05:00.000Z',
  },
  customer: {
    customerId: `customer-${id}`,
    checkoutId: id,
    version: 2,
    fullName: 'Ada Lovelace',
    email: 'ada@example.invalid',
    phone: '+573001112233',
  },
  deliveryDetails: {
    checkoutId: id,
    version: 3,
    addressLine1: 'Calle 1 # 2-3',
    city: 'Bogota',
    region: 'Cundinamarca',
  },
  expiresAt: '2026-01-01T00:10:00.000Z',
  ...overrides,
});

const transaction = (
  id = 'transaction-001',
  checkoutId = 'checkout-001',
  overrides: Partial<Transaction> = {},
): Transaction => ({
  transactionId: id,
  checkoutId,
  providerReference: `reference-${id}`,
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
    acceptedAt: now,
  },
  acceptedAt: now,
  updatedAt: now,
  amountInCents: 3_200_000,
  attempts: 0,
  currency: 'COP',
  effectsApplied: false,
  ...overrides,
});

const submission = (id = 'transaction-001'): PaymentSubmission => ({
  transactionId: id,
  statusUrl: `/api/transactions/${id}`,
  submissionState: 'ACCEPTED',
  acceptedAt: now,
});

const valueOf = <T, E>(result: Result<T, E>): T => {
  if (!result.ok) throw new Error(`unexpected error: ${JSON.stringify(result.error)}`);
  return result.value;
};

const prepare = async (
  repository: InMemoryCheckoutRepository,
  checkoutValue: Checkout,
  transactionValue: Transaction = transaction('transaction-001', checkoutValue.checkoutId),
  keyHash = 'key-hash',
  semanticHash = 'semantic-hash',
) => {
  await repository.create(checkoutValue);
  return repository.preparePayment({
    checkoutId: checkoutValue.checkoutId,
    capabilityHash: checkoutValue.capabilityHash,
    expectedVersion: checkoutValue.version,
    keyHash,
    semanticHash,
    transaction: transactionValue,
    submission: submission(transactionValue.transactionId),
  });
};

describe('InMemoryCheckoutRepository', () => {
  it('creates isolated snapshots and rejects duplicate checkout identifiers', async () => {
    const repository = new InMemoryCheckoutRepository(new InMemoryCatalogRepository([product]));
    const original = checkout();
    const created = valueOf(await repository.create(original));
    (created as { status: string }).status = 'DRAFT';

    await expect(repository.findCheckout(original.checkoutId)).resolves.toMatchObject({
      value: { status: 'READY' },
    });
    await expect(repository.findCheckout('missing')).resolves.toMatchObject({ value: null });
    await expect(repository.create(original)).resolves.toMatchObject({
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
  });

  it('enforces capability, optimistic version and mutability for customer and delivery', async () => {
    const repository = new InMemoryCheckoutRepository(new InMemoryCatalogRepository([product]));
    const {
      customer: ignoredCustomer,
      deliveryDetails: ignoredDelivery,
      ...draftBase
    } = checkout('checkout-edit');
    void ignoredCustomer;
    void ignoredDelivery;
    const draft: Checkout = {
      ...draftBase,
      status: 'DRAFT',
      version: 1,
    };
    await repository.create(draft);

    await expect(
      repository.replaceCustomer(draft.checkoutId, 'wrong-capability', 1, {
        customerId: 'customer-edit',
        checkoutId: draft.checkoutId,
        fullName: 'Ada Lovelace',
        email: 'ada@example.invalid',
        phone: '+573001112233',
      }),
    ).resolves.toMatchObject({ error: { code: 'CHECKOUT_NOT_FOUND' } });
    await expect(
      repository.replaceCustomer(draft.checkoutId, draft.capabilityHash, 99, {
        customerId: 'customer-edit',
        checkoutId: draft.checkoutId,
        fullName: 'Ada Lovelace',
        email: 'ada@example.invalid',
        phone: '+573001112233',
      }),
    ).resolves.toMatchObject({ error: { code: 'VERSION_MISMATCH' } });
    const withCustomer = valueOf(
      await repository.replaceCustomer(draft.checkoutId, draft.capabilityHash, 1, {
        customerId: 'customer-edit',
        checkoutId: draft.checkoutId,
        fullName: 'Ada Lovelace',
        email: 'ada@example.invalid',
        phone: '+573001112233',
      }),
    );
    expect(withCustomer).toMatchObject({ status: 'DRAFT', version: 2, customer: { version: 2 } });

    const ready = valueOf(
      await repository.replaceDeliveryDetails(draft.checkoutId, draft.capabilityHash, 2, {
        checkoutId: draft.checkoutId,
        addressLine1: 'Calle 1',
        city: 'Bogota',
        region: 'Cundinamarca',
      }),
    );
    expect(ready).toMatchObject({ status: 'READY', version: 3, deliveryDetails: { version: 3 } });
    await expect(
      repository.replaceDeliveryDetails(draft.checkoutId, draft.capabilityHash, 2, {
        checkoutId: draft.checkoutId,
        addressLine1: 'Otra',
        city: 'Bogota',
        region: 'Cundinamarca',
      }),
    ).resolves.toMatchObject({ error: { code: 'VERSION_MISMATCH' } });

    await repository.preparePayment({
      checkoutId: ready.checkoutId,
      capabilityHash: ready.capabilityHash,
      expectedVersion: ready.version,
      keyHash: 'edit-key',
      semanticHash: 'edit-semantic',
      transaction: transaction('transaction-edit', ready.checkoutId),
      submission: submission('transaction-edit'),
    });
    await expect(
      repository.replaceCustomer(ready.checkoutId, ready.capabilityHash, 4, {
        customerId: 'customer-edit',
        checkoutId: ready.checkoutId,
        fullName: 'Grace Hopper',
        email: 'grace@example.invalid',
        phone: '+573004445566',
      }),
    ).resolves.toMatchObject({ error: { code: 'PAYMENT_ALREADY_IN_PROGRESS' } });
    await expect(
      repository.replaceDeliveryDetails(ready.checkoutId, ready.capabilityHash, 4, {
        checkoutId: ready.checkoutId,
        addressLine1: 'Otra',
        city: 'Bogota',
        region: 'Cundinamarca',
      }),
    ).resolves.toMatchObject({ error: { code: 'PAYMENT_ALREADY_IN_PROGRESS' } });
  });

  it('atomically reserves stock and returns stable idempotent replays', async () => {
    const catalog = new InMemoryCatalogRepository([product]);
    const repository = new InMemoryCheckoutRepository(catalog);
    const checkoutValue = checkout();

    await expect(
      repository.findIdempotency({
        checkoutId: checkoutValue.checkoutId,
        keyHash: 'key',
        semanticHash: 'one',
      }),
    ).resolves.toMatchObject({ value: null });
    const created = await prepare(repository, checkoutValue, transaction(), 'key', 'one');
    expect(created).toMatchObject({ value: { kind: 'CREATED', checkout: { version: 4 } } });
    await expect(
      repository.findIdempotency({
        checkoutId: checkoutValue.checkoutId,
        keyHash: 'key',
        semanticHash: 'one',
      }),
    ).resolves.toMatchObject({ value: { kind: 'REPLAY', submission: submission() } });
    await expect(
      repository.findIdempotency({
        checkoutId: checkoutValue.checkoutId,
        keyHash: 'key',
        semanticHash: 'two',
      }),
    ).resolves.toMatchObject({ error: { code: 'IDEMPOTENCY_CONFLICT' } });
    await expect(
      repository.preparePayment({
        checkoutId: checkoutValue.checkoutId,
        capabilityHash: checkoutValue.capabilityHash,
        expectedVersion: checkoutValue.version,
        keyHash: 'key',
        semanticHash: 'one',
        transaction: transaction('ignored'),
        submission: submission('ignored'),
      }),
    ).resolves.toMatchObject({
      value: { kind: 'REPLAY', transaction: { transactionId: 'transaction-001' } },
    });
    await expect(
      repository.preparePayment({
        checkoutId: checkoutValue.checkoutId,
        capabilityHash: checkoutValue.capabilityHash,
        expectedVersion: 4,
        keyHash: 'key',
        semanticHash: 'two',
        transaction: transaction('ignored'),
        submission: submission('ignored'),
      }),
    ).resolves.toMatchObject({ error: { code: 'IDEMPOTENCY_CONFLICT' } });
    await expect(catalog.findById(product.productId)).resolves.toMatchObject({
      value: { available: 3, reserved: 1 },
    });
  });

  it('maps authorization, version, active-payment, out-of-stock and repository failures', async () => {
    const catalog = new InMemoryCatalogRepository([{ ...product, onHand: 0, available: 0 }]);
    const repository = new InMemoryCheckoutRepository(catalog);
    const value = checkout('checkout-errors');
    await repository.create(value);
    const base = {
      checkoutId: value.checkoutId,
      capabilityHash: value.capabilityHash,
      expectedVersion: value.version,
      keyHash: 'key',
      semanticHash: 'semantic',
      transaction: transaction('transaction-errors', value.checkoutId),
      submission: submission('transaction-errors'),
    };
    await expect(
      repository.preparePayment({ ...base, capabilityHash: 'wrong' }),
    ).resolves.toMatchObject({
      error: { code: 'CHECKOUT_NOT_FOUND' },
    });
    await expect(
      repository.preparePayment({ ...base, expectedVersion: 99 }),
    ).resolves.toMatchObject({
      error: { code: 'VERSION_MISMATCH' },
    });
    await expect(repository.preparePayment(base)).resolves.toMatchObject({
      error: { code: 'OUT_OF_STOCK' },
    });

    const brokenCatalog: CatalogRepository = {
      ...catalog,
      reserve: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
    } as unknown as CatalogRepository;
    const broken = new InMemoryCheckoutRepository(brokenCatalog);
    await broken.create(checkout('checkout-broken'));
    await expect(
      broken.preparePayment({
        ...base,
        checkoutId: 'checkout-broken',
        capabilityHash: 'cap-checkout-broken',
        transaction: transaction('transaction-broken', 'checkout-broken'),
      }),
    ).resolves.toMatchObject({ error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const activeCatalog = new InMemoryCatalogRepository([product]);
    const active = new InMemoryCheckoutRepository(activeCatalog);
    const activeCheckout = checkout('checkout-active');
    await prepare(
      active,
      activeCheckout,
      transaction('transaction-active', activeCheckout.checkoutId),
    );
    await expect(
      active.preparePayment({
        ...base,
        checkoutId: activeCheckout.checkoutId,
        capabilityHash: activeCheckout.capabilityHash,
        expectedVersion: 4,
        keyHash: 'second-key',
        transaction: transaction('transaction-second', activeCheckout.checkoutId),
      }),
    ).resolves.toMatchObject({ error: { code: 'PAYMENT_ALREADY_IN_PROGRESS' } });
  });

  it('elects one dispatch leader and conservatively tracks provider acknowledgement/unknown', async () => {
    const repository = new InMemoryCheckoutRepository(new InMemoryCatalogRepository([product]));
    await prepare(repository, checkout());

    await expect(repository.claimDispatch('missing', later, lease)).resolves.toMatchObject({
      error: { code: 'CHECKOUT_NOT_FOUND' },
    });
    const claims = await Promise.all([
      repository.claimDispatch('transaction-001', later, lease),
      repository.claimDispatch('transaction-001', later, lease),
    ]);
    expect(claims.map((claim) => valueOf(claim).kind).sort()).toEqual(['CLAIMED', 'NOT_LEADER']);
    await expect(
      repository.acknowledgeProvider(
        'missing',
        'provider',
        'PENDING',
        later,
        reconciliationCheck(),
      ),
    ).resolves.toMatchObject({ error: { code: 'CHECKOUT_NOT_FOUND' } });
    await expect(
      repository.acknowledgeProvider(
        'transaction-001',
        'provider-001',
        'PENDING',
        later,
        reconciliationCheck(),
      ),
    ).resolves.toMatchObject({
      value: { dispatchPhase: 'ACKNOWLEDGED', providerStatus: 'PENDING', nextCheckAt: lease },
    });
    await expect(
      repository.markUnknown('transaction-001', later, reconciliationCheck()),
    ).resolves.toMatchObject({
      value: {
        dispatchPhase: 'UNKNOWN',
        providerStatus: 'PENDING',
        recoveryCode: 'PROVIDER_OUTCOME_UNKNOWN',
      },
    });
    await expect(
      repository.markUnknown('missing', later, reconciliationCheck()),
    ).resolves.toMatchObject({
      error: { code: 'CHECKOUT_NOT_FOUND' },
    });
  });

  it('owns each providerId once and blocks a second fulfillment after conflict', async () => {
    const catalog = new InMemoryCatalogRepository([product]);
    const repository = new InMemoryCheckoutRepository(catalog);
    const firstCheckout = checkout('checkout-provider-1');
    const secondCheckout = checkout('checkout-provider-2');
    const firstTransaction = transaction('transaction-provider-1', firstCheckout.checkoutId);
    const secondTransaction = transaction('transaction-provider-2', secondCheckout.checkoutId);
    await prepare(repository, firstCheckout, firstTransaction, 'key-provider-1');
    await prepare(repository, secondCheckout, secondTransaction, 'key-provider-2');
    await repository.claimDispatch(firstTransaction.transactionId, later, lease);
    await repository.claimDispatch(secondTransaction.transactionId, later, lease);

    await expect(
      repository.acknowledgeProvider(
        firstTransaction.transactionId,
        'provider-shared',
        'APPROVED',
        later,
        reconciliationCheck(),
      ),
    ).resolves.toMatchObject({ ok: true });
    await expect(
      repository.acknowledgeProvider(
        secondTransaction.transactionId,
        'provider-shared',
        'APPROVED',
        later,
        reconciliationCheck(),
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'FINAL_STATE_CONFLICT' } });
    await expect(
      repository.finalize(
        secondTransaction.transactionId,
        'APPROVED',
        'APPROVED',
        undefined,
        later,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'FINAL_STATE_CONFLICT' } });

    const approved = valueOf(
      await repository.finalize(
        firstTransaction.transactionId,
        'APPROVED',
        'APPROVED',
        undefined,
        later,
      ),
    );
    expect(approved.deliveryId).toBe(`delivery_${firstTransaction.transactionId}`);
    await expect(
      repository.findDelivery(`delivery_${secondTransaction.transactionId}`),
    ).resolves.toMatchObject({ value: null });
    await expect(repository.findTransactionByProviderId('provider-shared')).resolves.toMatchObject({
      value: { transactionId: firstTransaction.transactionId },
    });
    await expect(catalog.findById(product.productId)).resolves.toMatchObject({
      value: { onHand: 3, reserved: 1, available: 2 },
    });
  });

  it('finalizes APPROVED exactly once with one delivery and detects conflicting finals', async () => {
    const catalog = new InMemoryCatalogRepository([product]);
    const repository = new InMemoryCheckoutRepository(catalog);
    await prepare(repository, checkout());
    await repository.acknowledgeProvider(
      'transaction-001',
      'provider-001',
      'APPROVED',
      later,
      reconciliationCheck(),
    );

    const approved = valueOf(
      await repository.finalize('transaction-001', 'APPROVED', 'APPROVED', undefined, later),
    );
    expect(approved).toMatchObject({
      reservationStatus: 'CONSUMED',
      effectsApplied: true,
      deliveryId: 'delivery_transaction-001',
    });
    await expect(
      repository.finalize('transaction-001', 'APPROVED', 'APPROVED', undefined, lease),
    ).resolves.toMatchObject({ value: { integrityStatus: 'OK', updatedAt: later } });
    await expect(repository.findDelivery('delivery_transaction-001')).resolves.toMatchObject({
      value: { status: 'CREATED', destination: { addressLine1: 'Calle 1 # 2-3' } },
    });
    await expect(repository.findDelivery('missing')).resolves.toMatchObject({ value: null });
    await expect(repository.findTransactionByProviderId('provider-001')).resolves.toMatchObject({
      value: { transactionId: 'transaction-001' },
    });
    await expect(repository.findTransactionByProviderId('missing')).resolves.toMatchObject({
      value: null,
    });
    await expect(catalog.findById(product.productId)).resolves.toMatchObject({
      value: { onHand: 3, reserved: 0, available: 3 },
    });
    await expect(
      repository.finalize('transaction-001', 'DECLINED', 'DECLINED', undefined, lease),
    ).resolves.toMatchObject({ value: { integrityStatus: 'FINAL_STATE_CONFLICT' } });
    await expect(
      repository.finalize('missing', 'ERROR', 'ERROR', undefined, later),
    ).resolves.toMatchObject({
      error: { code: 'CHECKOUT_NOT_FOUND' },
    });
  });

  it('releases failed reservations and marks proven-not-sent without an acknowledgement', async () => {
    const catalog = new InMemoryCatalogRepository([product]);
    const repository = new InMemoryCheckoutRepository(catalog);
    await prepare(repository, checkout());
    await expect(
      repository.finalize('transaction-001', 'ERROR', null, 'PROVIDER_NOT_SENT', later),
    ).resolves.toEqual({ ok: false, error: { code: 'FINAL_STATE_CONFLICT' } });
    await expect(catalog.findById(product.productId)).resolves.toMatchObject({
      value: { available: 3, reserved: 1 },
    });
    await repository.claimDispatch('transaction-001', later, lease);

    await expect(
      repository.finalize('transaction-001', 'ERROR', null, 'PROVIDER_NOT_SENT', later),
    ).resolves.toMatchObject({
      value: {
        paymentStatus: 'ERROR',
        dispatchPhase: 'NOT_SENT_FAILED',
        reservationStatus: 'RELEASED',
      },
    });
    await expect(catalog.findById(product.productId)).resolves.toMatchObject({
      value: { available: 4, reserved: 0 },
    });
    await expect(
      repository.markUnknown('transaction-001', later, reconciliationCheck()),
    ).resolves.toMatchObject({
      value: { paymentStatus: 'ERROR', dispatchPhase: 'NOT_SENT_FAILED' },
    });
    await expect(
      repository.acknowledgeProvider(
        'transaction-001',
        'late-provider',
        'APPROVED',
        later,
        reconciliationCheck(),
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'FINAL_STATE_CONFLICT' } });
  });

  it('fails closed before partial APPROVED effects and records inventory conflicts', async () => {
    const noDeliveryCatalog = new InMemoryCatalogRepository([product]);
    const noDelivery = new InMemoryCheckoutRepository(noDeliveryCatalog);
    const { deliveryDetails: ignoredDelivery, ...incompleteBase } = checkout('checkout-incomplete');
    void ignoredDelivery;
    const incomplete: Checkout = { ...incompleteBase, status: 'DRAFT' };
    await prepare(
      noDelivery,
      incomplete,
      transaction('transaction-incomplete', incomplete.checkoutId),
    );
    await noDelivery.acknowledgeProvider(
      'transaction-incomplete',
      'provider-incomplete',
      'APPROVED',
      later,
      reconciliationCheck(),
    );
    await expect(
      noDelivery.finalize('transaction-incomplete', 'APPROVED', 'APPROVED', undefined, later),
    ).resolves.toMatchObject({ error: { code: 'REPOSITORY_UNAVAILABLE' } });
    await expect(noDeliveryCatalog.findById(product.productId)).resolves.toMatchObject({
      value: { onHand: 4, reserved: 1 },
    });

    const conflictCatalog = new InMemoryCatalogRepository([product]);
    const conflict = new InMemoryCheckoutRepository(conflictCatalog);
    const conflictCheckout = checkout('checkout-conflict');
    await prepare(
      conflict,
      conflictCheckout,
      transaction('transaction-conflict', conflictCheckout.checkoutId, {
        reservationStatus: 'RELEASED',
      }),
    );
    await conflict.acknowledgeProvider(
      'transaction-conflict',
      'provider-conflict',
      'APPROVED',
      later,
      reconciliationCheck(),
    );
    await expect(
      conflict.finalize('transaction-conflict', 'APPROVED', 'APPROVED', undefined, later),
    ).resolves.toMatchObject({
      value: {
        paymentStatus: 'APPROVED',
        integrityStatus: 'APPROVED_INVENTORY_CONFLICT',
        recoveryCode: 'STATE_TRANSITION_CONFLICT',
      },
    });
  });

  it('fails closed when inventory release or consume reports a conflict', async () => {
    const consumeCatalog = new InMemoryCatalogRepository([product]);
    jest.spyOn(consumeCatalog, 'consume').mockResolvedValue(err({ code: 'INVENTORY_CONFLICT' }));
    const consumeRepository = new InMemoryCheckoutRepository(consumeCatalog);
    await prepare(consumeRepository, checkout());
    await consumeRepository.acknowledgeProvider(
      'transaction-001',
      'provider-consume',
      'APPROVED',
      later,
      reconciliationCheck(),
    );
    await expect(
      consumeRepository.finalize('transaction-001', 'APPROVED', 'APPROVED', undefined, later),
    ).resolves.toMatchObject({ value: { integrityStatus: 'APPROVED_INVENTORY_CONFLICT' } });

    const releaseCatalog = new InMemoryCatalogRepository([product]);
    jest.spyOn(releaseCatalog, 'release').mockResolvedValue(err({ code: 'INVENTORY_CONFLICT' }));
    const releaseRepository = new InMemoryCheckoutRepository(releaseCatalog);
    const releaseCheckout = checkout('checkout-release');
    await prepare(
      releaseRepository,
      releaseCheckout,
      transaction('transaction-release', releaseCheckout.checkoutId),
    );
    await releaseRepository.acknowledgeProvider(
      'transaction-release',
      'provider-release',
      'DECLINED',
      later,
      reconciliationCheck(),
    );
    await expect(
      releaseRepository.finalize('transaction-release', 'DECLINED', 'DECLINED', undefined, later),
    ).resolves.toMatchObject({ error: { code: 'REPOSITORY_UNAVAILABLE' } });
  });

  it('claims due work once with bounded limits and deduplicates internal events', async () => {
    const repository = new InMemoryCheckoutRepository(new InMemoryCatalogRepository([product]));
    for (const index of [1, 2]) {
      const checkoutValue = checkout(`checkout-due-${index}`);
      const transactionValue = transaction(`transaction-due-${index}`, checkoutValue.checkoutId);
      await prepare(
        repository,
        checkoutValue,
        transactionValue,
        `key-${index}`,
        `semantic-${index}`,
      );
      await repository.claimDispatch(transactionValue.transactionId, now, now);
      await repository.acknowledgeProvider(
        transactionValue.transactionId,
        `provider-${index}`,
        'PENDING',
        now,
        reconciliationCheck(now),
      );
    }
    const [first, second] = await Promise.all([
      repository.claimDue(now, lease, 1),
      repository.claimDue(now, lease, 1000),
    ]);
    expect(valueOf(first)).toHaveLength(1);
    expect(valueOf(second)).toHaveLength(1);
    await expect(repository.claimDue(now, lease, 0)).resolves.toMatchObject({ value: [] });
    await expect(repository.recordWebhook('event-hash')).resolves.toMatchObject({ value: 'NEW' });
    await expect(repository.recordWebhook('event-hash')).resolves.toMatchObject({
      value: 'DUPLICATE',
    });
    await expect(repository.findTransaction('missing')).resolves.toMatchObject({ value: null });
  });

  it('atomically turns a due NOT_SENT into NOT_SENT_FAILED before dispatch can claim', async () => {
    const repository = new InMemoryCheckoutRepository(new InMemoryCatalogRepository([product]));
    const checkoutValue = checkout('checkout-not-sent');
    const transactionValue = transaction('transaction-not-sent', checkoutValue.checkoutId, {
      nextCheckAt: now,
    });
    await prepare(repository, checkoutValue, transactionValue);

    await expect(repository.claimDue(now, lease, 1)).resolves.toMatchObject({
      value: [{ transactionId: transactionValue.transactionId, dispatchPhase: 'NOT_SENT_FAILED' }],
    });
    await expect(
      repository.claimDispatch(transactionValue.transactionId, later, lease),
    ).resolves.toMatchObject({
      value: { kind: 'NOT_LEADER', transaction: { dispatchPhase: 'NOT_SENT_FAILED' } },
    });
  });
});
