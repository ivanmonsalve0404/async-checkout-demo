import { createHash } from 'node:crypto';
import {
  type GetCommand,
  type QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import type { Checkout, Delivery, Transaction } from '../../domain/checkout/checkout';
import { DynamoDbCheckoutRepository } from './dynamodb-checkout.repository';

const now = '2026-08-15T12:00:00.000Z';
const later = '2026-08-15T12:01:00.000Z';
const reconciliationCheck = (nextCheckAt = later, attempts = 1) => ({
  attempts,
  lastCheckedAt: nextCheckAt,
  nextCheckAt,
});

const checkoutId = 'checkout_demo_001';
const transactionId = 'transaction_demo_001';
const keyHash = 'idem_hash_synthetic_000000000000000000000001';
const semanticHash = 'semantic_hash_synthetic_0000000000000000001';

const checkout: Checkout = {
  checkoutId,
  status: 'READY',
  version: 3,
  capabilityHash: 'capability_hash_synthetic_000000000000001',
  productId: 'product-demo-001',
  quote: {
    quoteId: 'quote_demo_001',
    version: 1,
    productId: 'product-demo-001',
    quantity: 1,
    subtotal: { amountInCents: 2_500_000, currency: 'COP' },
    baseFee: { amountInCents: 200_000, currency: 'COP' },
    deliveryFee: { amountInCents: 500_000, currency: 'COP' },
    total: { amountInCents: 3_200_000, currency: 'COP' },
    expiresAt: later,
  },
  customer: {
    customerId: 'customer_demo_001',
    checkoutId,
    version: 2,
    fullName: 'Persona Sintética',
    email: 'persona@example.test',
    phone: '+570000000000',
  },
  deliveryDetails: {
    checkoutId,
    version: 3,
    addressLine1: 'Calle de prueba 1',
    city: 'Bogotá',
    region: 'Bogotá D.C.',
  },
  expiresAt: later,
};

const transaction: Transaction = {
  transactionId,
  checkoutId,
  providerReference: 'reference_transaction_demo_001',
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
  nextCheckAt: now,
  attempts: 0,
  amountInCents: 3_200_000,
  currency: 'COP',
  effectsApplied: false,
};

const acknowledgedApproved: Transaction = {
  ...transaction,
  providerId: 'provider_synthetic_001',
  providerStatus: 'APPROVED',
  dispatchPhase: 'ACKNOWLEDGED',
};

const submission = {
  transactionId,
  statusUrl: '/api/v1/transactions/' + transactionId,
  submissionState: 'ACCEPTED' as const,
  acceptedAt: now,
};

const lookupHash = (value: string): string =>
  createHash('sha256')
    .update('test-only|' + value)
    .digest('base64url');

const lockPk = (kind: 'TRANSACTION' | 'PROVIDER' | 'DELIVERY', value: string): string =>
  'UNIQUE#' + kind + '#' + lookupHash(kind + '|' + value);

const lockItem = (
  kind: 'TRANSACTION' | 'PROVIDER' | 'DELIVERY',
  value: string,
  targetTransactionId = transactionId,
) => ({
  PK: lockPk(kind, value),
  SK: 'LOCK',
  itemType: 'UNIQUE_LOCK',
  kind,
  checkoutId,
  transactionId: targetTransactionId,
  schemaVersion: 1,
});

const checkoutItems = (value: Checkout = checkout): Record<string, unknown>[] => {
  const { quote, customer, deliveryDetails, ...meta } = value;
  return [
    {
      ...meta,
      PK: 'CHECKOUT#' + value.checkoutId,
      SK: 'META',
      itemType: 'CHECKOUT',
      quoteId: quote.quoteId,
      schemaVersion: 1,
    },
    {
      ...quote,
      PK: 'CHECKOUT#' + value.checkoutId,
      SK: 'QUOTE#' + quote.quoteId,
      itemType: 'QUOTE',
      schemaVersion: 1,
    },
    ...(customer === undefined
      ? []
      : [
          {
            ...customer,
            PK: 'CHECKOUT#' + value.checkoutId,
            SK: 'CUSTOMER',
            itemType: 'CUSTOMER',
            schemaVersion: 1,
          },
        ]),
    ...(deliveryDetails === undefined
      ? []
      : [
          {
            ...deliveryDetails,
            PK: 'CHECKOUT#' + value.checkoutId,
            SK: 'DELIVERY_DETAILS',
            itemType: 'DELIVERY_DETAILS',
            schemaVersion: 1,
          },
        ]),
  ];
};

const paymentItem = (
  overrides: Partial<Transaction> = {},
  storedKeyHash = keyHash,
): Record<string, unknown> => {
  const value = { ...transaction, ...overrides };
  return {
    ...value,
    ...(value.paymentStatus === 'PENDING' &&
    value.nextCheckAt !== undefined &&
    (value.dispatchPhase === 'NOT_SENT' ||
      value.dispatchPhase === 'NOT_SENT_FAILED' ||
      value.dispatchPhase === 'SENDING' ||
      value.dispatchPhase === 'ACKNOWLEDGED' ||
      value.dispatchPhase === 'UNKNOWN')
      ? {
          GSI1PK: 'RECON#DUE',
          GSI1SK: value.nextCheckAt + '#' + value.transactionId,
        }
      : {}),
    PK: 'CHECKOUT#' + value.checkoutId,
    SK: 'PAYMENT#' + value.transactionId,
    itemType: 'PAYMENT',
    idempotencyKeyHash: storedKeyHash,
    schemaVersion: 1,
  };
};
const reconciliationProjection = (overrides: Partial<Transaction> = {}) => {
  const item = paymentItem(overrides);
  return {
    PK: item.PK,
    SK: item.SK,
    checkoutId: item.checkoutId,
    transactionId: item.transactionId,
    dispatchPhase: item.dispatchPhase,
    paymentStatus: item.paymentStatus,
  };
};

const reservationItem = (status: 'ACTIVE' | 'CONSUMED' | 'RELEASED' = 'ACTIVE') => ({
  PK: 'CHECKOUT#' + checkoutId,
  SK: 'RESERVATION#' + transactionId,
  itemType: 'RESERVATION',
  reservationId: transactionId,
  checkoutId,
  transactionId,
  productId: checkout.productId,
  quantity: 1,
  status,
  expiresAt: later,
  updatedAt: now,
  schemaVersion: 1,
});

const idempotencyItem = (hash = semanticHash) => ({
  PK: 'CHECKOUT#' + checkoutId,
  SK: 'IDEMPOTENCY#SUBMIT_PAYMENT#' + keyHash,
  itemType: 'IDEMPOTENCY',
  operation: 'SUBMIT_PAYMENT',
  keyHash,
  semanticHash: hash,
  status: 'IN_PROGRESS',
  checkoutId,
  transactionId,
  submission,
  schemaVersion: 1,
});

const transactionCanceled = (conditionalIndex: number) =>
  Object.assign(new Error('sanitized'), {
    name: 'TransactionCanceledException',
    CancellationReasons: Array.from({ length: 8 }, (_, index) => ({
      Code: index === conditionalIndex ? 'ConditionalCheckFailed' : 'None',
    })),
  });

const conditionalFailure = Object.assign(new Error('sanitized'), {
  name: 'ConditionalCheckFailedException',
});

type Response = Record<string, unknown> | Error;
type Command = GetCommand | QueryCommand | TransactWriteCommand | UpdateCommand;

const setup = (responses: readonly Response[]) => {
  let index = 0;
  const send = jest.fn<Promise<Response | undefined>, [Command]>(async () => {
    const response = responses[index++];
    if (response instanceof Error) throw response;
    return response;
  });
  const client = { send } as unknown as DynamoDBDocumentClient;
  return {
    repository: new DynamoDbCheckoutRepository(
      client,
      'catalog-local',
      'checkout-local',
      lookupHash,
    ),
    send,
  };
};

const submittedPayment = {
  checkoutId,
  capabilityHash: checkout.capabilityHash,
  expectedVersion: checkout.version,
  keyHash,
  semanticHash,
  transaction,
  submission,
};

describe('DynamoDbCheckoutRepository', () => {
  it('creates DBITEM-04/07 atomically and assembles an authorized checkout partition', async () => {
    const { repository, send } = setup([{}, { Items: checkoutItems() }]);

    await expect(repository.create(checkout)).resolves.toEqual({ ok: true, value: checkout });
    await expect(repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: true,
      value: checkout,
    });

    const create = send.mock.calls[0]?.[0] as unknown as TransactWriteCommand;
    expect(create).toBeInstanceOf(TransactWriteCommand);
    expect(create.input.TransactItems).toHaveLength(4);
    expect(create.input.TransactItems?.map((item) => item.Put?.Item?.itemType)).toEqual([
      'CHECKOUT',
      'QUOTE',
      'CUSTOMER',
      'DELIVERY_DETAILS',
    ]);
    const read = send.mock.calls[1]?.[0] as unknown as QueryCommand;
    expect(read.input).toMatchObject({
      TableName: 'checkout-local',
      ConsistentRead: true,
      ExpressionAttributeValues: { ':pk': 'CHECKOUT#' + checkoutId },
    });
  });

  it('returns missing and rejects malformed checkout records without leaking storage data', async () => {
    const { repository } = setup([
      { Items: [] },
      { Items: [{ PK: 'CHECKOUT#' + checkoutId, SK: 'META', itemType: 'CHECKOUT' }] },
      new Error('private database detail'),
    ]);

    await expect(repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: true,
      value: null,
    });
    await expect(repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
    await expect(repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
  });

  it('updates customer and delivery with a version/capability CAS', async () => {
    const customer = {
      customerId: 'customer_demo_002',
      checkoutId,
      fullName: 'Otra Persona Sintética',
      email: 'otra@example.test',
      phone: '+570000000001',
    };
    const details = {
      checkoutId,
      addressLine1: 'Carrera sintética 2',
      city: 'Bogotá',
      region: 'Bogotá D.C.',
    };
    const first = setup([{ Items: checkoutItems() }, {}]);
    const customerResult = await first.repository.replaceCustomer(
      checkoutId,
      checkout.capabilityHash,
      checkout.version,
      customer,
    );
    expect(customerResult).toMatchObject({
      ok: true,
      value: { version: 4, customer: { version: 4 } },
    });
    const customerWrite = first.send.mock.calls[1]?.[0] as unknown as TransactWriteCommand;
    expect(customerWrite.input.TransactItems).toHaveLength(2);
    expect(customerWrite.input.TransactItems?.[0]?.Update?.ConditionExpression).toContain(
      '#capabilityHash = :capabilityHash',
    );

    const second = setup([{ Items: checkoutItems() }, {}]);
    const deliveryResult = await second.repository.replaceDeliveryDetails(
      checkoutId,
      checkout.capabilityHash,
      checkout.version,
      details,
    );
    expect(deliveryResult).toMatchObject({
      ok: true,
      value: { version: 4, deliveryDetails: { version: 4 } },
    });
    const deliveryWrite = second.send.mock.calls[1]?.[0] as unknown as TransactWriteCommand;
    expect(deliveryWrite.input.TransactItems?.[1]?.Put?.Item?.itemType).toBe('DELIVERY_DETAILS');
  });

  it('maps checkout CAS cancellation to version conflict and blocks a hidden capability', async () => {
    const advanced = { ...checkout, version: checkout.version + 1 };
    const versioned = setup([
      { Items: checkoutItems() },
      transactionCanceled(0),
      { Items: checkoutItems(advanced) },
    ]);
    await expect(
      versioned.repository.replaceCustomer(checkoutId, checkout.capabilityHash, checkout.version, {
        customerId: 'customer_demo_003',
        checkoutId,
        fullName: 'Persona Sintética',
        email: 'persona3@example.test',
        phone: '+570000000003',
      }),
    ).resolves.toEqual({ ok: false, error: { code: 'VERSION_MISMATCH' } });

    const forbidden = setup([{ Items: checkoutItems() }]);
    await expect(
      forbidden.repository.replaceDeliveryDetails(
        checkoutId,
        'different_capability_hash_000000000000000',
        checkout.version,
        {
          checkoutId,
          addressLine1: 'Dirección sintética',
          city: 'Bogotá',
          region: 'Bogotá D.C.',
        },
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'CHECKOUT_NOT_FOUND' } });
    expect(forbidden.send).toHaveBeenCalledTimes(1);
  });

  it('returns idempotency MISS, conflict and the original response snapshot on replay', async () => {
    const miss = setup([{ Item: undefined }]);
    await expect(
      miss.repository.findIdempotency({ checkoutId, keyHash, semanticHash }),
    ).resolves.toEqual({ ok: true, value: null });

    const conflict = setup([{ Item: idempotencyItem('different_semantic_hash') }]);
    await expect(
      conflict.repository.findIdempotency({ checkoutId, keyHash, semanticHash }),
    ).resolves.toEqual({ ok: false, error: { code: 'IDEMPOTENCY_CONFLICT' } });

    const replay = setup([
      { Item: idempotencyItem() },
      { Items: checkoutItems() },
      { Item: paymentItem() },
    ]);
    await expect(
      replay.repository.findIdempotency({ checkoutId, keyHash, semanticHash }),
    ).resolves.toEqual({
      ok: true,
      value: {
        kind: 'REPLAY',
        checkout,
        transaction,
        submission,
      },
    });
  });

  it('prepares stock, checkout, payment, reservation, idempotency and lookup in one transaction', async () => {
    const { repository, send } = setup([{ Item: undefined }, { Items: checkoutItems() }, {}]);

    await expect(repository.preparePayment(submittedPayment)).resolves.toMatchObject({
      ok: true,
      value: {
        kind: 'CREATED',
        checkout: { status: 'PAYMENT_PENDING', version: 4 },
        transaction,
        submission,
      },
    });

    const command = send.mock.calls[2]?.[0] as unknown as TransactWriteCommand;
    expect(command).toBeInstanceOf(TransactWriteCommand);
    expect(command.input.TransactItems).toHaveLength(6);
    expect(command.input.TransactItems?.[0]?.Update).toMatchObject({
      TableName: 'catalog-local',
      ConditionExpression:
        'attribute_exists(PK) AND #active = :active AND #available >= :one AND #reserved < #onHand',
    });
    expect(
      command.input.TransactItems?.slice(1).every((item) => {
        const write = item.Put ?? item.Update;
        return write?.TableName === 'checkout-local';
      }),
    ).toBe(true);
    const pendingPayment = command.input.TransactItems?.[2]?.Put?.Item;
    expect(pendingPayment).toMatchObject({
      acceptanceEvidence: transaction.acceptanceEvidence,
      dispatchPhase: 'NOT_SENT',
      GSI1PK: 'RECON#DUE',
      GSI1SK: now + '#' + transactionId,
    });
    expect(Object.keys(pendingPayment?.acceptanceEvidence ?? {})).toEqual([
      'termsVersion',
      'termsContractHash',
      'personalDataVersion',
      'personalDataContractHash',
      'acceptedAt',
    ]);

    const serialized = JSON.stringify(command.input).toLowerCase();
    expect(serialized).not.toContain('paymentmethodtoken');
    expect(serialized).not.toContain('cvc');
    expect(serialized).not.toContain('pan');
  });

  it('maps an atomic stock cancellation to OUT_OF_STOCK with no partial fallback writes', async () => {
    const { repository, send } = setup([
      { Item: undefined },
      { Items: checkoutItems() },
      transactionCanceled(0),
      { Item: undefined },
    ]);

    await expect(repository.preparePayment(submittedPayment)).resolves.toEqual({
      ok: false,
      error: { code: 'OUT_OF_STOCK' },
    });
    expect(
      send.mock.calls.filter(([command]) => command instanceof TransactWriteCommand),
    ).toHaveLength(1);
  });

  it('claims dispatch once and returns NOT_LEADER after the phase advances', async () => {
    const sending = {
      ...transaction,
      dispatchPhase: 'SENDING' as const,
      nextCheckAt: later,
      updatedAt: later,
    };
    const claimed = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
      { Attributes: paymentItem(sending) },
    ]);
    await expect(claimed.repository.claimDispatch(transactionId, later, later)).resolves.toEqual({
      ok: true,
      value: { kind: 'CLAIMED', transaction: sending },
    });
    const update = claimed.send.mock.calls[2]?.[0] as unknown as UpdateCommand;
    expect(update.input.ConditionExpression).toBe(
      '#dispatchPhase = :notSent AND #paymentStatus = :pending',
    );
    expect(update.input.UpdateExpression).toContain('GSI1PK = :gsi1pk');
    expect(update.input.ExpressionAttributeValues).toMatchObject({
      ':gsi1sk': later + '#' + transactionId,
    });

    const loser = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(sending) },
    ]);
    await expect(loser.repository.claimDispatch(transactionId, later, later)).resolves.toEqual({
      ok: true,
      value: { kind: 'NOT_LEADER', transaction: sending },
    });
    expect(loser.send).toHaveBeenCalledTimes(2);
  });

  it.each(['PENDING', 'APPROVED'] as const)(
    'acknowledges a %s provider result, creates an HMAC lookup and schedules GSI1',
    async (providerStatus) => {
      const sending = {
        ...transaction,
        dispatchPhase: 'SENDING' as const,
        nextCheckAt: later,
      };
      const { repository, send } = setup([
        { Item: lockItem('TRANSACTION', transactionId) },
        { Item: paymentItem(sending) },
        {},
      ]);

      await expect(
        repository.acknowledgeProvider(
          transactionId,
          'provider_synthetic_001',
          providerStatus,
          later,
          reconciliationCheck(),
        ),
      ).resolves.toMatchObject({
        ok: true,
        value: {
          providerId: 'provider_synthetic_001',
          providerStatus,
          dispatchPhase: 'ACKNOWLEDGED',
          nextCheckAt: later,
        },
      });

      const command = send.mock.calls[2]?.[0] as unknown as TransactWriteCommand;
      expect(command.input.TransactItems).toHaveLength(2);
      expect(command.input.TransactItems?.[0]?.Update?.UpdateExpression).toContain(
        'GSI1PK = :gsi1pk',
      );
      const lookup = command.input.TransactItems?.[1]?.Put?.Item;
      expect(lookup?.PK).toBe(lockPk('PROVIDER', 'provider_synthetic_001'));
      expect(String(lookup?.PK)).not.toContain('provider_synthetic_001');
    },
  );

  it('rejects a providerId lock already owned by another transaction', async () => {
    const sending: Transaction = {
      ...transaction,
      dispatchPhase: 'SENDING',
      nextCheckAt: later,
    };
    const { repository, send } = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(sending) },
      transactionCanceled(1),
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(sending) },
    ]);

    await expect(
      repository.acknowledgeProvider(
        transactionId,
        'provider_owned_elsewhere_001',
        'APPROVED',
        later,
        reconciliationCheck(),
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'FINAL_STATE_CONFLICT' } });

    const writes = send.mock.calls
      .map(([command]) => command)
      .filter((command) => command instanceof TransactWriteCommand);
    expect(writes).toHaveLength(1);
    const providerLock = writes[0]?.input.TransactItems?.[1]?.Put;
    expect(providerLock?.ConditionExpression).toBe(
      'attribute_not_exists(PK) OR #transactionId = :transactionId',
    );
  });

  it('marks an uncertain outcome without erasing the last provider status', async () => {
    const acknowledged: Transaction = {
      ...transaction,
      providerId: 'provider_synthetic_001',
      providerStatus: 'PENDING',
      dispatchPhase: 'ACKNOWLEDGED',
    };
    const unknown: Transaction = {
      ...acknowledged,
      dispatchPhase: 'UNKNOWN',
      recoveryCode: 'PROVIDER_OUTCOME_UNKNOWN',
      nextCheckAt: later,
      attempts: 1,
      lastCheckedAt: later,
      updatedAt: later,
    };
    const { repository, send } = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(acknowledged) },
      { Attributes: paymentItem(unknown) },
    ]);

    await expect(
      repository.markUnknown(transactionId, later, reconciliationCheck()),
    ).resolves.toEqual({
      ok: true,
      value: unknown,
    });
    const update = send.mock.calls[2]?.[0] as unknown as UpdateCommand;
    expect(update.input.UpdateExpression).not.toContain('#providerStatus');
    expect(update.input.UpdateExpression).toContain('GSI1PK = :gsi1pk');
  });

  it('recovers an expired SENDING candidate and skips a concurrent lease loser', async () => {
    const due = {
      ...transaction,
      dispatchPhase: 'SENDING' as const,
    };
    const { repository, send } = setup([
      {
        Items: [
          reconciliationProjection(due),
          reconciliationProjection({ ...due, transactionId: 'transaction_demo_002' }),
        ],
      },
      { Item: paymentItem(due) },
      { Attributes: paymentItem({ ...due, nextCheckAt: later }) },
      { Item: paymentItem({ ...due, transactionId: 'transaction_demo_002' }) },
      conditionalFailure,
    ]);

    await expect(repository.claimDue(now, later, 999)).resolves.toEqual({
      ok: true,
      value: [{ ...due, nextCheckAt: later }],
    });
    const query = send.mock.calls[0]?.[0] as unknown as QueryCommand;
    expect(query.input).toMatchObject({
      IndexName: 'GSI1-Reconcile',
      Limit: 10,
      ConsistentRead: false,
    });
    const claim = send.mock.calls[2]?.[0] as unknown as UpdateCommand;
    expect(claim.input.ConditionExpression).toContain('#leaseUntil < :now');
    expect(claim.input.UpdateExpression).toContain('GSI1SK = :gsi1sk');
    expect(claim.input.ConditionExpression).toContain('#dispatchPhase = :expectedDispatchPhase');
    expect(claim.input.ExpressionAttributeValues?.[':expectedDispatchPhase']).toBe('SENDING');
    expect(claim.input.ExpressionAttributeValues).not.toHaveProperty(':notSentFailed');
  });

  it('atomically converts an expired NOT_SENT candidate into proven NOT_SENT_FAILED', async () => {
    const failed: Transaction = {
      ...transaction,
      dispatchPhase: 'NOT_SENT_FAILED',
      nextCheckAt: later,
    };
    const { repository, send } = setup([
      { Items: [reconciliationProjection()] },
      { Item: paymentItem() },
      { Attributes: paymentItem(failed) },
    ]);

    await expect(repository.claimDue(now, later, 1)).resolves.toEqual({
      ok: true,
      value: [failed],
    });

    const claim = send.mock.calls[2]?.[0] as unknown as UpdateCommand;
    expect(claim.input.ConditionExpression).toContain('#dispatchPhase = :expectedDispatchPhase');
    expect(claim.input.ExpressionAttributeValues).toMatchObject({
      ':expectedDispatchPhase': 'NOT_SENT',
      ':notSentFailed': 'NOT_SENT_FAILED',
    });
    expect(claim.input.UpdateExpression).toContain('#dispatchPhase = :notSentFailed');
  });

  it('resolves transaction/provider/delivery IDs only through hashed unique locks', async () => {
    const providerTransaction = {
      ...transaction,
      providerId: 'provider_synthetic_001',
      providerStatus: 'PENDING' as const,
      dispatchPhase: 'ACKNOWLEDGED' as const,
    };
    const provider = setup([
      { Item: lockItem('PROVIDER', 'provider_synthetic_001') },
      { Item: paymentItem(providerTransaction) },
    ]);
    await expect(
      provider.repository.findTransactionByProviderId('provider_synthetic_001'),
    ).resolves.toEqual({ ok: true, value: providerTransaction });
    const providerLookup = provider.send.mock.calls[0]?.[0] as unknown as GetCommand;
    expect(String(providerLookup.input.Key?.PK)).not.toContain('provider_synthetic_001');

    const deliveryId = 'delivery_' + transactionId;
    const delivery: Delivery = {
      deliveryId,
      checkoutId,
      transactionId,
      status: 'CREATED',
      destination: {
        addressLine1: 'Calle sintética 1',
        city: 'Bogotá',
        region: 'Bogotá D.C.',
      },
      createdAt: later,
      updatedAt: later,
    };
    const storedDelivery = {
      ...delivery,
      PK: 'CHECKOUT#' + checkoutId,
      SK: 'DELIVERY#' + deliveryId,
      itemType: 'DELIVERY',
      schemaVersion: 1,
    };
    const found = setup([{ Item: lockItem('DELIVERY', deliveryId) }, { Item: storedDelivery }]);
    await expect(found.repository.findDelivery(deliveryId)).resolves.toEqual({
      ok: true,
      value: delivery,
    });
  });

  it('deduplicates webhook hashes conditionally without persisting a raw event', async () => {
    const fresh = setup([{}]);
    await expect(fresh.repository.recordWebhook('event_hash_synthetic')).resolves.toEqual({
      ok: true,
      value: 'NEW',
    });

    const duplicate = setup([transactionCanceled(0)]);
    await expect(duplicate.repository.recordWebhook('event_hash_synthetic')).resolves.toEqual({
      ok: true,
      value: 'DUPLICATE',
    });
  });

  it('finalizes APPROVED in one cross-table transaction without stale inventory snapshots', async () => {
    const { nextCheckAt: ignoredNext, ...pendingBase } = acknowledgedApproved;
    void ignoredNext;
    const approved: Transaction = {
      ...pendingBase,
      paymentStatus: 'APPROVED',
      providerStatus: 'APPROVED',
      dispatchPhase: 'ACKNOWLEDGED',
      reservationStatus: 'CONSUMED',
      integrityStatus: 'OK',
      deliveryId: 'delivery_' + transactionId,
      effectsApplied: true,
      updatedAt: later,
    };
    const { repository, send } = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(acknowledgedApproved) },
      { Items: checkoutItems() },
      { Item: reservationItem() },
      {},
    ]);

    await expect(
      repository.finalize(transactionId, 'APPROVED', 'APPROVED', undefined, later),
    ).resolves.toEqual({ ok: true, value: approved });

    const command = send.mock.calls[4]?.[0] as unknown as TransactWriteCommand;
    expect(command.input.TransactItems).toHaveLength(7);
    const paymentUpdate = command.input.TransactItems?.[0]?.Update;
    expect(paymentUpdate?.ConditionExpression).toContain('#dispatchPhase = :expectedDispatchPhase');
    expect(paymentUpdate?.ConditionExpression).toContain('#providerId = :expectedProviderId');
    expect(paymentUpdate?.ConditionExpression).toContain(
      '#providerStatus = :expectedProviderStatus',
    );
    expect(paymentUpdate?.ExpressionAttributeValues).toMatchObject({
      ':expectedDispatchPhase': 'ACKNOWLEDGED',
      ':expectedProviderId': 'provider_synthetic_001',
      ':expectedProviderStatus': 'APPROVED',
    });
    const inventory = command.input.TransactItems?.[2]?.Update;
    expect(inventory?.TableName).toBe('catalog-local');
    expect(inventory?.ConditionExpression).toBe('#reserved >= :one AND #onHand >= :one');
    expect(inventory?.ExpressionAttributeValues).not.toHaveProperty(':productVersion');
    expect(inventory?.ExpressionAttributeValues).not.toHaveProperty(':available');
    expect(command.input.TransactItems?.[3]?.Put?.Item?.itemType).toBe('DELIVERY');
    expect(command.input.TransactItems?.[4]?.Put?.Item?.kind).toBe('DELIVERY');
  });

  it('rejects an APPROVED fulfillment when the provider ACK changes after the read', async () => {
    const regressed: Transaction = {
      ...acknowledgedApproved,
      providerStatus: 'PENDING',
    };
    const { repository, send } = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(acknowledgedApproved) },
      { Items: checkoutItems() },
      { Item: reservationItem() },
      transactionCanceled(0),
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(regressed) },
    ]);

    await expect(
      repository.finalize(transactionId, 'APPROVED', 'APPROVED', undefined, later),
    ).resolves.toEqual({ ok: false, error: { code: 'FINAL_STATE_CONFLICT' } });

    const transactions = send.mock.calls
      .map(([command]) => command)
      .filter((command) => command instanceof TransactWriteCommand);
    expect(transactions).toHaveLength(1);
    expect(transactions[0]?.input.TransactItems?.[0]?.Update?.ConditionExpression).toContain(
      '#providerStatus = :expectedProviderStatus',
    );
  });

  it('replays the same approved final without a second inventory or delivery write', async () => {
    const approved = {
      ...acknowledgedApproved,
      paymentStatus: 'APPROVED' as const,
      providerStatus: 'APPROVED' as const,
      dispatchPhase: 'ACKNOWLEDGED' as const,
      reservationStatus: 'CONSUMED' as const,
      deliveryId: 'delivery_' + transactionId,
      effectsApplied: true,
      updatedAt: later,
    };
    const { repository, send } = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(approved) },
    ]);

    await expect(
      repository.finalize(transactionId, 'APPROVED', 'APPROVED', undefined, later),
    ).resolves.toEqual({ ok: true, value: approved });
    expect(
      send.mock.calls.filter(([command]) => command instanceof TransactWriteCommand),
    ).toHaveLength(0);
  });

  it('records APPROVED_INVENTORY_CONFLICT after an inventory condition loses atomically', async () => {
    const { nextCheckAt: ignoredNext, ...conflictBase } = acknowledgedApproved;
    void ignoredNext;
    const conflict: Transaction = {
      ...conflictBase,
      paymentStatus: 'APPROVED',
      providerStatus: 'APPROVED',
      dispatchPhase: 'ACKNOWLEDGED',
      integrityStatus: 'APPROVED_INVENTORY_CONFLICT',
      recoveryCode: 'STATE_TRANSITION_CONFLICT',
      effectsApplied: false,
      updatedAt: later,
    };
    const { repository, send } = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(acknowledgedApproved) },
      { Items: checkoutItems() },
      { Item: reservationItem() },
      transactionCanceled(2),
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(acknowledgedApproved) },
      {},
    ]);

    await expect(
      repository.finalize(transactionId, 'APPROVED', 'APPROVED', undefined, later),
    ).resolves.toEqual({ ok: true, value: conflict });

    const transactions = send.mock.calls
      .map(([command]) => command)
      .filter((command) => command instanceof TransactWriteCommand);
    expect(transactions).toHaveLength(2);
    expect(transactions[0]?.input.TransactItems).toHaveLength(7);
    expect(transactions[1]?.input.TransactItems).toHaveLength(3);
    expect(transactions[1]?.input.TransactItems?.some((item) => item.Put !== undefined)).toBe(
      false,
    );
  });

  it.each([
    ['DECLINED', 'DECLINED', undefined, 'ACKNOWLEDGED'],
    ['ERROR', null, 'PROVIDER_NOT_SENT', 'NOT_SENT_FAILED'],
  ] as const)(
    'finalizes %s by releasing the reservation with no delivery',
    async (status, providerStatus, recoveryCode, dispatchPhase) => {
      const current: Transaction =
        recoveryCode === 'PROVIDER_NOT_SENT'
          ? { ...transaction, dispatchPhase: 'NOT_SENT_FAILED' }
          : {
              ...transaction,
              providerId: 'provider_declined_001',
              providerStatus: 'DECLINED',
              dispatchPhase: 'ACKNOWLEDGED',
            };
      const { nextCheckAt: ignoredNext, ...pendingBase } = current;
      void ignoredNext;
      const expected: Transaction = {
        ...pendingBase,
        paymentStatus: status,
        providerStatus,
        dispatchPhase,
        reservationStatus: 'RELEASED',
        integrityStatus: 'OK',
        ...(recoveryCode === undefined ? {} : { recoveryCode }),
        effectsApplied: true,
        updatedAt: later,
      };
      const { repository, send } = setup([
        { Item: lockItem('TRANSACTION', transactionId) },
        { Item: paymentItem(current) },
        { Items: checkoutItems() },
        { Item: reservationItem() },
        {},
      ]);

      await expect(
        repository.finalize(transactionId, status, providerStatus, recoveryCode, later),
      ).resolves.toEqual({ ok: true, value: expected });
      const command = send.mock.calls[4]?.[0] as unknown as TransactWriteCommand;
      expect(command.input.TransactItems).toHaveLength(5);
      expect(command.input.TransactItems?.some((item) => item.Put !== undefined)).toBe(false);
      const inventory = command.input.TransactItems?.[2]?.Update;
      expect(inventory?.ConditionExpression).toBe('#reserved >= :one');
      expect(inventory?.UpdateExpression).toContain('#available = #available + :one');
      expect(command.input.TransactItems?.[0]?.Update?.ExpressionAttributeNames).not.toHaveProperty(
        '#deliveryId',
      );
      if (recoveryCode === 'PROVIDER_NOT_SENT') {
        const paymentUpdate = command.input.TransactItems?.[0]?.Update;
        expect(paymentUpdate?.ConditionExpression).toContain(
          '#dispatchPhase = :expectedDispatchPhase',
        );
        expect(paymentUpdate?.ExpressionAttributeValues?.[':expectedDispatchPhase']).toBe(
          'NOT_SENT_FAILED',
        );
      }
    },
  );

  it('refuses PROVIDER_NOT_SENT release while the payment is still raw NOT_SENT', async () => {
    const { repository, send } = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
    ]);

    await expect(
      repository.finalize(transactionId, 'ERROR', null, 'PROVIDER_NOT_SENT', later),
    ).resolves.toEqual({ ok: false, error: { code: 'FINAL_STATE_CONFLICT' } });
    expect(send).toHaveBeenCalledTimes(2);
    expect(
      send.mock.calls.filter(([command]) => command instanceof TransactWriteCommand),
    ).toHaveLength(0);
  });

  it('preserves the original final and records a conflicting later final without effects', async () => {
    const declined: Transaction = {
      ...transaction,
      paymentStatus: 'DECLINED',
      providerStatus: 'DECLINED',
      dispatchPhase: 'ACKNOWLEDGED',
      reservationStatus: 'RELEASED',
      effectsApplied: true,
      updatedAt: later,
    };
    const conflicted: Transaction = {
      ...declined,
      integrityStatus: 'FINAL_STATE_CONFLICT',
      recoveryCode: 'STATE_TRANSITION_CONFLICT',
    };
    const { repository, send } = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(declined) },
      { Attributes: paymentItem(conflicted) },
    ]);

    await expect(
      repository.finalize(transactionId, 'APPROVED', 'APPROVED', undefined, later),
    ).resolves.toEqual({ ok: true, value: conflicted });
    expect(send.mock.calls[2]?.[0]).toBeInstanceOf(UpdateCommand);
    expect(
      send.mock.calls.filter(([command]) => command instanceof TransactWriteCommand),
    ).toHaveLength(0);
  });

  const invalidPaymentRecords: ReadonlyArray<readonly [string, unknown]> = [
    ['non-object', 'invalid'],
    ['item type', { ...paymentItem(), itemType: 'OTHER' }],
    ['schema version', { ...paymentItem(), schemaVersion: 2 }],
    ['transaction id', { ...paymentItem(), transactionId: 1 }],
    ['checkout id', { ...paymentItem(), checkoutId: 1 }],
    ['provider reference', { ...paymentItem(), providerReference: 1 }],
    ['provider id', { ...paymentItem(), providerId: 1 }],
    ['payment status', { ...paymentItem(), paymentStatus: 'OTHER' }],
    ['dispatch phase', { ...paymentItem(), dispatchPhase: 'OTHER' }],
    ['provider status', { ...paymentItem(), providerStatus: 'OTHER' }],
    ['provider status type', { ...paymentItem(), providerStatus: 1 }],
    ['reservation status', { ...paymentItem(), reservationStatus: 'OTHER' }],
    ['integrity status', { ...paymentItem(), integrityStatus: 'OTHER' }],
    ['recovery code', { ...paymentItem(), recoveryCode: 'OTHER' }],
    ['delivery id', { ...paymentItem(), deliveryId: 1 }],
    ['accepted at', { ...paymentItem(), acceptedAt: 1 }],
    ['acceptance evidence missing', { ...paymentItem(), acceptanceEvidence: undefined }],
    [
      'terms contract hash',
      {
        ...paymentItem(),
        acceptanceEvidence: { ...transaction.acceptanceEvidence, termsContractHash: 1 },
      },
    ],
    [
      'personal data contract hash',
      {
        ...paymentItem(),
        acceptanceEvidence: { ...transaction.acceptanceEvidence, personalDataContractHash: 1 },
      },
    ],
    [
      'acceptance evidence with extra data',
      {
        ...paymentItem(),
        acceptanceEvidence: { ...transaction.acceptanceEvidence, termsToken: 'forbidden' },
      },
    ],
    ['updated at', { ...paymentItem(), updatedAt: 1 }],
    ['attempts type', { ...paymentItem(), attempts: '1' }],
    ['fractional attempts', { ...paymentItem(), attempts: 1.5 }],
    ['negative attempts', { ...paymentItem(), attempts: -1 }],
    ['last checked at', { ...paymentItem(), lastCheckedAt: 1 }],
    ['next check', { ...paymentItem(), nextCheckAt: 1 }],
    ['amount type', { ...paymentItem(), amountInCents: '1' }],
    ['fractional amount', { ...paymentItem(), amountInCents: 1.5 }],
    ['negative amount', { ...paymentItem(), amountInCents: -1 }],
    ['currency', { ...paymentItem(), currency: 'USD' }],
    ['effects flag', { ...paymentItem(), effectsApplied: 'false' }],
    ['idempotency hash', { ...paymentItem(), idempotencyKeyHash: 1 }],
  ];

  it.each(invalidPaymentRecords)('rejects a malformed %s payment item', async (_label, item) => {
    const { repository } = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: item },
    ]);
    await expect(repository.findTransaction(transactionId)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
  });

  const invalidLockRecords: ReadonlyArray<readonly [string, unknown]> = [
    ['non-object', null],
    ['item type', { ...lockItem('TRANSACTION', transactionId), itemType: 'OTHER' }],
    ['kind', { ...lockItem('TRANSACTION', transactionId), kind: 'PROVIDER' }],
    ['sort key', { ...lockItem('TRANSACTION', transactionId), SK: 'OTHER' }],
    ['schema version', { ...lockItem('TRANSACTION', transactionId), schemaVersion: 2 }],
    ['checkout id', { ...lockItem('TRANSACTION', transactionId), checkoutId: 1 }],
    ['transaction id', { ...lockItem('TRANSACTION', transactionId), transactionId: 1 }],
  ];

  it.each(invalidLockRecords)('rejects a malformed %s unique lock', async (_label, item) => {
    const { repository, send } = setup([{ Item: item }]);
    await expect(repository.findTransaction(transactionId)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
    expect(send).toHaveBeenCalledTimes(1);
  });

  const invalidIdempotencyRecords: ReadonlyArray<readonly [string, unknown]> = [
    ['non-object', 'invalid'],
    ['submission object', { ...idempotencyItem(), submission: null }],
    ['item type', { ...idempotencyItem(), itemType: 'OTHER' }],
    ['operation', { ...idempotencyItem(), operation: 'OTHER' }],
    ['schema version', { ...idempotencyItem(), schemaVersion: 2 }],
    ['key hash', { ...idempotencyItem(), keyHash: 1 }],
    ['semantic hash', { ...idempotencyItem(), semanticHash: 1 }],
    ['status', { ...idempotencyItem(), status: 'OTHER' }],
    ['checkout id', { ...idempotencyItem(), checkoutId: 1 }],
    ['transaction id', { ...idempotencyItem(), transactionId: 1 }],
    [
      'submission transaction',
      { ...idempotencyItem(), submission: { ...submission, transactionId: 'other' } },
    ],
    ['status URL', { ...idempotencyItem(), submission: { ...submission, statusUrl: 1 } }],
    [
      'submission state',
      { ...idempotencyItem(), submission: { ...submission, submissionState: 'OTHER' } },
    ],
    ['accepted at', { ...idempotencyItem(), submission: { ...submission, acceptedAt: 1 } }],
  ];

  it.each(invalidIdempotencyRecords)(
    'rejects a malformed %s idempotency record',
    async (_label, item) => {
      const { repository } = setup([{ Item: item }]);
      await expect(
        repository.findIdempotency({ checkoutId, keyHash, semanticHash }),
      ).resolves.toEqual({
        ok: false,
        error: { code: 'REPOSITORY_UNAVAILABLE' },
      });
    },
  );
});

describe('DynamoDbCheckoutRepository critical failure semantics', () => {
  const customerInput = {
    customerId: 'customer_demo_failure',
    checkoutId,
    fullName: 'Persona Sintética',
    email: 'failure@example.test',
    phone: '+570000000099',
  };
  const deliveryInput = {
    checkoutId,
    addressLine1: 'Calle sintética 99',
    city: 'Bogotá',
    region: 'Bogotá D.C.',
  };

  it('writes relation-free checkouts and fails closed on malformed partitions or storage errors', async () => {
    const {
      customer: ignoredCustomer,
      deliveryDetails: ignoredDelivery,
      ...withoutRelations
    } = checkout;
    void ignoredCustomer;
    void ignoredDelivery;
    const relationFree = setup([{}, new Error('synthetic create failure')]);
    await expect(relationFree.repository.create(withoutRelations)).resolves.toEqual({
      ok: true,
      value: withoutRelations,
    });
    await expect(relationFree.repository.create(checkout)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    const undefinedItems = setup([{ Items: undefined }]);
    await expect(undefinedItems.repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: true,
      value: null,
    });

    const malformedMeta = Object.assign(() => undefined, { SK: 'META' });
    const invalidMeta = setup([{ Items: [malformedMeta] }]);
    await expect(invalidMeta.repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    const [meta] = checkoutItems();
    const malformedQuote = Object.assign(() => undefined, {
      SK: 'QUOTE#' + checkout.quote.quoteId,
    });
    const invalidQuote = setup([{ Items: [meta, malformedQuote] }]);
    await expect(invalidQuote.repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    const invalidCustomer = setup([
      {
        Items: checkoutItems().map((item) =>
          item.SK === 'CUSTOMER' ? { ...item, email: 1 } : item,
        ),
      },
    ]);
    await expect(invalidCustomer.repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    const invalidDetails = setup([
      {
        Items: checkoutItems().map((item) =>
          item.SK === 'DELIVERY_DETAILS' ? { ...item, region: 1 } : item,
        ),
      },
    ]);
    await expect(invalidDetails.repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    const minimal = setup([{ Items: checkoutItems(withoutRelations) }]);
    await expect(minimal.repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: true,
      value: withoutRelations,
    });

    const existingDelivery = checkout.deliveryDetails;
    if (existingDelivery === undefined) throw new Error('Expected delivery fixture');
    const withOptionalDelivery: Checkout = {
      ...checkout,
      deliveryDetails: {
        ...existingDelivery,
        addressLine2: 'Interior sintético',
        postalCode: '110111',
        deliveryInstructions: 'Portería sintética',
      },
    };
    const optional = setup([{ Items: checkoutItems(withOptionalDelivery) }]);
    await expect(optional.repository.findCheckout(checkoutId)).resolves.toEqual({
      ok: true,
      value: withOptionalDelivery,
    });
  });

  it('rejects stale, hidden, missing, and active checkout mutations before side effects', async () => {
    const missingCustomer = setup([{ Items: [] }]);
    await expect(
      missingCustomer.repository.replaceCustomer(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        customerInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'CHECKOUT_NOT_FOUND' } });

    const unavailableCustomer = setup([new Error('synthetic read failure')]);
    await expect(
      unavailableCustomer.repository.replaceCustomer(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        customerInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const staleCustomer = setup([{ Items: checkoutItems() }]);
    await expect(
      staleCustomer.repository.replaceCustomer(
        checkoutId,
        checkout.capabilityHash,
        checkout.version - 1,
        customerInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'VERSION_MISMATCH' } });

    const active = { ...checkout, activeTransactionId: transactionId };
    const activeCustomer = setup([{ Items: checkoutItems(active) }]);
    await expect(
      activeCustomer.repository.replaceCustomer(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        customerInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'PAYMENT_ALREADY_IN_PROGRESS' } });

    const { deliveryDetails: ignoredDetails, ...customerWithoutDelivery } = checkout;
    void ignoredDetails;
    const customerDraft = setup([{ Items: checkoutItems(customerWithoutDelivery) }, {}]);
    await expect(
      customerDraft.repository.replaceCustomer(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        customerInput,
      ),
    ).resolves.toMatchObject({ ok: true, value: { status: 'DRAFT' } });

    const missingDelivery = setup([{ Items: [] }]);
    await expect(
      missingDelivery.repository.replaceDeliveryDetails(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        deliveryInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'CHECKOUT_NOT_FOUND' } });

    const unavailableDelivery = setup([new Error('synthetic read failure')]);
    await expect(
      unavailableDelivery.repository.replaceDeliveryDetails(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        deliveryInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const staleDelivery = setup([{ Items: checkoutItems() }]);
    await expect(
      staleDelivery.repository.replaceDeliveryDetails(
        checkoutId,
        checkout.capabilityHash,
        checkout.version - 1,
        deliveryInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'VERSION_MISMATCH' } });

    const activeDelivery = setup([{ Items: checkoutItems(active) }]);
    await expect(
      activeDelivery.repository.replaceDeliveryDetails(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        deliveryInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'PAYMENT_ALREADY_IN_PROGRESS' } });

    const { customer: ignoredCustomer, ...deliveryWithoutCustomer } = checkout;
    void ignoredCustomer;
    const deliveryDraft = setup([{ Items: checkoutItems(deliveryWithoutCustomer) }, {}]);
    await expect(
      deliveryDraft.repository.replaceDeliveryDetails(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        deliveryInput,
      ),
    ).resolves.toMatchObject({ ok: true, value: { status: 'DRAFT' } });
  });

  it('classifies checkout CAS failures from a fresh consistent read', async () => {
    const unavailable = setup([{ Items: checkoutItems() }, new Error('synthetic write failure')]);
    await expect(
      unavailable.repository.replaceCustomer(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        customerInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const disappeared = setup([{ Items: checkoutItems() }, transactionCanceled(0), { Items: [] }]);
    await expect(
      disappeared.repository.replaceCustomer(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        customerInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'CHECKOUT_NOT_FOUND' } });

    const unchanged = setup([
      { Items: checkoutItems() },
      transactionCanceled(0),
      { Items: checkoutItems() },
    ]);
    await expect(
      unchanged.repository.replaceCustomer(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        customerInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const nowActive = setup([
      { Items: checkoutItems() },
      transactionCanceled(0),
      { Items: checkoutItems({ ...checkout, activeTransactionId: transactionId }) },
    ]);
    await expect(
      nowActive.repository.replaceCustomer(
        checkoutId,
        checkout.capabilityHash,
        checkout.version,
        customerInput,
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'PAYMENT_ALREADY_IN_PROGRESS' } });
  });

  it('prepares payment only after replay, capability, version, and stock checks', async () => {
    const idempotencyUnavailable = setup([new Error('synthetic idempotency read')]);
    await expect(
      idempotencyUnavailable.repository.preparePayment(submittedPayment),
    ).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    const replay = setup([
      { Item: idempotencyItem() },
      { Items: checkoutItems() },
      { Item: paymentItem() },
    ]);
    await expect(replay.repository.preparePayment(submittedPayment)).resolves.toMatchObject({
      ok: true,
      value: { kind: 'REPLAY' },
    });

    const missing = setup([{ Item: undefined }, { Items: [] }]);
    await expect(missing.repository.preparePayment(submittedPayment)).resolves.toEqual({
      ok: false,
      error: { code: 'CHECKOUT_NOT_FOUND' },
    });

    const hidden = setup([{ Item: undefined }, { Items: checkoutItems() }]);
    await expect(
      hidden.repository.preparePayment({
        ...submittedPayment,
        capabilityHash: 'different_capability_hash_000000000000000',
      }),
    ).resolves.toEqual({ ok: false, error: { code: 'CHECKOUT_NOT_FOUND' } });

    const stale = setup([{ Item: undefined }, { Items: checkoutItems() }]);
    await expect(
      stale.repository.preparePayment({
        ...submittedPayment,
        expectedVersion: checkout.version - 1,
      }),
    ).resolves.toEqual({ ok: false, error: { code: 'VERSION_MISMATCH' } });

    const active = setup([
      { Item: undefined },
      { Items: checkoutItems({ ...checkout, activeTransactionId: transactionId }) },
    ]);
    await expect(active.repository.preparePayment(submittedPayment)).resolves.toEqual({
      ok: false,
      error: { code: 'PAYMENT_ALREADY_IN_PROGRESS' },
    });

    const unavailableWrite = setup([
      { Item: undefined },
      { Items: checkoutItems() },
      new Error('synthetic write failure'),
    ]);
    await expect(unavailableWrite.repository.preparePayment(submittedPayment)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    const failedReplayRead = setup([
      { Item: undefined },
      { Items: checkoutItems() },
      transactionCanceled(2),
      new Error('synthetic replay failure'),
    ]);
    await expect(failedReplayRead.repository.preparePayment(submittedPayment)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    const wonByReplay = setup([
      { Item: undefined },
      { Items: checkoutItems() },
      transactionCanceled(2),
      { Item: idempotencyItem() },
      { Items: checkoutItems() },
      { Item: paymentItem() },
    ]);
    await expect(wonByReplay.repository.preparePayment(submittedPayment)).resolves.toMatchObject({
      ok: true,
      value: { kind: 'REPLAY' },
    });

    const checkoutCondition = setup([
      { Item: undefined },
      { Items: checkoutItems() },
      transactionCanceled(1),
      { Item: undefined },
      { Items: checkoutItems() },
    ]);
    await expect(checkoutCondition.repository.preparePayment(submittedPayment)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    const unknownCancellation = setup([
      { Item: undefined },
      { Items: checkoutItems() },
      transactionCanceled(2),
      { Item: undefined },
    ]);
    await expect(unknownCancellation.repository.preparePayment(submittedPayment)).resolves.toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
  });

  it('keeps dispatch, provider acknowledgement, and unknown marking fail closed', async () => {
    const missingDispatch = setup([{ Item: undefined }]);
    await expect(
      missingDispatch.repository.claimDispatch(transactionId, now, later),
    ).resolves.toEqual({ ok: false, error: { code: 'CHECKOUT_NOT_FOUND' } });

    const { nextCheckAt: ignoredNextCheck, ...terminalBase } = transaction;
    void ignoredNextCheck;
    const terminal: Transaction = {
      ...terminalBase,
      paymentStatus: 'APPROVED',
      reservationStatus: 'CONSUMED',
      effectsApplied: true,
    };
    const terminalDispatch = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(terminal) },
    ]);
    await expect(
      terminalDispatch.repository.claimDispatch(transactionId, now, later),
    ).resolves.toMatchObject({ ok: true, value: { kind: 'NOT_LEADER' } });

    const malformedDispatch = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
      { Attributes: {} },
    ]);
    await expect(
      malformedDispatch.repository.claimDispatch(transactionId, now, later),
    ).resolves.toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const unavailableDispatch = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
      new Error('synthetic update failure'),
    ]);
    await expect(
      unavailableDispatch.repository.claimDispatch(transactionId, now, later),
    ).resolves.toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const lostDispatch = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
      conditionalFailure,
      { Item: undefined },
    ]);
    await expect(lostDispatch.repository.claimDispatch(transactionId, now, later)).resolves.toEqual(
      {
        ok: false,
        error: { code: 'CHECKOUT_NOT_FOUND' },
      },
    );

    const missingAcknowledge = setup([{ Item: undefined }]);
    await expect(
      missingAcknowledge.repository.acknowledgeProvider(
        transactionId,
        'provider_synthetic_001',
        'PENDING',
        now,
        reconciliationCheck(),
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'CHECKOUT_NOT_FOUND' } });

    const mismatchedProvider = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem({ providerId: 'provider_other' }) },
    ]);
    await expect(
      mismatchedProvider.repository.acknowledgeProvider(
        transactionId,
        'provider_synthetic_001',
        'PENDING',
        now,
        reconciliationCheck(),
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'FINAL_STATE_CONFLICT' } });

    const sameTerminal = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem({ ...terminal, providerId: 'provider_synthetic_001' }) },
    ]);
    await expect(
      sameTerminal.repository.acknowledgeProvider(
        transactionId,
        'provider_synthetic_001',
        'APPROVED',
        now,
        reconciliationCheck(),
      ),
    ).resolves.toMatchObject({ ok: true, value: { paymentStatus: 'APPROVED' } });

    const terminalWithoutProvider = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(terminal) },
    ]);
    await expect(
      terminalWithoutProvider.repository.acknowledgeProvider(
        transactionId,
        'provider_synthetic_001',
        'APPROVED',
        now,
        reconciliationCheck(),
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'FINAL_STATE_CONFLICT' } });

    const unavailableAcknowledge = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
      new Error('synthetic transaction failure'),
    ]);
    await expect(
      unavailableAcknowledge.repository.acknowledgeProvider(
        transactionId,
        'provider_synthetic_001',
        'PENDING',
        now,
        reconciliationCheck(),
      ),
    ).resolves.toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const latestTerminal = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
      transactionCanceled(0),
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem({ ...terminal, providerId: 'provider_synthetic_001' }) },
    ]);
    await expect(
      latestTerminal.repository.acknowledgeProvider(
        transactionId,
        'provider_synthetic_001',
        'APPROVED',
        now,
        reconciliationCheck(),
      ),
    ).resolves.toMatchObject({ ok: true, value: { paymentStatus: 'APPROVED' } });

    const missingUnknown = setup([{ Item: undefined }]);
    await expect(
      missingUnknown.repository.markUnknown(transactionId, now, reconciliationCheck()),
    ).resolves.toEqual({ ok: false, error: { code: 'CHECKOUT_NOT_FOUND' } });

    const terminalUnknown = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(terminal) },
    ]);
    await expect(
      terminalUnknown.repository.markUnknown(transactionId, now, reconciliationCheck()),
    ).resolves.toMatchObject({ ok: true, value: { paymentStatus: 'APPROVED' } });

    const malformedUnknown = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
      { Attributes: {} },
    ]);
    await expect(
      malformedUnknown.repository.markUnknown(transactionId, now, reconciliationCheck()),
    ).resolves.toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const unavailableUnknown = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
      new Error('synthetic update failure'),
    ]);
    await expect(
      unavailableUnknown.repository.markUnknown(transactionId, now, reconciliationCheck()),
    ).resolves.toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });

    const settledUnknown = setup([
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem() },
      conditionalFailure,
      { Item: lockItem('TRANSACTION', transactionId) },
      { Item: paymentItem(terminal) },
    ]);
    await expect(
      settledUnknown.repository.markUnknown(transactionId, now, reconciliationCheck()),
    ).resolves.toMatchObject({ ok: true, value: { paymentStatus: 'APPROVED' } });
  });
});
