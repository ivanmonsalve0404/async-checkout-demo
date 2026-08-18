import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import {
  CreateTableCommand,
  DescribeTableCommand,
  DynamoDBClient,
  ListTablesCommand,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import type { Result } from '../../application/result/result';
import type {
  Checkout,
  PaymentStatus,
  PaymentSubmission,
  ProviderStatus,
  Transaction,
} from '../../domain/checkout/checkout';
import { DynamoDbCatalogRepository } from './dynamodb-catalog.repository';
import { DynamoDbCheckoutRepository } from './dynamodb-checkout.repository';
import { createProductSeed } from './product-seed';

const SUITE_NAME = 'DynamoDbCheckoutRepository local integration';
const IMAGE = 'amazon/dynamodb-local:2.6.1';
const RUN_LABEL = 'com.async-checkout.integration-run';
const T0 = '2026-08-15T12:00:00.000Z';
const T1 = '2026-08-15T12:00:01.000Z';
const T2 = '2026-08-15T12:00:02.000Z';
const T3 = '2026-08-15T12:00:30.000Z';
const T4 = '2026-08-15T12:01:00.000Z';
const T5 = '2026-08-15T12:02:00.000Z';
const T6 = '2026-08-15T12:03:00.000Z';
const EXPIRES_AT = '2026-08-16T12:00:00.000Z';

const enabled = process.env.RUN_DYNAMODB_LOCAL_INTEGRATION === '1';
const describeLocal = describe;

const requireLocalEndpoint = (): string => {
  const value = process.env.DYNAMODB_LOCAL_ENDPOINT;
  if (value === undefined) throw new Error('DYNAMODB_LOCAL_ENDPOINT is required');
  const endpoint = new URL(value);
  if (
    endpoint.protocol !== 'http:' ||
    endpoint.hostname !== '127.0.0.1' ||
    endpoint.username !== '' ||
    endpoint.password !== '' ||
    endpoint.pathname !== '/'
  ) {
    throw new Error('Integration endpoint must be an unauthenticated IPv4 loopback HTTP URL');
  }
  return endpoint.toString();
};

let endpoint = enabled ? requireLocalEndpoint() : 'http://127.0.0.1:1/';
const catalogTableName = process.env.DYNAMODB_LOCAL_CATALOG_TABLE ?? 'integration-disabled';
const checkoutTableName = process.env.DYNAMODB_LOCAL_CHECKOUT_TABLE ?? 'integration-disabled';

const lookupHash = (value: string): string =>
  createHash('sha256')
    .update('dynamodb-local-integration|' + value)
    .digest('base64url');

const lockPk = (kind: 'TRANSACTION' | 'PROVIDER' | 'DELIVERY', value: string): string =>
  'UNIQUE#' + kind + '#' + lookupHash(kind + '|' + value);

const valueOf = <T, E>(result: Result<T, E>): T => {
  if (!result.ok) throw new Error(`Expected success, received ${JSON.stringify(result.error)}`);
  return result.value;
};

const makeCheckout = (label: string, productId: string): Checkout => {
  const checkoutId = 'checkout_' + label;
  return {
    checkoutId,
    status: 'READY',
    version: 3,
    capabilityHash: 'capability_hash_' + label.padEnd(32, 'x'),
    productId,
    quote: {
      quoteId: 'quote_' + label,
      version: 1,
      productId,
      quantity: 1,
      subtotal: { amountInCents: 2_500_000, currency: 'COP' },
      baseFee: { amountInCents: 200_000, currency: 'COP' },
      deliveryFee: { amountInCents: 500_000, currency: 'COP' },
      total: { amountInCents: 3_200_000, currency: 'COP' },
      expiresAt: EXPIRES_AT,
    },
    customer: {
      customerId: 'customer_' + label,
      checkoutId,
      version: 3,
      fullName: 'Persona Sintética',
      email: `${label}@example.test`,
      phone: '+570000000000',
    },
    deliveryDetails: {
      checkoutId,
      version: 3,
      addressLine1: 'Calle de prueba 1',
      city: 'Bogotá',
      region: 'Bogotá D.C.',
    },
    expiresAt: EXPIRES_AT,
  };
};

const makeTransaction = (
  checkout: Checkout,
  label: string,
  overrides: Partial<Transaction> = {},
): Transaction => ({
  transactionId: 'transaction_' + label,
  checkoutId: checkout.checkoutId,
  providerReference: 'reference_' + label,
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
    acceptedAt: T0,
  },
  acceptedAt: T0,
  updatedAt: T0,
  attempts: 0,
  nextCheckAt: EXPIRES_AT,
  amountInCents: checkout.quote.total.amountInCents,
  currency: 'COP',
  effectsApplied: false,
  ...overrides,
});

const submissionFor = (transaction: Transaction): PaymentSubmission => ({
  transactionId: transaction.transactionId,
  statusUrl: '/api/v1/transactions/' + transaction.transactionId,
  submissionState: 'ACCEPTED',
  acceptedAt: transaction.acceptedAt,
});

describeLocal(SUITE_NAME, () => {
  let lowLevelClient: DynamoDBClient | null = null;
  let documentClient: DynamoDBDocumentClient;
  let catalogRepository: DynamoDbCatalogRepository;
  let checkoutRepository: DynamoDbCheckoutRepository;

  const connect = (): void => {
    lowLevelClient = new DynamoDBClient({
      endpoint,
      region: 'us-east-1',
      credentials: { accessKeyId: 'local', secretAccessKey: 'local' },
      maxAttempts: 1,
    });
    documentClient = DynamoDBDocumentClient.from(lowLevelClient, {
      marshallOptions: { removeUndefinedValues: true },
    });
    catalogRepository = new DynamoDbCatalogRepository(documentClient, catalogTableName);
    checkoutRepository = new DynamoDbCheckoutRepository(
      documentClient,
      catalogTableName,
      checkoutTableName,
      lookupHash,
    );
  };

  const disconnect = (): void => {
    lowLevelClient?.destroy();
    lowLevelClient = null;
  };

  const waitForHealth = async (): Promise<void> => {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      try {
        if (lowLevelClient === null) throw new Error('client is disconnected');
        await lowLevelClient.send(new ListTablesCommand({ Limit: 1 }));
        return;
      } catch {
        await delay(200);
      }
    }
    throw new Error('DynamoDB Local did not recover after restart');
  };

  const waitForTable = async (tableName: string): Promise<void> => {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const response = await lowLevelClient?.send(
        new DescribeTableCommand({ TableName: tableName }),
      );
      if (response?.Table?.TableStatus === 'ACTIVE') return;
      await delay(50);
    }
    throw new Error(`Table ${tableName} did not become active`);
  };

  const queryCheckoutPartition = async (checkoutId: string): Promise<Record<string, unknown>[]> => {
    const response = await documentClient.send(
      new QueryCommand({
        TableName: checkoutTableName,
        KeyConditionExpression: 'PK = :pk',
        ExpressionAttributeValues: { ':pk': 'CHECKOUT#' + checkoutId },
        ConsistentRead: true,
      }),
    );
    return (response.Items ?? []) as Record<string, unknown>[];
  };

  const getCheckoutItem = async (
    checkoutId: string,
    sortKey: string,
  ): Promise<Record<string, unknown> | undefined> => {
    const response = await documentClient.send(
      new GetCommand({
        TableName: checkoutTableName,
        Key: { PK: 'CHECKOUT#' + checkoutId, SK: sortKey },
        ConsistentRead: true,
      }),
    );
    return response.Item as Record<string, unknown> | undefined;
  };

  const seedProduct = async (productId: string, stock: number): Promise<void> => {
    const seed = createProductSeed(productId, 'http://127.0.0.1', stock);
    const result = await catalogRepository.seedIfAbsent({
      ...seed,
      sku: 'SKU_' + productId.toUpperCase(),
    });
    expect(result).toEqual({ ok: true, value: 'CREATED' });
  };

  const createCheckout = async (label: string, productId: string): Promise<Checkout> => {
    const checkout = makeCheckout(label, productId);
    expect(await checkoutRepository.create(checkout)).toEqual({ ok: true, value: checkout });
    return checkout;
  };

  const prepare = (
    checkout: Checkout,
    transaction: Transaction,
    keyHash = 'key_' + transaction.transactionId,
    semanticHash = 'semantic_' + transaction.transactionId,
    expectedVersion = checkout.version,
  ) =>
    checkoutRepository.preparePayment({
      checkoutId: checkout.checkoutId,
      capabilityHash: checkout.capabilityHash,
      expectedVersion,
      keyHash,
      semanticHash,
      transaction,
      submission: submissionFor(transaction),
    });

  const acknowledge = async (
    transaction: Transaction,
    providerStatus: Exclude<ProviderStatus, null>,
    label: string,
  ): Promise<Transaction> => {
    const claim = valueOf(
      await checkoutRepository.claimDispatch(transaction.transactionId, T1, T3),
    );
    expect(claim.kind).toBe('CLAIMED');
    return valueOf(
      await checkoutRepository.acknowledgeProvider(
        transaction.transactionId,
        'provider_' + label,
        providerStatus,
        T2,
        { attempts: 1, lastCheckedAt: T2, nextCheckAt: EXPIRES_AT },
      ),
    );
  };

  const waitForDueProjection = async (transactionId: string, upper: string): Promise<void> => {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const response = await documentClient.send(
        new QueryCommand({
          TableName: checkoutTableName,
          IndexName: 'GSI1-Reconcile',
          KeyConditionExpression: 'GSI1PK = :due AND GSI1SK <= :upper',
          ExpressionAttributeValues: {
            ':due': 'RECON#DUE',
            ':upper': upper + '#\uffff',
          },
        }),
      );
      if (response.Items?.some((item) => item.transactionId === transactionId)) return;
      await delay(50);
    }
    throw new Error('The due payment did not become visible through GSI1-Reconcile');
  };

  const restartContainer = async (): Promise<void> => {
    const containerId = process.env.DYNAMODB_LOCAL_CONTAINER_ID ?? '';
    const runToken = process.env.DYNAMODB_LOCAL_RUN_TOKEN ?? '';
    if (!/^[a-f0-9]{64}$/u.test(containerId) || runToken.length < 3) {
      throw new Error('Runner did not provide a validated container identity');
    }
    const label = spawnSync(
      'docker',
      ['inspect', '--format', `{{index .Config.Labels "${RUN_LABEL}"}}`, containerId],
      { encoding: 'utf8', windowsHide: true },
    );
    const image = spawnSync('docker', ['inspect', '--format', '{{.Config.Image}}', containerId], {
      encoding: 'utf8',
      windowsHide: true,
    });
    if (label.status !== 0 || label.stdout.trim() !== runToken) {
      throw new Error('Container ownership validation failed before restart');
    }
    if (image.status !== 0 || image.stdout.trim() !== IMAGE) {
      throw new Error('Container image validation failed before restart');
    }
    disconnect();
    const restarted = spawnSync('docker', ['restart', containerId], {
      encoding: 'utf8',
      windowsHide: true,
    });
    if (restarted.status !== 0) throw new Error('Exact DynamoDB Local restart failed');
    const published = spawnSync('docker', ['port', containerId, '8000/tcp'], {
      encoding: 'utf8',
      windowsHide: true,
    });
    const loopback = published.stdout.trim();
    if (published.status !== 0 || !/^127\.0\.0\.1:[0-9]+$/u.test(loopback)) {
      throw new Error('Restarted DynamoDB Local did not publish one exact IPv4 loopback port');
    }
    endpoint = 'http://' + loopback + '/';

    connect();
    await waitForHealth();
  };

  beforeAll(async () => {
    expect(process.env.DYNAMODB_LOCAL_IMAGE).toBe(IMAGE);
    expect(process.env.AWS_EC2_METADATA_DISABLED).toBe('true');
    connect();
    await waitForHealth();
    await lowLevelClient?.send(
      new CreateTableCommand({
        TableName: catalogTableName,
        BillingMode: 'PAY_PER_REQUEST',
        AttributeDefinitions: [
          { AttributeName: 'PK', AttributeType: 'S' },
          { AttributeName: 'SK', AttributeType: 'S' },
        ],
        KeySchema: [
          { AttributeName: 'PK', KeyType: 'HASH' },
          { AttributeName: 'SK', KeyType: 'RANGE' },
        ],
      }),
    );
    await lowLevelClient?.send(
      new CreateTableCommand({
        TableName: checkoutTableName,
        BillingMode: 'PAY_PER_REQUEST',
        AttributeDefinitions: [
          { AttributeName: 'PK', AttributeType: 'S' },
          { AttributeName: 'SK', AttributeType: 'S' },
          { AttributeName: 'GSI1PK', AttributeType: 'S' },
          { AttributeName: 'GSI1SK', AttributeType: 'S' },
          { AttributeName: 'GSI2PK', AttributeType: 'S' },
          { AttributeName: 'GSI2SK', AttributeType: 'S' },
        ],
        KeySchema: [
          { AttributeName: 'PK', KeyType: 'HASH' },
          { AttributeName: 'SK', KeyType: 'RANGE' },
        ],
        GlobalSecondaryIndexes: [
          {
            IndexName: 'GSI1-Reconcile',
            KeySchema: [
              { AttributeName: 'GSI1PK', KeyType: 'HASH' },
              { AttributeName: 'GSI1SK', KeyType: 'RANGE' },
            ],
            Projection: {
              ProjectionType: 'INCLUDE',
              NonKeyAttributes: ['checkoutId', 'transactionId', 'dispatchPhase', 'paymentStatus'],
            },
          },
          {
            IndexName: 'GSI2-PendingAge',
            KeySchema: [
              { AttributeName: 'GSI2PK', KeyType: 'HASH' },
              { AttributeName: 'GSI2SK', KeyType: 'RANGE' },
            ],
            Projection: {
              ProjectionType: 'INCLUDE',
              NonKeyAttributes: ['acceptedAt', 'paymentStatus'],
            },
          },
        ],
      }),
    );
    await Promise.all([waitForTable(catalogTableName), waitForTable(checkoutTableName)]);
  });

  afterAll(() => disconnect());

  it('creates the two real tables and both production GSI key contracts', async () => {
    const tables = await lowLevelClient?.send(new ListTablesCommand({}));
    expect(tables?.TableNames).toEqual(
      expect.arrayContaining([catalogTableName, checkoutTableName]),
    );
    const catalog = await lowLevelClient?.send(
      new DescribeTableCommand({ TableName: catalogTableName }),
    );
    expect(catalog?.Table?.KeySchema).toEqual([
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ]);
    const checkout = await lowLevelClient?.send(
      new DescribeTableCommand({ TableName: checkoutTableName }),
    );
    const index = checkout?.Table?.GlobalSecondaryIndexes?.find(
      (candidate) => candidate.IndexName === 'GSI1-Reconcile',
    );
    expect(index?.IndexStatus).toBe('ACTIVE');
    expect(index?.KeySchema).toEqual([
      { AttributeName: 'GSI1PK', KeyType: 'HASH' },
      { AttributeName: 'GSI1SK', KeyType: 'RANGE' },
    ]);
    expect([...(index?.Projection?.NonKeyAttributes ?? [])].sort()).toEqual(
      ['checkoutId', 'dispatchPhase', 'paymentStatus', 'transactionId'].sort(),
    );
    const pendingAge = checkout?.Table?.GlobalSecondaryIndexes?.find(
      (candidate) => candidate.IndexName === 'GSI2-PendingAge',
    );
    expect(pendingAge?.IndexStatus).toBe('ACTIVE');
    expect(pendingAge?.KeySchema).toEqual([
      { AttributeName: 'GSI2PK', KeyType: 'HASH' },
      { AttributeName: 'GSI2SK', KeyType: 'RANGE' },
    ]);
    expect([...(pendingAge?.Projection?.NonKeyAttributes ?? [])].sort()).toEqual([
      'acceptedAt',
      'paymentStatus',
    ]);
  });

  it('keeps future work in the global pending index and removes it on finalization', async () => {
    const productId = 'product_pending_age';
    await seedProduct(productId, 1);
    const checkout = await createCheckout('pending_age', productId);
    const transaction = makeTransaction(checkout, 'pending_age', { nextCheckAt: EXPIRES_AT });
    valueOf(await prepare(checkout, transaction));

    let oldest: string | null = null;
    for (let attempt = 0; attempt < 100 && oldest === null; attempt += 1) {
      oldest = valueOf(await checkoutRepository.findOldestPendingAcceptedAt());
      if (oldest === null) await delay(50);
    }
    expect(oldest).toBe(T0);
    expect(valueOf(await checkoutRepository.claimDue(T5, T6, 10))).toEqual([]);
    expect(valueOf(await checkoutRepository.findOldestPendingAcceptedAt())).toBe(T0);

    await acknowledge(transaction, 'DECLINED', 'pending_age');
    valueOf(
      await checkoutRepository.finalize(
        transaction.transactionId,
        'DECLINED',
        'DECLINED',
        undefined,
        T5,
      ),
    );
    oldest = T0;
    for (let attempt = 0; attempt < 100 && oldest !== null; attempt += 1) {
      oldest = valueOf(await checkoutRepository.findOldestPendingAcceptedAt());
      if (oldest !== null) await delay(50);
    }
    expect(oldest).toBeNull();
    const payment = await getCheckoutItem(
      checkout.checkoutId,
      'PAYMENT#' + transaction.transactionId,
    );
    expect(payment).not.toHaveProperty('GSI2PK');
    expect(payment).not.toHaveProperty('GSI2SK');
  });

  it('awards the last unit to exactly one concurrent checkout without partial loser writes', async () => {
    const productId = 'product_last_unit';
    await seedProduct(productId, 1);
    const first = await createCheckout('last_unit_a', productId);
    const second = await createCheckout('last_unit_b', productId);
    const transactions = [
      makeTransaction(first, 'last_unit_a'),
      makeTransaction(second, 'last_unit_b'),
    ] as const;
    const results = await Promise.all([
      prepare(first, transactions[0]),
      prepare(second, transactions[1]),
    ]);
    const successIndexes = results.flatMap((result, index) => (result.ok ? [index] : []));
    expect(successIndexes).toHaveLength(1);
    expect(results.filter((result) => !result.ok)).toEqual([
      { ok: false, error: { code: 'OUT_OF_STOCK' } },
    ]);
    const product = valueOf(await catalogRepository.findById(productId));
    expect(product).toMatchObject({ onHand: 1, reserved: 1, available: 0 });

    const loser = successIndexes[0] === 0 ? second : first;
    expect(valueOf(await checkoutRepository.findCheckout(loser.checkoutId))).toEqual(loser);
    const loserItems = await queryCheckoutPartition(loser.checkoutId);
    expect(
      loserItems.filter((item) =>
        ['PAYMENT', 'RESERVATION', 'IDEMPOTENCY'].includes(String(item.itemType)),
      ),
    ).toHaveLength(0);
  });

  it('replays the same idempotency semantics and rejects changed semantics or a new key', async () => {
    const productId = 'product_idempotency';
    await seedProduct(productId, 2);
    const checkout = await createCheckout('idempotency', productId);
    const firstTransaction = makeTransaction(checkout, 'idempotency_first');
    const keyHash = 'key_idempotency_shared';
    const semanticHash = 'semantic_idempotency_shared';
    expect(await prepare(checkout, firstTransaction, keyHash, semanticHash)).toMatchObject({
      ok: true,
      value: { kind: 'CREATED', transaction: { transactionId: firstTransaction.transactionId } },
    });

    const replayTransaction = makeTransaction(checkout, 'idempotency_replay');
    expect(await prepare(checkout, replayTransaction, keyHash, semanticHash)).toMatchObject({
      ok: true,
      value: { kind: 'REPLAY', transaction: { transactionId: firstTransaction.transactionId } },
    });
    expect(await prepare(checkout, replayTransaction, keyHash, 'semantic_changed')).toEqual({
      ok: false,
      error: { code: 'IDEMPOTENCY_CONFLICT' },
    });
    expect(
      await prepare(
        checkout,
        replayTransaction,
        'key_idempotency_different',
        semanticHash,
        checkout.version + 1,
      ),
    ).toEqual({ ok: false, error: { code: 'PAYMENT_ALREADY_IN_PROGRESS' } });

    const product = valueOf(await catalogRepository.findById(productId));
    expect(product).toMatchObject({ onHand: 2, reserved: 1, available: 1 });
    const items = await queryCheckoutPartition(checkout.checkoutId);
    expect(items.filter((item) => item.itemType === 'PAYMENT')).toHaveLength(1);
    expect(items.filter((item) => item.itemType === 'RESERVATION')).toHaveLength(1);
    expect(items.filter((item) => item.itemType === 'IDEMPOTENCY')).toHaveLength(1);
  });

  it('rolls back catalog, checkout, payment, reservation and idempotency when prepare fails last', async () => {
    const productId = 'product_prepare_atomic';
    await seedProduct(productId, 2);
    const source = await createCheckout('prepare_atomic_source', productId);
    const sourceTransaction = makeTransaction(source, 'prepare_atomic_shared');
    valueOf(await prepare(source, sourceTransaction));

    const target = await createCheckout('prepare_atomic_target', productId);
    const colliding = makeTransaction(target, 'prepare_atomic_target', {
      transactionId: sourceTransaction.transactionId,
      providerReference: 'reference_prepare_atomic_target',
    });
    expect(await prepare(target, colliding)).toEqual({
      ok: false,
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });

    expect(valueOf(await catalogRepository.findById(productId))).toMatchObject({
      onHand: 2,
      reserved: 1,
      available: 1,
    });
    expect(valueOf(await checkoutRepository.findCheckout(target.checkoutId))).toEqual(target);
    const targetItems = await queryCheckoutPartition(target.checkoutId);
    expect(
      targetItems.filter((item) =>
        ['PAYMENT', 'RESERVATION', 'IDEMPOTENCY'].includes(String(item.itemType)),
      ),
    ).toHaveLength(0);
    expect(
      valueOf(await checkoutRepository.findTransaction(sourceTransaction.transactionId))
        ?.checkoutId,
    ).toBe(source.checkoutId);
  });

  it('applies APPROVED exactly once as one atomic inventory, checkout and delivery effect', async () => {
    const productId = 'product_approved_once';
    await seedProduct(productId, 1);
    const checkout = await createCheckout('approved_once', productId);
    const transaction = makeTransaction(checkout, 'approved_once');
    valueOf(await prepare(checkout, transaction));
    await acknowledge(transaction, 'APPROVED', 'approved_once');

    const finals = await Promise.all([
      checkoutRepository.finalize(transaction.transactionId, 'APPROVED', 'APPROVED', undefined, T5),
      checkoutRepository.finalize(transaction.transactionId, 'APPROVED', 'APPROVED', undefined, T5),
    ]);
    expect(finals.every((result) => result.ok)).toBe(true);
    const finalized = valueOf(await checkoutRepository.findTransaction(transaction.transactionId));
    expect(finalized).toMatchObject({
      paymentStatus: 'APPROVED',
      reservationStatus: 'CONSUMED',
      effectsApplied: true,
      integrityStatus: 'OK',
      attempts: 1,
    });
    expect(valueOf(await catalogRepository.findById(productId))).toMatchObject({
      onHand: 0,
      reserved: 0,
      available: 0,
    });
    expect(valueOf(await checkoutRepository.findCheckout(checkout.checkoutId))?.status).toBe(
      'PAID',
    );
    const items = await queryCheckoutPartition(checkout.checkoutId);
    expect(items.filter((item) => item.itemType === 'DELIVERY')).toHaveLength(1);
    expect(items.find((item) => item.itemType === 'IDEMPOTENCY')).toMatchObject({
      status: 'FINAL',
    });
    expect(items.find((item) => item.itemType === 'RESERVATION')).toMatchObject({
      status: 'CONSUMED',
    });
    const payment = items.find((item) => item.itemType === 'PAYMENT');
    expect(payment).not.toHaveProperty('GSI1PK');
    expect(payment).not.toHaveProperty('GSI1SK');
    expect(payment).not.toHaveProperty('GSI2PK');
    expect(payment).not.toHaveProperty('GSI2SK');
    expect(payment).not.toHaveProperty('leaseUntil');
    expect(payment).not.toHaveProperty('nextCheckAt');
    expect(
      valueOf(await checkoutRepository.findDelivery('delivery_' + transaction.transactionId))
        ?.transactionId,
    ).toBe(transaction.transactionId);
  });

  it('keeps every APPROVED effect unapplied when the delivery uniqueness condition fails', async () => {
    const productId = 'product_approved_rollback';
    await seedProduct(productId, 1);
    const checkout = await createCheckout('approved_rollback', productId);
    const transaction = makeTransaction(checkout, 'approved_rollback');
    const keyHash = 'key_' + transaction.transactionId;
    valueOf(await prepare(checkout, transaction, keyHash));
    await acknowledge(transaction, 'APPROVED', 'approved_rollback');
    const deliveryId = 'delivery_' + transaction.transactionId;
    await documentClient.send(
      new PutCommand({
        TableName: checkoutTableName,
        Item: {
          PK: lockPk('DELIVERY', deliveryId),
          SK: 'LOCK',
          itemType: 'UNIQUE_LOCK',
          kind: 'DELIVERY',
          checkoutId: 'checkout_collision_owner',
          transactionId: 'transaction_collision_owner',
          schemaVersion: 1,
        },
      }),
    );

    expect(
      await checkoutRepository.finalize(
        transaction.transactionId,
        'APPROVED',
        'APPROVED',
        undefined,
        T5,
      ),
    ).toEqual({ ok: false, error: { code: 'REPOSITORY_UNAVAILABLE' } });
    expect(
      valueOf(await checkoutRepository.findTransaction(transaction.transactionId)),
    ).toMatchObject({
      paymentStatus: 'PENDING',
      providerStatus: 'APPROVED',
      reservationStatus: 'ACTIVE',
      effectsApplied: false,
    });
    expect(valueOf(await catalogRepository.findById(productId))).toMatchObject({
      onHand: 1,
      reserved: 1,
      available: 0,
    });
    expect(valueOf(await checkoutRepository.findCheckout(checkout.checkoutId))?.status).toBe(
      'PAYMENT_PENDING',
    );
    const items = await queryCheckoutPartition(checkout.checkoutId);
    expect(items.filter((item) => item.itemType === 'DELIVERY')).toHaveLength(0);
    expect(items.find((item) => item.itemType === 'RESERVATION')).toMatchObject({
      status: 'ACTIVE',
    });
    expect(items.find((item) => item.itemType === 'IDEMPOTENCY')).toMatchObject({
      status: 'IN_PROGRESS',
    });
    expect(await getCheckoutItem(checkout.checkoutId, 'DELIVERY#' + deliveryId)).toBeUndefined();
  });

  const failureCases: ReadonlyArray<
    readonly [
      string,
      Exclude<PaymentStatus, 'PENDING' | 'APPROVED'>,
      ProviderStatus,
      Transaction['recoveryCode'],
      'ACKNOWLEDGE' | 'PROVEN_NOT_SENT',
    ]
  > = [
    ['declined', 'DECLINED', 'DECLINED', undefined, 'ACKNOWLEDGE'],
    ['error', 'ERROR', null, 'PROVIDER_NOT_SENT', 'PROVEN_NOT_SENT'],
  ];

  it.each(failureCases)(
    'releases inventory and creates no delivery for terminal %s',
    async (label, status, providerStatus, recoveryCode, path) => {
      const productId = 'product_failure_' + label;
      await seedProduct(productId, 1);
      const checkout = await createCheckout('failure_' + label, productId);
      const transaction = makeTransaction(checkout, 'failure_' + label);
      valueOf(await prepare(checkout, transaction));
      if (path === 'ACKNOWLEDGE') {
        await acknowledge(transaction, status, 'failure_' + label);
      } else {
        expect(
          valueOf(await checkoutRepository.claimDispatch(transaction.transactionId, T1, T3)).kind,
        ).toBe('CLAIMED');
      }
      const finalized = valueOf(
        await checkoutRepository.finalize(
          transaction.transactionId,
          status,
          providerStatus,
          recoveryCode,
          T5,
        ),
      );
      expect(finalized).toMatchObject({
        paymentStatus: status,
        reservationStatus: 'RELEASED',
        effectsApplied: true,
      });
      expect(finalized.deliveryId).toBeUndefined();
      expect(valueOf(await catalogRepository.findById(productId))).toMatchObject({
        onHand: 1,
        reserved: 0,
        available: 1,
      });
      expect(valueOf(await checkoutRepository.findCheckout(checkout.checkoutId))?.status).toBe(
        'PAYMENT_FAILED',
      );
      const items = await queryCheckoutPartition(checkout.checkoutId);
      expect(items.filter((item) => item.itemType === 'DELIVERY')).toHaveLength(0);
      expect(items.find((item) => item.itemType === 'RESERVATION')).toMatchObject({
        status: 'RELEASED',
      });
      expect(items.find((item) => item.itemType === 'IDEMPOTENCY')).toMatchObject({
        status: 'FINAL',
      });
    },
  );

  it('makes a duplicate final a no-op and quarantines an opposite final without new effects', async () => {
    const productId = 'product_final_conflict';
    await seedProduct(productId, 1);
    const checkout = await createCheckout('final_conflict', productId);
    const transaction = makeTransaction(checkout, 'final_conflict');
    valueOf(await prepare(checkout, transaction));
    await acknowledge(transaction, 'DECLINED', 'final_conflict');
    const first = valueOf(
      await checkoutRepository.finalize(
        transaction.transactionId,
        'DECLINED',
        'DECLINED',
        undefined,
        T4,
      ),
    );
    const inventoryAfterFirst = valueOf(await catalogRepository.findById(productId));
    const duplicate = valueOf(
      await checkoutRepository.finalize(
        transaction.transactionId,
        'DECLINED',
        'DECLINED',
        undefined,
        T5,
      ),
    );
    expect(duplicate).toEqual(first);
    const opposite = valueOf(
      await checkoutRepository.finalize(
        transaction.transactionId,
        'APPROVED',
        'APPROVED',
        undefined,
        T6,
      ),
    );
    expect(opposite).toMatchObject({
      paymentStatus: 'DECLINED',
      reservationStatus: 'RELEASED',
      effectsApplied: true,
      integrityStatus: 'FINAL_STATE_CONFLICT',
      recoveryCode: 'STATE_TRANSITION_CONFLICT',
    });
    expect(opposite.deliveryId).toBeUndefined();
    expect(valueOf(await catalogRepository.findById(productId))).toEqual(inventoryAfterFirst);
    const items = await queryCheckoutPartition(checkout.checkoutId);
    expect(items.filter((item) => item.itemType === 'DELIVERY')).toHaveLength(0);
    expect(items.find((item) => item.itemType === 'RESERVATION')).toMatchObject({
      status: 'RELEASED',
    });
  });

  it('claims due work once per lease through the GSI and persists it across a real restart', async () => {
    const productId = 'product_lease_restart';
    await seedProduct(productId, 1);
    const checkout = await createCheckout('lease_restart', productId);
    const transaction = makeTransaction(checkout, 'lease_restart', { nextCheckAt: T0 });
    valueOf(await prepare(checkout, transaction));
    await waitForDueProjection(transaction.transactionId, T1);

    const concurrent = await Promise.all([
      checkoutRepository.claimDue(T1, T4, 10),
      checkoutRepository.claimDue(T1, T4, 10),
    ]);
    const claims = concurrent.map((result) => valueOf(result));
    expect(claims.map((claim) => claim.length).sort()).toEqual([0, 1]);
    const winner = claims.find((claim) => claim.length === 1)?.[0];
    expect(winner).toMatchObject({
      transactionId: transaction.transactionId,
      dispatchPhase: 'NOT_SENT_FAILED',
      nextCheckAt: T4,
      attempts: 0,
    });
    const storedBeforeRestart = await getCheckoutItem(
      checkout.checkoutId,
      'PAYMENT#' + transaction.transactionId,
    );
    expect(storedBeforeRestart).toMatchObject({
      leaseUntil: T4,
      GSI1SK: T4 + '#' + transaction.transactionId,
      attempts: 0,
    });

    await restartContainer();
    expect(valueOf(await checkoutRepository.findCheckout(checkout.checkoutId))).toMatchObject({
      checkoutId: checkout.checkoutId,
      status: 'PAYMENT_PENDING',
    });
    expect(valueOf(await catalogRepository.findById(productId))).toMatchObject({
      onHand: 1,
      reserved: 1,
      available: 0,
    });
    expect(
      valueOf(await checkoutRepository.findTransaction(transaction.transactionId)),
    ).toMatchObject({
      dispatchPhase: 'NOT_SENT_FAILED',
      nextCheckAt: T4,
      attempts: 0,
    });
    expect(valueOf(await checkoutRepository.claimDue(T3, T5, 10))).toEqual([]);

    let reclaimed: readonly Transaction[] = [];
    for (let attempt = 0; attempt < 100 && reclaimed.length === 0; attempt += 1) {
      reclaimed = valueOf(await checkoutRepository.claimDue(T5, T6, 10));
      if (reclaimed.length === 0) await delay(50);
    }
    expect(reclaimed).toHaveLength(1);
    expect(reclaimed[0]).toMatchObject({
      transactionId: transaction.transactionId,
      dispatchPhase: 'NOT_SENT_FAILED',
      nextCheckAt: T6,
      attempts: 0,
    });
  });
});
