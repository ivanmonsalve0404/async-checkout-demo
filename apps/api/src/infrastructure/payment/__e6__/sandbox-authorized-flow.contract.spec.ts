import type { Result } from '../../../application/result/result';
import type { ProviderObservation } from '../../../application/ports/payment-provider';
import type { Checkout, PaymentStatus, Transaction } from '../../../domain/checkout/checkout';
import { InMemoryCatalogRepository } from '../../persistence/in-memory-catalog.repository';
import { InMemoryCheckoutRepository } from '../../persistence/in-memory-checkout.repository';
import { createProductSeed } from '../../persistence/product-seed';
import { SystemRuntimeSecurity } from '../../security/system-runtime-security';
import {
  SandboxPaymentProvider,
  type SandboxTransport,
  type SandboxTransportResponse,
} from '../sandbox-payment-provider';

const valueOf = <T, E>(result: Result<T, E>): T => {
  if (!result.ok) throw new Error('synthetic result failure');
  return result.value;
};

const paymentStatus = (status: ProviderObservation['status']): PaymentStatus => {
  if (status === 'UNKNOWN_EXTERNAL') throw new Error('unexpected external status');
  return status;
};

const providerAcceptanceJwt = (subject: string): string =>
  [
    Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify({ sub: subject, exp: 4_102_444_800 })).toString('base64url'),
    Buffer.from(`synthetic-signature-${subject}`).toString('base64url'),
  ].join('.');

const reconcile = async (
  repository: InMemoryCheckoutRepository,
  transactionId: string,
  observation: ProviderObservation,
  attempt: number,
): Promise<Transaction> => {
  const now = `2026-08-16T12:00:0${attempt}.000Z`;
  const current = valueOf(await repository.findTransaction(transactionId));
  if (current === null) throw new Error('missing transaction');
  expect(observation).toMatchObject({
    reference: current.providerReference,
    amountInCents: current.amountInCents,
    currency: current.currency,
  });
  const status = paymentStatus(observation.status);
  const acknowledged = valueOf(
    await repository.acknowledgeProvider(transactionId, observation.providerId, status, now, {
      attempts: attempt,
      lastCheckedAt: now,
      nextCheckAt: now,
    }),
  );
  return status === 'PENDING'
    ? acknowledged
    : valueOf(await repository.finalize(transactionId, status, status, undefined, now));
};

describe('authorized sandbox provider candidate contract', () => {
  it('persists PENDING before one provider POST and reconciles repeated reads idempotently', async () => {
    const publicKey = ['pub', 'test', 'synthetic-provider'].join('_');
    const privateKey = ['prv', 'test', 'synthetic-provider'].join('_');
    const integritySecret = ['test', 'integrity', 'synthetic-provider'].join('_');
    const paymentToken = ['tok', 'test', 'synthetic-provider'].join('_');
    const productId = 'product-e6-sandbox';
    const checkoutId = 'checkout-e6-sandbox';
    const transactionId = 'transaction-e6-sandbox';
    const reference = 'e6-synthetic-reference';
    const amountInCents = 3_200_000;
    const now = '2026-08-16T12:00:00.000Z';
    const catalog = new InMemoryCatalogRepository([
      createProductSeed(productId, 'http://127.0.0.1:1', 1),
    ]);
    const repository = new InMemoryCheckoutRepository(catalog);
    const runtime = new SystemRuntimeSecurity(() => new Date(now), Buffer.alloc(32, 7));
    const capabilityHash = runtime.hashCapability('synthetic-capability');
    const checkout: Checkout = {
      checkoutId,
      status: 'READY',
      version: 3,
      capabilityHash,
      productId,
      quote: {
        quoteId: 'quote-e6-sandbox',
        version: 1,
        productId,
        quantity: 1,
        subtotal: { amountInCents: 2_500_000, currency: 'COP' },
        baseFee: { amountInCents: 200_000, currency: 'COP' },
        deliveryFee: { amountInCents: 500_000, currency: 'COP' },
        total: { amountInCents, currency: 'COP' },
        expiresAt: '2026-08-16T12:15:00.000Z',
      },
      deliveryDetails: {
        checkoutId,
        version: 1,
        addressLine1: 'Synthetic destination',
        city: 'Bogota',
        region: 'Cundinamarca',
      },
      expiresAt: '2026-08-16T12:30:00.000Z',
    };
    valueOf(await repository.create(checkout));
    const transaction: Transaction = {
      transactionId,
      checkoutId,
      providerReference: reference,
      paymentStatus: 'PENDING',
      dispatchPhase: 'NOT_SENT',
      providerStatus: null,
      reservationStatus: 'ACTIVE',
      integrityStatus: 'OK',
      acceptanceEvidence: {
        termsVersion: 'terms-synthetic',
        termsContractHash: runtime.semanticHash('terms-synthetic'),
        personalDataVersion: 'personal-synthetic',
        personalDataContractHash: runtime.semanticHash('personal-synthetic'),
        acceptedAt: now,
      },
      acceptedAt: now,
      updatedAt: now,
      attempts: 0,
      nextCheckAt: now,
      amountInCents,
      currency: 'COP',
      effectsApplied: false,
    };
    const preparedInput = {
      checkoutId,
      capabilityHash,
      expectedVersion: checkout.version,
      keyHash: runtime.hashIdempotency(checkoutId, 'idem.auth02.synthetic'),
      semanticHash: runtime.semanticHash('auth02-synthetic'),
      transaction,
      submission: {
        transactionId,
        statusUrl: `/api/v1/transactions/${transactionId}`,
        submissionState: 'ACCEPTED' as const,
        acceptedAt: now,
      },
    };
    expect(valueOf(await repository.preparePayment(preparedInput)).kind).toBe('CREATED');
    expect(valueOf(await repository.claimDispatch(transactionId, now, now)).kind).toBe('CLAIMED');

    const response = (status: 'PENDING' | 'APPROVED'): SandboxTransportResponse => ({
      status: 200,
      contentType: 'application/json',
      body: {
        data: {
          id: 'provider-e6-synthetic',
          reference,
          amount_in_cents: amountInCents,
          currency: 'COP',
          status,
        },
      },
    });
    const transport = jest
      .fn<Promise<SandboxTransportResponse>, Parameters<SandboxTransport>>()
      .mockImplementationOnce(async (request) => {
        expect(request.method).toBe('POST');
        await expect(repository.findTransaction(transactionId)).resolves.toMatchObject({
          value: {
            paymentStatus: 'PENDING',
            dispatchPhase: 'SENDING',
            reservationStatus: 'ACTIVE',
          },
        });
        return response('PENDING');
      })
      .mockResolvedValueOnce(response('APPROVED'))
      .mockResolvedValueOnce(response('APPROVED'));
    const providerContracts = [
      {
        type: 'TERMS',
        permalink: 'https://comercios.wompi.co/terminos/synthetic',
        version: 'terms-synthetic',
      },
      {
        type: 'PERSONAL_DATA',
        permalink: 'https://wompi.com/datos/synthetic',
        version: 'personal-synthetic',
      },
    ] as const;
    const provider = new SandboxPaymentProvider({
      enabled: true,
      publicKey,
      privateKey,
      integritySecret,
      acceptanceReader: () =>
        Promise.resolve({
          contracts: providerContracts,
          providerAcceptances: {
            terms: providerAcceptanceJwt('provider-terms-synthetic'),
            personalData: providerAcceptanceJwt('provider-personal-synthetic'),
          },
        }),
      expectedContracts: providerContracts,
      quoteTtlSeconds: 900,
      authorizedUntilUtc: '2099-01-01T00:00:00.000Z',
      transport,
    });
    const created = valueOf(
      await provider.createOnce({
        reference,
        amountInCents,
        currency: 'COP',
        customerEmail: 'synthetic@example.invalid',
        installments: 1,
        paymentMethodHandle: { kind: 'OPAQUE_TOKEN', value: paymentToken },
        acceptances: {
          termsAcceptanceToken: 'terms-synthetic',
          personalDataAcceptanceToken: 'personal-synthetic',
        },
      }),
    );
    if (created.kind !== 'ACKNOWLEDGED') throw new Error('create was not acknowledged');
    await reconcile(repository, transactionId, created, 0);
    const firstRead = valueOf(await provider.getById(created.providerId, reference));
    await reconcile(repository, transactionId, firstRead, 1);
    const beforeReplayProduct = valueOf(await catalog.findById(productId));
    const beforeReplayTransaction = valueOf(await repository.findTransaction(transactionId));
    const replayRead = valueOf(await provider.getById(created.providerId, reference));
    await reconcile(repository, transactionId, replayRead, 2);
    await reconcile(repository, transactionId, replayRead, 2);
    const afterReplayProduct = valueOf(await catalog.findById(productId));
    const afterReplayTransaction = valueOf(await repository.findTransaction(transactionId));

    expect(beforeReplayProduct).not.toBeNull();
    expect(afterReplayProduct).toEqual(beforeReplayProduct);
    expect(afterReplayTransaction).toEqual(beforeReplayTransaction);
    expect(afterReplayTransaction).toMatchObject({
      paymentStatus: 'APPROVED',
      providerStatus: 'APPROVED',
      reservationStatus: 'CONSUMED',
      effectsApplied: true,
    });
    expect(valueOf(await repository.preparePayment(preparedInput))).toMatchObject({
      kind: 'REPLAY',
      transaction: { transactionId },
    });
    expect(transport).toHaveBeenCalledTimes(3);
    expect(transport.mock.calls.filter(([request]) => request.method === 'POST')).toHaveLength(1);
  });
});
