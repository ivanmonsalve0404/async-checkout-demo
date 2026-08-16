import type { ProviderPaymentCommand } from '../../application/ports/payment-provider';
import { E5ScriptedPaymentProvider, e5PaymentScenarios } from './e5-scripted-payment-provider';

const command: ProviderPaymentCommand = {
  reference: 'reference-e5-001',
  amountInCents: 3_200_000,
  currency: 'COP',
  customerEmail: 'buyer@example.invalid',
  installments: 1,
  paymentMethodHandle: { kind: 'OPAQUE_TOKEN', value: 'tok_synthetic' },
  acceptances: {
    termsAcceptanceToken: 'terms_synthetic',
    personalDataAcceptanceToken: 'personal_synthetic',
  },
};

const providerId = `provider_${command.reference}`;

const retainedPayments = (provider: E5ScriptedPaymentProvider): readonly unknown[] =>
  Array.from((provider as unknown as { commands: Map<string, unknown> }).commands.values());

describe('E5ScriptedPaymentProvider', () => {
  it('exposes exactly FAKE-E5-01..12 and accepts no request-level selector', async () => {
    expect(e5PaymentScenarios).toEqual(
      Array.from({ length: 12 }, (_, index) => `FAKE-E5-${String(index + 1).padStart(2, '0')}`),
    );
    for (const scenario of e5PaymentScenarios) {
      const provider = new E5ScriptedPaymentProvider(scenario);
      expect(provider.getPublicConfiguration()).toMatchObject({
        value: { mode: 'fake', captureVariant: 'FAKE_CONTRACT' },
      });
      await expect(provider.createOnce(command)).resolves.toMatchObject({ ok: true });
      expect(provider.createCalls).toBe(1);
    }
  });

  it('retains only the fields required to reconcile', async () => {
    for (const scenario of ['FAKE-E5-01', 'FAKE-E5-05'] as const) {
      const provider = new E5ScriptedPaymentProvider(scenario);
      await provider.createOnce(command);
      expect(retainedPayments(provider)).toEqual([
        {
          reference: command.reference,
          amountInCents: command.amountInCents,
          currency: command.currency,
        },
      ]);
    }
  });

  it.each([
    ['FAKE-E5-01', 'APPROVED'],
    ['FAKE-E5-02', 'DECLINED'],
    ['FAKE-E5-03', 'ERROR'],
  ] as const)('%s moves PENDING to %s', async (scenario, status) => {
    const provider = new E5ScriptedPaymentProvider(scenario);
    await expect(provider.createOnce(command)).resolves.toMatchObject({
      value: { kind: 'ACKNOWLEDGED', status: 'PENDING' },
    });
    await expect(provider.getById(providerId)).resolves.toMatchObject({ value: { status } });
  });

  it('FAKE-E5-04 sustains PENDING deterministically', async () => {
    const provider = new E5ScriptedPaymentProvider('FAKE-E5-04');
    await provider.createOnce(command);
    await expect(provider.getById(providerId)).resolves.toMatchObject({
      value: { status: 'PENDING' },
    });
    await expect(provider.getById(providerId)).resolves.toMatchObject({
      value: { status: 'PENDING' },
    });
    expect(provider.readCalls).toBe(2);
  });

  it('FAKE-E5-05 records that an external operation exists despite create timeout', async () => {
    const provider = new E5ScriptedPaymentProvider('FAKE-E5-05');
    await expect(provider.createOnce(command)).resolves.toMatchObject({
      value: { kind: 'OUTCOME_UNKNOWN' },
    });
    expect(provider.hasExternalTransaction(command.reference)).toBe(true);
    await expect(provider.getByReference(command.reference)).resolves.toMatchObject({
      value: { providerId, status: 'APPROVED' },
    });
    expect(provider.createCalls).toBe(1);
  });

  it('FAKE-E5-06 fails reads and FAKE-E5-07 returns malformed/protocol outcome', async () => {
    const unavailable = new E5ScriptedPaymentProvider('FAKE-E5-06');
    await unavailable.createOnce(command);
    await expect(unavailable.getById(providerId)).resolves.toMatchObject({
      error: { code: 'FAKE_SCRIPT_EXHAUSTED' },
    });
    const malformed = new E5ScriptedPaymentProvider('FAKE-E5-07');
    await expect(malformed.createOnce(command)).resolves.toMatchObject({
      value: { kind: 'PROTOCOL_VIOLATION_AFTER_POSSIBLE_SEND' },
    });
  });

  it('FAKE-E5-08 diverges all correlation fields', async () => {
    const provider = new E5ScriptedPaymentProvider('FAKE-E5-08');
    const created = await provider.createOnce(command);
    expect(created).toMatchObject({
      value: {
        reference: `${command.reference}_divergent`,
        amountInCents: command.amountInCents + 1,
        currency: 'USD',
      },
    });
  });

  it('FAKE-E5-09 deduplicates an internal event without exposing API-11', () => {
    const provider = new E5ScriptedPaymentProvider('FAKE-E5-09');
    expect(provider.verifyAndNormalizeEvent('fake.event-001')).toMatchObject({ ok: true });
    expect(provider.verifyAndNormalizeEvent('fake.event-001')).toMatchObject({ ok: true });
    expect(provider.verifiedEventCount).toBe(1);
    expect(provider.verifyAndNormalizeEvent('external.event')).toMatchObject({
      error: { code: 'EVENT_REJECTED' },
    });
  });

  it('FAKE-E5-10 repeats final and FAKE-E5-11 regresses final to PENDING at the port boundary', async () => {
    const repeated = new E5ScriptedPaymentProvider('FAKE-E5-10');
    await repeated.createOnce(command);
    await expect(repeated.getById(providerId)).resolves.toMatchObject({
      value: { status: 'APPROVED' },
    });
    await expect(repeated.getById(providerId)).resolves.toMatchObject({
      value: { status: 'APPROVED' },
    });

    const regressed = new E5ScriptedPaymentProvider('FAKE-E5-11');
    await regressed.createOnce(command);
    await expect(regressed.getById(providerId)).resolves.toMatchObject({
      value: { status: 'APPROVED' },
    });
    await expect(regressed.getById(providerId)).resolves.toMatchObject({
      value: { status: 'PENDING' },
    });
  });

  it('isolates deterministic read progress per external transaction', async () => {
    const provider = new E5ScriptedPaymentProvider('FAKE-E5-01');
    const another = { ...command, reference: 'reference-e5-002' };
    await Promise.all([provider.createOnce(command), provider.createOnce(another)]);
    await expect(provider.getById(providerId)).resolves.toMatchObject({
      value: { status: 'APPROVED' },
    });
    await expect(provider.getById('provider_reference-e5-002')).resolves.toMatchObject({
      value: { status: 'APPROVED' },
    });
  });

  it('FAKE-E5-12 uses an injected clock and no real sleep', async () => {
    let now = 10_000;
    const provider = new E5ScriptedPaymentProvider('FAKE-E5-12', { now: () => now });
    await provider.createOnce(command);
    await expect(provider.getById(providerId)).resolves.toMatchObject({
      value: { status: 'PENDING' },
    });
    now += 1_000;
    await expect(provider.getById(providerId)).resolves.toMatchObject({
      value: { status: 'APPROVED' },
    });
  });
});
