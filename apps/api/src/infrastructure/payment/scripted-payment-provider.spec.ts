import type { ProviderPaymentCommand } from '../../application/ports/payment-provider';
import { fakePaymentScenarios, ScriptedPaymentProvider } from './scripted-payment-provider';

const command: ProviderPaymentCommand = {
  reference: 'reference-fake-001',
  amountInCents: 2_500_000,
  currency: 'COP',
  customerEmail: 'buyer@example.invalid',
  installments: 1,
  paymentMethodHandle: { kind: 'OPAQUE_TOKEN', value: 'tok_synthetic' },
  acceptances: {
    termsAcceptanceToken: 'terms_synthetic',
    personalDataAcceptanceToken: 'personal_synthetic',
  },
};

const retainedPayments = (provider: ScriptedPaymentProvider): readonly unknown[] =>
  Array.from((provider as unknown as { commands: Map<string, unknown> }).commands.values());

describe('ScriptedPaymentProvider', () => {
  it('implements all 12 deterministic scripts without network configuration', async () => {
    expect(fakePaymentScenarios).toHaveLength(12);
    for (const scenario of fakePaymentScenarios) {
      const provider = new ScriptedPaymentProvider(scenario);
      expect(provider.getPublicConfiguration()).toMatchObject({
        ok: true,
        value: { mode: 'fake', installments: [1, 2, 3] },
      });
      await expect(provider.createOnce(command)).resolves.toMatchObject({ ok: true });
    }
  });

  it('retains only the fields required to reconcile', async () => {
    const provider = new ScriptedPaymentProvider('FAKE-PAY-03');
    await provider.createOnce(command);
    expect(retainedPayments(provider)).toEqual([
      {
        reference: command.reference,
        amountInCents: command.amountInCents,
        currency: command.currency,
      },
    ]);
  });

  it('reconciles an unknown create by stable reference from the safe projection', async () => {
    const provider = new ScriptedPaymentProvider('FAKE-PAY-06');

    await expect(provider.createOnce(command)).resolves.toEqual({
      ok: true,
      value: { kind: 'OUTCOME_UNKNOWN' },
    });
    await expect(provider.getByReference(command.reference)).resolves.toMatchObject({
      ok: true,
      value: {
        providerId: 'provider_' + command.reference,
        reference: command.reference,
        amountInCents: command.amountInCents,
        currency: 'COP',
        status: 'PENDING',
      },
    });
    expect(retainedPayments(provider)).toEqual([
      {
        reference: command.reference,
        amountInCents: command.amountInCents,
        currency: command.currency,
      },
    ]);
  });

  it('advances scripted reads and fails explicitly when exhausted', async () => {
    const provider = new ScriptedPaymentProvider('FAKE-PAY-03');
    await provider.createOnce(command);
    const providerId = `provider_${command.reference}`;
    await expect(provider.getById(providerId)).resolves.toMatchObject({
      value: { status: 'PENDING' },
    });
    await expect(provider.getById(providerId)).resolves.toMatchObject({
      value: { status: 'APPROVED' },
    });
    await expect(provider.getById(providerId)).resolves.toMatchObject({
      error: { code: 'FAKE_SCRIPT_EXHAUSTED' },
    });
  });

  it('accepts only synthetic event names', () => {
    const provider = new ScriptedPaymentProvider('FAKE-PAY-01');
    expect(provider.verifyAndNormalizeEvent('fake.approved')).toMatchObject({ ok: true });
    expect(provider.verifyAndNormalizeEvent('external.approved')).toMatchObject({
      error: { code: 'EVENT_REJECTED' },
    });
  });
});
