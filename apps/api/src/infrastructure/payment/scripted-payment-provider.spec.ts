import type { ProviderPaymentCommand } from '../../application/ports/payment-provider';
import { fakePaymentScenarios, ScriptedPaymentProvider } from './scripted-payment-provider';

const command: ProviderPaymentCommand = {
  reference: 'reference-fake-001',
  amountInCents: 2_500_000,
  currency: 'COP',
  installments: 1,
  paymentMethodHandle: { kind: 'SYNTHETIC_FAKE' },
};

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

  it('advances scripted reads and fails explicitly when exhausted', async () => {
    const provider = new ScriptedPaymentProvider('FAKE-PAY-03');
    await expect(provider.getById('provider-fake-001')).resolves.toMatchObject({
      value: 'PENDING',
    });
    await expect(provider.getById('provider-fake-001')).resolves.toMatchObject({
      value: 'APPROVED',
    });
    await expect(provider.getById('provider-fake-001')).resolves.toMatchObject({
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
