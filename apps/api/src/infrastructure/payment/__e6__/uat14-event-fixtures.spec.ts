import { SandboxPaymentProvider, type SandboxTransport } from '../sandbox-payment-provider';

describe('UAT-14 isolated event fixtures', () => {
  it('[UAT-14-IF-01] rejects an invalid-signature fixture with zero network or mutation', () => {
    const transport: jest.MockedFunction<SandboxTransport> = jest.fn();
    const provider = new SandboxPaymentProvider({ enabled: false, transport });

    expect(provider.verifyAndNormalizeEvent('fixture.invalid-signature')).toEqual({
      ok: false,
      error: { code: 'ENVIRONMENT_DISABLED' },
    });
    expect(transport).not.toHaveBeenCalled();
  });
});
