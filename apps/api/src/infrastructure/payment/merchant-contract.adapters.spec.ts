import { FakeMerchantContractAdapter } from './fake-merchant-contract.adapter';
import { SandboxMerchantContractAdapter } from './sandbox-merchant-contract.adapter';

describe('merchant contract adapters', () => {
  it('returns exactly the two versioned local contracts in fake mode', () => {
    const adapter = new FakeMerchantContractAdapter('http://localhost:5173/nested');

    expect(adapter.status).toBe('READY');
    expect(adapter.getCurrentContracts()).toEqual({
      ok: true,
      value: [
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
      ],
    });
  });

  it('fails closed when either required contract is missing', () => {
    const adapter = new FakeMerchantContractAdapter('http://localhost:5173', [
      {
        type: 'TERMS',
        permalink: 'http://localhost:5173/legal/terms-v1.html',
        version: 'terms-v1',
      },
    ]);

    expect(adapter.getCurrentContracts()).toEqual({
      ok: false,
      error: { code: 'CONTRACTS_UNAVAILABLE' },
    });
  });

  it('keeps the sandbox adapter READY_DISABLED without returning guessed contracts', () => {
    const adapter = new SandboxMerchantContractAdapter();

    expect(adapter.status).toBe('READY_DISABLED');
    expect(adapter.getCurrentContracts()).toEqual({
      ok: false,
      error: { code: 'ENVIRONMENT_DISABLED' },
    });
  });
});
