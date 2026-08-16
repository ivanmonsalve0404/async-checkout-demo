import type {
  MerchantContract,
  MerchantContractPort,
} from '../../application/ports/merchant-contract';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';

const hasSafeContractShape = (contract: MerchantContract): boolean => {
  if (contract.version.trim().length === 0) return false;
  try {
    const permalink = new URL(contract.permalink);
    return permalink.protocol === 'http:' || permalink.protocol === 'https:';
  } catch {
    return false;
  }
};

const isCompleteContractSet = (contracts: readonly MerchantContract[]): boolean =>
  contracts.length === 2 &&
  contracts.filter(({ type }) => type === 'TERMS').length === 1 &&
  contracts.filter(({ type }) => type === 'PERSONAL_DATA').length === 1 &&
  contracts.every(hasSafeContractShape);

export class FakeMerchantContractAdapter implements MerchantContractPort {
  public readonly status = 'READY' as const;
  private readonly contracts: readonly MerchantContract[];

  public constructor(publicAssetOrigin: string, contracts?: readonly MerchantContract[]) {
    this.contracts = contracts ?? [
      {
        type: 'TERMS',
        permalink: new URL('/legal/terms-v1.html', publicAssetOrigin).toString(),
        version: 'terms-v1',
      },
      {
        type: 'PERSONAL_DATA',
        permalink: new URL('/legal/personal-data-v1.html', publicAssetOrigin).toString(),
        version: 'personal-data-v1',
      },
    ];
  }

  public getCurrentContracts(): Result<
    readonly MerchantContract[],
    Readonly<{ code: 'CONTRACTS_UNAVAILABLE' }>
  > {
    if (!isCompleteContractSet(this.contracts)) {
      return err({ code: 'CONTRACTS_UNAVAILABLE' });
    }
    return ok(this.contracts.map((contract) => ({ ...contract })));
  }
}
