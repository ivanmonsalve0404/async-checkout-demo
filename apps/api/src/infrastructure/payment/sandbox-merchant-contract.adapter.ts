import type {
  MerchantContract,
  MerchantContractError,
  MerchantContractPort,
} from '../../application/ports/merchant-contract';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';

export class SandboxMerchantContractAdapter implements MerchantContractPort {
  public readonly status: 'READY' | 'READY_DISABLED';

  public constructor(private readonly contracts?: readonly MerchantContract[]) {
    this.status = contracts === undefined ? 'READY_DISABLED' : 'READY';
  }

  public getCurrentContracts(): Result<readonly MerchantContract[], MerchantContractError> {
    return this.contracts === undefined
      ? err({ code: 'ENVIRONMENT_DISABLED' })
      : ok(this.contracts);
  }
}
