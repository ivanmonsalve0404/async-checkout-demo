import type {
  MerchantContract,
  MerchantContractError,
  MerchantContractPort,
} from '../../application/ports/merchant-contract';
import type { Result } from '../../application/result/result';
import { err } from '../../application/result/result';

export class SandboxMerchantContractAdapter implements MerchantContractPort {
  public readonly status = 'READY_DISABLED' as const;

  public getCurrentContracts(): Result<readonly MerchantContract[], MerchantContractError> {
    return err({ code: 'ENVIRONMENT_DISABLED' });
  }
}
