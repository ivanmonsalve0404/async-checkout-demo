import type { Result } from '../result/result';

export type MerchantContractType = 'TERMS' | 'PERSONAL_DATA';

export type TermsMerchantContract = Readonly<{
  type: 'TERMS';
  permalink: string;
  version: string;
}>;

export type PersonalDataMerchantContract = Readonly<{
  type: 'PERSONAL_DATA';
  permalink: string;
  version: string;
}>;

export type MerchantContract = TermsMerchantContract | PersonalDataMerchantContract;

export type MerchantContractSet = readonly [TermsMerchantContract, PersonalDataMerchantContract];

export type MerchantContractError = Readonly<{
  code: 'CONTRACTS_UNAVAILABLE' | 'ENVIRONMENT_DISABLED';
}>;

export interface MerchantContractPort {
  getCurrentContracts(): Result<readonly MerchantContract[], MerchantContractError>;
}

export const MERCHANT_CONTRACT_PORT = Symbol('MERCHANT_CONTRACT_PORT');
