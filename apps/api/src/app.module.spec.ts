import { Test } from '@nestjs/testing';
import { AppModule, selectReconciliationBackoffPolicy } from './app.module';
import {
  LOCAL_FAKE_RECONCILIATION_BACKOFF_POLICY,
  PRODUCTION_RECONCILIATION_BACKOFF_POLICY,
} from './application/use-cases/checkout-service';
import { CHECKOUT_REPOSITORY } from './application/ports/checkout-repository';
import { MERCHANT_CONTRACT_PORT } from './application/ports/merchant-contract';
import { APP_CONFIG, loadAppConfig } from './infrastructure/configuration/app-config';
import { FakeMerchantContractAdapter } from './infrastructure/payment/fake-merchant-contract.adapter';
import { SandboxMerchantContractAdapter } from './infrastructure/payment/sandbox-merchant-contract.adapter';
import { DynamoDbCheckoutRepository } from './infrastructure/persistence/dynamodb-checkout.repository';
import { InMemoryCheckoutRepository } from './infrastructure/persistence/in-memory-checkout.repository';

describe('AppModule adapter wiring', () => {
  it.each([
    ['memory', loadAppConfig({ APP_ENV: 'test' }), InMemoryCheckoutRepository],
    [
      'dynamodb',
      loadAppConfig({
        APP_ENV: 'test',
        DATA_ADAPTER: 'dynamodb',
        DYNAMODB_ENDPOINT: 'http://127.0.0.1:8000',
        RUNTIME_SECURITY_ROOT_KEY: Buffer.alloc(32, 9).toString('base64url'),
      }),
      DynamoDbCheckoutRepository,
    ],
  ] as const)('selects the %s checkout repository', async (_name, config, expected) => {
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(APP_CONFIG)
      .useValue(config)
      .compile();

    expect(module.get(CHECKOUT_REPOSITORY)).toBeInstanceOf(expected);
    await module.close();
  });

  it.each([
    ['fake', loadAppConfig({ APP_ENV: 'test' }), FakeMerchantContractAdapter],
    [
      'sandbox',
      loadAppConfig({ APP_ENV: 'test', PAYMENT_ADAPTER: 'sandbox' }),
      SandboxMerchantContractAdapter,
    ],
  ] as const)('selects the %s merchant contract adapter', async (_name, config, expected) => {
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(APP_CONFIG)
      .useValue(config)
      .compile();

    expect(module.get(MERCHANT_CONTRACT_PORT)).toBeInstanceOf(expected);
    await module.close();
  });

  it.each([
    ['local fake', loadAppConfig({ APP_ENV: 'local' }), LOCAL_FAKE_RECONCILIATION_BACKOFF_POLICY],
    ['test fake', loadAppConfig({ APP_ENV: 'test' }), LOCAL_FAKE_RECONCILIATION_BACKOFF_POLICY],
    [
      'preview fake',
      loadAppConfig({ APP_ENV: 'preview' }),
      PRODUCTION_RECONCILIATION_BACKOFF_POLICY,
    ],
    [
      'local sandbox',
      loadAppConfig({ APP_ENV: 'local', PAYMENT_ADAPTER: 'sandbox' }),
      PRODUCTION_RECONCILIATION_BACKOFF_POLICY,
    ],
  ] as const)('selects the expected %s reconciliation policy', (_name, config, expected) => {
    expect(selectReconciliationBackoffPolicy(config)).toBe(expected);
  });
});
