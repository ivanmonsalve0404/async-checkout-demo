import 'reflect-metadata';

import { NestFactory } from '@nestjs/core';

import { AppModule } from './app.module';
import { CheckoutService } from './application/use-cases/checkout-service';

export interface ReconciliationResult {
  readonly status: 'PASS' | 'FAIL';
  readonly reconciled: number;
}

export const handler = async (): Promise<ReconciliationResult> => {
  const application = await NestFactory.createApplicationContext(AppModule, { logger: false });
  try {
    const result = await application.get(CheckoutService).reconcileDue();
    if (!result.ok) throw new Error('RECONCILIATION_FAILED');
    return { status: 'PASS', reconciled: result.value };
  } finally {
    await application.close();
  }
};
