import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { CheckoutService } from '../../application/use-cases/checkout-service';
import { APP_CONFIG, type AppConfig } from '../configuration/app-config';
import { SafeLogger } from '../logging/safe-logger';

@Injectable()
export class FakeReconciliationRunner implements OnModuleInit, OnModuleDestroy {
  private timer?: NodeJS.Timeout;
  private running = false;

  public constructor(
    @Inject(CheckoutService) private readonly service: CheckoutService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    @Inject(SafeLogger) private readonly logger: SafeLogger,
  ) {}

  public onModuleInit(): void {
    if (this.config.paymentAdapter !== 'fake') return;
    this.timer = setInterval(() => {
      void this.tick().catch(() => this.logger.info('payment.reconciliation.failed', {}));
    }, this.config.fakeReconcileIntervalMs);
    this.timer.unref();
  }

  public onModuleDestroy(): void {
    if (this.timer !== undefined) clearInterval(this.timer);
  }

  private async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      await this.service.reconcileDue();
    } finally {
      this.running = false;
    }
  }
}
