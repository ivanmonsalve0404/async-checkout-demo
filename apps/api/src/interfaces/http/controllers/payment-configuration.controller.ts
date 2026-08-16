import { Controller, Get, Header, Inject, Req } from '@nestjs/common';
import { CheckoutService } from '../../../application/use-cases/checkout-service';
import { unwrap } from '../checkout-http';
import type { RequestWithCorrelation } from '../request-context';

@Controller('api/v1/payment-configuration')
export class PaymentConfigurationController {
  public constructor(@Inject(CheckoutService) private readonly service: CheckoutService) {}

  @Get()
  @Header('Cache-Control', 'no-store')
  @Header('Vary', 'Origin')
  public get(@Req() request: RequestWithCorrelation) {
    return unwrap(this.service.getPaymentConfiguration(), request);
  }
}
