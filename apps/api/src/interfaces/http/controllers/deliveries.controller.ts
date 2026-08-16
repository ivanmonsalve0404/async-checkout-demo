import { Controller, Get, Header, Inject, Param, Req } from '@nestjs/common';
import { CheckoutService } from '../../../application/use-cases/checkout-service';
import { capabilityFrom, unwrap } from '../checkout-http';
import { presentDelivery } from '../presenters/checkout.presenter';
import type { RequestWithCorrelation } from '../request-context';

@Controller('api/v1/deliveries')
export class DeliveriesController {
  public constructor(@Inject(CheckoutService) private readonly service: CheckoutService) {}

  @Get(':deliveryId')
  @Header('Cache-Control', 'no-store')
  public async get(
    @Param('deliveryId') deliveryId: string,
    @Req() request: RequestWithCorrelation,
  ) {
    return presentDelivery(
      unwrap(await this.service.getDelivery(deliveryId, capabilityFrom(request)), request),
    );
  }
}
