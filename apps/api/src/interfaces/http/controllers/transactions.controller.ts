import { Controller, Get, Header, Inject, Param, Req } from '@nestjs/common';
import { CheckoutService } from '../../../application/use-cases/checkout-service';
import { capabilityFrom, unwrap } from '../checkout-http';
import { presentTransaction } from '../presenters/checkout.presenter';
import type { RequestWithCorrelation } from '../request-context';

@Controller('api/v1/transactions')
export class TransactionsController {
  public constructor(@Inject(CheckoutService) private readonly service: CheckoutService) {}

  @Get(':transactionId')
  @Header('Cache-Control', 'no-store')
  public async get(
    @Param('transactionId') transactionId: string,
    @Req() request: RequestWithCorrelation,
  ) {
    return presentTransaction(
      unwrap(await this.service.getTransaction(transactionId, capabilityFrom(request)), request),
    );
  }
}
