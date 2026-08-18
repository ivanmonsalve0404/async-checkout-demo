import {
  Body,
  Controller,
  Get,
  Header,
  Headers,
  HttpCode,
  Inject,
  Param,
  Post,
  Put,
  Req,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import {
  type CheckoutApplicationError,
  CheckoutService,
} from '../../../application/use-cases/checkout-service';
import { APP_CONFIG, type AppConfig } from '../../../infrastructure/configuration/app-config';
import {
  capabilityCookie,
  capabilityFrom,
  createCheckoutSchema,
  customerSchema,
  deliveryDetailsSchema,
  parseBody,
  paymentSubmissionSchemaFor,
  setCheckoutHeaders,
  unwrap,
  type DeliveryInput,
  type PaymentTokenValidationMode,
} from '../checkout-http';
import {
  presentCheckout,
  presentCheckoutCreated,
  presentCustomer,
  presentDeliveryDetails,
  presentSubmission,
} from '../presenters/checkout.presenter';
import type { RequestWithCorrelation } from '../request-context';

const paymentTokenValidationModeFor = (
  config: Pick<AppConfig, 'paymentAdapter' | 'paymentsEnabled'>,
): PaymentTokenValidationMode =>
  config.paymentAdapter === 'fake'
    ? 'FAKE'
    : config.paymentsEnabled
      ? 'AUTHORIZED_SANDBOX'
      : 'DISABLED';

@Controller('api/v1/checkouts')
export class CheckoutsController {
  public constructor(
    @Inject(CheckoutService) private readonly service: CheckoutService,
    @Inject(APP_CONFIG)
    private readonly config: Pick<AppConfig, 'paymentAdapter' | 'paymentsEnabled'>,
  ) {}

  private async setRecoveryHeaders(
    checkoutId: string,
    capability: string | null,
    code: CheckoutApplicationError['code'],
    response: Response,
  ): Promise<void> {
    if (code !== 'PRECONDITION_FAILED' && code !== 'PAYMENT_ALREADY_IN_PROGRESS') return;
    const current = await this.service.getCheckout(checkoutId, capability);
    if (!current.ok) return;
    if (code === 'PRECONDITION_FAILED') {
      setCheckoutHeaders(response, current.value.checkout);
      return;
    }
    const transactionId = current.value.checkout.activeTransactionId;
    if (transactionId !== undefined) {
      response.setHeader('Location', `/api/v1/transactions/${transactionId}`);
    }
  }

  @Post()
  @HttpCode(201)
  @Header('Cache-Control', 'no-store')
  @Header('Vary', 'Origin')
  public async create(
    @Body() body: unknown,
    @Req() request: RequestWithCorrelation,
    @Res({ passthrough: true }) response: Response,
  ) {
    const input = parseBody(createCheckoutSchema, body, request);
    const created = unwrap(await this.service.createCheckout(input.productId), request);
    response.setHeader('Location', `/api/v1/checkouts/${created.checkout.checkoutId}`);
    response.setHeader('Set-Cookie', capabilityCookie(created.rawCapability));
    setCheckoutHeaders(response, created.checkout);
    return presentCheckoutCreated(created.checkout);
  }

  @Get(':checkoutId')
  @Header('Cache-Control', 'no-store')
  public async get(
    @Param('checkoutId') checkoutId: string,
    @Req() request: RequestWithCorrelation,
    @Res({ passthrough: true }) response: Response,
  ) {
    const view = unwrap(
      await this.service.getCheckout(checkoutId, capabilityFrom(request)),
      request,
    );
    setCheckoutHeaders(response, view.checkout);
    return presentCheckout(view);
  }

  @Put(':checkoutId/customer')
  @Header('Cache-Control', 'no-store')
  public async replaceCustomer(
    @Param('checkoutId') checkoutId: string,
    @Headers('if-match') ifMatch: string | undefined,
    @Body() body: unknown,
    @Req() request: RequestWithCorrelation,
    @Res({ passthrough: true }) response: Response,
  ) {
    const input = parseBody(customerSchema, body, request);
    const capability = capabilityFrom(request);
    const result = await this.service.replaceCustomer(checkoutId, capability, ifMatch, input);
    if (!result.ok) {
      await this.setRecoveryHeaders(checkoutId, capability, result.error.code, response);
    }
    const checkout = unwrap(result, request);
    setCheckoutHeaders(response, checkout);
    return presentCustomer(checkout);
  }

  @Put(':checkoutId/delivery-details')
  @Header('Cache-Control', 'no-store')
  public async replaceDeliveryDetails(
    @Param('checkoutId') checkoutId: string,
    @Headers('if-match') ifMatch: string | undefined,
    @Body() body: unknown,
    @Req() request: RequestWithCorrelation,
    @Res({ passthrough: true }) response: Response,
  ) {
    const input = parseBody(deliveryDetailsSchema, body, request) as DeliveryInput;
    const capability = capabilityFrom(request);
    const result = await this.service.replaceDeliveryDetails(
      checkoutId,
      capability,
      ifMatch,
      input,
    );
    if (!result.ok) {
      await this.setRecoveryHeaders(checkoutId, capability, result.error.code, response);
    }
    const checkout = unwrap(result, request);
    setCheckoutHeaders(response, checkout);
    return presentDeliveryDetails(checkout);
  }

  @Post(':checkoutId/transactions')
  @HttpCode(202)
  @Header('Cache-Control', 'no-store')
  public async submitPayment(
    @Param('checkoutId') checkoutId: string,
    @Headers('if-match') ifMatch: string | undefined,
    @Headers('idempotency-key') idempotencyKey: string | undefined,
    @Body() body: unknown,
    @Req() request: RequestWithCorrelation,
    @Res({ passthrough: true }) response: Response,
  ) {
    const input = parseBody(
      paymentSubmissionSchemaFor(paymentTokenValidationModeFor(this.config)),
      body,
      request,
    );
    const capability = capabilityFrom(request);
    const result = await this.service.submitPayment(
      checkoutId,
      capability,
      ifMatch,
      idempotencyKey,
      input,
    );
    if (!result.ok) {
      await this.setRecoveryHeaders(checkoutId, capability, result.error.code, response);
    }
    const submission = unwrap(result, request);
    response.setHeader('Location', submission.statusUrl);
    return presentSubmission(submission);
  }
}
