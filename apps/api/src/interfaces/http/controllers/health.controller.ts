import { Controller, Get, Header, Inject, Req } from '@nestjs/common';
import type { CatalogRepository } from '../../../application/ports/catalog-repository';
import { CATALOG_REPOSITORY } from '../../../application/ports/catalog-repository';
import type { PaymentProvider } from '../../../application/ports/payment-provider';
import { PAYMENT_PROVIDER } from '../../../application/ports/payment-provider';
import { createProblem, ProblemException } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';

export interface HealthResponse {
  readonly status: 'ok';
  readonly checkedAt: string;
}

export interface LivenessResponse {
  readonly status: 'alive';
  readonly checkedAt: string;
}

@Controller('api/health')
export class HealthController {
  public constructor(
    @Inject(CATALOG_REPOSITORY)
    private readonly catalogRepository: CatalogRepository,
    @Inject(PAYMENT_PROVIDER)
    private readonly paymentProvider: PaymentProvider,
  ) {}

  @Get()
  @Header('Cache-Control', 'no-store')
  public async getHealth(@Req() request: RequestWithCorrelation): Promise<HealthResponse> {
    return this.getReadiness(request);
  }

  @Get('live')
  @Header('Cache-Control', 'no-store')
  public getLiveness(): LivenessResponse {
    return { status: 'alive', checkedAt: new Date().toISOString() };
  }

  @Get('ready')
  @Header('Cache-Control', 'no-store')
  public async getReadiness(@Req() request: RequestWithCorrelation): Promise<HealthResponse> {
    if (
      !(await this.catalogRepository.isReady()) ||
      !this.paymentProvider.getPublicConfiguration().ok
    ) {
      throw new ProblemException(
        createProblem('ENVIRONMENT_MISMATCH', 503, request.correlationId, request.originalUrl),
      );
    }
    return { status: 'ok', checkedAt: new Date().toISOString() };
  }
}
