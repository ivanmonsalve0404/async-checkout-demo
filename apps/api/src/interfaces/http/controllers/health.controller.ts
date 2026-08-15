import { Controller, Get, Header, Inject, Req } from '@nestjs/common';
import type { CatalogRepository } from '../../../application/ports/catalog-repository';
import { CATALOG_REPOSITORY } from '../../../application/ports/catalog-repository';
import { createProblem, ProblemException } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';

export interface HealthResponse {
  readonly status: 'ok';
  readonly checkedAt: string;
}

@Controller('api/health')
export class HealthController {
  public constructor(
    @Inject(CATALOG_REPOSITORY)
    private readonly catalogRepository: CatalogRepository,
  ) {}

  @Get()
  @Header('Cache-Control', 'no-store')
  public async getHealth(@Req() request: RequestWithCorrelation): Promise<HealthResponse> {
    if (!(await this.catalogRepository.isReady())) {
      throw new ProblemException(
        createProblem('ENVIRONMENT_MISMATCH', 503, request.correlationId, request.originalUrl),
      );
    }
    return { status: 'ok', checkedAt: new Date().toISOString() };
  }
}
