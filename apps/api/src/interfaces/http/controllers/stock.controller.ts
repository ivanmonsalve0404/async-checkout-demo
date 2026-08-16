import { Controller, Get, Header, Inject, Param, Req } from '@nestjs/common';
import {
  GetProductStock,
  type ProductStock,
} from '../../../application/use-cases/get-product-stock';
import { createProblem, ProblemException } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';

@Controller('api/v1/stock')
export class StockController {
  public constructor(@Inject(GetProductStock) private readonly getProductStock: GetProductStock) {}

  @Get(':productId')
  @Header('Cache-Control', 'no-cache')
  public async get(
    @Param('productId') productId: string,
    @Req() request: RequestWithCorrelation,
  ): Promise<ProductStock> {
    const result = await this.getProductStock.execute(productId);
    if (result.ok) return result.value;
    if (result.error.code === 'INVALID_PRODUCT_ID' || result.error.code === 'PRODUCT_NOT_FOUND') {
      throw new ProblemException(
        createProblem('PRODUCT_NOT_FOUND', 404, request.correlationId, request.originalUrl),
      );
    }
    throw new ProblemException(
      createProblem('INTERNAL_ERROR', 500, request.correlationId, request.originalUrl),
    );
  }
}
