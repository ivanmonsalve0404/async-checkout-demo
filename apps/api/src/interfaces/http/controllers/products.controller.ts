import { Controller, Get, Header, Inject, Param, Req } from '@nestjs/common';
import { GetProductAvailability } from '../../../application/use-cases/get-product-availability';
import { createProblem, ProblemException } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';
import { presentProduct, type ProductResponse } from '../presenters/product.presenter';

@Controller('api/v1/products')
export class ProductsController {
  public constructor(
    @Inject(GetProductAvailability)
    private readonly getProductAvailability: GetProductAvailability,
  ) {}

  @Get(':productId')
  @Header('Cache-Control', 'public, max-age=300')
  public async getProduct(
    @Param('productId') productId: string,
    @Req() request: RequestWithCorrelation,
  ): Promise<ProductResponse> {
    const result = await this.getProductAvailability.execute(productId);
    if (result.ok) {
      return presentProduct(result.value);
    }
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
