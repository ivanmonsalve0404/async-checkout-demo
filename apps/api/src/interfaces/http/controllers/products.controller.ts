import { Controller, Get, Header, Inject, Param, Req } from '@nestjs/common';
import { GetProductAvailability } from '../../../application/use-cases/get-product-availability';
import { ListProducts } from '../../../application/use-cases/list-products';
import { createProblem, ProblemException } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';
import { presentProduct, type ProductResponse } from '../presenters/product.presenter';

@Controller('api/v1/products')
export class ProductsController {
  public constructor(
    @Inject(ListProducts)
    private readonly listProducts: ListProducts,
    @Inject(GetProductAvailability)
    private readonly getProductAvailability: GetProductAvailability,
  ) {}
  @Get()
  @Header('Cache-Control', 'no-cache')
  public async list(
    @Req() request: RequestWithCorrelation,
  ): Promise<Readonly<{ items: readonly ProductResponse[]; count: number }>> {
    const result = await this.listProducts.execute();
    if (!result.ok) {
      throw new ProblemException(
        createProblem('INTERNAL_ERROR', 500, request.correlationId, request.originalUrl),
      );
    }
    const items = result.value.map(presentProduct);
    return { items, count: items.length };
  }

  @Get(':productId')
  @Header('Cache-Control', 'no-cache')
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
