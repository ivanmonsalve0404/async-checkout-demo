import { Inject, Injectable, type NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { SafeLogger } from '../../../infrastructure/logging/safe-logger';
import type { RequestWithCorrelation } from '../request-context';

const resourceIdName: Readonly<Record<string, string>> = {
  products: 'productId',
  stock: 'productId',
  checkouts: 'checkoutId',
  transactions: 'transactionId',
  deliveries: 'deliveryId',
};
const normalizePath = (path: string): string =>
  path.replace(
    /(\/api\/v1\/(products|stock|checkouts|transactions|deliveries))\/[^/]+/,
    (_match, prefix: string, resource: string) => `${prefix}/{${resourceIdName[resource]}}`,
  );

@Injectable()
export class RequestLoggingMiddleware implements NestMiddleware {
  public constructor(@Inject(SafeLogger) private readonly logger: SafeLogger) {}

  public use(request: Request, response: Response, next: NextFunction): void {
    const startedAt = performance.now();
    response.once('finish', () => {
      const correlatedRequest = request as RequestWithCorrelation;
      this.logger.info('http.request.completed', {
        requestId: correlatedRequest.correlationId,
        correlationId: correlatedRequest.correlationId,
        route: normalizePath(request.originalUrl.split('?')[0] ?? request.path),
        method: request.method,
        durationMs: Math.round(performance.now() - startedAt),
        resultCode: response.statusCode,
      });
    });
    next();
  }
}
