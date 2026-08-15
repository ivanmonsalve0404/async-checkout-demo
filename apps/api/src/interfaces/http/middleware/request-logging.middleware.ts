import { Inject, Injectable, type NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { SafeLogger } from '../../../infrastructure/logging/safe-logger';
import type { RequestWithCorrelation } from '../request-context';

const normalizePath = (path: string): string =>
  path.replace(/\/api\/v1\/products\/[^/]+$/, '/api/v1/products/{productId}');

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
        route: normalizePath(request.path),
        method: request.method,
        durationMs: Math.round(performance.now() - startedAt),
        resultCode: response.statusCode,
      });
    });
    next();
  }
}
