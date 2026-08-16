import { Injectable, type NestMiddleware } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

@Injectable()
export class CorrelationMiddleware implements NestMiddleware {
  public use(request: Request, response: Response, next: NextFunction): void {
    const correlationId = randomUUID();
    Object.assign(request, { correlationId });
    response.setHeader('X-Correlation-Id', correlationId);
    next();
  }
}
