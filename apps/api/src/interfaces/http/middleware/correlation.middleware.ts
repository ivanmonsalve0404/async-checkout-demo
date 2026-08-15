import { Injectable, type NestMiddleware } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

const safeCorrelationId = /^[A-Za-z0-9._:-]{8,128}$/;

@Injectable()
export class CorrelationMiddleware implements NestMiddleware {
  public use(request: Request, response: Response, next: NextFunction): void {
    const candidate = request.header('x-correlation-id');
    const correlationId =
      candidate !== undefined && safeCorrelationId.test(candidate) ? candidate : randomUUID();
    Object.assign(request, { correlationId });
    response.setHeader('X-Correlation-Id', correlationId);
    next();
  }
}
