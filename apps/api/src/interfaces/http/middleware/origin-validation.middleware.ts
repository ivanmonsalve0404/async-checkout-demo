import { Inject, Injectable, type NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { APP_CONFIG, type AppConfig } from '../../../infrastructure/configuration/app-config';
import { createProblem, ProblemException } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';

const unsafeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const jsonMethods = new Set(['POST', 'PUT', 'PATCH']);

@Injectable()
export class OriginValidationMiddleware implements NestMiddleware {
  public constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  public use(request: Request, response: Response, next: NextFunction): void {
    void response;
    const origin = request.header('origin');
    const crossSite = request.header('sec-fetch-site') === 'cross-site';
    const forbidden =
      (unsafeMethods.has(request.method) && (origin !== this.config.allowedOrigin || crossSite)) ||
      (origin !== undefined && origin !== this.config.allowedOrigin);
    if (forbidden) {
      const correlated = request as RequestWithCorrelation;
      throw new ProblemException(
        createProblem('ORIGIN_FORBIDDEN', 403, correlated.correlationId, correlated.originalUrl),
      );
    }

    if (jsonMethods.has(request.method)) {
      const contentType = request.header('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
      if (contentType !== 'application/json') {
        const correlated = request as RequestWithCorrelation;
        throw new ProblemException(
          createProblem('REQUEST_MALFORMED', 415, correlated.correlationId, correlated.originalUrl),
        );
      }
    }

    next();
  }
}
