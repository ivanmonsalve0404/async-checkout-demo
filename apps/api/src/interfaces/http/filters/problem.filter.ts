import { ArgumentsHost, Catch, HttpException, type ExceptionFilter } from '@nestjs/common';
import type { Response } from 'express';
import { createProblem, type ProblemDetails } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';

const isProblem = (value: unknown): value is ProblemDetails => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const candidate = value as Partial<ProblemDetails>;
  return (
    typeof candidate.type === 'string' &&
    typeof candidate.title === 'string' &&
    typeof candidate.status === 'number' &&
    typeof candidate.detail === 'string' &&
    typeof candidate.instance === 'string' &&
    typeof candidate.code === 'string' &&
    typeof candidate.correlationId === 'string' &&
    typeof candidate.retryable === 'boolean'
  );
};

@Catch()
export class ProblemFilter implements ExceptionFilter {
  public catch(exception: unknown, host: ArgumentsHost): void {
    const context = host.switchToHttp();
    const request = context.getRequest<RequestWithCorrelation>();
    const response = context.getResponse<Response>();
    const knownResponse = exception instanceof HttpException ? exception.getResponse() : null;
    const problem = isProblem(knownResponse)
      ? knownResponse
      : createProblem('INTERNAL_ERROR', 500, request.correlationId, request.originalUrl);

    response.status(problem.status).type('application/problem+json').send(problem);
  }
}
