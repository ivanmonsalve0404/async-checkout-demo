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

const bodyParsingStatus = (exception: unknown): 400 | 413 | null => {
  if (exception instanceof SyntaxError) return 400;
  if (exception instanceof HttpException && exception.getStatus() === 400) {
    return 400;
  }
  if (typeof exception !== 'object' || exception === null) return null;
  const candidate = exception as Readonly<{ status?: unknown; type?: unknown }>;
  if (
    (candidate.status === 400 ||
      (candidate as Readonly<{ statusCode?: unknown }>).statusCode === 400) &&
    (candidate.type === 'entity.parse.failed' || candidate.type === 'encoding.unsupported')
  ) {
    return 400;
  }
  return (candidate.status === 413 ||
    (candidate as Readonly<{ statusCode?: unknown }>).statusCode === 413) &&
    candidate.type === 'entity.too.large'
    ? 413
    : null;
};

@Catch()
export class ProblemFilter implements ExceptionFilter {
  public catch(exception: unknown, host: ArgumentsHost): void {
    const context = host.switchToHttp();
    const request = context.getRequest<RequestWithCorrelation>();
    const response = context.getResponse<Response>();
    const knownResponse = exception instanceof HttpException ? exception.getResponse() : null;
    const parsingStatus = bodyParsingStatus(exception);
    const problem =
      parsingStatus !== null
        ? createProblem(
            'REQUEST_MALFORMED',
            parsingStatus,
            request.correlationId,
            request.originalUrl,
          )
        : isProblem(knownResponse)
          ? knownResponse
          : createProblem('INTERNAL_ERROR', 500, request.correlationId, request.originalUrl);

    response.setHeader('Cache-Control', 'no-store');
    response.status(problem.status).type('application/problem+json').send(problem);
  }
}
