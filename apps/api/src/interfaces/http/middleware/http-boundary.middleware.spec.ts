import { HttpException, type ArgumentsHost } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import type { AppConfig } from '../../../infrastructure/configuration/app-config';
import type { RuntimeSecrets } from '../../../infrastructure/configuration/runtime-secrets';
import { SafeLogger } from '../../../infrastructure/logging/safe-logger';
import { ProblemFilter } from '../filters/problem.filter';
import { createProblem, ProblemException } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';
import { CorrelationMiddleware } from './correlation.middleware';
import { OriginValidationMiddleware } from './origin-validation.middleware';
import { RequestLoggingMiddleware } from './request-logging.middleware';

type TestResponse = Omit<Response, 'once' | 'send' | 'setHeader' | 'status' | 'type'> &
  Readonly<{
    once: jest.Mock;
    send: jest.Mock;
    setHeader: jest.Mock;
    status: jest.Mock;
    type: jest.Mock;
  }>;

const response = (): TestResponse => {
  const candidate = {
    statusCode: 200,
    setHeader: jest.fn(),
    status: jest.fn(),
    type: jest.fn(),
    send: jest.fn(),
    once: jest.fn(),
  };
  candidate.status.mockReturnValue(candidate);
  candidate.type.mockReturnValue(candidate);
  candidate.send.mockReturnValue(candidate);
  return candidate as unknown as TestResponse;
};

const noGuardSecrets: RuntimeSecrets = {
  prereleaseOriginToken: undefined,
  runtimeSecurityRootKey: undefined,
  sandbox: undefined,
};

const originRequest = (
  method: string,
  headers: Readonly<Record<string, string | undefined>> = {},
  originalUrl = '/api/v1/checkouts',
): Request =>
  ({
    method,
    originalUrl,
    correlationId: 'corr-boundary-001',
    header: (name: string) => headers[name.toLowerCase()],
  }) as unknown as Request;

describe('HTTP security and observability middleware', () => {
  it.each([
    ['GET', {}],
    ['POST', { origin: 'https://shop.example.invalid', 'content-type': 'application/json' }],
    [
      'PUT',
      {
        origin: 'https://shop.example.invalid',
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
      },
    ],
  ])('accepts permitted origin case %#', (method, headers) => {
    const middleware = new OriginValidationMiddleware(
      {
        allowedOrigin: 'https://shop.example.invalid',
      } as AppConfig,
      noGuardSecrets,
    );
    const next = jest.fn() as NextFunction;
    middleware.use(originRequest(method, headers), response(), next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['POST', '/api/v1/checkouts'],
    ['PUT', '/api/v1/checkouts/checkout-001/customer'],
    ['PUT', '/api/v1/checkouts/checkout-001/delivery-details'],
    ['POST', '/api/v1/checkouts/checkout-001/transactions'],
  ])('rejects form-urlencoded on %s %s before a use case runs', (method, originalUrl) => {
    const middleware = new OriginValidationMiddleware(
      {
        allowedOrigin: 'https://shop.example.invalid',
      } as AppConfig,
      noGuardSecrets,
    );
    const invoke = () =>
      middleware.use(
        originRequest(
          method,
          {
            origin: 'https://shop.example.invalid',
            'content-type': 'application/x-www-form-urlencoded',
          },
          originalUrl,
        ),
        response(),
        jest.fn(),
      );
    expect(invoke).toThrow(ProblemException);
    try {
      invoke();
    } catch (error) {
      expect((error as ProblemException).getStatus()).toBe(415);
      expect((error as ProblemException).getResponse()).toMatchObject({
        code: 'REQUEST_MALFORMED',
        status: 415,
      });
    }
  });

  it.each([
    ['POST', {}],
    ['GET', { origin: 'https://evil.example.invalid' }],
    ['DELETE', { origin: 'https://shop.example.invalid', 'sec-fetch-site': 'cross-site' }],
  ])('rejects forbidden origin case %#', (method, headers) => {
    const middleware = new OriginValidationMiddleware(
      {
        allowedOrigin: 'https://shop.example.invalid',
      } as AppConfig,
      noGuardSecrets,
    );
    expect(() => middleware.use(originRequest(method, headers), response(), jest.fn())).toThrow(
      ProblemException,
    );
  });

  it.each([
    { headers: {}, label: 'missing' },
    { headers: { 'x-stage7-origin-verify': 'wrong-token' }, label: 'altered' },
  ])('rejects $label prerelease origin proof before routing', ({ headers }) => {
    const middleware = new OriginValidationMiddleware(
      {
        allowedOrigin: 'https://shop.example.invalid',
        prereleaseAccessMode: 'cloudfront_signed_cookie',
      } as AppConfig,
      {
        ...noGuardSecrets,
        prereleaseOriginToken: Buffer.alloc(32, 17).toString('base64url'),
      },
    );
    expect(() => middleware.use(originRequest('GET', headers), response(), jest.fn())).toThrow(
      ProblemException,
    );
  });

  it('accepts CloudFront origin proof only when the prerelease guard is active and exact', () => {
    const token = Buffer.alloc(32, 17).toString('base64url');
    const guarded = new OriginValidationMiddleware(
      {
        allowedOrigin: 'https://shop.example.invalid',
        prereleaseAccessMode: 'cloudfront_signed_cookie',
      } as AppConfig,
      { ...noGuardSecrets, prereleaseOriginToken: token },
    );
    const next = jest.fn();
    guarded.use(originRequest('GET', { 'x-stage7-origin-verify': token }), response(), next);
    expect(next).toHaveBeenCalledTimes(1);

    const fullRelease = new OriginValidationMiddleware(
      {
        allowedOrigin: 'https://shop.example.invalid',
        prereleaseAccessMode: 'origin_gate',
      } as AppConfig,
      { ...noGuardSecrets, prereleaseOriginToken: token },
    );
    expect(() => fullRelease.use(originRequest('GET'), response(), next)).toThrow(ProblemException);
    fullRelease.use(originRequest('GET', { 'x-stage7-origin-verify': token }), response(), next);
    expect(next).toHaveBeenCalledTimes(2);
  });

  it('always replaces client-supplied correlation IDs with a server-generated value', () => {
    const middleware = new CorrelationMiddleware();
    const accepted = originRequest('GET', { 'x-correlation-id': 'client-correlation-001' });
    const acceptedResponse = response();
    middleware.use(accepted, acceptedResponse, jest.fn());
    expect((accepted as RequestWithCorrelation).correlationId).toMatch(/^[0-9a-f-]{36}$/);
    expect((accepted as RequestWithCorrelation).correlationId).not.toBe('client-correlation-001');
    expect(acceptedResponse.setHeader).toHaveBeenCalledWith(
      'X-Correlation-Id',
      (accepted as RequestWithCorrelation).correlationId,
    );

    const replaced = originRequest('GET', { 'x-correlation-id': 'bad id' });
    middleware.use(replaced, response(), jest.fn());
    expect((replaced as RequestWithCorrelation).correlationId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('never writes a client-supplied Luhn value to logs', () => {
    const body = [4, ...Array<number>(14).fill(1)];
    const sum = body.reduce((total, digit, index) => {
      const doubled = index % 2 === 0 ? digit * 2 : digit;
      return total + (doubled > 9 ? doubled - 9 : doubled);
    }, 0);
    const clientValue = `${body.join('')}${(10 - (sum % 10)) % 10}`;
    const candidate = originRequest('GET', { 'x-correlation-id': clientValue });
    new CorrelationMiddleware().use(candidate, response(), jest.fn());

    const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      new SafeLogger('api', 'test', 'e5').info('http.request.completed', {
        correlationId: (candidate as RequestWithCorrelation).correlationId,
      });
      const leaked = write.mock.calls.some(([entry]) => String(entry).includes(clientValue));
      expect(leaked).toBe(false);
    } finally {
      write.mockRestore();
    }
  });

  it.each([
    ['/api/v1/products/product-demo-001?expand=false', '/api/v1/products/{productId}'],
    ['/api/v1/stock/product-demo-001', '/api/v1/stock/{productId}'],
    ['/api/v1/checkouts/checkout-001/customer', '/api/v1/checkouts/{checkoutId}/customer'],
    ['/api/v1/transactions/transaction-001', '/api/v1/transactions/{transactionId}'],
    ['/api/v1/deliveries/delivery-001', '/api/v1/deliveries/{deliveryId}'],
  ])('logs normalized route %s', (originalUrl, normalized) => {
    const logger = { info: jest.fn() };
    const middleware = new RequestLoggingMiddleware(logger as unknown as SafeLogger);
    let finish: (() => void) | undefined;
    const target = response();
    target.once.mockImplementation((_event: string, listener: () => void) => {
      finish = listener;
      return target;
    });
    const candidate = {
      method: 'GET',
      originalUrl,
      path: originalUrl,
      correlationId: 'corr-log-001',
    } as RequestWithCorrelation;
    const next = jest.fn() as NextFunction;
    middleware.use(candidate, target, next);
    target.statusCode = 204;
    finish?.();
    expect(next).toHaveBeenCalledTimes(1);
    expect(logger.info).toHaveBeenCalledWith(
      'http.request.completed',
      expect.objectContaining({
        correlationId: 'corr-log-001',
        requestId: 'corr-log-001',
        route: normalized,
        resultCode: 204,
      }),
    );
  });
});

describe('ProblemFilter', () => {
  const invoke = (exception: unknown) => {
    const target = response();
    const candidateRequest = {
      correlationId: 'corr-problem-001',
      originalUrl: '/api/v1/checkouts',
    } as RequestWithCorrelation;
    const host = {
      switchToHttp: () => ({
        getRequest: () => candidateRequest,
        getResponse: () => target,
      }),
    } as ArgumentsHost;
    new ProblemFilter().catch(exception, host);
    return target;
  };

  it('preserves an already safe RFC 9457 problem', () => {
    const problem = createProblem('OUT_OF_STOCK', 409, 'corr-problem-001', '/api/v1/checkouts');
    const target = invoke(new ProblemException(problem));
    expect(target.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
    expect(target.status).toHaveBeenCalledWith(409);
    expect(target.send).toHaveBeenCalledWith(problem);
  });

  it.each([
    [new SyntaxError('bad JSON'), 400],
    [new HttpException('bad JSON', 400), 400],
    [{ status: 400, type: 'entity.parse.failed' }, 400],
    [{ statusCode: 400, type: 'encoding.unsupported' }, 400],
    [{ status: 413, type: 'entity.too.large' }, 413],
    [{ statusCode: 413, type: 'entity.too.large' }, 413],
  ])('maps parser failure %# to REQUEST_MALFORMED/%s', (exception, status) => {
    const target = invoke(exception);
    expect(target.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
    expect(target.status).toHaveBeenCalledWith(status);
    expect(target.send).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'REQUEST_MALFORMED', status }),
    );
  });

  it.each([null, 'boom', { status: 400, type: 'other' }, new HttpException({ status: 400 }, 409)])(
    'redacts unknown exception %# as INTERNAL_ERROR',
    (exception) => {
      const target = invoke(exception);
      expect(target.status).toHaveBeenCalledWith(500);
      expect(target.type).toHaveBeenCalledWith('application/problem+json');
      expect(target.send).toHaveBeenCalledWith(
        expect.objectContaining({ code: 'INTERNAL_ERROR', retryable: true }),
      );
    },
  );
});
