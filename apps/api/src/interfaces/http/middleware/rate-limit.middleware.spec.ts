import type { NextFunction, Request, Response } from 'express';
import { ProblemException } from '../problems/problem';
import { RateLimitMiddleware } from './rate-limit.middleware';

const request = (
  method: string,
  originalUrl: string,
  options: Readonly<{ cookie?: string; remoteAddress?: string; origin?: string }> = {},
): Request =>
  ({
    method,
    originalUrl,
    correlationId: 'corr-rate-001',
    headers: {
      ...(options.cookie === undefined ? {} : { cookie: options.cookie }),
      ...(options.origin === undefined ? {} : { origin: options.origin }),
    },
    socket: { remoteAddress: options.remoteAddress },
  }) as unknown as Request;

type TestResponse = Omit<Response, 'setHeader'> & Readonly<{ setHeader: jest.Mock }>;

const response = (): TestResponse => ({ setHeader: jest.fn() }) as unknown as TestResponse;

describe('RateLimitMiddleware', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it.each([
    ['GET', '/api/v1/products'],
    ['POST', '/api/v1/products'],
    ['PUT', '/api/v1/checkouts/checkout-001/not-sensitive'],
  ])('bypasses non-sensitive %s %s', (method, url) => {
    const limiter = new RateLimitMiddleware();
    const target = response();
    const next = jest.fn() as NextFunction;
    limiter.use(request(method, url), target, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(target.setHeader).not.toHaveBeenCalled();
  });

  it.each([
    ['POST', '/api/v1/checkouts', 10, 9],
    ['PUT', '/api/v1/checkouts/checkout-001/customer', 10, 9],
    ['PUT', '/api/v1/checkouts/checkout-001/delivery-details', 10, 9],
    ['POST', '/api/v1/checkouts/checkout-001/transactions?source=retry', 2, 1],
  ])('applies the approved quota to %s %s', (method, url, limit, remaining) => {
    jest.spyOn(Date, 'now').mockReturnValue(1_000);
    const limiter = new RateLimitMiddleware();
    const target = response();
    const next = jest.fn() as NextFunction;
    limiter.use(
      request(method, url, {
        remoteAddress: '192.0.2.1',
        cookie: '__Secure-checkout_cap=one',
        origin: 'http://localhost:5173',
      }),
      target,
      next,
    );
    expect(next).toHaveBeenCalledTimes(1);
    expect(target.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', limit);
    expect(target.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', remaining);
  });

  it('limits payment to two attempts per minute and refills after thirty seconds', () => {
    let now = 10_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    const limiter = new RateLimitMiddleware();
    const payment = request('POST', '/api/v1/checkouts/checkout-001/transactions', {
      remoteAddress: '192.0.2.1',
      cookie: '__Secure-checkout_cap=one',
    });
    limiter.use(payment, response(), jest.fn());
    limiter.use(payment, response(), jest.fn());

    const rejected = response();
    expect(() => limiter.use(payment, rejected, jest.fn())).toThrow(ProblemException);
    expect(rejected.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', 2);
    expect(rejected.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', 0);
    expect(rejected.setHeader).toHaveBeenCalledWith('Retry-After', 30);

    now += 30_000;
    const next = jest.fn();
    limiter.use(payment, response(), next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('keeps checkout creation and customer mutation in independent ten-per-minute buckets', () => {
    jest.spyOn(Date, 'now').mockReturnValue(10_000);
    const limiter = new RateLimitMiddleware();
    const create = request('POST', '/api/v1/checkouts', {
      remoteAddress: '192.0.2.2',
      origin: 'http://localhost:5173',
    });
    for (let index = 0; index < 10; index += 1) limiter.use(create, response(), jest.fn());
    expect(() => limiter.use(create, response(), jest.fn())).toThrow(ProblemException);

    const mutation = request('PUT', '/api/v1/checkouts/checkout-001/customer', {
      remoteAddress: '192.0.2.2',
      cookie: '__Secure-checkout_cap=one',
    });
    expect(() => limiter.use(mutation, response(), jest.fn())).not.toThrow();
  });

  it('does not let rotating only the capability or only the network identity evade payment quota', () => {
    jest.spyOn(Date, 'now').mockReturnValue(10_000);

    const networkBound = new RateLimitMiddleware();
    for (let index = 0; index < 2; index += 1) {
      networkBound.use(
        request('POST', '/api/v1/checkouts/checkout-001/transactions', {
          remoteAddress: '192.0.2.3',
          cookie: '__Secure-checkout_cap=one',
        }),
        response(),
        jest.fn(),
      );
    }
    expect(() =>
      networkBound.use(
        request('POST', '/api/v1/checkouts/checkout-001/transactions', {
          remoteAddress: '192.0.2.3',
          cookie: '__Secure-checkout_cap=rotated',
        }),
        response(),
        jest.fn(),
      ),
    ).toThrow(ProblemException);

    const capabilityBound = new RateLimitMiddleware();
    for (let index = 0; index < 2; index += 1) {
      capabilityBound.use(
        request('POST', '/api/v1/checkouts/checkout-001/transactions', {
          remoteAddress: '192.0.2.4',
          cookie: '__Secure-checkout_cap=stable',
        }),
        response(),
        jest.fn(),
      );
    }
    expect(() =>
      capabilityBound.use(
        request('POST', '/api/v1/checkouts/checkout-001/transactions', {
          remoteAddress: '192.0.2.5',
          cookie: '__Secure-checkout_cap=stable',
        }),
        response(),
        jest.fn(),
      ),
    ).toThrow(ProblemException);
  });

  it('keeps the bucket cache bounded by evicting the oldest identity', () => {
    jest.spyOn(Date, 'now').mockReturnValue(1_000);
    const limiter = new RateLimitMiddleware();
    for (let index = 0; index <= 10_000; index += 1) {
      limiter.use(
        request('POST', '/api/v1/checkouts', {
          remoteAddress: `192.0.2.${index}`,
          origin: 'http://localhost:5173',
        }),
        response(),
        jest.fn(),
      );
    }
    expect(() =>
      limiter.use(
        request('POST', '/api/v1/checkouts', {
          remoteAddress: '192.0.2.0',
          origin: 'http://localhost:5173',
        }),
        response(),
        jest.fn(),
      ),
    ).not.toThrow();
  });
});
