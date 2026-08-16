import { createHash } from 'node:crypto';
import { Injectable, type NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { CAPABILITY_COOKIE_NAME } from '../checkout-http';
import { createProblem, ProblemException } from '../problems/problem';
import type { RequestWithCorrelation } from '../request-context';

interface Bucket {
  tokens: number;
  checkedAt: number;
}

interface Policy {
  readonly scope: 'checkout-create' | 'checkout-mutation' | 'payment';
  readonly capacity: number;
  readonly refillPerMillisecond: number;
}

const PER_MINUTE = 1 / 60_000;
const policies = {
  checkoutCreate: {
    scope: 'checkout-create',
    capacity: 10,
    refillPerMillisecond: 10 * PER_MINUTE,
  },
  checkoutMutation: {
    scope: 'checkout-mutation',
    capacity: 10,
    refillPerMillisecond: 10 * PER_MINUTE,
  },
  payment: {
    scope: 'payment',
    capacity: 2,
    refillPerMillisecond: 2 * PER_MINUTE,
  },
} as const satisfies Readonly<Record<string, Policy>>;
const MAX_BUCKETS = 10_000;

const policyFor = (request: Request): Policy | null => {
  const path = request.originalUrl.split('?')[0] ?? '';
  if (request.method === 'POST' && path === '/api/v1/checkouts') return policies.checkoutCreate;
  if (request.method === 'POST' && /^\/api\/v1\/checkouts\/[^/]+\/transactions$/.test(path)) {
    return policies.payment;
  }
  if (
    request.method === 'PUT' &&
    /^\/api\/v1\/checkouts\/[^/]+\/(customer|delivery-details)$/.test(path)
  ) {
    return policies.checkoutMutation;
  }
  return null;
};

const capabilityFrom = (request: Request): string | undefined =>
  request.headers.cookie
    ?.split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${CAPABILITY_COOKIE_NAME}=`));

const bucketKeys = (request: Request, policy: Policy): readonly string[] => {
  const network = request.socket.remoteAddress ?? 'unknown';
  const origin = typeof request.headers.origin === 'string' ? request.headers.origin : 'no-origin';
  const capability = capabilityFrom(request);
  const identities =
    policy.scope === 'checkout-create'
      ? [`network|${network}|origin|${origin}`]
      : [`network|${network}`, ...(capability === undefined ? [] : [`capability|${capability}`])];
  return identities.map((identity) =>
    createHash('sha256').update(`${policy.scope}|${identity}`).digest('base64url'),
  );
};

@Injectable()
export class RateLimitMiddleware implements NestMiddleware {
  // ponytail: process-local buckets cover the local demo; API Gateway owns distributed throttling.
  private readonly buckets = new Map<string, Bucket>();

  public use(request: Request, response: Response, next: NextFunction): void {
    const policy = policyFor(request);
    if (policy === null) {
      next();
      return;
    }
    const now = Date.now();
    const candidates = bucketKeys(request, policy).map((key) => {
      const previous = this.buckets.get(key) ?? { tokens: policy.capacity, checkedAt: now };
      const tokens = Math.min(
        policy.capacity,
        previous.tokens + Math.max(0, now - previous.checkedAt) * policy.refillPerMillisecond,
      );
      return { key, tokens };
    });
    response.setHeader('X-RateLimit-Limit', policy.capacity);
    const blocked = candidates.filter(({ tokens }) => tokens < 1);
    if (blocked.length > 0) {
      const retryAfterSeconds = Math.max(
        ...blocked.map(({ tokens }) =>
          Math.max(1, Math.ceil((1 - tokens) / policy.refillPerMillisecond / 1_000)),
        ),
      );
      response.setHeader('X-RateLimit-Remaining', 0);
      response.setHeader('Retry-After', retryAfterSeconds);
      const correlated = request as RequestWithCorrelation;
      throw new ProblemException(
        createProblem('RATE_LIMITED', 429, correlated.correlationId, correlated.originalUrl),
      );
    }
    for (const { key, tokens } of candidates) {
      if (!this.buckets.has(key) && this.buckets.size >= MAX_BUCKETS) {
        const oldest = this.buckets.keys().next().value;
        if (oldest !== undefined) this.buckets.delete(oldest);
      }
      this.buckets.set(key, { tokens: tokens - 1, checkedAt: now });
    }
    response.setHeader(
      'X-RateLimit-Remaining',
      Math.floor(Math.min(...candidates.map(({ tokens }) => tokens)) - 1),
    );
    next();
  }
}
