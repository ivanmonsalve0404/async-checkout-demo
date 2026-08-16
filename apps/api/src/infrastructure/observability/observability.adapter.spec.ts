import type { ObservabilityFields } from '../../application/ports/observability';
import { SafeLogger } from '../logging/safe-logger';
import { FakeObservability, SafeLoggerObservability } from './observability.adapter';

describe('observability adapters', () => {
  const unsafeFields = {
    fromState: 'PENDING',
    toState: 'PENDING',
    errorCode: 'PROVIDER_UNAVAILABLE',
    retryCount: 2,
    requestId: 'request-not-owned-by-domain-event',
    correlationId: 'correlation-not-owned-by-domain-event',
    email: 'private@example.invalid',
    paymentMethodToken: 'tok_private',
    cardNumber: 'synthetic-card-alias',
  } as unknown as ObservabilityFields;

  it('keeps only domain-event fields and ignores invalid metric increments in the fake', () => {
    const observability = new FakeObservability();
    observability.event('payment.outcome_unknown', unsafeFields);
    observability.increment('payment_unknown_total', 2);
    observability.increment('payment_unknown_total', Number.NaN);
    observability.increment('payment_unknown_total', -1);
    observability.observe('payment_start_latency_ms', 17);
    observability.observe('payment_start_latency_ms', Number.NaN);
    observability.observe('payment_start_latency_ms', -1);

    expect(observability.events).toEqual([
      {
        name: 'payment.outcome_unknown',
        fields: {
          fromState: 'PENDING',
          toState: 'PENDING',
          errorCode: 'PROVIDER_UNAVAILABLE',
          retryCount: 2,
        },
      },
    ]);
    expect(observability.metrics).toEqual([
      { name: 'payment_unknown_total', value: 2 },
      { name: 'payment_start_latency_ms', value: 17 },
    ]);
    expect(observability.count('payment_unknown_total')).toBe(2);
    expect(JSON.stringify(observability)).not.toContain('private');
    expect(observability.values('payment_start_latency_ms')).toEqual([17]);
    expect(JSON.stringify(observability)).not.toContain('synthetic-card-alias');
  });

  it('writes allowlisted domain events and aggregate metrics without payload fields', () => {
    const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const observability = new SafeLoggerObservability(new SafeLogger('api', 'test', '1'));

    observability.event('payment.outcome_unknown', unsafeFields);
    observability.increment('payment_unknown_total', 3);
    observability.observe('provider_query_latency_ms', 19);

    expect(write).toHaveBeenCalledTimes(3);
    const event = JSON.parse(String(write.mock.calls[0]?.[0])) as Record<string, unknown>;
    const metric = JSON.parse(String(write.mock.calls[1]?.[0])) as Record<string, unknown>;
    const observation = JSON.parse(String(write.mock.calls[2]?.[0])) as Record<string, unknown>;
    expect(event).toMatchObject({
      eventName: 'payment.outcome_unknown',
      fromState: 'PENDING',
      toState: 'PENDING',
      errorCode: 'PROVIDER_UNAVAILABLE',
      retryCount: 2,
    });
    expect(event).not.toHaveProperty('requestId');
    expect(event).not.toHaveProperty('correlationId');
    expect(event).not.toHaveProperty('email');
    expect(event).not.toHaveProperty('paymentMethodToken');
    expect(event).not.toHaveProperty('cardNumber');
    expect(metric).toMatchObject({
      eventName: 'metric.recorded',
      metricName: 'payment_unknown_total',
      metricValue: 3,
    });
    expect(observation).toMatchObject({
      eventName: 'metric.recorded',
      metricName: 'provider_query_latency_ms',
      metricValue: 19,
    });
    write.mockRestore();
  });
});
