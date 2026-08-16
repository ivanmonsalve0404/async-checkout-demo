import type {
  DomainEventName,
  MetricName,
  ObservabilityFields,
  ObservabilityPort,
} from '../../application/ports/observability';
import { allowlistLogFields, type SafeLogger } from '../logging/safe-logger';

const observabilityFieldNames = new Set([
  'fromState',
  'toState',
  'dispatchPhase',
  'providerStatus',
  'errorCode',
  'retryCount',
]);

const allowlistObservabilityFields = (fields: ObservabilityFields): ObservabilityFields =>
  Object.fromEntries(
    Object.entries(allowlistLogFields(fields)).filter(([key]) => observabilityFieldNames.has(key)),
  );
export class SafeLoggerObservability implements ObservabilityPort {
  public constructor(private readonly logger: SafeLogger) {}

  public event(name: DomainEventName, fields: ObservabilityFields = {}): void {
    this.logger.info(name, allowlistObservabilityFields(fields));
  }

  public increment(name: MetricName, value = 1): void {
    if (!Number.isFinite(value) || value < 0) return;
    this.logger.info('metric.recorded', { metricName: name, metricValue: value });
  }

  public observe(name: MetricName, value: number): void {
    if (!Number.isFinite(value) || value < 0) return;
    this.logger.info('metric.recorded', { metricName: name, metricValue: value });
  }
}

export class FakeObservability implements ObservabilityPort {
  public readonly events: Array<Readonly<{ name: DomainEventName; fields: ObservabilityFields }>> =
    [];
  public readonly metrics: Array<Readonly<{ name: MetricName; value: number }>> = [];

  public event(name: DomainEventName, fields: ObservabilityFields = {}): void {
    this.events.push({ name, fields: allowlistObservabilityFields(fields) });
  }

  public increment(name: MetricName, value = 1): void {
    if (!Number.isFinite(value) || value < 0) return;
    this.metrics.push({ name, value });
  }

  public observe(name: MetricName, value: number): void {
    if (!Number.isFinite(value) || value < 0) return;
    this.metrics.push({ name, value });
  }

  public count(name: MetricName): number {
    return this.metrics
      .filter((metric) => metric.name === name)
      .reduce((total, metric) => total + metric.value, 0);
  }

  public values(name: MetricName): readonly number[] {
    return this.metrics.filter((metric) => metric.name === name).map(({ value }) => value);
  }
}
