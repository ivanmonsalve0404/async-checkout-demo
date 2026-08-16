export const domainEventNames = [
  'checkout.created',
  'checkout.quoted',
  'checkout.quote_expired',
  'payment.reserved',
  'payment.dispatch_claimed',
  'payment.idempotency_replayed',
  'payment.idempotency_conflict',
  'payment.outcome_unknown',
  'payment.finalized',
  'provider.external_error',
  'reservation.committed',
  'reservation.released',
  'inventory.conflict',
  'reconcile.claimed',
  'reconcile.retry_scheduled',
  'reconcile.exhausted',
  'reconcile.deduplicated',
  'sandbox_guard.blocked',
] as const;

export const metricNames = [
  'checkout_sessions_total',
  'checkout_quotes_total',
  'checkout_quotes_expired_total',
  'payment_attempts_total',
  'payment_finalized_total',
  'payment_finalized_approved_total',
  'payment_finalized_declined_total',
  'payment_finalized_voided_total',
  'payment_finalized_error_total',
  'payment_tokenization_latency_ms',
  'payment_start_latency_ms',
  'provider_query_latency_ms',
  'reconciliation_retries_total',
  'provider_timeouts_total',
  'payment_unknown_total',
  'idempotency_replays_total',
  'idempotency_conflicts_total',
  'reservations_total',
  'reservations_created_total',
  'reservations_committed_total',
  'reservations_released_total',
  'reservations_expired_total',
  'inventory_conflicts_total',
  'deduplicated_operations_total',
  'duplicate_finalizations_avoided_total',
  'provider_external_errors_total',
  'provider_rate_limited_total',
  'provider_unavailable_total',
  'provider_unknown_outcomes_total',
  'provider_protocol_errors_total',
  'sandbox_guard_blocked_total',
] as const;

export type DomainEventName = (typeof domainEventNames)[number];
export type MetricName = (typeof metricNames)[number];

export type ObservabilityFields = Readonly<{
  fromState?: string;
  toState?: string;
  dispatchPhase?: string;
  providerStatus?: string | null;
  errorCode?: string;
  retryCount?: number;
}>;

export interface ObservabilityPort {
  event(name: DomainEventName, fields?: ObservabilityFields): void;
  increment(name: MetricName, value?: number): void;
  observe(name: MetricName, value: number): void;
}

export const NOOP_OBSERVABILITY: ObservabilityPort = {
  event: () => undefined,
  increment: () => undefined,
  observe: () => undefined,
};

export const OBSERVABILITY = Symbol('OBSERVABILITY');
