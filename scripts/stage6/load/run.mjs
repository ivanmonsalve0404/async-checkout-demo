#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { stage6Environment, stage6RunId } from '../lib/evidence.mjs';
import { writeSanitizedJsonAtomic } from '../lib/artifact-sanitizer.mjs';
import {
  ApiSession as FlowSession,
  expectStatus,
  getStock,
  prepareReady,
  withApi as withFlowApi,
} from '../uat/harness.mjs';

const ROOT = process.cwd();
const PORT = Number(process.env.STAGE6_LOAD_PORT ?? 3106);
const API_ORIGIN = `http://127.0.0.1:${PORT}`;
const WEB_ORIGIN = 'http://127.0.0.1:4173';
const PRODUCT_ID = 'product-demo-001';
const EVIDENCE_PATH = path.join(ROOT, 'output', 'evidence', 'runtime', 'stage-6', 'load.json');
const COMMAND = 'node scripts/stage6/load/run.mjs';
const NETWORK_GUARD = path.join(ROOT, 'scripts', 'smoke', 'deny-external-network.cjs');
const API_ENTRY = path.join(ROOT, 'apps', 'api', 'dist', 'main.js');
const RUN_ID = stage6RunId();

const profiles = [
  {
    id: 'LOAD-E6-01',
    name: 'catalog-read',
    method: 'GET',
    pathname: '/api/v1/products',
    iterations: 40,
    virtualUsers: 4,
    rampUpMs: 100,
    maxDurationMs: 5_000,
    p95BudgetMs: 500,
    expectedStatuses: [200],
  },
  {
    id: 'LOAD-E6-02',
    name: 'stock-read',
    method: 'GET',
    pathname: `/api/v1/stock/${PRODUCT_ID}`,
    iterations: 40,
    virtualUsers: 4,
    rampUpMs: 100,
    maxDurationMs: 5_000,
    p95BudgetMs: 500,
    expectedStatuses: [200],
  },
  {
    id: 'LOAD-E6-03',
    name: 'payment-configuration-read',
    method: 'GET',
    pathname: '/api/v1/payment-configuration',
    iterations: 20,
    virtualUsers: 2,
    rampUpMs: 50,
    maxDurationMs: 5_000,
    p95BudgetMs: 500,
    expectedStatuses: [200],
  },
  {
    id: 'LOAD-E6-04',
    name: 'checkout-and-quote-create',
    method: 'POST',
    pathname: '/api/v1/checkouts',
    iterations: 10,
    virtualUsers: 2,
    rampUpMs: 50,
    maxDurationMs: 5_000,
    p95BudgetMs: 800,
    expectedStatuses: [201],
  },
];

const scenarioProfiles = [
  {
    id: 'LOAD-E6-05',
    scenarioId: 'SCN-E6-LOAD-01',
    name: 'checkout-session-and-quote',
    measurementUnit: 'checkout-session-quote-operation',
    iterations: 4,
    virtualUsers: 2,
    rampUpMs: 50,
    maxDurationMs: 5_000,
    p95BudgetMs: 800,
  },
  {
    id: 'LOAD-E6-06',
    scenarioId: 'SCN-E6-LOAD-02',
    name: 'fake-submit-and-bounded-polling',
    measurementUnit: 'submit-polling-journey',
    iterations: 2,
    virtualUsers: 2,
    rampUpMs: 50,
    maxDurationMs: 5_000,
    p95BudgetMs: 800,
  },
  {
    id: 'LOAD-E6-07',
    scenarioId: 'SCN-E6-LOAD-03',
    name: 'idempotent-replay-and-duplicate-reconciliation',
    measurementUnit: 'idempotent-submit-request',
    iterations: 2,
    virtualUsers: 2,
    rampUpMs: 0,
    maxDurationMs: 5_000,
    p95BudgetMs: 800,
  },
  {
    id: 'LOAD-E6-08',
    scenarioId: 'SCN-E6-LOAD-04',
    name: 'last-unit-concurrency',
    measurementUnit: 'last-unit-submit-request',
    iterations: 2,
    virtualUsers: 2,
    rampUpMs: 0,
    maxDurationMs: 5_000,
    p95BudgetMs: 800,
  },
];
const PROFILE_CONFIGURATION_VERSION = '1.0.0';
const requiredProfileIds = [...profiles, ...scenarioProfiles].map(({ id }) => id);
const requiredScenarioIds = scenarioProfiles.map(({ scenarioId }) => scenarioId);
const datasetIds = [
  `DATASET-E6-BASE-${RUN_ID}`,
  ...scenarioProfiles.map(({ id }) => `DATASET-${id}-${RUN_ID}`),
];

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

const commitSha = () => {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : 'UNKNOWN';
};

const percentile = (values, quantile) => {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.max(0, Math.ceil(ordered.length * quantile) - 1)] ?? 0;
};

const requestOptions = (profile) =>
  profile.method === 'POST'
    ? {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: WEB_ORIGIN },
        body: JSON.stringify({ productId: PRODUCT_ID }),
      }
    : { method: 'GET', headers: { Accept: 'application/json' } };

const executeProfile = async (profile) => {
  const durations = [];
  const statuses = new Map();
  const failureCodes = [];
  let next = 0;
  const startedAt = performance.now();

  const worker = async (workerIndex) => {
    if (profile.virtualUsers > 1) {
      await sleep(Math.round((workerIndex * profile.rampUpMs) / (profile.virtualUsers - 1)));
    }
    while (next < profile.iterations) {
      const iteration = next;
      next += 1;
      const requestStartedAt = performance.now();
      try {
        const response = await fetch(`${API_ORIGIN}${profile.pathname}`, {
          ...requestOptions(profile),
          signal: AbortSignal.timeout(5_000),
        });
        durations.push(performance.now() - requestStartedAt);
        statuses.set(response.status, (statuses.get(response.status) ?? 0) + 1);
        await response.arrayBuffer();
        if (!profile.expectedStatuses.includes(response.status)) {
          failureCodes.push(
            response.status >= 500 ? 'UNEXPECTED_5XX' : `UNEXPECTED_STATUS_${response.status}`,
          );
        }
      } catch {
        durations.push(performance.now() - requestStartedAt);
        failureCodes.push(`REQUEST_FAILED_${iteration}`);
      }
    }
  };

  await Promise.all(Array.from({ length: profile.virtualUsers }, (_, index) => worker(index)));
  const elapsedMs = performance.now() - startedAt;
  const p50Ms = Math.round(percentile(durations, 0.5));
  const p95Ms = Math.round(percentile(durations, 0.95));
  const p99Ms = Math.round(percentile(durations, 0.99));
  if (p95Ms > profile.p95BudgetMs) failureCodes.push('P95_BUDGET_EXCEEDED');
  if (elapsedMs > profile.maxDurationMs) failureCodes.push('MAX_DURATION_EXCEEDED');
  const technicalErrorCount = failureCodes.filter((code) =>
    /^(?:REQUEST_FAILED|UNEXPECTED_(?:5XX|STATUS))/u.test(code),
  ).length;

  return {
    id: profile.id,
    name: profile.name,
    status: failureCodes.length === 0 ? 'PASS' : 'FAIL',
    virtualUsers: profile.virtualUsers,
    iterations: profile.iterations,
    rampUpMs: profile.rampUpMs,
    maxDurationMs: profile.maxDurationMs,
    elapsedMs: Math.round(elapsedMs),
    p95BudgetMs: profile.p95BudgetMs,
    requestSamples: durations.length,
    measurementUnit: 'http-request',
    p50Ms,
    p95Ms,
    p99Ms,
    throughputPerSecond: Number((profile.iterations / (elapsedMs / 1_000)).toFixed(2)),
    errorRate: Number((technicalErrorCount / profile.iterations).toFixed(4)),
    technicalErrorRate: Number((technicalErrorCount / profile.iterations).toFixed(4)),
    expectedRejectionRate: 0,
    expectedRejections: {},
    technicalErrorCount,
    unexpected5xx: [...statuses].reduce(
      (total, [status, count]) => (status >= 500 ? total + count : total),
      0,
    ),
    statuses: Object.fromEntries([...statuses].sort(([left], [right]) => left - right)),
    failureCodes: [...new Set(failureCodes)].sort(),
  };
};

const failureCode = (error) =>
  typeof error?.code === 'string'
    ? error.code
    : error instanceof Error
      ? error.message
      : 'UNEXPECTED_FAILURE';

const countStatuses = (statuses) =>
  Object.fromEntries(
    [...new Set(statuses)]
      .sort((left, right) => left - right)
      .map((status) => [status, statuses.filter((candidate) => candidate === status).length]),
  );

let scenarioBlockedExternalRequests = 0;

const runIterations = async (definition, durations, failureCodes, operation) => {
  let next = 0;
  const worker = async (workerIndex) => {
    if (definition.virtualUsers > 1) {
      await sleep(Math.round((workerIndex * definition.rampUpMs) / (definition.virtualUsers - 1)));
    }
    while (next < definition.iterations) {
      const iteration = next;
      next += 1;
      const startedAt = performance.now();
      try {
        await operation(iteration);
      } catch (error) {
        failureCodes.push(failureCode(error));
      } finally {
        durations.push(performance.now() - startedAt);
      }
    }
  };
  await Promise.all(Array.from({ length: definition.virtualUsers }, (_, index) => worker(index)));
};

const scenarioResult = (
  definition,
  startedAt,
  durations,
  httpStatuses,
  failureCodes,
  expectedRejections,
  invariants,
) => {
  const elapsedMs = performance.now() - startedAt;
  const p50Ms = Math.round(percentile(durations, 0.5));
  const p95Ms = Math.round(percentile(durations, 0.95));
  const p99Ms = Math.round(percentile(durations, 0.99));
  const unexpected5xx = httpStatuses.filter((status) => status >= 500).length;
  if (durations.length !== definition.iterations) failureCodes.push('ITERATION_COUNT_MISMATCH');
  if (p95Ms > definition.p95BudgetMs) failureCodes.push('P95_BUDGET_EXCEEDED');
  if (elapsedMs > definition.maxDurationMs) failureCodes.push('MAX_DURATION_EXCEEDED');
  if (unexpected5xx > 0) failureCodes.push('UNEXPECTED_5XX');
  const uniqueFailures = [...new Set(failureCodes)].sort();
  const technicalErrorCount = failureCodes.filter((code) =>
    /(?:_HTTP_|API_(?:EXITED|NOT_READY)|REQUEST|TIMEOUT|PORT_NOT_RELEASED|UNEXPECTED)/u.test(code),
  ).length;
  const expectedRejectionCount = Object.values(expectedRejections).reduce(
    (total, count) => total + count,
    0,
  );
  return {
    id: definition.id,
    scenarioId: definition.scenarioId,
    name: definition.name,
    status: uniqueFailures.length === 0 ? 'PASS' : 'FAIL',
    virtualUsers: definition.virtualUsers,
    iterations: definition.iterations,
    rampUpMs: definition.rampUpMs,
    maxDurationMs: definition.maxDurationMs,
    elapsedMs: Math.round(elapsedMs),
    p95BudgetMs: definition.p95BudgetMs,
    requestSamples: httpStatuses.length,
    measurementUnit: definition.measurementUnit,
    p50Ms,
    p95Ms,
    p99Ms,
    throughputPerSecond: Number((definition.iterations / (elapsedMs / 1_000)).toFixed(2)),
    errorRate: Number((technicalErrorCount / definition.iterations).toFixed(4)),
    technicalErrorRate: Number((technicalErrorCount / definition.iterations).toFixed(4)),
    expectedRejectionRate: Number(
      (expectedRejectionCount / Math.max(httpStatuses.length, 1)).toFixed(4),
    ),
    statuses: countStatuses(httpStatuses),
    expectedRejections,
    technicalErrorCount,
    unexpected5xx,
    failureCodes: uniqueFailures,
    invariants,
  };
};

const boundedPoll = async (session, transactionId, httpStatuses) => {
  for (let attempt = 1; attempt <= 40; attempt += 1) {
    const response = await session.request('GET', `/api/v1/transactions/${transactionId}`);
    httpStatuses.push(response.status);
    const transaction = expectStatus(response, 200, 'LOAD_POLL');
    if (transaction.paymentStatus !== 'PENDING') return { transaction, attempts: attempt };
    await sleep(25);
  }
  throw new Error('BOUNDED_POLLING_EXHAUSTED');
};

const waitForFlowPortFree = async () => {
  let consecutiveFreeChecks = 0;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      await fetch('http://127.0.0.1:3000/api/health', { signal: AbortSignal.timeout(100) });
      consecutiveFreeChecks = 0;
    } catch {
      consecutiveFreeChecks += 1;
      if (consecutiveFreeChecks === 8) return;
    }
    await sleep(25);
  }
  throw new Error('FLOW_API_PORT_NOT_RELEASED');
};

const submitReady = (session, ready, idempotencyKey) =>
  session.request('POST', `/api/v1/checkouts/${ready.checkoutId}/transactions`, {
    headers: { 'If-Match': ready.etag, 'Idempotency-Key': idempotencyKey },
    body: ready.body,
  });

const runSessionQuote = async (definition) => {
  const durations = [];
  const httpStatuses = [];
  const failureCodes = [];
  const invariants = { sessionsCreated: 0, sessionsQueried: 0, quotesMatched: 0 };
  const startedAt = performance.now();
  try {
    await waitForFlowPortFree();
    await withFlowApi({ PRODUCT_INITIAL_STOCK: '10' }, async ({ outputContains }) => {
      await runIterations(definition, durations, failureCodes, async () => {
        const session = new FlowSession();
        const createdResponse = await session.request('POST', '/api/v1/checkouts', {
          body: { productId: PRODUCT_ID },
        });
        httpStatuses.push(createdResponse.status);
        const created = expectStatus(createdResponse, 201, 'LOAD_SESSION_CREATE');
        invariants.sessionsCreated += 1;
        const queriedResponse = await session.request(
          'GET',
          `/api/v1/checkouts/${created.checkoutId}`,
        );
        httpStatuses.push(queriedResponse.status);
        const queried = expectStatus(queriedResponse, 200, 'LOAD_SESSION_QUERY');
        invariants.sessionsQueried += 1;
        if (
          queried.checkoutId !== created.checkoutId ||
          queried.quote?.quoteId !== created.quote?.quoteId ||
          queried.quote?.total?.amountInCents !== created.quote?.total?.amountInCents
        ) {
          throw new Error('SESSION_QUOTE_DRIFT');
        }
        invariants.quotesMatched += 1;
      });
      if (outputContains('SMOKE_EXTERNAL_NETWORK_BLOCKED')) scenarioBlockedExternalRequests += 1;
    });
  } catch (error) {
    failureCodes.push(failureCode(error));
  }
  if (Object.values(invariants).some((count) => count !== definition.iterations)) {
    failureCodes.push('SESSION_QUOTE_COUNT_MISMATCH');
  }
  return scenarioResult(
    definition,
    startedAt,
    durations,
    httpStatuses,
    failureCodes,
    {},
    invariants,
  );
};

const runSubmitPolling = async (definition) => {
  const durations = [];
  const httpStatuses = [];
  const failureCodes = [];
  const pollAttempts = [];
  const deliveryIds = [];
  let consumedReservations = 0;
  const invariants = {};
  const startedAt = performance.now();
  try {
    await waitForFlowPortFree();
    await withFlowApi(
      {
        FAKE_PAYMENT_SCENARIO: 'FAKE-E5-01',
        FAKE_RECONCILE_INTERVAL_MS: '10',
        PRODUCT_INITIAL_STOCK: String(definition.iterations),
      },
      async ({ countLog, outputContains }) => {
        await runIterations(definition, durations, failureCodes, async (iteration) => {
          const session = new FlowSession();
          const ready = await prepareReady(session);
          httpStatuses.push(201, 200, 200, 200);
          const acceptedResponse = await submitReady(
            session,
            ready,
            `idem.${RUN_ID}.submit.${iteration}`,
          );
          httpStatuses.push(acceptedResponse.status);
          const accepted = expectStatus(acceptedResponse, 202, 'LOAD_SUBMIT');
          const polled = await boundedPoll(session, accepted.transactionId, httpStatuses);
          pollAttempts.push(polled.attempts);
          if (
            polled.transaction.paymentStatus !== 'APPROVED' ||
            polled.transaction.reservationStatus !== 'CONSUMED' ||
            typeof polled.transaction.deliveryId !== 'string'
          ) {
            throw new Error('SUBMIT_FINAL_INVARIANT_FAILED');
          }
          deliveryIds.push(polled.transaction.deliveryId);
          consumedReservations += 1;
          const delivery = await session.request(
            'GET',
            `/api/v1/deliveries/${polled.transaction.deliveryId}`,
          );
          httpStatuses.push(delivery.status);
          expectStatus(delivery, 200, 'LOAD_DELIVERY');
        });
        const stock = await getStock(new FlowSession());
        httpStatuses.push(200);
        await sleep(25);
        Object.assign(invariants, {
          boundedPollingMaxAttempts: 40,
          maximumObservedPollAttempts: Math.max(0, ...pollAttempts),
          approved: deliveryIds.length,
          uniqueDeliveries: new Set(deliveryIds).size,
          consumedReservations,
          dispatchCount: countLog('payment.dispatch_claimed'),
          finalizationCount: countLog('payment.finalized'),
          reservationCommitCount: countLog('reservation.committed'),
          finalStock: stock,
        });
        if (outputContains('SMOKE_EXTERNAL_NETWORK_BLOCKED')) scenarioBlockedExternalRequests += 1;
      },
    );
  } catch (error) {
    failureCodes.push(failureCode(error));
  }
  if (
    invariants.approved !== definition.iterations ||
    invariants.uniqueDeliveries !== definition.iterations ||
    invariants.consumedReservations !== definition.iterations ||
    invariants.dispatchCount !== definition.iterations ||
    invariants.finalizationCount !== definition.iterations ||
    invariants.reservationCommitCount !== definition.iterations ||
    invariants.finalStock?.available !== 0
  ) {
    failureCodes.push('SUBMIT_POLLING_EFFECT_INVARIANT_FAILED');
  }
  return scenarioResult(
    definition,
    startedAt,
    durations,
    httpStatuses,
    failureCodes,
    {},
    invariants,
  );
};

const runReplayReconciliation = async (definition) => {
  const durations = [];
  const httpStatuses = [];
  const failureCodes = [];
  const invariants = {};
  const startedAt = performance.now();
  try {
    await waitForFlowPortFree();
    await withFlowApi(
      {
        FAKE_PAYMENT_SCENARIO: 'FAKE-E5-10',
        FAKE_RECONCILE_INTERVAL_MS: '10',
        PRODUCT_INITIAL_STOCK: '1',
      },
      async ({ countLog, outputContains }) => {
        const session = new FlowSession();
        const ready = await prepareReady(session);
        httpStatuses.push(201, 200, 200, 200);
        const idempotencyKey = `idem.${RUN_ID}.replay`;
        const measuredSubmit = async () => {
          const requestStartedAt = performance.now();
          try {
            const response = await submitReady(session, ready, idempotencyKey);
            httpStatuses.push(response.status);
            return expectStatus(response, 202, 'LOAD_REPLAY_SUBMIT');
          } finally {
            durations.push(performance.now() - requestStartedAt);
          }
        };
        const submissions = await Promise.all([measuredSubmit(), measuredSubmit()]);
        if (new Set(submissions.map(({ transactionId }) => transactionId)).size !== 1) {
          throw new Error('REPLAY_TRANSACTION_DUPLICATED');
        }
        const transactionId = submissions[0].transactionId;
        const polled = await boundedPoll(session, transactionId, httpStatuses);
        if (
          polled.transaction.paymentStatus !== 'APPROVED' ||
          polled.transaction.reservationStatus !== 'CONSUMED' ||
          typeof polled.transaction.deliveryId !== 'string'
        ) {
          throw new Error('REPLAY_FINAL_INVARIANT_FAILED');
        }
        const deliveryId = polled.transaction.deliveryId;
        const beforeStock = await getStock(session);
        httpStatuses.push(200);
        for (let index = 0; index < 10; index += 1) {
          await sleep(10);
          const response = await session.request('GET', `/api/v1/transactions/${transactionId}`);
          httpStatuses.push(response.status);
          const stable = expectStatus(response, 200, 'LOAD_REPLAY_STABILITY');
          if (stable.paymentStatus !== 'APPROVED' || stable.deliveryId !== deliveryId) {
            throw new Error('REPLAY_FINAL_STATE_DRIFT');
          }
        }
        const afterStock = await getStock(session);
        httpStatuses.push(200);
        const delivery = await session.request('GET', `/api/v1/deliveries/${deliveryId}`);
        httpStatuses.push(delivery.status);
        expectStatus(delivery, 200, 'LOAD_REPLAY_DELIVERY');
        await sleep(25);
        Object.assign(invariants, {
          providerScenario: 'FAKE-E5-10',
          acceptedReplays: submissions.length,
          uniqueTransactions: 1,
          stableReconciliationPolls: 10,
          reconciliationStabilityWindowMs: 100,
          dispatchCount: countLog('payment.dispatch_claimed'),
          idempotencyReplayCount: countLog('payment.idempotency_replayed'),
          finalizationCount: countLog('payment.finalized'),
          reservationCommitCount: countLog('reservation.committed'),
          uniqueDeliveries: 1,
          finalReservationStatus: polled.transaction.reservationStatus,
          stockStable: beforeStock.available === afterStock.available,
          finalStock: afterStock,
        });
        if (outputContains('SMOKE_EXTERNAL_NETWORK_BLOCKED')) scenarioBlockedExternalRequests += 1;
      },
    );
  } catch (error) {
    failureCodes.push(failureCode(error));
  }
  if (
    invariants.acceptedReplays !== definition.iterations ||
    invariants.uniqueTransactions !== 1 ||
    invariants.dispatchCount !== 1 ||
    invariants.idempotencyReplayCount !== 1 ||
    invariants.finalizationCount !== 1 ||
    invariants.reservationCommitCount !== 1 ||
    invariants.uniqueDeliveries !== 1 ||
    invariants.finalReservationStatus !== 'CONSUMED' ||
    invariants.stockStable !== true ||
    invariants.finalStock?.available !== 0
  ) {
    failureCodes.push('REPLAY_RECONCILIATION_EFFECT_INVARIANT_FAILED');
  }
  return scenarioResult(
    definition,
    startedAt,
    durations,
    httpStatuses,
    failureCodes,
    {},
    invariants,
  );
};

const runLastUnit = async (definition) => {
  const durations = [];
  const httpStatuses = [];
  const failureCodes = [];
  const expectedRejections = { 409: 0 };
  const invariants = {};
  const startedAt = performance.now();
  try {
    await waitForFlowPortFree();
    await withFlowApi(
      { FAKE_PAYMENT_SCENARIO: 'FAKE-E5-09', PRODUCT_INITIAL_STOCK: '1' },
      async ({ countLog, outputContains }) => {
        const contenders = await Promise.all(
          Array.from({ length: definition.virtualUsers }, async () => {
            const session = new FlowSession();
            const ready = await prepareReady(session);
            httpStatuses.push(201, 200, 200, 200);
            return { session, ready };
          }),
        );
        const responses = await Promise.all(
          contenders.map(async ({ session, ready }, index) => {
            const requestStartedAt = performance.now();
            try {
              const response = await submitReady(session, ready, `idem.${RUN_ID}.last.${index}`);
              httpStatuses.push(response.status);
              return response;
            } finally {
              durations.push(performance.now() - requestStartedAt);
            }
          }),
        );
        const winners = responses.filter(({ status }) => status === 202);
        const losers = responses.filter(({ status }) => status === 409);
        expectedRejections[409] = losers.length;
        if (winners.length !== 1 || losers.length !== 1) {
          throw new Error('LAST_UNIT_OUTCOME_COUNT');
        }
        if (losers[0].body?.code !== 'OUT_OF_STOCK') {
          throw new Error('LAST_UNIT_REJECTION_CODE');
        }
        const winnerIndex = responses.indexOf(winners[0]);
        const winner = expectStatus(winners[0], 202, 'LOAD_LAST_UNIT_WINNER');
        const winnerSession = contenders[winnerIndex].session;
        const polled = await boundedPoll(winnerSession, winner.transactionId, httpStatuses);
        if (
          polled.transaction.paymentStatus !== 'APPROVED' ||
          polled.transaction.reservationStatus !== 'CONSUMED' ||
          typeof polled.transaction.deliveryId !== 'string'
        ) {
          throw new Error('LAST_UNIT_FINAL_INVARIANT_FAILED');
        }
        const delivery = await winnerSession.request(
          'GET',
          `/api/v1/deliveries/${polled.transaction.deliveryId}`,
        );
        httpStatuses.push(delivery.status);
        expectStatus(delivery, 200, 'LOAD_LAST_UNIT_DELIVERY');
        const stock = await getStock(winnerSession);
        httpStatuses.push(200);
        await sleep(25);
        Object.assign(invariants, {
          winners: winners.length,
          expectedStockRejections: losers.length,
          uniqueTransactions: 1,
          uniqueDeliveries: 1,
          dispatchCount: countLog('payment.dispatch_claimed'),
          finalizationCount: countLog('payment.finalized'),
          inventoryConflictCount: countLog('inventory.conflict'),
          winnerReservationStatus: polled.transaction.reservationStatus,
          finalStock: stock,
        });
        if (outputContains('SMOKE_EXTERNAL_NETWORK_BLOCKED')) scenarioBlockedExternalRequests += 1;
      },
    );
  } catch (error) {
    failureCodes.push(failureCode(error));
  }
  if (
    invariants.winners !== 1 ||
    invariants.expectedStockRejections !== 1 ||
    invariants.uniqueTransactions !== 1 ||
    invariants.uniqueDeliveries !== 1 ||
    invariants.dispatchCount !== 1 ||
    invariants.finalizationCount !== 1 ||
    invariants.inventoryConflictCount !== 1 ||
    invariants.winnerReservationStatus !== 'CONSUMED' ||
    invariants.finalStock?.available !== 0
  ) {
    failureCodes.push('LAST_UNIT_EFFECT_INVARIANT_FAILED');
  }
  return scenarioResult(
    definition,
    startedAt,
    durations,
    httpStatuses,
    failureCodes,
    expectedRejections,
    invariants,
  );
};

const waitForApi = async (child) => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error('API_EXITED');
    try {
      const response = await fetch(`${API_ORIGIN}/api/health`, {
        signal: AbortSignal.timeout(500),
      });
      if (response.ok) return;
    } catch {
      // Bounded loopback-only startup polling.
    }
    await sleep(100);
  }
  throw new Error('API_NOT_READY');
};

const stop = async (child) => {
  if (child.exitCode !== null) return;
  child.kill();
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    sleep(3_000).then(() => child.kill('SIGKILL')),
  ]);
};

const baseEvidence = (sha) => ({
  schemaVersion: 1,
  stage: 6,
  generatedAt: new Date().toISOString(),
  commitSha: sha,
  runId: RUN_ID,
  command: COMMAND,
  tool: 'node',
  toolVersion: process.version,
  containsSensitiveData: false,
  environment: stage6Environment(),
  executionScope: 'LOCAL_MEMORY_FAKE_LOOPBACK_ONLY',
  networkPolicy: 'loopback-only-enforced',
  purpose: 'diagnostic-light-load-not-production-capacity-certification',
  sloSource: 'stage-3 API global/read/local-mutation p95 budgets',
});

const writeEvidence = async (evidence) => {
  await writeSanitizedJsonAtomic(EVIDENCE_PATH, 'load.json', evidence);
};

const main = async () => {
  if (!Number.isInteger(PORT) || PORT < 1_024 || PORT > 65_535) {
    throw new Error('INVALID_LOCAL_PORT');
  }
  const sha = commitSha();
  let blockedExternalRequests = 0;
  const child = spawn(process.execPath, [API_ENTRY], {
    cwd: ROOT,
    windowsHide: true,
    stdio: ['ignore', 'ignore', 'pipe'],
    env: {
      ...process.env,
      ALLOWED_ORIGIN: WEB_ORIGIN,
      API_PORT: String(PORT),
      APP_ENV: 'test',
      CHECKOUT_TTL_SECONDS: '1800',
      DATA_ADAPTER: 'memory',
      FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
      FAKE_RECONCILE_INTERVAL_MS: '60000',
      NODE_OPTIONS:
        `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(NETWORK_GUARD).href}`.trim(),
      PAYMENT_ADAPTER: 'fake',
      PAYMENTS_ENABLED: 'false',
      PRODUCT_INITIAL_STOCK: '20',
      PUBLIC_ASSET_ORIGIN: WEB_ORIGIN,
      QUOTE_TTL_SECONDS: '900',
      TOKENIZATION_MODE: 'disabled',
    },
  });
  child.stderr.on('data', (chunk) => {
    blockedExternalRequests += String(chunk).match(/SMOKE_EXTERNAL_NETWORK_BLOCKED/gu)?.length ?? 0;
  });

  try {
    await waitForApi(child);
    for (let index = 0; index < 5; index += 1) {
      await fetch(`${API_ORIGIN}/api/v1/products`, { signal: AbortSignal.timeout(1_000) });
    }
    const results = [];
    for (const profile of profiles) results.push(await executeProfile(profile));

    const limited = await fetch(`${API_ORIGIN}/api/v1/checkouts`, {
      ...requestOptions(profiles.at(-1)),
      signal: AbortSignal.timeout(5_000),
    });
    const retryAfter = limited.headers.get('retry-after');
    const limitedBody = await limited.json().catch(() => null);
    const rateLimit = {
      id: 'RATE-E6-01',
      status:
        limited.status === 429 &&
        limitedBody?.code === 'RATE_LIMITED' &&
        /^\d+$/u.test(retryAfter ?? '')
          ? 'PASS'
          : 'FAIL',
      observedStatus: limited.status,
      contractCode: limitedBody?.code,
      retryAfterPresent: /^\d+$/u.test(retryAfter ?? ''),
      expectedRejection: true,
      excludedFromTechnicalErrorRate: true,
    };

    await stop(child);
    results.push(await runSessionQuote(scenarioProfiles[0]));
    results.push(await runSubmitPolling(scenarioProfiles[1]));
    results.push(await runReplayReconciliation(scenarioProfiles[2]));
    results.push(await runLastUnit(scenarioProfiles[3]));

    const observedProfileIds = results.map(({ id }) => id);
    const observedScenarioIds = results
      .filter(({ scenarioId }) => scenarioId !== undefined)
      .map(({ scenarioId }) => scenarioId);
    const inventoryComplete =
      observedProfileIds.length === requiredProfileIds.length &&
      requiredProfileIds.every((id) => observedProfileIds.includes(id)) &&
      observedScenarioIds.length === requiredScenarioIds.length &&
      requiredScenarioIds.every((id) => observedScenarioIds.includes(id));
    const unexpected5xx = results.reduce((total, result) => total + result.unexpected5xx, 0);
    const technicalErrorCount = results.reduce(
      (total, result) => total + result.technicalErrorCount,
      0,
    );
    const allStatuses = results.flatMap((result) =>
      Object.entries(result.statuses).flatMap(([status, count]) =>
        Array.from({ length: count }, () => Number(status)),
      ),
    );
    allStatuses.push(limited.status);
    const expected409 = results.reduce(
      (total, result) => total + Number(result.expectedRejections?.[409] ?? 0),
      0,
    );
    const totalBlockedExternalRequests = blockedExternalRequests + scenarioBlockedExternalRequests;
    const requestSamples = results.reduce((total, result) => total + result.requestSamples, 1);
    const status =
      inventoryComplete &&
      results.every((result) => result.status === 'PASS') &&
      rateLimit.status === 'PASS' &&
      technicalErrorCount === 0 &&
      unexpected5xx === 0 &&
      totalBlockedExternalRequests === 0
        ? 'PASS'
        : 'FAIL';
    const evidence = {
      ...baseEvidence(sha),
      status,
      profileConfigurationVersion: PROFILE_CONFIGURATION_VERSION,
      profileInventory: {
        requiredIds: requiredProfileIds,
        observedIds: observedProfileIds,
        complete: inventoryComplete,
      },
      scenarioInventory: {
        requiredIds: requiredScenarioIds,
        observedIds: observedScenarioIds,
        complete: inventoryComplete,
      },
      dataIsolation: {
        strategy: 'fresh-in-memory-process-per-scenario',
        namespace: RUN_ID,
        datasetIds,
      },
      profiles: results,
      rateLimit,
      httpSummary: {
        requestSamples,
        statuses: countStatuses(allStatuses),
        technicalErrorCount,
        technicalErrorRate: Number((technicalErrorCount / requestSamples).toFixed(4)),
        expectedRejections: { 409: expected409, 429: rateLimit.status === 'PASS' ? 1 : 0 },
        expectedRejectionRate: Number(
          ((expected409 + (rateLimit.status === 'PASS' ? 1 : 0)) / requestSamples).toFixed(4),
        ),
        unexpected5xx,
      },
      unexpected5xx,
      blockedExternalRequests: totalBlockedExternalRequests,
    };
    await writeEvidence(evidence);
    process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
    if (status !== 'PASS') process.exitCode = 1;
  } finally {
    await stop(child);
  }
};

try {
  await main();
} catch (error) {
  const sha = commitSha();
  const evidence = {
    ...baseEvidence(sha),
    status: 'FAIL',
    profileConfigurationVersion: PROFILE_CONFIGURATION_VERSION,
    profileInventory: { requiredIds: requiredProfileIds, observedIds: [], complete: false },
    scenarioInventory: { requiredIds: requiredScenarioIds, observedIds: [], complete: false },
    failureCodes: [error instanceof Error ? error.message : 'UNEXPECTED_FAILURE'],
  };
  await writeEvidence(evidence);
  process.stderr.write(`${JSON.stringify(evidence, null, 2)}\n`);
  process.exitCode = 1;
}
