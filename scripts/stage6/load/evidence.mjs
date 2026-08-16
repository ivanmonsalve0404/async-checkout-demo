/* global structuredClone */
import assert from 'node:assert/strict';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const RUN_ID = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const COMMIT_SHA = /^[0-9a-f]{40}$/u;
const PROFILE_CONFIGURATION_VERSION = '1.0.0';
const expectedEnvironment = () => (process.env.CI === 'true' ? 'ENV-E6-CI' : 'ENV-E6-LOCAL');

const PROFILES = [
  ['LOAD-E6-01', undefined, 'catalog-read', 4, 40, 100, 500, 'http-request'],
  ['LOAD-E6-02', undefined, 'stock-read', 4, 40, 100, 500, 'http-request'],
  ['LOAD-E6-03', undefined, 'payment-configuration-read', 2, 20, 50, 500, 'http-request'],
  ['LOAD-E6-04', undefined, 'checkout-and-quote-create', 2, 10, 50, 800, 'http-request'],
  [
    'LOAD-E6-05',
    'SCN-E6-LOAD-01',
    'checkout-session-and-quote',
    2,
    4,
    50,
    800,
    'checkout-session-quote-operation',
  ],
  [
    'LOAD-E6-06',
    'SCN-E6-LOAD-02',
    'fake-submit-and-bounded-polling',
    2,
    2,
    50,
    800,
    'submit-polling-journey',
  ],
  [
    'LOAD-E6-07',
    'SCN-E6-LOAD-03',
    'idempotent-replay-and-duplicate-reconciliation',
    2,
    2,
    0,
    800,
    'idempotent-submit-request',
  ],
  [
    'LOAD-E6-08',
    'SCN-E6-LOAD-04',
    'last-unit-concurrency',
    2,
    2,
    0,
    800,
    'last-unit-submit-request',
  ],
].map(
  ([id, scenarioId, name, virtualUsers, iterations, rampUpMs, p95BudgetMs, measurementUnit]) => ({
    id,
    scenarioId,
    name,
    virtualUsers,
    iterations,
    rampUpMs,
    maxDurationMs: 5_000,
    p95BudgetMs,
    measurementUnit,
  }),
);

const PROFILE_IDS = PROFILES.map(({ id }) => id);
const SCENARIO_IDS = PROFILES.flatMap(({ scenarioId }) =>
  scenarioId === undefined ? [] : [scenarioId],
);
const exact = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected);
const roundedRate = (numerator, denominator) =>
  Number((numerator / Math.max(denominator, 1)).toFixed(4));
const validIsoDate = (value) => typeof value === 'string' && !Number.isNaN(Date.parse(value));

const exactStatusCounts = (actual, expected) =>
  exact(Object.keys(actual ?? {}), Object.keys(expected)) &&
  Object.entries(expected).every(([status, count]) => actual[status] === count);

const validStock = (stock) =>
  stock?.productId === 'product-demo-001' && stock.available === 0 && validIsoDate(stock.asOf);

const validInvariants = (profile) => {
  const invariants = profile.invariants;
  switch (profile.id) {
    case 'LOAD-E6-05':
      return exact(invariants, { sessionsCreated: 4, sessionsQueried: 4, quotesMatched: 4 });
    case 'LOAD-E6-06':
      return (
        exact(Object.keys(invariants ?? {}), [
          'boundedPollingMaxAttempts',
          'maximumObservedPollAttempts',
          'approved',
          'uniqueDeliveries',
          'consumedReservations',
          'dispatchCount',
          'finalizationCount',
          'reservationCommitCount',
          'finalStock',
        ]) &&
        invariants.boundedPollingMaxAttempts === 40 &&
        Number.isInteger(invariants.maximumObservedPollAttempts) &&
        invariants.maximumObservedPollAttempts >= 1 &&
        invariants.maximumObservedPollAttempts <= 40 &&
        invariants.approved === 2 &&
        invariants.uniqueDeliveries === 2 &&
        invariants.consumedReservations === 2 &&
        invariants.dispatchCount === 2 &&
        invariants.finalizationCount === 2 &&
        invariants.reservationCommitCount === 2 &&
        validStock(invariants.finalStock)
      );
    case 'LOAD-E6-07':
      return (
        exact(Object.keys(invariants ?? {}), [
          'providerScenario',
          'acceptedReplays',
          'uniqueTransactions',
          'stableReconciliationPolls',
          'reconciliationStabilityWindowMs',
          'dispatchCount',
          'idempotencyReplayCount',
          'finalizationCount',
          'reservationCommitCount',
          'uniqueDeliveries',
          'finalReservationStatus',
          'stockStable',
          'finalStock',
        ]) &&
        invariants.providerScenario === 'FAKE-E5-10' &&
        invariants.acceptedReplays === 2 &&
        invariants.uniqueTransactions === 1 &&
        invariants.stableReconciliationPolls === 10 &&
        invariants.reconciliationStabilityWindowMs === 100 &&
        invariants.dispatchCount === 1 &&
        invariants.idempotencyReplayCount === 1 &&
        invariants.finalizationCount === 1 &&
        invariants.reservationCommitCount === 1 &&
        invariants.uniqueDeliveries === 1 &&
        invariants.finalReservationStatus === 'CONSUMED' &&
        invariants.stockStable === true &&
        validStock(invariants.finalStock)
      );
    case 'LOAD-E6-08':
      return (
        exact(Object.keys(invariants ?? {}), [
          'winners',
          'expectedStockRejections',
          'uniqueTransactions',
          'uniqueDeliveries',
          'dispatchCount',
          'finalizationCount',
          'inventoryConflictCount',
          'winnerReservationStatus',
          'finalStock',
        ]) &&
        invariants.winners === 1 &&
        invariants.expectedStockRejections === 1 &&
        invariants.uniqueTransactions === 1 &&
        invariants.uniqueDeliveries === 1 &&
        invariants.dispatchCount === 1 &&
        invariants.finalizationCount === 1 &&
        invariants.inventoryConflictCount === 1 &&
        invariants.winnerReservationStatus === 'CONSUMED' &&
        validStock(invariants.finalStock)
      );
    default:
      return invariants === undefined;
  }
};

const validProfileStatuses = (profile) => {
  switch (profile.id) {
    case 'LOAD-E6-01':
    case 'LOAD-E6-02':
      return exactStatusCounts(profile.statuses, { 200: 40 });
    case 'LOAD-E6-03':
      return exactStatusCounts(profile.statuses, { 200: 20 });
    case 'LOAD-E6-04':
      return exactStatusCounts(profile.statuses, { 201: 10 });
    case 'LOAD-E6-05':
      return exactStatusCounts(profile.statuses, { 200: 4, 201: 4 });
    case 'LOAD-E6-06':
      return (
        exact(Object.keys(profile.statuses ?? {}), ['200', '201', '202']) &&
        profile.statuses[200] >= 11 &&
        profile.statuses[201] === 2 &&
        profile.statuses[202] === 2
      );
    case 'LOAD-E6-07':
      return (
        exact(Object.keys(profile.statuses ?? {}), ['200', '201', '202']) &&
        profile.statuses[200] >= 17 &&
        profile.statuses[201] === 1 &&
        profile.statuses[202] === 2
      );
    case 'LOAD-E6-08':
      return (
        exact(Object.keys(profile.statuses ?? {}), ['200', '201', '202', '409']) &&
        profile.statuses[200] >= 9 &&
        profile.statuses[201] === 2 &&
        profile.statuses[202] === 1 &&
        profile.statuses[409] === 1
      );
    default:
      return false;
  }
};

const validProfile = (profile, expected) => {
  const statusTotal = Object.values(profile?.statuses ?? {}).reduce(
    (total, count) => total + count,
    0,
  );
  const expectedRejections = expected.id === 'LOAD-E6-08' ? { 409: 1 } : {};
  const expectedRejectionCount = Object.values(expectedRejections).reduce(
    (total, count) => total + count,
    0,
  );
  return (
    profile?.id === expected.id &&
    profile.scenarioId === expected.scenarioId &&
    profile.name === expected.name &&
    profile.status === 'PASS' &&
    profile.virtualUsers === expected.virtualUsers &&
    profile.iterations === expected.iterations &&
    profile.rampUpMs === expected.rampUpMs &&
    profile.maxDurationMs === expected.maxDurationMs &&
    profile.p95BudgetMs === expected.p95BudgetMs &&
    profile.measurementUnit === expected.measurementUnit &&
    Number.isInteger(profile.elapsedMs) &&
    profile.elapsedMs >= 0 &&
    profile.elapsedMs <= expected.maxDurationMs &&
    [profile.p50Ms, profile.p95Ms, profile.p99Ms].every(
      (value) => Number.isInteger(value) && value >= 0,
    ) &&
    profile.p50Ms <= profile.p95Ms &&
    profile.p95Ms <= profile.p99Ms &&
    profile.p95Ms <= expected.p95BudgetMs &&
    Number.isFinite(profile.throughputPerSecond) &&
    profile.throughputPerSecond > 0 &&
    Number.isInteger(profile.requestSamples) &&
    profile.requestSamples > 0 &&
    statusTotal === profile.requestSamples &&
    validProfileStatuses(profile) &&
    profile.errorRate === 0 &&
    profile.technicalErrorRate === 0 &&
    profile.technicalErrorCount === 0 &&
    profile.unexpected5xx === 0 &&
    exact(profile.failureCodes, []) &&
    exact(profile.expectedRejections, expectedRejections) &&
    profile.expectedRejectionRate === roundedRate(expectedRejectionCount, profile.requestSamples) &&
    validInvariants(profile)
  );
};

const aggregateStatuses = (profiles) => {
  const counts = new Map([[429, 1]]);
  for (const profile of profiles) {
    for (const [status, count] of Object.entries(profile.statuses)) {
      const numericStatus = Number(status);
      counts.set(numericStatus, (counts.get(numericStatus) ?? 0) + count);
    }
  }
  return Object.fromEntries([...counts].sort(([left], [right]) => left - right));
};

export const validateLoadEvidence = (evidence) => {
  try {
    if (
      evidence?.schemaVersion !== 1 ||
      evidence.stage !== 6 ||
      evidence.status !== 'PASS' ||
      evidence.command !== 'node scripts/stage6/load/run.mjs' ||
      evidence.tool !== 'node' ||
      !/^v24\.[0-9]+\.[0-9]+$/u.test(evidence.toolVersion ?? '') ||
      evidence.containsSensitiveData !== false ||
      evidence.environment !== expectedEnvironment() ||
      evidence.executionScope !== 'LOCAL_MEMORY_FAKE_LOOPBACK_ONLY' ||
      evidence.networkPolicy !== 'loopback-only-enforced' ||
      evidence.purpose !== 'diagnostic-light-load-not-production-capacity-certification' ||
      evidence.sloSource !== 'stage-3 API global/read/local-mutation p95 budgets' ||
      evidence.profileConfigurationVersion !== PROFILE_CONFIGURATION_VERSION ||
      !RUN_ID.test(evidence.runId) ||
      !COMMIT_SHA.test(evidence.commitSha) ||
      !validIsoDate(evidence.generatedAt) ||
      !exact(evidence.profileInventory, {
        requiredIds: PROFILE_IDS,
        observedIds: PROFILE_IDS,
        complete: true,
      }) ||
      !exact(evidence.scenarioInventory, {
        requiredIds: SCENARIO_IDS,
        observedIds: SCENARIO_IDS,
        complete: true,
      }) ||
      evidence.dataIsolation?.strategy !== 'fresh-in-memory-process-per-scenario' ||
      evidence.dataIsolation.namespace !== evidence.runId ||
      !exact(evidence.dataIsolation.datasetIds, [
        `DATASET-E6-BASE-${evidence.runId}`,
        ...PROFILE_IDS.slice(4).map((id) => `DATASET-${id}-${evidence.runId}`),
      ]) ||
      !Array.isArray(evidence.profiles) ||
      evidence.profiles.length !== PROFILES.length ||
      !evidence.profiles.every((profile, index) => validProfile(profile, PROFILES[index])) ||
      !exact(evidence.rateLimit, {
        id: 'RATE-E6-01',
        status: 'PASS',
        observedStatus: 429,
        contractCode: 'RATE_LIMITED',
        retryAfterPresent: true,
        expectedRejection: true,
        excludedFromTechnicalErrorRate: true,
      }) ||
      evidence.unexpected5xx !== 0 ||
      evidence.blockedExternalRequests !== 0
    ) {
      return false;
    }

    const requestSamples =
      evidence.profiles.reduce((total, profile) => total + profile.requestSamples, 0) + 1;
    const expected409 = evidence.profiles.reduce(
      (total, profile) => total + Number(profile.expectedRejections?.[409] ?? 0),
      0,
    );
    return (
      evidence.httpSummary?.requestSamples === requestSamples &&
      exact(evidence.httpSummary.statuses, aggregateStatuses(evidence.profiles)) &&
      evidence.httpSummary.technicalErrorCount === 0 &&
      evidence.httpSummary.technicalErrorRate === 0 &&
      exact(evidence.httpSummary.expectedRejections, { 409: expected409, 429: 1 }) &&
      expected409 === 1 &&
      evidence.httpSummary.expectedRejectionRate === roundedRate(expected409 + 1, requestSamples) &&
      evidence.httpSummary.unexpected5xx === 0
    );
  } catch {
    return false;
  }
};

const invariantsFixture = (id) => {
  const finalStock = {
    productId: 'product-demo-001',
    available: 0,
    asOf: '2026-08-16T12:00:00.000Z',
  };
  if (id === 'LOAD-E6-05') {
    return { sessionsCreated: 4, sessionsQueried: 4, quotesMatched: 4 };
  }
  if (id === 'LOAD-E6-06') {
    return {
      boundedPollingMaxAttempts: 40,
      maximumObservedPollAttempts: 1,
      approved: 2,
      uniqueDeliveries: 2,
      consumedReservations: 2,
      dispatchCount: 2,
      finalizationCount: 2,
      reservationCommitCount: 2,
      finalStock,
    };
  }
  if (id === 'LOAD-E6-07') {
    return {
      providerScenario: 'FAKE-E5-10',
      acceptedReplays: 2,
      uniqueTransactions: 1,
      stableReconciliationPolls: 10,
      reconciliationStabilityWindowMs: 100,
      dispatchCount: 1,
      idempotencyReplayCount: 1,
      finalizationCount: 1,
      reservationCommitCount: 1,
      uniqueDeliveries: 1,
      finalReservationStatus: 'CONSUMED',
      stockStable: true,
      finalStock,
    };
  }
  if (id === 'LOAD-E6-08') {
    return {
      winners: 1,
      expectedStockRejections: 1,
      uniqueTransactions: 1,
      uniqueDeliveries: 1,
      dispatchCount: 1,
      finalizationCount: 1,
      inventoryConflictCount: 1,
      winnerReservationStatus: 'CONSUMED',
      finalStock,
    };
  }
  return undefined;
};

const statusesFixture = (id) =>
  ({
    'LOAD-E6-01': { 200: 40 },
    'LOAD-E6-02': { 200: 40 },
    'LOAD-E6-03': { 200: 20 },
    'LOAD-E6-04': { 201: 10 },
    'LOAD-E6-05': { 200: 4, 201: 4 },
    'LOAD-E6-06': { 200: 11, 201: 2, 202: 2 },
    'LOAD-E6-07': { 200: 17, 201: 1, 202: 2 },
    'LOAD-E6-08': { 200: 9, 201: 2, 202: 1, 409: 1 },
  })[id];

const validFixture = () => {
  const runId = 'e6-20260816t120000z-0123abcd';
  const profiles = PROFILES.map((expected) => {
    const statuses = statusesFixture(expected.id);
    const requestSamples = Object.values(statuses).reduce((total, count) => total + count, 0);
    const expectedRejections = expected.id === 'LOAD-E6-08' ? { 409: 1 } : {};
    return {
      id: expected.id,
      ...(expected.scenarioId === undefined ? {} : { scenarioId: expected.scenarioId }),
      name: expected.name,
      status: 'PASS',
      virtualUsers: expected.virtualUsers,
      iterations: expected.iterations,
      rampUpMs: expected.rampUpMs,
      maxDurationMs: expected.maxDurationMs,
      elapsedMs: 1,
      p95BudgetMs: expected.p95BudgetMs,
      requestSamples,
      measurementUnit: expected.measurementUnit,
      p50Ms: 1,
      p95Ms: 1,
      p99Ms: 1,
      throughputPerSecond: 1,
      errorRate: 0,
      technicalErrorRate: 0,
      expectedRejectionRate: roundedRate(
        Object.values(expectedRejections).reduce((total, count) => total + count, 0),
        requestSamples,
      ),
      statuses,
      expectedRejections,
      technicalErrorCount: 0,
      unexpected5xx: 0,
      failureCodes: [],
      ...(expected.scenarioId === undefined ? {} : { invariants: invariantsFixture(expected.id) }),
    };
  });
  const requestSamples = profiles.reduce((total, profile) => total + profile.requestSamples, 0) + 1;
  return {
    schemaVersion: 1,
    stage: 6,
    generatedAt: '2026-08-16T12:00:00.000Z',
    commitSha: 'a'.repeat(40),
    runId,
    command: 'node scripts/stage6/load/run.mjs',
    tool: 'node',
    toolVersion: 'v24.19.0',
    containsSensitiveData: false,
    environment: expectedEnvironment(),
    executionScope: 'LOCAL_MEMORY_FAKE_LOOPBACK_ONLY',
    networkPolicy: 'loopback-only-enforced',
    purpose: 'diagnostic-light-load-not-production-capacity-certification',
    sloSource: 'stage-3 API global/read/local-mutation p95 budgets',
    status: 'PASS',
    profileConfigurationVersion: '1.0.0',
    profileInventory: { requiredIds: PROFILE_IDS, observedIds: PROFILE_IDS, complete: true },
    scenarioInventory: { requiredIds: SCENARIO_IDS, observedIds: SCENARIO_IDS, complete: true },
    dataIsolation: {
      strategy: 'fresh-in-memory-process-per-scenario',
      namespace: runId,
      datasetIds: [
        `DATASET-E6-BASE-${runId}`,
        ...PROFILE_IDS.slice(4).map((id) => `DATASET-${id}-${runId}`),
      ],
    },
    profiles,
    rateLimit: {
      id: 'RATE-E6-01',
      status: 'PASS',
      observedStatus: 429,
      contractCode: 'RATE_LIMITED',
      retryAfterPresent: true,
      expectedRejection: true,
      excludedFromTechnicalErrorRate: true,
    },
    httpSummary: {
      requestSamples,
      statuses: aggregateStatuses(profiles),
      technicalErrorCount: 0,
      technicalErrorRate: 0,
      expectedRejections: { 409: 1, 429: 1 },
      expectedRejectionRate: roundedRate(2, requestSamples),
      unexpected5xx: 0,
    },
    unexpected5xx: 0,
    blockedExternalRequests: 0,
  };
};

export const selfTestLoadEvidence = () => {
  const valid = validFixture();
  assert.equal(validateLoadEvidence(valid), true);

  const alteredScenario = structuredClone(valid);
  alteredScenario.profiles[4].scenarioId = 'SCN-E6-LOAD-99';
  assert.equal(validateLoadEvidence(alteredScenario), false);

  const alteredRateLimit = structuredClone(valid);
  alteredRateLimit.rateLimit.observedStatus = 200;
  assert.equal(validateLoadEvidence(alteredRateLimit), false);

  const alteredInvariant = structuredClone(valid);
  alteredInvariant.profiles[7].invariants.uniqueDeliveries = 2;
  assert.equal(validateLoadEvidence(alteredInvariant), false);

  const mixedExpectedError = structuredClone(valid);
  mixedExpectedError.httpSummary.technicalErrorCount = 1;
  assert.equal(validateLoadEvidence(mixedExpectedError), false);
};

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  selfTestLoadEvidence();
  process.stdout.write('stage-6 load evidence validator self-test: PASS\n');
}
