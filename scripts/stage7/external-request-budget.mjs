#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export const FULL_EXTERNAL_AUTHORIZATION_IDS = Object.freeze([
  'AUTH-E7-EXT-01',
  'AUTH-E7-EXT-02',
  'AUTH-E7-EXT-03',
]);

export const FULL_REQUEST_BUDGET_USAGE_IDS = Object.freeze([
  'EXTERNAL_AUTHORIZATION_PREFLIGHT',
  'SMOKE_INPUT_PREFLIGHT_CANDIDATE',
  'ACTIVATION_CANDIDATE',
  'SMOKE_POST_DEPLOY',
  'QUALITY_FOCAL',
  'EDGE_PASSIVE',
  'SANDBOX_ONE_USE',
  'ROLLBACK_PENDING_INPUT_PREFLIGHT',
  'RB_E7_05_PENDING_PRODUCER',
  'POST_ROLLBACK_VERSIONED',
  'ACTIVATION_REPROMOTION',
  'POST_REPROMOTION_VERSIONED',
  'ROLLBACK_RESILIENCE',
  'RECONCILIATION_ROLLBACK_CHECK_SMOKE',
  'RECONCILIATION_ROLLBACK_RESILIENCE_SMOKE',
  'PUBLICATION_TARGET_PREFLIGHT',
]);

export const FULL_REQUEST_BUDGET_PREFENCE_USAGE_IDS = Object.freeze(
  FULL_REQUEST_BUDGET_USAGE_IDS.filter((usageId) => usageId !== 'PUBLICATION_TARGET_PREFLIGHT'),
);

const [OWNED_ID, SANDBOX_ID, PASSIVE_ID] = FULL_EXTERNAL_AUTHORIZATION_IDS;
const ZERO = Object.freeze({ [OWNED_ID]: 0, [SANDBOX_ID]: 0, [PASSIVE_ID]: 0 });
const counts = (owned = 0, sandbox = 0, passive = 0) => ({
  [OWNED_ID]: owned,
  [SANDBOX_ID]: sandbox,
  [PASSIVE_ID]: passive,
});

const EXACT_USAGE_COUNTS = Object.freeze({
  EXTERNAL_AUTHORIZATION_PREFLIGHT: ZERO,
  SMOKE_INPUT_PREFLIGHT_CANDIDATE: ZERO,
  ACTIVATION_CANDIDATE: ZERO,
  QUALITY_FOCAL: Object.freeze(counts(0, 0, 24)),
  EDGE_PASSIVE: Object.freeze(counts(0, 0, 12)),
  SANDBOX_ONE_USE: Object.freeze(counts(0, 7, 0)),
  ROLLBACK_PENDING_INPUT_PREFLIGHT: ZERO,
  POST_ROLLBACK_VERSIONED: Object.freeze(counts(3, 0, 0)),
  ACTIVATION_REPROMOTION: ZERO,
  POST_REPROMOTION_VERSIONED: Object.freeze(counts(3, 0, 0)),
  ROLLBACK_RESILIENCE: Object.freeze(counts(11, 0, 0)),
  RECONCILIATION_ROLLBACK_CHECK_SMOKE: Object.freeze(counts(3, 0, 0)),
  RECONCILIATION_ROLLBACK_RESILIENCE_SMOKE: Object.freeze(counts(3, 0, 0)),
  PUBLICATION_TARGET_PREFLIGHT: Object.freeze(counts(3, 0, 0)),
});

const VARIABLE_USAGE_IDS = Object.freeze(['SMOKE_POST_DEPLOY', 'RB_E7_05_PENDING_PRODUCER']);

export const FULL_REQUEST_BUDGET_FIXED_COMPONENTS = Object.freeze([
  Object.freeze({ componentId: 'QUALITY_FOCAL', requestCounts: Object.freeze(counts(0, 0, 24)) }),
  Object.freeze({
    componentId: 'EDGE_PASSIVE_DIRECT',
    requestCounts: Object.freeze(counts(0, 0, 6)),
  }),
  Object.freeze({
    componentId: 'EDGE_PASSIVE_ZAP_EXACT_INVENTORY',
    requestCounts: Object.freeze(counts(0, 0, 6)),
  }),
  Object.freeze({ componentId: 'SANDBOX_ONE_USE', requestCounts: Object.freeze(counts(0, 7, 0)) }),
  Object.freeze({
    componentId: 'POST_ROLLBACK_VERSIONED',
    requestCounts: Object.freeze(counts(3, 0, 0)),
  }),
  Object.freeze({
    componentId: 'POST_REPROMOTION_VERSIONED',
    requestCounts: Object.freeze(counts(3, 0, 0)),
  }),
  Object.freeze({
    componentId: 'ROLLBACK_RESILIENCE',
    requestCounts: Object.freeze(counts(11, 0, 0)),
  }),
  Object.freeze({
    componentId: 'RECONCILIATION_ROLLBACK_CHECK_SMOKE',
    requestCounts: Object.freeze(counts(3, 0, 0)),
  }),
  Object.freeze({
    componentId: 'RECONCILIATION_ROLLBACK_RESILIENCE_SMOKE',
    requestCounts: Object.freeze(counts(3, 0, 0)),
  }),
  Object.freeze({
    componentId: 'PUBLICATION_TARGET_PREFLIGHT',
    requestCounts: Object.freeze(counts(3, 0, 0)),
  }),
]);

export class Stage7ExternalRequestBudgetError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7ExternalRequestBudgetError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7ExternalRequestBudgetError(code);
};

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, expected) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...expected].toSorted().join('\0');

const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) {
    return `{${Object.keys(value)
      .toSorted()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
};

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const objectSha256 = (value) => sha256(canonical(value));
const clone = (value) => JSON.parse(JSON.stringify(value));

const zeroCounts = () => counts();
const addCounts = (target, source) => {
  for (const id of FULL_EXTERNAL_AUTHORIZATION_IDS) target[id] += source[id];
  return target;
};
const subtractCounts = (left, right) =>
  Object.fromEntries(FULL_EXTERNAL_AUTHORIZATION_IDS.map((id) => [id, left[id] - right[id]]));

const validateCounts = (value, code = 'E7_EXTERNAL_REQUEST_BUDGET_COUNTS_INVALID') => {
  if (
    !exactKeys(value, FULL_EXTERNAL_AUTHORIZATION_IDS) ||
    FULL_EXTERNAL_AUTHORIZATION_IDS.some(
      (id) => !Number.isSafeInteger(value[id]) || value[id] < 0 || value[id] > 100,
    )
  ) {
    fail(code);
  }
  return value;
};

const fixedTotals = () =>
  FULL_REQUEST_BUDGET_FIXED_COMPONENTS.reduce(
    (total, component) => addCounts(total, component.requestCounts),
    zeroCounts(),
  );

const planBody = ({
  candidateSha,
  releaseId,
  configSha256,
  authorizationSha256,
  ownedOriginSha256,
  sandboxHostSha256,
  requestLimits,
}) => {
  validateCounts(requestLimits, 'E7_EXTERNAL_REQUEST_BUDGET_LIMITS_INVALID');
  const reservations = fixedTotals();
  const variableCapacity = subtractCounts(requestLimits, reservations);
  if (
    variableCapacity[OWNED_ID] < 1 ||
    variableCapacity[SANDBOX_ID] < 0 ||
    variableCapacity[PASSIVE_ID] < 0
  ) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_CAPACITY_INVALID');
  }
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_EXTERNAL_REQUEST_BUDGET_PLAN',
    status: 'RESERVED_BEFORE_EXTERNAL_REQUESTS',
    candidateSha,
    releaseId,
    configSha256,
    authorizationSha256,
    ownedOriginSha256,
    sandboxHostSha256,
    requestLimits: { ...requestLimits },
    fixedComponents: FULL_REQUEST_BUDGET_FIXED_COMPONENTS.map((component) => ({
      componentId: component.componentId,
      requestCounts: { ...component.requestCounts },
    })),
    fixedReservations: reservations,
    variableCapacity,
    requiredEnforcement: {
      browserRouteBeforeContinue: true,
      pendingRouteBeforeContinue: true,
      zapBeforeEgress: true,
      zapExactRequestCount: 6,
      cumulativeBeforeEveryPhase: true,
    },
    containsSensitiveData: false,
  };
};

export const createFullExternalRequestBudgetPlan = (input) => {
  if (
    !object(input) ||
    !SHA.test(input.candidateSha ?? '') ||
    !/^rel-\d{8}-\d{4}-[0-9a-f]{7}$/u.test(input.releaseId ?? '') ||
    !SHA256.test(input.configSha256 ?? '') ||
    !SHA256.test(input.authorizationSha256 ?? '') ||
    !SHA256.test(input.ownedOriginSha256 ?? '') ||
    !SHA256.test(input.sandboxHostSha256 ?? '')
  ) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_IDENTITY_INVALID');
  }
  const body = planBody(input);
  return { ...body, planSha256: objectSha256(body) };
};

export const validateFullExternalRequestBudgetPlan = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'configSha256',
      'authorizationSha256',
      'ownedOriginSha256',
      'sandboxHostSha256',
      'requestLimits',
      'fixedComponents',
      'fixedReservations',
      'variableCapacity',
      'requiredEnforcement',
      'containsSensitiveData',
      'planSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_EXTERNAL_REQUEST_BUDGET_PLAN' ||
    value.status !== 'RESERVED_BEFORE_EXTERNAL_REQUESTS' ||
    value.containsSensitiveData !== false ||
    value.planSha256 !==
      objectSha256(
        Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'planSha256')),
      )
  ) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_PLAN_INVALID');
  }
  const expected = createFullExternalRequestBudgetPlan(value);
  if (canonical(value) !== canonical(expected)) fail('E7_EXTERNAL_REQUEST_BUDGET_PLAN_INVALID');
  return value;
};

const validateUsage = (usage, plan) => {
  if (
    !exactKeys(usage, [
      'schemaVersion',
      'usageId',
      'bundleSha256',
      'candidateSha',
      'releaseId',
      'configSha256',
      'ownedOriginSha256',
      'sandboxHostSha256',
      'requestCounts',
    ]) ||
    usage.schemaVersion !== 1 ||
    !FULL_REQUEST_BUDGET_USAGE_IDS.includes(usage.usageId) ||
    usage.bundleSha256 !== plan.authorizationSha256 ||
    usage.candidateSha !== plan.candidateSha ||
    usage.releaseId !== plan.releaseId ||
    usage.configSha256 !== plan.configSha256 ||
    usage.ownedOriginSha256 !== plan.ownedOriginSha256 ||
    usage.sandboxHostSha256 !== plan.sandboxHostSha256
  ) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_USAGE_INVALID');
  }
  validateCounts(usage.requestCounts, 'E7_EXTERNAL_REQUEST_BUDGET_USAGE_INVALID');
  const expected = EXACT_USAGE_COUNTS[usage.usageId];
  if (expected !== undefined && canonical(usage.requestCounts) !== canonical(expected)) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_FIXED_USAGE_INVALID');
  }
  if (usage.usageId === 'SMOKE_POST_DEPLOY' || usage.usageId === 'RB_E7_05_PENDING_PRODUCER') {
    if (usage.requestCounts[PASSIVE_ID] !== 0) {
      fail('E7_EXTERNAL_REQUEST_BUDGET_VARIABLE_USAGE_INVALID');
    }
  } else if (!Object.hasOwn(EXACT_USAGE_COUNTS, usage.usageId)) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_VARIABLE_USAGE_INVALID');
  }
  return usage;
};

const requestedSet = (phase) => {
  if (phase === 'PARTIAL') return null;
  if (phase === 'PRE_FENCE') return FULL_REQUEST_BUDGET_PREFENCE_USAGE_IDS;
  if (phase === 'POST_PUBLICATION') return FULL_REQUEST_BUDGET_USAGE_IDS;
  fail('E7_EXTERNAL_REQUEST_BUDGET_PHASE_INVALID');
};

const validateFullExternalRequestBudgetCheckpointInternal = ({ plan, usages, phase }) => {
  validateFullExternalRequestBudgetPlan(plan);
  if (!Array.isArray(usages)) fail('E7_EXTERNAL_REQUEST_BUDGET_USAGE_SET_INVALID');
  const expectedSet = requestedSet(phase);
  const seen = new Map();
  for (const usage of usages) {
    validateUsage(usage, plan);
    if (seen.has(usage.usageId)) fail('E7_EXTERNAL_REQUEST_BUDGET_USAGE_DUPLICATE');
    seen.set(usage.usageId, usage);
  }
  if (
    expectedSet !== null &&
    [...seen.keys()].toSorted().join('\0') !== [...expectedSet].toSorted().join('\0')
  ) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_USAGE_SET_INVALID');
  }

  const actualTotals = [...seen.values()].reduce(
    (total, usage) => addCounts(total, usage.requestCounts),
    zeroCounts(),
  );
  const variableUsed = counts(
    (seen.get('SMOKE_POST_DEPLOY')?.requestCounts[OWNED_ID] ?? 0) +
      (seen.get('RB_E7_05_PENDING_PRODUCER')?.requestCounts[OWNED_ID] ?? 0),
    (seen.get('SMOKE_POST_DEPLOY')?.requestCounts[SANDBOX_ID] ?? 0) +
      (seen.get('RB_E7_05_PENDING_PRODUCER')?.requestCounts[SANDBOX_ID] ?? 0),
    0,
  );
  if (
    FULL_EXTERNAL_AUTHORIZATION_IDS.some(
      (id) =>
        variableUsed[id] > plan.variableCapacity[id] || actualTotals[id] > plan.requestLimits[id],
    )
  ) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_EXCEEDED');
  }

  const missingFixedReservations = FULL_REQUEST_BUDGET_FIXED_COMPONENTS.filter(({ componentId }) =>
    componentId.startsWith('EDGE_PASSIVE_') ? !seen.has('EDGE_PASSIVE') : !seen.has(componentId),
  ).reduce((total, component) => addCounts(total, component.requestCounts), zeroCounts());
  const committedTotals = Object.fromEntries(
    FULL_EXTERNAL_AUTHORIZATION_IDS.map((id) => [
      id,
      actualTotals[id] + missingFixedReservations[id],
    ]),
  );
  if (FULL_EXTERNAL_AUTHORIZATION_IDS.some((id) => committedTotals[id] > plan.requestLimits[id])) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_RESERVATION_EXCEEDED');
  }
  const remaining = subtractCounts(plan.requestLimits, actualTotals);
  const remainingAfterReservations = subtractCounts(plan.requestLimits, committedTotals);
  const variableCapacityRemaining = subtractCounts(plan.variableCapacity, variableUsed);
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_EXTERNAL_REQUEST_BUDGET_CHECKPOINT',
    status: 'WITHIN_AUTHORIZED_LIMITS',
    phase,
    candidateSha: plan.candidateSha,
    releaseId: plan.releaseId,
    planSha256: plan.planSha256,
    usageIds: [...seen.keys()].toSorted(),
    actualTotals,
    reservedTotals: missingFixedReservations,
    committedTotals,
    remaining,
    remainingAfterReservations,
    variableUsed,
    variableCapacityRemaining,
    containsSensitiveData: false,
  };
};

export const validateFullExternalRequestBudgetCheckpoint = (input) =>
  validateFullExternalRequestBudgetCheckpointInternal(input);

export const assertFullExternalRequestAllowed = ({ plan, usages, usageId, requestCounts }) => {
  if (!VARIABLE_USAGE_IDS.includes(usageId)) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_VARIABLE_USAGE_INVALID');
  }
  validateCounts(requestCounts, 'E7_EXTERNAL_REQUEST_BUDGET_NEXT_REQUEST_INVALID');
  const synthetic = {
    schemaVersion: 1,
    usageId,
    bundleSha256: plan.authorizationSha256,
    candidateSha: plan.candidateSha,
    releaseId: plan.releaseId,
    configSha256: plan.configSha256,
    ownedOriginSha256: plan.ownedOriginSha256,
    sandboxHostSha256: plan.sandboxHostSha256,
    requestCounts: { ...requestCounts },
  };
  validateUsage(synthetic, plan);
  const prior = usages.filter((usage) => usage.usageId !== usageId);
  return validateFullExternalRequestBudgetCheckpointInternal({
    plan,
    usages: [...prior, synthetic],
    phase: 'PARTIAL',
  });
};

export const createFullExternalRequestCounter = ({ plan, usages, usageId }) => {
  validateFullExternalRequestBudgetPlan(plan);
  if (!VARIABLE_USAGE_IDS.includes(usageId) || !Array.isArray(usages)) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_COUNTER_INPUT_INVALID');
  }
  validateFullExternalRequestBudgetCheckpoint({ plan, usages, phase: 'PARTIAL' });
  if (usages.some((usage) => usage.usageId === usageId)) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_COUNTER_ALREADY_RECORDED');
  }
  const allowedIds = [OWNED_ID, SANDBOX_ID];
  let current = zeroCounts();
  let closed = false;
  const document = () => usage(plan, usageId, { ...current });
  return Object.freeze({
    beforeRequest(authorizationId) {
      if (closed || !allowedIds.includes(authorizationId)) {
        fail('E7_EXTERNAL_REQUEST_BUDGET_COUNTER_REQUEST_INVALID');
      }
      const next = { ...current, [authorizationId]: current[authorizationId] + 1 };
      assertFullExternalRequestAllowed({ plan, usages, usageId, requestCounts: next });
      current = next;
      return { usageId, authorizationId, count: current[authorizationId] };
    },
    close() {
      if (closed) fail('E7_EXTERNAL_REQUEST_BUDGET_COUNTER_CLOSED');
      const result = document();
      validateUsage(result, plan);
      closed = true;
      return result;
    },
  });
};

export const createFullExternalRequestComponentCounter = ({ plan, componentId }) => {
  validateFullExternalRequestBudgetPlan(plan);
  const component = FULL_REQUEST_BUDGET_FIXED_COMPONENTS.find(
    (candidate) => candidate.componentId === componentId,
  );
  if (
    component === undefined ||
    FULL_EXTERNAL_AUTHORIZATION_IDS.every((id) => component.requestCounts[id] === 0)
  ) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_COMPONENT_COUNTER_INPUT_INVALID');
  }
  let current = zeroCounts();
  let closed = false;
  return Object.freeze({
    beforeRequest(authorizationId) {
      if (
        closed ||
        !FULL_EXTERNAL_AUTHORIZATION_IDS.includes(authorizationId) ||
        current[authorizationId] >= component.requestCounts[authorizationId]
      ) {
        fail('E7_EXTERNAL_REQUEST_BUDGET_COMPONENT_REQUEST_INVALID');
      }
      current = { ...current, [authorizationId]: current[authorizationId] + 1 };
      return {
        componentId,
        authorizationId,
        count: current[authorizationId],
        reserved: component.requestCounts[authorizationId],
      };
    },
    close() {
      if (closed || canonical(current) !== canonical(component.requestCounts)) {
        fail('E7_EXTERNAL_REQUEST_BUDGET_COMPONENT_COUNT_INVALID');
      }
      closed = true;
      return { componentId, requestCounts: { ...current } };
    },
  });
};

const usage = (plan, usageId, requestCounts) => ({
  schemaVersion: 1,
  usageId,
  bundleSha256: plan.authorizationSha256,
  candidateSha: plan.candidateSha,
  releaseId: plan.releaseId,
  configSha256: plan.configSha256,
  ownedOriginSha256: plan.ownedOriginSha256,
  sandboxHostSha256: plan.sandboxHostSha256,
  requestCounts,
});

export const selfTestExternalRequestBudget = () => {
  const plan = createFullExternalRequestBudgetPlan({
    candidateSha: 'a'.repeat(40),
    releaseId: 'rel-20260818-1200-aaaaaaa',
    configSha256: 'b'.repeat(64),
    authorizationSha256: 'c'.repeat(64),
    ownedOriginSha256: 'd'.repeat(64),
    sandboxHostSha256: 'e'.repeat(64),
    requestLimits: counts(100, 20, 100),
  });
  assert.equal(validateFullExternalRequestBudgetPlan(plan), plan);
  assert.deepEqual(plan.fixedReservations, counts(26, 7, 36));
  assert.deepEqual(plan.variableCapacity, counts(74, 13, 64));

  const dynamic = {
    SMOKE_POST_DEPLOY: counts(40, 3, 0),
    EDGE_PASSIVE: counts(0, 0, 12),
    RB_E7_05_PENDING_PRODUCER: counts(10, 2, 0),
  };
  const usages = FULL_REQUEST_BUDGET_USAGE_IDS.map((usageId) =>
    usage(plan, usageId, dynamic[usageId] ?? EXACT_USAGE_COUNTS[usageId]),
  );
  const preFence = validateFullExternalRequestBudgetCheckpoint({
    plan,
    usages: usages.filter(({ usageId }) => usageId !== 'PUBLICATION_TARGET_PREFLIGHT'),
    phase: 'PRE_FENCE',
  });
  assert.deepEqual(preFence.actualTotals, counts(73, 12, 36));
  assert.deepEqual(preFence.reservedTotals, counts(3, 0, 0));
  assert.deepEqual(preFence.committedTotals, counts(76, 12, 36));
  const final = validateFullExternalRequestBudgetCheckpoint({
    plan,
    usages,
    phase: 'POST_PUBLICATION',
  });
  assert.deepEqual(final.actualTotals, counts(76, 12, 36));
  assert.deepEqual(final.reservedTotals, counts(0, 0, 0));
  assert.deepEqual(final.remaining, counts(24, 8, 64));

  const beforePending = usages.filter(({ usageId }) => usageId === 'SMOKE_POST_DEPLOY');
  assert.equal(
    assertFullExternalRequestAllowed({
      plan,
      usages: beforePending,
      usageId: 'RB_E7_05_PENDING_PRODUCER',
      requestCounts: counts(34, 10, 0),
    }).status,
    'WITHIN_AUTHORIZED_LIMITS',
  );
  assert.throws(
    () =>
      assertFullExternalRequestAllowed({
        plan,
        usages: beforePending,
        usageId: 'RB_E7_05_PENDING_PRODUCER',
        requestCounts: counts(35, 11, 0),
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_EXCEEDED',
  );

  const smokeCounter = createFullExternalRequestCounter({
    plan,
    usages: [],
    usageId: 'SMOKE_POST_DEPLOY',
  });
  for (let count = 0; count < 74; count += 1) smokeCounter.beforeRequest(OWNED_ID);
  assert.throws(
    () => smokeCounter.beforeRequest(OWNED_ID),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_EXCEEDED',
  );
  const smokeUsage = smokeCounter.close();
  assert.equal(smokeUsage.requestCounts[OWNED_ID], 74);
  assert.throws(
    () => smokeCounter.beforeRequest(SANDBOX_ID),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_COUNTER_REQUEST_INVALID',
  );
  assert.throws(
    () =>
      createFullExternalRequestCounter({
        plan,
        usages: [],
        usageId: 'EDGE_PASSIVE',
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_COUNTER_INPUT_INVALID',
  );
  const zapComponentCounter = createFullExternalRequestComponentCounter({
    plan,
    componentId: 'EDGE_PASSIVE_ZAP_EXACT_INVENTORY',
  });
  for (let count = 0; count < 6; count += 1) zapComponentCounter.beforeRequest(PASSIVE_ID);
  assert.throws(
    () => zapComponentCounter.beforeRequest(PASSIVE_ID),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_COMPONENT_REQUEST_INVALID',
  );
  assert.deepEqual(zapComponentCounter.close(), {
    componentId: 'EDGE_PASSIVE_ZAP_EXACT_INVENTORY',
    requestCounts: counts(0, 0, 6),
  });
  const incompleteComponentCounter = createFullExternalRequestComponentCounter({
    plan,
    componentId: 'EDGE_PASSIVE_DIRECT',
  });
  incompleteComponentCounter.beforeRequest(PASSIVE_ID);
  assert.throws(
    () => incompleteComponentCounter.close(),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_COMPONENT_COUNT_INVALID',
  );
  assert.throws(
    () =>
      createFullExternalRequestCounter({
        plan,
        usages: [smokeUsage],
        usageId: 'SMOKE_POST_DEPLOY',
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_COUNTER_ALREADY_RECORDED',
  );

  const mutate = (callback) => {
    const value = clone(plan);
    callback(value);
    return value;
  };
  for (const changed of [
    mutate((value) => {
      value.requestLimits[OWNED_ID] = 25;
      const body = Object.fromEntries(
        Object.entries(value).filter(([key]) => key !== 'planSha256'),
      );
      value.planSha256 = objectSha256(body);
    }),
    mutate((value) => {
      value.variableCapacity[OWNED_ID] += 1;
      const body = Object.fromEntries(
        Object.entries(value).filter(([key]) => key !== 'planSha256'),
      );
      value.planSha256 = objectSha256(body);
    }),
    mutate((value) => {
      value.requiredEnforcement.zapBeforeEgress = false;
      const body = Object.fromEntries(
        Object.entries(value).filter(([key]) => key !== 'planSha256'),
      );
      value.planSha256 = objectSha256(body);
    }),
  ]) {
    assert.throws(
      () => validateFullExternalRequestBudgetPlan(changed),
      Stage7ExternalRequestBudgetError,
    );
  }

  const wrongFixed = clone(usages);
  wrongFixed.find(({ usageId }) => usageId === 'QUALITY_FOCAL').requestCounts[PASSIVE_ID] = 23;
  assert.throws(
    () =>
      validateFullExternalRequestBudgetCheckpoint({
        plan,
        usages: wrongFixed,
        phase: 'POST_PUBLICATION',
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_FIXED_USAGE_INVALID',
  );
  const duplicate = [...usages, clone(usages[0])];
  assert.throws(
    () =>
      validateFullExternalRequestBudgetCheckpoint({
        plan,
        usages: duplicate,
        phase: 'POST_PUBLICATION',
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_USAGE_DUPLICATE',
  );
  const wrongBundle = clone(usages);
  wrongBundle[0].bundleSha256 = 'f'.repeat(64);
  assert.throws(
    () =>
      validateFullExternalRequestBudgetCheckpoint({
        plan,
        usages: wrongBundle,
        phase: 'POST_PUBLICATION',
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_USAGE_INVALID',
  );
  const missing = usages.slice(1);
  assert.throws(
    () =>
      validateFullExternalRequestBudgetCheckpoint({
        plan,
        usages: missing,
        phase: 'POST_PUBLICATION',
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_USAGE_SET_INVALID',
  );
  const edgeBelowExact = clone(usages);
  edgeBelowExact.find(({ usageId }) => usageId === 'EDGE_PASSIVE').requestCounts[PASSIVE_ID] = 11;
  assert.throws(
    () =>
      validateFullExternalRequestBudgetCheckpoint({
        plan,
        usages: edgeBelowExact,
        phase: 'POST_PUBLICATION',
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_FIXED_USAGE_INVALID',
  );
  assert.throws(
    () =>
      createFullExternalRequestBudgetPlan({
        ...plan,
        requestLimits: counts(26, 7, 36),
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_CAPACITY_INVALID',
  );

  return { assertions: 25, externalRequests: 0, mutationsPerformed: 0 };
};

const main = () => {
  if (process.argv.length === 3 && process.argv[2] === '--self-test') {
    const result = selfTestExternalRequestBudget();
    process.stdout.write(
      `stage-7 external request budget self-test: PASS (${result.assertions} assertions, 0 external requests, 0 mutations)\n`,
    );
    return;
  }
  fail('E7_EXTERNAL_REQUEST_BUDGET_ARGUMENT_SET_INVALID');
};

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(
      `${error instanceof Stage7ExternalRequestBudgetError ? error.code : 'E7_EXTERNAL_REQUEST_BUDGET_UNEXPECTED_FAILURE'}\n`,
    );
    process.exitCode = 1;
  }
}
