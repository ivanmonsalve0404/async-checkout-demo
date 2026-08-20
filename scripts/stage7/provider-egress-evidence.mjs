#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-\d{8}-\d{4}-[0-9a-f]{7}$/u;
const EVENT_ID = /^[\x21-\x7e]{1,512}$/u;
const LOG_GROUP =
  /^\/checkout-assessment-(?:release|prerelease-[a-z0-9-]+)\/lambda\/(?:api|worker)$/u;
const EVENT_NAME = 'provider.sandbox.egress.attempted';
const PROVIDER_HOST_SHA256 = createHash('sha256').update('sandbox.wompi.co').digest('hex');
const EVENT_KEYS = Object.freeze([
  'timestamp',
  'level',
  'service',
  'environment',
  'version',
  'eventName',
  'schemaVersion',
  'candidateSha',
  'releaseId',
  'providerHostSha256',
  'operation',
  'method',
  'correlationSha256',
  'containsSensitiveData',
]);
const OPERATIONS = Object.freeze({
  MERCHANT_CONFIGURATION: 'GET',
  TRANSACTION_CREATE: 'POST',
  TRANSACTION_STATUS: 'GET',
});

export class Stage7ProviderEgressEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7ProviderEgressEvidenceError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7ProviderEgressEvidenceError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
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
const canonicalUtc = (value) => {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
};

export const providerEgressCorrelationSha256 = (providerReference) => {
  if (
    typeof providerReference !== 'string' ||
    !/^[A-Za-z0-9._~-]{1,512}$/u.test(providerReference)
  ) {
    fail('E7_PROVIDER_EGRESS_REFERENCE_INVALID');
  }
  return sha256(`stage7-sandbox-egress/v1\0${providerReference}`);
};

export const providerEgressCorrelationSetSha256 = (correlations) => {
  if (
    !Array.isArray(correlations) ||
    correlations.length === 0 ||
    correlations.some((value) => !SHA256.test(value)) ||
    new Set(correlations).size !== correlations.length
  ) {
    fail('E7_PROVIDER_EGRESS_CORRELATION_SET_INVALID');
  }
  return sha256([...correlations].toSorted().join('\0'));
};

export const stage7ProviderEgressLogGroups = (environment) => {
  if (!/^assessment-(?:release|prerelease-[a-z0-9-]+)$/u.test(environment ?? '')) {
    fail('E7_PROVIDER_EGRESS_ENVIRONMENT_INVALID');
  }
  return Object.freeze({
    api: `/checkout-${environment}/lambda/api`,
    worker: `/checkout-${environment}/lambda/worker`,
  });
};

const parseJson = (source, code) => {
  if (typeof source !== 'string' || source.length === 0 || source.length > 131_072) fail(code);
  try {
    return JSON.parse(source);
  } catch {
    fail(code);
  }
};

const applicationEntry = (message) => {
  const outer = parseJson(message, 'E7_PROVIDER_EGRESS_LOG_MESSAGE_INVALID');
  if (object(outer) && outer.eventName === EVENT_NAME) return outer;
  if (!object(outer) || !Object.hasOwn(outer, 'message')) {
    fail('E7_PROVIDER_EGRESS_LOG_MESSAGE_INVALID');
  }
  if (object(outer.message)) return outer.message;
  return parseJson(outer.message, 'E7_PROVIDER_EGRESS_LOG_MESSAGE_INVALID');
};

const validateApplicationEntry = (entry) => {
  const operation = entry.operation;
  if (
    !exactKeys(entry, EVENT_KEYS) ||
    !canonicalUtc(entry.timestamp) ||
    entry.level !== 'info' ||
    entry.service !== 'checkout-api' ||
    !/^assessment$/u.test(entry.environment ?? '') ||
    typeof entry.version !== 'string' ||
    !/^\d+\.\d+\.\d+$/u.test(entry.version) ||
    entry.eventName !== EVENT_NAME ||
    entry.schemaVersion !== 1 ||
    !SHA.test(entry.candidateSha ?? '') ||
    !RELEASE_ID.test(entry.releaseId ?? '') ||
    !entry.releaseId.endsWith(entry.candidateSha.slice(0, 7)) ||
    entry.providerHostSha256 !== PROVIDER_HOST_SHA256 ||
    !Object.hasOwn(OPERATIONS, operation) ||
    entry.method !== OPERATIONS[operation] ||
    !SHA256.test(entry.correlationSha256 ?? '') ||
    entry.containsSensitiveData !== false
  ) {
    fail('E7_PROVIDER_EGRESS_EVENT_INVALID');
  }
  return entry;
};

const validateIdentitySet = (identities) => {
  if (
    !Array.isArray(identities) ||
    identities.length === 0 ||
    identities.some(
      (identity) =>
        !exactKeys(identity, ['candidateSha', 'releaseId']) ||
        !SHA.test(identity.candidateSha ?? '') ||
        !RELEASE_ID.test(identity.releaseId ?? '') ||
        !identity.releaseId.endsWith(identity.candidateSha.slice(0, 7)),
    )
  ) {
    fail('E7_PROVIDER_EGRESS_IDENTITY_SET_INVALID');
  }
  const keys = identities.map(({ candidateSha, releaseId }) => `${candidateSha}\0${releaseId}`);
  if (new Set(keys).size !== keys.length) fail('E7_PROVIDER_EGRESS_IDENTITY_SET_INVALID');
  return new Set(keys);
};

const validateCollectionInput = (input) => {
  if (
    !object(input) ||
    !exactKeys(input.logGroups, ['api', 'worker']) ||
    !LOG_GROUP.test(input.logGroups.api ?? '') ||
    !LOG_GROUP.test(input.logGroups.worker ?? '') ||
    input.logGroups.api === input.logGroups.worker ||
    !Number.isSafeInteger(input.startTimeMs) ||
    !Number.isSafeInteger(input.endTimeMs) ||
    input.startTimeMs < 0 ||
    input.endTimeMs <= input.startTimeMs ||
    input.endTimeMs - input.startTimeMs > 60 * 60 * 1_000 ||
    !Array.isArray(input.expectedCorrelations) ||
    input.expectedCorrelations.length === 0 ||
    input.expectedCorrelations.some(
      (value) =>
        !exactKeys(value, ['correlationSha256', 'requiresStatusRead']) ||
        !SHA256.test(value.correlationSha256 ?? '') ||
        typeof value.requiresStatusRead !== 'boolean',
    ) ||
    typeof input.client?.filterLogEvents !== 'function' ||
    (input.requiredStatusReleaseIdentity !== undefined &&
      (!object(input.requiredStatusReleaseIdentity) ||
        !exactKeys(input.requiredStatusReleaseIdentity, ['candidateSha', 'releaseId'])))
  ) {
    fail('E7_PROVIDER_EGRESS_COLLECTION_INPUT_INVALID');
  }
  providerEgressCorrelationSetSha256(
    input.expectedCorrelations.map(({ correlationSha256 }) => correlationSha256),
  );
  const allowedIdentities = validateIdentitySet(input.allowedReleaseIdentities);
  const requiredStatusIdentityKey =
    input.requiredStatusReleaseIdentity === undefined
      ? null
      : `${input.requiredStatusReleaseIdentity.candidateSha}\0${input.requiredStatusReleaseIdentity.releaseId}`;
  if (requiredStatusIdentityKey !== null && !allowedIdentities.has(requiredStatusIdentityKey)) {
    fail('E7_PROVIDER_EGRESS_REQUIRED_STATUS_IDENTITY_INVALID');
  }
  return { allowedIdentities, requiredStatusIdentityKey };
};

const readPage = async ({ client, logGroupName, startTimeMs, endTimeMs, nextToken }) => {
  const response = await client.filterLogEvents({
    logGroupName,
    startTime: startTimeMs,
    endTime: endTimeMs,
    filterPattern: `"${EVENT_NAME}"`,
    ...(nextToken === undefined ? {} : { nextToken }),
  });
  if (
    !object(response) ||
    !Array.isArray(response.events) ||
    (response.nextToken !== undefined &&
      (typeof response.nextToken !== 'string' || response.nextToken.length === 0))
  ) {
    fail('E7_PROVIDER_EGRESS_CLOUDWATCH_RESPONSE_INVALID');
  }
  return response;
};

const eventEnvelope = (event) => {
  if (
    !object(event) ||
    !EVENT_ID.test(event.eventId ?? '') ||
    !Number.isSafeInteger(event.timestamp) ||
    !Number.isSafeInteger(event.ingestionTime) ||
    typeof event.logStreamName !== 'string' ||
    event.logStreamName.length === 0 ||
    typeof event.message !== 'string'
  ) {
    fail('E7_PROVIDER_EGRESS_CLOUDWATCH_EVENT_INVALID');
  }
  return event;
};

const aggregate = ({ events, expected, allowedIdentities }) => {
  const counts = Object.fromEntries(
    [...expected].map((correlationSha256) => [
      correlationSha256,
      { merchant: 0, create: 0, status: 0, statusIdentities: new Set() },
    ]),
  );
  const byRuntime = { api: 0, worker: 0 };
  const acceptedEventIds = [];
  for (const { event, runtime } of events.values()) {
    const entry = validateApplicationEntry(applicationEntry(event.message));
    if (!expected.has(entry.correlationSha256)) continue;
    if (!allowedIdentities.has(`${entry.candidateSha}\0${entry.releaseId}`)) {
      fail('E7_PROVIDER_EGRESS_EVENT_IDENTITY_MISMATCH');
    }
    if (
      (runtime === 'api' && entry.operation === 'TRANSACTION_STATUS') ||
      (runtime === 'worker' && entry.operation !== 'TRANSACTION_STATUS')
    ) {
      fail('E7_PROVIDER_EGRESS_RUNTIME_OPERATION_INVALID');
    }
    const current = counts[entry.correlationSha256];
    if (entry.operation === 'MERCHANT_CONFIGURATION') current.merchant += 1;
    else if (entry.operation === 'TRANSACTION_CREATE') current.create += 1;
    else {
      current.status += 1;
      current.statusIdentities.add(`${entry.candidateSha}\0${entry.releaseId}`);
    }
    byRuntime[runtime] += 1;
    acceptedEventIds.push(event.eventId);
  }
  return { counts, byRuntime, acceptedEventIds };
};

const complete = (aggregated, expectedCorrelations, requiredStatusIdentityKey) =>
  expectedCorrelations.every(({ correlationSha256, requiresStatusRead }) => {
    const counts = aggregated.counts[correlationSha256];
    return (
      counts.create === 1 &&
      counts.merchant <= 1 &&
      (!requiresStatusRead || counts.status >= 1) &&
      (requiredStatusIdentityKey === null ||
        !requiresStatusRead ||
        counts.statusIdentities.has(requiredStatusIdentityKey))
    );
  });

const assertFinalCounts = (aggregated, expectedCorrelations, requiredStatusIdentityKey) => {
  if (
    !complete(aggregated, expectedCorrelations, requiredStatusIdentityKey) ||
    expectedCorrelations.some(({ correlationSha256 }) => {
      const counts = aggregated.counts[correlationSha256];
      return counts.create !== 1 || counts.merchant > 1;
    })
  ) {
    fail('E7_PROVIDER_EGRESS_EXPECTATION_NOT_MET');
  }
};

export const collectStage7ProviderEgressEvidence = async (input) => {
  const { allowedIdentities, requiredStatusIdentityKey } = validateCollectionInput(input);
  const expected = new Set(
    input.expectedCorrelations.map(({ correlationSha256 }) => correlationSha256),
  );
  const maximumPolls = input.maximumPolls ?? 6;
  const maximumPagesPerGroup = input.maximumPagesPerGroup ?? 25;
  const settlePolls = input.settlePolls ?? 1;
  const sleep =
    input.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  if (
    !Number.isSafeInteger(maximumPolls) ||
    maximumPolls < 1 ||
    maximumPolls > 20 ||
    !Number.isSafeInteger(maximumPagesPerGroup) ||
    maximumPagesPerGroup < 1 ||
    maximumPagesPerGroup > 100 ||
    !Number.isSafeInteger(settlePolls) ||
    settlePolls < 0 ||
    settlePolls > 3 ||
    typeof sleep !== 'function'
  ) {
    fail('E7_PROVIDER_EGRESS_COLLECTION_BOUNDS_INVALID');
  }

  const events = new Map();
  let cloudWatchReadCount = 0;
  let completePoll = null;
  for (let poll = 0; poll < maximumPolls; poll += 1) {
    for (const [runtime, logGroupName] of Object.entries(input.logGroups)) {
      let nextToken;
      const seenTokens = new Set();
      for (let page = 0; page < maximumPagesPerGroup; page += 1) {
        const response = await readPage({
          client: input.client,
          logGroupName,
          startTimeMs: input.startTimeMs,
          endTimeMs: input.endTimeMs,
          nextToken,
        });
        cloudWatchReadCount += 1;
        for (const rawEvent of response.events) {
          const event = eventEnvelope(rawEvent);
          if (event.timestamp < input.startTimeMs || event.timestamp > input.endTimeMs) {
            fail('E7_PROVIDER_EGRESS_EVENT_WINDOW_INVALID');
          }
          const prior = events.get(event.eventId);
          if (
            prior !== undefined &&
            (prior.runtime !== runtime || canonical(prior.event) !== canonical(event))
          ) {
            fail('E7_PROVIDER_EGRESS_EVENT_ID_COLLISION');
          }
          events.set(event.eventId, { event, runtime });
        }
        if (response.nextToken === undefined || response.nextToken === nextToken) break;
        if (seenTokens.has(response.nextToken)) fail('E7_PROVIDER_EGRESS_PAGINATION_LOOP');
        seenTokens.add(response.nextToken);
        nextToken = response.nextToken;
        if (page + 1 === maximumPagesPerGroup) fail('E7_PROVIDER_EGRESS_PAGE_LIMIT_EXCEEDED');
      }
    }
    const current = aggregate({ events, expected, allowedIdentities });
    if (complete(current, input.expectedCorrelations, requiredStatusIdentityKey)) {
      completePoll ??= poll;
      if (poll - completePoll >= settlePolls) break;
    } else {
      completePoll = null;
    }
    if (poll + 1 < maximumPolls) await sleep(Math.min(250 * 2 ** poll, 2_000));
  }

  const aggregated = aggregate({ events, expected, allowedIdentities });
  assertFinalCounts(aggregated, input.expectedCorrelations, requiredStatusIdentityKey);
  const operationCounts = Object.values(aggregated.counts).reduce(
    (total, value) => ({
      merchantConfiguration: total.merchantConfiguration + value.merchant,
      transactionCreate: total.transactionCreate + value.create,
      transactionStatus: total.transactionStatus + value.status,
    }),
    { merchantConfiguration: 0, transactionCreate: 0, transactionStatus: 0 },
  );
  const total = Object.values(operationCounts).reduce((sum, value) => sum + value, 0);
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'BACKEND_PROVIDER_EGRESS_EVIDENCE',
    status: 'PASS',
    observationWindow: {
      startedAtUtc: new Date(input.startTimeMs).toISOString(),
      endedAtUtc: new Date(input.endTimeMs).toISOString(),
    },
    allowedReleaseIdentitySetSha256: sha256([...allowedIdentities].toSorted().join('\0')),
    logGroupSetSha256: sha256(Object.values(input.logGroups).toSorted().join('\0')),
    correlationSetSha256: providerEgressCorrelationSetSha256([...expected]),
    attempts: {
      total,
      ...operationCounts,
      byRuntime: aggregated.byRuntime,
    },
    cloudWatchReadCount,
    eventSetSha256: sha256(aggregated.acceptedEventIds.toSorted().join('\0')),
    requiredStatusReleaseIdentitySha256:
      requiredStatusIdentityKey === null ? null : sha256(requiredStatusIdentityKey),
    rawIdentifiersCaptured: false,
    containsSensitiveData: false,
  };
};

export const createAwsCliProviderEgressClient = ({
  region,
  command = process.platform === 'win32' ? 'aws.cmd' : 'aws',
  executor = spawnSync,
}) => {
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/u.test(region ?? '') || typeof executor !== 'function') {
    fail('E7_PROVIDER_EGRESS_AWS_CLIENT_INVALID');
  }
  return Object.freeze({
    async filterLogEvents(request) {
      const arguments_ = [
        'logs',
        'filter-log-events',
        '--region',
        region,
        '--log-group-name',
        request.logGroupName,
        '--start-time',
        String(request.startTime),
        '--end-time',
        String(request.endTime),
        '--filter-pattern',
        request.filterPattern,
        '--limit',
        '10000',
        ...(request.nextToken === undefined ? [] : ['--next-token', request.nextToken]),
        '--output',
        'json',
        '--no-cli-pager',
      ];
      const result = executor(command, arguments_, {
        encoding: 'utf8',
        maxBuffer: 8 * 1024 * 1024,
        shell: false,
        windowsHide: true,
      });
      if (result.error !== undefined || result.status !== 0 || typeof result.stdout !== 'string') {
        fail('E7_PROVIDER_EGRESS_CLOUDWATCH_READ_FAILED');
      }
      const parsed = parseJson(result.stdout, 'E7_PROVIDER_EGRESS_CLOUDWATCH_RESPONSE_INVALID');
      return {
        events: parsed.events,
        ...(parsed.nextToken === undefined ? {} : { nextToken: parsed.nextToken }),
      };
    },
  });
};

const fixtureEntry = ({ correlationSha256, operation, candidateSha = 'a'.repeat(40) }) => ({
  timestamp: '2026-08-19T12:00:00.000Z',
  level: 'info',
  service: 'checkout-api',
  environment: 'assessment',
  version: '0.1.0',
  eventName: EVENT_NAME,
  schemaVersion: 1,
  candidateSha,
  releaseId: `rel-20260819-1200-${candidateSha.slice(0, 7)}`,
  providerHostSha256: PROVIDER_HOST_SHA256,
  operation,
  method: OPERATIONS[operation],
  correlationSha256,
  containsSensitiveData: false,
});
const fixtureEvent = (eventId, entry) => ({
  eventId,
  timestamp: Date.parse(entry.timestamp),
  ingestionTime: Date.parse(entry.timestamp) + 100,
  logStreamName: 'synthetic-stream',
  message: JSON.stringify(entry),
});

export const selfTestStage7ProviderEgressEvidence = async () => {
  const correlation = providerEgressCorrelationSha256('reference_synthetic-001');
  const pages = new Map([
    [
      '/checkout-assessment-release/lambda/api\0',
      {
        events: [
          fixtureEvent(
            'merchant',
            fixtureEntry({ correlationSha256: correlation, operation: 'MERCHANT_CONFIGURATION' }),
          ),
        ],
        nextToken: 'page-2',
      },
    ],
    [
      '/checkout-assessment-release/lambda/api\0page-2',
      {
        events: [
          fixtureEvent(
            'create',
            fixtureEntry({ correlationSha256: correlation, operation: 'TRANSACTION_CREATE' }),
          ),
        ],
      },
    ],
    [
      '/checkout-assessment-release/lambda/worker\0',
      {
        events: [
          fixtureEvent(
            'status',
            fixtureEntry({ correlationSha256: correlation, operation: 'TRANSACTION_STATUS' }),
          ),
        ],
      },
    ],
  ]);
  const client = {
    filterLogEvents: async ({ logGroupName, nextToken }) =>
      pages.get(`${logGroupName}\0${nextToken ?? ''}`) ?? { events: [] },
  };
  const evidence = await collectStage7ProviderEgressEvidence({
    logGroups: stage7ProviderEgressLogGroups('assessment-release'),
    startTimeMs: Date.parse('2026-08-19T11:59:00.000Z'),
    endTimeMs: Date.parse('2026-08-19T12:01:00.000Z'),
    allowedReleaseIdentities: [
      { candidateSha: 'a'.repeat(40), releaseId: 'rel-20260819-1200-aaaaaaa' },
    ],
    requiredStatusReleaseIdentity: {
      candidateSha: 'a'.repeat(40),
      releaseId: 'rel-20260819-1200-aaaaaaa',
    },
    expectedCorrelations: [{ correlationSha256: correlation, requiresStatusRead: true }],
    client,
    maximumPolls: 1,
    settlePolls: 0,
  });
  assert.deepEqual(evidence.attempts, {
    total: 3,
    merchantConfiguration: 1,
    transactionCreate: 1,
    transactionStatus: 1,
    byRuntime: { api: 2, worker: 1 },
  });
  assert.equal(evidence.cloudWatchReadCount, 3);
  assert.equal(evidence.containsSensitiveData, false);
  assert.equal(evidence.rawIdentifiersCaptured, false);
  assert.equal(
    evidence.requiredStatusReleaseIdentitySha256,
    sha256(`${'a'.repeat(40)}\0rel-20260819-1200-aaaaaaa`),
  );
  assert.equal(
    providerEgressCorrelationSha256('reference_transaction-001'),
    '012dc06ee0e083dc8fea80a018270f1638e66a317f8ff42985b88066264f823b',
  );
  await assert.rejects(
    collectStage7ProviderEgressEvidence({
      logGroups: stage7ProviderEgressLogGroups('assessment-release'),
      startTimeMs: Date.parse('2026-08-19T11:59:00.000Z'),
      endTimeMs: Date.parse('2026-08-19T12:01:00.000Z'),
      allowedReleaseIdentities: [
        { candidateSha: 'b'.repeat(40), releaseId: 'rel-20260819-1200-bbbbbbb' },
      ],
      expectedCorrelations: [{ correlationSha256: correlation, requiresStatusRead: true }],
      client,
      maximumPolls: 1,
      settlePolls: 0,
    }),
    (error) => error.code === 'E7_PROVIDER_EGRESS_EVENT_IDENTITY_MISMATCH',
  );
  const wrongRuntimeClient = {
    filterLogEvents: async ({ logGroupName }) => ({
      events: logGroupName.endsWith('/api')
        ? [
            fixtureEvent(
              'wrong-runtime',
              fixtureEntry({ correlationSha256: correlation, operation: 'TRANSACTION_STATUS' }),
            ),
          ]
        : [],
    }),
  };
  await assert.rejects(
    collectStage7ProviderEgressEvidence({
      logGroups: stage7ProviderEgressLogGroups('assessment-release'),
      startTimeMs: Date.parse('2026-08-19T11:59:00.000Z'),
      endTimeMs: Date.parse('2026-08-19T12:01:00.000Z'),
      allowedReleaseIdentities: [
        { candidateSha: 'a'.repeat(40), releaseId: 'rel-20260819-1200-aaaaaaa' },
      ],
      expectedCorrelations: [{ correlationSha256: correlation, requiresStatusRead: true }],
      client: wrongRuntimeClient,
      maximumPolls: 1,
      settlePolls: 0,
    }),
    (error) => error.code === 'E7_PROVIDER_EGRESS_RUNTIME_OPERATION_INVALID',
  );
  const wrongWorkerOperationClient = {
    filterLogEvents: async ({ logGroupName }) => ({
      events: logGroupName.endsWith('/worker')
        ? [
            fixtureEvent(
              'wrong-worker-operation',
              fixtureEntry({
                correlationSha256: correlation,
                operation: 'TRANSACTION_CREATE',
              }),
            ),
          ]
        : [],
    }),
  };
  await assert.rejects(
    collectStage7ProviderEgressEvidence({
      logGroups: stage7ProviderEgressLogGroups('assessment-release'),
      startTimeMs: Date.parse('2026-08-19T11:59:00.000Z'),
      endTimeMs: Date.parse('2026-08-19T12:01:00.000Z'),
      allowedReleaseIdentities: [
        { candidateSha: 'a'.repeat(40), releaseId: 'rel-20260819-1200-aaaaaaa' },
      ],
      expectedCorrelations: [{ correlationSha256: correlation, requiresStatusRead: true }],
      client: wrongWorkerOperationClient,
      maximumPolls: 1,
      settlePolls: 0,
    }),
    (error) => error.code === 'E7_PROVIDER_EGRESS_RUNTIME_OPERATION_INVALID',
  );
  await assert.rejects(
    collectStage7ProviderEgressEvidence({
      logGroups: stage7ProviderEgressLogGroups('assessment-release'),
      startTimeMs: Date.parse('2026-08-19T11:59:00.000Z'),
      endTimeMs: Date.parse('2026-08-19T12:01:00.000Z'),
      allowedReleaseIdentities: [
        { candidateSha: 'a'.repeat(40), releaseId: 'rel-20260819-1200-aaaaaaa' },
        { candidateSha: 'b'.repeat(40), releaseId: 'rel-20260819-1200-bbbbbbb' },
      ],
      requiredStatusReleaseIdentity: {
        candidateSha: 'b'.repeat(40),
        releaseId: 'rel-20260819-1200-bbbbbbb',
      },
      expectedCorrelations: [{ correlationSha256: correlation, requiresStatusRead: true }],
      client,
      maximumPolls: 1,
      settlePolls: 0,
    }),
    (error) => error.code === 'E7_PROVIDER_EGRESS_EXPECTATION_NOT_MET',
  );
  return { assertions: 10, externalRequests: 0, mutationsPerformed: 0 };
};

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length === 3 && process.argv[2] === '--self-test') {
    selfTestStage7ProviderEgressEvidence()
      .then((result) => {
        process.stdout.write(
          `stage-7 provider egress evidence self-test: PASS (${result.assertions} assertions, 0 external requests, 0 mutations)\n`,
        );
      })
      .catch((error) => {
        process.stderr.write(`${error?.code ?? 'E7_PROVIDER_EGRESS_SELF_TEST_FAILED'}\n`);
        process.exitCode = 1;
      });
  } else {
    process.stderr.write('E7_PROVIDER_EGRESS_ARGUMENT_SET_INVALID\n');
    process.exitCode = 1;
  }
}
