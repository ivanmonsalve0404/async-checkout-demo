/* global structuredClone */
import assert from 'node:assert/strict';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const RUN_ID = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT_SHA = /^[0-9a-f]{40}$/u;
const REQUIRED_RUNS = 3;
const expectedEnvironment = () => (process.env.CI === 'true' ? 'ENV-E6-CI' : 'ENV-E6-LOCAL');

const NAVIGATION_METRICS = {
  lcpMs: ['ms', 'LIGHTHOUSE_NAVIGATION'],
  cls: ['score', 'LIGHTHOUSE_NAVIGATION'],
  tbtMs: ['ms', 'LIGHTHOUSE_NAVIGATION'],
  fcpMs: ['ms', 'LIGHTHOUSE_NAVIGATION'],
  speedIndexMs: ['ms', 'LIGHTHOUSE_NAVIGATION'],
  transferredBytes: ['bytes', 'LIGHTHOUSE_NAVIGATION'],
  javascriptBytes: ['bytes', 'LIGHTHOUSE_NAVIGATION'],
  cssBytes: ['bytes', 'LIGHTHOUSE_NAVIGATION'],
  imageBytes: ['bytes', 'LIGHTHOUSE_NAVIGATION'],
  fontBytes: ['bytes', 'LIGHTHOUSE_NAVIGATION'],
  requestCount: ['count', 'LIGHTHOUSE_NAVIGATION'],
  performanceScore: ['ratio', 'LIGHTHOUSE_NAVIGATION'],
  accessibilityScore: ['ratio', 'LIGHTHOUSE_NAVIGATION'],
  bestPracticesScore: ['ratio', 'LIGHTHOUSE_NAVIGATION'],
  externalRequestCount: ['count', 'LIGHTHOUSE_NAVIGATION'],
};

const SUMMARY_METRICS = {
  transitionCls: ['score', 'LIGHTHOUSE_USER_FLOW_TRANSITION_DIAGNOSTIC'],
  cls: ['score', 'LIGHTHOUSE_USER_FLOW_STABLE_OBSERVATION'],
  tbtMs: ['ms', 'LIGHTHOUSE_USER_FLOW_TRANSITION'],
  transferredBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  javascriptBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  cssBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  imageBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  fontBytes: ['bytes', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  requestCount: ['count', 'BROWSER_RESOURCE_TIMING_AT_STABLE_SUMMARY'],
  performanceScore: ['ratio', 'LIGHTHOUSE_USER_FLOW_TRANSITION'],
  accessibilityScore: ['ratio', 'LIGHTHOUSE_USER_FLOW_SNAPSHOT'],
  bestPracticesScore: ['ratio', 'LIGHTHOUSE_USER_FLOW_SNAPSHOT'],
  externalRequestCount: ['count', 'BROWSER_RESOURCE_TIMING_AND_REQUEST_OBSERVER'],
};

const exact = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected);
const finiteNonNegative = (value) => Number.isFinite(value) && value >= 0;
const rounded = (value) => Number(value.toFixed(3));
const validSample = (value, unit) =>
  finiteNonNegative(value) &&
  (unit !== 'ratio' || value <= 1) &&
  (!['bytes', 'count'].includes(unit) || Number.isInteger(value));

const validDistribution = (distribution, [unit, source]) => {
  if (
    distribution?.unit !== unit ||
    distribution?.source !== source ||
    distribution?.dispersion?.method !== 'range' ||
    !Array.isArray(distribution?.samples) ||
    distribution.samples.length !== REQUIRED_RUNS ||
    !distribution.samples.every((value) => validSample(value, unit))
  ) {
    return false;
  }
  const ordered = [...distribution.samples].sort((left, right) => left - right);
  const minimum = rounded(ordered[0]);
  const maximum = rounded(ordered.at(-1));
  return (
    distribution.median === rounded(ordered[1]) &&
    distribution.dispersion.minimum === minimum &&
    distribution.dispersion.maximum === maximum &&
    distribution.dispersion.value === rounded(maximum - minimum)
  );
};

const validMetrics = (metrics, contract) =>
  exact(Object.keys(metrics ?? {}), Object.keys(contract)) &&
  Object.entries(contract).every(([name, descriptor]) =>
    validDistribution(metrics[name], descriptor),
  );

const validVersions = (versions) =>
  Array.isArray(versions) &&
  versions.length === 1 &&
  typeof versions[0] === 'string' &&
  /^[0-9]+(?:\.[0-9]+){1,3}$/u.test(versions[0]);

const validNavigationVisit = (visit, expectedVisit, budgets) =>
  visit?.status === 'PASS' &&
  visit.visit === expectedVisit &&
  visit.measuredRuns === REQUIRED_RUNS &&
  visit.warmupRuns === (expectedVisit === 'first' ? 0 : 1) &&
  visit.isolation ===
    (expectedVisit === 'first'
      ? 'FRESH_BROWSER_PROFILE_PER_RUN'
      : 'ONE_WARMUP_THEN_THREE_FRESH_BROWSERS_WITH_SHARED_PERSISTED_PROFILE') &&
  validVersions(visit.lighthouseVersions) &&
  validVersions(visit.browserVersions) &&
  validMetrics(visit.metrics, NAVIGATION_METRICS) &&
  visit.metrics.lcpMs.samples.every((value) => value < budgets.lcpMsMaximumExclusive) &&
  visit.metrics.cls.samples.every((value) => value < budgets.clsMaximumExclusive) &&
  visit.metrics.externalRequestCount.samples.every((value) => value === 0);

const validSummary = (summary, budgets) =>
  summary?.status === 'PASS' &&
  summary.route === '/products/product-demo-001/checkout' &&
  summary.mode === 'LIGHTHOUSE_USER_FLOW_TWO_TIMESPANS_PLUS_SNAPSHOT' &&
  summary.measuredRuns === REQUIRED_RUNS &&
  exact(summary.firstVisit, {
    applicable: true,
    measuredRuns: REQUIRED_RUNS,
    isolation: 'FRESH_REAL_CHECKOUT_JOURNEY_AND_BROWSER_PROFILE_PER_RUN',
  }) &&
  exact(summary.repeatVisit, {
    applicable: false,
    reason: 'REVIEW_USES_INTENTIONALLY_EPHEMERAL_IN_MEMORY_PAYMENT_SELECTION',
  }) &&
  exact(summary.unavailableNavigationMetrics, {
    lcpMs: 'NOT_AVAILABLE_FOR_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
    fcpMs: 'NOT_AVAILABLE_FOR_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
    speedIndexMs: 'NOT_AVAILABLE_FOR_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
  }) &&
  validVersions(summary.lighthouseVersions) &&
  validVersions(summary.browserVersions) &&
  validMetrics(summary.metrics, SUMMARY_METRICS) &&
  summary.metrics.cls.samples.every((value) => value < budgets.clsMaximumExclusive) &&
  summary.metrics.externalRequestCount.samples.every((value) => value === 0) &&
  summary.rawArtifacts === 'IN_MEMORY_ONLY_NOT_PERSISTED';

const validApiCounts = (counts) =>
  exact(Object.keys(counts ?? {}), [
    'product',
    'checkoutCreated',
    'reviewCheckout',
    'finalCheckout',
    'customerSaved',
    'deliverySaved',
    'paymentConfiguration',
    'transaction',
    'unknownApi',
  ]) &&
  Object.values(counts).every((value) => Number.isInteger(value) && value >= 0) &&
  counts.product >= 17 &&
  counts.checkoutCreated >= REQUIRED_RUNS &&
  counts.reviewCheckout >= REQUIRED_RUNS &&
  counts.finalCheckout >= 7 &&
  counts.customerSaved >= REQUIRED_RUNS &&
  counts.deliverySaved >= REQUIRED_RUNS &&
  counts.paymentConfiguration >= REQUIRED_RUNS &&
  counts.transaction >= 7 &&
  counts.unknownApi === 0;

const validLighthouse = (lighthouse, budgets) =>
  lighthouse?.status === 'PASS' &&
  lighthouse.tool?.name === 'Lighthouse + Lighthouse User Flows + Puppeteer' &&
  /^13\.4\.1 \+ [0-9]+\.[0-9]+\.[0-9]+$/u.test(lighthouse.tool?.version ?? '') &&
  exact(lighthouse.config, {
    path: 'scripts/stage6/perf/lighthouse.mobile.json',
    formFactor: 'mobile',
    viewport: '390x844',
    categories: ['performance', 'accessibility', 'best-practices'],
    requiredMeasuredRunsPerApplicableVisit: REQUIRED_RUNS,
  }) &&
  exact(lighthouse.assertions, {
    status: 'PASS',
    engine: 'EXCLUSIVE_LOCAL_ASSERTIONS_OVER_LIGHTHOUSE_RESULTS',
    lcpMsMaximumExclusive: budgets.lcpMsMaximumExclusive,
    clsMaximumExclusive: budgets.clsMaximumExclusive,
    summaryLcp: 'NOT_APPLICABLE_TO_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
  }) &&
  exact(Object.keys(lighthouse.views ?? {}), ['product', 'summary', 'final']) &&
  lighthouse.views.product?.status === 'PASS' &&
  lighthouse.views.product.route === '/products/product-demo-001' &&
  validNavigationVisit(lighthouse.views.product.firstVisit, 'first', budgets) &&
  validNavigationVisit(lighthouse.views.product.repeatVisit, 'repeat', budgets) &&
  validSummary(lighthouse.views.summary, budgets) &&
  lighthouse.views.final?.status === 'PASS' &&
  lighthouse.views.final.route === '/products/product-demo-001/checkout/status' &&
  lighthouse.views.final.fixture ===
    'CANONICAL_RECOVERY_IDS_INJECTED_BEFORE_DOCUMENT_LOOPBACK_ONLY' &&
  validNavigationVisit(lighthouse.views.final.firstVisit, 'first', budgets) &&
  validNavigationVisit(lighthouse.views.final.repeatVisit, 'repeat', budgets) &&
  exact(lighthouse.runAccounting, {
    navigationAudits: 14,
    measuredNavigationRuns: 12,
    navigationWarmupRuns: 2,
    summaryUserFlowRuns: 3,
    summaryFlowSteps: 9,
  }) &&
  validApiCounts(lighthouse.apiRequestCounts) &&
  lighthouse.secondaryMetricPolicy ===
    'THIS_STAGE_6_RESULT_FREEZES_THE_LOCAL_BASELINE; CHANGES_OVER_10_PERCENT_REQUIRE_JUSTIFICATION' &&
  lighthouse.fieldMetrics === 'NOT_RUN_FIELD_REQUIRED' &&
  lighthouse.externalNetworkPolicy === 'DENY_LOOPBACK_ONLY' &&
  lighthouse.rawArtifacts === 'IN_MEMORY_ONLY_NOT_PERSISTED';

const validBrowserLab = (lab, budgets) =>
  lab?.status === 'PASS_BROWSER_LAB_EQUIVALENT' &&
  finiteNonNegative(lab.durationMs) &&
  lab.durationMs > 0 &&
  lab.runtime === 'playwright-chromium' &&
  typeof lab.browserVersion === 'string' &&
  /^[0-9]+(?:\.[0-9]+){1,3}$/u.test(lab.browserVersion) &&
  lab.viewport === '1334x750' &&
  exact(Object.keys(lab.metrics ?? {}), [
    'lcpMs',
    'lcpTargetMs',
    'cls',
    'clsTarget',
    'navigationDurationMs',
    'syntheticInteractionMs',
    'inp',
  ]) &&
  finiteNonNegative(lab.metrics.lcpMs) &&
  lab.metrics.lcpMs > 0 &&
  lab.metrics.lcpMs < budgets.lcpMsMaximumExclusive &&
  lab.metrics.lcpTargetMs === budgets.lcpMsMaximumExclusive &&
  finiteNonNegative(lab.metrics.cls) &&
  lab.metrics.cls < budgets.clsMaximumExclusive &&
  lab.metrics.clsTarget === budgets.clsMaximumExclusive &&
  finiteNonNegative(lab.metrics.navigationDurationMs) &&
  finiteNonNegative(lab.metrics.syntheticInteractionMs) &&
  lab.metrics.inp === 'NOT_RUN_FIELD_REQUIRED' &&
  lab.mediaReservation?.status === 'PASS' &&
  Number(lab.mediaReservation.widthAttribute) === lab.mediaReservation.naturalWidth &&
  Number(lab.mediaReservation.heightAttribute) === lab.mediaReservation.naturalHeight &&
  lab.mediaReservation.naturalWidth > 0 &&
  lab.mediaReservation.naturalHeight > 0 &&
  lab.blockedExternalRequests === 0 &&
  lab.unknownApiRequests === 0;

export const validatePerformanceEvidence = (evidence) => {
  try {
    const budgets = evidence?.budgets;
    return (
      evidence?.schemaVersion === 1 &&
      evidence.stage === 6 &&
      evidence.status === 'PASS' &&
      evidence.command === 'node scripts/stage6/perf/run.mjs' &&
      evidence.tool?.name === 'Lighthouse + Playwright PerformanceObserver' &&
      evidence.tool?.version === '13.4.1 + 1.61.1' &&
      evidence.environment === expectedEnvironment() &&
      evidence.executionScope === 'LOCAL_SYNTHETIC_LOOPBACK_ONLY' &&
      evidence.networkPolicy === 'LOOPBACK_ONLY_DENY_EXTERNAL' &&
      evidence.containsSensitiveData === false &&
      RUN_ID.test(evidence.runId) &&
      COMMIT_SHA.test(evidence.commitSha) &&
      SHA256.test(evidence.scriptSha256) &&
      /^v24\.[0-9]+\.[0-9]+$/u.test(evidence.nodeVersion ?? '') &&
      !Number.isNaN(Date.parse(evidence.generatedAtUtc)) &&
      typeof evidence.branch === 'string' &&
      evidence.branch.length > 0 &&
      exact(budgets, {
        mainImageBytesMaximum: 120 * 1024,
        lcpMsMaximumExclusive: 2_500,
        clsMaximumExclusive: 0.1,
        inpMsMaximum: 200,
      }) &&
      evidence.assetCheck?.path === 'apps/web/public/product-placeholder.svg' &&
      evidence.assetCheck.status === 'PASS' &&
      evidence.assetCheck.budgetBytes === budgets.mainImageBytesMaximum &&
      Number.isInteger(evidence.assetCheck.bytes) &&
      evidence.assetCheck.bytes > 0 &&
      evidence.assetCheck.bytes <= evidence.assetCheck.budgetBytes &&
      validBrowserLab(evidence.browserLab, budgets) &&
      validLighthouse(evidence.lighthouse, budgets) &&
      exact(evidence.fieldVitals, {
        lcpP75: 'NOT_RUN_FIELD_REQUIRED',
        clsP75: 'NOT_RUN_FIELD_REQUIRED',
        inpP75: 'NOT_RUN_FIELD_REQUIRED',
      }) &&
      evidence.declaration === 'LOCAL_LAB_ONLY_NOT_FIELD_PERFORMANCE' &&
      evidence.sanitizedHtml?.path === 'output/evidence/runtime/stage-6/performance-report.html' &&
      SHA256.test(evidence.sanitizedHtml.sha256) &&
      evidence.sanitizedHtml.containsSensitiveData === false &&
      evidence.sanitizedHtml.rawArtifactsPersisted === false
    );
  } catch {
    return false;
  }
};

const distributionFixture = ([unit, source], value = 1) => ({
  unit,
  source,
  median: value,
  dispersion: { method: 'range', minimum: value, maximum: value, value: 0 },
  samples: [value, value, value],
});

const metricFixture = (contract) =>
  Object.fromEntries(
    Object.entries(contract).map(([name, descriptor]) => [
      name,
      distributionFixture(descriptor, name === 'externalRequestCount' ? 0 : 1),
    ]),
  );

const navigationFixture = (visit) => {
  const metrics = metricFixture(NAVIGATION_METRICS);
  metrics.cls = distributionFixture(NAVIGATION_METRICS.cls, 0);
  return {
    status: 'PASS',
    visit,
    measuredRuns: 3,
    warmupRuns: visit === 'first' ? 0 : 1,
    isolation:
      visit === 'first'
        ? 'FRESH_BROWSER_PROFILE_PER_RUN'
        : 'ONE_WARMUP_THEN_THREE_FRESH_BROWSERS_WITH_SHARED_PERSISTED_PROFILE',
    lighthouseVersions: ['13.4.1'],
    browserVersions: ['149.0.0.0'],
    metrics,
  };
};

const validFixture = () => {
  const budgets = {
    mainImageBytesMaximum: 122_880,
    lcpMsMaximumExclusive: 2_500,
    clsMaximumExclusive: 0.1,
    inpMsMaximum: 200,
  };
  const summaryMetrics = metricFixture(SUMMARY_METRICS);
  summaryMetrics.cls = distributionFixture(SUMMARY_METRICS.cls, 0);
  return {
    schemaVersion: 1,
    stage: 6,
    generatedAtUtc: '2026-08-16T12:00:00.000Z',
    commitSha: 'a'.repeat(40),
    runId: 'e6-20260816t120000z-0123abcd',
    command: 'node scripts/stage6/perf/run.mjs',
    tool: { name: 'Lighthouse + Playwright PerformanceObserver', version: '13.4.1 + 1.61.1' },
    environment: expectedEnvironment(),
    executionScope: 'LOCAL_SYNTHETIC_LOOPBACK_ONLY',
    branch: 'codex/stage-6-integration-verification',
    nodeVersion: 'v24.19.0',
    scriptSha256: 'b'.repeat(64),
    networkPolicy: 'LOOPBACK_ONLY_DENY_EXTERNAL',
    containsSensitiveData: false,
    status: 'PASS',
    budgets,
    assetCheck: {
      path: 'apps/web/public/product-placeholder.svg',
      bytes: 639,
      budgetBytes: 122_880,
      status: 'PASS',
    },
    browserLab: {
      status: 'PASS_BROWSER_LAB_EQUIVALENT',
      durationMs: 1,
      runtime: 'playwright-chromium',
      browserVersion: '149.0.0.0',
      viewport: '1334x750',
      metrics: {
        lcpMs: 1,
        lcpTargetMs: 2_500,
        cls: 0,
        clsTarget: 0.1,
        navigationDurationMs: 1,
        syntheticInteractionMs: 1,
        inp: 'NOT_RUN_FIELD_REQUIRED',
      },
      mediaReservation: {
        widthAttribute: '800',
        heightAttribute: '600',
        naturalWidth: 800,
        naturalHeight: 600,
        status: 'PASS',
      },
      blockedExternalRequests: 0,
      unknownApiRequests: 0,
    },
    lighthouse: {
      status: 'PASS',
      tool: {
        name: 'Lighthouse + Lighthouse User Flows + Puppeteer',
        version: '13.4.1 + 25.7.0',
      },
      config: {
        path: 'scripts/stage6/perf/lighthouse.mobile.json',
        formFactor: 'mobile',
        viewport: '390x844',
        categories: ['performance', 'accessibility', 'best-practices'],
        requiredMeasuredRunsPerApplicableVisit: 3,
      },
      assertions: {
        status: 'PASS',
        engine: 'EXCLUSIVE_LOCAL_ASSERTIONS_OVER_LIGHTHOUSE_RESULTS',
        lcpMsMaximumExclusive: 2_500,
        clsMaximumExclusive: 0.1,
        summaryLcp: 'NOT_APPLICABLE_TO_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
      },
      views: {
        product: {
          status: 'PASS',
          route: '/products/product-demo-001',
          firstVisit: navigationFixture('first'),
          repeatVisit: navigationFixture('repeat'),
        },
        summary: {
          status: 'PASS',
          route: '/products/product-demo-001/checkout',
          mode: 'LIGHTHOUSE_USER_FLOW_TWO_TIMESPANS_PLUS_SNAPSHOT',
          measuredRuns: 3,
          firstVisit: {
            applicable: true,
            measuredRuns: 3,
            isolation: 'FRESH_REAL_CHECKOUT_JOURNEY_AND_BROWSER_PROFILE_PER_RUN',
          },
          repeatVisit: {
            applicable: false,
            reason: 'REVIEW_USES_INTENTIONALLY_EPHEMERAL_IN_MEMORY_PAYMENT_SELECTION',
          },
          unavailableNavigationMetrics: {
            lcpMs: 'NOT_AVAILABLE_FOR_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
            fcpMs: 'NOT_AVAILABLE_FOR_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
            speedIndexMs: 'NOT_AVAILABLE_FOR_USER_FLOW_TIMESPAN_OR_SNAPSHOT',
          },
          lighthouseVersions: ['13.4.1'],
          browserVersions: ['149.0.0.0'],
          metrics: summaryMetrics,
          rawArtifacts: 'IN_MEMORY_ONLY_NOT_PERSISTED',
        },
        final: {
          status: 'PASS',
          route: '/products/product-demo-001/checkout/status',
          fixture: 'CANONICAL_RECOVERY_IDS_INJECTED_BEFORE_DOCUMENT_LOOPBACK_ONLY',
          firstVisit: navigationFixture('first'),
          repeatVisit: navigationFixture('repeat'),
        },
      },
      runAccounting: {
        navigationAudits: 14,
        measuredNavigationRuns: 12,
        navigationWarmupRuns: 2,
        summaryUserFlowRuns: 3,
        summaryFlowSteps: 9,
      },
      apiRequestCounts: {
        product: 17,
        checkoutCreated: 3,
        reviewCheckout: 3,
        finalCheckout: 7,
        customerSaved: 3,
        deliverySaved: 3,
        paymentConfiguration: 3,
        transaction: 7,
        unknownApi: 0,
      },
      secondaryMetricPolicy:
        'THIS_STAGE_6_RESULT_FREEZES_THE_LOCAL_BASELINE; CHANGES_OVER_10_PERCENT_REQUIRE_JUSTIFICATION',
      fieldMetrics: 'NOT_RUN_FIELD_REQUIRED',
      externalNetworkPolicy: 'DENY_LOOPBACK_ONLY',
      rawArtifacts: 'IN_MEMORY_ONLY_NOT_PERSISTED',
    },
    fieldVitals: {
      lcpP75: 'NOT_RUN_FIELD_REQUIRED',
      clsP75: 'NOT_RUN_FIELD_REQUIRED',
      inpP75: 'NOT_RUN_FIELD_REQUIRED',
    },
    declaration: 'LOCAL_LAB_ONLY_NOT_FIELD_PERFORMANCE',
    sanitizedHtml: {
      path: 'output/evidence/runtime/stage-6/performance-report.html',
      sha256: 'c'.repeat(64),
      containsSensitiveData: false,
      rawArtifactsPersisted: false,
    },
  };
};

export const selfTestPerformanceEvidence = () => {
  const valid = validFixture();
  assert.equal(validatePerformanceEvidence(valid), true);

  const passFake = structuredClone(valid);
  passFake.status = 'PASS_FAKE';
  assert.equal(validatePerformanceEvidence(passFake), false);

  const missingMetric = structuredClone(valid);
  delete missingMetric.lighthouse.views.product.firstVisit.metrics.lcpMs;
  assert.equal(validatePerformanceEvidence(missingMetric), false);

  const forgedMedian = structuredClone(valid);
  forgedMedian.lighthouse.views.final.repeatVisit.metrics.lcpMs.median = 2;
  assert.equal(validatePerformanceEvidence(forgedMedian), false);

  const inconsistentRoundedRange = structuredClone(valid);
  inconsistentRoundedRange.lighthouse.views.product.firstVisit.metrics.lcpMs = {
    unit: 'ms',
    source: 'LIGHTHOUSE_NAVIGATION',
    median: 1975.928,
    dispersion: { method: 'range', minimum: 1971.32, maximum: 1985.954, value: 14.633 },
    samples: [1975.928, 1985.954, 1971.32],
  };
  assert.equal(validatePerformanceEvidence(inconsistentRoundedRange), false);

  inconsistentRoundedRange.lighthouse.views.product.firstVisit.metrics.lcpMs.dispersion.value = 14.634;
  assert.equal(validatePerformanceEvidence(inconsistentRoundedRange), true);

  const externalRequest = structuredClone(valid);
  externalRequest.lighthouse.views.summary.metrics.externalRequestCount.samples[0] = 1;
  assert.equal(validatePerformanceEvidence(externalRequest), false);

  const rawPersisted = structuredClone(valid);
  rawPersisted.sanitizedHtml.rawArtifactsPersisted = true;
  assert.equal(validatePerformanceEvidence(rawPersisted), false);
};

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  selfTestPerformanceEvidence();
  process.stdout.write('stage-6 performance evidence validator self-test: PASS\n');
}
