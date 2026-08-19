/* global structuredClone */

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import { canonicalJson, objectSha256 } from './core.mjs';

import {
  STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
  STAGE7_RELEASE_RECONCILIATION_CONTRACT,
  STAGE7_RELEASE_RECONCILIATION_FILES,
  STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT,
  classifyReleasePublicationState,
  classifyReleaseRollbackJournalAccess,
  createReleasePreFenceGate,
  createReleaseReconciliationIntent,
  createReleaseReconciliationJournalAuthority,
  createReleaseReconciliationReceipt,
  createReleaseRollbackJournalOwner,
  validateReleasePreFenceGate,
  validateReleaseReconciliationIntent,
  validateReleaseReconciliationJournalAuthority,
  validateReleasePublicationClassification,
  validateReleaseReconciliationReceipt,
  validateReleaseReconciliationSmokeAuthorizationUsage,
  validateReleaseReconciliationSource,
  validateReleaseRollbackJournalOwner,
} from './release-reconciliation.mjs';

const source = {
  repository: 'ivanmonsalve0404/async-checkout-demo',
  workflowPath: '.github/workflows/release.yml',
  ref: 'refs/heads/master',
  runId: '123456789',
  runAttempt: 1,
  candidateSha: 'a'.repeat(40),
  releaseId: 'rel-20260818-1200-aaaaaaa',
  releaseTag: 'v1.0.0',
  configSha256: '1'.repeat(64),
};
const digests = {
  state: '3'.repeat(64),
  readbackRaw: '4'.repeat(64),
  readbackCanonical: '5'.repeat(64),
  drift: '6'.repeat(64),
  smoke: '7'.repeat(64),
  scan: '8'.repeat(64),
  terminal: '9'.repeat(64),
  plan: 'b'.repeat(64),
  notes: 'c'.repeat(64),
  asset: 'd'.repeat(64),
  driftRaw: 'e'.repeat(64),
  smokeRaw: 'f'.repeat(64),
};
const intentBindings = STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.map((descriptor, index) => ({
  ...descriptor,
  rawSha256:
    descriptor.sourceType === 'NESTED_JSON' ? null : (index + 1).toString(16).padStart(64, '0'),
  canonicalSha256:
    descriptor.sourceType === 'RAW_TEXT' ? null : (index + 101).toString(16).padStart(64, '0'),
  bytes: 100 + index,
}));
const intent = createReleaseReconciliationIntent({
  source,
  authority: {
    accountId: '123456789012',
    region: 'us-east-1',
    rollbackRoleArn: 'arn:aws:iam::123456789012:role/checkout-rollback',
    journalRoleArn: 'arn:aws:iam::123456789012:role/stage7-release-journal-cleanup',
    rollbackPermissionSetSha256: '2'.repeat(64),
    journalEffectivePermissionsSha256: 'a'.repeat(64),
  },
  bindings: intentBindings,
});
const intentChunkBindings = (sourceValue, intentValue) => {
  const text = canonicalJson(intentValue);
  const values = [];
  let current = '';
  for (const character of text) {
    if (Buffer.byteLength(current + character, 'utf8') > 3000) {
      values.push(current);
      current = character;
    } else current += character;
  }
  if (current !== '') values.push(current);
  return values.map((value, index) => ({
    index: index + 1,
    parameterName: `/checkout/stage7/rollback/${sourceValue.candidateSha}/release-reconciliation/${sourceValue.runId}/intent/${String(index + 1).padStart(4, '0')}`,
    rawSha256: createHash('sha256').update(value).digest('hex'),
    bytes: Buffer.byteLength(value, 'utf8'),
  }));
};
const owner = createReleaseRollbackJournalOwner({
  source,
  intent,
  intentRawSha256: createHash('sha256').update(canonicalJson(intent)).digest('hex'),
  intentBytes: Buffer.byteLength(canonicalJson(intent), 'utf8'),
  intentChunks: intentChunkBindings(source, intent),
  createdAtUtc: '2026-08-18T12:00:00.000Z',
});
const runtimeProofFixture = ({
  ownerValue,
  phase,
  proofKind,
  rawSha256,
  canonicalSha256,
  observedAtUtc,
}) => {
  const root = `${ownerValue.runtimeProofRootPrefix}/${phase === 'ROLLBACK_CHECK' ? 'rollback-check' : 'rollback-resilience'}/${proofKind.toLowerCase()}/${rawSha256}`;
  const chunkRawSha256 = createHash('sha256').update(`${phase}\0${proofKind}\0chunk`).digest('hex');
  const indexSha256 = createHash('sha256').update(`${phase}\0${proofKind}\0index`).digest('hex');
  return {
    reference: {
      indexParameterName: `${root}/index`,
      indexSha256,
      rawSha256,
      canonicalSha256,
      bytes: 200,
      observedAtUtc,
      chunkCount: 1,
      chunksSha256: createHash('sha256').update(`${phase}\0${proofKind}\0chunks`).digest('hex'),
    },
    parameters: [
      { name: `${root}/index`, rawSha256: indexSha256, bytes: 300, version: 1 },
      {
        name: `${root}/chunk/0001-${chunkRawSha256}`,
        rawSha256: chunkRawSha256,
        bytes: 200,
        version: 1,
      },
    ],
  };
};
const smokeAuthorizationUsage = (phase, sourceValue = source) => ({
  schemaVersion: 1,
  phase,
  usageId:
    phase === 'ROLLBACK_CHECK'
      ? 'RECONCILIATION_ROLLBACK_CHECK_SMOKE'
      : 'RECONCILIATION_ROLLBACK_RESILIENCE_SMOKE',
  authorizationSha256: '0'.repeat(64),
  bundleSha256: '0'.repeat(64),
  configSha256: sourceValue.configSha256,
  candidateSha: sourceValue.candidateSha,
  releaseId: sourceValue.releaseId,
  ownedOriginSha256: 'a'.repeat(64),
  sandboxHostSha256: 'b'.repeat(64),
  requestCounts: {
    'AUTH-E7-EXT-01': 3,
    'AUTH-E7-EXT-02': 0,
    'AUTH-E7-EXT-03': 0,
  },
  total: 3,
  passed: 3,
  failed: 0,
  containsSensitiveData: false,
});
const receipt = ({
  phase,
  originalJobConclusion = 'SUCCESS',
  recoveryAction = 'VERIFIED_NOOP',
  sourceValue = source,
  ownerValue = owner,
  intentValue = intent,
  startedAtUtc,
  observedAtUtc,
  convergenceCompletedAtUtc = observedAtUtc,
  driftObservedAtUtc = observedAtUtc,
  smokeObservedAtUtc = observedAtUtc,
  completedAtUtc,
  observedStateSha256 = digests.state,
}) => {
  const driftProof = runtimeProofFixture({
    ownerValue,
    phase,
    proofKind: 'DRIFT',
    rawSha256: digests.driftRaw,
    canonicalSha256: digests.drift,
    observedAtUtc: driftObservedAtUtc,
  });
  const smokeProof = runtimeProofFixture({
    ownerValue,
    phase,
    proofKind: 'SMOKE',
    rawSha256: digests.smokeRaw,
    canonicalSha256: digests.smoke,
    observedAtUtc: smokeObservedAtUtc,
  });
  const runtimeProofParameters = [...driftProof.parameters, ...smokeProof.parameters].toSorted(
    (left, right) => left.name.localeCompare(right.name),
  );
  return createReleaseReconciliationReceipt({
    phase,
    source: sourceValue,
    owner: ownerValue,
    intent: intentValue,
    originalJobConclusion,
    recoveryAction,
    expectedStateSha256: digests.state,
    observedStateSha256,
    readbackRawSha256: digests.readbackRaw,
    readbackCanonicalSha256: digests.readbackCanonical,
    driftProofSha256: digests.drift,
    smokeProofSha256: digests.smoke,
    smokeAuthorizationUsage: smokeAuthorizationUsage(phase, sourceValue),
    driftProofJournal: driftProof.reference,
    smokeProofJournal: smokeProof.reference,
    runtimeProofParameters,
    runtimeProofParameterCount: runtimeProofParameters.length,
    runtimeProofParametersSha256: objectSha256(runtimeProofParameters),
    journalScanSha256: digests.scan,
    terminalStateSha256: digests.terminal,
    startedAtUtc,
    convergenceCompletedAtUtc,
    driftObservedAtUtc,
    smokeObservedAtUtc,
    observedAtUtc,
    completedAtUtc,
  });
};
const rollbackCheck = receipt({
  phase: 'ROLLBACK_CHECK',
  startedAtUtc: '2026-08-18T12:01:00.000Z',
  observedAtUtc: '2026-08-18T12:02:00.000Z',
  completedAtUtc: '2026-08-18T12:03:00.000Z',
});
const rollbackResilience = receipt({
  phase: 'ROLLBACK_RESILIENCE',
  startedAtUtc: '2026-08-18T12:04:00.000Z',
  observedAtUtc: '2026-08-18T12:05:00.000Z',
  completedAtUtc: '2026-08-18T12:06:00.000Z',
});
const encode = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
const checkSource = encode(rollbackCheck);
const resilienceSource = encode(rollbackResilience);
const canaryIds = [];
const canary = (id, assertion) => {
  assertion();
  canaryIds.push(id);
};
const throwsCode = (code, assertion) => assert.throws(assertion, (error) => error?.code === code);

canary('OWNER_INTENT_IS_APPEND_ONLY_AND_HASH_BOUND', () => {
  assert.equal(validateReleaseRollbackJournalOwner(owner), owner);
  assert.equal(owner.writeMode, 'SSM_PUT_PARAMETER_OVERWRITE_FALSE');
  const tampered = { ...owner, intentBindingsSha256: 'f'.repeat(64) };
  throwsCode('E7_RELEASE_RECONCILIATION_JOURNAL_OWNER_INVALID', () =>
    validateReleaseRollbackJournalOwner(tampered),
  );
});

canary('INTENT_LAYOUT_HAS_EXACT_23_PRE_MUTATION_BINDINGS', () => {
  assert.equal(STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.length, 23);
  assert.equal(validateReleaseReconciliationIntent(intent), intent);
  assert.equal(intent.bindings.at(-1).label, 'previousReleaseProjectionIndex');
  assert.equal(
    intent.bindings.some(({ label }) => label === 'journalRoleEffectivePermissions'),
    true,
  );
});

canary('INTENT_SWAP_OR_TAMPER_IS_REJECTED', () => {
  const swapped = structuredClone(intent);
  [swapped.bindings[0], swapped.bindings[1]] = [swapped.bindings[1], swapped.bindings[0]];
  throwsCode('E7_RELEASE_RECONCILIATION_INTENT_INVALID', () =>
    validateReleaseReconciliationIntent(swapped),
  );
});

canary('EMPTY_JOURNAL_ALLOWS_ONE_NEW_INTENT', () => {
  const access = classifyReleaseRollbackJournalAccess({ source, journalEntryCount: 0 });
  assert.equal(access.decision, 'ALLOW_NEW_INTENT');
  assert.equal(access.mutationAllowed, true);
});

canary('SAME_RUN_ATTEMPT_ONE_CAN_RESUME', () => {
  const access = classifyReleaseRollbackJournalAccess({ source, owner, journalEntryCount: 17 });
  assert.equal(access.decision, 'RESUME_SAME_RUN');
  assert.equal(access.mutationAllowed, true);
});

canary('NEW_DISPATCH_CANNOT_CROSS_AN_OPEN_JOURNAL', () => {
  const nextRun = { ...source, runId: '123456790' };
  const access = classifyReleaseRollbackJournalAccess({
    source: nextRun,
    owner,
    journalEntryCount: 17,
  });
  assert.equal(access.decision, 'BLOCK_DIFFERENT_RUN');
  assert.equal(access.mutationAllowed, false);
});

canary('NATIVE_RERUN_ATTEMPT_TWO_IS_REJECTED', () => {
  throwsCode('E7_RELEASE_RECONCILIATION_SOURCE_INVALID', () =>
    validateReleaseReconciliationSource({ ...source, runAttempt: 2 }),
  );
});

canary('UNOWNED_PARTIAL_JOURNAL_IS_BLOCKED', () => {
  const access = classifyReleaseRollbackJournalAccess({ source, journalEntryCount: 1 });
  assert.equal(access.decision, 'BLOCK_UNOWNED_JOURNAL');
  assert.equal(access.mutationAllowed, false);
});

canary('ROLLBACK_CHECK_TERMINAL_N_RECEIPT_IS_EXACT', () => {
  assert.equal(validateReleaseReconciliationReceipt(rollbackCheck), rollbackCheck);
  assert.equal(rollbackCheck.eligibleForFence, true);
  assert.deepEqual(rollbackCheck.runtime.mixedComponents, []);
  assert.deepEqual(rollbackCheck.runtime.pendingMutations, []);
});

canary('ROLLBACK_RESILIENCE_TERMINAL_N_RECEIPT_IS_EXACT', () => {
  assert.equal(validateReleaseReconciliationReceipt(rollbackResilience), rollbackResilience);
  assert.equal(rollbackResilience.eligibleForFence, true);
});

canary('SMOKE_AUTHORIZATION_USAGE_TAMPER_IS_REJECTED_AFTER_REHASH', () => {
  assert.equal(
    validateReleaseReconciliationSmokeAuthorizationUsage(
      rollbackCheck.runtime.smokeAuthorizationUsage,
      { phase: 'ROLLBACK_CHECK', source },
    ),
    rollbackCheck.runtime.smokeAuthorizationUsage,
  );
  const tampered = structuredClone(rollbackCheck);
  tampered.runtime.smokeAuthorizationUsage.requestCounts['AUTH-E7-EXT-01'] = 2;
  delete tampered.receiptSha256;
  tampered.receiptSha256 = objectSha256(tampered);
  throwsCode('E7_RELEASE_RECONCILIATION_SMOKE_AUTHORIZATION_USAGE_INVALID', () =>
    validateReleaseReconciliationReceipt(tampered),
  );
});

canary('REHASHED_RECEIPT_CANNOT_MOVE_CONVERGENCE_AFTER_FRESH_PROOFS', () => {
  const tampered = structuredClone(rollbackCheck);
  tampered.runtime.convergenceCompletedAtUtc = '2026-08-18T12:02:00.001Z';
  delete tampered.receiptSha256;
  tampered.receiptSha256 = objectSha256(tampered);
  throwsCode('E7_RELEASE_RECONCILIATION_RUNTIME_NOT_TERMINAL_N', () =>
    validateReleaseReconciliationReceipt(tampered),
  );
});

const recoveredAfterFailure = receipt({
  phase: 'ROLLBACK_CHECK',
  originalJobConclusion: 'FAILURE',
  recoveryAction: 'REPROMOTED_CANDIDATE',
  startedAtUtc: '2026-08-18T12:01:00.000Z',
  observedAtUtc: '2026-08-18T12:02:00.000Z',
  completedAtUtc: '2026-08-18T12:03:00.000Z',
});

canary('CRASH_AFTER_N_MINUS_ONE_RECOVERS_N_BUT_BLOCKS_FENCE', () => {
  assert.equal(recoveredAfterFailure.status, 'TERMINAL_CANDIDATE_N_VERIFIED');
  assert.equal(recoveredAfterFailure.eligibleForFence, false);
  throwsCode('E7_RELEASE_RECONCILIATION_PRE_FENCE_NOT_ELIGIBLE', () =>
    createReleasePreFenceGate({
      rollbackCheckSource: encode(recoveredAfterFailure),
      rollbackResilienceSource: resilienceSource,
      evaluatedAtUtc: '2026-08-18T12:07:00.000Z',
    }),
  );
});

canary('REUSABLE_CRASH_BEFORE_ARTIFACT_CANNOT_REACH_GATE', () => {
  throwsCode('E7_RELEASE_RECONCILIATION_RECEIPT_DOCUMENT_INVALID', () =>
    createReleasePreFenceGate({
      rollbackCheckSource: checkSource,
      rollbackResilienceSource: Buffer.alloc(0),
      evaluatedAtUtc: '2026-08-18T12:07:00.000Z',
    }),
  );
});

canary('REUSABLE_RECOVERY_TO_N_STILL_BLOCKS_RELEASE', () => {
  const recoveredResilience = receipt({
    phase: 'ROLLBACK_RESILIENCE',
    originalJobConclusion: 'FAILURE',
    recoveryAction: 'REPROMOTED_CANDIDATE',
    startedAtUtc: '2026-08-18T12:04:00.000Z',
    observedAtUtc: '2026-08-18T12:05:00.000Z',
    completedAtUtc: '2026-08-18T12:06:00.000Z',
  });
  assert.equal(recoveredResilience.eligibleForFence, false);
  throwsCode('E7_RELEASE_RECONCILIATION_PRE_FENCE_NOT_ELIGIBLE', () =>
    createReleasePreFenceGate({
      rollbackCheckSource: checkSource,
      rollbackResilienceSource: encode(recoveredResilience),
      evaluatedAtUtc: '2026-08-18T12:07:00.000Z',
    }),
  );
});

canary('UNEXPECTED_RECOVERY_AFTER_SUCCESS_STILL_BLOCKS_FENCE', () => {
  const suspiciousRecovery = receipt({
    phase: 'ROLLBACK_CHECK',
    originalJobConclusion: 'SUCCESS',
    recoveryAction: 'REPROMOTED_CANDIDATE',
    startedAtUtc: '2026-08-18T12:01:00.000Z',
    observedAtUtc: '2026-08-18T12:02:00.000Z',
    completedAtUtc: '2026-08-18T12:03:00.000Z',
  });
  assert.equal(suspiciousRecovery.eligibleForFence, false);
});

canary('MIXED_ALIAS_READBACK_CANNOT_FORM_A_RECEIPT', () => {
  throwsCode('E7_RELEASE_RECONCILIATION_RECEIPT_INPUT_INVALID', () =>
    receipt({
      phase: 'ROLLBACK_CHECK',
      originalJobConclusion: 'FAILURE',
      recoveryAction: 'REPROMOTED_CANDIDATE',
      observedStateSha256: 'e'.repeat(64),
      startedAtUtc: '2026-08-18T12:01:00.000Z',
      convergenceCompletedAtUtc: '2026-08-18T12:01:30.000Z',
      driftObservedAtUtc: '2026-08-18T12:01:45.000Z',
      smokeObservedAtUtc: '2026-08-18T12:02:00.000Z',
      observedAtUtc: '2026-08-18T12:02:00.000Z',
      completedAtUtc: '2026-08-18T12:03:00.000Z',
    }),
  );
});

canary('UNRESOLVED_JOURNAL_ENTRY_INVALIDATES_RECEIPT', () => {
  const tampered = {
    ...rollbackCheck,
    journal: { ...rollbackCheck.journal, unresolvedEntryNames: ['RB-E7-06/000001'] },
  };
  throwsCode('E7_RELEASE_RECONCILIATION_RECEIPT_INVALID', () =>
    validateReleaseReconciliationReceipt(tampered),
  );
});

const gate = createReleasePreFenceGate({
  rollbackCheckSource: checkSource,
  rollbackResilienceSource: resilienceSource,
  evaluatedAtUtc: '2026-08-18T12:07:00.000Z',
});

canary('PRE_FENCE_GATE_BINDS_BOTH_RAW_RECEIPTS', () => {
  assert.equal(
    validateReleasePreFenceGate(gate, {
      rollbackCheckSource: checkSource,
      rollbackResilienceSource: resilienceSource,
    }),
    gate,
  );
  assert.equal(gate.status, 'ALLOW_FENCE');
  assert.equal(gate.receiptBindings.rollbackCheck.bytes, checkSource.length);
  assert.equal(gate.receiptBindings.rollbackResilience.bytes, resilienceSource.length);
  assert.equal(gate.intentIndex.bindings.length, 23);
  const authority = createReleaseReconciliationJournalAuthority({
    rollbackCheckReceipt: rollbackCheck,
    rollbackResilienceReceipt: rollbackResilience,
  });
  assert.equal(
    validateReleaseReconciliationJournalAuthority(authority, {
      rollbackCheckReceipt: rollbackCheck,
      rollbackResilienceReceipt: rollbackResilience,
    }),
    authority,
  );
  assert.deepEqual(gate.reconciliationJournalAuthority, authority);
  assert.deepEqual(gate.smokeAuthorizationUsages, authority.smokeAuthorizationUsages);
  assert.deepEqual(
    authority.smokeAuthorizationUsages.map(({ phase, usageId, total, passed, failed }) => ({
      phase,
      usageId,
      total,
      passed,
      failed,
    })),
    [
      {
        phase: 'ROLLBACK_CHECK',
        usageId: 'RECONCILIATION_ROLLBACK_CHECK_SMOKE',
        total: 3,
        passed: 3,
        failed: 0,
      },
      {
        phase: 'ROLLBACK_RESILIENCE',
        usageId: 'RECONCILIATION_ROLLBACK_RESILIENCE_SMOKE',
        total: 3,
        passed: 3,
        failed: 0,
      },
    ],
  );
  const proofNames = [rollbackCheck, rollbackResilience]
    .flatMap((receiptValue) => receiptValue.journal.runtimeProofParameters)
    .map(({ name }) => name);
  const expectedCleanupNames = [
    owner.parameterName,
    ...owner.intentChunks.map(({ parameterName }) => parameterName),
    ...new Set(proofNames),
    rollbackCheck.journal.terminalParameterName,
    rollbackResilience.journal.terminalParameterName,
  ];
  assert.equal(authority.cleanupParameterCount, expectedCleanupNames.length);
  assert.deepEqual(authority.cleanupParameterNames, expectedCleanupNames);
  assert.equal(authority.runtimeProofParameters.length, new Set(proofNames).size);
  assert.equal(authority.requiredResidualCount, 0);
});

canary('SWAPPED_SMOKE_AUTHORIZATION_USAGES_CANNOT_SATISFY_AUTHORITY', () => {
  const swapped = structuredClone(gate.reconciliationJournalAuthority);
  swapped.smokeAuthorizationUsages.reverse();
  delete swapped.journalAuthoritySha256;
  swapped.journalAuthoritySha256 = objectSha256(swapped);
  throwsCode('E7_RELEASE_RECONCILIATION_JOURNAL_AUTHORITY_INVALID', () =>
    validateReleaseReconciliationJournalAuthority(swapped, {
      rollbackCheckReceipt: rollbackCheck,
      rollbackResilienceReceipt: rollbackResilience,
    }),
  );
});

canary('DUPLICATE_SMOKE_AUTHORIZATION_USAGE_CANNOT_SATISFY_GATE', () => {
  const duplicate = structuredClone(gate);
  duplicate.smokeAuthorizationUsages[1] = structuredClone(duplicate.smokeAuthorizationUsages[0]);
  delete duplicate.gateSha256;
  duplicate.gateSha256 = objectSha256(duplicate);
  throwsCode('E7_RELEASE_RECONCILIATION_PRE_FENCE_GATE_INVALID', () =>
    validateReleasePreFenceGate(duplicate, {
      rollbackCheckSource: checkSource,
      rollbackResilienceSource: resilienceSource,
    }),
  );
});

canary('SWAPPED_RECEIPTS_CANNOT_SATISFY_GATE', () => {
  throwsCode('E7_RELEASE_RECONCILIATION_RECEIPT_PHASE_MISMATCH', () =>
    createReleasePreFenceGate({
      rollbackCheckSource: resilienceSource,
      rollbackResilienceSource: checkSource,
      evaluatedAtUtc: '2026-08-18T12:07:00.000Z',
    }),
  );
});

canary('GATE_HASH_TAMPER_IS_REJECTED', () => {
  throwsCode('E7_RELEASE_RECONCILIATION_PRE_FENCE_GATE_INVALID', () =>
    validateReleasePreFenceGate(
      { ...gate, gateSha256: 'f'.repeat(64) },
      {
        rollbackCheckSource: checkSource,
        rollbackResilienceSource: resilienceSource,
      },
    ),
  );
});

canary('CROSS_RUN_RECEIPTS_CANNOT_SATISFY_GATE', () => {
  const otherSource = { ...source, runId: '123456790' };
  const otherIntent = createReleaseReconciliationIntent({
    source: otherSource,
    authority: intent.authority,
    bindings: intent.bindings,
  });
  const otherOwner = createReleaseRollbackJournalOwner({
    source: otherSource,
    intent: otherIntent,
    intentRawSha256: createHash('sha256').update(canonicalJson(otherIntent)).digest('hex'),
    intentBytes: Buffer.byteLength(canonicalJson(otherIntent), 'utf8'),
    intentChunks: intentChunkBindings(otherSource, otherIntent),
    createdAtUtc: '2026-08-18T12:00:00.000Z',
  });
  const otherResilience = receipt({
    phase: 'ROLLBACK_RESILIENCE',
    sourceValue: otherSource,
    ownerValue: otherOwner,
    intentValue: otherIntent,
    startedAtUtc: '2026-08-18T12:04:00.000Z',
    observedAtUtc: '2026-08-18T12:05:00.000Z',
    completedAtUtc: '2026-08-18T12:06:00.000Z',
  });
  throwsCode('E7_RELEASE_RECONCILIATION_PRE_FENCE_NOT_ELIGIBLE', () =>
    createReleasePreFenceGate({
      rollbackCheckSource: checkSource,
      rollbackResilienceSource: encode(otherResilience),
      evaluatedAtUtc: '2026-08-18T12:07:00.000Z',
    }),
  );
});

canary('RECONCILIATION_ARTIFACT_SET_AND_COUNTS_ARE_STATIC', () => {
  assert.equal(STAGE7_RELEASE_RECONCILIATION_ARTIFACT, 'stage7-release-reconciliation');
  assert.deepEqual(STAGE7_RELEASE_RECONCILIATION_FILES, [
    'rollback-check-reconciliation.json',
    'rollback-resilience-reconciliation.json',
    'stage7-release-pre-fence-gate.json',
  ]);
  assert.equal(
    STAGE7_RELEASE_RECONCILIATION_CONTRACT.sourceArtifactsWithFenceAndReconciliation,
    31,
  );
  assert.equal(STAGE7_RELEASE_RECONCILIATION_CONTRACT.apiArtifactsWithFenceAndReconciliation, 32);
  assert.deepEqual(STAGE7_RELEASE_RECONCILIATION_CONTRACT.approvedInternalArtifacts, [
    'release-observability-pending',
  ]);
});

const publicationExpected = {
  source,
  publicationPlanSha256: digests.plan,
  releaseName: source.releaseTag,
  notesSha256: digests.notes,
  prerelease: false,
  asset: {
    name: 'candidate-manifest.json',
    sha256: digests.asset,
    bytes: 512,
    contentType: 'application/json',
  },
};
const exactTag = { name: source.releaseTag, objectType: 'commit', commitSha: source.candidateSha };
const baseRelease = {
  id: 41,
  tagName: source.releaseTag,
  targetCommitish: source.candidateSha,
  name: source.releaseTag,
  bodySha256: digests.notes,
  draft: false,
  prerelease: false,
  assets: [],
};
const exactAsset = {
  id: 99,
  name: 'candidate-manifest.json',
  state: 'uploaded',
  digest: `sha256:${digests.asset}`,
  size: 512,
  contentType: 'application/json',
};

canary('FENCE_WRITTEN_AND_RELEASE_ABSENT_CONVERGES_FORWARD', () => {
  const classified = classifyReleasePublicationState({
    expected: publicationExpected,
    observation: { tag: exactTag, release: null },
  });
  assert.equal(classified.state, 'ABSENT');
  assert.equal(classified.decision, 'CREATE_EXACT_RELEASE_AND_ASSET');
  assert.equal(classified.destructiveOperationsAllowed, false);
});

canary('CRASH_AFTER_RELEASE_CREATE_BEFORE_ASSET_IS_PARTIAL', () => {
  const classified = classifyReleasePublicationState({
    expected: publicationExpected,
    observation: { tag: exactTag, release: baseRelease },
  });
  assert.equal(classified.state, 'PARTIAL');
  assert.deepEqual(classified.permittedOperations, ['UPLOAD_EXACT_ASSET']);
});

const exactObservation = {
  tag: exactTag,
  release: { ...baseRelease, assets: [exactAsset] },
};

canary('CRASH_AFTER_ASSET_BEFORE_PROOF_RECONCILES_AS_NOOP', () => {
  const classified = classifyReleasePublicationState({
    expected: publicationExpected,
    observation: exactObservation,
  });
  assert.equal(classified.state, 'EXACT');
  assert.equal(classified.decision, 'NOOP_VERIFIED');
  assert.equal(
    validateReleasePublicationClassification(classified, {
      expected: publicationExpected,
      observation: exactObservation,
    }),
    classified,
  );
});

canary('TAG_TARGET_CONFLICT_BLOCKS_WITH_ZERO_WRITES', () => {
  const classified = classifyReleasePublicationState({
    expected: publicationExpected,
    observation: {
      tag: { ...exactTag, commitSha: 'f'.repeat(40) },
      release: null,
    },
  });
  assert.equal(classified.state, 'CONFLICT');
  assert.equal(classified.decision, 'BLOCK_NO_MUTATION');
  assert.equal(classified.externalWritesRequired, 0);
});

canary('RELEASE_BODY_CONFLICT_NEVER_OVERWRITES', () => {
  const classified = classifyReleasePublicationState({
    expected: publicationExpected,
    observation: {
      tag: exactTag,
      release: { ...baseRelease, bodySha256: 'e'.repeat(64) },
    },
  });
  assert.equal(classified.state, 'CONFLICT');
  assert.equal(classified.destructiveOperationsAllowed, false);
  assert.deepEqual(classified.permittedOperations, []);
});

canary('ASSET_DIGEST_CONFLICT_NEVER_REUPLOADS', () => {
  const classified = classifyReleasePublicationState({
    expected: publicationExpected,
    observation: {
      tag: exactTag,
      release: {
        ...baseRelease,
        assets: [{ ...exactAsset, digest: `sha256:${'e'.repeat(64)}` }],
      },
    },
  });
  assert.equal(classified.state, 'CONFLICT');
  assert.equal(classified.decision, 'BLOCK_NO_MUTATION');
});

canary('UNEXPECTED_OR_DUPLICATE_ASSET_SET_BLOCKS', () => {
  const classified = classifyReleasePublicationState({
    expected: publicationExpected,
    observation: {
      tag: exactTag,
      release: { ...baseRelease, assets: [exactAsset, { ...exactAsset }] },
    },
  });
  assert.equal(classified.state, 'CONFLICT');
  assert.equal(classified.reasonCodes.includes('ASSET_ID_DUPLICATE'), true);
  assert.equal(classified.reasonCodes.includes('ASSET_NAME_DUPLICATE'), true);
});

process.stdout.write(
  `${JSON.stringify({
    status: 'PASS',
    contract: 'stage7-release-reconciliation',
    canaries: canaryIds.length,
    canaryIds,
    artifactName: STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
    artifactEntries: STAGE7_RELEASE_RECONCILIATION_FILES.length,
    externalRequests: 0,
  })}\n`,
);
