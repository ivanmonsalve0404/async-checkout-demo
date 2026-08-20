import { STAGE7_FULL_SOURCE_ARTIFACT_NAMES } from './evidence-provenance.mjs';

const RECONCILIATION_ARTIFACT_NAME = 'stage7-release-reconciliation';
const JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME =
  'stage7-release-journal-role-effective-permissions.json';
const RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME =
  'stage7-release-reconciliation-recovery-role-effective-permissions.json';
const JOURNAL_SNAPSHOT_BASENAME = 'release-reconciliation-journal-snapshot.json';

export const RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME = 'stage7-release-successor-source';
export const RELEASE_SUCCESSOR_INPUT_ARTIFACT_NAME = 'stage7-previous-release';
export const RELEASE_SUCCESSOR_WORKFLOW_PATH = '.github/workflows/release.yml';
export const RELEASE_SUCCESSOR_WORKFLOW_NAME = 'Stage 7 Release';
export const RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH =
  '.github/workflows/stage7-release-successor-post-success.yml';
export const RELEASE_SUCCESSOR_REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
export const RELEASE_SUCCESSOR_MASTER_REF = 'refs/heads/master';

export const RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS = Object.freeze(
  [
    ...new Set([
      ...STAGE7_FULL_SOURCE_ARTIFACT_NAMES,
      'stage7-candidate',
      'stage7-release-reports',
      'stage7-release-successor-fence',
      RECONCILIATION_ARTIFACT_NAME,
    ]),
  ].toSorted(),
);

export const RELEASE_SUCCESSOR_INTERNAL_ARTIFACTS = Object.freeze(
  [
    'release-observability-pending',
    'release-external-authorization-request',
    'release-sandbox-execution-request',
  ].toSorted(),
);

export const RELEASE_SUCCESSOR_SOURCE_LAYOUT = Object.freeze({
  observation: 'release-successor-run-observation.json',
  releaseMetadata: 'release-successor-release-metadata.json',
  stage6Closeout: 'release-successor-stage6-closeout.json',
  config: 'release-successor-current-config.json',
  freeze: 'release-successor-freeze-manifest.json',
  predecessor: 'release-successor-predecessor-manifest.json',
  predecessorSourceProvenance: 'release-successor-predecessor-source-provenance.json',
  predecessorTargetCompatibility: 'release-successor-predecessor-target-compatibility.json',
  predecessorFinalDisable: 'release-successor-predecessor-final-disable-provenance.json',
  predecessorApiContract: 'release-successor-predecessor-api-contract-evidence.json',
  predecessorPending: 'release-successor-predecessor-pending-evidence.json',
  predecessorSmoke: 'release-successor-predecessor-smoke-evidence.json',
  predecessorProjectionIndex: 'release-successor-predecessor-projection-index.json',
  candidateRecord: 'release-successor-candidate-record.json',
  emergencyRecovery: 'release-successor-emergency-recovery.json',
  emergencyRecoveryNoActionOutcome: 'release-successor-emergency-recovery-no-action-outcome.json',
  approvedPlan: 'release-successor-approved-plan.json',
  rawDiff: 'release-successor-infra-diff.txt',
  githubApproval: 'release-successor-github-approval.json',
  approval: 'release-successor-approval.json',
  activation: 'release-successor-activation.json',
  drift: 'release-successor-drift.json',
  rollback: 'release-successor-rollback.json',
  rollbackSourceBinding: 'release-successor-rollback-source-binding.json',
  rollbackProtectedRun: 'release-successor-rollback-protected-run.json',
  rollbackCompletion: 'release-successor-rollback-completion.json',
  rollbackInputs: 'release-successor-rollback-inputs.json',
  rollbackRb06: 'release-successor-rb-e7-06-descriptor.json',
  rollbackRb08: 'release-successor-rb-e7-08-descriptor.json',
  releaseManifest: 'release-successor-release-manifest.json',
  provenanceLedger: 'release-successor-provenance-ledger.json',
  closeout: 'release-successor-closeout.json',
  releaseHandoff: 'release-successor-handoff-payload.json',
  publicationPreparation: 'release-successor-publication.json',
  publicationPlan: 'release-successor-publication-plan.json',
  publicationTargetProof: 'release-successor-publication-target-proof.json',
  publicationOperation: 'release-successor-publication-operation.json',
  publicationProof: 'release-successor-publication-proof.json',
  apiDeployment: 'release-successor-api-deployment.json',
  pendingProducer: 'release-successor-pending-producer.json',
  pendingEgressCloseout: 'release-successor-pending-egress-closeout.json',
  postdeploySmoke: 'release-successor-postdeploy-smoke.json',
  repromotionSmoke: 'release-successor-repromotion-smoke.json',
  releaseFence: 'release-successor-completion-fence.json',
  reconciliationRollbackCheck: 'release-successor-rollback-check-reconciliation.json',
  reconciliationRollbackResilience: 'release-successor-rollback-resilience-reconciliation.json',
  preFenceGate: 'release-successor-pre-fence-gate.json',
  awsAuth: 'release-successor-aws-auth.json',
  journalRoleEffectivePermissions: JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  reconciliationRecoveryRoleEffectivePermissions: RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  finalizationMarker: 'release-successor-finalization-marker.json',
  finalDisable: 'release-successor-final-disable-provenance.json',
  journalSnapshot: JOURNAL_SNAPSHOT_BASENAME,
  apiContract: 'release-successor-api-contract-evidence.json',
  pendingReconciliation: 'release-successor-pending-reconciliation-evidence.json',
  smoke: 'release-successor-smoke-evidence.json',
  provenance: 'release-successor-source-provenance.json',
  index: 'release-successor-source-bundle.json',
});

export const RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES = Object.freeze(
  Object.values(RELEASE_SUCCESSOR_SOURCE_LAYOUT).filter(
    (name) =>
      ![RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance, RELEASE_SUCCESSOR_SOURCE_LAYOUT.index].includes(
        name,
      ),
  ),
);
