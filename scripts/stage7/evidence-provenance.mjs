import assert from 'node:assert/strict';

import { calculateStage6Rubric, stage6RubricIsExact } from '../stage6/rubric.mjs';
import {
  STAGE7_ARTIFACTS,
  STAGE7_EVIDENCE,
  STAGE7_REPORT_HEADINGS,
  canonicalJson,
  createStage7Index,
  objectSha256,
} from './core.mjs';
import {
  RELEASE_SUCCESSOR_COMPOSITE_GATE_JOB_IDS,
  RELEASE_SUCCESSOR_RECOVERY_JOB_IDS,
  RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME,
  validateReleaseSuccessorRecoveryCloseoutAuthority,
} from './release-successor-recovery-integration.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const ALIAS = /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/ -]{1,512}$/u;
const ARTIFACT_STATES = new Set([
  'PLANNED',
  'IN_PROGRESS',
  'VERIFIED',
  'FAILED',
  'BLOCKED_AUTH',
  'NOT_APPLICABLE_APPROVED',
  'SUPERSEDED',
]);
const EVIDENCE_STATES = new Set([
  'NOT_RUN',
  'PASS',
  'FAIL',
  'BLOCKED_AUTH',
  'NOT_APPLICABLE_APPROVED',
]);
const GATE_IDS = ['EVD-E7-55', 'EVD-E7-56', 'EVD-E7-57'];
const GATE_NAMES = ['GATE-E7-01', 'GATE-E7-02', 'GATE-E7-03'];
const EVIDENCE_DOWNLOAD_ROOT = '.stage7/evidence';
const PRERELEASE_FORBIDDEN_PASS = new Set(
  [20, 30, 35, 36, 37, 38, 39, 40, 42, 43, 44, 46, 47, 48, 49, 51, 52, 53, 55, 56, 57].map(
    (number) => `EVD-E7-${String(number).padStart(2, '0')}`,
  ),
);

const producer = (artifactName, producerJob) => Object.freeze({ artifactName, producerJob });
export const STAGE7_SOURCE_PRODUCERS = Object.freeze({
  full: Object.freeze({
    'release-metadata.json': producer('stage7-release-metadata', 'release-metadata'),
    'stage6-closeout.json': producer('stage7-release-metadata', 'release-metadata'),
    'verify-candidate.json': producer('stage7-candidate-verification', 'verify-candidate'),
    'prefreeze.json': producer('stage7-prefreeze', 'build-or-fetch'),
    'candidate-manifest.json': producer('stage7-candidate-manifest', 'build-or-fetch'),
    'checksums-sbom.json': producer('stage7-integrity', 'checksums-sbom'),
    'security.json': producer('stage7-security', 'secret-scan'),
    'aws-auth.json': producer('stage7-aws-auth', 'aws-auth'),
    'stage7-release-journal-role-effective-permissions.json': producer(
      'stage7-aws-auth',
      'aws-auth',
    ),
    'stage7-release-reconciliation-recovery-role-effective-permissions.json': producer(
      'stage7-aws-auth',
      'aws-auth',
    ),
    'infra-synth.json': producer('stage7-infra-synth', 'infra-synth-test'),
    'release-plan.json': producer('stage7-release-plan', 'infra-diff'),
    'infra-diff.json': producer('stage7-infra-diff', 'infra-diff'),
    'infra-diff.txt': producer('stage7-infra-diff', 'infra-diff'),
    'previous-release-readiness.json': producer('stage7-infra-diff', 'infra-diff'),
    'previous-release-manifest.json': producer('stage7-previous-release', 'infra-diff'),
    'previous-api-contract-evidence.json': producer('stage7-previous-release', 'infra-diff'),
    'previous-pending-evidence.json': producer('stage7-previous-release', 'infra-diff'),
    'previous-smoke-evidence.json': producer('stage7-previous-release', 'infra-diff'),
    'previous-source-provenance.json': producer('stage7-previous-release', 'infra-diff'),
    'previous-target-compatibility.json': producer('stage7-previous-release', 'infra-diff'),
    'previous-final-disable-provenance.json': producer('stage7-previous-release', 'infra-diff'),
    'previous-release-projection-index.json': producer('stage7-previous-release', 'infra-diff'),
    'github-environment-approval.json': producer('stage7-approval', 'approval'),
    'approval.json': producer('stage7-approval', 'approval'),
    'data.json': producer('stage7-data', 'deploy-data'),
    'api.json': producer('stage7-api', 'deploy-api'),
    'web.json': producer('stage7-web', 'deploy-web'),
    'activation.json': producer('stage7-activation', 'postdeploy-smoke'),
    'external-authorization.json': producer('stage7-external-authorization', 'postdeploy-smoke'),
    'observability.json': producer('stage7-observability', 'postdeploy-smoke'),
    'smoke-input-preflight.json': producer('stage7-smoke', 'postdeploy-smoke'),
    'smoke.json': producer('stage7-smoke', 'postdeploy-smoke'),
    'edge-security.json': producer('stage7-edge-security', 'edge-security'),
    'quality.json': producer('stage7-quality', 'quality'),
    'sandbox-smoke.json': producer('stage7-sandbox', 'sandbox-smoke'),
    'versioned-rollback-candidate.json': producer('stage7-recovery-probe', 'emergency-recovery'),
    'emergency-recovery.json': producer('stage7-recovery-probe', 'emergency-recovery'),
    'emergency-recovery-no-action-outcome.json': producer(
      'stage7-recovery-probe',
      'emergency-recovery',
    ),
    'rollback-smoke-input-preflight.json': producer('stage7-rollback', 'rollback-check'),
    'rollback-pending-producer.json': producer('stage7-rollback', 'rollback-check'),
    'rollback-pending-egress-closeout.json': producer('stage7-rollback', 'rollback-check'),
    'versioned-rollback-aws-transition.json': producer('stage7-rollback', 'rollback-check'),
    'versioned-rollback-smoke.json': producer('stage7-rollback', 'rollback-check'),
    'versioned-rollback-checkpoint.json': producer('stage7-rollback', 'rollback-check'),
    'versioned-repromotion-aws-transition.json': producer('stage7-rollback', 'rollback-check'),
    'versioned-repromotion-smoke.json': producer('stage7-rollback', 'rollback-check'),
    'versioned-repromotion-checkpoint.json': producer('stage7-rollback', 'rollback-check'),
    'rollback.json': producer('stage7-rollback', 'rollback-check'),
    'drift.json': producer('stage7-rollback', 'rollback-check'),
    'stage7-rollback-resilience-source-binding.json': producer(
      'stage7-rollback-resilience',
      'rollback-resilience',
    ),
    'stage7-rollback-resilience-protected-run.json': producer(
      'stage7-rollback-resilience',
      'rollback-resilience',
    ),
    'stage7-rollback-resilience-complete.json': producer(
      'stage7-rollback-resilience',
      'rollback-resilience',
    ),
    'rollback-check-reconciliation.json': producer(
      'stage7-release-reconciliation',
      'release-reconciliation',
    ),
    'rollback-resilience-reconciliation.json': producer(
      'stage7-release-reconciliation',
      'release-reconciliation',
    ),
    'stage7-release-pre-fence-gate.json': producer(
      'stage7-release-reconciliation',
      'release-reconciliation',
    ),
    'release-successor-completion-fence.json': producer(
      'stage7-release-successor-fence',
      'release-successor-fence',
    ),
    'publication.json': producer('stage7-publication', 'publish-release'),
    'publication-plan.json': producer('stage7-publication', 'publish-release'),
    'publication-target-proof.json': producer('stage7-publication', 'publish-release'),
    'publication-operation.json': producer('stage7-publication', 'publish-release'),
    'publication-proof.json': producer('stage7-publication', 'publish-release'),
    'job-results.json': producer('stage7-release-authorities', 'summary'),
    'scorecard.json': producer('stage7-release-authorities', 'summary'),
    'operations-runbook.json': producer('stage7-release-authorities', 'summary'),
    'gate-evaluation.json': producer('stage7-release-authorities', 'summary'),
    'evidence-index-checkpoint.json': producer('stage7-release-authorities', 'summary'),
    'handoff-payload.json': producer('stage7-release-authorities', 'summary'),
  }),
  prerelease: Object.freeze({
    'metadata.json': producer('stage7-prerelease-metadata', 'prerelease-metadata'),
    'stage6-closeout.json': producer('stage7-prerelease-metadata', 'prerelease-metadata'),
    'verify-candidate.json': producer(
      'stage7-prerelease-candidate-verification',
      'verify-candidate',
    ),
    'candidate-manifest.json': producer('stage7-prerelease-candidate-manifest', 'build-once'),
    'checksums-sbom.json': producer('stage7-prerelease-integrity-security', 'integrity-security'),
    'security.json': producer('stage7-prerelease-integrity-security', 'integrity-security'),
    'infra-synth.json': producer('stage7-prerelease-infra-synth', 'infra-synth-test'),
    'release-plan.json': producer('stage7-prerelease-release-plan', 'infra-diff'),
    'aws-auth.json': producer('stage7-prerelease-infra-diff', 'infra-diff'),
    'infra-diff.json': producer('stage7-prerelease-infra-diff', 'infra-diff'),
    'infra-diff.txt': producer('stage7-prerelease-infra-diff', 'infra-diff'),
    'github-environment-approval.json': producer('stage7-prerelease-approval', 'approval'),
    'approval.json': producer('stage7-prerelease-approval', 'approval'),
    'prerelease-safety-readiness.json': producer(
      'stage7-prerelease-safety-readiness',
      'prerelease-safety-readiness',
    ),
    'prerelease-activation-live-safety-recheck.json': producer(
      'stage7-prerelease-live-safety-rechecks',
      'external-verification',
    ),
    'prerelease-sandbox-live-safety-recheck.json': producer(
      'stage7-prerelease-live-safety-rechecks',
      'external-verification',
    ),
    'deployment.json': producer('stage7-prerelease-external-checks', 'external-verification'),
    'smoke.json': producer('stage7-prerelease-external-checks', 'external-verification'),
    'external-uat.json': producer('stage7-prerelease-external-checks', 'external-verification'),
    'edge-security.json': producer('stage7-prerelease-external-checks', 'external-verification'),
    'sandbox-smoke.json': producer('stage7-prerelease-external-checks', 'external-verification'),
    'stage6-external-evidence.json': producer(
      'stage6-authorized-external-evidence',
      'external-evidence',
    ),
    'cleanup.json': producer('stage7-prerelease-cleanup', 'cleanup'),
    'job-results.json': producer('stage7-prerelease-authorities', 'summary'),
    'scorecard.json': producer('stage7-prerelease-authorities', 'summary'),
    'operations-runbook.json': producer('stage7-prerelease-authorities', 'summary'),
    'gate-evaluation.json': producer('stage7-prerelease-authorities', 'summary'),
    'evidence-index-checkpoint.json': producer('stage7-prerelease-authorities', 'summary'),
    'handoff-payload.json': producer('stage7-prerelease-authorities', 'summary'),
  }),
});

const sourceArtifactNames = (scope) =>
  Object.freeze(
    [
      ...new Set(
        Object.values(STAGE7_SOURCE_PRODUCERS[scope]).map(({ artifactName }) => artifactName),
      ),
    ].toSorted(),
  );
export const STAGE7_FULL_SOURCE_ARTIFACT_NAMES = sourceArtifactNames('full');
export const STAGE7_PRERELEASE_SOURCE_ARTIFACT_NAMES = sourceArtifactNames('prerelease');

const frozenRequirements = (rows) =>
  Object.freeze(rows.map((basenames) => Object.freeze(basenames)));
export const STAGE7_EVIDENCE_SOURCE_REQUIREMENTS = Object.freeze({
  full: frozenRequirements([
    [
      'release-metadata.json',
      'release-plan.json',
      'github-environment-approval.json',
      'approval.json',
      'external-authorization.json',
    ],
    ['stage6-closeout.json', 'verify-candidate.json', 'prefreeze.json', 'candidate-manifest.json'],
    ['candidate-manifest.json', 'checksums-sbom.json'],
    ['verify-candidate.json', 'checksums-sbom.json'],
    [
      'aws-auth.json',
      'stage7-release-journal-role-effective-permissions.json',
      'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    [
      'aws-auth.json',
      'stage7-release-journal-role-effective-permissions.json',
      'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    [
      'aws-auth.json',
      'stage7-release-journal-role-effective-permissions.json',
      'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    ['candidate-manifest.json', 'infra-synth.json', 'release-plan.json', 'infra-diff.json'],
    ['candidate-manifest.json', 'infra-synth.json', 'release-plan.json', 'infra-diff.json'],
    [
      'release-plan.json',
      'infra-diff.json',
      'infra-diff.txt',
      'github-environment-approval.json',
      'approval.json',
    ],
    ['infra-diff.json', 'infra-diff.txt', 'github-environment-approval.json', 'approval.json'],
    [
      'infra-diff.json',
      'infra-diff.txt',
      'github-environment-approval.json',
      'approval.json',
      'aws-auth.json',
      'stage7-release-journal-role-effective-permissions.json',
      'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    ['security.json', 'infra-synth.json'],
    ['data.json'],
    ['data.json'],
    ['data.json'],
    ['api.json'],
    ['api.json', 'activation.json'],
    ['api.json', 'smoke.json'],
    ['smoke.json'],
    ['api.json'],
    ['web.json', 'activation.json'],
    ['web.json'],
    ['web.json'],
    ['candidate-manifest.json', 'web.json', 'external-authorization.json', 'edge-security.json'],
    ['web.json'],
    ['web.json', 'security.json'],
    ['candidate-manifest.json', 'web.json', 'external-authorization.json', 'edge-security.json'],
    ['candidate-manifest.json', 'web.json', 'external-authorization.json', 'edge-security.json'],
    ['smoke.json'],
    ['observability.json'],
    ['observability.json'],
    ['observability.json'],
    ['observability.json'],
    ['smoke-input-preflight.json', 'smoke.json'],
    ['smoke-input-preflight.json', 'smoke.json'],
    ['smoke-input-preflight.json', 'smoke.json'],
    ['smoke-input-preflight.json', 'smoke.json'],
    ['smoke-input-preflight.json', 'smoke.json'],
    ['smoke-input-preflight.json', 'smoke.json'],
    ['candidate-manifest.json', 'web.json', 'external-authorization.json', 'sandbox-smoke.json'],
    ['candidate-manifest.json', 'external-authorization.json', 'web.json', 'quality.json'],
    ['candidate-manifest.json', 'external-authorization.json', 'web.json', 'quality.json'],
    ['candidate-manifest.json', 'external-authorization.json', 'web.json', 'quality.json'],
    ['candidate-manifest.json', 'web.json', 'external-authorization.json', 'edge-security.json'],
    [
      'rollback.json',
      'versioned-rollback-candidate.json',
      'emergency-recovery.json',
      'emergency-recovery-no-action-outcome.json',
      'versioned-rollback-aws-transition.json',
      'versioned-rollback-checkpoint.json',
      'previous-release-readiness.json',
      'previous-release-manifest.json',
      'previous-api-contract-evidence.json',
      'previous-pending-evidence.json',
      'previous-smoke-evidence.json',
      'previous-source-provenance.json',
      'previous-target-compatibility.json',
      'previous-final-disable-provenance.json',
      'previous-release-projection-index.json',
      'stage7-rollback-resilience-source-binding.json',
      'stage7-rollback-resilience-protected-run.json',
      'stage7-rollback-resilience-complete.json',
      'rollback-check-reconciliation.json',
      'rollback-resilience-reconciliation.json',
      'stage7-release-pre-fence-gate.json',
      'release-successor-completion-fence.json',
      'stage7-release-journal-role-effective-permissions.json',
      'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    [
      'rollback.json',
      'versioned-rollback-candidate.json',
      'emergency-recovery.json',
      'emergency-recovery-no-action-outcome.json',
      'versioned-rollback-aws-transition.json',
      'versioned-rollback-checkpoint.json',
      'rollback-pending-egress-closeout.json',
      'previous-release-readiness.json',
      'previous-release-manifest.json',
      'previous-api-contract-evidence.json',
      'previous-pending-evidence.json',
      'previous-smoke-evidence.json',
      'previous-source-provenance.json',
      'previous-target-compatibility.json',
      'previous-final-disable-provenance.json',
      'previous-release-projection-index.json',
      'stage7-rollback-resilience-source-binding.json',
      'stage7-rollback-resilience-protected-run.json',
      'stage7-rollback-resilience-complete.json',
      'rollback-check-reconciliation.json',
      'rollback-resilience-reconciliation.json',
      'stage7-release-pre-fence-gate.json',
      'release-successor-completion-fence.json',
      'stage7-release-journal-role-effective-permissions.json',
      'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    [
      'rollback.json',
      'versioned-rollback-candidate.json',
      'emergency-recovery-no-action-outcome.json',
      'rollback-smoke-input-preflight.json',
      'rollback-pending-producer.json',
      'rollback-pending-egress-closeout.json',
      'versioned-rollback-aws-transition.json',
      'versioned-rollback-smoke.json',
      'versioned-rollback-checkpoint.json',
      'previous-release-readiness.json',
      'previous-release-manifest.json',
      'previous-api-contract-evidence.json',
      'previous-pending-evidence.json',
      'previous-smoke-evidence.json',
      'previous-source-provenance.json',
      'previous-target-compatibility.json',
      'previous-final-disable-provenance.json',
      'previous-release-projection-index.json',
      'stage7-rollback-resilience-source-binding.json',
      'stage7-rollback-resilience-protected-run.json',
      'stage7-rollback-resilience-complete.json',
      'rollback-check-reconciliation.json',
      'rollback-resilience-reconciliation.json',
      'stage7-release-pre-fence-gate.json',
      'release-successor-completion-fence.json',
      'stage7-release-journal-role-effective-permissions.json',
      'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    [
      'rollback.json',
      'versioned-rollback-candidate.json',
      'emergency-recovery-no-action-outcome.json',
      'versioned-repromotion-aws-transition.json',
      'versioned-repromotion-smoke.json',
      'versioned-repromotion-checkpoint.json',
      'rollback-pending-egress-closeout.json',
      'drift.json',
      'previous-release-readiness.json',
      'previous-release-manifest.json',
      'previous-api-contract-evidence.json',
      'previous-pending-evidence.json',
      'previous-smoke-evidence.json',
      'previous-source-provenance.json',
      'previous-target-compatibility.json',
      'previous-final-disable-provenance.json',
      'previous-release-projection-index.json',
      'stage7-rollback-resilience-source-binding.json',
      'stage7-rollback-resilience-protected-run.json',
      'stage7-rollback-resilience-complete.json',
      'rollback-check-reconciliation.json',
      'rollback-resilience-reconciliation.json',
      'stage7-release-pre-fence-gate.json',
      'release-successor-completion-fence.json',
      'stage7-release-journal-role-effective-permissions.json',
      'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    ['security.json'],
    [
      'publication.json',
      'publication-plan.json',
      'publication-target-proof.json',
      'publication-operation.json',
      'publication-proof.json',
      'release-successor-completion-fence.json',
    ],
    [
      'publication-plan.json',
      'publication-target-proof.json',
      'publication-operation.json',
      'publication-proof.json',
      'release-successor-completion-fence.json',
    ],
    ['scorecard.json', 'job-results.json'],
    ['operations-runbook.json'],
    ['gate-evaluation.json', 'job-results.json', 'release-successor-completion-fence.json'],
    ['gate-evaluation.json', 'job-results.json', 'release-successor-completion-fence.json'],
    ['gate-evaluation.json', 'job-results.json', 'release-successor-completion-fence.json'],
  ]),
  prerelease: frozenRequirements([
    [
      'metadata.json',
      'release-plan.json',
      'github-environment-approval.json',
      'approval.json',
      'prerelease-safety-readiness.json',
    ],
    ['stage6-closeout.json', 'verify-candidate.json', 'candidate-manifest.json'],
    ['candidate-manifest.json', 'checksums-sbom.json'],
    ['verify-candidate.json', 'checksums-sbom.json'],
    ['aws-auth.json'],
    ['aws-auth.json'],
    ['aws-auth.json'],
    ['candidate-manifest.json', 'infra-synth.json', 'release-plan.json', 'infra-diff.json'],
    ['candidate-manifest.json', 'infra-synth.json', 'release-plan.json', 'infra-diff.json'],
    [
      'release-plan.json',
      'infra-diff.json',
      'infra-diff.txt',
      'github-environment-approval.json',
      'approval.json',
    ],
    ['infra-diff.json', 'infra-diff.txt', 'github-environment-approval.json', 'approval.json'],
    [
      'infra-diff.json',
      'infra-diff.txt',
      'github-environment-approval.json',
      'approval.json',
      'aws-auth.json',
    ],
    [
      'security.json',
      'infra-synth.json',
      'prerelease-safety-readiness.json',
      'prerelease-activation-live-safety-recheck.json',
    ],
    ['deployment.json'],
    ['deployment.json'],
    ['deployment.json'],
    ['deployment.json'],
    [
      'deployment.json',
      'prerelease-safety-readiness.json',
      'prerelease-activation-live-safety-recheck.json',
    ],
    ['deployment.json', 'smoke.json'],
    [],
    [
      'deployment.json',
      'prerelease-safety-readiness.json',
      'prerelease-activation-live-safety-recheck.json',
    ],
    [
      'deployment.json',
      'prerelease-safety-readiness.json',
      'prerelease-activation-live-safety-recheck.json',
    ],
    ['deployment.json'],
    ['deployment.json'],
    ['deployment.json', 'edge-security.json'],
    ['deployment.json'],
    [
      'deployment.json',
      'security.json',
      'prerelease-safety-readiness.json',
      'prerelease-activation-live-safety-recheck.json',
    ],
    ['deployment.json', 'edge-security.json'],
    ['deployment.json', 'edge-security.json'],
    [],
    ['deployment.json'],
    ['deployment.json'],
    ['deployment.json'],
    [
      'deployment.json',
      'prerelease-safety-readiness.json',
      'prerelease-activation-live-safety-recheck.json',
    ],
    [],
    [],
    [],
    [],
    [],
    [],
    [
      'candidate-manifest.json',
      'deployment.json',
      'sandbox-smoke.json',
      'stage6-external-evidence.json',
      'prerelease-sandbox-live-safety-recheck.json',
    ],
    [],
    [],
    [],
    ['deployment.json', 'external-uat.json', 'edge-security.json'],
    [],
    [],
    [],
    [],
    ['security.json'],
    [],
    [],
    [],
    ['operations-runbook.json', 'cleanup.json', 'prerelease-safety-readiness.json'],
    [],
    [],
    [],
  ]),
});

export class Stage7ProvenanceError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7ProvenanceError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7ProvenanceError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, expected) =>
  object(value) && Object.keys(value).toSorted().join('\0') === expected.toSorted().join('\0');
const utc = (value) =>
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
  !Number.isNaN(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const exactIds = (prefix, total) =>
  Array.from({ length: total }, (_, index) => `${prefix}-${String(index + 1).padStart(2, '0')}`);
const pathBasename = (value) => value.split('/').at(-1);
const secureUrl = (value) => {
  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      url.username === '' &&
      url.password === '' &&
      url.search === '' &&
      url.hash === ''
    );
  } catch {
    return false;
  }
};
const evidenceSatisfied = (status) => ['PASS', 'NOT_APPLICABLE_APPROVED'].includes(status);
const artifactSatisfied = (status) => ['VERIFIED', 'NOT_APPLICABLE_APPROVED'].includes(status);

const assertIdentity = ({ candidateSha, releaseId, releaseTag, scope }) => {
  if (
    !SHA.test(candidateSha ?? '') ||
    !RELEASE_ID.test(releaseId ?? '') ||
    !releaseId.endsWith(`-${candidateSha.slice(0, 7)}`) ||
    !['full', 'prerelease'].includes(scope) ||
    (scope === 'full' && !RELEASE_TAG.test(releaseTag ?? '')) ||
    (scope === 'prerelease' && releaseTag !== null)
  ) {
    fail('E7_PROVENANCE_IDENTITY_INVALID');
  }
};

const sameIdentity = (left, right) =>
  left?.scope === right?.scope &&
  left?.candidateSha === right?.candidateSha &&
  left?.releaseId === right?.releaseId &&
  left?.releaseTag === right?.releaseTag;

export const createSourceReference = ({ path, sha256, artifactName, producerJob, selectors }) => {
  const value = { path, sha256, artifactName, producerJob, selectors };
  validateSourceReference(value);
  return value;
};

export const validateSourceReference = (value) => {
  if (
    !exactKeys(value, ['path', 'sha256', 'artifactName', 'producerJob', 'selectors']) ||
    !SAFE_PATH.test(value.path ?? '') ||
    !SHA256.test(value.sha256 ?? '') ||
    !/^(?:stage[67]|runtime)-[a-z0-9-]{2,100}$/u.test(value.artifactName ?? '') ||
    !/^[a-z0-9][a-z0-9-]{1,79}$/u.test(value.producerJob ?? '') ||
    !Array.isArray(value.selectors) ||
    value.selectors.length < 1 ||
    value.selectors.length > 32 ||
    new Set(value.selectors).size !== value.selectors.length ||
    value.selectors.some(
      (selector) => typeof selector !== 'string' || selector.length < 1 || selector.length > 256,
    )
  ) {
    fail('E7_PROVENANCE_SOURCE_INVALID');
  }
  return value;
};

export const validateBoundSourceReference = ({ scope, basename, source }) => {
  if (!['full', 'prerelease'].includes(scope) || typeof basename !== 'string') {
    fail('E7_PROVENANCE_SOURCE_BINDING_INVALID');
  }
  validateSourceReference(source);
  const expected = STAGE7_SOURCE_PRODUCERS[scope]?.[basename];
  const normalizedPath = source.path.replaceAll('\\', '/');
  if (
    expected === undefined ||
    pathBasename(normalizedPath) !== basename ||
    source.artifactName !== expected.artifactName ||
    source.producerJob !== expected.producerJob ||
    normalizedPath !== `${EVIDENCE_DOWNLOAD_ROOT}/${expected.artifactName}/${basename}`
  ) {
    fail('E7_PROVENANCE_SOURCE_BINDING_INVALID');
  }
  return source;
};

export const validateEvidenceRowSourceRequirements = ({ scope, row }) => {
  validateProvenanceRow(row, { kind: 'evidence' });
  const index = Number.parseInt(row.id.slice(-2), 10) - 1;
  const required = STAGE7_EVIDENCE_SOURCE_REQUIREMENTS[scope]?.[index];
  if (required === undefined) fail('E7_EVIDENCE_SOURCE_REQUIREMENT_INVALID');
  const basenames = new Set(
    row.sources.map((source) => {
      const basename = pathBasename(source.path.replaceAll('\\', '/'));
      validateBoundSourceReference({ scope, basename, source });
      return basename;
    }),
  );
  const requiredSourcesPresent = required.every((basename) => basenames.has(basename));
  const jobResultFallbackPresent = basenames.has('job-results.json');
  if (
    (required.length === 0 && evidenceSatisfied(row.status)) ||
    (required.length > 0 && evidenceSatisfied(row.status) && !requiredSourcesPresent) ||
    (!evidenceSatisfied(row.status) && !requiredSourcesPresent && !jobResultFallbackPresent)
  ) {
    fail('E7_EVIDENCE_SOURCE_REQUIREMENT_INVALID');
  }
  return row;
};

const uniqueSources = (sources) => {
  const byIdentity = new Map();
  for (const source of sources) {
    validateSourceReference(source);
    const key = `${source.path}\0${source.sha256}\0${source.producerJob}`;
    const previous = byIdentity.get(key);
    if (previous === undefined) byIdentity.set(key, source);
    else {
      byIdentity.set(key, {
        ...source,
        selectors: [...new Set([...previous.selectors, ...source.selectors])].sort(),
      });
    }
  }
  return [...byIdentity.values()].sort((left, right) => left.path.localeCompare(right.path, 'en'));
};

export const createProvenanceRow = ({
  id,
  name,
  status,
  ownerAlias,
  validatedAtUtc,
  validator,
  sources,
}) => {
  const value = {
    id,
    name,
    status,
    ownerAlias,
    validatedAtUtc,
    validator,
    sources: uniqueSources(sources),
  };
  validateProvenanceRow(value);
  return value;
};

export const validateProvenanceRow = (value, { kind } = {}) => {
  const artifact = /^ART-REL-(?:0[1-9]|1[0-9]|20)$/u.test(value?.id ?? '');
  const evidence = /^EVD-E7-(?:0[1-9]|[1-4][0-9]|5[0-7])$/u.test(value?.id ?? '');
  if (
    !exactKeys(value, [
      'id',
      'name',
      'status',
      'ownerAlias',
      'validatedAtUtc',
      'validator',
      'sources',
    ]) ||
    (kind === 'artifact' && !artifact) ||
    (kind === 'evidence' && !evidence) ||
    (!artifact && !evidence) ||
    typeof value.name !== 'string' ||
    value.name.length < 3 ||
    value.name.length > 160 ||
    (artifact ? !ARTIFACT_STATES.has(value.status) : !EVIDENCE_STATES.has(value.status)) ||
    !ALIAS.test(value.ownerAlias ?? '') ||
    !utc(value.validatedAtUtc) ||
    !/^[A-Za-z][A-Za-z0-9._:-]{2,127}$/u.test(value.validator ?? '') ||
    !Array.isArray(value.sources) ||
    value.sources.length < 1 ||
    value.sources.length > 96
  ) {
    fail('E7_PROVENANCE_ROW_INVALID');
  }
  for (const source of value.sources) validateSourceReference(source);
  if (
    new Set(value.sources.map(({ path, sha256 }) => `${path}\0${sha256}`)).size !==
    value.sources.length
  ) {
    fail('E7_PROVENANCE_ROW_SOURCE_DUPLICATE');
  }
  return value;
};

const sourceUnion = (rows) => uniqueSources(rows.flatMap(({ sources }) => sources));

const sourceAuthorities = (rows) => {
  const authorities = new Map();
  for (const source of rows.flatMap(({ sources }) => sources)) {
    validateSourceReference(source);
    const normalizedPath = source.path.replaceAll('\\', '/');
    const authority = {
      sha256: source.sha256,
      artifactName: source.artifactName,
      producerJob: source.producerJob,
    };
    const previous = authorities.get(normalizedPath);
    if (previous !== undefined && objectSha256(previous) !== objectSha256(authority)) {
      fail('E7_PROVENANCE_SOURCE_AUTHORITY_CONFLICT');
    }
    authorities.set(normalizedPath, authority);
  }
  return authorities;
};

const sourceSha256ByBasename = (rows, basename) => {
  const matches = [...sourceAuthorities(rows).entries()].filter(
    ([sourcePath]) => pathBasename(sourcePath) === basename,
  );
  if (matches.length !== 1) fail('E7_PROVENANCE_SOURCE_AUTHORITY_MISSING');
  return matches[0][1].sha256;
};

export const STAGE7_LEDGER_SOURCE_BINDING_SPECS = Object.freeze(
  [
    ['previousReleaseManifest', 'previous-release-manifest.json'],
    ['previousSourceProvenance', 'previous-source-provenance.json'],
    ['previousTargetCompatibility', 'previous-target-compatibility.json'],
    ['previousFinalDisableProvenance', 'previous-final-disable-provenance.json'],
    ['previousReleaseProjectionIndex', 'previous-release-projection-index.json'],
    ['previousApiContractEvidence', 'previous-api-contract-evidence.json'],
    ['previousPendingEvidence', 'previous-pending-evidence.json'],
    ['previousSmokeEvidence', 'previous-smoke-evidence.json'],
    ['approval', 'approval.json'],
    ['emergencyRecoveryNoActionOutcome', 'emergency-recovery-no-action-outcome.json'],
    [
      'releaseJournalRoleEffectivePermissions',
      'stage7-release-journal-role-effective-permissions.json',
    ],
    [
      'releaseReconciliationRecoveryRoleEffectivePermissions',
      'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    ['activation', 'activation.json'],
    ['drift', 'drift.json'],
    ['rollbackPendingEgressCloseout', 'rollback-pending-egress-closeout.json'],
    ['rollbackResilienceSourceBinding', 'stage7-rollback-resilience-source-binding.json'],
    ['rollbackResilienceProtectedRun', 'stage7-rollback-resilience-protected-run.json'],
    ['rollbackResilienceCompletion', 'stage7-rollback-resilience-complete.json'],
    ['rollbackCheckReconciliation', 'rollback-check-reconciliation.json'],
    ['rollbackResilienceReconciliation', 'rollback-resilience-reconciliation.json'],
    ['releasePreFenceGate', 'stage7-release-pre-fence-gate.json'],
    ['releaseSuccessorFence', 'release-successor-completion-fence.json'],
    ['publicationPreparation', 'publication.json'],
    ['publicationPlan', 'publication-plan.json'],
    ['publicationTargetProof', 'publication-target-proof.json'],
    ['publicationOperation', 'publication-operation.json'],
    ['publicationProof', 'publication-proof.json'],
  ].map(([key, basename]) => Object.freeze({ key, basename })),
);

const sourceReferenceByBasename = (rows, basename) => {
  const matches = sourceUnion(rows).filter(
    (source) => pathBasename(source.path.replaceAll('\\', '/')) === basename,
  );
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail('E7_LEDGER_SOURCE_BINDING_AMBIGUOUS');
  return matches[0];
};

const validateCanonicalSha256Map = (value) => {
  if (
    !object(value) ||
    Object.entries(value).some(
      ([basename, sha256]) =>
        !SAFE_PATH.test(basename) || basename.includes('/') || !SHA256.test(sha256 ?? ''),
    )
  ) {
    fail('E7_LEDGER_CANONICAL_DIGEST_MAP_INVALID');
  }
  return value;
};

export const createStage7LedgerSourceBindings = ({
  scope,
  artifactRows,
  evidenceRows,
  canonicalSha256ByBasename,
}) => {
  if (scope === 'prerelease') return {};
  if (scope !== 'full') fail('E7_LEDGER_SOURCE_BINDING_SCOPE_INVALID');
  validateCanonicalSha256Map(canonicalSha256ByBasename);
  const rows = [...artifactRows, ...evidenceRows];
  const bindings = {};
  for (const { key, basename } of STAGE7_LEDGER_SOURCE_BINDING_SPECS) {
    const source = sourceReferenceByBasename(rows, basename);
    const canonicalSha256 = canonicalSha256ByBasename[basename];
    if (source === null || !SHA256.test(canonicalSha256 ?? '')) {
      bindings[key] = {
        status: 'NOT_AVAILABLE',
        basename,
        path: null,
        artifactName: null,
        producerJob: null,
        rawSha256: null,
        objectSha256: null,
      };
      continue;
    }
    validateBoundSourceReference({ scope, basename, source });
    bindings[key] = {
      status: 'BOUND',
      basename,
      path: source.path.replaceAll('\\', '/'),
      artifactName: source.artifactName,
      producerJob: source.producerJob,
      rawSha256: source.sha256,
      objectSha256: canonicalSha256,
    };
  }
  validateStage7LedgerSourceBindings(bindings, {
    scope,
    artifactRows,
    evidenceRows,
    canonicalSha256ByBasename,
  });
  return bindings;
};

export const validateStage7LedgerSourceBindings = (
  value,
  { scope, artifactRows, evidenceRows, canonicalSha256ByBasename },
) => {
  if (scope === 'prerelease') {
    if (!exactKeys(value, [])) fail('E7_LEDGER_SOURCE_BINDING_INVALID');
    return value;
  }
  if (scope !== 'full') fail('E7_LEDGER_SOURCE_BINDING_SCOPE_INVALID');
  validateCanonicalSha256Map(canonicalSha256ByBasename);
  if (
    !exactKeys(
      value,
      STAGE7_LEDGER_SOURCE_BINDING_SPECS.map(({ key }) => key),
    )
  ) {
    fail('E7_LEDGER_SOURCE_BINDING_INVALID');
  }
  const rows = [...artifactRows, ...evidenceRows];
  for (const { key, basename } of STAGE7_LEDGER_SOURCE_BINDING_SPECS) {
    const binding = value[key];
    const source = sourceReferenceByBasename(rows, basename);
    const canonicalSha256 = canonicalSha256ByBasename[basename];
    if (
      !exactKeys(binding, [
        'status',
        'basename',
        'path',
        'artifactName',
        'producerJob',
        'rawSha256',
        'objectSha256',
      ]) ||
      binding.basename !== basename ||
      !['BOUND', 'NOT_AVAILABLE'].includes(binding.status)
    ) {
      fail('E7_LEDGER_SOURCE_BINDING_INVALID');
    }
    if (binding.status === 'NOT_AVAILABLE') {
      if (
        [
          binding.path,
          binding.artifactName,
          binding.producerJob,
          binding.rawSha256,
          binding.objectSha256,
        ].some((item) => item !== null) ||
        (source !== null && SHA256.test(canonicalSha256 ?? ''))
      ) {
        fail('E7_LEDGER_SOURCE_BINDING_INVALID');
      }
      continue;
    }
    if (source === null || !SHA256.test(canonicalSha256 ?? '')) {
      fail('E7_LEDGER_SOURCE_BINDING_INVALID');
    }
    validateBoundSourceReference({ scope, basename, source });
    if (
      binding.path !== source.path.replaceAll('\\', '/') ||
      binding.artifactName !== source.artifactName ||
      binding.producerJob !== source.producerJob ||
      binding.rawSha256 !== source.sha256 ||
      binding.objectSha256 !== canonicalSha256
    ) {
      fail('E7_LEDGER_SOURCE_BINDING_INVALID');
    }
  }
  return value;
};

const ARTIFACT_EVIDENCE = Object.freeze({
  'ART-REL-01': ['EVD-E7-01', 'EVD-E7-54'],
  'ART-REL-02': ['EVD-E7-02', 'EVD-E7-03', 'EVD-E7-04'],
  'ART-REL-03': ['EVD-E7-05', 'EVD-E7-07'],
  'ART-REL-04': ['EVD-E7-03', 'EVD-E7-04', 'EVD-E7-08', 'EVD-E7-09'],
  'ART-REL-05': ['EVD-E7-10', 'EVD-E7-11', 'EVD-E7-12'],
  'ART-REL-06': ['EVD-E7-06', 'EVD-E7-12'],
  'ART-REL-07': ['EVD-E7-14', 'EVD-E7-15', 'EVD-E7-16'],
  'ART-REL-08': ['EVD-E7-17', 'EVD-E7-18', 'EVD-E7-19', 'EVD-E7-20', 'EVD-E7-21'],
  'ART-REL-09': ['EVD-E7-22', 'EVD-E7-23', 'EVD-E7-24', 'EVD-E7-25', 'EVD-E7-26', 'EVD-E7-27'],
  'ART-REL-10': ['EVD-E7-25', 'EVD-E7-28', 'EVD-E7-29', 'EVD-E7-30', 'EVD-E7-45'],
  'ART-REL-11': ['EVD-E7-31', 'EVD-E7-32', 'EVD-E7-33'],
  'ART-REL-12': ['EVD-E7-34', 'EVD-E7-54'],
  'ART-REL-13': ['EVD-E7-35', 'EVD-E7-36', 'EVD-E7-37', 'EVD-E7-38', 'EVD-E7-39', 'EVD-E7-40'],
  'ART-REL-14': ['EVD-E7-41'],
  'ART-REL-15': ['EVD-E7-46', 'EVD-E7-47', 'EVD-E7-48', 'EVD-E7-49'],
  'ART-REL-16': ['EVD-E7-50', 'EVD-E7-52'],
  'ART-REL-17': ['EVD-E7-20', 'EVD-E7-51'],
});

const artifactStatusFromEvidence = (rows) => {
  if (rows.some(({ status }) => status === 'FAIL')) return 'FAILED';
  if (rows.some(({ status }) => status === 'BLOCKED_AUTH')) return 'BLOCKED_AUTH';
  if (rows.every(({ status }) => evidenceSatisfied(status))) return 'VERIFIED';
  return 'IN_PROGRESS';
};
const artifactStatusFromGate = (gate) =>
  gate === 'PASS'
    ? 'VERIFIED'
    : gate === 'FAIL'
      ? 'FAILED'
      : gate === 'BLOCKED_AUTH'
        ? 'BLOCKED_AUTH'
        : 'IN_PROGRESS';

export const createOperationalArtifactRows = ({ evidenceRows, ownerAlias, validatedAtUtc }) => {
  const byId = new Map(evidenceRows.map((row) => [row.id, row]));
  if (
    evidenceRows.length !== 54 ||
    evidenceRows.map(({ id }) => id).join('\0') !== exactIds('EVD-E7', 54).join('\0') ||
    byId.size !== evidenceRows.length ||
    !ALIAS.test(ownerAlias ?? '') ||
    !utc(validatedAtUtc)
  ) {
    fail('E7_OPERATIONAL_ARTIFACT_INPUT_INVALID');
  }
  for (const row of evidenceRows) validateProvenanceRow(row, { kind: 'evidence' });
  return STAGE7_ARTIFACTS.slice(0, 17).map(({ id, name }) => {
    const dependencies = ARTIFACT_EVIDENCE[id].map((evidenceId) => byId.get(evidenceId));
    return createProvenanceRow({
      id,
      name,
      status: artifactStatusFromEvidence(dependencies),
      ownerAlias,
      validatedAtUtc,
      validator: 'deriveArtifactStatusFromEvidence',
      sources: sourceUnion(dependencies),
    });
  });
};

export const validateOperationalArtifactRows = (
  value,
  { evidenceRows, ownerAlias, validatedAtUtc },
) => {
  if (
    !Array.isArray(value) ||
    value.length !== 17 ||
    value.map(({ id }) => id).join('\0') !== exactIds('ART-REL', 17).join('\0')
  ) {
    fail('E7_OPERATIONAL_ARTIFACT_MATRIX_INVALID');
  }
  for (const row of value) validateProvenanceRow(row, { kind: 'artifact' });
  const expected = createOperationalArtifactRows({
    evidenceRows,
    ownerAlias,
    validatedAtUtc,
  });
  if (objectSha256(value) !== objectSha256(expected)) {
    fail('E7_OPERATIONAL_ARTIFACT_MATRIX_INVALID');
  }
  return value;
};

export const createEvidenceIndexCheckpoint = ({
  scope,
  candidateSha,
  releaseId,
  releaseTag,
  ownerAlias,
  generatedAtUtc,
  evidenceRows,
}) => {
  assertIdentity({ scope, candidateSha, releaseId, releaseTag });
  if (!ALIAS.test(ownerAlias ?? '') || !utc(generatedAtUtc)) {
    fail('E7_EVIDENCE_INDEX_IDENTITY_INVALID');
  }
  if (
    evidenceRows.length !== 57 ||
    evidenceRows.map(({ id }) => id).join('\0') !== exactIds('EVD-E7', 57).join('\0')
  ) {
    fail('E7_EVIDENCE_INDEX_MATRIX_INCOMPLETE');
  }
  for (const row of evidenceRows) validateProvenanceRow(row, { kind: 'evidence' });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_EVIDENCE_INDEX_CHECKPOINT',
    status: 'VERIFIED',
    scope,
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    catalogSha256: objectSha256(STAGE7_EVIDENCE),
    evidenceCount: evidenceRows.length,
    statesSha256: objectSha256(
      evidenceRows.map(({ id, status, sources }) => ({
        id,
        status,
        sourceSha256: objectSha256(sources),
      })),
    ),
    evidence: evidenceRows,
    containsSensitiveData: false,
  };
  const value = { ...body, checkpointBodySha256: objectSha256(body) };
  validateEvidenceIndexCheckpoint(value, { evidenceRows });
  return value;
};

export const validateEvidenceIndexCheckpoint = (value, { evidenceRows }) => {
  if (
    !Array.isArray(evidenceRows) ||
    evidenceRows.length !== 57 ||
    evidenceRows.map(({ id }) => id).join('\0') !== exactIds('EVD-E7', 57).join('\0') ||
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'ownerAlias',
      'generatedAtUtc',
      'catalogSha256',
      'evidenceCount',
      'statesSha256',
      'evidence',
      'containsSensitiveData',
      'checkpointBodySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_EVIDENCE_INDEX_CHECKPOINT' ||
    value.status !== 'VERIFIED' ||
    value.catalogSha256 !== objectSha256(STAGE7_EVIDENCE) ||
    value.evidenceCount !== 57 ||
    objectSha256(value.evidence) !== objectSha256(evidenceRows) ||
    value.statesSha256 !==
      objectSha256(
        evidenceRows.map(({ id, status, sources }) => ({
          id,
          status,
          sourceSha256: objectSha256(sources),
        })),
      ) ||
    value.checkpointBodySha256 !==
      objectSha256(
        Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'checkpointBodySha256')),
      ) ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_EVIDENCE_INDEX_CHECKPOINT_INVALID');
  }
  assertIdentity(value);
  if (
    !ALIAS.test(value.ownerAlias ?? '') ||
    !utc(value.generatedAtUtc) ||
    evidenceRows.some(
      (row) => row.ownerAlias !== value.ownerAlias || row.validatedAtUtc !== value.generatedAtUtc,
    )
  ) {
    fail('E7_EVIDENCE_INDEX_CHECKPOINT_INVALID');
  }
  for (const row of evidenceRows) {
    validateEvidenceRowSourceRequirements({ scope: value.scope, row });
  }
  return value;
};

export const createGateEvaluationCheckpoint = ({
  scope,
  candidateSha,
  releaseId,
  releaseTag,
  ownerAlias,
  generatedAtUtc,
  entryGate,
  operationalArtifactRows,
  evidenceRows,
}) => {
  assertIdentity({ scope, candidateSha, releaseId, releaseTag });
  if (
    evidenceRows.length !== 54 ||
    evidenceRows.map(({ id }) => id).join('\0') !== exactIds('EVD-E7', 54).join('\0') ||
    evidenceRows.some(
      (row) => row.ownerAlias !== ownerAlias || row.validatedAtUtc !== generatedAtUtc,
    )
  ) {
    fail('E7_GATE_EVALUATION_EVIDENCE_MATRIX_INVALID');
  }
  for (const row of evidenceRows) validateEvidenceRowSourceRequirements({ scope, row });
  validateOperationalArtifactRows(operationalArtifactRows, {
    evidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
  });
  const artifactStates = Object.fromEntries(
    operationalArtifactRows.map(({ id, status }) => [id, status]),
  );
  const evidenceStates = Object.fromEntries(
    evidenceRows.slice(0, 54).map(({ id, status }) => [id, status]),
  );
  const index = createStage7Index({ entryGate, artifactStates, evidenceStates });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_GATE_EVALUATION_CHECKPOINT',
    status: Object.values(index.gates).includes('FAIL')
      ? 'FAILED'
      : index.gates['GATE-E7-03'] === 'PASS'
        ? 'VERIFIED'
        : index.gates['GATE-E7-03'] === 'BLOCKED_AUTH'
          ? 'BLOCKED_AUTH'
          : 'IN_PROGRESS',
    scope,
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    entryGate,
    operationalArtifactsSha256: objectSha256(operationalArtifactRows),
    evidenceStatesSha256: objectSha256(evidenceStates),
    gates: index.gates,
    containsSensitiveData: false,
  };
  const value = { ...body, checkpointBodySha256: objectSha256(body) };
  validateGateEvaluationCheckpoint(value, {
    entryGate,
    operationalArtifactRows,
    evidenceRows,
  });
  return value;
};

export const validateGateEvaluationCheckpoint = (
  value,
  { entryGate, operationalArtifactRows, evidenceRows },
) => {
  if (
    evidenceRows.length !== 54 ||
    evidenceRows.map(({ id }) => id).join('\0') !== exactIds('EVD-E7', 54).join('\0') ||
    evidenceRows.some(
      (row) => row.ownerAlias !== value?.ownerAlias || row.validatedAtUtc !== value?.generatedAtUtc,
    )
  ) {
    fail('E7_GATE_EVALUATION_EVIDENCE_MATRIX_INVALID');
  }
  for (const row of evidenceRows) {
    validateEvidenceRowSourceRequirements({ scope: value?.scope, row });
  }
  validateOperationalArtifactRows(operationalArtifactRows, {
    evidenceRows,
    ownerAlias: value?.ownerAlias,
    validatedAtUtc: value?.generatedAtUtc,
  });
  const artifactStates = Object.fromEntries(
    operationalArtifactRows.map(({ id, status }) => [id, status]),
  );
  const evidenceStates = Object.fromEntries(
    evidenceRows.slice(0, 54).map(({ id, status }) => [id, status]),
  );
  const index = createStage7Index({ entryGate, artifactStates, evidenceStates });
  const expectedStatus = Object.values(index.gates).includes('FAIL')
    ? 'FAILED'
    : index.gates['GATE-E7-03'] === 'PASS'
      ? 'VERIFIED'
      : index.gates['GATE-E7-03'] === 'BLOCKED_AUTH'
        ? 'BLOCKED_AUTH'
        : 'IN_PROGRESS';
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'ownerAlias',
      'generatedAtUtc',
      'entryGate',
      'operationalArtifactsSha256',
      'evidenceStatesSha256',
      'gates',
      'containsSensitiveData',
      'checkpointBodySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_GATE_EVALUATION_CHECKPOINT' ||
    value.status !== expectedStatus ||
    value.entryGate !== entryGate ||
    value.operationalArtifactsSha256 !== objectSha256(operationalArtifactRows) ||
    value.evidenceStatesSha256 !== objectSha256(evidenceStates) ||
    objectSha256(value.gates) !== objectSha256(index.gates) ||
    value.checkpointBodySha256 !==
      objectSha256(
        Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'checkpointBodySha256')),
      ) ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_GATE_EVALUATION_CHECKPOINT_INVALID');
  }
  assertIdentity(value);
  if (!ALIAS.test(value.ownerAlias ?? '') || !utc(value.generatedAtUtc)) {
    fail('E7_GATE_EVALUATION_CHECKPOINT_INVALID');
  }
  return value;
};

export const createAuthorityArtifactRows = ({
  evidenceRows,
  ownerAlias,
  validatedAtUtc,
  operationalArtifactRows,
  evidenceIndexCheckpoint,
  evidenceIndexSource,
  gateEvaluationCheckpoint,
  gateEvaluationSource,
  entryGate,
}) => {
  const byId = new Map(evidenceRows.map((row) => [row.id, row]));
  if (
    evidenceRows.length !== 57 ||
    byId.size !== 57 ||
    !exactIds('EVD-E7', 57).every((id) => byId.has(id))
  ) {
    fail('E7_PROVENANCE_EVIDENCE_MATRIX_INCOMPLETE');
  }
  validateOperationalArtifactRows(operationalArtifactRows, {
    evidenceRows: evidenceRows.slice(0, 54),
    ownerAlias,
    validatedAtUtc,
  });
  validateEvidenceIndexCheckpoint(evidenceIndexCheckpoint, { evidenceRows });
  validateGateEvaluationCheckpoint(gateEvaluationCheckpoint, {
    entryGate,
    operationalArtifactRows,
    evidenceRows: evidenceRows.slice(0, 54),
  });
  validateBoundSourceReference({
    scope: evidenceIndexCheckpoint.scope,
    basename: 'evidence-index-checkpoint.json',
    source: evidenceIndexSource,
  });
  validateBoundSourceReference({
    scope: gateEvaluationCheckpoint.scope,
    basename: 'gate-evaluation.json',
    source: gateEvaluationSource,
  });
  if (
    !sameIdentity(evidenceIndexCheckpoint, gateEvaluationCheckpoint) ||
    evidenceIndexCheckpoint.ownerAlias !== ownerAlias ||
    evidenceIndexCheckpoint.generatedAtUtc !== validatedAtUtc ||
    gateEvaluationCheckpoint.ownerAlias !== ownerAlias ||
    gateEvaluationCheckpoint.generatedAtUtc !== validatedAtUtc
  ) {
    fail('E7_AUTHORITY_CHECKPOINT_IDENTITY_INVALID');
  }
  const rows = [...operationalArtifactRows];
  rows.push(
    createProvenanceRow({
      ...STAGE7_ARTIFACTS[17],
      status: 'VERIFIED',
      ownerAlias,
      validatedAtUtc,
      validator: 'validateCompleteProvenanceMatrix',
      sources: [evidenceIndexSource],
    }),
    createProvenanceRow({
      ...STAGE7_ARTIFACTS[18],
      status: artifactStatusFromGate(gateEvaluationCheckpoint.gates['GATE-E7-03']),
      ownerAlias,
      validatedAtUtc,
      validator: 'deriveStage7Gates',
      sources: [gateEvaluationSource],
    }),
  );
  return rows;
};

export const createArtifactRows = ({
  authorityArtifactRows,
  evidenceRows,
  ownerAlias,
  validatedAtUtc,
  operationalArtifactRows,
  evidenceIndexCheckpoint,
  evidenceIndexSource,
  gateEvaluationCheckpoint,
  gateEvaluationSource,
  entryGate,
  handoff,
  handoffSource,
}) => {
  const expectedAuthorityRows = createAuthorityArtifactRows({
    evidenceRows,
    ownerAlias,
    validatedAtUtc,
    operationalArtifactRows,
    evidenceIndexCheckpoint,
    evidenceIndexSource,
    gateEvaluationCheckpoint,
    gateEvaluationSource,
    entryGate,
  });
  if (objectSha256(authorityArtifactRows) !== objectSha256(expectedAuthorityRows)) {
    fail('E7_AUTHORITY_ARTIFACT_MATRIX_INVALID');
  }
  validateStage7Handoff(handoff);
  validateBoundSourceReference({
    scope: handoff.scope,
    basename: 'handoff-payload.json',
    source: handoffSource,
  });
  const expectedHandoff = createStage7Handoff({
    scope: evidenceIndexCheckpoint.scope,
    candidateSha: evidenceIndexCheckpoint.candidateSha,
    releaseId: evidenceIndexCheckpoint.releaseId,
    releaseTag: evidenceIndexCheckpoint.releaseTag,
    ownerAlias,
    generatedAtUtc: validatedAtUtc,
    artifactRows: authorityArtifactRows,
    evidenceRows,
  });
  if (
    !sameIdentity(handoff, evidenceIndexCheckpoint) ||
    objectSha256(handoff) !== objectSha256(expectedHandoff)
  ) {
    fail('E7_HANDOFF_AUTHORITY_MISMATCH');
  }
  return [
    ...authorityArtifactRows,
    createProvenanceRow({
      ...STAGE7_ARTIFACTS[19],
      status:
        handoff.status === 'READY_FOR_STAGE8'
          ? 'VERIFIED'
          : handoff.status === 'FAIL'
            ? 'FAILED'
            : handoff.status === 'BLOCKED_AUTH'
              ? 'BLOCKED_AUTH'
              : 'IN_PROGRESS',
      ownerAlias,
      validatedAtUtc,
      validator: 'validateStage7Handoff',
      sources: [handoffSource],
    }),
  ];
};

const BASE_RUBRIC = Object.freeze([
  {
    id: 'RUB-E7-BASE-01',
    stage6Id: 'RUB-BASE-01',
    label: 'README correcto',
    max: 5,
    evidenceIds: ['EVD-E7-20', 'EVD-E7-51', 'EVD-E7-52'],
  },
  {
    id: 'RUB-E7-BASE-02',
    stage6Id: 'RUB-BASE-02',
    label: 'Imágenes rápidas y sin overflow',
    max: 5,
    evidenceIds: ['EVD-E7-42', 'EVD-E7-43', 'EVD-E7-44'],
  },
  {
    id: 'RUB-E7-BASE-03',
    stage6Id: 'RUB-BASE-03',
    label: 'Checkout completo',
    max: 20,
    evidenceIds: [
      'EVD-E7-35',
      'EVD-E7-36',
      'EVD-E7-37',
      'EVD-E7-38',
      'EVD-E7-39',
      'EVD-E7-40',
      'EVD-E7-41',
    ],
  },
  {
    id: 'RUB-E7-BASE-04',
    stage6Id: 'RUB-BASE-04',
    label: 'API correcta',
    max: 20,
    evidenceIds: [
      'EVD-E7-17',
      'EVD-E7-18',
      'EVD-E7-19',
      'EVD-E7-20',
      'EVD-E7-21',
      'EVD-E7-28',
      'EVD-E7-29',
      'EVD-E7-30',
    ],
  },
  {
    id: 'RUB-E7-BASE-05',
    stage6Id: 'RUB-BASE-05',
    label: 'Cobertura mayor a 80 %',
    max: 30,
    evidenceIds: ['EVD-E7-02', 'EVD-E7-03', 'EVD-E7-50', 'EVD-E7-52'],
  },
  {
    id: 'RUB-E7-BASE-06',
    stage6Id: 'RUB-BASE-06',
    label: 'App y API cloud',
    max: 20,
    evidenceIds: ['EVD-E7-14', 'EVD-E7-17', 'EVD-E7-22', 'EVD-E7-25'],
  },
]);
const BONUS_RUBRIC = Object.freeze([
  {
    id: 'RUB-E7-BONUS-01',
    stage6Id: 'RUB-BONUS-01',
    label: 'OWASP, HTTPS y headers',
    max: 5,
    evidenceIds: ['EVD-E7-25', 'EVD-E7-28', 'EVD-E7-29', 'EVD-E7-45', 'EVD-E7-50'],
  },
  {
    id: 'RUB-E7-BONUS-02',
    stage6Id: 'RUB-BONUS-02',
    label: 'Responsive y cross-browser',
    max: 5,
    evidenceIds: ['EVD-E7-42', 'EVD-E7-43', 'EVD-E7-44'],
  },
  {
    id: 'RUB-E7-BONUS-03',
    stage6Id: 'RUB-BONUS-03',
    label: 'CSS',
    max: 10,
    evidenceIds: ['EVD-E7-22', 'EVD-E7-26', 'EVD-E7-42', 'EVD-E7-44'],
  },
  {
    id: 'RUB-E7-BONUS-04',
    stage6Id: 'RUB-BONUS-04',
    label: 'Clean code',
    max: 10,
    evidenceIds: ['EVD-E7-03', 'EVD-E7-04', 'EVD-E7-50', 'EVD-E7-52'],
  },
  {
    id: 'RUB-E7-BONUS-05',
    stage6Id: 'RUB-BONUS-05',
    label: 'Hexagonal y Ports & Adapters',
    max: 10,
    evidenceIds: ['EVD-E7-02', 'EVD-E7-03', 'EVD-E7-08', 'EVD-E7-09'],
  },
  {
    id: 'RUB-E7-BONUS-06',
    stage6Id: 'RUB-BONUS-06',
    label: 'Railway Oriented Programming',
    max: 10,
    evidenceIds: ['EVD-E7-35', 'EVD-E7-36', 'EVD-E7-37', 'EVD-E7-38', 'EVD-E7-39', 'EVD-E7-40'],
  },
]);

const scorecardRows = ({ definitions, stage6Rubric, evidenceById }) =>
  definitions.map((definition) => {
    const stage6 = stage6Rubric.results.find(({ id }) => id === definition.stage6Id);
    const stage7Statuses = definition.evidenceIds.map((id) => evidenceById.get(id)?.status);
    const traced =
      stage6?.status === 'PASS' && stage7Statuses.every((status) => evidenceSatisfied(status));
    const traceStatus = traced
      ? 'TRACED'
      : stage6?.status === 'FAIL' || stage7Statuses.includes('FAIL')
        ? 'FAIL'
        : stage6?.status === 'BLOCKED_AUTH' || stage7Statuses.includes('BLOCKED_AUTH')
          ? 'BLOCKED_AUTH'
          : 'IN_PROGRESS';
    return {
      id: definition.id,
      label: definition.label,
      potentialPoints: definition.max,
      potentialPointsTraced: traced ? definition.max : 0,
      traceStatus,
      stage6RubricId: definition.stage6Id,
      stage7EvidenceIds: definition.evidenceIds,
      awardedPoints: null,
    };
  });

const scorecardStatus = (rows) =>
  rows.every(({ traceStatus }) => traceStatus === 'TRACED')
    ? 'TRACEABILITY_COMPLETE'
    : rows.some(({ traceStatus }) => traceStatus === 'FAIL')
      ? 'FAILED'
      : rows.some(({ traceStatus }) => traceStatus === 'BLOCKED_AUTH')
        ? 'BLOCKED_AUTH'
        : 'IN_PROGRESS';

const validateScorecardEvidenceRows = ({ scope, evidenceRows }) => {
  const expected = exactIds('EVD-E7', 52);
  if (
    !['full', 'prerelease'].includes(scope) ||
    !Array.isArray(evidenceRows) ||
    evidenceRows.length !== expected.length ||
    evidenceRows.map(({ id }) => id).join('\0') !== expected.join('\0')
  ) {
    fail('E7_SCORECARD_EVIDENCE_MATRIX_INVALID');
  }
  for (const row of evidenceRows) validateEvidenceRowSourceRequirements({ scope, row });
  return evidenceRows;
};

export const createStage7Scorecard = ({
  scope,
  candidateSha,
  releaseId,
  releaseTag,
  ownerAlias,
  generatedAtUtc,
  stage6Closeout,
  stage6CloseoutSha256,
  evidenceRows,
}) => {
  assertIdentity({ scope, candidateSha, releaseId, releaseTag });
  validateScorecardEvidenceRows({ scope, evidenceRows });
  if (
    !ALIAS.test(ownerAlias ?? '') ||
    !utc(generatedAtUtc) ||
    !SHA256.test(stage6CloseoutSha256 ?? '') ||
    !Array.isArray(stage6Closeout?.evidence) ||
    !stage6RubricIsExact(stage6Closeout.rubric, stage6Closeout.evidence) ||
    stage6Closeout.candidate?.commitSha !== candidateSha
  ) {
    fail('E7_SCORECARD_STAGE6_SOURCE_INVALID');
  }
  const recomputedStage6Rubric = calculateStage6Rubric(stage6Closeout.evidence);
  const evidenceById = new Map(evidenceRows.map((row) => [row.id, row]));
  const baseRows = scorecardRows({
    definitions: BASE_RUBRIC,
    stage6Rubric: recomputedStage6Rubric,
    evidenceById,
  });
  const bonusRows = scorecardRows({
    definitions: BONUS_RUBRIC,
    stage6Rubric: recomputedStage6Rubric,
    evidenceById,
  });
  const total = (rows, field) => rows.reduce((sum, row) => sum + row[field], 0);
  const value = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RUBRIC_TRACEABILITY_SCORECARD',
    status: scorecardStatus(baseRows),
    scope,
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    stage6: {
      closeoutSha256: stage6CloseoutSha256,
      runId: stage6Closeout.runId,
      gate: stage6Closeout.gates?.['GATE-E6-03'],
      rubricSha256: objectSha256(recomputedStage6Rubric),
    },
    base: {
      potentialPointsTraced: total(baseRows, 'potentialPointsTraced'),
      potentialPointsTotal: total(baseRows, 'potentialPoints'),
      rows: baseRows,
    },
    bonus: {
      potentialPointsTraced: total(bonusRows, 'potentialPointsTraced'),
      potentialPointsTotal: total(bonusRows, 'potentialPoints'),
      rows: bonusRows,
    },
    evaluation: {
      awardedPointsAssigned: false,
      awardedPoints: null,
      reservedForStage: 8,
      rule: 'STAGE7_TRACES_POTENTIAL_POINTS_AND_DOES_NOT_SELF_GRADE',
    },
    containsSensitiveData: false,
  };
  validateStage7Scorecard(value, { stage6Closeout, evidenceRows });
  return value;
};

export const validateStage7Scorecard = (value, { stage6Closeout, evidenceRows }) => {
  validateScorecardEvidenceRows({ scope: value?.scope, evidenceRows });
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'ownerAlias',
      'generatedAtUtc',
      'stage6',
      'base',
      'bonus',
      'evaluation',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RUBRIC_TRACEABILITY_SCORECARD' ||
    !['TRACEABILITY_COMPLETE', 'FAILED', 'BLOCKED_AUTH', 'IN_PROGRESS'].includes(value.status) ||
    !exactKeys(value.stage6, ['closeoutSha256', 'runId', 'gate', 'rubricSha256']) ||
    !SHA256.test(value.stage6?.closeoutSha256 ?? '') ||
    value.stage6?.runId !== stage6Closeout.runId ||
    value.stage6?.rubricSha256 !== objectSha256(stage6Closeout.rubric) ||
    !exactKeys(value.base, ['potentialPointsTraced', 'potentialPointsTotal', 'rows']) ||
    !exactKeys(value.bonus, ['potentialPointsTraced', 'potentialPointsTotal', 'rows']) ||
    !exactKeys(value.evaluation, [
      'awardedPointsAssigned',
      'awardedPoints',
      'reservedForStage',
      'rule',
    ]) ||
    value.containsSensitiveData !== false ||
    value.evaluation?.awardedPointsAssigned !== false ||
    value.evaluation?.awardedPoints !== null ||
    value.evaluation?.reservedForStage !== 8 ||
    value.evaluation?.rule !== 'STAGE7_TRACES_POTENTIAL_POINTS_AND_DOES_NOT_SELF_GRADE' ||
    value.base?.potentialPointsTotal !== 100 ||
    value.bonus?.potentialPointsTotal !== 50 ||
    value.stage6?.gate !== stage6Closeout.gates?.['GATE-E6-03'] ||
    !stage6RubricIsExact(stage6Closeout.rubric, stage6Closeout.evidence)
  ) {
    fail('E7_SCORECARD_INVALID');
  }
  assertIdentity(value);
  if (!ALIAS.test(value.ownerAlias ?? '') || !utc(value.generatedAtUtc)) {
    fail('E7_SCORECARD_IDENTITY_INVALID');
  }
  const evidenceById = new Map(evidenceRows.map((row) => [row.id, row]));
  const expectedBase = scorecardRows({
    definitions: BASE_RUBRIC,
    stage6Rubric: stage6Closeout.rubric,
    evidenceById,
  });
  const expectedBonus = scorecardRows({
    definitions: BONUS_RUBRIC,
    stage6Rubric: stage6Closeout.rubric,
    evidenceById,
  });
  if (
    objectSha256(value.base.rows) !== objectSha256(expectedBase) ||
    objectSha256(value.bonus.rows) !== objectSha256(expectedBonus) ||
    value.base.potentialPointsTraced !==
      expectedBase.reduce((sum, row) => sum + row.potentialPointsTraced, 0) ||
    value.bonus.potentialPointsTraced !==
      expectedBonus.reduce((sum, row) => sum + row.potentialPointsTraced, 0) ||
    value.status !== scorecardStatus(expectedBase)
  ) {
    fail('E7_SCORECARD_DERIVATION_INVALID');
  }
  return value;
};

const CLEANUP_RESOURCE_CLASSES = [
  'CloudFormation stacks',
  'S3 buckets and objects',
  'DynamoDB tables and backups',
  'CloudFront distributions',
  'Certificates',
  'DNS records and hosted zones',
  'CloudWatch log groups',
  'CloudWatch alarms and SNS topics',
  'AWS Budgets',
  'GitHub OIDC roles',
  'CDK bootstrap resources',
  'CDK assets',
  'Resources with RETAIN',
  'Exceptional manual resources',
];
const CLEANUP_ORDER = [
  'Unpublish links and documentation after separate authorization',
  'Disable the scheduler',
  'Preserve approved evidence and backups',
  'Remove DNS and custom-domain bindings',
  'Disable and dispose CloudFront',
  'Remove WebStack',
  'Remove ApiStack',
  'Remove ObservabilityStack',
  'Remove DataStack only under the approved data policy',
  'Remove OIDC roles only when no workflow consumes them',
  'Keep CDK bootstrap unless separately approved',
  'Verify residual resources and cost',
];
const resourceDisposition = (resourceClass) =>
  resourceClass === 'CDK bootstrap resources'
    ? 'EXCLUDED_BY_DEFAULT'
    : resourceClass === 'DynamoDB tables and backups' || resourceClass === 'Resources with RETAIN'
      ? 'SEPARATE_DATA_OR_RETENTION_APPROVAL_REQUIRED'
      : 'INVENTORY_AND_REMOVE_WHEN_AUTHORIZED';

const FULL_ROLLBACK_COMMANDS = Object.freeze([
  [
    'node scripts/stage7/aws-ops.mjs execute-versioned-rollback',
    '--app .stage7/candidate/iac',
    '--manifest .stage7/candidate-manifest/candidate-manifest.json',
    '--previous-manifest .stage7/previous/previous-release-manifest.json',
    '--previous-api-contract-evidence .stage7/previous/previous-api-contract-evidence.json',
    '--previous-pending-evidence .stage7/previous/previous-pending-evidence.json',
    '--previous-smoke-evidence .stage7/previous/previous-smoke-evidence.json',
    '--candidate-record output/evidence/runtime/stage-7/versioned-rollback-candidate.json',
    '--approval .stage7/approval/approval.json',
    '--aws-auth .stage7/aws-auth/aws-auth.json',
    '--approved-plan .stage7/infra-diff/infra-diff.json',
    '--deployment-evidence .stage7/web/web.json',
    '--direction ROLLBACK_TO_PREVIOUS',
    '--output output/evidence/runtime/stage-7/versioned-rollback-aws-transition.json',
  ].join(' '),
  [
    'pnpm release:smoke -- --scope full --post-versioned-rollback',
    '--previous-manifest .stage7/previous/previous-release-manifest.json',
    '--candidate-record output/evidence/runtime/stage-7/versioned-rollback-candidate.json',
    '--rollback-evidence output/evidence/runtime/stage-7/rollback.json',
    '--transition output/evidence/runtime/stage-7/versioned-rollback-aws-transition.json',
    '--manifest .stage7/candidate-manifest/candidate-manifest.json',
    '--evidence output/evidence/runtime/stage-7/versioned-rollback-smoke.json',
  ].join(' '),
  [
    'node scripts/stage7/aws-ops.mjs finalize-versioned-rollback',
    '--app .stage7/candidate/iac',
    '--manifest .stage7/candidate-manifest/candidate-manifest.json',
    '--previous-manifest .stage7/previous/previous-release-manifest.json',
    '--previous-api-contract-evidence .stage7/previous/previous-api-contract-evidence.json',
    '--previous-pending-evidence .stage7/previous/previous-pending-evidence.json',
    '--previous-smoke-evidence .stage7/previous/previous-smoke-evidence.json',
    '--candidate-record output/evidence/runtime/stage-7/versioned-rollback-candidate.json',
    '--approval .stage7/approval/approval.json',
    '--aws-auth .stage7/aws-auth/aws-auth.json',
    '--approved-plan .stage7/infra-diff/infra-diff.json',
    '--deployment-evidence .stage7/web/web.json',
    '--transition output/evidence/runtime/stage-7/versioned-rollback-aws-transition.json',
    '--smoke-evidence output/evidence/runtime/stage-7/versioned-rollback-smoke.json',
    '--output output/evidence/runtime/stage-7/versioned-rollback-checkpoint.json',
  ].join(' '),
]);
const PRERELEASE_ROLLBACK_COMMANDS = Object.freeze([
  'pnpm release:rollback:api -- --scope prerelease --record "${STAGE7_API_ROLLBACK_RECORD}" --initial-release --to-disabled',
  'pnpm release:rollback:web -- --scope prerelease --record "${STAGE7_WEB_ROLLBACK_RECORD}" --initial-release --to-unpublished',
]);
const FULL_OPERATION_ENVIRONMENT = Object.freeze([
  'STAGE7_CONFIG',
  'STAGE7_CANDIDATE_SHA',
  'STAGE7_RELEASE_ID',
  'STAGE7_RELEASE_TAG',
  'STAGE7_EXTERNAL_AUTHORIZATIONS',
]);
const PRERELEASE_OPERATION_ENVIRONMENT = Object.freeze([
  'STAGE7_CONFIG',
  'STAGE7_CANDIDATE_SHA',
  'STAGE7_RELEASE_ID',
]);
const rollbackContract = (scope) =>
  scope === 'full'
    ? {
        workflowPath: '.github/workflows/release.yml',
        job: 'rollback-check',
        execution: 'PROTECTED_VERSIONED_ROLLBACK',
        requiredEnvironmentVariables: [...FULL_OPERATION_ENVIRONMENT],
        commands: [...FULL_ROLLBACK_COMMANDS],
      }
    : {
        workflowPath: '.github/workflows/prerelease.yml',
        job: 'cleanup',
        execution: 'PROTECTED_INITIAL_DISABLE_AND_UNPUBLISH',
        requiredEnvironmentVariables: [
          ...PRERELEASE_OPERATION_ENVIRONMENT,
          'STAGE7_API_ROLLBACK_RECORD',
          'STAGE7_WEB_ROLLBACK_RECORD',
        ],
        commands: [...PRERELEASE_ROLLBACK_COMMANDS],
      };
const cleanupContract = (scope, cleanupVerified) =>
  scope === 'prerelease'
    ? {
        authorizationRequired: true,
        cleanupVerified,
        workflowPath: '.github/workflows/prerelease.yml',
        job: 'cleanup',
        execution: 'PROTECTED_EPHEMERAL_CLEANUP',
        requiredEnvironmentVariables: [...PRERELEASE_OPERATION_ENVIRONMENT, 'CLEANUP_CONFIRM'],
        command:
          'pnpm release:cleanup -- --scope prerelease --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json --execute --ephemeral-only --confirm "${CLEANUP_CONFIRM}"',
        finalCheck: 'VERIFY_RESIDUAL_RESOURCES_AND_COST',
      }
    : {
        authorizationRequired: true,
        cleanupVerified,
        workflowPath: null,
        job: null,
        execution: 'NOT_AUTOMATED_REQUIRES_SEPARATE_AUTHORIZATION',
        requiredEnvironmentVariables: [],
        command: null,
        finalCheck: 'VERIFY_RESIDUAL_RESOURCES_AND_COST',
      };

export const createStage7OperationsRunbook = ({
  scope,
  candidateSha,
  releaseId,
  releaseTag,
  ownerAlias,
  generatedAtUtc,
  expiresAtUtc,
  environment,
  stacks,
  budgetMaxUsd,
  cleanupVerified,
  sourceSha256,
}) => {
  assertIdentity({ scope, candidateSha, releaseId, releaseTag });
  if (
    !ALIAS.test(ownerAlias ?? '') ||
    !utc(generatedAtUtc) ||
    !utc(expiresAtUtc) ||
    Date.parse(expiresAtUtc) <= Date.parse(generatedAtUtc) ||
    !/^[a-z][a-z0-9-]{2,63}$/u.test(environment ?? '') ||
    !Array.isArray(stacks) ||
    stacks.length !== 4 ||
    new Set(stacks).size !== 4 ||
    stacks.toSorted().join('\0') !==
      ['api', 'data', 'observability', 'web']
        .map((suffix) => `checkout-${environment}-${suffix}`)
        .toSorted()
        .join('\0') ||
    typeof budgetMaxUsd !== 'number' ||
    !Number.isFinite(budgetMaxUsd) ||
    budgetMaxUsd <= 0 ||
    typeof cleanupVerified !== 'boolean' ||
    !SHA256.test(sourceSha256 ?? '')
  ) {
    fail('E7_OPERATIONS_RUNBOOK_INPUT_INVALID');
  }
  const value = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_OPERATIONS_RUNBOOK',
    status: cleanupVerified ? 'CLEANUP_VERIFIED' : 'REVIEWED_NOT_EXECUTED',
    scope,
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    reviewedAtUtc: generatedAtUtc,
    expiresAtUtc,
    environment,
    budget: { maxUsd: budgetMaxUsd, residualCostReviewRequired: true },
    resources: CLEANUP_RESOURCE_CLASSES.map((resourceClass) => ({
      resourceClass,
      disposition: resourceDisposition(resourceClass),
    })),
    stackOrder: ['web', 'api', 'observability', 'data'].map((suffix) => {
      const stack = stacks.find((candidate) => candidate.endsWith(`-${suffix}`));
      if (stack === undefined) fail('E7_OPERATIONS_RUNBOOK_STACK_SET_INVALID');
      return stack;
    }),
    destructionOrder: CLEANUP_ORDER.map((instruction, index) => ({ step: index + 1, instruction })),
    rollback: {
      preservePreviousReleaseAssets: true,
      preserveActiveVersionAssets: true,
      dataPolicy: 'FORWARD_ONLY_UNLESS_SEPARATELY_AUTHORIZED',
      ...rollbackContract(scope),
    },
    cleanup: cleanupContract(scope, cleanupVerified),
    sourceSha256,
    containsSensitiveData: false,
  };
  validateStage7OperationsRunbook(value);
  return value;
};

export const validateStage7OperationsRunbook = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'ownerAlias',
      'reviewedAtUtc',
      'expiresAtUtc',
      'environment',
      'budget',
      'resources',
      'stackOrder',
      'destructionOrder',
      'rollback',
      'cleanup',
      'sourceSha256',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_OPERATIONS_RUNBOOK' ||
    !['CLEANUP_VERIFIED', 'REVIEWED_NOT_EXECUTED'].includes(value.status) ||
    !['full', 'prerelease'].includes(value.scope) ||
    !ALIAS.test(value.ownerAlias ?? '') ||
    !utc(value.reviewedAtUtc) ||
    !utc(value.expiresAtUtc) ||
    Date.parse(value.expiresAtUtc) <= Date.parse(value.reviewedAtUtc) ||
    !/^[a-z][a-z0-9-]{2,63}$/u.test(value.environment ?? '') ||
    !exactKeys(value.budget, ['maxUsd', 'residualCostReviewRequired']) ||
    typeof value.budget?.maxUsd !== 'number' ||
    !Number.isFinite(value.budget.maxUsd) ||
    value.budget.maxUsd <= 0 ||
    value.budget.residualCostReviewRequired !== true ||
    value.resources?.length !== CLEANUP_RESOURCE_CLASSES.length ||
    value.resources.some(
      (resource, index) =>
        !exactKeys(resource, ['resourceClass', 'disposition']) ||
        resource.resourceClass !== CLEANUP_RESOURCE_CLASSES[index] ||
        resource.disposition !== resourceDisposition(resource.resourceClass),
    ) ||
    value.stackOrder?.length !== 4 ||
    new Set(value.stackOrder).size !== 4 ||
    value.stackOrder.toSorted().join('\0') !==
      ['api', 'data', 'observability', 'web']
        .map((suffix) => `checkout-${value.environment}-${suffix}`)
        .toSorted()
        .join('\0') ||
    value.destructionOrder?.length !== CLEANUP_ORDER.length ||
    value.destructionOrder.some(
      (entry, index) =>
        !exactKeys(entry, ['step', 'instruction']) ||
        entry.step !== index + 1 ||
        entry.instruction !== CLEANUP_ORDER[index],
    ) ||
    !exactKeys(value.rollback, [
      'preservePreviousReleaseAssets',
      'preserveActiveVersionAssets',
      'dataPolicy',
      'workflowPath',
      'job',
      'execution',
      'requiredEnvironmentVariables',
      'commands',
    ]) ||
    value.rollback?.preservePreviousReleaseAssets !== true ||
    value.rollback?.preserveActiveVersionAssets !== true ||
    value.rollback?.dataPolicy !== 'FORWARD_ONLY_UNLESS_SEPARATELY_AUTHORIZED' ||
    objectSha256({
      workflowPath: value.rollback?.workflowPath,
      job: value.rollback?.job,
      execution: value.rollback?.execution,
      requiredEnvironmentVariables: value.rollback?.requiredEnvironmentVariables,
      commands: value.rollback?.commands,
    }) !== objectSha256(rollbackContract(value.scope)) ||
    value.stackOrder?.map((stack) => stack.slice(stack.lastIndexOf('-') + 1)).join('\0') !==
      ['web', 'api', 'observability', 'data'].join('\0') ||
    !exactKeys(value.cleanup, [
      'authorizationRequired',
      'cleanupVerified',
      'workflowPath',
      'job',
      'execution',
      'requiredEnvironmentVariables',
      'command',
      'finalCheck',
    ]) ||
    value.cleanup?.authorizationRequired !== true ||
    value.cleanup?.cleanupVerified !== (value.status === 'CLEANUP_VERIFIED') ||
    objectSha256(value.cleanup) !==
      objectSha256(cleanupContract(value.scope, value.status === 'CLEANUP_VERIFIED')) ||
    value.cleanup?.finalCheck !== 'VERIFY_RESIDUAL_RESOURCES_AND_COST' ||
    !SHA256.test(value.sourceSha256 ?? '') ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_OPERATIONS_RUNBOOK_INVALID');
  }
  assertIdentity(value);
  return value;
};

const HANDOFF_LABELS = [
  'Executed Stage 7 report',
  'GATE-E7-01, GATE-E7-02 and GATE-E7-03',
  'Release ID, SHA, tag and checksums',
  'Public SPA URL',
  'Public API URL',
  'Public Swagger/OpenAPI URL',
  'Health endpoint',
  'Public repository link',
  'Updated README',
  'Release notes',
  'Deployed architecture',
  'Sanitized CloudFormation outputs',
  'Stack and resource manifest',
  'OIDC/IAM evidence',
  'Private S3 and OAC evidence',
  'TLS, headers and CORS evidence',
  'DataStack and seed evidence',
  'API, Lambda and reconciler evidence',
  'Logs, metrics, alarms and dashboard',
  'Budget and cleanup owner',
  '18 of 18 smoke cases',
  'Sandbox smoke',
  'Focal cross-browser, accessibility and performance',
  'DAST and edge security',
  'Frontend rollback',
  'API rollback',
  'Pending transaction state',
  'Re-promotion and final smoke',
  'Tree and history secret scan',
  'Traceability matrix',
  '100-point base and bonus scorecard',
  'Defects and residual risks',
  'Approved deviations',
  'Rollback runbook',
  'Cleanup runbook',
  'Environment expiry date',
  'Complete evidence index',
];
const H = (number) => `EVD-E7-${String(number).padStart(2, '0')}`;
const HANDOFF_DEPENDENCIES = [
  ['ART-REL-18', 'ART-REL-19'],
  [H(55), H(56), H(57)],
  [H(2), H(3), H(4)],
  [H(22), H(25), H(51)],
  [H(17), H(19), H(51)],
  [H(20), H(51)],
  [H(19), H(51)],
  [H(50), H(51), H(52)],
  [H(51)],
  [H(51)],
  [H(9), H(14), H(17), H(22)],
  [H(14), H(17), H(22)],
  [H(9), H(14), H(17), H(22)],
  [H(5), H(6), H(7), H(12)],
  [H(23), H(24)],
  [H(25), H(28), H(29)],
  [H(14), H(15), H(16)],
  [H(17), H(18), H(19), H(20), H(21)],
  [H(31), H(32), H(33)],
  [H(34), H(54)],
  [H(35), H(36), H(37), H(38), H(39), H(40)],
  [H(41)],
  [H(42), H(43), H(44)],
  [H(29), H(45)],
  [H(46)],
  [H(47)],
  [H(48)],
  [H(49)],
  [H(50), H(52)],
  ['ART-REL-18'],
  [H(53)],
  [H(50), H(53), H(54)],
  [H(1), H(10), H(11), H(12)],
  [H(46), H(47), H(48), H(49), H(54)],
  [H(54)],
  [H(54)],
  ['ART-REL-18', H(55), H(56), H(57)],
];

const handoffState = (rows) => {
  const states = rows.map(({ status }) => status);
  if (states.some((status) => ['FAIL', 'FAILED'].includes(status))) return 'FAIL';
  if (states.some((status) => status === 'BLOCKED_AUTH')) return 'BLOCKED_AUTH';
  if (
    rows.every((row) =>
      row.id.startsWith('ART-REL') ? artifactSatisfied(row.status) : evidenceSatisfied(row.status),
    )
  )
    return 'READY';
  return 'NOT_RUN';
};

export const createStage7Handoff = ({
  scope,
  candidateSha,
  releaseId,
  releaseTag,
  ownerAlias,
  generatedAtUtc,
  artifactRows,
  evidenceRows,
}) => {
  assertIdentity({ scope, candidateSha, releaseId, releaseTag });
  if (
    artifactRows.length !== 19 ||
    artifactRows.map(({ id }) => id).join('\0') !== exactIds('ART-REL', 19).join('\0') ||
    evidenceRows.length !== 57 ||
    evidenceRows.map(({ id }) => id).join('\0') !== exactIds('EVD-E7', 57).join('\0') ||
    !ALIAS.test(ownerAlias ?? '') ||
    !utc(generatedAtUtc) ||
    [...artifactRows, ...evidenceRows].some(
      (row) => row.ownerAlias !== ownerAlias || row.validatedAtUtc !== generatedAtUtc,
    )
  ) {
    fail('E7_HANDOFF_AUTHORITY_MATRIX_INVALID');
  }
  for (const [index, row] of artifactRows.entries()) {
    validateProvenanceRow(row, { kind: 'artifact' });
    if (row.name !== STAGE7_ARTIFACTS[index].name) fail('E7_HANDOFF_AUTHORITY_MATRIX_INVALID');
    for (const source of row.sources) {
      validateBoundSourceReference({
        scope,
        basename: pathBasename(source.path),
        source,
      });
    }
  }
  for (const [index, row] of evidenceRows.entries()) {
    validateEvidenceRowSourceRequirements({ scope, row });
    if (row.name !== STAGE7_EVIDENCE[index].name) fail('E7_HANDOFF_AUTHORITY_MATRIX_INVALID');
  }
  validateOperationalArtifactRows(artifactRows.slice(0, 17), {
    evidenceRows: evidenceRows.slice(0, 54),
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
  });
  if (
    artifactRows[17].status !== 'VERIFIED' ||
    artifactRows[18].status !== artifactStatusFromGate(evidenceRows[56].status)
  ) {
    fail('E7_HANDOFF_AUTHORITY_MATRIX_INVALID');
  }
  const byId = new Map([...artifactRows, ...evidenceRows].map((row) => [row.id, row]));
  const items = HANDOFF_LABELS.map((label, index) => {
    const dependencies = HANDOFF_DEPENDENCIES[index].map((id) => byId.get(id));
    if (dependencies.some((row) => row === undefined)) fail('E7_HANDOFF_DEPENDENCY_MISSING');
    return {
      number: index + 1,
      label,
      status: handoffState(dependencies),
      dependencyIds: HANDOFF_DEPENDENCIES[index],
      sources: sourceUnion(dependencies),
    };
  });
  const value = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_HANDOFF_TO_STAGE8',
    status: items.some(({ status }) => status === 'FAIL')
      ? 'FAIL'
      : items.some(({ status }) => status === 'BLOCKED_AUTH')
        ? 'BLOCKED_AUTH'
        : items.every(({ status }) => status === 'READY')
          ? 'READY_FOR_STAGE8'
          : 'NOT_RUN',
    scope,
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    itemCount: items.length,
    readyCount: items.filter(({ status }) => status === 'READY').length,
    items,
    nextStage: items.every(({ status }) => status === 'READY') ? 8 : null,
    containsSensitiveData: false,
  };
  validateStage7Handoff(value);
  return value;
};

export const validateStage7Handoff = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'ownerAlias',
      'generatedAtUtc',
      'itemCount',
      'readyCount',
      'items',
      'nextStage',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_HANDOFF_TO_STAGE8' ||
    !['READY_FOR_STAGE8', 'BLOCKED_AUTH', 'NOT_RUN', 'FAIL'].includes(value.status) ||
    value.itemCount !== 37 ||
    value.items?.length !== 37 ||
    value.readyCount !== value.items.filter(({ status }) => status === 'READY').length ||
    value.items.some(
      (item, index) =>
        !exactKeys(item, ['number', 'label', 'status', 'dependencyIds', 'sources']) ||
        item.number !== index + 1 ||
        item.label !== HANDOFF_LABELS[index] ||
        !['READY', 'BLOCKED_AUTH', 'NOT_RUN', 'FAIL'].includes(item.status) ||
        item.dependencyIds?.join('\0') !== HANDOFF_DEPENDENCIES[index].join('\0') ||
        !Array.isArray(item.sources) ||
        item.sources.length < 1,
    ) ||
    (value.status === 'READY_FOR_STAGE8') !== (value.readyCount === 37) ||
    (value.status === 'FAIL') !== value.items.some(({ status }) => status === 'FAIL') ||
    (value.status === 'BLOCKED_AUTH') !==
      (!value.items.some(({ status }) => status === 'FAIL') &&
        value.items.some(({ status }) => status === 'BLOCKED_AUTH')) ||
    (value.status === 'NOT_RUN') !==
      (!value.items.some(({ status }) => ['FAIL', 'BLOCKED_AUTH'].includes(status)) &&
        value.items.some(({ status }) => status === 'NOT_RUN')) ||
    value.nextStage !== (value.status === 'READY_FOR_STAGE8' ? 8 : null) ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_HANDOFF_INVALID');
  }
  assertIdentity(value);
  if (!ALIAS.test(value.ownerAlias ?? '') || !utc(value.generatedAtUtc)) {
    fail('E7_HANDOFF_IDENTITY_INVALID');
  }
  for (const item of value.items)
    for (const source of item.sources) validateSourceReference(source);
  return value;
};

export const createJobResultsDocument = ({
  scope,
  candidateSha,
  releaseId,
  releaseTag,
  generatedAtUtc,
  runId,
  runAttempt,
  workflow,
  jobs,
}) => {
  const normalizedJobs = Array.isArray(jobs)
    ? jobs.map((job) => (typeof job === 'string' ? { id: job, result: 'success' } : job))
    : null;
  assertIdentity({ scope, candidateSha, releaseId, releaseTag });
  if (
    !utc(generatedAtUtc) ||
    !/^[1-9][0-9]{0,19}$/u.test(String(runId ?? '')) ||
    !Number.isSafeInteger(runAttempt) ||
    runAttempt < 1 ||
    typeof workflow !== 'string' ||
    workflow.length < 3 ||
    workflow.length > 128 ||
    !Array.isArray(normalizedJobs) ||
    normalizedJobs.length < 1 ||
    new Set(normalizedJobs.map(({ id }) => id)).size !== normalizedJobs.length ||
    normalizedJobs.some(
      (job) =>
        !exactKeys(job, ['id', 'result']) ||
        !/^[a-z0-9][a-z0-9-]{1,79}$/u.test(job.id ?? '') ||
        !['success', 'failure', 'cancelled', 'skipped'].includes(job.result),
    )
  ) {
    fail('E7_JOB_RESULTS_DOCUMENT_INPUT_INVALID');
  }
  const documentStatus = normalizedJobs.some(({ result }) =>
    ['failure', 'cancelled'].includes(result),
  )
    ? 'FAILED'
    : normalizedJobs.some(({ result }) => result === 'skipped')
      ? 'INCOMPLETE'
      : 'PASS';
  const value = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_EXACT_JOB_RESULTS',
    status: documentStatus,
    scope,
    candidateSha,
    releaseId,
    releaseTag,
    generatedAtUtc,
    runId: String(runId),
    runAttempt,
    workflow,
    jobs: normalizedJobs,
    containsSensitiveData: false,
  };
  validateJobResultsDocument(value, {
    expectedJobs: normalizedJobs.map(({ id }) => id),
    expectedIdentity: { scope, candidateSha, releaseId, releaseTag },
    expectedExecution: { runId: String(runId), runAttempt, workflow },
  });
  return value;
};

export const validateJobResultsDocument = (
  value,
  { expectedJobs, expectedIdentity, expectedExecution } = {},
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'generatedAtUtc',
      'runId',
      'runAttempt',
      'workflow',
      'jobs',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_EXACT_JOB_RESULTS' ||
    !['PASS', 'FAILED', 'INCOMPLETE'].includes(value.status) ||
    !object(expectedIdentity) ||
    value.scope !== expectedIdentity.scope ||
    value.candidateSha !== expectedIdentity.candidateSha ||
    value.releaseId !== expectedIdentity.releaseId ||
    value.releaseTag !== expectedIdentity.releaseTag ||
    !exactKeys(expectedExecution, ['runId', 'runAttempt', 'workflow']) ||
    value.runId !== expectedExecution.runId ||
    value.runAttempt !== expectedExecution.runAttempt ||
    value.workflow !== expectedExecution.workflow ||
    !Array.isArray(expectedJobs) ||
    expectedJobs.length < 1 ||
    new Set(expectedJobs).size !== expectedJobs.length ||
    expectedJobs.some((job) => !/^[a-z0-9][a-z0-9-]{1,79}$/u.test(job)) ||
    !utc(value.generatedAtUtc) ||
    !/^[1-9][0-9]{0,19}$/u.test(value.runId ?? '') ||
    !Number.isSafeInteger(value.runAttempt) ||
    value.runAttempt < 1 ||
    value.runAttempt > 100 ||
    typeof value.workflow !== 'string' ||
    value.workflow.length < 3 ||
    value.workflow.length > 128 ||
    value.jobs?.length !== expectedJobs.length ||
    value.jobs.some(
      (job, index) =>
        !exactKeys(job, ['id', 'result']) ||
        job.id !== expectedJobs[index] ||
        !['success', 'failure', 'cancelled', 'skipped'].includes(job.result),
    ) ||
    value.status !==
      (value.jobs.some(({ result }) => ['failure', 'cancelled'].includes(result))
        ? 'FAILED'
        : value.jobs.some(({ result }) => result === 'skipped')
          ? 'INCOMPLETE'
          : 'PASS') ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_JOB_RESULTS_DOCUMENT_INVALID');
  }
  assertIdentity(value);
  return value;
};

const compositeLogicalJobResults = (authority) =>
  RELEASE_SUCCESSOR_COMPOSITE_GATE_JOB_IDS.map((id) => {
    const recovered =
      (id === 'release-successor-fence' &&
        authority.source.crashWindow === 'FENCE_DURABLE_SOURCE_ARTIFACT_MISSING') ||
      (id === 'publish-release' &&
        authority.source.crashWindow !== 'SOURCE_PUBLICATION_PRESENT_SUMMARY_INCOMPLETE');
    return { id, result: recovered ? 'RECOVERED_SUCCESS' : 'SOURCE_SUCCESS' };
  });

export const createCompositeRecoveryJobResultsDocument = ({ authority }) => {
  const closeoutAuthority = validateReleaseSuccessorRecoveryCloseoutAuthority(authority);
  const value = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_EXACT_COMPOSITE_RECOVERY_JOB_RESULTS',
    status: 'PASS',
    scope: 'full',
    candidateSha: closeoutAuthority.source.candidateSha,
    releaseId: closeoutAuthority.source.releaseId,
    releaseTag: closeoutAuthority.source.releaseTag,
    generatedAtUtc: closeoutAuthority.authorizedAtUtc,
    runId: closeoutAuthority.recovery.runId,
    runAttempt: closeoutAuthority.recovery.runAttempt,
    workflow: RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME,
    jobs: compositeLogicalJobResults(closeoutAuthority),
    sourceExecution: {
      workflow: closeoutAuthority.source.workflowName,
      runId: closeoutAuthority.source.runId,
      runAttempt: closeoutAuthority.source.runAttempt,
      conclusion: closeoutAuthority.source.conclusion,
      crashWindow: closeoutAuthority.source.crashWindow,
      jobs: closeoutAuthority.source.jobs,
      conclusionUnchanged: true,
    },
    recoveryExecution: {
      workflow: closeoutAuthority.recovery.workflowName,
      runId: closeoutAuthority.recovery.runId,
      runAttempt: closeoutAuthority.recovery.runAttempt,
      conclusion: closeoutAuthority.recovery.conclusion,
      jobs: closeoutAuthority.recovery.jobs,
      conclusionVerified: true,
    },
    resultSemantics: {
      sourceSuccess: 'SOURCE_SUCCESS',
      recoveredSuccess: 'RECOVERED_SUCCESS',
      logicalResultsAreGithubConclusions: false,
      recoveredSuccessChangesSourceRunConclusion: false,
      summaryJobIsLogicalGate: false,
    },
    compositeRecovery: closeoutAuthority,
    containsSensitiveData: false,
  };
  return validateCompositeRecoveryJobResultsDocument(value, {
    expectedJobs: RELEASE_SUCCESSOR_COMPOSITE_GATE_JOB_IDS,
    expectedIdentity: {
      scope: 'full',
      candidateSha: closeoutAuthority.source.candidateSha,
      releaseId: closeoutAuthority.source.releaseId,
      releaseTag: closeoutAuthority.source.releaseTag,
    },
    expectedExecution: {
      runId: closeoutAuthority.recovery.runId,
      runAttempt: closeoutAuthority.recovery.runAttempt,
      workflow: RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME,
    },
    expectedAuthority: closeoutAuthority,
  });
};

export const validateCompositeRecoveryJobResultsDocument = (
  value,
  { expectedJobs, expectedIdentity, expectedExecution, expectedAuthority } = {},
) => {
  const authority = validateReleaseSuccessorRecoveryCloseoutAuthority(value?.compositeRecovery);
  const expectedLogicalJobs = compositeLogicalJobResults(authority);
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'generatedAtUtc',
      'runId',
      'runAttempt',
      'workflow',
      'jobs',
      'sourceExecution',
      'recoveryExecution',
      'resultSemantics',
      'compositeRecovery',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_EXACT_COMPOSITE_RECOVERY_JOB_RESULTS' ||
    value.status !== 'PASS' ||
    !object(expectedIdentity) ||
    value.scope !== expectedIdentity.scope ||
    value.scope !== 'full' ||
    value.candidateSha !== expectedIdentity.candidateSha ||
    value.releaseId !== expectedIdentity.releaseId ||
    value.releaseTag !== expectedIdentity.releaseTag ||
    !exactKeys(expectedExecution, ['runId', 'runAttempt', 'workflow']) ||
    value.runId !== expectedExecution.runId ||
    value.runAttempt !== expectedExecution.runAttempt ||
    value.workflow !== expectedExecution.workflow ||
    value.workflow !== RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME ||
    !utc(value.generatedAtUtc) ||
    !Array.isArray(expectedJobs) ||
    canonicalJson(expectedJobs) !== canonicalJson(RELEASE_SUCCESSOR_COMPOSITE_GATE_JOB_IDS) ||
    !Array.isArray(value.jobs) ||
    value.jobs.length !== RELEASE_SUCCESSOR_COMPOSITE_GATE_JOB_IDS.length ||
    value.jobs.map(({ id } = {}) => id).join('\0') !== expectedJobs.join('\0') ||
    value.jobs.some((job) => !exactKeys(job, ['id', 'result'])) ||
    canonicalJson(value.jobs) !== canonicalJson(expectedLogicalJobs) ||
    !exactKeys(value.sourceExecution, [
      'workflow',
      'runId',
      'runAttempt',
      'conclusion',
      'crashWindow',
      'jobs',
      'conclusionUnchanged',
    ]) ||
    value.sourceExecution.workflow !== authority.source.workflowName ||
    value.sourceExecution.runId !== authority.source.runId ||
    value.sourceExecution.runAttempt !== authority.source.runAttempt ||
    value.sourceExecution.conclusion !== authority.source.conclusion ||
    value.sourceExecution.crashWindow !== authority.source.crashWindow ||
    canonicalJson(value.sourceExecution.jobs) !== canonicalJson(authority.source.jobs) ||
    value.sourceExecution.conclusionUnchanged !== true ||
    !exactKeys(value.recoveryExecution, [
      'workflow',
      'runId',
      'runAttempt',
      'conclusion',
      'jobs',
      'conclusionVerified',
    ]) ||
    value.recoveryExecution.workflow !== authority.recovery.workflowName ||
    value.recoveryExecution.runId !== authority.recovery.runId ||
    value.recoveryExecution.runAttempt !== authority.recovery.runAttempt ||
    value.recoveryExecution.conclusion !== authority.recovery.conclusion ||
    value.recoveryExecution.jobs.map(({ id } = {}) => id).join('\0') !==
      RELEASE_SUCCESSOR_RECOVERY_JOB_IDS.join('\0') ||
    canonicalJson(value.recoveryExecution.jobs) !== canonicalJson(authority.recovery.jobs) ||
    value.recoveryExecution.conclusionVerified !== true ||
    !exactKeys(value.resultSemantics, [
      'sourceSuccess',
      'recoveredSuccess',
      'logicalResultsAreGithubConclusions',
      'recoveredSuccessChangesSourceRunConclusion',
      'summaryJobIsLogicalGate',
    ]) ||
    value.resultSemantics.sourceSuccess !== 'SOURCE_SUCCESS' ||
    value.resultSemantics.recoveredSuccess !== 'RECOVERED_SUCCESS' ||
    value.resultSemantics.logicalResultsAreGithubConclusions !== false ||
    value.resultSemantics.recoveredSuccessChangesSourceRunConclusion !== false ||
    value.resultSemantics.summaryJobIsLogicalGate !== false ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_COMPOSITE_RECOVERY_JOB_RESULTS_INVALID');
  }
  if (
    value.generatedAtUtc !== authority.authorizedAtUtc ||
    value.runId !== authority.recovery.runId ||
    value.runAttempt !== authority.recovery.runAttempt ||
    value.candidateSha !== authority.source.candidateSha ||
    value.releaseId !== authority.source.releaseId ||
    value.releaseTag !== authority.source.releaseTag ||
    objectSha256(authority) !== objectSha256(expectedAuthority)
  ) {
    fail('E7_COMPOSITE_RECOVERY_JOB_RESULTS_AUTHORITY_MISMATCH');
  }
  assertIdentity(value);
  return value;
};

export const validateStage7JobResultsAuthority = (
  value,
  { expectedJobs, expectedIdentity, expectedExecution, expectedCompositeAuthority } = {},
) =>
  value?.kind === 'STAGE7_EXACT_COMPOSITE_RECOVERY_JOB_RESULTS'
    ? validateCompositeRecoveryJobResultsDocument(value, {
        expectedJobs,
        expectedIdentity,
        expectedExecution,
        expectedAuthority: expectedCompositeAuthority,
      })
    : validateJobResultsDocument(value, { expectedJobs, expectedIdentity, expectedExecution });

export const createStage7ProvenanceLedger = ({
  scope,
  candidateSha,
  releaseId,
  releaseTag,
  generatedAtUtc,
  entryGate,
  artifactRows,
  evidenceRows,
  handoff,
  canonicalSha256ByBasename,
}) => {
  assertIdentity({ scope, candidateSha, releaseId, releaseTag });
  if (!utc(generatedAtUtc)) fail('E7_PROVENANCE_TIMESTAMP_INVALID');
  const artifactIds = artifactRows.map(({ id }) => id);
  const evidenceIds = evidenceRows.map(({ id }) => id);
  if (
    artifactIds.join('\0') !== exactIds('ART-REL', 20).join('\0') ||
    new Set(artifactIds).size !== 20 ||
    evidenceIds.join('\0') !== exactIds('EVD-E7', 57).join('\0') ||
    new Set(evidenceIds).size !== 57
  ) {
    fail('E7_PROVENANCE_MATRIX_INCOMPLETE');
  }
  for (const row of artifactRows) validateProvenanceRow(row, { kind: 'artifact' });
  for (const row of evidenceRows) validateProvenanceRow(row, { kind: 'evidence' });
  if (
    handoff?.ownerAlias === undefined ||
    handoff.ownerAlias !== artifactRows[0]?.ownerAlias ||
    handoff.generatedAtUtc !== generatedAtUtc ||
    [...artifactRows, ...evidenceRows].some(
      (row) => row.ownerAlias !== handoff.ownerAlias || row.validatedAtUtc !== generatedAtUtc,
    )
  ) {
    fail('E7_PROVENANCE_AUTHORITY_IDENTITY_INVALID');
  }
  const index = createStage7Index({
    entryGate,
    artifactStates: Object.fromEntries(artifactRows.map(({ id, status }) => [id, status])),
    evidenceStates: Object.fromEntries(
      evidenceRows.slice(0, 54).map(({ id, status }) => [id, status]),
    ),
  });
  if (
    GATE_IDS.some(
      (id, index_) =>
        evidenceRows[54 + index_].id !== id ||
        evidenceRows[54 + index_].status !== index.gates[GATE_NAMES[index_]],
    ) ||
    artifactRows[17].status !== 'VERIFIED' ||
    artifactRows[18].status !== artifactStatusFromGate(index.gates['GATE-E7-03']) ||
    !artifactRows[18].sources.some((source) =>
      evidenceRows
        .slice(54)
        .every((row) =>
          row.sources.some((candidate) => objectSha256(candidate) === objectSha256(source)),
        ),
    ) ||
    artifactRows[19].status !==
      (handoff.status === 'READY_FOR_STAGE8'
        ? 'VERIFIED'
        : handoff.status === 'FAIL'
          ? 'FAILED'
          : handoff.status === 'BLOCKED_AUTH'
            ? 'BLOCKED_AUTH'
            : 'IN_PROGRESS')
  ) {
    fail('E7_PROVENANCE_GATE_DERIVATION_INVALID');
  }
  const sourceBindings = createStage7LedgerSourceBindings({
    scope,
    artifactRows,
    evidenceRows,
    canonicalSha256ByBasename,
  });
  const sourceBindingsReady =
    scope === 'prerelease' ||
    Object.values(sourceBindings).every(({ status }) => status === 'BOUND');
  const closureVerified =
    index.gates['GATE-E7-03'] === 'PASS' &&
    artifactRows.every(({ status }) => artifactSatisfied(status)) &&
    evidenceRows.every(({ status }) => evidenceSatisfied(status)) &&
    handoff.status === 'READY_FOR_STAGE8' &&
    sourceBindingsReady;
  const closureFailed =
    Object.values(index.gates).includes('FAIL') ||
    artifactRows.some(({ status }) => status === 'FAILED') ||
    evidenceRows.some(({ status }) => status === 'FAIL') ||
    handoff.status === 'FAIL';
  const closureBlocked =
    !closureFailed &&
    (index.gates['GATE-E7-03'] === 'BLOCKED_AUTH' ||
      artifactRows.some(({ status }) => status === 'BLOCKED_AUTH') ||
      evidenceRows.some(({ status }) => status === 'BLOCKED_AUTH') ||
      handoff.status === 'BLOCKED_AUTH');
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_PROVENANCE_LEDGER',
    status: closureFailed
      ? 'FAILED'
      : closureBlocked
        ? 'BLOCKED_AUTH'
        : closureVerified
          ? 'VERIFIED'
          : 'IN_PROGRESS',
    scope,
    candidateSha,
    releaseId,
    releaseTag,
    generatedAtUtc,
    ownerAlias: handoff.ownerAlias,
    entryGate,
    catalogSha256: objectSha256({ artifacts: STAGE7_ARTIFACTS, evidence: STAGE7_EVIDENCE }),
    counts: {
      artifacts: {
        verified: artifactRows.filter(({ status }) => artifactSatisfied(status)).length,
        total: 20,
      },
      evidence: {
        pass: evidenceRows.filter(({ status }) => evidenceSatisfied(status)).length,
        total: 57,
      },
    },
    gates: index.gates,
    artifacts: artifactRows,
    evidence: evidenceRows,
    sourceBindings,
    handoffContentSha256: objectSha256(handoff),
    nextStage: closureVerified ? 8 : null,
    containsSensitiveData: false,
  };
  const value = { ...body, ledgerSha256: objectSha256(body) };
  validateStage7ProvenanceLedger(value, {
    entryGate,
    handoff,
    canonicalSha256ByBasename,
  });
  return value;
};

export const validateStage7ProvenanceLedger = (
  value,
  { entryGate, handoff, canonicalSha256ByBasename },
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'generatedAtUtc',
      'ownerAlias',
      'entryGate',
      'catalogSha256',
      'counts',
      'gates',
      'artifacts',
      'evidence',
      'sourceBindings',
      'handoffContentSha256',
      'nextStage',
      'containsSensitiveData',
      'ledgerSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_PROVENANCE_LEDGER' ||
    value.entryGate !== entryGate ||
    value.artifacts?.length !== 20 ||
    value.evidence?.length !== 57 ||
    value.catalogSha256 !==
      objectSha256({ artifacts: STAGE7_ARTIFACTS, evidence: STAGE7_EVIDENCE }) ||
    !exactKeys(value.counts, ['artifacts', 'evidence']) ||
    !exactKeys(value.counts?.artifacts, ['verified', 'total']) ||
    !exactKeys(value.counts?.evidence, ['pass', 'total']) ||
    !exactKeys(value.gates, GATE_NAMES) ||
    value.counts?.artifacts?.verified !==
      value.artifacts.filter(({ status }) => artifactSatisfied(status)).length ||
    value.counts?.artifacts?.total !== 20 ||
    value.counts?.evidence?.pass !==
      value.evidence.filter(({ status }) => evidenceSatisfied(status)).length ||
    value.counts?.evidence?.total !== 57 ||
    value.handoffContentSha256 !== objectSha256(handoff) ||
    value.ledgerSha256 !==
      objectSha256(
        Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'ledgerSha256')),
      ) ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_PROVENANCE_LEDGER_INVALID');
  }
  assertIdentity(value);
  if (!utc(value.generatedAtUtc) || !ALIAS.test(value.ownerAlias ?? '')) {
    fail('E7_PROVENANCE_LEDGER_TIMESTAMP_INVALID');
  }
  for (const [index, row] of value.artifacts.entries()) {
    validateProvenanceRow(row, { kind: 'artifact' });
    if (row.id !== STAGE7_ARTIFACTS[index].id || row.name !== STAGE7_ARTIFACTS[index].name) {
      fail('E7_PROVENANCE_LEDGER_CATALOG_INVALID');
    }
    for (const source of row.sources) {
      validateBoundSourceReference({
        scope: value.scope,
        basename: pathBasename(source.path),
        source,
      });
    }
  }
  for (const [index, row] of value.evidence.entries()) {
    validateEvidenceRowSourceRequirements({ scope: value.scope, row });
    if (row.id !== STAGE7_EVIDENCE[index].id || row.name !== STAGE7_EVIDENCE[index].name) {
      fail('E7_PROVENANCE_LEDGER_CATALOG_INVALID');
    }
  }
  sourceAuthorities([...value.artifacts, ...value.evidence]);
  validateStage7LedgerSourceBindings(value.sourceBindings, {
    scope: value.scope,
    artifactRows: value.artifacts,
    evidenceRows: value.evidence,
    canonicalSha256ByBasename,
  });
  validateOperationalArtifactRows(value.artifacts.slice(0, 17), {
    evidenceRows: value.evidence.slice(0, 54),
    ownerAlias: value.ownerAlias,
    validatedAtUtc: value.generatedAtUtc,
  });
  validateStage7Handoff(handoff);
  if (
    handoff.scope !== value.scope ||
    handoff.candidateSha !== value.candidateSha ||
    handoff.releaseId !== value.releaseId ||
    handoff.releaseTag !== value.releaseTag ||
    handoff.ownerAlias !== value.ownerAlias ||
    handoff.generatedAtUtc !== value.generatedAtUtc ||
    [...value.artifacts, ...value.evidence].some(
      (row) => row.ownerAlias !== handoff.ownerAlias || row.validatedAtUtc !== value.generatedAtUtc,
    )
  ) {
    fail('E7_PROVENANCE_LEDGER_HANDOFF_INVALID');
  }
  const expectedHandoff = createStage7Handoff({
    scope: value.scope,
    candidateSha: value.candidateSha,
    releaseId: value.releaseId,
    releaseTag: value.releaseTag,
    ownerAlias: handoff.ownerAlias,
    generatedAtUtc: handoff.generatedAtUtc,
    artifactRows: value.artifacts.slice(0, 19),
    evidenceRows: value.evidence,
  });
  if (objectSha256(handoff) !== objectSha256(expectedHandoff)) {
    fail('E7_PROVENANCE_LEDGER_HANDOFF_INVALID');
  }
  const expectedIndex = createStage7Index({
    entryGate,
    artifactStates: Object.fromEntries(value.artifacts.map(({ id, status }) => [id, status])),
    evidenceStates: Object.fromEntries(
      value.evidence.slice(0, 54).map(({ id, status }) => [id, status]),
    ),
  });
  const closureVerified =
    value.gates?.['GATE-E7-03'] === 'PASS' &&
    value.artifacts.every(({ status }) => artifactSatisfied(status)) &&
    value.evidence.every(({ status }) => evidenceSatisfied(status)) &&
    handoff.status === 'READY_FOR_STAGE8' &&
    (value.scope === 'prerelease' ||
      Object.values(value.sourceBindings).every(({ status }) => status === 'BOUND'));
  const closureFailed =
    Object.values(value.gates ?? {}).includes('FAIL') ||
    value.artifacts.some(({ status }) => status === 'FAILED') ||
    value.evidence.some(({ status }) => status === 'FAIL') ||
    handoff.status === 'FAIL';
  const closureBlocked =
    !closureFailed &&
    (value.gates?.['GATE-E7-03'] === 'BLOCKED_AUTH' ||
      value.artifacts.some(({ status }) => status === 'BLOCKED_AUTH') ||
      value.evidence.some(({ status }) => status === 'BLOCKED_AUTH') ||
      handoff.status === 'BLOCKED_AUTH');
  if (
    objectSha256(value.gates) !== objectSha256(expectedIndex.gates) ||
    GATE_IDS.some(
      (id, index) =>
        value.evidence[54 + index]?.id !== id ||
        value.evidence[54 + index]?.status !== value.gates[GATE_NAMES[index]],
    ) ||
    value.artifacts[17].status !== 'VERIFIED' ||
    value.artifacts[18].status !== artifactStatusFromGate(value.gates['GATE-E7-03']) ||
    !value.artifacts[18].sources.some((source) =>
      value.evidence
        .slice(54)
        .every((row) =>
          row.sources.some((candidate) => objectSha256(candidate) === objectSha256(source)),
        ),
    ) ||
    value.artifacts[19].status !==
      (handoff.status === 'READY_FOR_STAGE8'
        ? 'VERIFIED'
        : handoff.status === 'FAIL'
          ? 'FAILED'
          : handoff.status === 'BLOCKED_AUTH'
            ? 'BLOCKED_AUTH'
            : 'IN_PROGRESS') ||
    (value.status === 'VERIFIED') !== closureVerified ||
    (value.status === 'FAILED') !== closureFailed ||
    (value.status === 'BLOCKED_AUTH') !== closureBlocked ||
    (value.status === 'IN_PROGRESS') !== (!closureVerified && !closureFailed && !closureBlocked) ||
    value.nextStage !== (closureVerified ? 8 : null) ||
    (value.scope === 'prerelease' &&
      (value.status === 'VERIFIED' ||
        value.artifacts[19]?.status === 'VERIFIED' ||
        value.evidence.some(
          ({ id, status }) => PRERELEASE_FORBIDDEN_PASS.has(id) && evidenceSatisfied(status),
        )))
  ) {
    fail('E7_PROVENANCE_LEDGER_STATE_INVALID');
  }
  return value;
};

const REPORT_EVIDENCE = [
  [1, 53, 57],
  [2, 55],
  [2, 3, 4],
  [1, 10, 11, 12],
  [5, 6],
  [4, 7],
  [8, 9, 10, 11],
  [6, 12],
  [13, 27, 50],
  [14, 15, 16],
  [17, 18, 19, 20],
  [21],
  [31, 32, 33, 34],
  [22, 23, 24, 25, 26, 27],
  [25, 28, 29, 30],
  [1, 8, 9, 10],
  [35, 36, 37, 38, 39, 40],
  [41],
  [45, 50],
  [42, 43, 44],
  [46],
  [47, 48],
  [49],
  [50, 51, 52],
  [51],
  [53, 54, 55, 56, 57],
  [53],
  [50, 51, 52, 53, 54],
  [34, 54],
  [55],
  [56],
  [57],
  [57],
].map((numbers) => numbers.map(H));

export const renderStage7Report = ({ ledger, scorecard, runbook, handoff }) => {
  validateStage7OperationsRunbook(runbook);
  validateStage7Handoff(handoff);
  const evidenceById = new Map(ledger.evidence.map((row) => [row.id, row]));
  const lines = [
    '# Etapa 7 — Release y despliegue (reporte ejecutado)',
    '',
    `- Candidato: \`${ledger.candidateSha}\``,
    `- Release: \`${ledger.releaseId}\`${ledger.releaseTag === null ? '' : ` / \`${ledger.releaseTag}\``}`,
    `- Estado de cierre: **${ledger.status}**`,
    `- Generado: ${ledger.generatedAtUtc}`,
    '',
  ];
  STAGE7_REPORT_HEADINGS.forEach((heading, index) => {
    const rows = REPORT_EVIDENCE[index].map((id) => evidenceById.get(id));
    const sectionStatus = rows.every(({ status }) => evidenceSatisfied(status))
      ? 'PASS'
      : rows.some(({ status }) => status === 'FAIL')
        ? 'FAIL'
        : rows.some(({ status }) => status === 'BLOCKED_AUTH')
          ? 'BLOCKED_AUTH'
          : 'NOT_RUN';
    lines.push(`## ${index + 1}. ${heading}`, '');
    lines.push(`Estado: **${sectionStatus}**.`);
    lines.push(`Evidencias: ${rows.map(({ id, status }) => `\`${id}\` (${status})`).join(', ')}.`);
    lines.push(
      `Fuentes: ${sourceUnion(rows)
        .slice(0, 8)
        .map(({ path, sha256 }) => `\`${path}\` (sha256:${sha256.slice(0, 12)}…)`)
        .join(', ')}.`,
    );
    if (index === 26)
      lines.push(
        `Rúbrica potencial trazada: ${scorecard.base.potentialPointsTraced}/${scorecard.base.potentialPointsTotal}; etapa 7 no asigna nota.`,
      );
    if (index === 28)
      lines.push(
        `Cleanup: ${runbook.status}; owner \`${runbook.ownerAlias}\`; vence ${runbook.expiresAtUtc}.`,
      );
    if (index === 32)
      lines.push(
        `Handoff: ${handoff.readyCount}/37 elementos listos; siguiente etapa: ${handoff.nextStage ?? 'bloqueada'}.`,
      );
    lines.push('');
  });
  const report = `${lines.join('\n').trim()}\n`;
  validateStage7Report(report, { ledger });
  return report;
};

export const validateStage7Report = (report, { ledger }) => {
  if (
    typeof report !== 'string' ||
    report.length < 2_000 ||
    report.length > 256_000 ||
    !report.includes(ledger.candidateSha) ||
    !report.includes(ledger.releaseId) ||
    /STATUS_BY_|TODO|TBD|PENDING_BY_/u.test(report)
  ) {
    fail('E7_EXECUTED_REPORT_INVALID');
  }
  for (const [index, heading] of STAGE7_REPORT_HEADINGS.entries()) {
    const marker = `## ${index + 1}. ${heading}`;
    if (report.split(marker).length !== 2) fail('E7_EXECUTED_REPORT_HEADING_INVALID');
  }
  return report;
};

export const createStage7FinalManifest = ({
  ledger,
  handoff,
  evidenceIndexCheckpoint,
  gateEvaluationCheckpoint,
  scorecard,
  runbook,
  jobResults,
  stage6Closeout,
  expectedJobs,
  expectedJobExecution,
  expectedCompositeAuthority,
  reportSha256,
  ledgerSha256,
  evidenceIndexSha256,
  gateEvaluationSha256,
  handoffSha256,
  scorecardSha256,
  runbookSha256,
  jobResultsSha256,
  stage6CloseoutSha256,
  urls,
  publication = null,
  rollback = null,
  canonicalSha256ByBasename,
}) => {
  validateStage7ProvenanceLedger(ledger, {
    entryGate: ledger?.entryGate,
    handoff,
    canonicalSha256ByBasename,
  });
  validateStage7Handoff(handoff);
  validateStage7OperationsRunbook(runbook);
  validateStage7Scorecard(scorecard, {
    stage6Closeout,
    evidenceRows: ledger.evidence.slice(0, 52),
  });
  validateStage7JobResultsAuthority(jobResults, {
    expectedJobs,
    expectedIdentity: {
      scope: ledger.scope,
      candidateSha: ledger.candidateSha,
      releaseId: ledger.releaseId,
      releaseTag: ledger.releaseTag,
    },
    expectedExecution: expectedJobExecution,
    expectedCompositeAuthority,
  });
  for (const value of [
    reportSha256,
    ledgerSha256,
    evidenceIndexSha256,
    gateEvaluationSha256,
    handoffSha256,
    scorecardSha256,
    runbookSha256,
    jobResultsSha256,
    stage6CloseoutSha256,
  ]) {
    if (!SHA256.test(value ?? '')) fail('E7_FINAL_MANIFEST_DIGEST_INVALID');
  }
  if (
    ledger.handoffContentSha256 !== objectSha256(handoff) ||
    scorecard.stage6.closeoutSha256 !== stage6CloseoutSha256
  ) {
    fail('E7_FINAL_MANIFEST_AUTHORITY_MISMATCH');
  }
  validateEvidenceIndexCheckpoint(evidenceIndexCheckpoint, { evidenceRows: ledger.evidence });
  validateGateEvaluationCheckpoint(gateEvaluationCheckpoint, {
    entryGate: ledger.entryGate,
    operationalArtifactRows: ledger.artifacts.slice(0, 17),
    evidenceRows: ledger.evidence.slice(0, 54),
  });
  if (
    !ledger.artifacts[17].sources.some(({ sha256 }) => sha256 === evidenceIndexSha256) ||
    !ledger.artifacts[18].sources.some(({ sha256 }) => sha256 === gateEvaluationSha256) ||
    !ledger.artifacts[19].sources.some(({ sha256 }) => sha256 === handoffSha256) ||
    sourceSha256ByBasename([...ledger.artifacts, ...ledger.evidence], 'stage6-closeout.json') !==
      stage6CloseoutSha256 ||
    sourceSha256ByBasename([...ledger.artifacts, ...ledger.evidence], 'job-results.json') !==
      jobResultsSha256 ||
    sourceSha256ByBasename([...ledger.artifacts, ...ledger.evidence], 'scorecard.json') !==
      scorecardSha256 ||
    sourceSha256ByBasename([...ledger.artifacts, ...ledger.evidence], 'operations-runbook.json') !==
      runbookSha256 ||
    !sameIdentity(ledger, evidenceIndexCheckpoint) ||
    !sameIdentity(ledger, gateEvaluationCheckpoint) ||
    !sameIdentity(ledger, scorecard) ||
    !sameIdentity(ledger, runbook) ||
    !sameIdentity(ledger, jobResults) ||
    !sameIdentity(ledger, handoff)
  ) {
    fail('E7_FINAL_MANIFEST_AUTHORITY_MISMATCH');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_FINAL_RELEASE_MANIFEST',
    status:
      ledger.status === 'VERIFIED'
        ? 'RELEASED'
        : ledger.status === 'FAILED'
          ? 'FAILED'
          : ledger.status === 'BLOCKED_AUTH'
            ? 'BLOCKED_AUTH'
            : 'IN_PROGRESS',
    scope: ledger.scope,
    candidateSha: ledger.candidateSha,
    runtimeSha: ledger.candidateSha,
    submissionSha: publication?.readmeCommitSha ?? null,
    releaseId: ledger.releaseId,
    releaseTag: ledger.releaseTag,
    generatedAtUtc: ledger.generatedAtUtc,
    ownerAlias: ledger.ownerAlias,
    releaseMode: ledger.scope === 'full' ? 'VERSIONED_UPDATE' : 'PRERELEASE_VALIDATION',
    authorities: {
      stage6CloseoutSha256,
      jobResultsSha256,
      provenanceLedgerSha256: ledgerSha256,
      evidenceIndexSha256,
      gateEvaluationSha256,
      scorecardSha256,
      operationsRunbookSha256: runbookSha256,
      handoffSha256,
      executedReportSha256: reportSha256,
    },
    contentBindings: {
      stage6CloseoutSha256: objectSha256(stage6Closeout),
      jobResultsSha256: objectSha256(jobResults),
      provenanceLedgerSha256: objectSha256(ledger),
      evidenceIndexSha256: objectSha256(evidenceIndexCheckpoint),
      gateEvaluationSha256: objectSha256(gateEvaluationCheckpoint),
      scorecardSha256: objectSha256(scorecard),
      operationsRunbookSha256: objectSha256(runbook),
      handoffSha256: objectSha256(handoff),
    },
    artifacts: ledger.counts.artifacts,
    evidence: ledger.counts.evidence,
    gates: ledger.gates,
    publication,
    rollback,
    urls,
    nextStage: ledger.nextStage,
    containsSensitiveData: false,
  };
  const value = { ...body, manifestSha256: objectSha256(body) };
  validateStage7FinalManifest(value, {
    ledger,
    handoff,
    evidenceIndexCheckpoint,
    gateEvaluationCheckpoint,
    scorecard,
    runbook,
    jobResults,
    stage6Closeout,
    expectedJobs,
    expectedJobExecution,
    expectedCompositeAuthority,
    expectedAuthorities: body.authorities,
    expectedOwnerAlias: ledger.ownerAlias,
    expectedUrls: urls,
    expectedPublication: publication,
    expectedRollback: rollback,
    canonicalSha256ByBasename,
  });
  return value;
};

export const validateStage7FinalManifest = (
  value,
  {
    ledger,
    handoff,
    evidenceIndexCheckpoint,
    gateEvaluationCheckpoint,
    scorecard,
    runbook,
    jobResults,
    stage6Closeout,
    expectedJobs,
    expectedJobExecution,
    expectedCompositeAuthority,
    expectedAuthorities,
    expectedOwnerAlias,
    expectedUrls,
    expectedPublication,
    expectedRollback,
    canonicalSha256ByBasename,
  },
) => {
  validateStage7ProvenanceLedger(ledger, {
    entryGate: ledger?.entryGate,
    handoff,
    canonicalSha256ByBasename,
  });
  validateStage7Handoff(handoff);
  validateStage7OperationsRunbook(runbook);
  validateStage7Scorecard(scorecard, {
    stage6Closeout,
    evidenceRows: ledger.evidence.slice(0, 52),
  });
  validateStage7JobResultsAuthority(jobResults, {
    expectedJobs,
    expectedIdentity: {
      scope: ledger.scope,
      candidateSha: ledger.candidateSha,
      releaseId: ledger.releaseId,
      releaseTag: ledger.releaseTag,
    },
    expectedExecution: expectedJobExecution,
    expectedCompositeAuthority,
  });
  validateEvidenceIndexCheckpoint(evidenceIndexCheckpoint, { evidenceRows: ledger.evidence });
  validateGateEvaluationCheckpoint(gateEvaluationCheckpoint, {
    entryGate: ledger.entryGate,
    operationalArtifactRows: ledger.artifacts.slice(0, 17),
    evidenceRows: ledger.evidence.slice(0, 54),
  });
  const authorityOwner = handoff.ownerAlias;
  const authorityTime = ledger.generatedAtUtc;
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'runtimeSha',
      'submissionSha',
      'releaseId',
      'releaseTag',
      'generatedAtUtc',
      'ownerAlias',
      'releaseMode',
      'authorities',
      'contentBindings',
      'artifacts',
      'evidence',
      'gates',
      'publication',
      'rollback',
      'urls',
      'nextStage',
      'containsSensitiveData',
      'manifestSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_FINAL_RELEASE_MANIFEST' ||
    !['RELEASED', 'BLOCKED_AUTH', 'IN_PROGRESS', 'FAILED'].includes(value.status) ||
    value.runtimeSha !== value.candidateSha ||
    !SHA.test(value.runtimeSha ?? '') ||
    value.submissionSha !== value.publication?.readmeCommitSha ||
    !SHA.test(value.submissionSha ?? '') ||
    value.releaseMode !== (value.scope === 'full' ? 'VERSIONED_UPDATE' : 'PRERELEASE_VALIDATION') ||
    !exactKeys(value.authorities, [
      'stage6CloseoutSha256',
      'jobResultsSha256',
      'provenanceLedgerSha256',
      'evidenceIndexSha256',
      'gateEvaluationSha256',
      'scorecardSha256',
      'operationsRunbookSha256',
      'handoffSha256',
      'executedReportSha256',
    ]) ||
    !Object.values(value.authorities).every((sha) => SHA256.test(sha ?? '')) ||
    objectSha256(value.authorities) !== objectSha256(expectedAuthorities) ||
    scorecard.stage6.closeoutSha256 !== value.authorities.stage6CloseoutSha256 ||
    !exactKeys(value.contentBindings, [
      'stage6CloseoutSha256',
      'jobResultsSha256',
      'provenanceLedgerSha256',
      'evidenceIndexSha256',
      'gateEvaluationSha256',
      'scorecardSha256',
      'operationsRunbookSha256',
      'handoffSha256',
    ]) ||
    value.contentBindings.stage6CloseoutSha256 !== objectSha256(stage6Closeout) ||
    value.contentBindings.jobResultsSha256 !== objectSha256(jobResults) ||
    value.contentBindings.provenanceLedgerSha256 !== objectSha256(ledger) ||
    value.contentBindings.evidenceIndexSha256 !== objectSha256(evidenceIndexCheckpoint) ||
    value.contentBindings.gateEvaluationSha256 !== objectSha256(gateEvaluationCheckpoint) ||
    value.contentBindings.scorecardSha256 !== objectSha256(scorecard) ||
    value.contentBindings.operationsRunbookSha256 !== objectSha256(runbook) ||
    value.contentBindings.handoffSha256 !== objectSha256(handoff) ||
    value.generatedAtUtc !== authorityTime ||
    value.ownerAlias !== authorityOwner ||
    value.ownerAlias !== expectedOwnerAlias ||
    evidenceIndexCheckpoint.ownerAlias !== authorityOwner ||
    evidenceIndexCheckpoint.generatedAtUtc !== authorityTime ||
    gateEvaluationCheckpoint.ownerAlias !== authorityOwner ||
    gateEvaluationCheckpoint.generatedAtUtc !== authorityTime ||
    scorecard.ownerAlias !== authorityOwner ||
    scorecard.generatedAtUtc !== authorityTime ||
    runbook.ownerAlias !== authorityOwner ||
    runbook.reviewedAtUtc !== authorityTime ||
    jobResults.generatedAtUtc !== authorityTime ||
    !sameIdentity(ledger, evidenceIndexCheckpoint) ||
    !sameIdentity(ledger, gateEvaluationCheckpoint) ||
    !sameIdentity(ledger, scorecard) ||
    !sameIdentity(ledger, runbook) ||
    !sameIdentity(ledger, jobResults) ||
    !sameIdentity(ledger, handoff) ||
    sourceSha256ByBasename([...ledger.artifacts, ...ledger.evidence], 'stage6-closeout.json') !==
      value.authorities.stage6CloseoutSha256 ||
    sourceSha256ByBasename([...ledger.artifacts, ...ledger.evidence], 'job-results.json') !==
      value.authorities.jobResultsSha256 ||
    sourceSha256ByBasename([...ledger.artifacts, ...ledger.evidence], 'scorecard.json') !==
      value.authorities.scorecardSha256 ||
    sourceSha256ByBasename([...ledger.artifacts, ...ledger.evidence], 'operations-runbook.json') !==
      value.authorities.operationsRunbookSha256 ||
    !ledger.artifacts[17].sources.some(
      ({ sha256 }) => sha256 === value.authorities.evidenceIndexSha256,
    ) ||
    !ledger.artifacts[18].sources.some(
      ({ sha256 }) => sha256 === value.authorities.gateEvaluationSha256,
    ) ||
    !ledger.artifacts[19].sources.some(
      ({ sha256 }) => sha256 === value.authorities.handoffSha256,
    ) ||
    !exactKeys(value.artifacts, ['verified', 'total']) ||
    objectSha256(value.artifacts) !== objectSha256(ledger.counts.artifacts) ||
    !exactKeys(value.evidence, ['pass', 'total']) ||
    objectSha256(value.evidence) !== objectSha256(ledger.counts.evidence) ||
    !exactKeys(value.gates, GATE_NAMES) ||
    objectSha256(value.gates) !== objectSha256(ledger.gates) ||
    !exactKeys(value.urls, ['application', 'api', 'docs', 'health', 'repository']) ||
    !exactKeys(expectedUrls, ['application', 'api', 'docs', 'health', 'repository']) ||
    objectSha256(value.urls) !== objectSha256(expectedUrls) ||
    Object.values(value.urls).some((url) => !secureUrl(url)) ||
    objectSha256(value.publication) !== objectSha256(expectedPublication) ||
    objectSha256(value.rollback) !== objectSha256(expectedRollback) ||
    value.manifestSha256 !==
      objectSha256(
        Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'manifestSha256')),
      ) ||
    (value.status === 'RELEASED') !== (ledger.status === 'VERIFIED') ||
    (value.status === 'FAILED') !== (ledger.status === 'FAILED') ||
    (value.status === 'BLOCKED_AUTH') !== (ledger.status === 'BLOCKED_AUTH') ||
    (value.status === 'IN_PROGRESS') !== (ledger.status === 'IN_PROGRESS') ||
    value.nextStage !== (value.status === 'RELEASED' ? 8 : null) ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_FINAL_MANIFEST_INVALID');
  }
  const publicationValid =
    exactKeys(value.publication, [
      'releaseUrl',
      'readmeCommitSha',
      'repositoryPublic',
      'urlsVerified',
      'proofRawSha256',
      'proofObjectSha256',
    ]) &&
    secureUrl(value.publication.releaseUrl) &&
    SHA.test(value.publication.readmeCommitSha ?? '') &&
    SHA256.test(value.publication.proofRawSha256 ?? '') &&
    SHA256.test(value.publication.proofObjectSha256 ?? '') &&
    typeof value.publication.repositoryPublic === 'boolean' &&
    typeof value.publication.urlsVerified === 'boolean';
  const rollbackValid =
    exactKeys(value.rollback, [
      'predecessorManifestSha256',
      'completionRawSha256',
      'completionObjectSha256',
      'completionEnvelopeSha256',
    ]) && Object.values(value.rollback).every((sha256) => SHA256.test(sha256 ?? ''));
  if (
    (value.publication !== null && !publicationValid) ||
    (value.rollback !== null && !rollbackValid) ||
    (value.status === 'RELEASED' &&
      (!publicationValid ||
        value.publication.repositoryPublic !== true ||
        value.publication.urlsVerified !== true ||
        value.publication.releaseUrl !==
          `${value.urls.repository}/releases/tag/${value.releaseTag}` ||
        value.publication.proofRawSha256 !== ledger.sourceBindings.publicationProof.rawSha256 ||
        value.publication.proofObjectSha256 !==
          ledger.sourceBindings.publicationProof.objectSha256 ||
        !rollbackValid ||
        value.artifacts.verified !== 20 ||
        value.artifacts.total !== 20 ||
        value.evidence.pass !== 57 ||
        value.evidence.total !== 57 ||
        value.rollback.completionRawSha256 !==
          ledger.sourceBindings.rollbackResilienceCompletion.rawSha256 ||
        value.rollback.completionObjectSha256 !==
          ledger.sourceBindings.rollbackResilienceCompletion.objectSha256)) ||
    (value.scope === 'prerelease' && value.status === 'RELEASED')
  ) {
    fail('E7_FINAL_MANIFEST_RELEASE_AUTHORITY_INVALID');
  }
  assertIdentity(value);
  if (!utc(value.generatedAtUtc) || !ALIAS.test(expectedOwnerAlias ?? '')) {
    fail('E7_FINAL_MANIFEST_TIMESTAMP_INVALID');
  }
  return value;
};

export const selfTestStage7Provenance = () => {
  assert.equal(STAGE7_FULL_SOURCE_ARTIFACT_NAMES.length, 29);
  assert.equal(STAGE7_PRERELEASE_SOURCE_ARTIFACT_NAMES.length, 14);
  assert.equal(STAGE7_LEDGER_SOURCE_BINDING_SPECS.length, 27);
  assert.deepEqual(STAGE7_FULL_SOURCE_ARTIFACT_NAMES, [
    'stage7-activation',
    'stage7-api',
    'stage7-approval',
    'stage7-aws-auth',
    'stage7-candidate-manifest',
    'stage7-candidate-verification',
    'stage7-data',
    'stage7-edge-security',
    'stage7-external-authorization',
    'stage7-infra-diff',
    'stage7-infra-synth',
    'stage7-integrity',
    'stage7-observability',
    'stage7-prefreeze',
    'stage7-previous-release',
    'stage7-publication',
    'stage7-quality',
    'stage7-recovery-probe',
    'stage7-release-authorities',
    'stage7-release-metadata',
    'stage7-release-plan',
    'stage7-release-reconciliation',
    'stage7-release-successor-fence',
    'stage7-rollback',
    'stage7-rollback-resilience',
    'stage7-sandbox',
    'stage7-security',
    'stage7-smoke',
    'stage7-web',
  ]);
  assert.equal(STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full.length, 57);
  assert.equal(STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.prerelease.length, 57);
  const journalAuthorityBasename = 'stage7-release-journal-role-effective-permissions.json';
  const recoveryRoleAuthorityBasename =
    'stage7-release-reconciliation-recovery-role-effective-permissions.json';
  for (const requirements of STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full) {
    if (requirements.includes(journalAuthorityBasename)) {
      assert.equal(requirements.includes(recoveryRoleAuthorityBasename), true);
    }
  }
  assert.equal(
    STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.prerelease.some((requirements) =>
      requirements.includes(recoveryRoleAuthorityBasename),
    ),
    false,
  );
  assert.deepEqual(STAGE7_SOURCE_PRODUCERS.full[recoveryRoleAuthorityBasename], {
    artifactName: 'stage7-aws-auth',
    producerJob: 'aws-auth',
  });
  assert.deepEqual(
    STAGE7_LEDGER_SOURCE_BINDING_SPECS.find(
      ({ basename }) => basename === recoveryRoleAuthorityBasename,
    ),
    {
      key: 'releaseReconciliationRecoveryRoleEffectivePermissions',
      basename: recoveryRoleAuthorityBasename,
    },
  );
  const noActionOutcomeBasename = 'emergency-recovery-no-action-outcome.json';
  assert.deepEqual(STAGE7_SOURCE_PRODUCERS.full[noActionOutcomeBasename], {
    artifactName: 'stage7-recovery-probe',
    producerJob: 'emergency-recovery',
  });
  for (const evidenceNumber of [46, 47, 48, 49]) {
    assert.equal(
      STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full[evidenceNumber - 1].includes(
        noActionOutcomeBasename,
      ),
      true,
    );
  }
  assert.deepEqual(
    STAGE7_LEDGER_SOURCE_BINDING_SPECS.find(({ basename }) => basename === noActionOutcomeBasename),
    {
      key: 'emergencyRecoveryNoActionOutcome',
      basename: noActionOutcomeBasename,
    },
  );
  const releaseSuccessorFenceBasename = 'release-successor-completion-fence.json';
  assert.deepEqual(STAGE7_SOURCE_PRODUCERS.full[releaseSuccessorFenceBasename], {
    artifactName: 'stage7-release-successor-fence',
    producerJob: 'release-successor-fence',
  });
  for (const evidenceNumber of [46, 47, 48, 49, 51, 52, 55, 56, 57]) {
    assert.equal(
      STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full[evidenceNumber - 1].includes(
        releaseSuccessorFenceBasename,
      ),
      true,
    );
  }
  assert.deepEqual(
    STAGE7_LEDGER_SOURCE_BINDING_SPECS.find(
      ({ basename }) => basename === releaseSuccessorFenceBasename,
    ),
    {
      key: 'releaseSuccessorFence',
      basename: releaseSuccessorFenceBasename,
    },
  );
  for (const scope of ['full', 'prerelease']) {
    const first52Sources = new Set(STAGE7_EVIDENCE_SOURCE_REQUIREMENTS[scope].slice(0, 52).flat());
    for (const laterAuthority of [
      'job-results.json',
      'scorecard.json',
      'operations-runbook.json',
      'gate-evaluation.json',
      'evidence-index-checkpoint.json',
      'handoff-payload.json',
    ]) {
      assert.equal(first52Sources.has(laterAuthority), false);
    }
  }
  for (const evidenceNumber of [46, 47, 48, 49]) {
    assert.deepEqual(
      STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full[evidenceNumber - 1].filter((basename) =>
        basename.startsWith('stage7-rollback-resilience-'),
      ),
      [
        'stage7-rollback-resilience-source-binding.json',
        'stage7-rollback-resilience-protected-run.json',
        'stage7-rollback-resilience-complete.json',
      ],
    );
    assert.deepEqual(
      STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full[evidenceNumber - 1].filter((basename) =>
        [
          'rollback-check-reconciliation.json',
          'rollback-resilience-reconciliation.json',
          'stage7-release-pre-fence-gate.json',
        ].includes(basename),
      ),
      [
        'rollback-check-reconciliation.json',
        'rollback-resilience-reconciliation.json',
        'stage7-release-pre-fence-gate.json',
      ],
    );
  }
  assert.deepEqual(
    STAGE7_LEDGER_SOURCE_BINDING_SPECS.filter(({ basename }) =>
      [
        'rollback-check-reconciliation.json',
        'rollback-resilience-reconciliation.json',
        'stage7-release-pre-fence-gate.json',
      ].includes(basename),
    ),
    [
      { key: 'rollbackCheckReconciliation', basename: 'rollback-check-reconciliation.json' },
      {
        key: 'rollbackResilienceReconciliation',
        basename: 'rollback-resilience-reconciliation.json',
      },
      { key: 'releasePreFenceGate', basename: 'stage7-release-pre-fence-gate.json' },
    ],
  );
  for (const basename of [
    'rollback-check-reconciliation.json',
    'rollback-resilience-reconciliation.json',
    'stage7-release-pre-fence-gate.json',
  ]) {
    assert.deepEqual(STAGE7_SOURCE_PRODUCERS.full[basename], {
      artifactName: 'stage7-release-reconciliation',
      producerJob: 'release-reconciliation',
    });
  }
  for (const evidenceNumber of [1, 13, 18, 21, 22, 27, 34, 54]) {
    assert.equal(
      STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.prerelease[evidenceNumber - 1].includes(
        'prerelease-safety-readiness.json',
      ),
      true,
    );
  }
  for (const evidenceNumber of [13, 18, 21, 22, 27, 34]) {
    assert.equal(
      STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.prerelease[evidenceNumber - 1].includes(
        'prerelease-activation-live-safety-recheck.json',
      ),
      true,
    );
  }
  assert.equal(
    STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.prerelease[40].includes(
      'prerelease-sandbox-live-safety-recheck.json',
    ),
    true,
  );
  const boundSource = createSourceReference({
    path: '.stage7/evidence/stage7-release-metadata/release-metadata.json',
    sha256: '0'.repeat(64),
    artifactName: 'stage7-release-metadata',
    producerJob: 'release-metadata',
    selectors: ['/candidateSha'],
  });
  assert.equal(
    validateBoundSourceReference({
      scope: 'full',
      basename: 'release-metadata.json',
      source: boundSource,
    }),
    boundSource,
  );
  assert.throws(
    () =>
      validateBoundSourceReference({
        scope: 'full',
        basename: 'release-metadata.json',
        source: { ...boundSource, producerJob: 'verify-candidate' },
      }),
    (error) => error.code === 'E7_PROVENANCE_SOURCE_BINDING_INVALID',
  );
  assert.throws(
    () =>
      validateBoundSourceReference({
        scope: 'full',
        basename: 'release-metadata.json',
        source: {
          ...boundSource,
          path: '.stage7/evidence/untrusted/stage7-release-metadata/release-metadata.json',
        },
      }),
    (error) => error.code === 'E7_PROVENANCE_SOURCE_BINDING_INVALID',
  );
  assert.throws(
    () =>
      validateBoundSourceReference({
        scope: 'full',
        basename: 'release-metadata.json',
        source: {
          ...boundSource,
          path: '.stage7/evidence/stage7-candidate-verification/release-metadata.json',
        },
      }),
    (error) => error.code === 'E7_PROVENANCE_SOURCE_BINDING_INVALID',
  );
  const sourceByBasename = new Map();
  const sourceForBasename = (basename) => {
    if (!sourceByBasename.has(basename)) {
      const binding = STAGE7_SOURCE_PRODUCERS.full[basename];
      assert.notEqual(binding, undefined);
      sourceByBasename.set(
        basename,
        createSourceReference({
          path: `.stage7/evidence/${binding.artifactName}/${basename}`,
          sha256: objectSha256({ fixture: basename }),
          artifactName: binding.artifactName,
          producerJob: binding.producerJob,
          selectors: ['/status'],
        }),
      );
    }
    return sourceByBasename.get(basename);
  };
  const evidenceIndexSource = sourceForBasename('evidence-index-checkpoint.json');
  const gateEvaluationSource = sourceForBasename('gate-evaluation.json');
  const handoffSource = sourceForBasename('handoff-payload.json');
  const stage6CloseoutSource = sourceForBasename('stage6-closeout.json');
  const scorecardSource = sourceForBasename('scorecard.json');
  const runbookSource = sourceForBasename('operations-runbook.json');
  const jobResultsSource = sourceForBasename('job-results.json');
  const canonicalSha256ByBasename = Object.fromEntries(
    STAGE7_LEDGER_SOURCE_BINDING_SPECS.map(({ basename }) => [
      basename,
      objectSha256({ fixture: basename, canonical: true }),
    ]),
  );
  const ownerAlias = 'release-owner';
  const generatedAtUtc = '2026-08-18T12:00:00.000Z';
  const candidateSha = 'b'.repeat(40);
  const releaseId = `rel-20260818-1200-${candidateSha.slice(0, 7)}`;
  const releaseTag = 'v1.0.0-rc.1';
  const stage6Evidence = Array.from({ length: 40 }, (_, index) => ({
    id: `EVD-E6-${String(index + 1).padStart(2, '0')}`,
    status: 'PASS',
  }));
  const stage6Closeout = {
    runId: 'e6-20260818t120000z-aaaaaaaa',
    candidate: { commitSha: candidateSha },
    gates: { 'GATE-E6-03': 'PASS' },
    evidence: stage6Evidence,
    rubric: calculateStage6Rubric(stage6Evidence),
  };
  const baseEvidenceRows = STAGE7_EVIDENCE.slice(0, 54).map(({ id, name }, index) =>
    createProvenanceRow({
      id,
      name,
      status: 'PASS',
      ownerAlias,
      validatedAtUtc: generatedAtUtc,
      validator: 'fixtureValidator',
      sources: STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full[index].map(sourceForBasename),
    }),
  );
  assert.throws(
    () =>
      validateEvidenceRowSourceRequirements({
        scope: 'full',
        row: { ...baseEvidenceRows[29], sources: [boundSource] },
      }),
    (error) => error.code === 'E7_EVIDENCE_SOURCE_REQUIREMENT_INVALID',
  );
  assert.throws(
    () =>
      validateEvidenceRowSourceRequirements({
        scope: 'full',
        row: { ...baseEvidenceRows[34], status: 'FAIL', sources: [boundSource] },
      }),
    (error) => error.code === 'E7_EVIDENCE_SOURCE_REQUIREMENT_INVALID',
  );
  const scorecard = createStage7Scorecard({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    stage6Closeout,
    stage6CloseoutSha256: stage6CloseoutSource.sha256,
    evidenceRows: baseEvidenceRows.slice(0, 52),
  });
  assert.equal(scorecard.base.potentialPointsTraced, 100);
  assert.equal(scorecard.evaluation.awardedPoints, null);
  assert.equal(
    createStage7Scorecard({
      scope: 'full',
      candidateSha,
      releaseId,
      releaseTag,
      ownerAlias,
      generatedAtUtc,
      stage6Closeout,
      stage6CloseoutSha256: stage6CloseoutSource.sha256,
      evidenceRows: baseEvidenceRows
        .slice(0, 52)
        .map((row) => (row.id === 'EVD-E7-35' ? { ...row, status: 'FAIL' } : row)),
    }).status,
    'FAILED',
  );
  assert.equal(
    createStage7Scorecard({
      scope: 'full',
      candidateSha,
      releaseId,
      releaseTag,
      ownerAlias,
      generatedAtUtc,
      stage6Closeout,
      stage6CloseoutSha256: stage6CloseoutSource.sha256,
      evidenceRows: baseEvidenceRows
        .slice(0, 52)
        .map((row) => (row.id === 'EVD-E7-35' ? { ...row, status: 'NOT_RUN' } : row)),
    }).status,
    'IN_PROGRESS',
  );
  assert.throws(
    () =>
      createStage7Scorecard({
        scope: 'full',
        candidateSha,
        releaseId,
        releaseTag,
        ownerAlias,
        generatedAtUtc,
        stage6Closeout,
        stage6CloseoutSha256: stage6CloseoutSource.sha256,
        evidenceRows: baseEvidenceRows,
      }),
    (error) => error.code === 'E7_SCORECARD_EVIDENCE_MATRIX_INVALID',
  );
  assert.throws(
    () =>
      createStage7Scorecard({
        scope: 'full',
        candidateSha,
        releaseId,
        releaseTag,
        ownerAlias,
        generatedAtUtc,
        stage6Closeout,
        stage6CloseoutSha256: stage6CloseoutSource.sha256,
        evidenceRows: baseEvidenceRows.slice(0, 51),
      }),
    (error) => error.code === 'E7_SCORECARD_EVIDENCE_MATRIX_INVALID',
  );
  const runbook = createStage7OperationsRunbook({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    expiresAtUtc: '2026-09-18T12:00:00.000Z',
    environment: 'assessment-release',
    stacks: [
      'checkout-assessment-release-data',
      'checkout-assessment-release-api',
      'checkout-assessment-release-observability',
      'checkout-assessment-release-web',
    ],
    budgetMaxUsd: 25,
    cleanupVerified: false,
    sourceSha256: 'd'.repeat(64),
  });
  assert.equal(runbook.resources.length, 14);
  assert.equal(runbook.rollback.execution, 'PROTECTED_VERSIONED_ROLLBACK');
  assert.equal(runbook.rollback.commands.length, 3);
  assert.equal(runbook.cleanup.execution, 'NOT_AUTOMATED_REQUIRES_SEPARATE_AUTHORIZATION');
  assert.equal(runbook.cleanup.command, null);
  assert.equal(
    runbook.rollback.commands.some((command) => command.includes('pnpm release:rollback --')),
    false,
  );
  assert.throws(
    () =>
      validateStage7OperationsRunbook({
        ...runbook,
        rollback: {
          ...runbook.rollback,
          commands: ['pnpm release:rollback -- --scope full --versioned-update'],
        },
      }),
    (error) => error.code === 'E7_OPERATIONS_RUNBOOK_INVALID',
  );
  const prereleaseRunbook = createStage7OperationsRunbook({
    scope: 'prerelease',
    candidateSha,
    releaseId,
    releaseTag: null,
    ownerAlias,
    generatedAtUtc,
    expiresAtUtc: '2026-09-18T12:00:00.000Z',
    environment: 'assessment-prerelease',
    stacks: [
      'checkout-assessment-prerelease-data',
      'checkout-assessment-prerelease-api',
      'checkout-assessment-prerelease-observability',
      'checkout-assessment-prerelease-web',
    ],
    budgetMaxUsd: 25,
    cleanupVerified: true,
    sourceSha256: 'd'.repeat(64),
  });
  assert.equal(prereleaseRunbook.rollback.commands.length, 2);
  assert.equal(prereleaseRunbook.cleanup.execution, 'PROTECTED_EPHEMERAL_CLEANUP');
  assert.equal(prereleaseRunbook.cleanup.command.includes('--ephemeral-only'), true);
  assert.equal(prereleaseRunbook.cleanup.command.includes('--confirm "${CLEANUP_CONFIRM}"'), true);
  const operationalArtifactRows = createOperationalArtifactRows({
    evidenceRows: baseEvidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
  });
  const gateEvaluationCheckpoint = createGateEvaluationCheckpoint({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    entryGate: 'PASS',
    operationalArtifactRows,
    evidenceRows: baseEvidenceRows,
  });
  const gateRows = STAGE7_EVIDENCE.slice(54).map(({ id, name }, index) =>
    createProvenanceRow({
      id,
      name,
      status: gateEvaluationCheckpoint.gates[GATE_NAMES[index]],
      ownerAlias,
      validatedAtUtc: generatedAtUtc,
      validator: 'deriveStage7Gates',
      sources: STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full[index + 54].map(sourceForBasename),
    }),
  );
  const allEvidenceRows = [...baseEvidenceRows, ...gateRows];
  const evidenceIndexCheckpoint = createEvidenceIndexCheckpoint({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    evidenceRows: allEvidenceRows,
  });
  const authorityArtifactRows = createAuthorityArtifactRows({
    evidenceRows: allEvidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    operationalArtifactRows,
    evidenceIndexCheckpoint,
    evidenceIndexSource,
    gateEvaluationCheckpoint,
    gateEvaluationSource,
    entryGate: 'PASS',
  });
  assert.throws(
    () =>
      createAuthorityArtifactRows({
        evidenceRows: allEvidenceRows,
        ownerAlias,
        validatedAtUtc: generatedAtUtc,
        operationalArtifactRows,
        evidenceIndexCheckpoint,
        evidenceIndexSource: {
          ...evidenceIndexSource,
          path: '.stage7/evidence/stage7-publication/evidence-index-checkpoint.json',
          artifactName: 'stage7-publication',
          producerJob: 'publish-release',
        },
        gateEvaluationCheckpoint,
        gateEvaluationSource,
        entryGate: 'PASS',
      }),
    (error) => error.code === 'E7_PROVENANCE_SOURCE_BINDING_INVALID',
  );
  const wrongIdentityGateBody = {
    ...gateEvaluationCheckpoint,
    releaseTag: 'v1.0.1-rc.1',
  };
  delete wrongIdentityGateBody.checkpointBodySha256;
  const wrongIdentityGateCheckpoint = {
    ...wrongIdentityGateBody,
    checkpointBodySha256: objectSha256(wrongIdentityGateBody),
  };
  assert.throws(
    () =>
      createAuthorityArtifactRows({
        evidenceRows: allEvidenceRows,
        ownerAlias,
        validatedAtUtc: generatedAtUtc,
        operationalArtifactRows,
        evidenceIndexCheckpoint,
        evidenceIndexSource,
        gateEvaluationCheckpoint: wrongIdentityGateCheckpoint,
        gateEvaluationSource,
        entryGate: 'PASS',
      }),
    (error) => error.code === 'E7_AUTHORITY_CHECKPOINT_IDENTITY_INVALID',
  );
  const handoff = createStage7Handoff({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    artifactRows: authorityArtifactRows,
    evidenceRows: allEvidenceRows,
  });
  const artifactRows = createArtifactRows({
    authorityArtifactRows,
    evidenceRows: allEvidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    operationalArtifactRows,
    evidenceIndexCheckpoint,
    evidenceIndexSource,
    gateEvaluationCheckpoint,
    gateEvaluationSource,
    entryGate: 'PASS',
    handoff,
    handoffSource,
  });
  assert.throws(
    () =>
      createArtifactRows({
        authorityArtifactRows: authorityArtifactRows.slice(0, 18),
        evidenceRows: allEvidenceRows,
        ownerAlias,
        validatedAtUtc: generatedAtUtc,
        operationalArtifactRows,
        evidenceIndexCheckpoint,
        evidenceIndexSource,
        gateEvaluationCheckpoint,
        gateEvaluationSource,
        entryGate: 'PASS',
        handoff,
        handoffSource,
      }),
    (error) => error.code === 'E7_AUTHORITY_ARTIFACT_MATRIX_INVALID',
  );
  assert.throws(
    () =>
      createStage7Handoff({
        scope: 'full',
        candidateSha,
        releaseId,
        releaseTag,
        ownerAlias,
        generatedAtUtc,
        artifactRows: operationalArtifactRows,
        evidenceRows: allEvidenceRows,
      }),
    (error) => error.code === 'E7_HANDOFF_AUTHORITY_MATRIX_INVALID',
  );
  const ledger = createStage7ProvenanceLedger({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    generatedAtUtc,
    entryGate: 'PASS',
    artifactRows,
    evidenceRows: allEvidenceRows,
    handoff,
    canonicalSha256ByBasename,
  });
  assert.deepEqual(ledger.counts, {
    artifacts: {
      verified: artifactRows.filter(({ status }) => artifactSatisfied(status)).length,
      total: 20,
    },
    evidence: {
      pass: allEvidenceRows.filter(({ status }) => evidenceSatisfied(status)).length,
      total: 57,
    },
  });
  assert.equal(ledger.sourceBindings.previousReleaseProjectionIndex.status, 'BOUND');
  assert.equal(
    ledger.sourceBindings.rollbackResilienceCompletion.rawSha256,
    sourceForBasename('stage7-rollback-resilience-complete.json').sha256,
  );
  const incompleteCanonicalSha256ByBasename = { ...canonicalSha256ByBasename };
  delete incompleteCanonicalSha256ByBasename['previous-release-projection-index.json'];
  const provenanceIncompleteLedger = createStage7ProvenanceLedger({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    generatedAtUtc,
    entryGate: 'PASS',
    artifactRows,
    evidenceRows: allEvidenceRows,
    handoff,
    canonicalSha256ByBasename: incompleteCanonicalSha256ByBasename,
  });
  assert.equal(provenanceIncompleteLedger.status, 'IN_PROGRESS');
  assert.equal(provenanceIncompleteLedger.nextStage, null);
  assert.equal(
    provenanceIncompleteLedger.sourceBindings.previousReleaseProjectionIndex.status,
    'NOT_AVAILABLE',
  );
  const report = renderStage7Report({ ledger, scorecard, runbook, handoff });
  assert.equal(report.includes('## 33. Handoff a etapa 8'), true);
  const notRunReport = renderStage7Report({
    ledger: {
      ...ledger,
      evidence: ledger.evidence.map((row) =>
        row.id === 'EVD-E7-01' ? { ...row, status: 'NOT_RUN' } : row,
      ),
    },
    scorecard,
    runbook,
    handoff,
  });
  assert.equal(notRunReport.includes('Estado: **NOT_RUN**.'), true);
  const expectedJobExecution = {
    runId: '123',
    runAttempt: 1,
    workflow: 'Stage 7 release',
  };
  const jobs = createJobResultsDocument({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    generatedAtUtc,
    runId: '123',
    runAttempt: 1,
    workflow: 'Stage 7 release',
    jobs: ['release-metadata'],
  });
  const failedJobs = createJobResultsDocument({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    generatedAtUtc,
    runId: '123',
    runAttempt: 1,
    workflow: 'Stage 7 release',
    jobs: [{ id: 'release-metadata', result: 'failure' }],
  });
  const incompleteJobs = createJobResultsDocument({
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag,
    generatedAtUtc,
    runId: '123',
    runAttempt: 1,
    workflow: 'Stage 7 release',
    jobs: [{ id: 'release-metadata', result: 'skipped' }],
  });
  assert.equal(failedJobs.status, 'FAILED');
  assert.equal(incompleteJobs.status, 'INCOMPLETE');
  const notRunWithJobAuthority = createProvenanceRow({
    ...STAGE7_EVIDENCE[0],
    status: 'NOT_RUN',
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    validator: 'deriveEvidenceStatusFromJobResult',
    sources: [jobResultsSource],
  });
  assert.equal(
    validateEvidenceRowSourceRequirements({ scope: 'full', row: notRunWithJobAuthority }),
    notRunWithJobAuthority,
  );
  assert.throws(
    () =>
      validateEvidenceRowSourceRequirements({
        scope: 'full',
        row: { ...notRunWithJobAuthority, sources: [scorecardSource] },
      }),
    (error) => error.code === 'E7_EVIDENCE_SOURCE_REQUIREMENT_INVALID',
  );
  assert.throws(
    () =>
      validateJobResultsDocument(jobs, {
        expectedJobs: ['verify-candidate'],
        expectedIdentity: { scope: 'full', candidateSha, releaseId, releaseTag },
        expectedExecution: expectedJobExecution,
      }),
    (error) => error.code === 'E7_JOB_RESULTS_DOCUMENT_INVALID',
  );
  assert.throws(
    () =>
      validateJobResultsDocument(
        { ...jobs, candidateSha: 'c'.repeat(40) },
        {
          expectedJobs: ['release-metadata'],
          expectedIdentity: { scope: 'full', candidateSha, releaseId, releaseTag },
          expectedExecution: expectedJobExecution,
        },
      ),
    (error) => error.code === 'E7_JOB_RESULTS_DOCUMENT_INVALID',
  );
  assert.throws(
    () =>
      validateJobResultsDocument(jobs, {
        expectedJobs: ['release-metadata'],
        expectedIdentity: { scope: 'full', candidateSha, releaseId, releaseTag },
        expectedExecution: { ...expectedJobExecution, runId: '124' },
      }),
    (error) => error.code === 'E7_JOB_RESULTS_DOCUMENT_INVALID',
  );
  const urls = {
    application: 'https://checkout.example.test',
    api: 'https://checkout.example.test/api',
    docs: 'https://checkout.example.test/api/docs',
    health: 'https://checkout.example.test/api/health',
    repository: 'https://github.com/example/checkout',
  };
  const manifestInput = {
    ledger,
    handoff,
    evidenceIndexCheckpoint,
    gateEvaluationCheckpoint,
    scorecard,
    runbook,
    jobResults: jobs,
    stage6Closeout,
    expectedJobs: ['release-metadata'],
    expectedJobExecution,
    reportSha256: 'e'.repeat(64),
    ledgerSha256: 'f'.repeat(64),
    evidenceIndexSha256: evidenceIndexSource.sha256,
    gateEvaluationSha256: gateEvaluationSource.sha256,
    handoffSha256: handoffSource.sha256,
    scorecardSha256: scorecardSource.sha256,
    runbookSha256: runbookSource.sha256,
    jobResultsSha256: jobResultsSource.sha256,
    stage6CloseoutSha256: stage6CloseoutSource.sha256,
    urls,
    publication: {
      releaseUrl: 'https://github.com/example/checkout/releases/tag/v1.0.0-rc.1',
      readmeCommitSha: candidateSha,
      repositoryPublic: true,
      urlsVerified: true,
      proofRawSha256: sourceForBasename('publication-proof.json').sha256,
      proofObjectSha256: canonicalSha256ByBasename['publication-proof.json'],
    },
    rollback: {
      predecessorManifestSha256: canonicalSha256ByBasename['previous-release-manifest.json'],
      completionRawSha256: sourceForBasename('stage7-rollback-resilience-complete.json').sha256,
      completionObjectSha256: canonicalSha256ByBasename['stage7-rollback-resilience-complete.json'],
      completionEnvelopeSha256: 'a'.repeat(64),
    },
    canonicalSha256ByBasename,
  };
  const manifest = createStage7FinalManifest(manifestInput);
  const manifestContext = {
    ledger,
    handoff,
    evidenceIndexCheckpoint,
    gateEvaluationCheckpoint,
    scorecard,
    runbook,
    jobResults: jobs,
    stage6Closeout,
    expectedJobs: ['release-metadata'],
    expectedJobExecution,
    expectedAuthorities: manifest.authorities,
    expectedOwnerAlias: ownerAlias,
    expectedUrls: urls,
    expectedPublication: manifest.publication,
    expectedRollback: manifest.rollback,
    canonicalSha256ByBasename,
  };
  validateStage7FinalManifest(manifest, manifestContext);
  assert.equal(manifest.releaseMode, 'VERSIONED_UPDATE');
  assert.equal(manifest.runtimeSha, candidateSha);
  assert.equal(manifest.submissionSha, manifest.publication.readmeCommitSha);
  assert.deepEqual(manifest.artifacts, ledger.counts.artifacts);
  assert.deepEqual(manifest.evidence, ledger.counts.evidence);
  assert.equal(
    manifest.status,
    ledger.status === 'VERIFIED'
      ? 'RELEASED'
      : ledger.status === 'FAILED'
        ? 'FAILED'
        : ledger.status === 'BLOCKED_AUTH'
          ? 'BLOCKED_AUTH'
          : 'IN_PROGRESS',
  );
  assert.equal(manifest.manifestSha256.length, 64);
  const ledgerWith = (artifacts, evidence = allEvidenceRows) =>
    createStage7ProvenanceLedger({
      scope: 'full',
      candidateSha,
      releaseId,
      releaseTag,
      generatedAtUtc,
      entryGate: 'PASS',
      artifactRows: artifacts,
      evidenceRows: evidence,
      handoff,
      canonicalSha256ByBasename,
    });
  assert.throws(
    () =>
      ledgerWith(
        artifactRows,
        allEvidenceRows.map((row) =>
          row.id === 'EVD-E7-36'
            ? {
                ...row,
                sources: row.sources.map((source) =>
                  pathBasename(source.path) === 'smoke.json'
                    ? { ...source, sha256: '9'.repeat(64) }
                    : source,
                ),
              }
            : row,
        ),
      ),
    (error) => error.code === 'E7_PROVENANCE_SOURCE_AUTHORITY_CONFLICT',
  );
  for (const index of [17, 18, 19]) {
    const current = artifactRows[index].status;
    const changed = current === 'VERIFIED' ? 'IN_PROGRESS' : 'VERIFIED';
    assert.throws(
      () =>
        ledgerWith(
          artifactRows.map((row, rowIndex) =>
            rowIndex === index ? { ...row, status: changed } : row,
          ),
        ),
      (error) => error instanceof Stage7ProvenanceError,
    );
    assert.throws(
      () => ledgerWith(artifactRows.filter((_, rowIndex) => rowIndex !== index)),
      (error) => error.code === 'E7_PROVENANCE_MATRIX_INCOMPLETE',
    );
  }
  for (const index of [17, 18]) {
    assert.throws(
      () =>
        ledgerWith(
          artifactRows.map((row, rowIndex) =>
            rowIndex === index
              ? {
                  ...row,
                  sources: [
                    { ...row.sources[0], sha256: ((index + 1) % 16).toString(16).repeat(64) },
                  ],
                }
              : row,
          ),
        ),
      (error) => error instanceof Stage7ProvenanceError,
    );
  }
  for (const index of [54, 55, 56]) {
    const current = allEvidenceRows[index].status;
    const changed = current === 'FAIL' ? 'PASS' : 'FAIL';
    assert.throws(
      () =>
        ledgerWith(
          artifactRows,
          allEvidenceRows.map((row, rowIndex) =>
            rowIndex === index ? { ...row, status: changed } : row,
          ),
        ),
      (error) => error instanceof Stage7ProvenanceError,
    );
    assert.throws(
      () =>
        ledgerWith(
          artifactRows,
          allEvidenceRows.filter((_, rowIndex) => rowIndex !== index),
        ),
      (error) => error.code === 'E7_PROVENANCE_MATRIX_INCOMPLETE',
    );
    assert.throws(
      () =>
        ledgerWith(
          artifactRows,
          allEvidenceRows.map((row, rowIndex) =>
            rowIndex === index
              ? {
                  ...row,
                  sources: [
                    { ...row.sources[0], sha256: ((index + 1) % 16).toString(16).repeat(64) },
                  ],
                }
              : row,
          ),
        ),
      (error) => error instanceof Stage7ProvenanceError,
    );
  }
  assert.throws(
    () =>
      ledgerWith(
        artifactRows,
        allEvidenceRows.map((row, index) =>
          index === 29
            ? {
                ...row,
                sources: [{ ...row.sources[0], producerJob: 'release-metadata' }],
              }
            : row,
        ),
      ),
    (error) => error.code === 'E7_PROVENANCE_SOURCE_BINDING_INVALID',
  );
  const tamperedHandoffSourceArtifacts = artifactRows.map((row, index) =>
    index === 19
      ? {
          ...row,
          sources: [{ ...row.sources[0], sha256: '9'.repeat(64) }],
        }
      : row,
  );
  const tamperedHandoffSourceLedger = ledgerWith(tamperedHandoffSourceArtifacts);
  assert.throws(
    () =>
      createStage7FinalManifest({
        ...manifestInput,
        ledger: tamperedHandoffSourceLedger,
      }),
    (error) => error.code === 'E7_FINAL_MANIFEST_AUTHORITY_MISMATCH',
  );
  assert.doesNotThrow(() =>
    createJobResultsDocument({
      scope: 'full',
      candidateSha,
      releaseId,
      releaseTag: 'v1.0.0',
      generatedAtUtc,
      runId: '123',
      runAttempt: 1,
      workflow: 'Stage 7 release',
      jobs: ['release-metadata'],
    }),
  );
  assert.throws(
    () =>
      createJobResultsDocument({
        scope: 'full',
        candidateSha,
        releaseId,
        releaseTag: 'v01.0.0',
        generatedAtUtc,
        runId: '123',
        runAttempt: 1,
        workflow: 'Stage 7 release',
        jobs: ['release-metadata'],
      }),
    (error) => error.code === 'E7_PROVENANCE_IDENTITY_INVALID',
  );
  const replaceEvidenceStatus = (id, status) =>
    allEvidenceRows.map((row) => (row.id === id ? { ...row, status } : row));
  const handoffForEvidenceStatus = (id, status) => {
    const changedBaseRows = baseEvidenceRows.map((row) =>
      row.id === id ? { ...row, status } : row,
    );
    const changedOperationalRows = createOperationalArtifactRows({
      evidenceRows: changedBaseRows,
      ownerAlias,
      validatedAtUtc: generatedAtUtc,
    });
    const changedGateCheckpoint = createGateEvaluationCheckpoint({
      scope: 'full',
      candidateSha,
      releaseId,
      releaseTag,
      ownerAlias,
      generatedAtUtc,
      entryGate: 'PASS',
      operationalArtifactRows: changedOperationalRows,
      evidenceRows: changedBaseRows,
    });
    const changedGateRows = STAGE7_EVIDENCE.slice(54).map(({ id: gateId, name }, index) =>
      createProvenanceRow({
        id: gateId,
        name,
        status: changedGateCheckpoint.gates[GATE_NAMES[index]],
        ownerAlias,
        validatedAtUtc: generatedAtUtc,
        validator: 'deriveStage7Gates',
        sources: STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full[index + 54].map(sourceForBasename),
      }),
    );
    const changedEvidenceRows = [...changedBaseRows, ...changedGateRows];
    const changedIndexCheckpoint = createEvidenceIndexCheckpoint({
      scope: 'full',
      candidateSha,
      releaseId,
      releaseTag,
      ownerAlias,
      generatedAtUtc,
      evidenceRows: changedEvidenceRows,
    });
    const changedAuthorityRows = createAuthorityArtifactRows({
      evidenceRows: changedEvidenceRows,
      ownerAlias,
      validatedAtUtc: generatedAtUtc,
      operationalArtifactRows: changedOperationalRows,
      evidenceIndexCheckpoint: changedIndexCheckpoint,
      evidenceIndexSource,
      gateEvaluationCheckpoint: changedGateCheckpoint,
      gateEvaluationSource,
      entryGate: 'PASS',
    });
    return createStage7Handoff({
      scope: 'full',
      candidateSha,
      releaseId,
      releaseTag,
      ownerAlias,
      generatedAtUtc,
      artifactRows: changedAuthorityRows,
      evidenceRows: changedEvidenceRows,
    });
  };
  assert.equal(handoffForEvidenceStatus('EVD-E7-35', 'FAIL').status, 'FAIL');
  assert.equal(handoffForEvidenceStatus('EVD-E7-35', 'NOT_RUN').status, 'NOT_RUN');
  assert.throws(
    () => validateProvenanceRow({ ...baseEvidenceRows[0], ownerAlias: 'x' }, { kind: 'evidence' }),
    (error) => error.code === 'E7_PROVENANCE_ROW_INVALID',
  );
  assert.throws(
    () =>
      ledgerWith(
        artifactRows,
        allEvidenceRows.map((row, index) =>
          index === 0 ? { ...row, ownerAlias: 'different-owner' } : row,
        ),
      ),
    (error) => error.code === 'E7_PROVENANCE_AUTHORITY_IDENTITY_INVALID',
  );
  assert.throws(
    () =>
      ledgerWith(
        artifactRows,
        allEvidenceRows.map((row, index) =>
          index === 0 ? { ...row, validatedAtUtc: '2026-08-18T12:00:01.000Z' } : row,
        ),
      ),
    (error) => error.code === 'E7_PROVENANCE_AUTHORITY_IDENTITY_INVALID',
  );
  assert.throws(
    () =>
      validateProvenanceRow(
        { ...baseEvidenceRows[0], validatedAtUtc: '2026-08-18' },
        { kind: 'evidence' },
      ),
    (error) => error.code === 'E7_PROVENANCE_ROW_INVALID',
  );
  assert.throws(
    () =>
      createStage7FinalManifest({
        ...manifestInput,
        scorecard: { ...scorecard, ownerAlias: 'different-owner' },
      }),
    (error) => error.code === 'E7_FINAL_MANIFEST_INVALID',
  );
  assert.throws(
    () =>
      createStage7FinalManifest({
        ...manifestInput,
        jobResults: { ...jobs, generatedAtUtc: '2026-08-18T12:00:01.000Z' },
      }),
    (error) => error.code === 'E7_FINAL_MANIFEST_INVALID',
  );
  assert.throws(
    () =>
      createGateEvaluationCheckpoint({
        scope: 'full',
        candidateSha,
        releaseId,
        releaseTag,
        ownerAlias,
        generatedAtUtc,
        entryGate: 'PASS',
        operationalArtifactRows: operationalArtifactRows.map((row, index) =>
          index === 0 ? { ...row, status: 'FAILED' } : row,
        ),
        evidenceRows: baseEvidenceRows,
      }),
    (error) => error.code === 'E7_OPERATIONAL_ARTIFACT_MATRIX_INVALID',
  );
  assert.throws(
    () =>
      createArtifactRows({
        authorityArtifactRows,
        evidenceRows: allEvidenceRows,
        ownerAlias,
        validatedAtUtc: generatedAtUtc,
        operationalArtifactRows,
        evidenceIndexCheckpoint,
        evidenceIndexSource: {
          ...evidenceIndexSource,
          path: 'output/evidence/runtime/stage-7/unrelated.json',
        },
        gateEvaluationCheckpoint,
        gateEvaluationSource,
        entryGate: 'PASS',
        handoff,
        handoffSource,
      }),
    (error) => error.code === 'E7_PROVENANCE_SOURCE_BINDING_INVALID',
  );
  assert.throws(
    () =>
      validateStage7ProvenanceLedger(
        { ...ledger, counts: { ...ledger.counts, evidence: { pass: 57, total: 56 } } },
        { entryGate: 'PASS', handoff, canonicalSha256ByBasename },
      ),
    (error) => error.code === 'E7_PROVENANCE_LEDGER_INVALID',
  );
  assert.throws(
    () =>
      validateStage7ProvenanceLedger(
        { ...ledger, evidence: replaceEvidenceStatus('EVD-E7-01', 'NOT_RUN') },
        { entryGate: 'PASS', handoff, canonicalSha256ByBasename },
      ),
    (error) =>
      ['E7_PROVENANCE_LEDGER_INVALID', 'E7_PROVENANCE_LEDGER_STATE_INVALID'].includes(error.code),
  );
  assert.throws(
    () => validateStage7FinalManifest({ ...manifest, unexpected: true }, manifestContext),
    (error) => error.code === 'E7_FINAL_MANIFEST_INVALID',
  );
  for (const [key, value] of [
    ['runtimeSha', '9'.repeat(40)],
    ['submissionSha', '8'.repeat(40)],
  ]) {
    const identityTamperBody = { ...manifest, [key]: value };
    delete identityTamperBody.manifestSha256;
    assert.throws(
      () =>
        validateStage7FinalManifest(
          { ...identityTamperBody, manifestSha256: objectSha256(identityTamperBody) },
          manifestContext,
        ),
      (error) => error.code === 'E7_FINAL_MANIFEST_INVALID',
    );
  }
  const wrongUrlsBody = {
    ...manifest,
    urls: { ...manifest.urls, application: 'https://attacker.example.test' },
  };
  delete wrongUrlsBody.manifestSha256;
  assert.throws(
    () =>
      validateStage7FinalManifest(
        { ...wrongUrlsBody, manifestSha256: objectSha256(wrongUrlsBody) },
        manifestContext,
      ),
    (error) => error.code === 'E7_FINAL_MANIFEST_INVALID',
  );
  const wrongOwnerManifestBody = { ...manifest, ownerAlias: 'different-owner' };
  delete wrongOwnerManifestBody.manifestSha256;
  assert.throws(
    () =>
      validateStage7FinalManifest(
        {
          ...wrongOwnerManifestBody,
          manifestSha256: objectSha256(wrongOwnerManifestBody),
        },
        manifestContext,
      ),
    (error) => error.code === 'E7_FINAL_MANIFEST_INVALID',
  );
  const mismatchedAuthorities = {
    ...manifest.authorities,
    stage6CloseoutSha256: '9'.repeat(64),
  };
  const mismatchedBody = {
    ...manifest,
    authorities: mismatchedAuthorities,
  };
  delete mismatchedBody.manifestSha256;
  const mismatchedManifest = {
    ...mismatchedBody,
    manifestSha256: objectSha256(mismatchedBody),
  };
  assert.throws(
    () => validateStage7FinalManifest(mismatchedManifest, manifestContext),
    (error) => error.code === 'E7_FINAL_MANIFEST_INVALID',
  );
  const resealLedger = (overrides) => {
    const body = { ...ledger, ...overrides };
    delete body.ledgerSha256;
    return { ...body, ledgerSha256: objectSha256(body) };
  };
  const swappedBindings = {
    ...ledger.sourceBindings,
    approval: ledger.sourceBindings.activation,
    activation: ledger.sourceBindings.approval,
  };
  assert.throws(
    () =>
      validateStage7ProvenanceLedger(resealLedger({ sourceBindings: swappedBindings }), {
        entryGate: 'PASS',
        handoff,
        canonicalSha256ByBasename,
      }),
    (error) => error.code === 'E7_LEDGER_SOURCE_BINDING_INVALID',
  );
  const tamperedCanonicalBindings = {
    ...ledger.sourceBindings,
    rollbackResilienceCompletion: {
      ...ledger.sourceBindings.rollbackResilienceCompletion,
      objectSha256: '9'.repeat(64),
    },
  };
  assert.throws(
    () =>
      validateStage7ProvenanceLedger(resealLedger({ sourceBindings: tamperedCanonicalBindings }), {
        entryGate: 'PASS',
        handoff,
        canonicalSha256ByBasename,
      }),
    (error) => error.code === 'E7_LEDGER_SOURCE_BINDING_INVALID',
  );
  const resealManifest = (overrides) => {
    const body = { ...manifest, ...overrides };
    delete body.manifestSha256;
    return { ...body, manifestSha256: objectSha256(body) };
  };
  assert.throws(
    () =>
      validateStage7FinalManifest(
        resealManifest({
          publication: { ...manifest.publication, repositoryPublic: false },
        }),
        manifestContext,
      ),
    (error) => error.code === 'E7_FINAL_MANIFEST_INVALID',
  );
  assert.throws(
    () =>
      validateStage7FinalManifest(
        resealManifest({
          rollback: { ...manifest.rollback, completionObjectSha256: '9'.repeat(64) },
        }),
        manifestContext,
      ),
    (error) => error.code === 'E7_FINAL_MANIFEST_INVALID',
  );
};

if (process.argv.includes('--self-test')) {
  selfTestStage7Provenance();
  process.stdout.write('stage-7 provenance self-test: PASS\n');
}
