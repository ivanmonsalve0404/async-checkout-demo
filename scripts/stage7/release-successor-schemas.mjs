import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import Ajv2020 from '@redocly/ajv/dist/2020.js';

import { PREVIOUS_RELEASE_PROJECTION_FILENAMES } from './previous-release-projection.mjs';
import {
  RELEASE_SUCCESSOR_SOURCE_LAYOUT,
  RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES,
} from './release-successor-contract.mjs';
import { RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_KIND } from './release-successor-iam-authority.mjs';

const directory = path.dirname(fileURLToPath(import.meta.url));
const readSchema = (name) => JSON.parse(readFileSync(path.join(directory, name), 'utf8'));

export const selfTestReleaseSuccessorSchemas = () => {
  const source = readSchema('release-successor-source.schema.json');
  const provenance = readSchema('release-successor-source-provenance.schema.json');
  const finalization = readSchema('release-successor-finalization.schema.json');
  const cleanup = readSchema('release-successor-cleanup-receipt.schema.json');
  const preservation = readSchema('release-successor-preservation-receipt.schema.json');
  const postObservation = readSchema('release-successor-post-observation.schema.json');
  const journalSnapshot = readSchema('release-successor-journal-snapshot.schema.json');
  const retrySelection = readSchema('release-successor-retry-selection.schema.json');
  const projection = readSchema('previous-release-projection-index.schema.json');
  const iam = readSchema('release-successor-journal-role-effective-permissions.schema.json');
  const rollbackJournal = readSchema('rollback-resilience-journal.schema.json');
  const layoutCount = Object.keys(RELEASE_SUCCESSOR_SOURCE_LAYOUT).length;
  const payloadCount = layoutCount - 2;
  assert.equal(source.properties.files.minItems, layoutCount - 1);
  assert.equal(source.properties.files.maxItems, layoutCount - 1);
  assert.equal(provenance.properties.files.minItems, payloadCount);
  assert.equal(provenance.properties.files.maxItems, payloadCount);
  assert.equal(provenance.properties.canonicalSha256ByPath.minProperties, payloadCount - 1);
  assert.equal(provenance.properties.canonicalSha256ByPath.maxProperties, payloadCount - 1);
  assert.equal(provenance.properties.artifactOriginsByPath.minProperties, payloadCount);
  assert.equal(provenance.properties.artifactOriginsByPath.maxProperties, payloadCount);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addFormat('date-time', {
    type: 'string',
    validate: (value) =>
      typeof value === 'string' &&
      !Number.isNaN(Date.parse(value)) &&
      new Date(value).toISOString() === value,
  });
  const canonicalSha256ByPathValidator = ajv.compile({
    ...provenance.properties.canonicalSha256ByPath,
    $defs: provenance.$defs,
  });
  const artifactOriginsByPathValidator = ajv.compile({
    ...provenance.properties.artifactOriginsByPath,
    $defs: provenance.$defs,
  });
  const rawFileValidator = ajv.compile({
    ...provenance.$defs.rawFile,
    $defs: provenance.$defs,
  });
  const canonicalSha256ByPathEntries = Array.from({ length: payloadCount - 1 }, (_, index) => [
    `canonical-${index}.json`,
    'a'.repeat(64),
  ]);
  const artifactOriginsByPathEntries = Array.from({ length: payloadCount }, (_, index) => [
    `artifact-${index}.json`,
    `release-successor-source-${index}`,
  ]);
  const provenanceValidator = ajv.compile(provenance);
  const provenanceDocument = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_SOURCE_PROVENANCE',
    status: 'PASS',
    artifactName: 'stage7-release-successor-source',
    repository: 'ivanmonsalve0404/async-checkout-demo',
    workflowPath: '.github/workflows/release.yml',
    sourceEvent: 'workflow_dispatch',
    sourceRef: 'refs/heads/master',
    sourceRunId: '32524629359',
    sourceRunAttempt: 1,
    headSha: 'a'.repeat(40),
    releaseId: 'rel-20260822-1200-aaaaaaa',
    releaseTag: 'v2026.8.22',
    sourceKind: 'RELEASE_SUCCESSOR_POST_SUCCESS',
    predecessorManifestSha256: '1'.repeat(64),
    candidateRecordSha256: '2'.repeat(64),
    rollbackRehearsalSha256: '3'.repeat(64),
    journalLifecycleSha256: '4'.repeat(64),
    reconciliationJournalAuthority: {
      schemaVersion: 1,
      stage: 7,
      kind: 'STAGE7_RELEASE_RECONCILIATION_JOURNAL_AUTHORITY',
      status: 'PRESERVE_THEN_DELETE_EXACT_SET',
      source: {},
      cleanupParameterNames: [
        '/checkout/stage7/rollback/one',
        '/checkout/stage7/rollback/two',
        '/checkout/stage7/rollback/three',
        '/checkout/stage7/rollback/four',
      ],
      cleanupParameterCount: 4,
      requiredResidualCount: 0,
      containsSensitiveData: false,
      journalAuthoritySha256: '5'.repeat(64),
    },
    reconciliationJournalAuthoritySha256: '5'.repeat(64),
    reconciliationEvidenceBindings: {
      rollbackCheck: {
        path: 'release-successor-rollback-check.json',
        artifactName: 'stage7-release-reconciliation',
        rawSha256: '6'.repeat(64),
        canonicalSha256: '7'.repeat(64),
        bytes: 2,
        receiptSha256: '8'.repeat(64),
      },
      rollbackResilience: {
        path: 'release-successor-rollback-resilience.json',
        artifactName: 'stage7-release-reconciliation',
        rawSha256: '9'.repeat(64),
        canonicalSha256: 'a'.repeat(64),
        bytes: 2,
        receiptSha256: 'b'.repeat(64),
      },
      preFenceGate: {
        path: 'release-successor-pre-fence-gate.json',
        artifactName: 'stage7-release-reconciliation',
        rawSha256: 'c'.repeat(64),
        canonicalSha256: 'd'.repeat(64),
        bytes: 2,
        gateSha256: 'e'.repeat(64),
      },
    },
    releaseFenceAuthoritySetSha256: 'f'.repeat(64),
    journalSnapshotBinding: {
      path: 'release-reconciliation-journal-snapshot.json',
      rawSha256: '1'.repeat(64),
      canonicalSha256: '2'.repeat(64),
      bytes: 2,
      snapshotSha256: '3'.repeat(64),
      targetNameSetSha256: '4'.repeat(64),
      entryCount: 3,
    },
    releaseEvidenceSetSha256: '5'.repeat(64),
    finalDisableEvidenceSha256: '6'.repeat(64),
    files: RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES.map((pathName) => ({
      path: pathName,
      sha256: '7'.repeat(64),
      bytes: 2,
    })),
    canonicalSha256ByPath: Object.fromEntries(canonicalSha256ByPathEntries),
    artifactOriginsByPath: Object.fromEntries(artifactOriginsByPathEntries),
    bundleSha256: '8'.repeat(64),
    capturedAtUtc: '2026-08-22T17:00:00.000Z',
    externalRequests: 3,
    mutationsPerformed: 0,
    containsSensitiveData: false,
    provenanceSha256: '9'.repeat(64),
  };
  assert.equal(
    canonicalSha256ByPathValidator(Object.fromEntries(canonicalSha256ByPathEntries)),
    true,
  );
  assert.equal(
    canonicalSha256ByPathValidator(Object.fromEntries(canonicalSha256ByPathEntries.slice(1))),
    false,
  );
  assert.equal(
    canonicalSha256ByPathValidator(
      Object.fromEntries([...canonicalSha256ByPathEntries, ['unexpected.json', 'b'.repeat(64)]]),
    ),
    false,
  );
  assert.equal(
    artifactOriginsByPathValidator(Object.fromEntries(artifactOriginsByPathEntries)),
    true,
  );
  assert.equal(
    artifactOriginsByPathValidator(Object.fromEntries(artifactOriginsByPathEntries.slice(1))),
    false,
  );
  assert.equal(
    artifactOriginsByPathValidator(
      Object.fromEntries([
        ...artifactOriginsByPathEntries,
        ['unexpected.json', 'release-successor-source-extra'],
      ]),
    ),
    false,
  );
  assert.deepEqual(
    provenanceDocument.files.filter((entry) => !rawFileValidator(entry)),
    [],
  );
  assert.equal(
    rawFileValidator({
      path: 'stage7-release-journal-role-effective-permissions-tampered.json',
      sha256: '7'.repeat(64),
      bytes: 2,
    }),
    false,
  );
  assert.equal(provenanceValidator(provenanceDocument), true);
  assert.equal(
    provenanceValidator({
      ...provenanceDocument,
      sourceKind: 'RELEASE_SUCCESSOR_POST_SUCCESS_COMPOSITE_RECOVERY',
    }),
    true,
  );
  assert.equal(
    provenanceValidator({
      ...provenanceDocument,
      sourceKind: 'RELEASE_SUCCESSOR_POST_SUCCESS_TAMPERED',
    }),
    false,
  );
  assert.equal(
    iam.properties.kind.const,
    RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_KIND,
  );
  assert.equal(
    iam.properties.permissionProfile.properties.profileKey.const,
    'journalCleanupRoleArn',
  );
  assert.equal(
    finalization.$defs.roleAuthority.required.includes('effectivePolicyProjectionSha256'),
    true,
  );
  assert.equal(finalization.$defs.evidenceBindings.required.includes('preFenceGate'), true);
  assert.equal(finalization.$defs.fence.required.includes('authoritySetSha256'), true);
  assert.equal(source.required.includes('journalSnapshotBinding'), true);
  assert.equal(source.required.includes('releaseFenceAuthoritySetSha256'), true);
  assert.equal(source.required.includes('reconciliationJournalAuthoritySha256'), true);
  assert.equal(provenance.required.includes('reconciliationJournalAuthority'), true);
  assert.equal(provenance.required.includes('reconciliationEvidenceBindings'), true);
  assert.equal(provenance.required.includes('journalSnapshotBinding'), true);
  assert.equal(provenance.required.includes('releaseFenceAuthoritySetSha256'), true);
  assert.equal(preservation.required.includes('journalSnapshotBinding'), true);
  assert.equal(preservation.required.includes('reconciliationJournalAuthoritySha256'), true);
  assert.equal(postObservation.required.includes('sourcePreservationRunAttempt'), true);
  assert.equal(postObservation.$defs.selectedArtifact.required.includes('attempt'), true);
  assert.equal(cleanup.required.includes('reconciliationParameters'), false);
  assert.equal(cleanup.required.includes('reconciliationJournalAuthority'), true);
  assert.equal(cleanup.required.includes('cleanupTargetSet'), true);
  assert.equal(cleanup.required.includes('journalSnapshotBinding'), true);
  assert.equal(cleanup.required.includes('sourcePreservationRunAttempt'), true);
  assert.equal(
    journalSnapshot.properties.kind.const,
    'RELEASE_SUCCESSOR_COMBINED_JOURNAL_SNAPSHOT',
  );
  assert.equal(journalSnapshot.properties.entries.items.$ref, '#/$defs/entry');
  assert.equal(retrySelection.properties.kind.const, 'RELEASE_SUCCESSOR_RETRY_SOURCE_SELECTION');
  assert.equal(
    projection.properties.sourceBundle.properties.journalSnapshotBinding.$ref,
    '#/$defs/journalSnapshotBinding',
  );
  assert.equal(PREVIOUS_RELEASE_PROJECTION_FILENAMES.length, 8);
  assert.equal(projection.properties.files.minItems, 7);
  assert.equal(projection.properties.files.maxItems, 7);
  assert.equal(
    rollbackJournal.oneOf.some(({ $ref }) => $ref === '#/$defs/owner'),
    true,
  );
  assert.equal(
    rollbackJournal.oneOf.some(({ $ref }) => $ref === '#/$defs/premutationAuthority'),
    true,
  );
  assert.equal(
    rollbackJournal.$defs.premutationAuthority.required.includes('rollbackBindingPreimage'),
    true,
  );
  assert.equal(rollbackJournal.$defs.owner.required.includes('journalCleanupRoleSha256'), true);
  assert.equal(
    rollbackJournal.$defs.owner.required.includes('premutationAuthorityRawSha256'),
    true,
  );
  return { status: 'PASS', canaries: 51, externalRequests: 0 };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--self-test') {
    throw new Error('E7_RELEASE_SUCCESSOR_SCHEMA_COMMAND_INVALID');
  }
  process.stdout.write(`${JSON.stringify(selfTestReleaseSuccessorSchemas())}\n`);
}
