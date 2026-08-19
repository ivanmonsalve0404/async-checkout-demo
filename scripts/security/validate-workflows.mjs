#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import {
  validatePrereleaseWorkflow,
  validateReleaseWorkflow,
  validateReleaseWorkflowCommands,
} from './validate-release-workflow.mjs';
import {
  PRERELEASE_CLEANUP_WORKFLOW,
  validatePrereleaseCleanupWorkflow,
} from './validate-prerelease-cleanup-workflow.mjs';
import {
  BASELINE_WORKFLOW,
  selfTestBaselineWorkflow,
  validateBaselineWorkflow,
} from './validate-baseline-workflow.mjs';
import {
  ROLLBACK_RESILIENCE_WORKFLOW,
  validateRollbackResilienceWorkflow,
} from './validate-rollback-resilience-workflow.mjs';
import {
  RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW,
  validateReleaseSuccessorPostSuccessWorkflow,
} from './validate-release-successor-post-success-workflow.mjs';
import {
  PUBLICATION_RECOVERY_WORKFLOW,
  selfTestPublicationRecoveryWorkflow,
  validatePublicationRecoveryWorkflow,
} from './validate-release-successor-publication-recovery-workflow.mjs';
import {
  STAGE7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW,
  validateStage7ReleaseReconciliationRecoveryWorkflow,
} from './validate-stage7-release-reconciliation-recovery.mjs';

const ACTION_REFERENCE = /^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*(?:#.*)?$/gmu;
const PINNED_SHA = /^[0-9a-f]{40}$/u;
const CODEQL_WORKFLOW = 'ci.yml';
const RELEASE_WORKFLOW = 'release.yml';
const PRERELEASE_WORKFLOW = 'prerelease.yml';
const CODEQL_ACTION_SHA = 'ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd';
const SETUP_NODE_ACTION_SHA = 'a0853c24544627f65ddf259abe73b1d18a591444';
const UPLOAD_ARTIFACT_ACTION_SHA = 'ea165f8d65b6e75b540449e92b4886f43607fa02';
const VERIFICATION_REPORT_PATHS = [
  'coverage/api/coverage-summary.json',
  'coverage/web/coverage-summary.json',
  'infra/cdk.out/*.template.json',
  'output/evidence/runtime/stage-5-dynamodb-integration.json',
  'output/evidence/runtime/stage-5-smoke-results.json',
  'output/evidence/runtime/stage-6/',
];
const UPLOAD_ARTIFACT_SCAN_COMMAND = 'node scripts/stage6/upload-artifact-scan.mjs';
const AUTHORIZED_SANDBOX_DRY_RUN_SCRIPT =
  'tsc -p scripts/stage6/sandbox-authorized/tsconfig.json --noEmit && node scripts/stage6/sandbox-authorized/run.mjs --self-test && node scripts/stage6/sandbox-authorized/run.mjs --dry-run';
const AUTHORIZED_SANDBOX_EXECUTE_SCRIPT =
  'node scripts/stage6/sandbox-authorized/run.mjs --execute';

const workflowJobIds = (source) => {
  const lines = source.replace(/\r\n?/gu, '\n').split('\n');
  const jobsIndex = lines.findIndex((line) => line === 'jobs:');
  if (jobsIndex === -1) return [];
  const ids = [];
  for (const line of lines.slice(jobsIndex + 1)) {
    if (line.length > 0 && !line.startsWith(' ')) break;
    const match = /^ {2}([a-zA-Z0-9_-]+):\s*$/u.exec(line);
    if (match !== null) ids.push(match[1]);
  }
  return ids;
};

const codeqlJobPermissions = (source) => {
  const lines = source.replace(/\r\n?/gu, '\n').split('\n');
  const jobIndex = lines.findIndex((line) => line === '  codeql:');
  if (jobIndex === -1) return [];
  const nextJobIndex = lines.findIndex(
    (line, index) => index > jobIndex && /^ {2}[a-zA-Z0-9_-]+:\s*$/u.test(line),
  );
  const jobEnd = nextJobIndex === -1 ? lines.length : nextJobIndex;
  const permissionsIndexes = lines
    .map((line, index) =>
      index > jobIndex && index < jobEnd && /^ {4}permissions:/u.test(line) ? index : -1,
    )
    .filter((index) => index !== -1);
  if (permissionsIndexes.length !== 1) return [];
  const [permissionsIndex] = permissionsIndexes;
  const permissions = [];
  for (const line of lines.slice(permissionsIndex + 1)) {
    const match = /^ {6}([a-z-]+):\s*([^\s]+)\s*$/u.exec(line);
    if (match === null) break;
    permissions.push([match[1], match[2]]);
  }
  return permissions;
};

const workflowJobBlock = (source, jobId) => {
  const lines = source.replace(/\r\n?/gu, '\n').split('\n');
  const start = lines.findIndex((line) => line === `  ${jobId}:`);
  if (start === -1) return '';
  const next = lines.findIndex(
    (line, index) => index > start && /^ {2}[a-zA-Z0-9_-]+:\s*$/u.test(line),
  );
  return lines.slice(start, next === -1 ? lines.length : next).join('\n');
};

const workflowStepBlocks = (source) => {
  const lines = source.replace(/\r\n?/gu, '\n').split('\n');
  const starts = lines
    .map((line, index) => (/^ {6}-\s/u.test(line) ? index : -1))
    .filter((index) => index !== -1);
  return starts.map((start, index) =>
    lines.slice(start, starts[index + 1] ?? lines.length).join('\n'),
  );
};

const verificationReportUploadIsExact = (verifyJob, actionReferences) => {
  const expectedAction = `actions/upload-artifact@${UPLOAD_ARTIFACT_ACTION_SHA}`;
  const uploadReferences = actionReferences.filter((reference) =>
    reference.startsWith('actions/upload-artifact@'),
  );
  const uploadSteps = workflowStepBlocks(verifyJob).filter((step) =>
    step.includes('uses: actions/upload-artifact@'),
  );
  if (
    uploadReferences.length !== 1 ||
    uploadReferences[0] !== expectedAction ||
    uploadSteps.length !== 1
  ) {
    return false;
  }
  const lines = uploadSteps[0].split('\n');
  if (
    lines.filter((line) => /^ {8}uses:/u.test(line)).length !== 1 ||
    lines.filter((line) => /^ {10}name:/u.test(line)).length !== 1 ||
    !lines.includes('          name: verification-reports') ||
    !lines.includes('          if-no-files-found: ignore') ||
    lines.filter((line) => /^ {10}path:/u.test(line)).length !== 1
  ) {
    return false;
  }
  const pathIndex = lines.indexOf('          path: |');
  if (pathIndex === -1) return false;
  const paths = [];
  for (const line of lines.slice(pathIndex + 1)) {
    if (line.trim().length === 0) continue;
    if (/^\s*/u.exec(line)[0].length <= 10) break;
    const match = /^ {12}(.+)$/u.exec(line);
    if (match === null) return false;
    paths.push(match[1]);
  }
  return JSON.stringify(paths) === JSON.stringify(VERIFICATION_REPORT_PATHS);
};

const verificationReportUploadGateIsExact = (verifyJob) => {
  const steps = workflowStepBlocks(verifyJob);
  const verifySteps = steps.filter((step) =>
    /^(?: {6}- run| {8}run): pnpm verify:stage6\s*$/mu.test(step),
  );
  const scanSteps = steps.filter(
    (step) =>
      step.includes('        id: stage6_upload_scan') ||
      step.includes(`        run: ${UPLOAD_ARTIFACT_SCAN_COMMAND}`),
  );
  const uploadSteps = steps.filter((step) => step.includes('uses: actions/upload-artifact@'));
  if (verifySteps.length !== 1 || scanSteps.length !== 1 || uploadSteps.length !== 1) return false;

  const [verifyStep] = verifySteps;
  const [scanStep] = scanSteps;
  const [uploadStep] = uploadSteps;
  const scanLines = scanStep.split('\n');
  const uploadLines = uploadStep.split('\n');
  return (
    steps.indexOf(verifyStep) < steps.indexOf(scanStep) &&
    steps.indexOf(scanStep) < steps.indexOf(uploadStep) &&
    scanLines.filter((line) => /^ {8}id:/u.test(line)).length === 1 &&
    scanLines.includes('        id: stage6_upload_scan') &&
    scanLines.filter((line) => /^ {8}if:/u.test(line)).length === 1 &&
    scanLines.includes('        if: ${{ always() }}') &&
    scanLines.filter((line) => /^ {8}run:/u.test(line)).length === 1 &&
    scanLines.includes(`        run: ${UPLOAD_ARTIFACT_SCAN_COMMAND}`) &&
    !scanStep.includes('continue-on-error:') &&
    uploadLines.filter((line) => /^ {8}if:/u.test(line)).length === 1 &&
    uploadLines.includes(
      "        if: ${{ always() && steps.stage6_upload_scan.outcome == 'success' }}",
    ) &&
    !uploadStep.includes('continue-on-error:')
  );
};

const permissionWrites = (source) => {
  const lines = source.replace(/\r\n?/gu, '\n').split('\n');
  const writes = [];
  for (const [index, line] of lines.entries()) {
    const header = /^(\s*)permissions:\s*(.*)$/iu.exec(line);
    if (header === null) continue;
    if (/\bwrite-all\b/iu.test(header[2])) writes.push('write-all');
    for (const match of header[2].matchAll(/([a-z][a-z-]*)\s*:\s*['"]?write['"]?/giu)) {
      writes.push(match[1].toLowerCase());
    }
    const indentation = header[1].length;
    for (const nested of lines.slice(index + 1)) {
      if (nested.trim().length === 0) continue;
      if (/^\s*/u.exec(nested)[0].length <= indentation) break;
      const entry = /^\s*([a-z][a-z-]*):\s*['"]?write['"]?\s*(?:#.*)?$/iu.exec(nested);
      if (entry !== null) writes.push(entry[1].toLowerCase());
    }
  }
  return writes;
};

const authorizedSandboxWiringIsExact = (manifest, verifySource) => {
  if (
    manifest?.scripts?.['test:sandbox:authorized'] !== AUTHORIZED_SANDBOX_DRY_RUN_SCRIPT ||
    manifest?.scripts?.['sandbox:authorized:execute'] !== AUTHORIZED_SANDBOX_EXECUTE_SCRIPT
  ) {
    return false;
  }
  const start = verifySource.indexOf('const steps = [');
  const end = start === -1 ? -1 : verifySource.indexOf('\n];', start);
  if (start === -1 || end === -1) return false;
  const stepsSource = verifySource.slice(start, end);
  const authorizedId = "id: 'E6-SANDBOX-AUTHORIZED-DRY-RUN'";
  const authorizedIndex = stepsSource.indexOf(authorizedId);
  const evidenceIndex = stepsSource.indexOf("id: 'E6-SANDBOX-EVIDENCE'");
  const securityIndex = stepsSource.indexOf("id: 'E6-SECURITY'");
  const uatIndex = stepsSource.indexOf("id: 'E6-UAT'");
  const authorizedBlock = stepsSource.slice(authorizedIndex, evidenceIndex);
  return (
    (stepsSource.match(/id: 'E6-SANDBOX-AUTHORIZED-DRY-RUN'/gu) ?? []).length === 1 &&
    authorizedIndex !== -1 &&
    evidenceIndex !== -1 &&
    securityIndex !== -1 &&
    uatIndex !== -1 &&
    authorizedIndex < evidenceIndex &&
    authorizedIndex < securityIndex &&
    authorizedIndex < uatIndex &&
    authorizedBlock.includes("...pnpmCommand(['test:sandbox:authorized'])") &&
    !authorizedBlock.includes('allowedExitCodes') &&
    !stepsSource.includes('sandbox:authorized:execute') &&
    !stepsSource.includes("'--execute'")
  );
};

export function validateWorkflow(name, source) {
  if (name === RELEASE_WORKFLOW) {
    return validateReleaseWorkflow(name, source);
  }
  if (name === PRERELEASE_WORKFLOW) {
    return validatePrereleaseWorkflow(name, source);
  }
  if (name === PRERELEASE_CLEANUP_WORKFLOW) {
    return validatePrereleaseCleanupWorkflow(name, source).map((error) => `${name}: ${error}`);
  }
  if (name === BASELINE_WORKFLOW) {
    return validateBaselineWorkflow(name, source);
  }
  if (name === ROLLBACK_RESILIENCE_WORKFLOW) {
    try {
      validateRollbackResilienceWorkflow({
        workflow: source,
        release: fs.readFileSync(
          path.join(process.cwd(), '.github', 'workflows', RELEASE_WORKFLOW),
          'utf8',
        ),
      });
      return [];
    } catch (error) {
      return [`${name}: ${error instanceof Error ? error.message : String(error)}`];
    }
  }
  if (name === RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW) {
    try {
      validateReleaseSuccessorPostSuccessWorkflow(source);
      return [];
    } catch (error) {
      return [`${name}: ${error instanceof Error ? error.message : String(error)}`];
    }
  }
  if (name === PUBLICATION_RECOVERY_WORKFLOW) {
    try {
      validatePublicationRecoveryWorkflow(source);
      return [];
    } catch (error) {
      return [`${name}: ${error instanceof Error ? error.message : String(error)}`];
    }
  }
  if (name === STAGE7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW) {
    try {
      validateStage7ReleaseReconciliationRecoveryWorkflow(source);
      return [];
    } catch (error) {
      return [`${name}: ${error instanceof Error ? error.message : String(error)}`];
    }
  }

  const errors = [];

  if (!/^\s{0}permissions:\s*\r?\n\s{2}contents:\s*read\s*$/gmu.test(source)) {
    errors.push('top-level permissions must be exactly contents: read');
  }
  if (!/\bpull_request\s*:/u.test(source)) {
    errors.push('pull_request trigger is required');
  }
  if (/\bpull_request_target\s*:/u.test(source)) {
    errors.push('pull_request_target is forbidden');
  }
  const codeqlJobForWritePolicy =
    name === CODEQL_WORKFLOW ? workflowJobBlock(source, 'codeql') : '';
  const sourceWithoutCodeql =
    codeqlJobForWritePolicy === '' ? source : source.replace(codeqlJobForWritePolicy, '');
  if (permissionWrites(sourceWithoutCodeql).length > 0) {
    errors.push('write permissions are forbidden outside the exact ci.yml CodeQL job');
  }
  if (/\bwrite-all\b/iu.test(source)) {
    errors.push('write-all is forbidden');
  }
  if (/\$\{\{\s*secrets\./iu.test(source)) {
    errors.push('secret contexts are forbidden in PR workflows');
  }
  if (/sandbox:authorized:execute|--execute/iu.test(source)) {
    errors.push('authorized sandbox execution is forbidden in CI workflows');
  }
  if (/aws-actions\/configure-aws-credentials/iu.test(source)) {
    errors.push('AWS credential actions are forbidden');
  }
  if (/\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b/u.test(source)) {
    errors.push('AWS credential environment variables are forbidden');
  }
  if (
    /\b(?:cdk|aws)\s+(?:bootstrap|cloudformation|deploy|destroy|dynamodb|lambda|s3)\b/iu.test(
      source,
    )
  ) {
    errors.push('cloud mutation commands are forbidden');
  }
  if (!/cancel-in-progress:\s*true\b/iu.test(source)) {
    errors.push('concurrency cancellation is required');
  }

  const runnerCount = (source.match(/^\s+runs-on:/gmu) ?? []).length;
  const timeoutCount = (source.match(/^\s+timeout-minutes:/gmu) ?? []).length;
  if (runnerCount === 0 || runnerCount !== timeoutCount) {
    errors.push('every job must define timeout-minutes');
  }

  ACTION_REFERENCE.lastIndex = 0;
  const actionReferences = [...source.matchAll(ACTION_REFERENCE)].map((match) => match[1]);
  for (const reference of actionReferences) {
    if (reference.startsWith('./')) {
      errors.push('local action references are forbidden outside an exact routed workflow');
      continue;
    }
    const separator = reference.lastIndexOf('@');
    const revision = separator === -1 ? '' : reference.slice(separator + 1);
    if (!PINNED_SHA.test(revision)) {
      errors.push('action must be pinned to a full SHA: ' + reference);
    }
  }

  const securityEventsWrites = source.match(/^\s*security-events:\s*write\s*$/gmu) ?? [];
  if (name !== CODEQL_WORKFLOW && securityEventsWrites.length > 0) {
    errors.push('security-events: write is only allowed in the ci.yml CodeQL job');
  }
  if (name === CODEQL_WORKFLOW) {
    const codeqlJob = workflowJobBlock(source, 'codeql');
    const verifyJob = workflowJobBlock(source, 'verify');
    const expectedPermissions = [
      ['contents', 'read'],
      ['security-events', 'write'],
    ];
    const jobIds = workflowJobIds(source);
    if (
      !jobIds.includes('codeql') ||
      JSON.stringify(codeqlJobPermissions(source)) !== JSON.stringify(expectedPermissions) ||
      securityEventsWrites.length !== 1
    ) {
      errors.push('The CodeQL job must have exactly contents: read and security-events: write');
    }
    const requiredCodeqlActions = [
      `github/codeql-action/init@${CODEQL_ACTION_SHA}`,
      `github/codeql-action/analyze@${CODEQL_ACTION_SHA}`,
    ];
    const codeqlReferences = actionReferences.filter((reference) =>
      reference.startsWith('github/codeql-action/'),
    );
    if (
      codeqlReferences.length !== requiredCodeqlActions.length ||
      requiredCodeqlActions.some((reference) => !codeqlReferences.includes(reference))
    ) {
      errors.push('CodeQL init/analyze must both use the approved full SHA');
    }
    if (
      !codeqlJob.includes(`actions/setup-node@${SETUP_NODE_ACTION_SHA}`) ||
      !codeqlJob.includes('node-version: ${{ env.NODE_VERSION }}')
    ) {
      errors.push('The CodeQL SARIF gate must use the pinned Node runtime');
    }
    const requiredSarifGateFragments = [
      'outputs:',
      'sarif_status:',
      'sarif_high:',
      'sarif_critical:',
      'sarif_sha256:',
      'id: codeql_analyze',
      'output: codeql-results',
      'upload: always',
      'id: codeql_gate',
      'codeql-sarif.mjs --input',
      'needs: [metadata, codeql]',
      'STAGE6_CODEQL_SARIF_STATUS:',
      'STAGE6_CODEQL_HIGH:',
      'STAGE6_CODEQL_CRITICAL:',
      'STAGE6_CODEQL_SARIF_SHA256:',
    ];
    if (requiredSarifGateFragments.some((fragment) => !source.includes(fragment))) {
      errors.push('CodeQL SARIF severity gate and Verify handoff are required');
    }
    const requiredManualEvidenceFragments = [
      'name: Materialize optional manual accessibility evidence',
      "if: ${{ github.event_name != 'pull_request' && vars.STAGE6_A11Y_MANUAL_EVIDENCE_B64 != '' }}",
      'STAGE6_A11Y_MANUAL_EVIDENCE_B64: ${{ vars.STAGE6_A11Y_MANUAL_EVIDENCE_B64 }}',
      'stage6-a11y-manual.json',
      'base64 --decode',
      'STAGE6_A11Y_MANUAL_EVIDENCE=${target}',
      'pnpm verify:stage6',
    ];
    const materializeIndex = verifyJob.indexOf(
      'name: Materialize optional manual accessibility evidence',
    );
    const verifyIndex = verifyJob.indexOf('pnpm verify:stage6');
    if (
      requiredManualEvidenceFragments.some((fragment) => !verifyJob.includes(fragment)) ||
      materializeIndex === -1 ||
      verifyIndex === -1 ||
      materializeIndex >= verifyIndex
    ) {
      errors.push('Verify must ingest optional same-commit manual accessibility evidence');
    }
    const requiredExternalEvidenceFragments = [
      'name: Materialize optional authorized external evidence',
      "if: ${{ github.event_name != 'pull_request' && vars.STAGE6_EXTERNAL_EVIDENCE_B64 != '' }}",
      'shell: bash',
      'STAGE6_EXTERNAL_EVIDENCE_B64: ${{ vars.STAGE6_EXTERNAL_EVIDENCE_B64 }}',
      'umask 077',
      '${RUNNER_TEMP}/stage6-external-evidence.json',
      'printf \'%s\' "${STAGE6_EXTERNAL_EVIDENCE_B64}" | base64 --decode > "${target}"',
      'STAGE6_EXTERNAL_EVIDENCE=${target}',
    ];
    const externalMaterializeIndex = verifyJob.indexOf(
      'name: Materialize optional authorized external evidence',
    );
    const externalMaterializeBlock =
      externalMaterializeIndex === -1 || verifyIndex === -1
        ? ''
        : verifyJob.slice(externalMaterializeIndex, verifyIndex);
    if (
      requiredExternalEvidenceFragments.some(
        (fragment) => !externalMaterializeBlock.includes(fragment),
      ) ||
      externalMaterializeIndex === -1 ||
      verifyIndex === -1 ||
      externalMaterializeIndex >= verifyIndex
    ) {
      errors.push('Verify must ingest optional authorized external evidence before Stage 6');
    }
    if (!verificationReportUploadIsExact(verifyJob, actionReferences)) {
      errors.push('verification-reports upload must be unique and use the exact sanitized paths');
    }
    if (!verificationReportUploadGateIsExact(verifyJob)) {
      errors.push('verification-reports upload must follow the mandatory artifact scan gate');
    }
  }

  return errors.map((error) => name + ': ' + error);
}

function selfTest() {
  const valid = [
    'name: Test',
    'on:',
    '  pull_request:',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  cancel-in-progress: true',
    'jobs:',
    '  check:',
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 5',
    '    steps:',
    '      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567',
  ].join('\n');
  assert.deepEqual(validateWorkflow('valid.yml', valid), []);
  assert.ok(
    validateWorkflow(
      'invalid.yml',
      valid
        .replace('pull_request:', 'pull_request_target:')
        .replace('0123456789abcdef0123456789abcdef01234567', 'v4'),
    ).length >= 2,
  );

  const releaseSource = fs.readFileSync(
    path.join(process.cwd(), '.github', 'workflows', RELEASE_WORKFLOW),
    'utf8',
  );
  assert.deepEqual(validateWorkflow(RELEASE_WORKFLOW, releaseSource), []);
  const malformedReleaseErrors = validateWorkflow(
    RELEASE_WORKFLOW,
    releaseSource.replace('  workflow_dispatch:', '  pull_request:'),
  );
  assert.ok(
    malformedReleaseErrors.some((error) =>
      error.includes('the only trigger must be workflow_dispatch'),
    ),
  );
  assert.ok(
    !malformedReleaseErrors.some((error) => error.includes('pull_request trigger is required')),
  );
  assert.ok(
    validateWorkflow('release-copy.yml', releaseSource).some((error) =>
      error.includes('pull_request trigger is required'),
    ),
  );
  const rollbackResilienceSource = fs.readFileSync(
    path.join(process.cwd(), '.github', 'workflows', ROLLBACK_RESILIENCE_WORKFLOW),
    'utf8',
  );
  assert.deepEqual(validateWorkflow(ROLLBACK_RESILIENCE_WORKFLOW, rollbackResilienceSource), []);
  assert.ok(
    validateWorkflow(
      ROLLBACK_RESILIENCE_WORKFLOW,
      rollbackResilienceSource.replace('  workflow_call:', '  workflow_dispatch:'),
    ).some((error) => error.includes('missing required contract: workflow_call:')),
  );
  assert.ok(
    validateWorkflow(
      ROLLBACK_RESILIENCE_WORKFLOW,
      rollbackResilienceSource.replace(
        'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',
        'actions/checkout@v5',
      ),
    ).some((error) => error.includes('pinned to one exact commit')),
  );
  assert.throws(
    () =>
      validateRollbackResilienceWorkflow({
        workflow: rollbackResilienceSource,
        release: releaseSource.replace(
          '    uses: ./.github/workflows/stage7-rollback-resilience.yml\n',
          '    uses: ./.github/workflows/stage7-rollback-resilience.yml\n    secrets: inherit\n',
        ),
      }),
    /publication still bypasses/u,
  );
  assert.throws(
    () =>
      validateRollbackResilienceWorkflow({
        workflow: rollbackResilienceSource,
        release: releaseSource.replace(
          "if: ${{ github.run_attempt == 1 && needs.release-reconciliation.result == 'success' }}\n    needs: release-reconciliation",
          "if: ${{ github.run_attempt == 1 && needs.rollback-resilience.outputs.rehearsal_pass == 'true' }}\n    needs: rollback-resilience",
        ),
      }),
    /protected reconciliation pre-fence chain|missing required contract/u,
  );
  assert.throws(
    () =>
      validateRollbackResilienceWorkflow({
        workflow: rollbackResilienceSource,
        release: releaseSource.replace(
          '      - rollback-resilience\n',
          '      - rollback-resilience-bypassed\n',
        ),
      }),
    /protected reconciliation pre-fence chain/u,
  );
  const releaseSuccessorPostSuccessSource = fs.readFileSync(
    path.join(process.cwd(), '.github', 'workflows', RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW),
    'utf8',
  );
  assert.deepEqual(
    validateWorkflow(RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW, releaseSuccessorPostSuccessSource),
    [],
  );
  assert.ok(
    validateWorkflow(
      RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW,
      releaseSuccessorPostSuccessSource.replace(
        'group: stage7-assessment-release',
        'group: unsafe-successor-race',
      ),
    ).some((error) => error.includes('missing required contract')),
  );
  const publicationRecoverySource = fs.readFileSync(
    path.join(process.cwd(), '.github', 'workflows', PUBLICATION_RECOVERY_WORKFLOW),
    'utf8',
  );
  assert.deepEqual(validateWorkflow(PUBLICATION_RECOVERY_WORKFLOW, publicationRecoverySource), []);
  selfTestPublicationRecoveryWorkflow();
  assert.ok(
    validateWorkflow(
      PUBLICATION_RECOVERY_WORKFLOW,
      publicationRecoverySource.replace(
        'group: stage7-assessment-release',
        'group: unsafe-publication-recovery-race',
      ),
    ).some((error) => error.includes('missing required contract')),
  );
  assert.ok(
    validateWorkflow(
      'stage7-release-successor-publication-recovery-copy.yml',
      publicationRecoverySource,
    ).some((error) => error.includes('pull_request trigger is required')),
  );
  assert.ok(
    validateWorkflow('stage7-release-successor-copy.yml', releaseSuccessorPostSuccessSource).some(
      (error) => error.includes('pull_request trigger is required'),
    ),
  );
  const reconciliationRecoverySource = fs.readFileSync(
    path.join(
      process.cwd(),
      '.github',
      'workflows',
      STAGE7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW,
    ),
    'utf8',
  );
  assert.deepEqual(
    validateWorkflow(STAGE7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW, reconciliationRecoverySource),
    [],
  );
  assert.ok(
    validateWorkflow(
      STAGE7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW,
      reconciliationRecoverySource.replace(
        'group: stage7-assessment-release',
        'group: unsafe-recovery-race',
      ),
    ).some((error) => error.includes('missing required contract')),
  );
  assert.ok(
    validateWorkflow(
      'stage7-release-reconciliation-recovery-copy.yml',
      reconciliationRecoverySource,
    ).some((error) => error.includes('pull_request trigger is required')),
  );
  assert.ok(
    validateWorkflow(
      'unsafe-local.yml',
      valid.replace(
        'actions/checkout@0123456789abcdef0123456789abcdef01234567',
        './.github/actions/unsafe',
      ),
    ).some((error) => error.includes('local action references are forbidden')),
  );
  const prereleaseSource = fs.readFileSync(
    path.join(process.cwd(), '.github', 'workflows', PRERELEASE_WORKFLOW),
    'utf8',
  );
  assert.deepEqual(validateWorkflow(PRERELEASE_WORKFLOW, prereleaseSource), []);
  const baselineSource = fs.readFileSync(
    path.join(process.cwd(), '.github', 'workflows', BASELINE_WORKFLOW),
    'utf8',
  );
  assert.deepEqual(validateWorkflow(BASELINE_WORKFLOW, baselineSource), []);
  selfTestBaselineWorkflow(baselineSource);
  const packageSource = fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8');
  assert.deepEqual(
    validateReleaseWorkflowCommands(
      [releaseSource, prereleaseSource, baselineSource, publicationRecoverySource],
      packageSource,
    ),
    [],
  );
  assert.ok(
    validateReleaseWorkflowCommands(
      [
        releaseSource.replace('pnpm release:seed --', 'pnpm release:orphan --'),
        prereleaseSource,
        baselineSource,
        publicationRecoverySource,
      ],
      packageSource,
    ).some((error) => error.includes('workflow command is orphaned: release:orphan')),
  );
  assert.ok(
    validateReleaseWorkflowCommands(
      [releaseSource, prereleaseSource, baselineSource, publicationRecoverySource],
      packageSource.replace(
        '"release:sandbox-smoke": "node scripts/stage7/control.mjs sandbox-smoke"',
        '"release:sandbox-smoke": "pnpm sandbox:authorized:execute"',
      ),
    ).some((error) => error.includes('direct Stage 6 execution alias is forbidden')),
  );
  assert.ok(
    validateReleaseWorkflowCommands(
      [releaseSource, prereleaseSource, baselineSource, publicationRecoverySource],
      packageSource.replace(
        'node scripts/stage7/release-successor-publication-recovery-self-test.mjs && node scripts/security/validate-release-successor-publication-recovery-workflow.mjs',
        'node scripts/stage7/release-successor-publication-recovery-self-test.mjs',
      ),
    ).some((error) =>
      error.includes('Stage 7 mapping diverges for release:publication-recovery:self-test'),
    ),
  );
  const malformedPrereleaseErrors = validateWorkflow(
    PRERELEASE_WORKFLOW,
    prereleaseSource.replace('  workflow_dispatch:', '  pull_request:'),
  );
  assert.ok(
    malformedPrereleaseErrors.some((error) =>
      error.includes('the only trigger must be workflow_dispatch'),
    ),
  );
  assert.ok(
    !malformedPrereleaseErrors.some((error) => error.includes('pull_request trigger is required')),
  );
  assert.ok(
    validateWorkflow('prerelease-copy.yml', prereleaseSource).some((error) =>
      error.includes('pull_request trigger is required'),
    ),
  );
  const prereleaseCleanupSource = fs.readFileSync(
    path.join(process.cwd(), '.github', 'workflows', PRERELEASE_CLEANUP_WORKFLOW),
    'utf8',
  );
  assert.deepEqual(validateWorkflow(PRERELEASE_CLEANUP_WORKFLOW, prereleaseCleanupSource), []);
  assert.ok(
    validateWorkflow('prerelease-cleanup-copy.yml', prereleaseCleanupSource).some((error) =>
      error.includes('pull_request trigger is required'),
    ),
  );
  assert.ok(
    validateWorkflow(
      PRERELEASE_CLEANUP_WORKFLOW,
      prereleaseCleanupSource.replace('      id-token: write', '      id-token: read'),
    ).some((error) => error.includes('dedicated bounded OIDC cleanup session')),
  );
  const forbiddenWritePermissions = ['issues', 'checks', 'actions', 'deployments', 'statuses'];
  for (const permission of forbiddenWritePermissions) {
    const errors = validateWorkflow(
      `${permission}.yml`,
      valid.replace(
        '    runs-on: ubuntu-24.04',
        `    permissions:\n      ${permission}: write\n    runs-on: ubuntu-24.04`,
      ),
    );
    assert.ok(
      errors.some((error) =>
        error.includes('write permissions are forbidden outside the exact ci.yml CodeQL job'),
      ),
    );
  }
  assert.ok(
    validateWorkflow(
      'top-level-write.yml',
      valid.replace('  contents: read', '  contents: read\n  issues: write'),
    ).some((error) =>
      error.includes('write permissions are forbidden outside the exact ci.yml CodeQL job'),
    ),
  );
  const validCodeql = [
    'name: CodeQL',
    'on:',
    '  pull_request:',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  cancel-in-progress: true',
    'jobs:',
    '  codeql:',
    '    needs: metadata',
    '    outputs:',
    '      sarif_status: PASS',
    '      sarif_high: 0',
    '      sarif_critical: 0',
    '      sarif_sha256: digest',
    '    permissions:',
    '      contents: read',
    '      security-events: write',
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 15',
    '    steps:',
    '      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567',
    '      - uses: actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444',
    '        with:',
    '          node-version: ${{ env.NODE_VERSION }}',
    '      - uses: github/codeql-action/init@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd',
    '      - id: codeql_analyze',
    '        uses: github/codeql-action/analyze@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd',
    '        with:',
    '          output: codeql-results',
    '          upload: always',
    '      - id: codeql_gate',
    '        run: node scripts/stage6/security/codeql-sarif.mjs --input codeql-results',
    '  verify:',
    '    needs: [metadata, codeql]',
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 45',
    '    steps:',
    '      - name: Materialize optional manual accessibility evidence',
    "        if: ${{ github.event_name != 'pull_request' && vars.STAGE6_A11Y_MANUAL_EVIDENCE_B64 != '' }}",
    '        env:',
    '          STAGE6_A11Y_MANUAL_EVIDENCE_B64: ${{ vars.STAGE6_A11Y_MANUAL_EVIDENCE_B64 }}',
    '        run: |',
    '          target="${RUNNER_TEMP}/stage6-a11y-manual.json"',
    '          printf \'%s\' "${STAGE6_A11Y_MANUAL_EVIDENCE_B64}" | base64 --decode > "${target}"',
    '          echo "STAGE6_A11Y_MANUAL_EVIDENCE=${target}" >> "${GITHUB_ENV}"',
    '      - name: Materialize optional authorized external evidence',
    "        if: ${{ github.event_name != 'pull_request' && vars.STAGE6_EXTERNAL_EVIDENCE_B64 != '' }}",
    '        shell: bash',
    '        env:',
    '          STAGE6_EXTERNAL_EVIDENCE_B64: ${{ vars.STAGE6_EXTERNAL_EVIDENCE_B64 }}',
    '        run: |',
    '          umask 077',
    '          target="${RUNNER_TEMP}/stage6-external-evidence.json"',
    '          printf \'%s\' "${STAGE6_EXTERNAL_EVIDENCE_B64}" | base64 --decode > "${target}"',
    '          echo "STAGE6_EXTERNAL_EVIDENCE=${target}" >> "${GITHUB_ENV}"',
    '      - run: pnpm verify:stage6',
    '        env:',
    '          STAGE6_CODEQL_SARIF_STATUS: PASS',
    '          STAGE6_CODEQL_HIGH: 0',
    '          STAGE6_CODEQL_CRITICAL: 0',
    '          STAGE6_CODEQL_SARIF_SHA256: digest',
    '      - name: Scan verification report upload set',
    '        id: stage6_upload_scan',
    '        if: ${{ always() }}',
    `        run: ${UPLOAD_ARTIFACT_SCAN_COMMAND}`,
    '      - name: Preserve sanitized verification reports',
    "        if: ${{ always() && steps.stage6_upload_scan.outcome == 'success' }}",
    `        uses: actions/upload-artifact@${UPLOAD_ARTIFACT_ACTION_SHA}`,
    '        with:',
    '          name: verification-reports',
    '          if-no-files-found: ignore',
    '          path: |',
    ...VERIFICATION_REPORT_PATHS.map((reportPath) => `            ${reportPath}`),
    '          retention-days: 7',
  ].join('\n');
  assert.deepEqual(validateWorkflow(CODEQL_WORKFLOW, validCodeql), []);
  const invalidUploads = [
    validCodeql.replace('coverage/api/coverage-summary.json', 'coverage/api/'),
    validCodeql.replace('            coverage/web/coverage-summary.json\n', ''),
    validCodeql.replace(
      '            infra/cdk.out/*.template.json',
      '            infra/cdk.out/*.template.json\n            output/unexpected.json',
    ),
    validCodeql.replace(
      '            output/evidence/runtime/stage-5-smoke-results.json',
      '            output/evidence/runtime/stage-5-smoke-results.json\n            output/evidence/runtime/stage-5-smoke-results.json',
    ),
    `${validCodeql}\n      - uses: actions/upload-artifact@${UPLOAD_ARTIFACT_ACTION_SHA}`,
  ];
  for (const invalidUpload of invalidUploads) {
    assert.ok(
      validateWorkflow(CODEQL_WORKFLOW, invalidUpload).some((error) =>
        error.includes(
          'verification-reports upload must be unique and use the exact sanitized paths',
        ),
      ),
    );
  }
  const validUploadScanStep = [
    '      - name: Scan verification report upload set',
    '        id: stage6_upload_scan',
    '        if: ${{ always() }}',
    `        run: ${UPLOAD_ARTIFACT_SCAN_COMMAND}`,
  ].join('\n');
  const invalidUploadGates = [
    validCodeql.replace(`${validUploadScanStep}\n`, ''),
    validCodeql.replace(
      "        if: ${{ always() && steps.stage6_upload_scan.outcome == 'success' }}",
      '        if: ${{ always() }}',
    ),
    validCodeql.replace(
      `        run: ${UPLOAD_ARTIFACT_SCAN_COMMAND}`,
      '        run: node scripts/stage6/not-the-upload-scan.mjs',
    ),
    validCodeql
      .replace(`${validUploadScanStep}\n`, '')
      .replace(
        '      - run: pnpm verify:stage6',
        `${validUploadScanStep}\n      - run: pnpm verify:stage6`,
      ),
    validCodeql.replace(
      `        run: ${UPLOAD_ARTIFACT_SCAN_COMMAND}`,
      `        continue-on-error: true\n        run: ${UPLOAD_ARTIFACT_SCAN_COMMAND}`,
    ),
  ];
  for (const invalidUploadGate of invalidUploadGates) {
    assert.ok(
      validateWorkflow(CODEQL_WORKFLOW, invalidUploadGate).some((error) =>
        error.includes('verification-reports upload must follow the mandatory artifact scan gate'),
      ),
    );
  }
  for (const forbiddenCommand of ['pnpm sandbox:authorized:execute', 'node runner.mjs --execute']) {
    assert.ok(
      validateWorkflow(
        CODEQL_WORKFLOW,
        validCodeql.replace(
          '      - name: Preserve sanitized verification reports',
          `      - run: ${forbiddenCommand}\n      - name: Preserve sanitized verification reports`,
        ),
      ).some((error) => error.includes('authorized sandbox execution is forbidden')),
    );
  }
  const validAuthorizedWiring = [
    'const steps = [',
    '  {',
    "    id: 'E6-SANDBOX-AUTHORIZED-DRY-RUN',",
    "    ...pnpmCommand(['test:sandbox:authorized']),",
    '  },',
    "  { id: 'E6-SANDBOX-EVIDENCE' },",
    "  { id: 'E6-SECURITY' },",
    "  { id: 'E6-UAT' },",
    '];',
  ].join('\n');
  const validAuthorizedManifest = {
    scripts: {
      'test:sandbox:authorized': AUTHORIZED_SANDBOX_DRY_RUN_SCRIPT,
      'sandbox:authorized:execute': AUTHORIZED_SANDBOX_EXECUTE_SCRIPT,
    },
  };
  assert.equal(
    authorizedSandboxWiringIsExact(validAuthorizedManifest, validAuthorizedWiring),
    true,
  );
  assert.equal(
    authorizedSandboxWiringIsExact(
      validAuthorizedManifest,
      validAuthorizedWiring.replace('test:sandbox:authorized', 'sandbox:authorized:execute'),
    ),
    false,
  );
  assert.equal(
    authorizedSandboxWiringIsExact(
      validAuthorizedManifest,
      validAuthorizedWiring.replace('E6-SANDBOX-AUTHORIZED-DRY-RUN', 'E6-SANDBOX-MISSING'),
    ),
    false,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        '    runs-on: ubuntu-24.04\n    timeout-minutes: 15',
        '    permissions:\n      issues: write\n    runs-on: ubuntu-24.04\n    timeout-minutes: 15',
      ),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        "github.event_name != 'pull_request' && vars.STAGE6_A11Y_MANUAL_EVIDENCE_B64 != ''",
        "vars.STAGE6_A11Y_MANUAL_EVIDENCE_B64 != ''",
      ),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        "github.event_name != 'pull_request' && vars.STAGE6_EXTERNAL_EVIDENCE_B64 != ''",
        "vars.STAGE6_EXTERNAL_EVIDENCE_B64 != ''",
      ),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        '  verify:\n    needs: [metadata, codeql]',
        '  verify:\n    permissions:\n      statuses: write\n    needs: [metadata, codeql]',
      ),
    ).some((error) =>
      error.includes('write permissions are forbidden outside the exact ci.yml CodeQL job'),
    ),
  );
  assert.ok(validateWorkflow('security.yml', validCodeql).length > 0);
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        /^.*actions\/setup-node@.*\n(?:.*with:.*\n)?(?:.*node-version:.*\n)?/gmu,
        '',
      ),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(/^.*github\/codeql-action\/init@.*\n/gmu, ''),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(/^.*github\/codeql-action\/analyze@.*\n?/gmu, ''),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(CODEQL_WORKFLOW, validCodeql.replaceAll(CODEQL_ACTION_SHA, '0'.repeat(40)))
      .length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        'node scripts/stage6/security/codeql-sarif.mjs --input',
        'node scripts/stage6/security/noop.mjs --input',
      ),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        'STAGE6_A11Y_MANUAL_EVIDENCE_B64: ${{ vars.STAGE6_A11Y_MANUAL_EVIDENCE_B64 }}',
        'STAGE6_A11Y_MANUAL_EVIDENCE_B64: disabled',
      ),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        'STAGE6_EXTERNAL_EVIDENCE_B64: ${{ vars.STAGE6_EXTERNAL_EVIDENCE_B64 }}',
        'STAGE6_EXTERNAL_EVIDENCE_B64: disabled',
      ),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        '      - name: Materialize optional authorized external evidence',
        '      - name: External evidence step removed',
      ),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replace(
        '      - name: Materialize optional authorized external evidence',
        '      - run: pnpm verify:stage6\n      - name: Materialize optional authorized external evidence',
      ),
    ).length > 0,
  );
  assert.ok(
    validateWorkflow(
      CODEQL_WORKFLOW,
      validCodeql.replaceAll(
        'vars.STAGE6_EXTERNAL_EVIDENCE_B64',
        'secrets.STAGE6_EXTERNAL_EVIDENCE_B64',
      ),
    ).length > 0,
  );
  process.stdout.write('workflow-policy self-test: PASS\n');
}

function main() {
  if (process.argv.includes('--self-test')) {
    selfTest();
    return;
  }

  const rootDirectory = path.resolve(process.cwd());
  const workflowDirectory = path.join(rootDirectory, '.github', 'workflows');
  if (!fs.existsSync(workflowDirectory)) {
    throw new Error('.github/workflows is required');
  }

  const workflowFiles = fs
    .readdirSync(workflowDirectory)
    .filter((name) => /\.ya?ml$/iu.test(name))
    .sort();
  if (workflowFiles.length === 0) {
    throw new Error('at least one workflow is required');
  }

  const workflowSources = new Map(
    workflowFiles.map((name) => [
      name,
      fs.readFileSync(path.join(workflowDirectory, name), 'utf8'),
    ]),
  );
  const errors = workflowFiles.flatMap((name) => validateWorkflow(name, workflowSources.get(name)));
  let authorizedSandboxWiringValid;
  let packageSource = '';
  try {
    packageSource = fs.readFileSync(path.join(rootDirectory, 'package.json'), 'utf8');
    const manifest = JSON.parse(packageSource);
    const verifySource = fs.readFileSync(
      path.join(rootDirectory, 'scripts', 'stage6', 'verify.mjs'),
      'utf8',
    );
    authorizedSandboxWiringValid = authorizedSandboxWiringIsExact(manifest, verifySource);
  } catch {
    authorizedSandboxWiringValid = false;
  }
  if (!authorizedSandboxWiringValid) {
    errors.push('repository: verify:stage6 must include the CI-safe authorized sandbox dry-run');
  }
  errors.push(
    ...validateReleaseWorkflowCommands(
      [
        workflowSources.get(RELEASE_WORKFLOW) ?? '',
        workflowSources.get(PRERELEASE_WORKFLOW) ?? '',
        workflowSources.get(BASELINE_WORKFLOW) ?? '',
        workflowSources.get(PUBLICATION_RECOVERY_WORKFLOW) ?? '',
      ],
      packageSource,
    ),
  );
  if (errors.length > 0) {
    process.stderr.write('workflow-policy: FAIL\n');
    for (const error of errors) {
      process.stderr.write(error + '\n');
    }
    process.exitCode = 1;
    return;
  }

  process.stdout.write('workflow-policy: PASS (' + workflowFiles.length + ' workflow(s))\n');
}

main();
