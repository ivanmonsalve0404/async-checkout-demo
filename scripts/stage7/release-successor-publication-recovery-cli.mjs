import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  writeSanitizedJsonAtomic,
  writeSanitizedTextAtomic,
} from '../stage6/lib/artifact-sanitizer.mjs';
import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { sha256 } from '../stage6/lib/evidence.mjs';
import {
  assessPublicationRecoverySource,
  createPublicationRecoveryPlan,
  createPublicationRecoveryPostSuccessIntake,
  createPublicationRecoveryReceipt,
  createPublicationRecoveryVerifyOnlyOperation,
  extractPublicationRecoveryArtifacts,
  extractPublicationRecoveryRouteArtifacts,
  readPublicationRecoveryResultArchive,
  validateRecoveryAuthority,
  validatePublicationRecoveryPlan,
} from './release-successor-publication-recovery-contract.mjs';

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const readJson = (filename, code) => {
  try {
    return parseStrictJsonSource(readFileSync(path.resolve(filename)), {
      scanForbiddenData: false,
    });
  } catch {
    throw new Error(code);
  }
};

const parseFlags = (arguments_, allowed) => {
  const flags = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const token = arguments_[index];
    const value = arguments_[index + 1];
    if (
      typeof token !== 'string' ||
      !token.startsWith('--') ||
      typeof value !== 'string' ||
      value.startsWith('--') ||
      !allowed.includes(token.slice(2)) ||
      flags[token.slice(2)] !== undefined
    ) {
      throw new Error('E7_PUBLICATION_RECOVERY_CLI_ARGUMENTS_INVALID');
    }
    flags[token.slice(2)] = value;
  }
  if (
    Object.keys(flags).length !== allowed.length ||
    allowed.some((name) => flags[name] === undefined)
  ) {
    throw new Error('E7_PUBLICATION_RECOVERY_CLI_ARGUMENTS_INVALID');
  }
  return flags;
};

const assess = async (arguments_) => {
  const allowed = [
    'expected',
    'run',
    'workflow',
    'jobs',
    'artifacts',
    'caller',
    'role',
    'role-policies',
    'role-policy',
    'attached-policies',
    'boundary-metadata',
    'boundary',
    'parameter',
    'authority',
    'route-archives',
    'observed-at',
    'plan-output',
    'fence-output',
  ];
  const flags = parseFlags(arguments_, allowed);
  const expected = readJson(flags.expected, 'E7_PUBLICATION_RECOVERY_CLI_EXPECTED_INVALID');
  if (!object(expected)) throw new Error('E7_PUBLICATION_RECOVERY_CLI_EXPECTED_INVALID');
  const result = createPublicationRecoveryPlan({
    expected,
    run: readJson(flags.run, 'E7_PUBLICATION_RECOVERY_CLI_RUN_INVALID'),
    workflow: readJson(flags.workflow, 'E7_PUBLICATION_RECOVERY_CLI_WORKFLOW_INVALID'),
    jobs: readJson(flags.jobs, 'E7_PUBLICATION_RECOVERY_CLI_JOBS_INVALID'),
    artifacts: readJson(flags.artifacts, 'E7_PUBLICATION_RECOVERY_CLI_ARTIFACTS_INVALID'),
    caller: readJson(flags.caller, 'E7_PUBLICATION_RECOVERY_CLI_CALLER_INVALID'),
    role: readJson(flags.role, 'E7_PUBLICATION_RECOVERY_CLI_ROLE_INVALID'),
    rolePolicies: readJson(
      flags['role-policies'],
      'E7_PUBLICATION_RECOVERY_CLI_ROLE_POLICIES_INVALID',
    ),
    rolePolicy: readJson(flags['role-policy'], 'E7_PUBLICATION_RECOVERY_CLI_ROLE_POLICY_INVALID'),
    attachedPolicies: readJson(
      flags['attached-policies'],
      'E7_PUBLICATION_RECOVERY_CLI_ATTACHED_POLICIES_INVALID',
    ),
    boundaryMetadata: readJson(
      flags['boundary-metadata'],
      'E7_PUBLICATION_RECOVERY_CLI_BOUNDARY_METADATA_INVALID',
    ),
    boundary: readJson(flags.boundary, 'E7_PUBLICATION_RECOVERY_CLI_BOUNDARY_INVALID'),
    parameterResponse: readJson(flags.parameter, 'E7_PUBLICATION_RECOVERY_CLI_PARAMETER_INVALID'),
    authority: readJson(flags.authority, 'E7_PUBLICATION_RECOVERY_CLI_AUTHORITY_INVALID'),
    routeArchiveDirectory: path.resolve(flags['route-archives']),
    observedAtUtc: flags['observed-at'],
  });
  await writeSanitizedJsonAtomic(
    path.resolve(flags['plan-output']),
    'release-successor-publication-recovery-plan.json',
    result.plan,
  );
  await writeSanitizedTextAtomic(
    path.resolve(flags['fence-output']),
    'release-successor-completion-fence.json',
    result.fenceBytes.toString('utf8'),
  );
  return result.plan;
};

const manifest = (arguments_) => {
  const flags = parseFlags(arguments_, ['plan']);
  const plan = validatePublicationRecoveryPlan(
    readJson(flags.plan, 'E7_PUBLICATION_RECOVERY_CLI_PLAN_INVALID'),
  );
  for (const artifact of plan.artifactInventory.downloadManifest) {
    process.stdout.write(`${artifact.name}\t${artifact.artifactId}\t${artifact.digest}\n`);
  }
  return plan;
};

const extract = (arguments_) => {
  const flags = parseFlags(arguments_, ['plan', 'archives', 'output-directory']);
  return extractPublicationRecoveryArtifacts({
    plan: readJson(flags.plan, 'E7_PUBLICATION_RECOVERY_CLI_PLAN_INVALID'),
    archiveDirectory: path.resolve(flags.archives),
    outputDirectory: path.resolve(flags['output-directory']),
  });
};

const sourceAssessment = (arguments_) => {
  const flags = parseFlags(arguments_, ['expected', 'run', 'workflow', 'jobs', 'artifacts']);
  const expected = readJson(flags.expected, 'E7_PUBLICATION_RECOVERY_CLI_EXPECTED_INVALID');
  return assessPublicationRecoverySource({
    expected,
    run: readJson(flags.run, 'E7_PUBLICATION_RECOVERY_CLI_RUN_INVALID'),
    workflow: readJson(flags.workflow, 'E7_PUBLICATION_RECOVERY_CLI_WORKFLOW_INVALID'),
    jobs: readJson(flags.jobs, 'E7_PUBLICATION_RECOVERY_CLI_JOBS_INVALID'),
    artifacts: readJson(flags.artifacts, 'E7_PUBLICATION_RECOVERY_CLI_ARTIFACTS_INVALID'),
  });
};

const crashWindow = (arguments_) => {
  const value = sourceAssessment(arguments_);
  process.stdout.write(`${value.source.crashWindow}\n`);
  return value;
};

const routeManifest = (arguments_) => {
  const value = sourceAssessment(arguments_);
  for (const artifact of [
    ...value.artifactInventory.sourceFenceManifest,
    ...value.artifactInventory.sourcePublicationManifest,
  ]) {
    process.stdout.write(`${artifact.name}\t${artifact.artifactId}\t${artifact.digest}\n`);
  }
  return value;
};

const extractRoute = (arguments_) => {
  const flags = parseFlags(arguments_, ['plan', 'archives', 'output-directory']);
  return extractPublicationRecoveryRouteArtifacts({
    plan: readJson(flags.plan, 'E7_PUBLICATION_RECOVERY_CLI_PLAN_INVALID'),
    archiveDirectory: path.resolve(flags.archives),
    outputDirectory: path.resolve(flags['output-directory']),
  });
};

const verifyOnlyOperation = async (arguments_) => {
  const flags = parseFlags(arguments_, ['plan', 'publication-directory', 'live-proof', 'output']);
  const operation = createPublicationRecoveryVerifyOnlyOperation({
    plan: readJson(flags.plan, 'E7_PUBLICATION_RECOVERY_CLI_PLAN_INVALID'),
    publicationDirectory: path.resolve(flags['publication-directory']),
    liveProofSource: readFileSync(path.resolve(flags['live-proof'])),
  });
  await writeSanitizedJsonAtomic(
    path.resolve(flags.output),
    'release-successor-publication-recovery-verify-only-operation.json',
    operation,
  );
  return operation;
};

const complete = async (arguments_) => {
  const flags = parseFlags(arguments_, [
    'plan',
    'publication-directory',
    'recovery-operation',
    'completed-at',
    'output',
  ]);
  const receipt = createPublicationRecoveryReceipt({
    plan: readJson(flags.plan, 'E7_PUBLICATION_RECOVERY_CLI_PLAN_INVALID'),
    publicationDirectory: path.resolve(flags['publication-directory']),
    recoveryOperationSource: readFileSync(path.resolve(flags['recovery-operation'])),
    completedAtUtc: flags['completed-at'],
  });
  await writeSanitizedJsonAtomic(
    path.resolve(flags.output),
    'release-successor-publication-recovery-receipt.json',
    receipt,
  );
  return receipt;
};

const assertReady = (arguments_) => {
  const flags = parseFlags(arguments_, ['plan', 'observed-at', 'expected-policy']);
  const plan = validatePublicationRecoveryPlan(
    readJson(flags.plan, 'E7_PUBLICATION_RECOVERY_CLI_PLAN_INVALID'),
  );
  const observedAt = Date.parse(flags['observed-at']);
  if (
    plan.status !== 'READY_FOR_AUTHORIZED_RECOVERY_ROUTE' ||
    plan.authority.status !== 'APPROVED' ||
    !Number.isFinite(observedAt) ||
    observedAt < Date.parse(plan.authority.approvedAtUtc) ||
    observedAt >= Date.parse(plan.authority.expiresAtUtc) ||
    plan.route.githubPublicationPolicy !== flags['expected-policy']
  ) {
    throw new Error('E7_PUBLICATION_RECOVERY_NOT_AUTHORIZED');
  }
  return plan;
};

const validateAuthority = (arguments_) => {
  const flags = parseFlags(arguments_, ['authority', 'expected', 'observed-at']);
  const expected = readJson(flags.expected, 'E7_PUBLICATION_RECOVERY_CLI_EXPECTED_INVALID');
  const authority = validateRecoveryAuthority(
    readJson(flags.authority, 'E7_PUBLICATION_RECOVERY_CLI_AUTHORITY_INVALID'),
    {
      sourceRunId: String(expected.sourceRunId),
      sourceRunAttempt: expected.sourceRunAttempt,
      candidateSha: expected.candidateSha,
      releaseId: expected.releaseId,
      releaseTag: expected.releaseTag,
      fenceSha256: expected.expectedFenceSha256,
      journalCleanupRoleSha256: expected.journalCleanupRoleSha256,
      journalRoleAuthoritySha256: expected.journalRoleAuthoritySha256,
      recoveryRoleArnSha256: sha256(expected.recoveryRoleArn),
      permissionsBoundaryArnSha256: sha256(expected.permissionsBoundaryArn),
      observedAtUtc: flags['observed-at'],
    },
  );
  if (authority.authoritySha256 !== expected.expectedAuthoritySha256) {
    throw new Error('E7_PUBLICATION_RECOVERY_CLI_AUTHORITY_HASH_MISMATCH');
  }
  return authority;
};

const sourceId = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'recovery-run-id',
    'artifacts',
    'plan-archive',
    'result-archive',
  ]);
  const result = readPublicationRecoveryResultArchive({
    recoveryRunId: flags['recovery-run-id'],
    recoveryArtifacts: readJson(
      flags.artifacts,
      'E7_PUBLICATION_RECOVERY_CLI_RECOVERY_ARTIFACTS_INVALID',
    ),
    planArchive: readFileSync(path.resolve(flags['plan-archive'])),
    resultArchive: readFileSync(path.resolve(flags['result-archive'])),
  });
  process.stdout.write(`${result.plan.source.runId}\n`);
  return result;
};

const intake = async (arguments_) => {
  const flags = parseFlags(arguments_, [
    'recovery-run',
    'recovery-workflow',
    'recovery-artifacts',
    'recovery-plan-archive',
    'result-archive',
    'source-run',
    'source-workflow',
    'source-jobs',
    'source-artifacts',
    'observed-at',
    'output',
  ]);
  const value = createPublicationRecoveryPostSuccessIntake({
    recoveryRun: readJson(
      flags['recovery-run'],
      'E7_PUBLICATION_RECOVERY_CLI_RECOVERY_RUN_INVALID',
    ),
    recoveryWorkflow: readJson(
      flags['recovery-workflow'],
      'E7_PUBLICATION_RECOVERY_CLI_RECOVERY_WORKFLOW_INVALID',
    ),
    recoveryArtifacts: readJson(
      flags['recovery-artifacts'],
      'E7_PUBLICATION_RECOVERY_CLI_RECOVERY_ARTIFACTS_INVALID',
    ),
    planArchive: readFileSync(path.resolve(flags['recovery-plan-archive'])),
    resultArchive: readFileSync(path.resolve(flags['result-archive'])),
    sourceRun: readJson(flags['source-run'], 'E7_PUBLICATION_RECOVERY_CLI_SOURCE_RUN_INVALID'),
    sourceWorkflow: readJson(
      flags['source-workflow'],
      'E7_PUBLICATION_RECOVERY_CLI_SOURCE_WORKFLOW_INVALID',
    ),
    sourceJobs: readJson(flags['source-jobs'], 'E7_PUBLICATION_RECOVERY_CLI_SOURCE_JOBS_INVALID'),
    sourceArtifacts: readJson(
      flags['source-artifacts'],
      'E7_PUBLICATION_RECOVERY_CLI_SOURCE_ARTIFACTS_INVALID',
    ),
    observedAtUtc: flags['observed-at'],
  });
  await writeSanitizedJsonAtomic(
    path.resolve(flags.output),
    'release-successor-publication-recovery-post-success-intake.json',
    value,
  );
  return value;
};

export const runPublicationRecoveryCli = async (arguments_) => {
  const [command, ...rest] = arguments_;
  if (command === 'assess') return assess(rest);
  if (command === 'manifest') return manifest(rest);
  if (command === 'extract') return extract(rest);
  if (command === 'crash-window') return crashWindow(rest);
  if (command === 'route-manifest') return routeManifest(rest);
  if (command === 'extract-route') return extractRoute(rest);
  if (command === 'verify-only-operation') return verifyOnlyOperation(rest);
  if (command === 'complete') return complete(rest);
  if (command === 'assert-ready') return assertReady(rest);
  if (command === 'validate-authority') return validateAuthority(rest);
  if (command === 'source-id') return sourceId(rest);
  if (command === 'intake') return intake(rest);
  throw new Error('E7_PUBLICATION_RECOVERY_CLI_COMMAND_INVALID');
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runPublicationRecoveryCli(process.argv.slice(2));
}
