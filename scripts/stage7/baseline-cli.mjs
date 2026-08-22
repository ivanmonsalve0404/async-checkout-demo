#!/usr/bin/env node

import {
  constants as fsConstants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { assertSanitizedArtifactText } from '../stage6/lib/artifact-sanitizer.mjs';
import {
  activateRestrictedBaselineAws,
  BASELINE_FILE_LAYOUT,
  bindBaselineForTarget,
  captureBaselineAws,
  createBaselineApproval,
  createBaselineAwsPreflight,
  createBaselineFreeze,
  createBaselinePlanAws,
  createPreviousReleaseBundle,
  deployBaselineAws,
  disableBaselineAws,
  runPendingCompatibilityFocalTest,
  seedBaselineAws,
  selfTestBaselineEstablishment,
  smokeRestrictedBaseline,
  Stage7BaselineError,
  synthBaseline,
  validateBaselineConfig,
  validatePreviousReleaseBundle,
  verifyBaselineNotificationAws,
} from './baseline-establishment.mjs';
import { currentCandidate, workspaceRoot } from './core.mjs';
import { normalizePnpmScriptArguments } from './cli-arguments.mjs';
import {
  createPreviousReleaseProjectionIndex,
  PREVIOUS_RELEASE_PROJECTION_FILENAMES,
  validatePreviousReleaseProjection,
} from './previous-release-projection.mjs';

const fail = (code) => {
  throw new Stage7BaselineError(code);
};

const safePath = (candidate, { mustExist = true, directory = false } = {}) => {
  if (typeof candidate !== 'string' || candidate.length === 0) fail('E7_BASELINE_CLI_PATH_INVALID');
  const absolute = path.resolve(candidate);
  const relative = path.relative(workspaceRoot, absolute);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('E7_BASELINE_CLI_PATH_OUTSIDE_WORKSPACE');
  }
  let current = workspaceRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) break;
    if (lstatSync(current).isSymbolicLink()) fail('E7_BASELINE_CLI_SYMLINK_FORBIDDEN');
  }
  if (mustExist && !existsSync(absolute)) fail('E7_BASELINE_CLI_PATH_MISSING');
  if (mustExist && directory !== lstatSync(absolute).isDirectory()) {
    fail('E7_BASELINE_CLI_PATH_TYPE_INVALID');
  }
  return absolute;
};

const parseFlags = (arguments_) => {
  const flags = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (
      typeof name !== 'string' ||
      !/^--[a-z][a-z0-9-]*$/u.test(name) ||
      typeof value !== 'string' ||
      value.length === 0 ||
      value.startsWith('--') ||
      Object.hasOwn(flags, name.slice(2))
    ) {
      fail('E7_BASELINE_CLI_ARGUMENT_INVALID');
    }
    flags[name.slice(2)] = value;
  }
  return flags;
};

const exactFlags = (flags, names) => {
  if (Object.keys(flags).toSorted().join('\0') !== [...names].toSorted().join('\0')) {
    fail('E7_BASELINE_CLI_ARGUMENT_SET_INVALID');
  }
  return flags;
};

const json = (filename) => {
  try {
    return JSON.parse(readFileSync(safePath(filename), 'utf8'));
  } catch (error) {
    if (error instanceof Stage7BaselineError) throw error;
    fail('E7_BASELINE_CLI_JSON_INVALID');
  }
};

const writeJson = (filename, value, label) => {
  const target = safePath(filename, { mustExist: false });
  if (existsSync(target)) fail('E7_BASELINE_CLI_OUTPUT_EXISTS');
  mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const source = `${JSON.stringify(value, null, 2)}\n`;
  assertSanitizedArtifactText(label, source);
  const temporary = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, source, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    renameSync(temporary, target);
  } finally {
    rmSync(temporary, { force: true });
  }
  return target;
};

const chain = (flags) => ({
  config: json(flags.config),
  freeze: json(flags.freeze),
  awsPreflight: json(flags.preflight),
  iamEvidence: json(flags.iam),
  plan: json(flags.plan),
  approval: json(flags.approval),
  githubApproval: json(flags['github-approval']),
  rawDiffFilename: flags['raw-diff'],
  githubApprovalFilename: flags['github-approval'],
});

const chainFlagNames = [
  'config',
  'freeze',
  'preflight',
  'iam',
  'plan',
  'approval',
  'github-approval',
  'raw-diff',
];

const provenanceFiles = (directory) =>
  Object.fromEntries(
    Object.entries(BASELINE_FILE_LAYOUT.provenance).map(([key, name]) => [
      key,
      path.join(directory, name),
    ]),
  );

const main = async () => {
  const [command, ...arguments_] = normalizePnpmScriptArguments(process.argv.slice(2), {
    separatorIndex: 0,
  });
  if (command === 'self-test') {
    if (arguments_.length !== 0) fail('E7_BASELINE_CLI_ARGUMENT_SET_INVALID');
    const result = await selfTestBaselineEstablishment();
    if (
      result?.status !== 'PASS' ||
      !Number.isSafeInteger(result.assertions) ||
      result.assertions < 1 ||
      result.externalRequests !== 0 ||
      result.mutationsPerformed !== 0
    ) {
      fail('E7_BASELINE_CLI_SELF_TEST_INVALID');
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  const flags = parseFlags(arguments_);
  if (command === 'validate-config') {
    exactFlags(flags, ['config']);
    validateBaselineConfig(json(flags.config));
    return;
  }
  if (command === 'freeze') {
    exactFlags(flags, [
      'config',
      'stage6-manifest',
      'stage6-sha256',
      'stage6-source-provenance',
      'stage6-source-run-id',
      'stage6-source-artifact-id',
      'stage6-source-artifact-digest',
      'source-run-id',
      'source-artifact-id',
      'source-artifact-sha256',
      'source-artifact-path',
      'baseline-version',
      'release-id',
      'web',
      'api',
      'worker',
      'iac',
      'toolchain',
      'output',
    ]);
    const config = json(flags.config);
    const manifest = json(flags['stage6-manifest']);
    const freeze = createBaselineFreeze({
      config,
      stage6Manifest: manifest,
      stage6ManifestFilename: flags['stage6-manifest'],
      stage6ManifestSha256: flags['stage6-sha256'],
      stage6SourceProvenance: json(flags['stage6-source-provenance']),
      stage6SourceProvenanceFilename: flags['stage6-source-provenance'],
      stage6SourceRunId: flags['stage6-source-run-id'],
      stage6SourceArtifactId: flags['stage6-source-artifact-id'],
      stage6SourceArtifactDigest: flags['stage6-source-artifact-digest'],
      sourceRunId: flags['source-run-id'],
      sourceArtifactId: flags['source-artifact-id'],
      sourceArtifactSha256: flags['source-artifact-sha256'],
      sourceArtifactPath: flags['source-artifact-path'],
      baselineVersion: flags['baseline-version'],
      candidate: currentCandidate(),
      releaseId: flags['release-id'],
      artifacts: { web: flags.web, api: flags.api, worker: flags.worker, iac: flags.iac },
      toolchain: json(flags.toolchain),
    });
    writeJson(flags.output, freeze, 'stage7-baseline-freeze.json');
    return;
  }
  if (command === 'synth') {
    exactFlags(flags, ['config', 'candidate-sha', 'release-id', 'output-directory']);
    synthBaseline({
      config: json(flags.config),
      freezeIdentity: {
        candidateSha: flags['candidate-sha'],
        releaseId: flags['release-id'],
      },
      output: flags['output-directory'],
    });
    return;
  }
  if (command === 'pending-test') {
    exactFlags(flags, ['freeze', 'output']);
    writeJson(
      flags.output,
      runPendingCompatibilityFocalTest({ freeze: json(flags.freeze) }),
      'stage7-baseline-pending-evidence.json',
    );
    return;
  }
  if (command === 'preflight') {
    exactFlags(flags, ['config', 'freeze', 'output']);
    writeJson(
      flags.output,
      createBaselineAwsPreflight({ config: json(flags.config), freeze: json(flags.freeze) }),
      'stage7-baseline-aws-preflight.json',
    );
    return;
  }
  if (command === 'plan') {
    exactFlags(flags, ['config', 'freeze', 'iam', 'preflight', 'app', 'raw-diff', 'output']);
    writeJson(
      flags.output,
      createBaselinePlanAws({
        config: json(flags.config),
        freeze: json(flags.freeze),
        iamEvidence: json(flags.iam),
        awsPreflight: json(flags.preflight),
        rawDiffOutput: { app: flags.app, filename: flags['raw-diff'] },
      }),
      'stage7-baseline-plan.json',
    );
    return;
  }
  if (command === 'approve') {
    exactFlags(flags, ['config', 'freeze', 'plan', 'github-approval', 'output']);
    writeJson(
      flags.output,
      createBaselineApproval({
        config: json(flags.config),
        freeze: json(flags.freeze),
        plan: json(flags.plan),
        githubApproval: json(flags['github-approval']),
        githubApprovalFilename: flags['github-approval'],
      }),
      'stage7-baseline-approval.json',
    );
    return;
  }
  if (command === 'deploy') {
    exactFlags(flags, [...chainFlagNames, 'app', 'output']);
    writeJson(
      flags.output,
      deployBaselineAws({ ...chain(flags), app: flags.app }),
      'stage7-baseline-deployment.json',
    );
    return;
  }
  if (command === 'notification') {
    exactFlags(flags, [...chainFlagNames, 'deployment', 'app', 'output']);
    writeJson(
      flags.output,
      verifyBaselineNotificationAws({
        ...chain(flags),
        deployment: json(flags.deployment),
        app: flags.app,
      }),
      'stage7-baseline-notification.json',
    );
    return;
  }
  if (command === 'seed') {
    exactFlags(flags, [...chainFlagNames, 'deployment', 'app', 'output']);
    writeJson(
      flags.output,
      seedBaselineAws({
        ...chain(flags),
        deployment: json(flags.deployment),
        app: flags.app,
      }),
      'stage7-baseline-seed.json',
    );
    return;
  }
  if (command === 'activate') {
    exactFlags(flags, [...chainFlagNames, 'deployment', 'notification', 'seed', 'app', 'output']);
    writeJson(
      flags.output,
      activateRestrictedBaselineAws({
        ...chain(flags),
        deployment: json(flags.deployment),
        notification: json(flags.notification),
        seed: json(flags.seed),
        app: flags.app,
      }),
      'stage7-baseline-activation.json',
    );
    return;
  }
  if (command === 'smoke') {
    exactFlags(flags, [
      ...chainFlagNames,
      'deployment',
      'notification',
      'activation',
      'seed',
      'valid-cookie',
      'expired-cookie',
      'pending',
      'app',
      'output-directory',
    ]);
    const output = safePath(flags['output-directory'], { mustExist: false });
    if (existsSync(output)) fail('E7_BASELINE_CLI_OUTPUT_EXISTS');
    mkdirSync(output, { recursive: false, mode: 0o700 });
    const result = await smokeRestrictedBaseline({
      ...chain(flags),
      deployment: json(flags.deployment),
      notification: json(flags.notification),
      activation: json(flags.activation),
      seed: json(flags.seed),
      validCookieFile: flags['valid-cookie'],
      expiredCookieFile: flags['expired-cookie'],
      pendingTest: json(flags.pending),
      trafficLedgerFile: path.join(output, BASELINE_FILE_LAYOUT.evidence[3]),
      app: flags.app,
    });
    writeJson(
      path.join(output, BASELINE_FILE_LAYOUT.evidence[0]),
      result.apiContract,
      BASELINE_FILE_LAYOUT.evidence[0],
    );
    writeJson(
      path.join(output, BASELINE_FILE_LAYOUT.evidence[1]),
      result.pending,
      BASELINE_FILE_LAYOUT.evidence[1],
    );
    writeJson(
      path.join(output, BASELINE_FILE_LAYOUT.evidence[2]),
      result.smoke,
      BASELINE_FILE_LAYOUT.evidence[2],
    );
    return;
  }
  if (command === 'disable') {
    exactFlags(flags, [...chainFlagNames, 'app', 'output']);
    writeJson(
      flags.output,
      disableBaselineAws({
        ...chain(flags),
        app: flags.app,
      }),
      'stage7-baseline-disable.json',
    );
    return;
  }
  if (command === 'recover-disable') {
    exactFlags(flags, ['config', 'freeze', 'app', 'output']);
    writeJson(
      flags.output,
      disableBaselineAws({
        config: json(flags.config),
        freeze: json(flags.freeze),
        app: flags.app,
        recoveryOnly: true,
      }),
      'stage7-baseline-disable.json',
    );
    return;
  }
  if (command === 'capture') {
    exactFlags(flags, [
      ...chainFlagNames,
      'deployment',
      'notification',
      'activation',
      'seed',
      'disable',
      'evidence-directory',
      'app',
      'output',
    ]);
    const evidence = safePath(flags['evidence-directory'], { directory: true });
    const apiContractFilename = path.join(evidence, BASELINE_FILE_LAYOUT.evidence[0]);
    const pendingFilename = path.join(evidence, BASELINE_FILE_LAYOUT.evidence[1]);
    const smokeFilename = path.join(evidence, BASELINE_FILE_LAYOUT.evidence[2]);
    writeJson(
      flags.output,
      captureBaselineAws({
        ...chain(flags),
        deployment: json(flags.deployment),
        seed: json(flags.seed),
        notification: json(flags.notification),
        activation: json(flags.activation),
        disable: json(flags.disable),
        apiContract: json(apiContractFilename),
        pending: json(pendingFilename),
        smoke: json(smokeFilename),
        apiContractFilename,
        pendingFilename,
        smokeFilename,
        trafficLedgerFilename: path.join(evidence, BASELINE_FILE_LAYOUT.evidence[3]),
        provenanceFiles: provenanceFiles(evidence),
        app: flags.app,
      }),
      BASELINE_FILE_LAYOUT.capture,
    );
    return;
  }
  if (command === 'bundle') {
    exactFlags(flags, [
      'capture',
      'final-disable',
      'recovery-artifact-id',
      'recovery-artifact-digest',
      'evidence-directory',
      'output-directory',
      'source-run-id',
      'source-run-attempt',
      'source-workflow-path',
      'source-event',
      'source-ref',
      'source-head-sha',
    ]);
    createPreviousReleaseBundle({
      capture: json(flags.capture),
      captureFilename: flags.capture,
      finalDisableFilename: flags['final-disable'],
      recoveryArtifactId: flags['recovery-artifact-id'],
      recoveryArtifactDigest: flags['recovery-artifact-digest'],
      evidenceDirectory: flags['evidence-directory'],
      outputDirectory: flags['output-directory'],
      sourceRunId: flags['source-run-id'],
      sourceRunAttempt: Number(flags['source-run-attempt']),
      sourceWorkflowPath: flags['source-workflow-path'],
      sourceEvent: flags['source-event'],
      sourceRef: flags['source-ref'],
      sourceHeadSha: flags['source-head-sha'],
    });
    return;
  }
  if (command === 'validate-bundle') {
    exactFlags(flags, ['directory', 'bundle-sha256', 'source-run-id']);
    validatePreviousReleaseBundle({
      directory: flags.directory,
      expectedBundleSha256: flags['bundle-sha256'],
      expectedRunId: flags['source-run-id'],
    });
    return;
  }
  if (command === 'bind') {
    exactFlags(flags, [
      'bundle-directory',
      'bundle-sha256',
      'source-run-id',
      'source-evidence',
      'target-config',
      'target-freeze',
      'target-web',
      'output-directory',
    ]);
    const bundle = validatePreviousReleaseBundle({
      directory: flags['bundle-directory'],
      expectedBundleSha256: flags['bundle-sha256'],
      expectedRunId: flags['source-run-id'],
    });
    const output = safePath(flags['output-directory'], { mustExist: false });
    if (existsSync(output)) fail('E7_BASELINE_CLI_OUTPUT_EXISTS');
    const captureFilename = path.join(flags['bundle-directory'], BASELINE_FILE_LAYOUT.capture);
    const bound = bindBaselineForTarget({
      capture: bundle.capture,
      captureFilename,
      evidenceDirectory: flags['bundle-directory'],
      expectedCaptureSha256: bundle.index.captureSha256,
      bundleIndex: bundle.index,
      sourceProvenance: json(flags['source-evidence']),
      targetConfig: json(flags['target-config']),
      targetFreeze: json(flags['target-freeze']),
      targetWebDirectory: safePath(flags['target-web'], { directory: true }),
    });
    mkdirSync(output, { recursive: false, mode: 0o700 });
    writeJson(
      path.join(output, 'previous-release-manifest.json'),
      bound.previousRelease,
      'stage7-previous-release.json',
    );
    writeJson(
      path.join(output, 'previous-target-compatibility.json'),
      bound.targetCompatibility,
      'stage7-baseline-target-compatibility.json',
    );
    writeJson(
      path.join(output, 'previous-final-disable-provenance.json'),
      bound.finalDisableProvenance,
      'stage7-previous-final-disable-provenance.json',
    );
    copyFileSync(
      safePath(flags['source-evidence']),
      path.join(output, 'previous-source-provenance.json'),
      fsConstants.COPYFILE_EXCL,
    );
    for (const [sourceName, targetName] of [
      [BASELINE_FILE_LAYOUT.evidence[0], 'previous-api-contract-evidence.json'],
      [BASELINE_FILE_LAYOUT.evidence[1], 'previous-pending-evidence.json'],
      [BASELINE_FILE_LAYOUT.evidence[2], 'previous-smoke-evidence.json'],
    ]) {
      const source = safePath(path.join(flags['bundle-directory'], sourceName));
      const target = path.join(output, targetName);
      copyFileSync(source, target, fsConstants.COPYFILE_EXCL);
    }
    const projectionFiles = Object.fromEntries(
      PREVIOUS_RELEASE_PROJECTION_FILENAMES.filter(
        (name) => name !== 'previous-release-projection-index.json',
      ).map((name) => [name, readFileSync(path.join(output, name))]),
    );
    const projectionIndex = createPreviousReleaseProjectionIndex({
      sourceKind: 'BASELINE_BOOTSTRAP',
      sourceBundle: {
        artifactName: bundle.index.artifactName,
        bundleSha256: bundle.index.bundleSha256,
        sourceRunId: bundle.index.sourceRunId,
        sourceRunAttempt: bundle.index.sourceRunAttempt,
        headSha: bundle.index.sourceHeadSha,
      },
      previousReleaseManifest: bound.previousRelease,
      files: projectionFiles,
    });
    writeJson(
      path.join(output, 'previous-release-projection-index.json'),
      projectionIndex,
      'previous-release-projection-index.json',
    );
    validatePreviousReleaseProjection(output);
    return;
  }
  fail('E7_BASELINE_CLI_COMMAND_INVALID');
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code = error instanceof Stage7BaselineError ? error.code : 'E7_BASELINE_CLI_UNEXPECTED';
    process.stderr.write(`stage-7 baseline: ${code}\n`);
    process.exitCode = 1;
  });
}
