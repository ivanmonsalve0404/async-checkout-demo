#!/usr/bin/env node
import process from 'node:process';

import {
  STAGE7_BUILD_OUTPUTS,
  Stage7Error,
  createFreezeManifest,
  createLocalPreflight,
  createStage7Plan,
  currentCandidate,
  readStrictJsonFile,
  selfTestStage7,
  stage7ConfigSummary,
  validateStage7Documents,
  workspaceRoot,
  writeStage7Json,
} from './core.mjs';

const fail = (code) => {
  throw new Stage7Error(code);
};

const parseFlags = (arguments_) => {
  const flags = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (!name?.startsWith('--') || value === undefined || value.startsWith('--')) {
      fail('E7_CLI_ARGUMENT_INVALID');
    }
    const key = name.slice(2);
    if (Object.hasOwn(flags, key)) fail('E7_CLI_ARGUMENT_DUPLICATE');
    flags[key] = value;
  }
  return flags;
};

const exactFlags = (flags, required, optional = []) => {
  const keys = Object.keys(flags);
  if (
    required.some((key) => !Object.hasOwn(flags, key)) ||
    keys.some((key) => !required.includes(key) && !optional.includes(key))
  ) {
    fail('E7_CLI_ARGUMENT_SET_INVALID');
  }
};

const readConfig = (filename) =>
  readStrictJsonFile(filename, { scanForbiddenData: false, validateConfig: true });
const readEvidence = (filename) =>
  readStrictJsonFile(filename, { scanForbiddenData: false, validateConfig: false });
const emit = async (value, flags, label) => {
  if (flags.output !== undefined) await writeStage7Json(flags.output, label, value);
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
};

const command = process.argv[2];
const flags = parseFlags(process.argv.slice(3));

const main = async () => {
  if (command === 'self-test') {
    exactFlags(flags, []);
    selfTestStage7();
    process.stdout.write('stage-7 local contracts self-test: PASS\n');
    return;
  }
  if (command === 'documents') {
    exactFlags(flags, []);
    validateStage7Documents();
    process.stdout.write('stage-7 documents: PASS (20 artifacts; 57 evidence; 33 sections)\n');
    return;
  }
  if (command === 'build-paths') {
    exactFlags(flags, []);
    process.stdout.write(`${JSON.stringify(STAGE7_BUILD_OUTPUTS, null, 2)}\n`);
    return;
  }
  if (command === 'config') {
    exactFlags(flags, ['config']);
    process.stdout.write(
      `${JSON.stringify(stage7ConfigSummary(readConfig(flags.config)), null, 2)}\n`,
    );
    return;
  }
  if (command === 'freeze') {
    exactFlags(
      flags,
      [
        'config',
        'e6-manifest',
        'web',
        'api',
        'worker',
        'iac',
        'public-config',
        'source-artifact-id',
        'source-artifact-sha256',
        'aws-cli-version',
        'output',
      ],
      ['tag', 'lockfile', 'openapi', 'generated-client', 'pre-freeze-evidence-sha256'],
    );
    const manifest = createFreezeManifest({
      config: readConfig(flags.config),
      e6Manifest: readEvidence(flags['e6-manifest']),
      candidate: currentCandidate(),
      releaseTag: flags.tag ?? null,
      sourceArtifactId: flags['source-artifact-id'],
      sourceArtifactSha256: flags['source-artifact-sha256'],
      preFreezeEvidenceSha256: flags['pre-freeze-evidence-sha256'] ?? null,
      awsCliVersion: flags['aws-cli-version'],
      paths: {
        web: flags.web,
        api: flags.api,
        worker: flags.worker,
        iac: flags.iac,
        lockfile: flags.lockfile ?? `${workspaceRoot}/pnpm-lock.yaml`,
        openapi: flags.openapi ?? `${workspaceRoot}/output/architecture/openapi.yaml`,
        generatedClient:
          flags['generated-client'] ??
          `${workspaceRoot}/packages/contracts/src/generated/openapi.d.ts`,
        publicConfig: flags['public-config'],
      },
    });
    await emit(manifest, flags, 'stage7-freeze-manifest.json');
    return;
  }
  if (command === 'preflight') {
    exactFlags(flags, ['config', 'e6-manifest'], ['freeze', 'previous-manifest', 'output']);
    const result = createLocalPreflight({
      config: readConfig(flags.config),
      e6Manifest: readEvidence(flags['e6-manifest']),
      freezeManifest: flags.freeze === undefined ? undefined : readEvidence(flags.freeze),
      previousReleaseManifest:
        flags['previous-manifest'] === undefined
          ? undefined
          : readEvidence(flags['previous-manifest']),
      candidate: currentCandidate(),
    });
    await emit(result, flags, 'stage7-local-preflight.json');
    if (result.decision === 'NOT_READY') process.exitCode = 2;
    return;
  }
  if (command === 'plan') {
    exactFlags(flags, ['preflight'], ['output']);
    const plan = createStage7Plan(readEvidence(flags.preflight));
    await emit(plan, flags, 'stage7-release-plan.json');
    return;
  }
  fail('E7_CLI_COMMAND_INVALID');
};

main().catch((error) => {
  const code =
    (error instanceof Stage7Error || /^[A-Z][A-Z0-9_]{2,127}$/u.test(error?.code ?? '')) &&
    typeof error.code === 'string'
      ? error.code
      : 'E7_UNEXPECTED_FAILURE';
  process.stderr.write(`stage-7: ${code}\n`);
  process.exitCode = 1;
});
