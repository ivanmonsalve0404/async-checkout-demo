/* global structuredClone */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstatSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { synthRelease } from './aws-operations.mjs';
import { buildReleaseArtifacts } from './build.mjs';
import { inspectReleaseStackResourceAllowlist } from './cloud-assembly-resource-contract.mjs';
import { authorStage7Configs } from './config-authoring.mjs';
import { buildStage7ConfigAuthoringSelfTestInput } from './config-authoring-self-test.mjs';
import { workspaceRoot } from './core.mjs';

const CANDIDATE_SHA = 'a'.repeat(40);
const COMMAND_TIMEOUT_MS = 20 * 60 * 1000;
const MAX_COMMAND_OUTPUT_BYTES = 32 * 1024 * 1024;
const STACK_SUFFIXES = Object.freeze(['data', 'api', 'observability', 'web']);
const TEMPORARY_DIRECTORY_PREFIX = '.stage7-synth-contract-self-test-';

const isoAt = (now, minutes) => new Date(now.getTime() + minutes * 60 * 1000).toISOString();

const activeAuthoringInput = (now) => {
  const input = buildStage7ConfigAuthoringSelfTestInput();
  for (const scope of ['release', 'prerelease', 'baseline']) {
    input[scope].authorization.approvedAtUtc = isoAt(now, -30);
    input[scope].authorization.expiresAtUtc = isoAt(now, 300);
    input[scope].window.startsAtUtc = isoAt(now, -10);
    input[scope].window.endsAtUtc = isoAt(now, 60);
    input[scope].cleanup.expiresAtUtc = isoAt(now, 120);
  }
  return input;
};

const releaseIdFor = (now) => {
  const stamp = now.toISOString().slice(0, 10).replaceAll('-', '');
  const time = now.toISOString().slice(11, 16).replace(':', '');
  return `rel-${stamp}-${time}-${CANDIDATE_SHA.slice(0, 7)}`;
};

const inheritedSystemEnvironment = () =>
  Object.fromEntries(
    ['PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR', 'WINDIR']
      .map((key) => [key, process.env[key]])
      .filter(([, value]) => typeof value === 'string' && value !== ''),
  );

const executeLocally =
  (calls) =>
  ({ command, args, cwd, env }) => {
    calls.push({ args: [...args], command, cwd, environmentKeys: Object.keys(env).toSorted() });
    const result = spawnSync(command, args, {
      cwd,
      encoding: 'utf8',
      env,
      maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
      shell: false,
      timeout: COMMAND_TIMEOUT_MS,
      windowsHide: true,
    });
    if (result.error !== undefined) {
      return {
        error: result.error,
        status: null,
        stderr: result.stderr ?? '',
        stdout: result.stdout ?? '',
      };
    }
    return {
      status: result.status,
      stderr: result.stderr ?? '',
      stdout: result.stdout ?? '',
    };
  };

const assertReleaseArtifacts = () => {
  for (const artifact of ['api', 'worker', 'web']) {
    const artifactPath = path.join(workspaceRoot, 'output/release/build', artifact);
    assert.equal(statSync(artifactPath).isDirectory(), true);
  }
};

const assertProductiveInvocation = ({ call, config, output }) => {
  assert.equal(call.command, process.execPath);
  assert.equal(call.cwd, workspaceRoot);
  assert.match(call.args[0], /[\\/]node_modules[\\/]aws-cdk[\\/]bin[\\/]cdk$/u);
  const cdkArguments = call.args.slice(1);
  const firstContext = cdkArguments.indexOf('--context');
  assert.notEqual(firstContext, -1);
  const fixedArguments = cdkArguments.slice(0, firstContext);
  const appIndex = fixedArguments.indexOf('--app');
  assert.notEqual(appIndex, -1);
  const appCommand = fixedArguments[appIndex + 1];
  assert.equal(appCommand.includes(process.execPath), true);
  assert.match(appCommand, /[\\/]node_modules[\\/]tsx[\\/]dist[\\/]cli\.mjs/u);
  assert.equal(appCommand.includes(path.join(workspaceRoot, 'infra/bin/app.ts')), true);
  assert.equal(/[\r\n]/u.test(appCommand), false);
  assert.deepEqual(fixedArguments, [
    'synth',
    ...config.authorization.stacks,
    '--app',
    appCommand,
    '--output',
    output,
    '--asset-metadata',
    'false',
    '--path-metadata',
    'false',
    '--version-reporting',
    'false',
    '--lookups',
    'false',
    '--quiet',
  ]);
  assert.equal(
    cdkArguments.some((argument) => argument.startsWith('--hotswap')),
    false,
  );
  assert.equal(
    cdkArguments.slice(firstContext).filter((value) => value === '--context').length > 0,
    true,
  );
  assert.equal(call.environmentKeys.includes('AWS_EC2_METADATA_DISABLED'), true);
  assert.equal(call.environmentKeys.includes('CI'), true);
  assert.deepEqual(
    call.environmentKeys.filter(
      (key) => key.startsWith('STAGE7_') || /^AWS_(?:ACCESS|SECRET|SESSION)/u.test(key),
    ),
    [],
  );
};

const stackTemplates = (output) => {
  const manifest = JSON.parse(readFileSync(path.join(output, 'manifest.json'), 'utf8'));
  const artifacts = Object.entries(manifest.artifacts ?? {}).filter(
    ([, artifact]) => artifact?.type === 'aws:cloudformation:stack',
  );
  assert.equal(artifacts.length, STACK_SUFFIXES.length);
  return artifacts.map(([artifactId, artifact]) => {
    const templateFile = artifact?.properties?.templateFile;
    assert.equal(typeof templateFile, 'string');
    const templatePath = path.resolve(output, templateFile);
    const relative = path.relative(output, templatePath);
    assert.equal(relative === '..' || relative.startsWith(`..${path.sep}`), false);
    return {
      artifactId,
      template: JSON.parse(readFileSync(templatePath, 'utf8')),
    };
  });
};

const assertStackContracts = ({ config, output }) => {
  const templates = stackTemplates(output);
  const contracts = templates.map(({ artifactId, template }) => ({
    artifactId,
    contract: inspectReleaseStackResourceAllowlist({
      artifactId,
      domainMode: config.domain.mode,
      scope: 'prerelease',
      template,
    }),
    template,
  }));
  assert.deepEqual(
    contracts.map(({ contract }) => contract.suffix).toSorted(),
    [...STACK_SUFFIXES].toSorted(),
  );
  for (const { contract } of contracts) {
    assert.equal(contract.valid, true);
    assert.deepEqual(contract.actual, contract.expected);
    assert.equal(contract.actual['AWS::CDK::Metadata'], undefined);
  }
  return contracts;
};

const assertNegativeCanaries = ({ artifactId, config, template }) => {
  const metadataTemplate = structuredClone(template);
  metadataTemplate.Resources.SynthContractUnexpectedMetadata = {
    Type: 'AWS::CDK::Metadata',
  };
  const metadataContract = inspectReleaseStackResourceAllowlist({
    artifactId,
    domainMode: config.domain.mode,
    scope: 'prerelease',
    template: metadataTemplate,
  });
  assert.equal(metadataContract.valid, false);
  assert.equal(metadataContract.actual['AWS::CDK::Metadata'], 1);

  const extraResourceTemplate = structuredClone(template);
  extraResourceTemplate.Resources.SynthContractUnexpectedTopic = {
    Type: 'AWS::SNS::Topic',
  };
  const extraResourceContract = inspectReleaseStackResourceAllowlist({
    artifactId,
    domainMode: config.domain.mode,
    scope: 'prerelease',
    template: extraResourceTemplate,
  });
  assert.equal(extraResourceContract.valid, false);
};

const main = async () => {
  const now = new Date();
  const temporaryRoot = mkdtempSync(path.join(workspaceRoot, TEMPORARY_DIRECTORY_PREFIX));
  try {
    assert.equal(path.dirname(temporaryRoot), workspaceRoot);
    assert.equal(path.basename(temporaryRoot).startsWith(TEMPORARY_DIRECTORY_PREFIX), true);
    assert.equal(lstatSync(temporaryRoot).isDirectory(), true);
    assert.equal(lstatSync(temporaryRoot).isSymbolicLink(), false);
    const releaseId = releaseIdFor(now);
    const build = await buildReleaseArtifacts({
      releaseIdentity: { candidateSha: CANDIDATE_SHA, releaseId },
      workspaceRoot,
    });
    assert.deepEqual(
      {
        apiFiles: build.apiFiles,
        publicConfigFiles: build.publicConfigFiles,
        workerFiles: build.workerFiles,
      },
      { apiFiles: 2, publicConfigFiles: 1, workerFiles: 2 },
    );
    assert.equal(build.webFiles > 0, true);
    assertReleaseArtifacts();

    const authored = authorStage7Configs(activeAuthoringInput(now), { now });
    const config = authored.prereleaseConfig.value;
    const configPath = path.join(temporaryRoot, 'prerelease-config.json');
    const output = path.join(temporaryRoot, 'cdk.out');
    writeFileSync(configPath, authored.prereleaseConfig.source, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    const calls = [];
    const evidenceWrites = [];
    const evidence = await synthRelease({
      executor: executeLocally(calls),
      flags: { 'initial-release': true, output, scope: 'prerelease' },
      environmentVariables: {
        ...inheritedSystemEnvironment(),
        STAGE7_AWS_ACCOUNT_ID: config.aws.accountId,
        STAGE7_AWS_REGION: config.aws.region,
        STAGE7_CANDIDATE_SHA: CANDIDATE_SHA,
        STAGE7_CONFIG: configPath,
        STAGE7_ENVIRONMENT: config.environment,
        STAGE7_RELEASE_ID: releaseId,
      },
      now,
      writeEvidence: async (...arguments_) => {
        evidenceWrites.push(arguments_);
      },
    });

    assert.equal(evidence.decision, 'PASS');
    assert.equal(evidence.mode, 'OFFLINE_SYNTH_NO_LOOKUPS');
    assert.equal(evidence.releaseMode, 'INITIAL');
    assert.equal(evidence.stackCount, STACK_SUFFIXES.length);
    assert.equal(evidence.lookupsAllowed, false);
    assert.equal(evidence.hotswapUsed, false);
    assert.deepEqual(evidence.certificates, []);
    assert.equal(evidence.hostedZone, null);
    assert.equal(evidence.awsIdentity, null);
    assert.equal(calls.length, 1);
    assert.equal(evidenceWrites.length, 1);
    assert.equal(evidenceWrites[0][3], evidence);
    assertProductiveInvocation({ call: calls[0], config, output });

    const contracts = assertStackContracts({ config, output });
    const dataStack = contracts.find(({ contract }) => contract.suffix === 'data');
    assert.notEqual(dataStack, undefined);
    assertNegativeCanaries({ config, ...dataStack });

    process.stdout.write(
      `${JSON.stringify({ decision: 'PASS', negativeCanaries: 2, stackMaps: 4 })}\n`,
    );
  } finally {
    const relative = path.relative(workspaceRoot, temporaryRoot);
    if (
      path.dirname(temporaryRoot) === workspaceRoot &&
      path.basename(temporaryRoot).startsWith(TEMPORARY_DIRECTORY_PREFIX) &&
      relative !== '' &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`)
    ) {
      rmSync(temporaryRoot, { force: true, recursive: true });
    }
  }
};

await main();
