import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { writeSanitizedJsonAtomic } from '../stage6/lib/artifact-sanitizer.mjs';

const IMAGE = 'amazon/dynamodb-local:2.6.1';
const IMAGE_DIGEST = 'sha256:1856c05cc66a0e49dc1099e483ad2851477eeebe2135250ac11a1d1227db54b1';
const RUN_LABEL = 'com.async-checkout.integration-run';
const SUITE_NAME = 'DynamoDbCheckoutRepository local integration';
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(scriptDirectory, '..', '..');
const apiDirectory = join(workspaceRoot, 'apps', 'api');
const apiRequire = createRequire(join(apiDirectory, 'package.json'));
const { DynamoDBClient, ListTablesCommand } = apiRequire('@aws-sdk/client-dynamodb');

const runToken = `${process.pid}-${Date.now()}`;
const containerName = `checkout-ddb-it-${runToken}`;
const networkName = `checkout-ddb-it-net-${runToken}`;
const volumeName = `checkout-ddb-it-data-${runToken}`;
const catalogTableName = 'checkout-integration-catalog';
const checkoutTableName = 'checkout-integration-session';
const jestJsonPath = join(tmpdir(), `checkout-ddb-jest-${runToken}.json`);
const evidencePath = join(
  workspaceRoot,
  'output',
  'evidence',
  'runtime',
  'stage-5-dynamodb-integration.json',
);

let containerReference;
let imageDigest = 'unavailable';
let started = false;
let healthy = false;
let endpointLoopback = false;
let cleanupStatus = 'NOT_STARTED';
let exitCode = 1;
let jestCounts = {
  suites: { total: 0, passed: 0, failed: 0 },
  tests: { total: 0, passed: 0, failed: 0, pending: 0 },
};

const docker = (args, allowFailure = false) => {
  const result = spawnSync('docker', args, {
    cwd: workspaceRoot,
    encoding: 'utf8',
    windowsHide: true,
  });
  if (!allowFailure && result.status !== 0) {
    const detail = (result.stderr || result.stdout || 'docker command failed').trim();
    throw new Error(detail);
  }
  return result;
};

const inspectLabel = (kind, reference) => {
  const prefix = kind === 'container' ? [] : [kind];
  const format =
    kind === 'container'
      ? `{{index .Config.Labels "${RUN_LABEL}"}}`
      : `{{index .Labels "${RUN_LABEL}"}}`;
  const result = docker([...prefix, 'inspect', '--format', format, reference], true);
  return result.status === 0 ? result.stdout.trim() : null;
};

const removeExactResources = () => {
  const failures = [];
  if (containerReference !== undefined) {
    if (inspectLabel('container', containerReference) !== runToken) {
      failures.push('container ownership validation failed');
    } else if (docker(['rm', '--force', containerReference], true).status !== 0) {
      failures.push('container cleanup failed');
    }
  }
  if (inspectLabel('network', networkName) === runToken) {
    if (docker(['network', 'rm', networkName], true).status !== 0) {
      failures.push('network cleanup failed');
    }
  } else if (docker(['network', 'inspect', networkName], true).status === 0) {
    failures.push('network ownership validation failed');
  }
  if (inspectLabel('volume', volumeName) === runToken) {
    if (docker(['volume', 'rm', volumeName], true).status !== 0) {
      failures.push('volume cleanup failed');
    }
  } else if (docker(['volume', 'inspect', volumeName], true).status === 0) {
    failures.push('volume ownership validation failed');
  }
  if (failures.length > 0) throw new Error(failures.join('; '));
};

const endpointForContainer = () => {
  const result = docker(['port', containerReference, '8000/tcp']);
  const candidates = result.stdout
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  const loopback = candidates.find((candidate) => /^127\.0\.0\.1:\d+$/u.test(candidate));
  if (loopback === undefined) {
    throw new Error('DynamoDB Local was not published exclusively on IPv4 loopback');
  }
  return `http://${loopback}`;
};

const waitForHealth = async (endpoint) => {
  const client = new DynamoDBClient({
    endpoint,
    region: 'us-east-1',
    credentials: { accessKeyId: 'local', secretAccessKey: 'local' },
    maxAttempts: 1,
  });
  const deadline = Date.now() + 30_000;
  try {
    while (Date.now() < deadline) {
      const controller = new globalThis.AbortController();
      const timeout = setTimeout(() => controller.abort(), 1_000);
      try {
        await client.send(new ListTablesCommand({ Limit: 1 }), {
          abortSignal: controller.signal,
        });
        return;
      } catch {
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 200));
      } finally {
        clearTimeout(timeout);
      }
    }
  } finally {
    client.destroy();
  }
  throw new Error('DynamoDB Local did not become healthy within 30 seconds');
};

const readJestCounts = () => {
  if (!existsSync(jestJsonPath)) return;
  const report = JSON.parse(readFileSync(jestJsonPath, 'utf8'));
  jestCounts = {
    suites: {
      total: Number(report.numTotalTestSuites ?? 0),
      passed: Number(report.numPassedTestSuites ?? 0),
      failed: Number(report.numFailedTestSuites ?? 0),
    },
    tests: {
      total: Number(report.numTotalTests ?? 0),
      passed: Number(report.numPassedTests ?? 0),
      failed: Number(report.numFailedTests ?? 0),
      pending: Number(report.numPendingTests ?? 0),
    },
  };
};

const writeEvidence = async () => {
  const passed = exitCode === 0 && cleanupStatus === 'PASSED';
  const evidence = {
    schemaVersion: 1,
    status: passed ? 'PASS' : 'FAIL',
    image: IMAGE,
    imageDigest,
    endpointLoopback,
    awsExternal: false,
    suites: jestCounts.suites.total,
    tests: jestCounts.tests.total,
    passed: jestCounts.tests.passed,
    generatedAt: new Date().toISOString(),
    engine: 'DynamoDB Local',
    suiteName: SUITE_NAME,
    failed: jestCounts.tests.failed,
    pending: jestCounts.tests.pending,
    lifecycle: {
      started,
      healthy,
      cleanup: cleanupStatus,
    },
    telemetryDisabled: true,
    dedicatedDockerNetwork: true,
  };
  await writeSanitizedJsonAtomic(evidencePath, 'stage-5-dynamodb-integration.json', evidence);
};

try {
  const image = docker(['image', 'inspect', IMAGE, '--format', '{{index .RepoDigests 0}}']);
  imageDigest = image.stdout.trim().split('@').at(-1) ?? '';
  if (imageDigest !== IMAGE_DIGEST) {
    throw new Error('The local DynamoDB image does not match the pinned registry digest');
  }

  docker(['network', 'create', '--label', `${RUN_LABEL}=${runToken}`, networkName]);
  docker(['volume', 'create', '--label', `${RUN_LABEL}=${runToken}`, volumeName]);
  const startedContainer = docker([
    'run',
    '--detach',
    '--pull',
    'never',
    '--name',
    containerName,
    '--hostname',
    'dynamodb-local',
    '--label',
    `${RUN_LABEL}=${runToken}`,
    '--network',
    networkName,
    '--publish',
    '127.0.0.1:0:8000',
    '--mount',
    `type=volume,source=${volumeName},target=/home/dynamodblocal/data`,
    '--user',
    '0:0',
    IMAGE,
    '-Djava.library.path=./DynamoDBLocal_lib',
    '-jar',
    'DynamoDBLocal.jar',
    '-sharedDb',
    '-dbPath',
    '/home/dynamodblocal/data',
    '-disableTelemetry',
  ]);
  containerReference = startedContainer.stdout.trim() || containerName;
  if (inspectLabel('container', containerReference) !== runToken) {
    throw new Error('Started container failed ownership validation');
  }
  started = true;

  const endpoint = endpointForContainer();
  endpointLoopback = true;
  await waitForHealth(endpoint);
  healthy = true;
  process.stdout.write(
    '[integration] DynamoDB Local healthy on loopback; external AWS disabled.\n',
  );

  const jestPackage = apiRequire.resolve('jest/package.json');
  const jestBin = join(dirname(jestPackage), 'bin', 'jest.js');
  const jestResult = spawnSync(
    process.execPath,
    [
      jestBin,
      '--config',
      join(apiDirectory, 'jest.integration.config.cjs'),
      '--runInBand',
      '--json',
      '--outputFile',
      jestJsonPath,
    ],
    {
      cwd: apiDirectory,
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: 'local',
        AWS_EC2_METADATA_DISABLED: 'true',
        AWS_REGION: 'us-east-1',
        AWS_SECRET_ACCESS_KEY: 'local',
        DYNAMODB_LOCAL_CATALOG_TABLE: catalogTableName,
        DYNAMODB_LOCAL_CHECKOUT_TABLE: checkoutTableName,
        DYNAMODB_LOCAL_CONTAINER_ID: containerReference,
        DYNAMODB_LOCAL_ENDPOINT: endpoint,
        DYNAMODB_LOCAL_IMAGE: IMAGE,
        DYNAMODB_LOCAL_RUN_TOKEN: runToken,
        RUN_DYNAMODB_LOCAL_INTEGRATION: '1',
      },
      encoding: 'utf8',
      windowsHide: true,
    },
  );
  if (jestResult.stdout) process.stdout.write(jestResult.stdout);
  if (jestResult.stderr) process.stderr.write(jestResult.stderr);
  readJestCounts();
  exitCode = jestResult.status === 0 ? 0 : 1;
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`[integration] ${message}\n`);
  exitCode = 1;
} finally {
  try {
    removeExactResources();
    cleanupStatus = 'PASSED';
  } catch (error) {
    cleanupStatus = 'FAILED';
    exitCode = 1;
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`[integration] ${message}\n`);
  }
  if (existsSync(jestJsonPath)) rmSync(jestJsonPath, { force: true });
  await writeEvidence();
}

process.exitCode = exitCode;
