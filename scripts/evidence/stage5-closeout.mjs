#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const trackedPath = resolve(workspaceRoot, 'output/evidence/stage-5/verification-manifest.json');
const excludedSnapshotPath = 'output/evidence/stage-5/verification-manifest.json';

const fail = (message) => {
  throw new Error(message);
};
const readJson = (relativePath) =>
  JSON.parse(readFileSync(resolve(workspaceRoot, relativePath), 'utf8'));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const normalizedText = (relativePath) =>
  readFileSync(resolve(workspaceRoot, relativePath), 'utf8').replace(/\r\n?/g, '\n');

const coverage = (application) => {
  const summary = readJson(`coverage/${application}/coverage-summary.json`).total;
  const metrics = Object.fromEntries(
    ['statements', 'branches', 'functions', 'lines'].map((name) => [name, summary?.[name]?.pct]),
  );
  for (const [name, value] of Object.entries(metrics)) {
    if (typeof value !== 'number' || value < 85) {
      fail(`${application} coverage ${name} is below 85`);
    }
  }
  return metrics;
};

const jestResult = (relativePath) => {
  const result = readJson(relativePath);
  if (
    result.schemaVersion !== 1 ||
    result.status !== 'PASS' ||
    result.containsTestPayloads !== false ||
    result.failedSuites !== 0 ||
    result.failedTests !== 0 ||
    result.passedTests !== result.tests
  ) {
    fail(`Jest evidence is not green: ${relativePath}`);
  }
  return {
    suites: result.suites,
    passedSuites: result.passedSuites,
    tests: result.tests,
    passedTests: result.passedTests,
  };
};

const sourceSnapshotSha256 = () => {
  const listing = spawnSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    { cwd: workspaceRoot, encoding: 'buffer', maxBuffer: 16 * 1024 * 1024 },
  );
  if (listing.status !== 0) fail('Unable to enumerate the source snapshot');
  const files = listing.stdout
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .map((file) => file.replaceAll('\\', '/'))
    .filter((file) => file !== excludedSnapshotPath)
    .sort();
  const blobs = spawnSync('git', ['hash-object', '--stdin-paths'], {
    cwd: workspaceRoot,
    input: files.join('\n') + '\n',
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  const hashes = blobs.stdout.trim().split('\n');
  if (blobs.status !== 0 || hashes.length !== files.length) {
    fail('Unable to hash the source snapshot');
  }
  const digest = createHash('sha256');
  for (const [index, file] of files.entries()) {
    digest.update(file);
    digest.update('\0');
    digest.update(hashes[index]);
    digest.update('\0');
  }
  return { files: files.length, sha256: digest.digest('hex') };
};

const openapiSource = normalizedText('output/architecture/openapi.yaml');
const openapiSha256 = sha256(openapiSource);
const generated = normalizedText('packages/contracts/src/generated/openapi.d.ts');
if (!generated.includes(`Source SHA-256 (LF-normalized): ${openapiSha256}`)) {
  fail('Generated contract does not match the OpenAPI source hash');
}

const smoke = readJson('output/evidence/stage-5/smoke-results.json');
const smokeResults = Array.isArray(smoke.results) ? smoke.results : [];
const smokeIds = new Set(smokeResults.map((result) => result.id));
if (
  smoke.schemaVersion !== 4 ||
  smoke.exitCode !== 0 ||
  smoke.passed !== 12 ||
  smoke.total !== 12 ||
  smoke.networkGuardCanaries !== 'PASS' ||
  smoke.browserExternalRequests !== 0 ||
  smoke.providerExternalSmoke !== 'NOT_RUN_AUTH_REQUIRED' ||
  smokeIds.size !== 12 ||
  smokeResults.length !== 12 ||
  smokeResults.some((result) => result.status !== 'PASS')
) {
  fail('Tracked smoke evidence is incomplete, stale, or unsafe');
}

const dynamodb = readJson('output/evidence/runtime/stage-5-dynamodb-integration.json');
if (
  dynamodb.schemaVersion !== 1 ||
  dynamodb.status !== 'PASS' ||
  dynamodb.image !== 'amazon/dynamodb-local:2.6.1' ||
  typeof dynamodb.imageDigest !== 'string' ||
  !dynamodb.imageDigest.startsWith('sha256:') ||
  dynamodb.endpointLoopback !== true ||
  dynamodb.awsExternal !== false ||
  !Number.isInteger(dynamodb.tests) ||
  dynamodb.tests < 1 ||
  dynamodb.passed !== dynamodb.tests
) {
  fail('DynamoDB Local evidence is incomplete or unsafe');
}

const secrets = readJson('output/evidence/runtime/stage-5-secrets.json');
if (secrets.status !== 'PASS' || secrets.findings !== 0 || secrets.history !== 'PASS') {
  fail('Secret scan evidence is not green');
}
const dependencies = readJson('output/evidence/runtime/stage-5-dependencies.json');
if (
  dependencies.status !== 'PASS' ||
  dependencies.scope !== 'production' ||
  dependencies.vulnerabilities?.high !== 0 ||
  dependencies.vulnerabilities?.critical !== 0
) {
  fail('Dependency audit evidence is not green');
}

const manifest = {
  schemaVersion: 1,
  stage: 5,
  status: 'LOCAL_FAKE_VERIFIED',
  remoteCi: 'NOT_RUN_CURRENT_SNAPSHOT',
  realProvider: 'BLOCKED_ADR_09_AUTH_REQUIRED',
  toolchain: {
    node: process.version,
    packageManager: readJson('package.json').packageManager,
  },
  sourceSnapshot: sourceSnapshotSha256(),
  contracts: {
    openapiSha256,
    generatedTypes: 'MATCH',
  },
  tests: {
    api: jestResult('output/evidence/runtime/api-tests.json'),
    web: jestResult('output/evidence/runtime/web-tests.json'),
    dynamodb: {
      image: dynamodb.image,
      imageDigest: dynamodb.imageDigest,
      suites: dynamodb.suites,
      tests: dynamodb.tests,
      passed: dynamodb.passed,
      endpointLoopback: true,
      awsExternal: false,
    },
    smoke: { passed: smoke.passed, total: smoke.total, scriptSha256: smoke.smokeScriptSha256 },
  },
  coverage: { api: coverage('api'), web: coverage('web') },
  security: {
    secrets: { findings: 0, history: 'PASS' },
    dependencies: {
      scope: dependencies.scope,
      threshold: dependencies.threshold,
      vulnerabilities: dependencies.vulnerabilities,
    },
    externalNetwork: { browser: 0, provider: 'NOT_RUN_AUTH_REQUIRED' },
  },
};

const serialized = JSON.stringify(manifest, null, 2) + '\n';
if (process.argv.includes('--promote')) {
  mkdirSync(dirname(trackedPath), { recursive: true });
  writeFileSync(trackedPath, serialized, 'utf8');
  process.stdout.write('stage-5 evidence: PROMOTED\n');
} else {
  const tracked = readFileSync(trackedPath, 'utf8');
  if (tracked !== serialized) fail('Stage 5 verification evidence drift detected');
  process.stdout.write('stage-5 evidence: PASS\n');
}
