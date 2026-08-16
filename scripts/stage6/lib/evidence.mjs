import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

import { selfTestArtifactSanitizer, serializeSanitizedEvidence } from './artifact-sanitizer.mjs';

export const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
export const runtimeDirectory = resolve(workspaceRoot, 'output', 'evidence', 'runtime', 'stage-6');

const fail = (message) => {
  throw new Error(message);
};

export const normalizedText = (relativePath) =>
  readFileSync(resolve(workspaceRoot, relativePath), 'utf8').replace(/\r\n?/gu, '\n');

export const readJson = (relativePath) =>
  JSON.parse(readFileSync(resolve(workspaceRoot, relativePath), 'utf8'));

export const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export const sha256File = (relativePath) => sha256(normalizedText(relativePath));

export const git = (arguments_, options = {}) => {
  const result = spawnSync('git', arguments_, {
    cwd: workspaceRoot,
    encoding: options.encoding ?? 'utf8',
    input: options.input,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    fail(`Git command failed: git ${arguments_.join(' ')}`);
  }
  return typeof result.stdout === 'string' ? result.stdout.trim() : result.stdout;
};

export const candidate = () => {
  const status = git(['status', '--porcelain=v1', '-z'], { encoding: 'buffer' });
  const changedFiles =
    status.length === 0 ? 0 : status.toString('utf8').split('\0').filter(Boolean).length;
  return {
    commitSha: git(['rev-parse', 'HEAD']),
    treeSha: git(['rev-parse', 'HEAD^{tree}']),
    branch: git(['branch', '--show-current']),
    workingTree: changedFiles === 0 ? 'CLEAN' : 'IMPLEMENTATION_SNAPSHOT',
    changedFiles,
  };
};

export const sourceSnapshot = ({ excluded = [] } = {}) => {
  const listing = git(['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {
    encoding: 'buffer',
  });
  const excludedSet = new Set(
    ['output/evidence/runtime/', ...excluded].map((entry) => entry.replaceAll('\\', '/')),
  );
  const files = listing
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .map((file) => file.replaceAll('\\', '/'))
    .filter(
      (file) =>
        ![...excludedSet].some((entry) =>
          entry.endsWith('/') ? file.startsWith(entry) : file === entry,
        ),
    )
    .sort();
  const hashes = git(['hash-object', '--stdin-paths'], {
    input: `${files.join('\n')}\n`,
  }).split('\n');
  if (files.length === 0 || hashes.length !== files.length) {
    fail('Unable to hash the Stage 6 source snapshot');
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

const runIdPattern = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;

export const stage6Environment = () => (process.env.CI === 'true' ? 'ENV-E6-CI' : 'ENV-E6-LOCAL');

export const stage6RunId = () => {
  const configured = process.env.STAGE6_RUN_ID;
  if (configured !== undefined) {
    if (!runIdPattern.test(configured)) fail('STAGE6_RUN_ID has an invalid format');
    return configured;
  }
  const timestamp = new Date()
    .toISOString()
    .replace(/[-:]/gu, '')
    .replace(/\.\d{3}/u, '')
    .toLowerCase();
  return `e6-${timestamp}-${randomBytes(4).toString('hex')}`;
};

export const baseEvidence = ({ artifactId, command, tool, runId = stage6RunId() }) => ({
  schemaVersion: 1,
  stage: 6,
  artifactId,
  runId,
  generatedAt: new Date().toISOString(),
  candidate: candidate(),
  environment: stage6Environment(),
  tool,
  command,
  dataClassification: 'C0_SANITIZED_SUMMARY',
  containsSensitiveData: false,
  sanitization: {
    payloads: 'OMITTED',
    pii: 'SYNTHETIC_NOT_RECORDED',
    cardData: 'NOT_CAPTURED',
    secrets: 'NOT_CAPTURED',
  },
});

export const writeRuntimeEvidence = (filename, evidence) => {
  mkdirSync(runtimeDirectory, { recursive: true });
  const target = resolve(runtimeDirectory, filename);
  const temporary = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, serializeSanitizedEvidence(filename, evidence), 'utf8');
    renameSync(temporary, target);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  return target;
};

export const assertLoopbackUrl = (candidateUrl) => {
  const parsed = new URL(candidateUrl);
  if (
    (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
    (parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost')
  ) {
    fail('Stage 6 local verification only permits loopback HTTP targets');
  }
};

export const assertEvidenceEnvelope = (evidence) => {
  if (
    evidence?.schemaVersion !== 1 ||
    evidence?.stage !== 6 ||
    typeof evidence?.runId !== 'string' ||
    !runIdPattern.test(evidence.runId) ||
    evidence?.containsSensitiveData !== false ||
    evidence?.environment !== stage6Environment()
  ) {
    fail('Invalid Stage 6 evidence envelope');
  }
};

export const selfTestEvidence = () => {
  selfTestArtifactSanitizer();
  assertLoopbackUrl('http://127.0.0.1:3000/api/health');
  assertEvidenceEnvelope({
    schemaVersion: 1,
    stage: 6,
    runId: 'e6-20260815t120000z-0123abcd',
    environment: stage6Environment(),
    containsSensitiveData: false,
  });
  let environmentRejected = false;
  try {
    assertEvidenceEnvelope({
      schemaVersion: 1,
      stage: 6,
      runId: 'e6-20260815t120000z-0123abcd',
      environment: stage6Environment() === 'ENV-E6-CI' ? 'ENV-E6-LOCAL' : 'ENV-E6-CI',
      containsSensitiveData: false,
    });
  } catch {
    environmentRejected = true;
  }
  if (!environmentRejected) fail('Stage 6 evidence environment self-test failed');
  let rejected = 0;
  for (const url of ['https://example.invalid', 'file:///tmp/report']) {
    try {
      assertLoopbackUrl(url);
    } catch {
      rejected += 1;
    }
  }
  if (rejected !== 2) fail('Loopback policy self-test failed');
  const safeSerialized = serializeSanitizedEvidence('safe-canary.json', {
    status: 'PASS',
    paymentMethodToken: 'NOT_CAPTURED',
  });
  if (!safeSerialized.includes('NOT_CAPTURED')) fail('Evidence sanitizer safe canary failed');
  let unsafeEvidenceRejected = false;
  try {
    serializeSanitizedEvidence('unsafe-canary.json', {
      paymentMethodToken: ['actual', 'token', 'value'].join('-'),
    });
  } catch (error) {
    unsafeEvidenceRejected =
      error instanceof Error && error.message === 'RUNTIME_EVIDENCE_SANITIZATION_FAILED';
  }
  if (!unsafeEvidenceRejected) fail('Evidence sanitizer unsafe canary failed');
};
