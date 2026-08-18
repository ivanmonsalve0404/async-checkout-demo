#!/usr/bin/env node

import { strict as assert } from 'node:assert';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { TextDecoder } from 'node:util';
import { fileURLToPath } from 'node:url';

import { build as esbuild } from 'esbuild';

import { scanText as scanRepositoryText } from '../security/scan-repository.mjs';
import { assertSanitizedArtifactText } from '../stage6/lib/artifact-sanitizer.mjs';

const REQUIRED_NODE = { major: 24, minimumMinor: 19 };
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_WEB_BYTES = 64 * 1024 * 1024;
const TEXT_EXTENSIONS = new Set([
  '.css',
  '.html',
  '.js',
  '.json',
  '.svg',
  '.txt',
  '.webmanifest',
  '.xml',
  '.yaml',
  '.yml',
]);
const WEB_EXTENSIONS = new Set([
  ...TEXT_EXTENSIONS,
  '.avif',
  '.gif',
  '.ico',
  '.jpeg',
  '.jpg',
  '.png',
  '.ttf',
  '.webp',
  '.woff',
  '.woff2',
]);
const FORBIDDEN_RELEASE_PATH =
  /(?:^|\/)(?:__tests__|coverage|node_modules|tests?)(?:\/|$)|(?:^|\/)(?:credentials?|secrets?)(?:[._/-]|$)|(?:^|\/)\.env(?:\.|$)|\.(?:key|map|p12|pem|pfx)$/iu;
const HASHED_WEB_ASSET = /^assets\/[^/]+-[A-Za-z0-9_-]+\.(?:css|js)$/u;
const PUBLIC_CONFIG = Object.freeze({ apiBaseUrl: '/api/v1', productId: 'product-demo-001' });
const OPTIONAL_NEST_PACKAGES = [
  '@nestjs/microservices',
  '@nestjs/microservices/microservices-module',
  '@nestjs/websockets/socket-module',
  'class-transformer',
  'class-validator',
];

const fail = (code) => {
  throw new Error(code);
};

const stableCompare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

const assertSupportedNode = () => {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major !== REQUIRED_NODE.major || minor < REQUIRED_NODE.minimumMinor) {
    fail('E7_BUILD_NODE_VERSION_UNSUPPORTED');
  }
};

const relativeInside = (root, candidate, code = 'E7_BUILD_PATH_OUTSIDE_WORKSPACE') => {
  const absolute = path.resolve(candidate);
  const relative = path.relative(root, absolute);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    fail(code);
  }
  return { absolute, relative: relative.replaceAll(path.sep, '/') };
};

const existingStat = async (candidate, missingCode) => {
  try {
    return await lstat(candidate);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') fail(missingCode);
    fail('E7_BUILD_FILESYSTEM_CHECK_FAILED');
  }
};

const assertNoSymlinkComponents = async (root, absolute, allowMissingTail = false) => {
  const { relative } = relativeInside(root, absolute);
  const segments = relative.split('/');
  let current = root;
  for (const [index, segment] of segments.entries()) {
    current = path.join(current, segment);
    let stat;
    try {
      stat = await lstat(current);
    } catch (error) {
      if (
        allowMissingTail &&
        error instanceof Error &&
        'code' in error &&
        error.code === 'ENOENT'
      ) {
        return;
      }
      fail('E7_BUILD_PATH_CHECK_FAILED');
    }
    if (stat.isSymbolicLink()) fail('E7_BUILD_SYMLINK_REJECTED');
    if (index < segments.length - 1 && !stat.isDirectory()) {
      fail('E7_BUILD_PATH_COMPONENT_INVALID');
    }
  }
};

const assertRegularFile = async (root, candidate, missingCode) => {
  const { absolute } = relativeInside(root, candidate);
  await assertNoSymlinkComponents(root, absolute);
  const stat = await existingStat(absolute, missingCode);
  if (!stat.isFile()) fail('E7_BUILD_SPECIAL_FILE_REJECTED');
  if (stat.size > MAX_FILE_BYTES) fail('E7_BUILD_INPUT_TOO_LARGE');
  const canonical = await realpath(absolute).catch(() => fail('E7_BUILD_PATH_CHECK_FAILED'));
  relativeInside(root, canonical);
  return { absolute, size: stat.size };
};

const readRegularFile = async (root, candidate, missingCode) => {
  const checked = await assertRegularFile(root, candidate, missingCode);
  const contents = await readFile(checked.absolute).catch(() => fail('E7_BUILD_READ_FAILED'));
  if (contents.length !== checked.size) fail('E7_BUILD_INPUT_CHANGED');
  return contents;
};

const assertSafeReleaseName = (relative) => {
  if (
    relative.length === 0 ||
    relative.includes('\\') ||
    path.posix.isAbsolute(relative) ||
    relative.split('/').includes('..') ||
    FORBIDDEN_RELEASE_PATH.test(relative)
  ) {
    fail('E7_BUILD_FORBIDDEN_RELEASE_PATH');
  }
};

const collectFiles = async (root, directory, prefix = '', enforceReleaseNames = true) => {
  const { absolute } = relativeInside(root, directory);
  await assertNoSymlinkComponents(root, absolute);
  const directoryStat = await existingStat(absolute, 'E7_BUILD_DIRECTORY_MISSING');
  if (!directoryStat.isDirectory()) fail('E7_BUILD_SPECIAL_FILE_REJECTED');

  const entries = await readdir(absolute, { withFileTypes: true }).catch(() =>
    fail('E7_BUILD_READ_FAILED'),
  );
  const files = [];
  for (const entry of entries.sort((left, right) => stableCompare(left.name, right.name))) {
    const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (enforceReleaseNames) assertSafeReleaseName(relative);
    const candidate = path.join(absolute, entry.name);
    const stat = await lstat(candidate).catch(() => fail('E7_BUILD_PATH_CHECK_FAILED'));
    if (stat.isSymbolicLink()) fail('E7_BUILD_SYMLINK_REJECTED');
    if (stat.isDirectory()) {
      files.push(...(await collectFiles(root, candidate, relative, enforceReleaseNames)));
    } else if (stat.isFile()) {
      if (stat.size > MAX_FILE_BYTES) fail('E7_BUILD_INPUT_TOO_LARGE');
      files.push({ absolute: candidate, relative, size: stat.size });
    } else {
      fail('E7_BUILD_SPECIAL_FILE_REJECTED');
    }
  }
  return files;
};

const decodeText = (buffer) => {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    fail('E7_BUILD_TEXT_ENCODING_INVALID');
  }
};

const scanText = (label, value) => {
  try {
    assertSanitizedArtifactText(label, value);
  } catch {
    fail('E7_BUILD_UNSAFE_TEXT_REJECTED');
  }
};

const scanBufferIfText = (label, buffer) => {
  if (TEXT_EXTENSIONS.has(path.posix.extname(label).toLowerCase())) {
    scanText(label, decodeText(buffer));
  }
};

const scanExecutableBundle = (label, buffer) => {
  if (scanRepositoryText(label, decodeText(buffer)).length > 0) {
    fail('E7_BUILD_UNSAFE_TEXT_REJECTED');
  }
};

const bundleHandler = async (workspaceRoot, entry, kind) => {
  await assertRegularFile(workspaceRoot, entry, `E7_BUILD_${kind.toUpperCase()}_ENTRY_MISSING`);
  let result;
  try {
    result = await esbuild({
      absWorkingDir: workspaceRoot,
      bundle: true,
      charset: 'utf8',
      entryPoints: [entry],
      external: OPTIONAL_NEST_PACKAGES,
      format: 'cjs',
      keepNames: true,
      legalComments: 'none',
      logLevel: 'silent',
      minify: true,
      outfile: path.join(workspaceRoot, 'output', 'release', 'build', kind, 'index.js'),
      platform: 'node',
      sourcemap: false,
      target: ['node24'],
      treeShaking: true,
      write: false,
    });
  } catch {
    fail('E7_BUILD_BUNDLE_EXECUTION_FAILED');
  }
  if (result.errors.length > 0) fail('E7_BUILD_BUNDLE_ERROR_REJECTED');
  if (result.warnings.length > 0) fail('E7_BUILD_BUNDLE_WARNING_REJECTED');
  if (result.outputFiles.length !== 1) fail('E7_BUILD_BUNDLE_OUTPUT_INVALID');
  const contents = Buffer.from(result.outputFiles[0].contents);
  if (contents.length === 0 || contents.length > MAX_FILE_BYTES) fail('E7_BUILD_BUNDLE_INVALID');
  scanExecutableBundle(`${kind}/index.js`, contents);
  return contents;
};

const loadWebFiles = async (workspaceRoot, source) => {
  const metadata = await collectFiles(workspaceRoot, source);
  if (
    metadata.some(({ relative }) => !WEB_EXTENSIONS.has(path.posix.extname(relative).toLowerCase()))
  ) {
    fail('E7_BUILD_WEB_FILE_TYPE_REJECTED');
  }
  if (!metadata.some(({ relative }) => relative === 'index.html')) {
    fail('E7_BUILD_WEB_INDEX_MISSING');
  }
  if (!metadata.some(({ relative }) => HASHED_WEB_ASSET.test(relative))) {
    fail('E7_BUILD_WEB_HASHED_ASSET_MISSING');
  }
  if (metadata.reduce((total, file) => total + file.size, 0) > MAX_WEB_BYTES) {
    fail('E7_BUILD_WEB_TOO_LARGE');
  }

  const files = [];
  for (const file of metadata) {
    const contents = await readFile(file.absolute).catch(() => fail('E7_BUILD_READ_FAILED'));
    if (contents.length !== file.size) fail('E7_BUILD_INPUT_CHANGED');
    if (path.posix.extname(file.relative).toLowerCase() === '.js') {
      scanExecutableBundle(`web/${file.relative}`, contents);
    } else {
      scanBufferIfText(`web/${file.relative}`, contents);
    }
    files.push({ relative: file.relative, contents });
  }
  return files;
};

const assertSafeExistingDestination = async (workspaceRoot, destination, kind) => {
  const { absolute } = relativeInside(workspaceRoot, destination);
  await assertNoSymlinkComponents(workspaceRoot, absolute, true);
  let stat;
  try {
    stat = await lstat(absolute);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return;
    fail('E7_BUILD_PATH_CHECK_FAILED');
  }
  if (stat.isSymbolicLink()) fail('E7_BUILD_SYMLINK_REJECTED');
  if (kind === 'directory') {
    if (!stat.isDirectory()) fail('E7_BUILD_DESTINATION_INVALID');
    await collectFiles(workspaceRoot, absolute, '', false);
  } else if (!stat.isFile()) {
    fail('E7_BUILD_DESTINATION_INVALID');
  }
};

const writeTree = async (directory, files) => {
  for (const file of files) {
    const target = path.join(directory, ...file.relative.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, file.contents, { flag: 'wx', mode: 0o644 });
  }
};

const publishStagedBuild = async (workspaceRoot, destinations, staged) => {
  await assertSafeExistingDestination(workspaceRoot, destinations.api, 'directory');
  await assertSafeExistingDestination(workspaceRoot, destinations.worker, 'directory');
  await assertSafeExistingDestination(workspaceRoot, destinations.web, 'directory');
  await assertSafeExistingDestination(workspaceRoot, destinations.publicConfig, 'file');

  for (const destination of [destinations.api, destinations.worker, destinations.web]) {
    await rm(destination, { force: true, recursive: true });
  }
  await rm(destinations.publicConfig, { force: true });
  await rename(staged.api, destinations.api);
  await rename(staged.worker, destinations.worker);
  await rename(staged.web, destinations.web);
  await rename(staged.publicConfig, destinations.publicConfig);
};

export const buildReleaseArtifacts = async ({ workspaceRoot: requestedRoot } = {}) => {
  assertSupportedNode();
  const workspaceRoot = await realpath(
    path.resolve(
      requestedRoot ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..'),
    ),
  ).catch(() => fail('E7_BUILD_WORKSPACE_MISSING'));
  const rootStat = await existingStat(workspaceRoot, 'E7_BUILD_WORKSPACE_MISSING');
  if (!rootStat.isDirectory()) fail('E7_BUILD_WORKSPACE_INVALID');

  const sources = {
    api: path.join(workspaceRoot, 'apps', 'api', 'dist', 'lambda.js'),
    worker: path.join(workspaceRoot, 'apps', 'api', 'dist', 'worker.js'),
    openapi: path.join(workspaceRoot, 'output', 'architecture', 'openapi.yaml'),
    web: path.join(workspaceRoot, 'apps', 'web', 'dist'),
  };
  const buildRoot = path.join(workspaceRoot, 'output', 'release', 'build');
  const destinations = {
    api: path.join(buildRoot, 'api'),
    worker: path.join(buildRoot, 'worker'),
    web: path.join(buildRoot, 'web'),
    publicConfig: path.join(buildRoot, 'public-config.json'),
  };
  for (const candidate of [...Object.values(sources), ...Object.values(destinations)]) {
    relativeInside(workspaceRoot, candidate);
  }

  const [api, worker, openapi, web] = await Promise.all([
    bundleHandler(workspaceRoot, sources.api, 'api'),
    bundleHandler(workspaceRoot, sources.worker, 'worker'),
    readRegularFile(workspaceRoot, sources.openapi, 'E7_BUILD_OPENAPI_MISSING'),
    loadWebFiles(workspaceRoot, sources.web),
  ]);
  scanBufferIfText('api/openapi.yaml', openapi);
  const publicConfig = Buffer.from(`${JSON.stringify(PUBLIC_CONFIG, null, 2)}\n`, 'utf8');
  scanBufferIfText('public-config.json', publicConfig);
  const releaseWeb = [
    ...web.filter(({ relative }) => relative !== 'public-config.json'),
    { relative: 'public-config.json', contents: publicConfig },
  ].sort((left, right) => stableCompare(left.relative, right.relative));

  await assertNoSymlinkComponents(workspaceRoot, buildRoot, true);
  await mkdir(buildRoot, { recursive: true });
  await assertNoSymlinkComponents(workspaceRoot, buildRoot);
  const stagingRoot = path.join(buildRoot, `.stage7-build-${process.pid}`);
  relativeInside(workspaceRoot, stagingRoot);
  await assertSafeExistingDestination(workspaceRoot, stagingRoot, 'directory');
  await rm(stagingRoot, { force: true, recursive: true });

  const staged = {
    api: path.join(stagingRoot, 'api'),
    worker: path.join(stagingRoot, 'worker'),
    web: path.join(stagingRoot, 'web'),
    publicConfig: path.join(stagingRoot, 'public-config.json'),
  };
  try {
    await mkdir(staged.api, { recursive: true });
    await mkdir(staged.worker, { recursive: true });
    await mkdir(staged.web, { recursive: true });
    await writeFile(path.join(staged.api, 'index.js'), api, { flag: 'wx', mode: 0o644 });
    await writeFile(path.join(staged.api, 'openapi.yaml'), openapi, { flag: 'wx', mode: 0o644 });
    await writeFile(path.join(staged.worker, 'index.js'), worker, { flag: 'wx', mode: 0o644 });
    await writeFile(path.join(staged.worker, 'openapi.yaml'), openapi, { flag: 'wx', mode: 0o644 });
    await writeTree(staged.web, releaseWeb);
    await writeFile(staged.publicConfig, publicConfig, { flag: 'wx', mode: 0o644 });
    await publishStagedBuild(workspaceRoot, destinations, staged);
  } catch (error) {
    await rm(stagingRoot, { force: true, recursive: true }).catch(() => undefined);
    throw error;
  }
  await rm(stagingRoot, { force: true, recursive: true });

  return { apiFiles: 2, workerFiles: 2, webFiles: releaseWeb.length, publicConfigFiles: 1 };
};

const digestBuild = async (workspaceRoot) => {
  const buildRoot = path.join(workspaceRoot, 'output', 'release', 'build');
  const files = await collectFiles(workspaceRoot, buildRoot, '', false);
  const hash = createHash('sha256');
  for (const file of files) {
    if (file.relative === 'keep.txt') continue;
    hash
      .update(file.relative)
      .update('\0')
      .update(await readFile(file.absolute))
      .update('\0');
  }
  return hash.digest('hex');
};

const writeFixture = async (workspaceRoot) => {
  const files = new Map([
    [
      'apps/api/dist/lambda.js',
      "'use strict'; exports.handler = async () => ({ statusCode: 200 });\n",
    ],
    [
      'apps/api/dist/worker.js',
      "'use strict'; exports.handler = async () => ({ status: 'PASS' });\n",
    ],
    [
      'apps/web/dist/index.html',
      '<!doctype html><script src="/assets/index-deadbeef.js"></script>\n',
    ],
    [
      'apps/web/dist/assets/index-deadbeef.js',
      "globalThis.__stage7Fixture = ['safe', 'cvc field', 'expiry field'];\n",
    ],
    ['apps/web/dist/assets/index-deadbeef.css', 'body { color: #123456; }\n'],
    [
      'output/architecture/openapi.yaml',
      'openapi: 3.1.2\ninfo:\n  title: Fixture\n  version: 1.0.0\n',
    ],
    ['output/release/build/keep.txt', 'preserve\n'],
  ]);
  for (const [relative, contents] of files) {
    const target = path.join(workspaceRoot, ...relative.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, contents, 'utf8');
  }
};

export const selfTestReleaseBuild = async () => {
  assertSupportedNode();
  const repositoryRoot = await realpath(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..'),
  );
  const runnerTemporary =
    process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_TEMP
      ? path.resolve(process.env.RUNNER_TEMP)
      : path.join(repositoryRoot, '.tmp');
  await mkdir(runnerTemporary, { recursive: true });
  const temporary = await mkdtemp(path.join(runnerTemporary, 'stage7-release-build-self-test-'));
  try {
    await writeFixture(temporary);
    const first = await buildReleaseArtifacts({ workspaceRoot: temporary });
    assert.deepEqual(first, { apiFiles: 2, workerFiles: 2, webFiles: 4, publicConfigFiles: 1 });
    const firstDigest = await digestBuild(temporary);
    await buildReleaseArtifacts({ workspaceRoot: temporary });
    assert.equal(await digestBuild(temporary), firstDigest);

    const required = [
      'output/release/build/api/index.js',
      'output/release/build/api/openapi.yaml',
      'output/release/build/worker/index.js',
      'output/release/build/worker/openapi.yaml',
      'output/release/build/web/index.html',
      'output/release/build/web/assets/index-deadbeef.js',
      'output/release/build/web/assets/index-deadbeef.css',
      'output/release/build/web/public-config.json',
      'output/release/build/public-config.json',
      'output/release/build/keep.txt',
    ];
    for (const relative of required) {
      assert.equal((await lstat(path.join(temporary, ...relative.split('/')))).isFile(), true);
    }
    assert.deepEqual(
      JSON.parse(await readFile(path.join(temporary, 'output/release/build/public-config.json'))),
      PUBLIC_CONFIG,
    );
    assert.deepEqual(
      JSON.parse(
        await readFile(path.join(temporary, 'output/release/build/web/public-config.json')),
      ),
      PUBLIC_CONFIG,
    );

    const unsafe = ['private', '_key=', 'sensitivevalue123456'].join('');
    await writeFile(path.join(temporary, 'apps/web/dist/unsafe.html'), unsafe, 'utf8');
    await assert.rejects(
      buildReleaseArtifacts({ workspaceRoot: temporary }),
      /E7_BUILD_UNSAFE_TEXT_REJECTED/u,
    );
    assert.equal(await digestBuild(temporary), firstDigest);

    await rm(path.join(temporary, 'apps/web/dist/unsafe.html'));
    const executableSecret = ['api', '_key = ', 'sensitivevalue123456'].join('');
    await writeFile(
      path.join(temporary, 'apps/web/dist/assets/index-deadbeef.js'),
      executableSecret,
      'utf8',
    );
    await assert.rejects(
      buildReleaseArtifacts({ workspaceRoot: temporary }),
      /E7_BUILD_UNSAFE_TEXT_REJECTED/u,
    );
    assert.equal(await digestBuild(temporary), firstDigest);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
  await assert.rejects(lstat(temporary), (error) => error?.code === 'ENOENT');
};

const executedDirectly =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (executedDirectly) {
  const unexpectedArguments = process.argv
    .slice(2)
    .filter((argument) => argument !== '--self-test');
  const command = process.argv.includes('--self-test')
    ? selfTestReleaseBuild
    : buildReleaseArtifacts;
  if (unexpectedArguments.length > 0) {
    process.stderr.write('stage-7 release build: FAIL (E7_BUILD_ARGUMENT_INVALID)\n');
    process.exitCode = 1;
  } else {
    command()
      .then((summary) => {
        if (process.argv.includes('--self-test')) {
          process.stdout.write('stage-7 release build self-test: PASS (offline; deterministic)\n');
        } else {
          process.stdout.write(
            `stage-7 release build: PASS (${summary.apiFiles + summary.workerFiles + summary.webFiles + summary.publicConfigFiles} files)\n`,
          );
        }
      })
      .catch((error) => {
        const code =
          error instanceof Error && /^E7_BUILD_[A-Z0-9_]+$/u.test(error.message)
            ? error.message
            : 'E7_BUILD_INTERNAL';
        process.stderr.write(`stage-7 release build: FAIL (${code})\n`);
        process.exitCode = 1;
      });
  }
}
