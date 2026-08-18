#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  lstatSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const WORKSPACE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RULESET = path.join(WORKSPACE, 'scripts/stage7/zap-passive-rules.tsv');
const IMAGE =
  'zaproxy/zap-stable@sha256:51dbcc578b217ea7563b22a6948f5f41dd2002936fc5148300077f988663b4aa';
const NAME = /^[a-z0-9][a-z0-9-]{0,62}$/u;

class CaptureError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7ZapCaptureError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new CaptureError(code);
};

const parseFlags = (arguments_) => {
  if (arguments_.length === 1 && arguments_[0] === '--self-test') return { 'self-test': true };
  const result = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (!/^--[a-z][a-z-]*$/u.test(name ?? '') || value === undefined || value.startsWith('--')) {
      fail('E7_ZAP_ARGUMENT_INVALID');
    }
    const key = name.slice(2);
    if (Object.hasOwn(result, key)) fail('E7_ZAP_ARGUMENT_DUPLICATE');
    result[key] = value;
  }
  const expected = ['count', 'image-digest', 'report', 'rules', 'target-file'];
  if (Object.keys(result).toSorted().join('\0') !== expected.join('\0')) {
    fail('E7_ZAP_ARGUMENT_SET_INVALID');
  }
  return result;
};

const inside = (root, candidate) => {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
};

const allowedPath = (candidate, { input = false } = {}) => {
  const absolute = path.resolve(candidate);
  const runnerTemp = process.env.RUNNER_TEMP?.trim();
  if (!inside(WORKSPACE, absolute) && !(runnerTemp && inside(runnerTemp, absolute))) {
    fail('E7_ZAP_PATH_OUTSIDE_ALLOWED_ROOT');
  }
  if (input) {
    let stat;
    try {
      stat = lstatSync(absolute);
    } catch {
      fail('E7_ZAP_INPUT_MISSING');
    }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 16 * 1024 * 1024) {
      fail('E7_ZAP_INPUT_INVALID');
    }
    const allowedRoot = inside(WORKSPACE, absolute) ? WORKSPACE : runnerTemp;
    if (!inside(realpathSync(allowedRoot), realpathSync(absolute))) fail('E7_ZAP_INPUT_INVALID');
  } else {
    const parent = path.dirname(absolute);
    let stat;
    try {
      stat = lstatSync(parent);
    } catch {
      fail('E7_ZAP_OUTPUT_PARENT_INVALID');
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail('E7_ZAP_OUTPUT_PARENT_INVALID');
    const allowedRoot = inside(WORKSPACE, absolute) ? WORKSPACE : runnerTemp;
    if (!inside(realpathSync(allowedRoot), realpathSync(parent))) {
      fail('E7_ZAP_OUTPUT_PARENT_INVALID');
    }
  }
  return absolute;
};

const readTarget = (filename) => {
  const source = readFileSync(allowedPath(filename, { input: true }), 'utf8');
  if (!/^https:\/\/[^\s]+\r?\n?$/u.test(source)) fail('E7_ZAP_TARGET_FILE_INVALID');
  let parsed;
  try {
    parsed = new URL(source.trim());
  } catch {
    fail('E7_ZAP_TARGET_INVALID');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== '/' ||
    parsed.search ||
    parsed.hash ||
    parsed.port
  ) {
    fail('E7_ZAP_TARGET_INVALID');
  }
  return parsed.origin;
};

const validateRules = (filename) => {
  const absolute = allowedPath(filename, { input: true });
  if (realpathSync(absolute) !== realpathSync(RULESET)) fail('E7_ZAP_RULESET_PATH_INVALID');
  const source = readFileSync(absolute, 'utf8').replaceAll('\r\n', '\n');
  if (
    source.length > 16 * 1024 ||
    source.split('\n').some((line) => line.trim() !== '' && !line.startsWith('#')) ||
    !source.includes('No alert is ignored')
  ) {
    fail('E7_ZAP_RULESET_INVALID');
  }
  return absolute;
};

const assertPinnedRuntime = () => {
  const pinned = readFileSync(path.join(WORKSPACE, '.node-version'), 'utf8').trim();
  if (process.version !== `v${pinned}` || pinned !== '24.19.0') {
    fail('E7_ZAP_NODE_VERSION_NOT_PINNED');
  }
};

const docker = (arguments_, { allowFailure = false } = {}) => {
  const result = spawnSync('docker', arguments_, {
    cwd: WORKSPACE,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (!allowFailure && result.status !== 0) fail('E7_ZAP_DOCKER_COMMAND_FAILED');
  return result;
};

const boundedJson = async (url) => {
  let response;
  try {
    response = await fetch(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    fail('E7_ZAP_API_UNAVAILABLE');
  }
  if (!response.ok) fail('E7_ZAP_API_RESPONSE_INVALID');
  const source = await response.text();
  if (source.length < 2 || source.length > 4 * 1024 * 1024) {
    fail('E7_ZAP_API_RESPONSE_INVALID');
  }
  try {
    return JSON.parse(source);
  } catch {
    fail('E7_ZAP_API_RESPONSE_INVALID');
  }
};

const api = (port, component, type, operation, parameters = {}) => {
  const url = new URL(`http://127.0.0.1:${port}/JSON/${component}/${type}/${operation}/`);
  for (const [key, value] of Object.entries(parameters)) url.searchParams.set(key, String(value));
  return boundedJson(url);
};

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

const waitFor = async (probe, { attempts, code }) => {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const value = await probe();
      if (value !== false) return value;
    } catch (error) {
      if (!(error instanceof CaptureError)) throw error;
    }
    await delay(500);
  }
  fail(code);
};

const escapeRegex = (value) => value.replaceAll(/[.*+?^${}()|[\]\\]/gu, '\\$&');

const privateWrite = (filename, source) => {
  const target = allowedPath(filename);
  const temporary = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`,
  );
  try {
    writeFileSync(temporary, source, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, target);
    chmodSync(target, 0o600);
  } finally {
    try {
      unlinkSync(temporary);
    } catch {
      // The atomic rename normally removes the temporary path.
    }
  }
};

const capture = async (flags) => {
  assertPinnedRuntime();
  if (flags['image-digest'] !== IMAGE) fail('E7_ZAP_IMAGE_DIGEST_INVALID');
  validateRules(flags.rules);
  const target = readTarget(flags['target-file']);
  const report = allowedPath(flags.report);
  const count = allowedPath(flags.count);
  if (report === count) fail('E7_ZAP_OUTPUT_COLLISION');

  const container = `stage7-zap-${randomBytes(8).toString('hex')}`;
  if (!NAME.test(container)) fail('E7_ZAP_CONTAINER_NAME_INVALID');
  let started = false;
  try {
    const run = docker([
      'run',
      '--detach',
      '--rm',
      '--name',
      container,
      '--publish',
      '127.0.0.1::8080',
      IMAGE,
      'zap.sh',
      '-daemon',
      '-host',
      '0.0.0.0',
      '-port',
      '8080',
      '-config',
      'api.disablekey=true',
      '-config',
      'api.addrs.addr.name=.*',
      '-config',
      'api.addrs.addr.regex=true',
      '-config',
      'spider.maxDepth=5',
      '-config',
      'spider.maxChildren=100',
      '-config',
      'spider.maxDuration=2',
    ]);
    if (!/^[0-9a-f]{12,64}\r?\n?$/u.test(run.stdout)) fail('E7_ZAP_CONTAINER_START_INVALID');
    started = true;
    const portOutput = await waitFor(
      async () => {
        const value = docker(['port', container, '8080/tcp'], { allowFailure: true });
        return value.status === 0 && value.stdout.trim() !== '' ? value.stdout.trim() : false;
      },
      { attempts: 40, code: 'E7_ZAP_PORT_UNAVAILABLE' },
    );
    const portMatch = /^127\.0\.0\.1:([0-9]{1,5})$/u.exec(portOutput);
    const port = Number(portMatch?.[1]);
    if (!Number.isSafeInteger(port) || port < 1024 || port > 65_535) {
      fail('E7_ZAP_PORT_INVALID');
    }
    await waitFor(
      async () => {
        try {
          const value = await api(port, 'core', 'view', 'version');
          return typeof value.version === 'string' ? value.version : false;
        } catch {
          return false;
        }
      },
      { attempts: 90, code: 'E7_ZAP_STARTUP_TIMEOUT' },
    );

    const contextName = 'stage7-owned-origin';
    const originRegex = `^${escapeRegex(target)}(?:/.*)?$`;
    const externalRegex = `^(?!${escapeRegex(target)}(?:/|$)).*$`;
    const created = await api(port, 'context', 'action', 'newContext', { contextName });
    if (!/^[0-9]+$/u.test(created.contextId ?? '')) fail('E7_ZAP_CONTEXT_INVALID');
    await api(port, 'context', 'action', 'includeInContext', {
      contextName,
      regex: originRegex,
    });
    await api(port, 'context', 'action', 'setContextInScope', {
      contextName,
      booleanInScope: true,
    });
    await api(port, 'spider', 'action', 'excludeFromScan', { regex: externalRegex });
    const scan = await api(port, 'spider', 'action', 'scan', {
      url: target,
      maxChildren: 100,
      recurse: true,
      contextName,
      subtreeOnly: true,
    });
    if (!/^[0-9]+$/u.test(scan.scan ?? '')) fail('E7_ZAP_SPIDER_START_INVALID');
    await waitFor(
      async () => {
        const status = await api(port, 'spider', 'view', 'status', { scanId: scan.scan });
        const number = Number(status.status);
        if (!Number.isSafeInteger(number) || number < 0 || number > 100) {
          fail('E7_ZAP_SPIDER_STATUS_INVALID');
        }
        return number === 100;
      },
      { attempts: 240, code: 'E7_ZAP_SPIDER_TIMEOUT' },
    );
    await waitFor(
      async () => {
        const queue = await api(port, 'pscan', 'view', 'recordsToScan');
        const number = Number(queue.recordsToScan);
        if (!Number.isSafeInteger(number) || number < 0) fail('E7_ZAP_PASSIVE_QUEUE_INVALID');
        return number === 0;
      },
      { attempts: 240, code: 'E7_ZAP_PASSIVE_TIMEOUT' },
    );

    const sites = await api(port, 'core', 'view', 'sites');
    if (
      !Array.isArray(sites.sites) ||
      sites.sites.length !== 1 ||
      sites.sites.some((site) => {
        try {
          return new URL(site).origin !== target;
        } catch {
          return true;
        }
      })
    ) {
      fail('E7_ZAP_EXTERNAL_NAVIGATION_DETECTED');
    }
    const messages = await api(port, 'core', 'view', 'numberOfMessages');
    const requestCount = Number(messages.numberOfMessages);
    if (!Number.isSafeInteger(requestCount) || requestCount < 1 || requestCount > 100) {
      fail('E7_ZAP_REQUEST_COUNT_INVALID');
    }
    const alerts = await api(port, 'core', 'view', 'alerts', {
      baseurl: target,
      start: 0,
      count: 1000,
    });
    if (!Array.isArray(alerts.alerts)) fail('E7_ZAP_ALERT_REPORT_INVALID');
    const reportSource = `${JSON.stringify(alerts)}\n`;
    if (reportSource.length > 4 * 1024 * 1024) fail('E7_ZAP_ALERT_REPORT_INVALID');
    privateWrite(report, reportSource);
    privateWrite(count, `${requestCount}\n`);
  } finally {
    if (started) docker(['stop', '--time', '10', container], { allowFailure: true });
  }
};

const selfTest = () => {
  assert.deepEqual(
    parseFlags([
      '--target-file',
      'a',
      '--report',
      'b',
      '--count',
      'c',
      '--rules',
      'd',
      '--image-digest',
      IMAGE,
    ]),
    {
      'target-file': 'a',
      report: 'b',
      count: 'c',
      rules: 'd',
      'image-digest': IMAGE,
    },
  );
  assert.throws(() => parseFlags(['--report', 'a']), CaptureError);
  assert.throws(() => parseFlags(['--report', 'a', '--report', 'b']), CaptureError);
  assert.equal(escapeRegex('https://a.example/x?y'), 'https://a\\.example/x\\?y');
  assert.equal(IMAGE.includes('@sha256:'), true);
  validateRules(RULESET);
  process.stdout.write('stage-7 passive ZAP capture self-test: PASS\n');
};

const main = async () => {
  const flags = parseFlags(process.argv.slice(2));
  if (flags['self-test'] === true) selfTest();
  else await capture(flags);
};

main().catch((error) => {
  const code = error instanceof CaptureError ? error.code : 'E7_ZAP_CAPTURE_UNEXPECTED_FAILURE';
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
});
