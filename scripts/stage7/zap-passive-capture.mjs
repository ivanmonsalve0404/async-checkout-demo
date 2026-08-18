#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  linkSync,
  lstatSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { URLSearchParams, fileURLToPath } from 'node:url';

import {
  assertCloudFrontAccessMaterialExcluded,
  readCloudFrontSignedCookieFile,
} from './cloudfront-access.mjs';
import {
  createZapPassiveRequestInventory,
  createZapPassiveEgressCounter,
  Stage7ZapPassiveInventoryError,
  validateZapPassiveRequestInventory,
  ZAP_PASSIVE_REQUEST_COUNT,
} from './zap-passive-inventory.mjs';

const WORKSPACE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RULESET = path.join(WORKSPACE, 'scripts/stage7/zap-passive-rules.tsv');
const IMAGE =
  'zaproxy/zap-stable@sha256:51dbcc578b217ea7563b22a6948f5f41dd2002936fc5148300077f988663b4aa';
export const ZAP_PASSIVE_IMAGE_DIGEST = IMAGE;
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
  const expected = [
    'capture',
    'count',
    'image-digest',
    'inventory',
    'report',
    'rules',
    'target-file',
  ];
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

const boundedJson = async (url, options = {}) => {
  let response;
  try {
    response = await fetch(url, {
      ...options,
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

const privateApiAction = (port, component, operation, parameters) =>
  boundedJson(`http://127.0.0.1:${port}/JSON/${component}/action/${operation}/`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(
      Object.entries(parameters).map(([key, value]) => [key, String(value)]),
    ),
  });

const prereleaseSignedCookies = (target) => {
  const filename = process.env.STAGE7_CLOUDFRONT_SIGNED_COOKIE_FILE;
  if (filename === undefined) return [];
  try {
    const configFilename = process.env.STAGE7_CONFIG;
    if (typeof configFilename !== 'string' || configFilename.trim() === '') {
      fail('E7_ZAP_SIGNED_COOKIE_CONFIG_REQUIRED');
    }
    const config = JSON.parse(readFileSync(allowedPath(configFilename, { input: true }), 'utf8'));
    const maximum = Math.min(
      Date.parse(config.authorization?.expiresAtUtc),
      Date.parse(config.cleanup?.expiresAtUtc),
      Date.parse(config.window?.endsAtUtc) + 2 * 60 * 60 * 1000,
    );
    if (!Number.isFinite(maximum)) fail('E7_ZAP_SIGNED_COOKIE_CONFIG_INVALID');
    return readCloudFrontSignedCookieFile({
      origin: target,
      filename,
      expectedPublicKeyId: config.prereleaseAccess?.publicKeyId,
      maxExpiresAtUtc: new Date(maximum).toISOString(),
    });
  } catch (error) {
    if (error instanceof CaptureError) throw error;
    fail('E7_ZAP_SIGNED_COOKIE_INVALID');
  }
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

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, expected) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...expected].toSorted().join('\0');
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) {
    return `{${Object.keys(value)
      .toSorted()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const objectSha256 = (value) => sha256(canonical(value));
const clone = (value) => JSON.parse(JSON.stringify(value));

const privateWrite = (filename, source) => {
  const target = allowedPath(filename);
  const temporary = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`,
  );
  try {
    writeFileSync(temporary, source, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    chmodSync(temporary, 0o600);
    linkSync(temporary, target);
    chmodSync(target, 0o600);
  } finally {
    try {
      unlinkSync(temporary);
    } catch {
      // The temporary hard-link source is normally removed after publication.
    }
  }
};

const readInventory = (filename, target) => {
  const absolute = allowedPath(filename, { input: true });
  try {
    const value = JSON.parse(readFileSync(absolute, 'utf8'));
    return validateZapPassiveRequestInventory(value, {
      targetOrigin: target,
      openApiSource: readFileSync(path.join(WORKSPACE, 'output/architecture/openapi.yaml')),
    });
  } catch (error) {
    if (error instanceof Stage7ZapPassiveInventoryError) fail('E7_ZAP_INVENTORY_INVALID');
    fail('E7_ZAP_INVENTORY_INVALID');
  }
};

const requestTarget = (requestLineTarget, target) => {
  let parsed;
  try {
    parsed = requestLineTarget.startsWith('/')
      ? new URL(requestLineTarget, target)
      : new URL(requestLineTarget);
  } catch {
    fail('E7_ZAP_MESSAGE_REQUEST_INVALID');
  }
  if (
    parsed.origin !== target ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    parsed.search ||
    parsed.hash
  ) {
    fail('E7_ZAP_MESSAGE_REQUEST_INVALID');
  }
  return parsed;
};

const messageObservation = (message, request, target) => {
  if (
    !object(message) ||
    typeof message.requestHeader !== 'string' ||
    typeof message.responseHeader !== 'string' ||
    message.requestHeader.length > 1024 * 1024 ||
    message.responseHeader.length > 1024 * 1024
  ) {
    fail('E7_ZAP_MESSAGE_INVALID');
  }
  const requestLine = /^(GET) ([^\s]+) HTTP\/[^\r\n]+/u.exec(message.requestHeader);
  const responseLine = /^HTTP\/[^\s]+ ([0-9]{3})(?:\s|\r?$)/mu.exec(message.responseHeader);
  const parsed = requestTarget(requestLine?.[2] ?? '', target);
  const status = Number(responseLine?.[1]);
  const host = /^Host:\s*([^\r\n]+)$/imu.exec(message.requestHeader)?.[1]?.trim();
  if (
    requestLine?.[1] !== request.method ||
    parsed.pathname !== request.path ||
    host !== new URL(target).host ||
    status !== request.expectedStatus ||
    /^Location:/imu.test(message.responseHeader)
  ) {
    fail('E7_ZAP_MESSAGE_MISMATCH');
  }
  return {
    requestId: request.requestId,
    method: request.method,
    path: request.path,
    status,
    redirectsFollowed: 0,
    responseBodyPersisted: false,
  };
};

const captureBody = ({ inventory, observations }) => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'ZAP_PASSIVE_EXACT_CAPTURE',
  status: 'PASS',
  imageDigest: IMAGE,
  zapVersion: '2.16.1',
  targetOriginSha256: inventory.targetOriginSha256,
  openApiRawSha256: inventory.openApiRawSha256,
  inventorySha256: inventory.inventorySha256,
  requestCount: observations.length,
  observations,
  observationsSha256: objectSha256(observations),
  budgetEnforcement: 'BEFORE_EACH_ZAP_EGRESS',
  callHomeDisabled: true,
  outsideAllowlist: 0,
  redirectsFollowed: 0,
  activeScanRequests: 0,
  mutationsPerformed: 0,
  containsSensitiveData: false,
});

const createCaptureEvidence = ({ inventory, observations }) => {
  const body = captureBody({ inventory, observations });
  if (body.requestCount !== ZAP_PASSIVE_REQUEST_COUNT) fail('E7_ZAP_CAPTURE_COUNT_INVALID');
  return { ...body, captureSha256: objectSha256(body) };
};

export const validateZapPassiveCaptureEvidence = (value, inventory) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'imageDigest',
      'zapVersion',
      'targetOriginSha256',
      'openApiRawSha256',
      'inventorySha256',
      'requestCount',
      'observations',
      'observationsSha256',
      'budgetEnforcement',
      'callHomeDisabled',
      'outsideAllowlist',
      'redirectsFollowed',
      'activeScanRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'captureSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'ZAP_PASSIVE_EXACT_CAPTURE' ||
    value.status !== 'PASS' ||
    value.imageDigest !== IMAGE ||
    value.zapVersion !== '2.16.1' ||
    value.targetOriginSha256 !== inventory.targetOriginSha256 ||
    value.openApiRawSha256 !== inventory.openApiRawSha256 ||
    value.inventorySha256 !== inventory.inventorySha256 ||
    value.requestCount !== ZAP_PASSIVE_REQUEST_COUNT ||
    value.budgetEnforcement !== 'BEFORE_EACH_ZAP_EGRESS' ||
    value.callHomeDisabled !== true ||
    value.outsideAllowlist !== 0 ||
    value.redirectsFollowed !== 0 ||
    value.activeScanRequests !== 0 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_ZAP_CAPTURE_EVIDENCE_INVALID');
  }
  const expectedObservations = inventory.requests.map((request) => ({
    requestId: request.requestId,
    method: request.method,
    path: request.path,
    status: request.expectedStatus,
    redirectsFollowed: 0,
    responseBodyPersisted: false,
  }));
  const expected = createCaptureEvidence({ inventory, observations: expectedObservations });
  if (canonical(value) !== canonical(expected)) fail('E7_ZAP_CAPTURE_EVIDENCE_INVALID');
  return value;
};

const capture = async (flags) => {
  assertPinnedRuntime();
  if (flags['image-digest'] !== IMAGE) fail('E7_ZAP_IMAGE_DIGEST_INVALID');
  validateRules(flags.rules);
  const target = readTarget(flags['target-file']);
  const inventory = readInventory(flags.inventory, target);
  const signedCookies = prereleaseSignedCookies(target);
  const report = allowedPath(flags.report);
  const count = allowedPath(flags.count);
  const captureEvidence = allowedPath(flags.capture);
  if (new Set([report, count, captureEvidence]).size !== 3) fail('E7_ZAP_OUTPUT_COLLISION');

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
      '-silent',
      '-notel',
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
      'autoupdate.checkOnStart=false',
      '-config',
      'autoupdate.downloadNewRelease=false',
      '-config',
      'autoupdate.installAddonUpdates=false',
      '-config',
      'autoupdate.installScannerRules=false',
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
    const zapVersion = await waitFor(
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
    if (zapVersion !== '2.16.1') fail('E7_ZAP_VERSION_INVALID');

    const contextName = 'stage7-owned-origin';
    const originRegex = `^${escapeRegex(target)}(?:/.*)?$`;
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
    await api(port, 'pscan', 'action', 'setScanOnlyInScope', { Boolean: true });
    if (signedCookies.length > 0) {
      const replacement = signedCookies.map(({ name, value }) => `${name}=${value}`).join('; ');
      const added = await privateApiAction(port, 'replacer', 'addRule', {
        description: 'stage7-cloudfront-signed-cookie',
        enabled: true,
        matchType: 'REQ_HEADER',
        matchRegex: false,
        matchString: 'Cookie',
        replacement,
        initiators: '',
      });
      if (added.Result !== 'OK') fail('E7_ZAP_SIGNED_COOKIE_RULE_FAILED');
    }
    const counter = createZapPassiveEgressCounter(inventory);
    for (const [index, request] of inventory.requests.entries()) {
      counter.beforeRequest(request);
      const accessed = await api(port, 'core', 'action', 'accessUrl', {
        url: new URL(request.path, target).href,
        followRedirects: false,
      });
      if (object(accessed) && Object.hasOwn(accessed, 'code')) fail('E7_ZAP_ACCESS_URL_FAILED');
      await waitFor(
        async () => {
          const messages = await api(port, 'core', 'view', 'numberOfMessages');
          const number = Number(messages.numberOfMessages);
          if (!Number.isSafeInteger(number) || number > index + 1) {
            fail('E7_ZAP_UNEXPECTED_EGRESS_DETECTED');
          }
          return number === index + 1;
        },
        { attempts: 40, code: 'E7_ZAP_MESSAGE_TIMEOUT' },
      );
    }
    const enforcement = counter.close();
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
    const messageCount = await api(port, 'core', 'view', 'numberOfMessages');
    const requestCount = Number(messageCount.numberOfMessages);
    if (
      requestCount !== ZAP_PASSIVE_REQUEST_COUNT ||
      enforcement.requestCount !== requestCount ||
      enforcement.inventorySha256 !== inventory.inventorySha256
    ) {
      fail('E7_ZAP_REQUEST_COUNT_INVALID');
    }
    const history = await api(port, 'core', 'view', 'messages', {
      baseurl: target,
      start: 0,
      count: ZAP_PASSIVE_REQUEST_COUNT + 1,
    });
    if (!Array.isArray(history.messages) || history.messages.length !== requestCount) {
      fail('E7_ZAP_MESSAGE_SET_INVALID');
    }
    const sortedMessages = [...history.messages].toSorted((left, right) => {
      const leftId = Number(left?.id);
      const rightId = Number(right?.id);
      if (!Number.isSafeInteger(leftId) || !Number.isSafeInteger(rightId) || leftId === rightId) {
        fail('E7_ZAP_MESSAGE_ID_INVALID');
      }
      return leftId - rightId;
    });
    const observations = sortedMessages.map((message, index) =>
      messageObservation(message, inventory.requests[index], target),
    );
    const alerts = await api(port, 'core', 'view', 'alerts', {
      baseurl: target,
      start: 0,
      count: 1000,
    });
    if (!Array.isArray(alerts.alerts)) fail('E7_ZAP_ALERT_REPORT_INVALID');
    const reportSource = `${JSON.stringify(alerts)}\n`;
    if (reportSource.length > 4 * 1024 * 1024) fail('E7_ZAP_ALERT_REPORT_INVALID');
    assertCloudFrontAccessMaterialExcluded(alerts, signedCookies);
    const sanitizedCapture = createCaptureEvidence({ inventory, observations });
    validateZapPassiveCaptureEvidence(sanitizedCapture, inventory);
    assertCloudFrontAccessMaterialExcluded(sanitizedCapture, signedCookies);
    privateWrite(report, reportSource);
    privateWrite(count, `${requestCount}\n`);
    privateWrite(captureEvidence, `${JSON.stringify(sanitizedCapture)}\n`);
  } finally {
    if (started) docker(['stop', '--time', '10', container], { allowFailure: true });
  }
};

const selfTest = () => {
  assert.deepEqual(
    parseFlags([
      '--target-file',
      'a',
      '--inventory',
      'f',
      '--report',
      'b',
      '--count',
      'c',
      '--capture',
      'g',
      '--rules',
      'd',
      '--image-digest',
      IMAGE,
    ]),
    {
      'target-file': 'a',
      inventory: 'f',
      report: 'b',
      count: 'c',
      capture: 'g',
      rules: 'd',
      'image-digest': IMAGE,
    },
  );
  assert.throws(() => parseFlags(['--report', 'a']), CaptureError);
  assert.throws(() => parseFlags(['--report', 'a', '--report', 'b']), CaptureError);
  assert.equal(escapeRegex('https://a.example/x?y'), 'https://a\\.example/x\\?y');
  assert.equal(IMAGE.includes('@sha256:'), true);
  validateRules(RULESET);
  const target = 'https://stage7.example.invalid';
  const inventory = createZapPassiveRequestInventory({
    targetOrigin: target,
    openApiSource: readFileSync(path.join(WORKSPACE, 'output/architecture/openapi.yaml')),
  });
  const observations = inventory.requests.map((request) =>
    messageObservation(
      {
        id: String(Number(request.requestId.slice(-2))),
        requestHeader: `${request.method} ${request.path} HTTP/1.1\r\nHost: ${new URL(target).host}\r\n\r\n`,
        responseHeader: `HTTP/1.1 ${request.expectedStatus} Result\r\nContent-Type: text/plain\r\n\r\n`,
      },
      request,
      target,
    ),
  );
  const evidence = createCaptureEvidence({ inventory, observations });
  assert.equal(validateZapPassiveCaptureEvidence(evidence, inventory), evidence);
  assert.equal(JSON.stringify(evidence).includes('Cookie'), false);
  const changed = clone(evidence);
  changed.observations[0].status = 201;
  changed.observationsSha256 = objectSha256(changed.observations);
  const changedBody = Object.fromEntries(
    Object.entries(changed).filter(([key]) => key !== 'captureSha256'),
  );
  changed.captureSha256 = objectSha256(changedBody);
  assert.throws(
    () => validateZapPassiveCaptureEvidence(changed, inventory),
    (error) => error.code === 'E7_ZAP_CAPTURE_EVIDENCE_INVALID',
  );
  process.stdout.write('stage-7 passive ZAP capture self-test: PASS\n');
};

const main = async () => {
  const flags = parseFlags(process.argv.slice(2));
  if (flags['self-test'] === true) selfTest();
  else await capture(flags);
};

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error) => {
    const code = error instanceof CaptureError ? error.code : 'E7_ZAP_CAPTURE_UNEXPECTED_FAILURE';
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
