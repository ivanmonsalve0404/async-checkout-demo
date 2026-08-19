#!/usr/bin/env node

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
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
import { TextDecoder } from 'node:util';
import { fileURLToPath } from 'node:url';

const WORKSPACE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OPENAPI = path.join(WORKSPACE, 'output/architecture/openapi.yaml');
const SHA256 = /^[0-9a-f]{64}$/u;

const OPENAPI_OPERATIONS = Object.freeze([
  Object.freeze({ template: '/api/v1/products', method: 'get', operationId: 'listProducts' }),
  Object.freeze({
    template: '/api/v1/products/{productId}',
    method: 'get',
    operationId: 'getProduct',
  }),
  Object.freeze({ template: '/api/docs', method: 'get', operationId: 'getApiDocumentation' }),
  Object.freeze({ template: '/api/health/live', method: 'get', operationId: 'getLiveness' }),
  Object.freeze({ template: '/api/health/ready', method: 'get', operationId: 'getReadiness' }),
]);

export const ZAP_PASSIVE_REQUEST_COUNT = 6;

export class Stage7ZapPassiveInventoryError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7ZapPassiveInventoryError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7ZapPassiveInventoryError(code);
};

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

const asBuffer = (value) => {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  fail('E7_ZAP_OPENAPI_SOURCE_INVALID');
};

const strictOrigin = (value) => {
  if (typeof value !== 'string' || value.length < 9 || value.length > 256) {
    fail('E7_ZAP_INVENTORY_TARGET_INVALID');
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail('E7_ZAP_INVENTORY_TARGET_INVALID');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    parsed.pathname !== '/' ||
    parsed.search ||
    parsed.hash ||
    parsed.origin !== value
  ) {
    fail('E7_ZAP_INVENTORY_TARGET_INVALID');
  }
  return parsed.origin;
};

const parseOpenApiOperations = (source) => {
  const bytes = asBuffer(source);
  if (bytes.length < 100 || bytes.length > 16 * 1024 * 1024 || bytes.includes(0)) {
    fail('E7_ZAP_OPENAPI_SOURCE_INVALID');
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('E7_ZAP_OPENAPI_SOURCE_INVALID');
  }
  if (text.includes('\t') || /\r(?!\n)/u.test(text)) fail('E7_ZAP_OPENAPI_SOURCE_INVALID');
  const lines = text.replaceAll('\r\n', '\n').split('\n');
  const operations = new Map();
  let inPaths = false;
  let currentPath;
  let currentMethod;
  for (const line of lines) {
    if (line === 'paths:') {
      if (inPaths) fail('E7_ZAP_OPENAPI_PATHS_INVALID');
      inPaths = true;
      continue;
    }
    if (!inPaths) continue;
    if (line === 'components:') break;
    const pathMatch = /^  (\/[^:\s]+):$/u.exec(line);
    if (pathMatch !== null) {
      currentPath = pathMatch[1];
      currentMethod = undefined;
      continue;
    }
    const methodMatch = /^    (get|post|put|patch|delete|options|head|trace):$/u.exec(line);
    if (methodMatch !== null) {
      currentMethod = methodMatch[1];
      continue;
    }
    const operationMatch = /^      operationId: ([A-Za-z][A-Za-z0-9]{0,127})$/u.exec(line);
    if (operationMatch !== null) {
      if (currentPath === undefined || currentMethod === undefined) {
        fail('E7_ZAP_OPENAPI_OPERATION_INVALID');
      }
      const key = `${currentMethod} ${currentPath}`;
      if (operations.has(key)) fail('E7_ZAP_OPENAPI_OPERATION_INVALID');
      operations.set(key, operationMatch[1]);
    }
  }
  if (!inPaths) fail('E7_ZAP_OPENAPI_PATHS_INVALID');
  for (const operation of OPENAPI_OPERATIONS) {
    if (operations.get(`${operation.method} ${operation.template}`) !== operation.operationId) {
      fail('E7_ZAP_OPENAPI_SAFE_OPERATION_MISSING');
    }
  }
  return { bytes, rawSha256: sha256(bytes) };
};

const requestBody = ({ requestId, path: requestPath, source, expectedStatus }) => ({
  requestId,
  method: 'GET',
  path: requestPath,
  source,
  expectedStatus,
  followRedirects: false,
  mutationExpected: false,
  responseBodyPersisted: false,
});

const inventoryBody = ({ targetOrigin, openApiRawSha256 }) => {
  const missingProductId = `stage7-zap-${sha256(`${targetOrigin}\0${openApiRawSha256}`).slice(0, 32)}`;
  const requests = [
    requestBody({
      requestId: 'ZAP-PASSIVE-01',
      path: '/',
      source: 'WEB_ROOT',
      expectedStatus: 200,
    }),
    requestBody({
      requestId: 'ZAP-PASSIVE-02',
      path: '/api/v1/products',
      source: 'OPENAPI:listProducts',
      expectedStatus: 200,
    }),
    requestBody({
      requestId: 'ZAP-PASSIVE-03',
      path: `/api/v1/products/${missingProductId}`,
      source: 'OPENAPI:getProduct:DETERMINISTIC_MISSING_ID',
      expectedStatus: 404,
    }),
    requestBody({
      requestId: 'ZAP-PASSIVE-04',
      path: '/api/docs',
      source: 'OPENAPI:getApiDocumentation',
      expectedStatus: 200,
    }),
    requestBody({
      requestId: 'ZAP-PASSIVE-05',
      path: '/api/health/live',
      source: 'OPENAPI:getLiveness',
      expectedStatus: 200,
    }),
    requestBody({
      requestId: 'ZAP-PASSIVE-06',
      path: '/api/health/ready',
      source: 'OPENAPI:getReadiness',
      expectedStatus: 200,
    }),
  ];
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'ZAP_PASSIVE_EXACT_REQUEST_INVENTORY',
    status: 'APPROVED_BEFORE_EGRESS',
    targetOriginSha256: sha256(targetOrigin),
    openApiRawSha256,
    requestCount: requests.length,
    requests,
    requestsSha256: objectSha256(requests),
    redirectsAllowed: false,
    activeScanAllowed: false,
    mutationRequestsAllowed: false,
    containsSensitiveData: false,
  };
};

export const createZapPassiveRequestInventory = ({ targetOrigin, openApiSource }) => {
  const origin = strictOrigin(targetOrigin);
  const openApi = parseOpenApiOperations(openApiSource);
  const body = inventoryBody({ targetOrigin: origin, openApiRawSha256: openApi.rawSha256 });
  if (body.requestCount !== ZAP_PASSIVE_REQUEST_COUNT) fail('E7_ZAP_INVENTORY_COUNT_INVALID');
  return { ...body, inventorySha256: objectSha256(body) };
};

export const validateZapPassiveRequestInventory = (value, { targetOrigin, openApiSource }) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'targetOriginSha256',
      'openApiRawSha256',
      'requestCount',
      'requests',
      'requestsSha256',
      'redirectsAllowed',
      'activeScanAllowed',
      'mutationRequestsAllowed',
      'containsSensitiveData',
      'inventorySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'ZAP_PASSIVE_EXACT_REQUEST_INVENTORY' ||
    value.status !== 'APPROVED_BEFORE_EGRESS' ||
    value.requestCount !== ZAP_PASSIVE_REQUEST_COUNT ||
    !Array.isArray(value.requests) ||
    value.requests.length !== ZAP_PASSIVE_REQUEST_COUNT ||
    !SHA256.test(value.inventorySha256 ?? '') ||
    value.redirectsAllowed !== false ||
    value.activeScanAllowed !== false ||
    value.mutationRequestsAllowed !== false ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_ZAP_INVENTORY_INVALID');
  }
  const expected = createZapPassiveRequestInventory({ targetOrigin, openApiSource });
  if (canonical(value) !== canonical(expected)) fail('E7_ZAP_INVENTORY_INVALID');
  return value;
};

export const createZapPassiveEgressCounter = (inventory) => {
  if (
    !object(inventory) ||
    inventory.kind !== 'ZAP_PASSIVE_EXACT_REQUEST_INVENTORY' ||
    inventory.requestCount !== ZAP_PASSIVE_REQUEST_COUNT ||
    !Array.isArray(inventory.requests) ||
    inventory.requests.length !== ZAP_PASSIVE_REQUEST_COUNT
  ) {
    fail('E7_ZAP_EGRESS_COUNTER_INPUT_INVALID');
  }
  let nextIndex = 0;
  let closed = false;
  return Object.freeze({
    beforeRequest(request) {
      if (closed || canonical(request) !== canonical(inventory.requests[nextIndex])) {
        fail('E7_ZAP_EGRESS_SEQUENCE_INVALID');
      }
      nextIndex += 1;
      return { requestId: request.requestId, ordinal: nextIndex };
    },
    close() {
      if (closed || nextIndex !== inventory.requestCount) fail('E7_ZAP_EGRESS_COUNT_INVALID');
      closed = true;
      return {
        requestCount: nextIndex,
        inventorySha256: inventory.inventorySha256,
        enforcement: 'BEFORE_EACH_ZAP_EGRESS',
      };
    },
  });
};

const inside = (root, candidate) => {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
};

const allowedPath = (candidate, { input = false } = {}) => {
  const absolute = path.resolve(candidate);
  const runnerTemp = process.env.RUNNER_TEMP?.trim();
  if (!inside(WORKSPACE, absolute) && !(runnerTemp && inside(runnerTemp, absolute))) {
    fail('E7_ZAP_INVENTORY_PATH_OUTSIDE_ALLOWED_ROOT');
  }
  if (input) {
    let stat;
    try {
      stat = lstatSync(absolute);
    } catch {
      fail('E7_ZAP_INVENTORY_INPUT_MISSING');
    }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 16 * 1024 * 1024) {
      fail('E7_ZAP_INVENTORY_INPUT_INVALID');
    }
    const allowedRoot = inside(WORKSPACE, absolute) ? WORKSPACE : runnerTemp;
    if (!inside(realpathSync(allowedRoot), realpathSync(absolute))) {
      fail('E7_ZAP_INVENTORY_INPUT_INVALID');
    }
  } else {
    const parent = path.dirname(absolute);
    let stat;
    try {
      stat = lstatSync(parent);
    } catch {
      fail('E7_ZAP_INVENTORY_OUTPUT_PARENT_INVALID');
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail('E7_ZAP_INVENTORY_OUTPUT_PARENT_INVALID');
    }
    const allowedRoot = inside(WORKSPACE, absolute) ? WORKSPACE : runnerTemp;
    if (!inside(realpathSync(allowedRoot), realpathSync(parent))) {
      fail('E7_ZAP_INVENTORY_OUTPUT_PARENT_INVALID');
    }
  }
  return absolute;
};

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

const readTargetFile = (filename) => {
  const source = readFileSync(allowedPath(filename, { input: true }), 'utf8');
  if (!/^https:\/\/[^\s]+\r?\n?$/u.test(source)) fail('E7_ZAP_INVENTORY_TARGET_FILE_INVALID');
  return strictOrigin(source.trim());
};

const parseFlags = (arguments_) => {
  if (arguments_.length === 1 && arguments_[0] === '--self-test') return { 'self-test': true };
  if (arguments_[0] !== 'create') fail('E7_ZAP_INVENTORY_ARGUMENT_SET_INVALID');
  const flags = {};
  for (let index = 1; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (!/^--[a-z][a-z-]*$/u.test(flag ?? '') || value === undefined || value.startsWith('--')) {
      fail('E7_ZAP_INVENTORY_ARGUMENT_INVALID');
    }
    const key = flag.slice(2);
    if (Object.hasOwn(flags, key)) fail('E7_ZAP_INVENTORY_ARGUMENT_DUPLICATE');
    flags[key] = value;
  }
  if (
    Object.keys(flags).toSorted().join('\0') !== ['openapi', 'output', 'target-file'].join('\0')
  ) {
    fail('E7_ZAP_INVENTORY_ARGUMENT_SET_INVALID');
  }
  return flags;
};

export const selfTestZapPassiveInventory = () => {
  const openApiSource = readFileSync(OPENAPI);
  const targetOrigin = 'https://stage7.example.invalid';
  const inventory = createZapPassiveRequestInventory({ targetOrigin, openApiSource });
  assert.equal(
    validateZapPassiveRequestInventory(inventory, { targetOrigin, openApiSource }),
    inventory,
  );
  assert.equal(inventory.requestCount, 6);
  assert.deepEqual(
    inventory.requests.map(({ method, expectedStatus }) => [method, expectedStatus]),
    [
      ['GET', 200],
      ['GET', 200],
      ['GET', 404],
      ['GET', 200],
      ['GET', 200],
      ['GET', 200],
    ],
  );
  assert.equal(
    inventory.requests.some(({ path: requestPath }) =>
      requestPath.includes('payment-configuration'),
    ),
    false,
  );
  const counter = createZapPassiveEgressCounter(inventory);
  for (const request of inventory.requests) counter.beforeRequest(request);
  assert.deepEqual(counter.close(), {
    requestCount: 6,
    inventorySha256: inventory.inventorySha256,
    enforcement: 'BEFORE_EACH_ZAP_EGRESS',
  });
  assert.throws(
    () => counter.beforeRequest(inventory.requests[0]),
    (error) => error.code === 'E7_ZAP_EGRESS_SEQUENCE_INVALID',
  );
  const outOfOrder = createZapPassiveEgressCounter(inventory);
  assert.throws(
    () => outOfOrder.beforeRequest(inventory.requests[1]),
    (error) => error.code === 'E7_ZAP_EGRESS_SEQUENCE_INVALID',
  );
  assert.throws(
    () => outOfOrder.close(),
    (error) => error.code === 'E7_ZAP_EGRESS_COUNT_INVALID',
  );
  const changed = clone(inventory);
  changed.requests[0].path = '/changed';
  changed.requestsSha256 = objectSha256(changed.requests);
  const changedBody = Object.fromEntries(
    Object.entries(changed).filter(([key]) => key !== 'inventorySha256'),
  );
  changed.inventorySha256 = objectSha256(changedBody);
  assert.throws(
    () => validateZapPassiveRequestInventory(changed, { targetOrigin, openApiSource }),
    (error) => error.code === 'E7_ZAP_INVENTORY_INVALID',
  );
  const missingOperation = Buffer.from(
    openApiSource.toString('utf8').replace('operationId: getReadiness', 'operationId: changed'),
  );
  assert.throws(
    () => createZapPassiveRequestInventory({ targetOrigin, openApiSource: missingOperation }),
    (error) => error.code === 'E7_ZAP_OPENAPI_SAFE_OPERATION_MISSING',
  );
  assert.throws(
    () => createZapPassiveRequestInventory({ targetOrigin: `${targetOrigin}/path`, openApiSource }),
    (error) => error.code === 'E7_ZAP_INVENTORY_TARGET_INVALID',
  );
  return { assertions: 11, externalRequests: 0, mutationsPerformed: 0 };
};

const main = () => {
  const flags = parseFlags(process.argv.slice(2));
  if (flags['self-test'] === true) {
    const result = selfTestZapPassiveInventory();
    process.stdout.write(
      `stage-7 passive ZAP inventory self-test: PASS (${result.assertions} assertions, 0 external requests, 0 mutations)\n`,
    );
    return;
  }
  const targetOrigin = readTargetFile(flags['target-file']);
  const openApiFilename = allowedPath(flags.openapi, { input: true });
  if (realpathSync(openApiFilename) !== realpathSync(OPENAPI)) {
    fail('E7_ZAP_INVENTORY_OPENAPI_PATH_INVALID');
  }
  const inventory = createZapPassiveRequestInventory({
    targetOrigin,
    openApiSource: readFileSync(openApiFilename),
  });
  privateWrite(flags.output, `${JSON.stringify(inventory)}\n`);
};

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(
      `${error instanceof Stage7ZapPassiveInventoryError ? error.code : 'E7_ZAP_INVENTORY_UNEXPECTED_FAILURE'}\n`,
    );
    process.exitCode = 1;
  }
}
