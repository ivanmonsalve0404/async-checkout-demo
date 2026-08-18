#!/usr/bin/env node

import assert from 'node:assert/strict';
import console from 'node:console';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, '../..');
const contractPath = resolve(repositoryRoot, 'output/architecture/openapi.yaml');
const packageDirectory = resolve(repositoryRoot, 'packages/contracts');
const packagePath = resolve(packageDirectory, 'package.json');
const generatedPath = resolve(packageDirectory, 'src/generated/openapi.d.ts');
const methods = 'get|put|post|delete|patch|options|head|trace';

function fail(message) {
  throw new Error(message);
}

function normalizeLineEndings(value) {
  return value.replace(/\r\n?/g, '\n');
}

function collectReferences(source) {
  const references = [];
  const pattern = /\$ref\s*:\s*(?:'([^'\r\n]*)'|"([^"\r\n]*)"|([^,\s}\]\r\n]+))/g;

  for (const match of source.matchAll(pattern)) {
    references.push(match[1] ?? match[2] ?? match[3]);
  }

  return references;
}

function inspectContentMediaTypes(source) {
  const lines = source.split(/\r?\n/);
  const mediaTypePattern = /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/;

  for (let index = 0; index < lines.length; index += 1) {
    const contentMatch = /^(\s*)content:\s*$/.exec(lines[index]);
    if (!contentMatch) continue;

    const contentIndent = contentMatch[1].length;
    for (let childIndex = index + 1; childIndex < lines.length; childIndex += 1) {
      const line = lines[childIndex];
      if (line.trim() === '' || line.trimStart().startsWith('#')) continue;

      const indent = line.length - line.trimStart().length;
      if (indent <= contentIndent) break;
      if (indent !== contentIndent + 2) continue;

      const keyMatch = /^\s*([^:]+):\s*$/.exec(line);
      if (keyMatch && !mediaTypePattern.test(keyMatch[1])) {
        fail(`Invalid media type under content: ${keyMatch[1]}`);
      }
    }
  }
}

function inspectPaymentTokenContract(source) {
  const tokenSchema =
    /^    PaymentMethodToken:\s*$([\s\S]*?)(?=^    PaymentSubmissionRequest:\s*$)/m.exec(
      source,
    )?.[1];
  const submissionSchema =
    /^    PaymentSubmissionRequest:\s*$([\s\S]*?)(?=^    PaymentSubmissionResponse:\s*$)/m.exec(
      source,
    )?.[1];

  if (tokenSchema === undefined || submissionSchema === undefined) {
    fail('Payment token and submission schemas must remain adjacent canonical components');
  }

  const requiredTokenFragments = [
    'oneOf:',
    "pattern: '^tok_fake_[A-Za-z0-9_-]{8,128}$'",
    "pattern: '^tok_(?!fake_)[A-Za-z0-9_-]{8,256}$'",
    'x-validation-mode: FAKE',
    'x-validation-mode: AUTHORIZED_SANDBOX',
    'writeOnly: true',
    'x-ephemeral: true',
    'x-loggable: false',
    'x-persisted: false',
  ];
  for (const fragment of requiredTokenFragments) {
    if (!tokenSchema.includes(fragment)) {
      fail(`Payment token contract is missing ${fragment}`);
    }
  }
  if (/^\s+(?:example|default):/m.test(tokenSchema)) {
    fail('Payment token contract must not provide an example or default');
  }
  if (
    !/^        paymentMethodToken:\s*\n          \$ref: '#\/components\/schemas\/PaymentMethodToken'\s*$/m.test(
      submissionSchema,
    )
  ) {
    fail('Payment submission must reference the canonical opaque payment token schema');
  }
  for (const forbiddenRawField of [
    'cardNumber',
    'pan',
    'securityCode',
    'cvc',
    'cvv',
    'expiry',
    'expiryMonth',
    'expiryYear',
    'cardholderName',
  ]) {
    if (!submissionSchema.includes(`- ${forbiddenRawField}`)) {
      fail(`Payment submission must reject raw card field ${forbiddenRawField}`);
    }
  }
}

function inspectContract(source) {
  inspectContentMediaTypes(source);
  inspectPaymentTokenContract(source);
  if (source.charCodeAt(0) === 0xfeff) fail('UTF-8 BOM is not allowed');
  if (!/^openapi:\s*3\.1\.2\s*$/m.test(source)) fail('OpenAPI must remain at 3.1.2');

  const pathsStart = source.search(/^paths:\s*$/m);
  const componentsStart = source.search(/^components:\s*$/m);
  if (pathsStart < 0 || componentsStart <= pathsStart)
    fail('paths/components sections are missing or out of order');

  const pathsBlock = source.slice(pathsStart, componentsStart);
  const paths = [...pathsBlock.matchAll(/^  (\/[^:\r\n]+):\s*$/gm)].map((match) => match[1]);
  const operationPattern = new RegExp(`^    (${methods}):\\s*$`, 'gm');
  const operations = [...pathsBlock.matchAll(operationPattern)].map((match) => match[1]);
  const operationIds = [
    ...pathsBlock.matchAll(/^      operationId:\s*([A-Za-z][A-Za-z0-9_]*)\s*$/gm),
  ].map((match) => match[1]);
  const apiIds = [...pathsBlock.matchAll(/^      x-api-id:\s*(API-\d{2})\s*$/gm)].map(
    (match) => match[1],
  );
  const operationBlocks =
    pathsBlock.match(
      new RegExp(
        `^    (?:${methods}):\\s*$[\\s\\S]*?(?=^    (?:${methods}):\\s*$|^  /|(?![\\s\\S]))`,
        'gm',
      ),
    ) ?? [];
  const references = collectReferences(source);
  const nonLocalReferences = references.filter((reference) => !reference.startsWith('#/'));

  if (paths.length !== 15 || new Set(paths).size !== 15) fail('Expected exactly 15 unique paths');
  if (operations.length !== 15) fail('Expected exactly 15 operations');
  if (operationBlocks.length !== 15) fail('Could not isolate all 15 operation blocks');
  if (operationIds.length !== 15 || new Set(operationIds).size !== 15)
    fail('operationId must exist and be unique on all operations');
  if (apiIds.length !== 15 || new Set(apiIds).size !== 15)
    fail('x-api-id must exist and be unique on all operations');
  if (
    apiIds.toSorted().join(',') !==
    Array.from({ length: 15 }, (_, index) => `API-${String(index + 1).padStart(2, '0')}`).join(',')
  ) {
    fail('x-api-id must be the canonical API-01..API-15 set');
  }
  if (references.length === 0) fail('The contract unexpectedly contains no references');
  if (nonLocalReferences.length > 0)
    fail(`Rejected ${nonLocalReferences.length} non-local reference(s)`);

  for (const block of operationBlocks) {
    if (!/^      security:/m.test(block)) fail('Every operation must declare security explicitly');
    if (!/^      responses:/m.test(block)) fail('Every operation must declare responses');
    if (!/^      x-trace:/m.test(block)) fail('Every operation must declare traceability');
  }

  return {
    apiIds: apiIds.length,
    operationIds: operationIds.length,
    operations: operations.length,
    paths: paths.length,
    references: references.length,
  };
}

async function loadContract() {
  const source = normalizeLineEndings(await readFile(contractPath, 'utf8'));
  const metadata = inspectContract(source);
  const hash = createHash('sha256').update(source, 'utf8').digest('hex');
  return { hash, metadata, source };
}

async function loadGenerated() {
  const current = await readFile(generatedPath, 'utf8').catch(() => null);
  return current === null ? null : normalizeLineEndings(current);
}

async function loadGenerator() {
  const requireFromPackage = createRequire(pathToFileURL(packagePath));
  const generatorPath = requireFromPackage.resolve('openapi-typescript');
  return import(pathToFileURL(generatorPath).href);
}

async function renderTypes(contract) {
  const generator = await loadGenerator();
  const openapiTS =
    typeof generator.default === 'function' ? generator.default : generator.default?.default;
  const astToString = generator.astToString ?? generator.default?.astToString;
  if (typeof openapiTS !== 'function' || typeof astToString !== 'function') {
    fail('Unsupported openapi-typescript module shape');
  }
  const ast = await openapiTS(contract.source, {
    alphabetize: true,
    immutable: true,
    silent: true,
  });
  const body = normalizeLineEndings(astToString(ast)).trimEnd();
  if (!body.includes('export interface paths') || !body.includes('export interface components')) {
    fail('Generator output is missing paths or components');
  }

  return [
    '// Generated by scripts/contracts/contracts.mjs. DO NOT EDIT.',
    '// Source: output/architecture/openapi.yaml',
    `// Source SHA-256 (LF-normalized): ${contract.hash}`,
    '',
    body,
    '',
  ].join('\n');
}

async function validate() {
  const contract = await loadContract();
  await renderTypes(contract);
  console.log(
    JSON.stringify({ ...contract.metadata, sha256: contract.hash, status: 'valid' }, null, 2),
  );
}

async function generate() {
  const contract = await loadContract();
  const expected = await renderTypes(contract);
  await mkdir(dirname(generatedPath), { recursive: true });

  const current = await loadGenerated();
  if (current === expected) {
    console.log('contracts: generated output already current');
    return;
  }

  await writeFile(generatedPath, expected, 'utf8');
  console.log('contracts: generated packages/contracts/src/generated/openapi.d.ts');
}

async function check() {
  const contract = await loadContract();
  const expected = await renderTypes(contract);
  const current = await loadGenerated();
  if (current !== expected) fail('Contract drift detected; run contracts:generate');
  console.log(`contracts: no drift (${contract.hash})`);
}

async function test() {
  const contract = await loadContract();
  const first = await renderTypes(contract);
  const second = await renderTypes(contract);
  assert.equal(first, second, 'generation must be deterministic');
  assert.throws(
    () =>
      inspectContract(
        contract.source.replace(
          '#/components/schemas/OpaqueId',
          'https://example.invalid/schema.yaml',
        ),
      ),
    /non-local reference/,
    'remote references must fail closed',
  );
  assert.throws(
    () =>
      inspectContract(
        contract.source.replace('            application/json:', '            X-RateLimit-Limit:'),
      ),
    /Invalid media type/,
    'response content must contain media types only',
  );
  assert.throws(
    () =>
      inspectContract(
        contract.source.replace(
          "pattern: '^tok_(?!fake_)[A-Za-z0-9_-]{8,256}$'",
          "pattern: '^tok_[A-Za-z0-9_-]{8,256}$'",
        ),
      ),
    /Payment token contract is missing/,
    'authorized sandbox tokens must remain mutually exclusive with fake tokens',
  );
  const current = await loadGenerated();
  assert.equal(current, first, 'committed output must match generation');
  console.log('contracts: deterministic generation, local refs and drift guards pass');
}

const command = process.argv[2];
const commands = { check, generate, test, validate };

if (!(command in commands)) {
  console.error('Usage: contracts.mjs <validate|generate|check|test>');
  process.exitCode = 2;
} else {
  commands[command]().catch((error) => {
    console.error(`contracts: ${error instanceof Error ? error.message : 'unknown failure'}`);
    process.exitCode = 1;
  });
}
