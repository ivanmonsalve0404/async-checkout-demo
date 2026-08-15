import { strict as assert } from 'node:assert';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import process from 'node:process';

const root = process.cwd();
const apiRoot = resolve(root, 'apps/api/src');
const sourceRoots = [
  apiRoot,
  resolve(root, 'apps/web/src'),
  resolve(root, 'packages/contracts/src'),
  resolve(root, 'infra/bin'),
  resolve(root, 'infra/lib'),
];
const sourceExtensions = new Set(['.ts', '.tsx']);
const forbidden = [
  {
    zone: join('apps', 'api', 'src', 'domain'),
    pattern: /from ['"](?:@nestjs\/|@aws-sdk\/|express|rxjs)/,
    reason: 'domain must not import frameworks, HTTP, RxJS, or AWS SDKs',
  },
  {
    zone: join('apps', 'api', 'src', 'application'),
    pattern: /from ['"](?:@nestjs\/|@aws-sdk\/|express)/,
    reason: 'application must not import transport or infrastructure frameworks',
  },
  {
    zone: join('apps', 'api', 'src', 'interfaces', 'http', 'controllers'),
    pattern: /from ['"].*(?:in-memory|dynamodb).*['"];/,
    reason: 'controllers must not import persistence adapters',
  },
];

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : sourceExtensions.has(extname(path)) ? [path] : [];
  });
}

function resolveLocalImport(importer, specifier, knownFiles) {
  const base = resolve(dirname(importer), specifier.replace(/\.js$/u, ''));
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    join(base, 'index.ts'),
    join(base, 'index.tsx'),
  ];
  return candidates.find((candidate) => knownFiles.has(candidate));
}

function buildGraph(sourceFiles) {
  const knownFiles = new Set(sourceFiles);
  const graph = new Map(sourceFiles.map((file) => [file, []]));
  const importPattern =
    /\b(?:import|export)\s+(?:type\s+)?(?:[^'"]*?\sfrom\s*)?['"](\.{1,2}\/[^'"]+)['"]/gu;

  for (const file of sourceFiles) {
    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(importPattern)) {
      const dependency = resolveLocalImport(file, match[1], knownFiles);
      if (dependency !== undefined) graph.get(file).push(dependency);
    }
  }
  return graph;
}

export function findCycles(graph) {
  const state = new Map();
  const stack = [];
  const cycles = [];
  const seen = new Set();

  const visit = (node) => {
    state.set(node, 'visiting');
    stack.push(node);
    for (const dependency of graph.get(node) ?? []) {
      if (state.get(dependency) === 'visiting') {
        const start = stack.indexOf(dependency);
        const cycle = [...stack.slice(start), dependency];
        const key = [...new Set(cycle)].sort().join('|');
        if (!seen.has(key)) {
          seen.add(key);
          cycles.push(cycle);
        }
      } else if (state.get(dependency) !== 'visited') {
        visit(dependency);
      }
    }
    stack.pop();
    state.set(node, 'visited');
  };

  for (const node of graph.keys()) {
    if (state.get(node) === undefined) visit(node);
  }
  return cycles;
}

if (process.argv.includes('--self-test')) {
  const cyclic = new Map([
    ['domain/a.ts', ['application/b.ts']],
    ['application/b.ts', ['domain/a.ts']],
  ]);
  const acyclic = new Map([
    ['domain/a.ts', []],
    ['application/b.ts', ['domain/a.ts']],
  ]);
  assert.equal(findCycles(cyclic).length, 1);
  assert.equal(findCycles(acyclic).length, 0);
  console.log('ARCHITECTURE_BOUNDARIES_SELF_TEST=PASS');
  process.exit(0);
}

const violations = [];
for (const file of files(apiRoot)) {
  const relativePath = relative(root, file);
  const source = readFileSync(file, 'utf8');
  for (const rule of forbidden) {
    if (relativePath.startsWith(rule.zone) && rule.pattern.test(source)) {
      violations.push(`${relativePath}: ${rule.reason}`);
    }
  }
}

const allSourceFiles = sourceRoots.filter(existsSync).flatMap(files);
for (const cycle of findCycles(buildGraph(allSourceFiles))) {
  violations.push(`circular dependency: ${cycle.map((file) => relative(root, file)).join(' -> ')}`);
}

if (violations.length > 0) {
  throw new Error(`Architecture boundary violations:\n${violations.join('\n')}`);
}
console.log('ARCHITECTURE_BOUNDARIES=PASS');
