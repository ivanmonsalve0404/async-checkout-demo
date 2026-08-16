import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const planPath = resolve(workspaceRoot, 'docs/build/slice-plan.md');
const catalogPath = resolve(workspaceRoot, 'docs/build/test-catalog.json');
const compactIdPattern = /TC-(?:UNIT|INT|E2E|CONTRACT)-\d{2}(?:(?:\/\d{2})+|\.\.\d{2})?/g;
const canonicalIdPattern = /^TC-(?:UNIT|INT|E2E|CONTRACT)-\d{2}$/;

const fail = (message) => {
  throw new Error(message);
};

const expandCompactId = (compactId) => {
  const prefixMatch = /^(TC-(?:UNIT|INT|E2E|CONTRACT)-)/.exec(compactId);
  if (!prefixMatch) fail(`Invalid compact test ID: ${compactId}`);
  const prefix = prefixMatch[1];
  const suffix = compactId.slice(prefix.length);

  if (suffix.includes('..')) {
    const [startText, endText] = suffix.split('..');
    const start = Number(startText);
    const end = Number(endText);
    if (!Number.isInteger(start) || !Number.isInteger(end) || end < start || end > 99) {
      fail(`Invalid test ID range: ${compactId}`);
    }
    return Array.from(
      { length: end - start + 1 },
      (_, index) => prefix + String(start + index).padStart(2, '0'),
    );
  }

  return suffix.split('/').map((value) => prefix + value);
};

const referencedIds = (plan) => {
  const ids = new Set();
  for (const match of plan.matchAll(compactIdPattern)) {
    for (const id of expandCompactId(match[0])) ids.add(id);
  }
  return ids;
};

const safeWorkspacePath = (relativePath) => {
  if (typeof relativePath !== 'string' || relativePath.length === 0) {
    fail('Every evidence selector needs a file');
  }
  const absolutePath = resolve(workspaceRoot, relativePath);
  if (!existsSync(absolutePath)) fail(`Evidence file is missing: ${relativePath}`);
  const rootPrefix = workspaceRoot.endsWith(sep) ? workspaceRoot : workspaceRoot + sep;
  if (!absolutePath.startsWith(rootPrefix))
    fail(`Evidence path escapes workspace: ${relativePath}`);
  return absolutePath;
};

const plan = readFileSync(planPath, 'utf8');
const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));
if (catalog.schemaVersion !== 1 || !Array.isArray(catalog.tests)) {
  fail('Test catalog schema is invalid');
}

const byId = new Map();
for (const entry of catalog.tests) {
  if (typeof entry !== 'object' || entry === null || !canonicalIdPattern.test(entry.id)) {
    fail('Catalog contains an invalid test ID');
  }
  if (byId.has(entry.id)) fail(`Duplicate catalog entry: ${entry.id}`);
  if (entry.status !== 'EXECUTABLE' && entry.status !== 'DEFERRED_P1') {
    fail(`Invalid catalog status: ${entry.id}`);
  }

  if (entry.status === 'EXECUTABLE') {
    if (typeof entry.runner !== 'string' || entry.runner.length === 0) {
      fail(`Executable entry has no runner: ${entry.id}`);
    }
    if (!Array.isArray(entry.evidence) || entry.evidence.length === 0) {
      fail(`Executable entry has no evidence selector: ${entry.id}`);
    }
    for (const selector of entry.evidence) {
      if (typeof selector.pattern !== 'string' || selector.pattern.length < 3) {
        fail(`Evidence selector has no stable pattern: ${entry.id}`);
      }
      const source = readFileSync(safeWorkspacePath(selector.file), 'utf8');
      if (!source.includes(selector.pattern)) {
        fail(`Broken executable trace ${entry.id}: ${selector.file} :: ${selector.pattern}`);
      }
    }
  } else if (
    typeof entry.reason !== 'string' ||
    entry.reason.length === 0 ||
    typeof entry.authority !== 'string' ||
    entry.authority.length === 0
  ) {
    fail(`Deferred entry lacks reason/authority: ${entry.id}`);
  }

  byId.set(entry.id, entry);
}

const references = referencedIds(plan);
for (const id of references) {
  if (!byId.has(id)) fail(`Matrix references an uncatalogued test: ${id}`);
}

for (const entry of byId.values()) {
  if (entry.status !== 'DEFERRED_P1' || !references.has(entry.id)) continue;
  const hasDisposition = plan
    .split(/\r?\n/)
    .some((line) => line.includes(entry.id) && line.includes('DEFERRED_P1'));
  if (!hasDisposition) fail(`Deferred test lacks an explicit matrix disposition: ${entry.id}`);
}

const executable = [...references].filter((id) => byId.get(id)?.status === 'EXECUTABLE').length;
const deferred = [...references].filter((id) => byId.get(id)?.status === 'DEFERRED_P1').length;
console.log(
  JSON.stringify(
    { catalogued: byId.size, deferred, executable, referenced: references.size, status: 'PASS' },
    null,
    2,
  ),
);
