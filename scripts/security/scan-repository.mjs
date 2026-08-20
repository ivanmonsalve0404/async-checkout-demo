#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const SKIPPED_DIRECTORIES = new Set([
  '.git',
  '.pnpm',
  '.turbo',
  '.vite',
  'coverage',
  'node_modules',
]);
const SKIPPED_RELATIVE_DIRECTORIES = new Set(['.stage7/private']);
const TRACKED_PRIVATE_PATH = /^\.stage7\/private(?:\/|$)/u;

const TEXT_EXTENSIONS = new Set([
  '.css',
  '.cjs',
  '.cts',
  '.env',
  '.html',
  '.js',
  '.json',
  '.jsx',
  '.md',
  '.mjs',
  '.mts',
  '.scss',
  '.sh',
  '.ts',
  '.tsx',
  '.txt',
  '.yaml',
  '.yml',
]);

const SECRET_PATTERNS = [
  {
    id: 'PRIVATE_KEY',
    expression: /-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----/gu,
  },
  {
    id: 'AWS_ACCESS_KEY',
    expression: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu,
  },
  {
    id: 'GITHUB_TOKEN',
    expression: /\b(?:gh[oprsu]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/gu,
  },
  {
    id: 'PROVIDER_CREDENTIAL',
    expression: /\b(?:prv|pub)_(?:test|prod)_[A-Za-z0-9_-]{8,}\b/gu,
  },
  {
    id: 'PROVIDER_INTEGRITY_OR_EVENTS_KEY',
    expression: /\b(?:test|prod)_(?:integrity|events)_[A-Za-z0-9_-]{8,}\b/gu,
  },
  {
    id: 'ASSIGNED_SECRET',
    expression:
      /\b(?:access[_-]?token|api[_-]?key|aws[_-]?secret[_-]?access[_-]?key|client[_-]?secret|events[_-]?key|integrity[_-]?key|password|passwd|private[_-]?key|secret)\b\s*[:=]\s*["']?([A-Za-z0-9+/_=.-]{16,})/giu,
    valueGroup: 1,
  },
  {
    id: 'BEARER_TOKEN',
    expression: /\bBearer\s+([A-Za-z0-9._~+/=-]{16,})/giu,
    valueGroup: 1,
  },
];

// A payment-card PAN cannot start with zero; excluding it avoids ISO/date ranges in minified code.
const PAN_CANDIDATE = /(?<!\d)[1-9][ -]?(?:\d[ -]?){11,17}\d(?!\d)/gu;
const HEX_DIGEST = /(?<![A-Fa-f0-9])[A-Fa-f0-9]{40,128}(?![A-Fa-f0-9])/gu;
const EXACT_PLACEHOLDER_VALUES = new Set([
  'change-me',
  'changeme',
  'dummy',
  'example.invalid',
  'fake-only',
  'not-a-real',
  'placeholder',
  'replace-me',
]);
const SCOPED_PLACEHOLDER_VALUE =
  /^(?:(?:prv|pub)_(?:test|prod)|(?:test|prod)_(?:integrity|events))_(?:change-me|changeme|dummy|fake-only|not-a-real|placeholder|replace-me)$/u;

function isPlaceholder(value) {
  const normalized = value.toLowerCase();
  return EXACT_PLACEHOLDER_VALUES.has(normalized) || SCOPED_PLACEHOLDER_VALUE.test(normalized);
}

function passesLuhn(candidate) {
  const digits = candidate.replace(/[^0-9]/gu, '');
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }

  let sum = 0;
  let doubleDigit = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
}

export function scanText(label, text) {
  const findings = [];
  const lines = text.split(/\r?\n/u);

  lines.forEach((line, lineIndex) => {
    const hexDigests = [...line.matchAll(HEX_DIGEST)];

    for (const pattern of SECRET_PATTERNS) {
      pattern.expression.lastIndex = 0;
      for (const match of line.matchAll(pattern.expression)) {
        const candidate = match[pattern.valueGroup ?? 0] ?? '';
        if (!isPlaceholder(candidate)) {
          findings.push({
            label,
            line: lineIndex + 1,
            rule: pattern.id,
          });
        }
      }
    }

    PAN_CANDIDATE.lastIndex = 0;
    for (const match of line.matchAll(PAN_CANDIDATE)) {
      const insideHexDigest = hexDigests.some(
        (digest) =>
          match.index >= digest.index &&
          match.index + match[0].length <= digest.index + digest[0].length,
      );
      if (!insideHexDigest && passesLuhn(match[0])) {
        findings.push({
          label,
          line: lineIndex + 1,
          rule: 'PAN_LUHN',
        });
      }
    }
  });

  return findings;
}

function isTextFile(filePath) {
  const basename = path.basename(filePath);
  return (
    TEXT_EXTENSIONS.has(path.extname(filePath).toLowerCase()) ||
    basename === '.env' ||
    basename === '.env.example' ||
    basename === '.npmrc' ||
    basename === '.pypirc' ||
    basename === '.yarnrc' ||
    basename.startsWith('.env.') ||
    basename === 'Dockerfile'
  );
}

export function shouldSkipDirectory(rootDirectory, candidateDirectory) {
  if (SKIPPED_DIRECTORIES.has(path.basename(candidateDirectory))) return true;
  const relative = path
    .relative(path.resolve(rootDirectory), path.resolve(candidateDirectory))
    .replaceAll('\\', '/');
  return SKIPPED_RELATIVE_DIRECTORIES.has(relative);
}

export function collectTextFiles(directory, rootDirectory = directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const resolved = path.join(directory, entry.name);
    if (entry.isDirectory() && shouldSkipDirectory(rootDirectory, resolved)) continue;
    if (entry.isDirectory()) {
      files.push(...collectTextFiles(resolved, rootDirectory));
    } else if (entry.isFile() && isTextFile(resolved)) {
      files.push(resolved);
    }
  }
  return files;
}

export function trackedPrivatePathFindings(gitIndexSource) {
  if (typeof gitIndexSource !== 'string') throw new Error('git index inventory is invalid');
  const containsTrackedPrivatePath = gitIndexSource
    .split('\0')
    .some((filename) => TRACKED_PRIVATE_PATH.test(filename));
  return containsTrackedPrivatePath
    ? [{ label: '.stage7/private/**', line: 0, rule: 'TRACKED_PRIVATE_PATH' }]
    : [];
}

function scanGitIndex(rootDirectory) {
  const inventory = spawnSync(
    'git',
    ['-C', rootDirectory, 'ls-files', '--cached', '--full-name', '-z'],
    {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  if (inventory.status !== 0) {
    throw new Error('git index scan failed without exposing command output');
  }
  return trackedPrivatePathFindings(inventory.stdout);
}

function withoutGitIndexMetadata(text) {
  return text
    .split(/\r?\n/u)
    .filter((line) => !/^index [0-9a-f]{7,64}\.\.[0-9a-f]{7,64}(?: [0-7]{6})?$/u.test(line))
    .join('\n');
}

function scanHistory(rootDirectory) {
  const inside = spawnSync('git', ['-C', rootDirectory, 'rev-parse', '--is-inside-work-tree'], {
    encoding: 'utf8',
  });
  if (inside.status !== 0 || inside.stdout.trim() !== 'true') {
    throw new Error('git history scan is BLOCKED because no repository exists');
  }

  const history = spawnSync(
    'git',
    [
      '-C',
      rootDirectory,
      'log',
      '--all',
      '-p',
      '--no-ext-diff',
      '--text',
      '--pretty=format:commit:%H',
    ],
    {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  if (history.status !== 0) {
    throw new Error('git history scan failed without exposing command output');
  }
  return scanText('git-history', withoutGitIndexMetadata(history.stdout));
}

function makeLuhnCandidate() {
  const base = '4'.repeat(15);
  for (let digit = 0; digit <= 9; digit += 1) {
    const candidate = base + String(digit);
    if (passesLuhn(candidate)) {
      return candidate;
    }
  }
  throw new Error('unable to construct self-test candidate');
}

function selfTest() {
  const scopedRoot = path.resolve('secret-scan-scoped-self-test');
  const privateDirectory = path.join(scopedRoot, '.stage7', 'private');
  const evidenceDirectory = path.join(scopedRoot, '.stage7', 'evidence');
  assert.equal(shouldSkipDirectory(scopedRoot, privateDirectory), true);
  assert.equal(shouldSkipDirectory(scopedRoot, evidenceDirectory), false);
  assert.deepEqual(
    trackedPrivatePathFindings(
      ['README.md', '.stage7/private/runtime.json', '.stage7/evidence/report.json', ''].join('\0'),
    ),
    [{ label: '.stage7/private/**', line: 0, rule: 'TRACKED_PRIVATE_PATH' }],
  );
  assert.deepEqual(
    trackedPrivatePathFindings(
      ['.stage7/private-safe/runtime.json', '.stage7/evidence/report.json', ''].join('\0'),
    ),
    [],
  );
  const accessKey = ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('');
  const assignedSecret = ['private', '_key', '='].join('') + 'sensitivevalue123456';
  const apiKey = ['API', '_KEY', '='].join('') + 'sensitivevalue234567';
  const accessToken = ['ACCESS', '_TOKEN', '='].join('') + 'sensitivevalue345678';
  const clientSecret = ['CLIENT', '_SECRET', '='].join('') + 'sensitivevalue456789';
  const awsSecret = ['AWS', '_SECRET_ACCESS_KEY', '='].join('') + 'sensitivevalue567890';
  const bearer = ['Authorization: Bear', 'er ', 'sensitivevalue678901'].join('');
  const scopedSecret = ['private', '_key', '='].join('') + 'scopedvalue123456789';
  const privateFindings = shouldSkipDirectory(scopedRoot, privateDirectory)
    ? []
    : scanText('.stage7/private/runtime.json', scopedSecret);
  const evidenceFindings = shouldSkipDirectory(scopedRoot, evidenceDirectory)
    ? []
    : scanText('.stage7/evidence/runtime.txt', scopedSecret);
  assert.equal(privateFindings.length, 0);
  assert.equal(
    evidenceFindings.some((finding) => finding.rule === 'ASSIGNED_SECRET'),
    true,
  );
  const filesystemRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'checkout-secret-scan-selftest-'));
  const privateFile = path.join(filesystemRoot, '.stage7', 'private', 'runtime.json');
  const evidenceFile = path.join(filesystemRoot, '.stage7', 'evidence', 'runtime.txt');
  try {
    fs.mkdirSync(path.dirname(privateFile), { recursive: true });
    fs.mkdirSync(path.dirname(evidenceFile), { recursive: true });
    fs.writeFileSync(privateFile, scopedSecret, 'utf8');
    fs.writeFileSync(evidenceFile, scopedSecret, 'utf8');
    const collectedFiles = collectTextFiles(filesystemRoot);
    assert.equal(collectedFiles.includes(privateFile), false);
    assert.equal(collectedFiles.includes(evidenceFile), true);
    const collectedFindings = collectedFiles.flatMap((filename) =>
      scanText(
        path.relative(filesystemRoot, filename).replaceAll('\\', '/'),
        fs.readFileSync(filename, 'utf8'),
      ),
    );
    assert.equal(
      collectedFindings.some(
        (finding) =>
          finding.label === '.stage7/evidence/runtime.txt' && finding.rule === 'ASSIGNED_SECRET',
      ),
      true,
    );
  } finally {
    for (const filename of [privateFile, evidenceFile]) {
      if (fs.existsSync(filename)) fs.writeFileSync(filename, '', 'utf8');
    }
    fs.rmSync(filesystemRoot, { force: true, recursive: true });
  }
  const findings = scanText(
    'self-test',
    [
      accessKey,
      assignedSecret,
      apiKey,
      accessToken,
      clientSecret,
      awsSecret,
      bearer,
      makeLuhnCandidate(),
    ].join('\n'),
  );
  assert.deepEqual(findings.map((finding) => finding.rule).sort(), [
    'ASSIGNED_SECRET',
    'ASSIGNED_SECRET',
    'ASSIGNED_SECRET',
    'ASSIGNED_SECRET',
    'ASSIGNED_SECRET',
    'AWS_ACCESS_KEY',
    'BEARER_TOKEN',
    'PAN_LUHN',
  ]);
  assert.equal(
    scanText(
      'placeholders',
      [
        'PRIVATE_KEY=replace-me',
        'BASE_URL=https://example.invalid',
        'PRIVATE_KEY=prv_test_not-a-real',
        'EVENTS_KEY=test_events_fake-only',
        'pub_test_replace-me',
      ].join('\n'),
    ).length,
    0,
  );
  const disguisedAssignedSecret = ['secret=', 'not-a-real', '-but-actual-secret-value'].join('');
  const markerAtProviderSuffix = ['prv_test_', 'actualvalue', 'fake-only'].join('');
  const markerAtProviderPrefix = ['prv_test_', 'fake-only', 'actualvalue'].join('');
  const disguisedFindings = scanText(
    'disguised-placeholders',
    [disguisedAssignedSecret, markerAtProviderSuffix, markerAtProviderPrefix].join('\n'),
  );
  assert.ok(
    disguisedFindings.some((finding) => finding.line === 1 && finding.rule === 'ASSIGNED_SECRET'),
  );
  assert.equal(
    disguisedFindings.filter((finding) => finding.rule === 'PROVIDER_CREDENTIAL').length,
    2,
  );
  process.stdout.write('secret-scan self-test: PASS\n');
  const luhnCandidate = makeLuhnCandidate();
  assert.equal(
    scanText('git-metadata', withoutGitIndexMetadata(`index ${luhnCandidate}..abcdef0 100644`))
      .length,
    0,
  );
  assert.equal(scanText('changed-content', `+${luhnCandidate}`)[0]?.rule, 'PAN_LUHN');
  const digestWithLuhnSubstring = `${'a'.repeat(24)}${luhnCandidate}${'b'.repeat(24)}`;
  assert.equal(scanText('sha256', `"sha256":"${digestWithLuhnSubstring}"`).length, 0);
}

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

async function main() {
  if (process.argv.includes('--self-test')) {
    selfTest();
    return;
  }

  const rootDirectory = path.resolve(argumentValue('--root') ?? process.cwd());
  const files = collectTextFiles(rootDirectory);
  const findings = [
    ...scanGitIndex(rootDirectory),
    ...files.flatMap((filePath) =>
      scanText(
        path.relative(rootDirectory, filePath).replaceAll('\\', '/'),
        fs.readFileSync(filePath, 'utf8'),
      ),
    ),
  ];

  let historyStatus = 'NOT_RUN';
  if (process.argv.includes('--history')) {
    findings.push(...scanHistory(rootDirectory));
    historyStatus = 'PASS';
  }

  if (findings.length > 0) {
    process.stderr.write('secret-scan: FAIL (' + findings.length + ' redacted finding(s))\n');
    for (const finding of findings) {
      process.stderr.write(finding.label + ':' + finding.line + ' [' + finding.rule + ']\n');
    }
    process.exitCode = 1;
    return;
  }

  process.stdout.write(
    'secret-scan: PASS (' + files.length + ' files; history=' + historyStatus + ')\n',
  );

  const evidencePath = argumentValue('--evidence');
  if (evidencePath !== undefined) {
    const resolvedEvidencePath = path.resolve(rootDirectory, evidencePath);
    const rootPrefix = rootDirectory.endsWith(path.sep) ? rootDirectory : rootDirectory + path.sep;
    if (!resolvedEvidencePath.startsWith(rootPrefix)) {
      throw new Error('secret-scan evidence path escapes the repository');
    }
    const { serializeSanitizedEvidence } = await import('../stage6/lib/artifact-sanitizer.mjs');
    const serialized = serializeSanitizedEvidence(path.basename(resolvedEvidencePath), {
      schemaVersion: 1,
      status: 'PASS',
      findings: 0,
      filesScanned: files.length,
      history: historyStatus,
    });
    const temporaryEvidence = `${resolvedEvidencePath}.${process.pid}.tmp`;
    fs.mkdirSync(path.dirname(resolvedEvidencePath), { recursive: true });
    try {
      fs.writeFileSync(temporaryEvidence, serialized, 'utf8');
      fs.renameSync(temporaryEvidence, resolvedEvidencePath);
    } catch (error) {
      fs.rmSync(temporaryEvidence, { force: true });
      throw error;
    }
  }
}

const executedDirectly =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (executedDirectly) {
  main().catch(() => {
    process.stderr.write('secret-scan: FAIL (evidence writer rejected output)\n');
    process.exitCode = 1;
  });
}
