#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import process from 'node:process';

const SKIPPED_DIRECTORIES = new Set([
  '.git',
  '.pnpm',
  '.turbo',
  '.vite',
  'coverage',
  'node_modules',
]);

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
      /\b(?:events[_-]?key|integrity[_-]?key|password|passwd|private[_-]?key|secret)\b\s*[:=]\s*["']?([A-Za-z0-9+/_=.-]{16,})/giu,
    valueGroup: 1,
  },
];

// A payment-card PAN cannot start with zero; excluding it avoids ISO/date ranges in minified code.
const PAN_CANDIDATE = /(?<!\d)[1-9][ -]?(?:\d[ -]?){11,17}\d(?!\d)/gu;

function isPlaceholder(value) {
  const normalized = value.toLowerCase();
  return [
    'change-me',
    'changeme',
    'dummy',
    'example.invalid',
    'fake-only',
    'not-a-real',
    'placeholder',
    'replace-me',
  ].some((marker) => normalized.includes(marker));
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
      if (passesLuhn(match[0])) {
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

function collectTextFiles(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && SKIPPED_DIRECTORIES.has(entry.name)) {
      continue;
    }
    const resolved = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectTextFiles(resolved));
    } else if (entry.isFile() && isTextFile(resolved)) {
      files.push(resolved);
    }
  }
  return files;
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
  const accessKey = ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('');
  const assignedSecret = ['private', '_key', '='].join('') + 'sensitivevalue123456';
  const findings = scanText(
    'self-test',
    [accessKey, assignedSecret, makeLuhnCandidate()].join('\n'),
  );
  assert.deepEqual(findings.map((finding) => finding.rule).sort(), [
    'ASSIGNED_SECRET',
    'AWS_ACCESS_KEY',
    'PAN_LUHN',
  ]);
  assert.equal(
    scanText('placeholders', 'PRIVATE_KEY=replace-me\nBASE_URL=https://example.invalid').length,
    0,
  );
  process.stdout.write('secret-scan self-test: PASS\n');
  const luhnCandidate = makeLuhnCandidate();
  assert.equal(
    scanText('git-metadata', withoutGitIndexMetadata(`index ${luhnCandidate}..abcdef0 100644`))
      .length,
    0,
  );
  assert.equal(scanText('changed-content', `+${luhnCandidate}`)[0]?.rule, 'PAN_LUHN');
}

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function main() {
  if (process.argv.includes('--self-test')) {
    selfTest();
    return;
  }

  const rootDirectory = path.resolve(argumentValue('--root') ?? process.cwd());
  const files = collectTextFiles(rootDirectory);
  const findings = files.flatMap((filePath) =>
    scanText(
      path.relative(rootDirectory, filePath).replaceAll('\\', '/'),
      fs.readFileSync(filePath, 'utf8'),
    ),
  );

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
}

main();
